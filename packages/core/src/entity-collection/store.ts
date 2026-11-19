import { cloneData } from "../data-copy.js";
/** In-memory collection snapshots and expiring pagination cursors. */

import { type EntityId, nowSeconds } from "../types.js";
import type {
	EntityCollectionCursor,
	EntityCollectionSnapshot,
	EntityCollectionStore,
	MemoryEntityCollectionStoreOptions,
} from "./types.js";

/** Cursor allocation exceeded capacity after expired cursors were removed. */
export class EntityCollectionCursorCapacityError extends Error {
	constructor(readonly maxCursors: number) {
		super("Collection cursor capacity exhausted");
		this.name = "EntityCollectionCursorCapacityError";
	}
}

/** Bounded in-memory snapshots and opaque cursors; no background cleanup timer. */
export class MemoryEntityCollectionStore implements EntityCollectionStore {
	private readonly snapshots = new Map<
		string,
		{ value: EntityCollectionSnapshot; retainUntil: number }
	>();
	private readonly current = new Map<string, string>();
	private readonly cursors = new Map<string, EntityCollectionCursor>();
	/**
	 * Validate capacity and retention options; snapshots and cursors are copied on reads and writes.
	 */
	constructor(private readonly options: MemoryEntityCollectionStoreOptions = {}) {
		for (const value of [
			options.retentionSeconds ?? 900,
			options.maxSnapshots ?? 100,
			options.maxCursors ?? 10000,
		])
			if (!Number.isSafeInteger(value) || value <= 0)
				throw new Error("Collection store limits must be positive safe integers");
	}
	private prune(): void {
		const now = nowSeconds(this.options.clock);
		for (const [id, cursor] of this.cursors) if (cursor.expiresAt <= now) this.cursors.delete(id);
		for (const [id, snapshot] of this.snapshots)
			if (this.current.get(snapshot.value.trustAnchor) !== id && snapshot.retainUntil <= now)
				this.snapshots.delete(id);
	}
	/**
	 * Publish a detached snapshot and advance its anchor's current pointer, subject to retention and
	 * capacity limits.
	 */
	async publish(snapshot: EntityCollectionSnapshot): Promise<void> {
		this.prune();
		const copy = cloneData(snapshot);
		if (this.snapshots.has(copy.id)) throw new Error("Snapshot identifiers must be unique");
		const max = this.options.maxSnapshots ?? 100;
		if (this.snapshots.size >= max) {
			const candidate = [...this.snapshots].find(
				([id, item]) => this.current.get(item.value.trustAnchor) !== id,
			);
			if (candidate) this.snapshots.delete(candidate[0]);
			else if (!this.current.has(copy.trustAnchor))
				throw new Error(
					`Collection snapshot capacity ${max} is occupied by current anchors; increase maxSnapshots to publish another anchor`,
				);
			else this.snapshots.delete(this.current.get(copy.trustAnchor) as string);
		}
		const previous = this.snapshots.get(this.current.get(copy.trustAnchor) ?? "");
		if (previous)
			previous.retainUntil =
				nowSeconds(this.options.clock) + (this.options.retentionSeconds ?? 900);
		this.snapshots.set(copy.id, { value: copy, retainUntil: Infinity });
		this.current.set(copy.trustAnchor, copy.id);
	}
	/** Return a detached copy of the anchor's current snapshot, if available. */
	async getCurrent(anchor: EntityId): Promise<EntityCollectionSnapshot | undefined> {
		return this.getSnapshot(this.current.get(anchor) ?? "");
	}
	/** Read a detached retained snapshot after pruning expired historical snapshots. */
	async getSnapshot(id: string): Promise<EntityCollectionSnapshot | undefined> {
		this.prune();
		const item = this.snapshots.get(id);
		return item ? cloneData(item.value) : undefined;
	}
	/**
	 * Store a detached cursor; a full live cursor table throws EntityCollectionCursorCapacityError.
	 */
	async putCursor(id: string, cursor: EntityCollectionCursor): Promise<void> {
		this.prune();
		if (!this.cursors.has(id) && this.cursors.size >= (this.options.maxCursors ?? 10000))
			throw new EntityCollectionCursorCapacityError(this.options.maxCursors ?? 10000);
		this.cursors.set(id, cloneData(cursor));
	}
	/** Read a detached cursor if it has not expired. */
	async getCursor(id: string): Promise<EntityCollectionCursor | undefined> {
		this.prune();
		const cursor = this.cursors.get(id);
		return cursor ? cloneData(cursor) : undefined;
	}
}
