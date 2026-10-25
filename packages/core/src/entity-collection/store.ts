import type { EntityId } from "../types.js";
import { nowSeconds } from "../types.js";
import type {
	EntityCollectionCursor,
	EntityCollectionSnapshot,
	EntityCollectionStore,
	MemoryEntityCollectionStoreOptions,
} from "./types.js";

/** Bounded in-memory snapshots and opaque cursors; no background cleanup timer. */
export class MemoryEntityCollectionStore implements EntityCollectionStore {
	private readonly snapshots = new Map<
		string,
		{ value: EntityCollectionSnapshot; retainUntil: number }
	>();
	private readonly current = new Map<string, string>();
	private readonly cursors = new Map<string, EntityCollectionCursor>();
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
	async publish(snapshot: EntityCollectionSnapshot): Promise<void> {
		this.prune();
		const copy = structuredClone(snapshot);
		if (this.snapshots.has(copy.id)) throw new Error("Snapshot identifiers must be unique");
		const max = this.options.maxSnapshots ?? 100;
		if (this.snapshots.size >= max) {
			const candidate = [...this.snapshots].find(
				([id, item]) => this.current.get(item.value.trustAnchor) !== id,
			);
			if (candidate) this.snapshots.delete(candidate[0]);
			else if (!this.current.has(copy.trustAnchor))
				throw new Error("Collection snapshot capacity exhausted");
			else this.snapshots.delete(this.current.get(copy.trustAnchor) as string);
		}
		const previous = this.snapshots.get(this.current.get(copy.trustAnchor) ?? "");
		if (previous)
			previous.retainUntil =
				nowSeconds(this.options.clock) + (this.options.retentionSeconds ?? 900);
		this.snapshots.set(copy.id, { value: copy, retainUntil: Infinity });
		this.current.set(copy.trustAnchor, copy.id);
	}
	async getCurrent(anchor: EntityId): Promise<EntityCollectionSnapshot | undefined> {
		return this.getSnapshot(this.current.get(anchor) ?? "");
	}
	async getSnapshot(id: string): Promise<EntityCollectionSnapshot | undefined> {
		this.prune();
		const item = this.snapshots.get(id);
		return item ? structuredClone(item.value) : undefined;
	}
	async putCursor(id: string, cursor: EntityCollectionCursor): Promise<void> {
		this.prune();
		if (this.cursors.size >= (this.options.maxCursors ?? 10000))
			this.cursors.delete(this.cursors.keys().next().value as string);
		this.cursors.set(id, structuredClone(cursor));
	}
	async getCursor(id: string): Promise<EntityCollectionCursor | undefined> {
		this.prune();
		const cursor = this.cursors.get(id);
		return cursor ? structuredClone(cursor) : undefined;
	}
}
