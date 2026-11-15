import {
	type Clock,
	decodeEntityStatement,
	type EntityCollectionStore,
	type EntityId,
	isValidEntityId,
	MemoryCache,
	MemoryEntityCollectionStore,
	MemoryReplayStore,
	MemoryTrustMarkStorage,
	nowSeconds,
	type SubordinateEvent,
} from "@oidfed/core";
import { InvalidMetadata, InvalidSubordinateRecord } from "../errors.js";
import { parsePublishedSubordinateEvent } from "../utils/subordinate-event.js";
import { assertSubordinatePublicationClaims } from "../utils/subordinate-publication.js";
import {
	assertMetadataValuesNotNull,
	isFederationEntityOperationalField,
} from "../utils/subordinate-statement-shape.js";
import type {
	ListFilter,
	ListPage,
	ListPageOptions,
	StorageAdapter,
	StorageReadSnapshot,
	StorageTransaction,
	SubordinateEventStorage,
	SubordinateRecord,
	SubordinateRecordUpdate,
	SubordinateStorage,
	TrustMarkRecord,
	TrustMarkStorage,
} from "./types.js";

interface MemoryState {
	subordinateEvents?: Map<string, Map<string, SubordinateEvent[]>>;
	subordinates: Map<string, SubordinateRecord>;
	trustMarks?: Map<string, TrustMarkRecord>;
}

type StateReader = () => MemoryState;
type StateMutation = <T>(operation: (state: MemoryState) => T | Promise<T>) => Promise<T>;

const detached = <T>(value: T): T => structuredClone(value);

export function validateSubordinateRecord(record: SubordinateRecord): void {
	if (!isValidEntityId(record.entityId))
		throw new InvalidSubordinateRecord("Subordinate entityId must be a valid Entity Identifier");
	try {
		assertSubordinatePublicationClaims(record);
	} catch (error) {
		throw new InvalidSubordinateRecord(
			error instanceof Error ? error.message : "Invalid Subordinate Statement claims",
		);
	}
	const metadata = record.metadata;
	if (!metadata) return;
	const fed = (metadata as Record<string, unknown>).federation_entity;
	if (fed && typeof fed === "object" && !Array.isArray(fed)) {
		const offenders = Object.keys(fed as Record<string, unknown>).filter(
			isFederationEntityOperationalField,
		);
		if (offenders.length > 0) {
			throw new InvalidSubordinateRecord(
				`SubordinateRecord.metadata.federation_entity must not carry operational fields (these belong only in the subordinate's own Entity Configuration). Offending field(s): ${offenders.join(", ")}. Apply TrustAnchor.sanitizeSubordinateMetadata or Intermediate.sanitizeSubordinateMetadata before calling add().`,
			);
		}
	}
	try {
		assertMetadataValuesNotNull(metadata as Record<string, unknown>);
	} catch (error) {
		if (error instanceof InvalidMetadata) {
			throw new InvalidSubordinateRecord(
				`SubordinateRecord.metadata has a forbidden null value: ${error.message}`,
			);
		}
		throw error;
	}
}

function isValidTrustMark(record: TrustMarkRecord, validAt: number): boolean {
	const decoded = decodeEntityStatement(record.jwt);
	if (decoded.ok && decoded.value.payload.delegation !== undefined) {
		const delegation = decodeEntityStatement(decoded.value.payload.delegation as string);
		if (
			!delegation.ok ||
			!Number.isFinite(delegation.value.payload.iat) ||
			delegation.value.payload.iat > validAt ||
			(delegation.value.payload.exp !== undefined && delegation.value.payload.exp <= validAt)
		)
			return false;
	}
	// Federation §7.3: select currently eligible marks before choosing the newest.
	// Authority storage uses its exact clock, including same-second issuance.
	return (
		record.active &&
		Number.isFinite(record.issuedAt) &&
		record.issuedAt <= validAt &&
		(record.expiresAt === undefined || record.expiresAt > validAt)
	);
}

function compareStrings(left: string, right: string): number {
	return left < right ? -1 : left > right ? 1 : 0;
}

function trustMarkRecords(state: MemoryState): Map<string, TrustMarkRecord> {
	if (!state.trustMarks) throw new Error("Trust mark storage is not configured");
	return state.trustMarks;
}

class MemorySubordinateStorage implements SubordinateStorage {
	constructor(
		private readonly read: StateReader,
		private readonly mutate: StateMutation,
		private readonly clock?: Clock,
	) {}

	async get(entityId: EntityId): Promise<SubordinateRecord | undefined> {
		const record = this.read().subordinates.get(entityId);
		return record ? detached(record) : undefined;
	}

	async list(filter?: ListFilter, options?: ListPageOptions): Promise<ListPage> {
		let results = [...this.read().subordinates.values()];
		if (filter?.entityTypes?.length) {
			results = results.filter(
				(record) => record.entityTypes?.some((type) => filter.entityTypes?.includes(type)) ?? false,
			);
		}
		if (filter?.intermediate !== undefined) {
			results = results.filter(
				(record) => (record.isIntermediate ?? false) === filter.intermediate,
			);
		}
		// Federation §8.2.1 defines true; false is unspecified.
		// Here false adds no restriction; supplied mark types still filter.
		if (filter?.trustMarked === true || filter?.trustMarkType !== undefined) {
			if (filter.validAt === undefined) {
				throw new TypeError("validAt is required for trust mark filters");
			}
			const marks = this.read().trustMarks;
			if (!marks) throw new Error("Trust mark filtering is not supported by this adapter");
			const requestedTypes =
				typeof filter.trustMarkType === "string" ? [filter.trustMarkType] : filter.trustMarkType;
			results = results.filter((record) => {
				const valid = [...marks.values()].some(
					(mark) =>
						mark.subject === record.entityId &&
						(requestedTypes === undefined || requestedTypes.includes(mark.trustMarkType)) &&
						isValidTrustMark(mark, filter.validAt as number),
				);
				return valid;
			});
		}
		if (options?.updatedAfter !== undefined) {
			results = results.filter((record) => record.updatedAt >= (options.updatedAfter as number));
		}
		if (options?.updatedBefore !== undefined) {
			results = results.filter((record) => record.updatedAt <= (options.updatedBefore as number));
		}
		results.sort((a, b) => compareStrings(a.entityId, b.entityId));
		if (options?.cursor !== undefined) {
			results = results.filter((record) => record.entityId >= (options.cursor as EntityId));
		}
		const limit = options?.limit;
		if (limit !== undefined && results.length > limit) {
			const next = results[limit];
			return next
				? { items: detached(results.slice(0, limit)), nextCursor: next.entityId }
				: { items: detached(results.slice(0, limit)) };
		}
		return { items: detached(results) };
	}

	async add(record: SubordinateRecord): Promise<void> {
		// Capture before waiting for a preceding transaction; validate what is stored.
		const captured = detached(record);
		validateSubordinateRecord(captured);
		await this.mutate((state) => {
			if (state.subordinates.has(captured.entityId)) {
				throw new Error(`Subordinate '${captured.entityId}' already exists`);
			}
			state.subordinates.set(captured.entityId, captured);
		});
	}

	async update(entityId: EntityId, updates: SubordinateRecordUpdate): Promise<void> {
		const captured = detached(updates);
		await this.mutate((state) => {
			const existing = state.subordinates.get(entityId);
			if (!existing) throw new Error(`Subordinate '${entityId}' not found`);
			const updated = {
				...existing,
				...captured,
				entityId: existing.entityId,
				createdAt: existing.createdAt,
				updatedAt: nowSeconds(this.clock),
			};
			validateSubordinateRecord(updated);
			state.subordinates.set(entityId, updated);
		});
	}

	async remove(entityId: EntityId): Promise<void> {
		await this.mutate((state) => {
			if (!state.subordinates.delete(entityId)) {
				throw new Error(`Subordinate '${entityId}' not found`);
			}
		});
	}
}

class MemorySubordinateEventStorage implements SubordinateEventStorage {
	constructor(
		private readonly read: StateReader,
		private readonly mutate: StateMutation,
	) {}
	async append(
		issuer: EntityId,
		subject: EntityId,
		events: readonly SubordinateEvent[],
	): Promise<void> {
		const parsed = events.map(parsePublishedSubordinateEvent);
		await this.mutate((state) => {
			const history = state.subordinateEvents;
			if (!history) throw new Error("Subordinate event storage is not enabled");
			let subjects = history.get(issuer);
			if (!subjects) {
				subjects = new Map();
				history.set(issuer, subjects);
			}
			subjects.set(subject, [...(subjects.get(subject) ?? []), ...detached(parsed)]);
		});
	}
	async list(issuer: EntityId, subject: EntityId): Promise<readonly SubordinateEvent[]> {
		return detached(this.read().subordinateEvents?.get(issuer)?.get(subject) ?? []);
	}
}

export interface MemoryStorageAdapterOptions {
	readonly collections?: boolean;
	readonly subordinateEvents?: boolean;
	readonly trustMarks?: boolean;
	readonly clock?: Clock;
	readonly maxReplayEntries?: number;
	readonly maxCacheEntries?: number;
}

/** Development-only unified authority storage adapter. */
export class MemoryStorageAdapter implements StorageAdapter {
	readonly collections?: EntityCollectionStore;
	private state: MemoryState;
	private tail: Promise<void> = Promise.resolve();
	private readonly clock: Clock | undefined;
	readonly subordinates: SubordinateStorage;
	readonly trustMarks?: TrustMarkStorage;
	readonly subordinateEvents?: SubordinateEventStorage;
	readonly replay: MemoryReplayStore;
	readonly cache: MemoryCache;

	constructor(options?: MemoryStorageAdapterOptions) {
		this.clock = options?.clock;
		if (options?.collections)
			this.collections = new MemoryEntityCollectionStore({
				...(options.clock ? { clock: options.clock } : {}),
			});
		this.state = {
			subordinates: new Map(),
			...(options?.subordinateEvents ? { subordinateEvents: new Map() } : {}),
			...(options?.trustMarks ? { trustMarks: new Map() } : {}),
		};
		const mutate: StateMutation = (operation) => this.runExclusive(() => operation(this.state));
		this.subordinates = new MemorySubordinateStorage(() => this.state, mutate, this.clock);
		if (options?.trustMarks) {
			this.trustMarks = new MemoryTrustMarkStorage(
				() => trustMarkRecords(this.state),
				(op) => mutate((state) => op(trustMarkRecords(state))),
			);
		}
		if (options?.subordinateEvents)
			this.subordinateEvents = new MemorySubordinateEventStorage(() => this.state, mutate);
		this.replay = new MemoryReplayStore({
			...(options?.clock ? { clock: options.clock } : {}),
			...(options?.maxReplayEntries !== undefined ? { maxEntries: options.maxReplayEntries } : {}),
		});
		this.cache = new MemoryCache({
			...(options?.clock ? { clock: options.clock } : {}),
			...(options?.maxCacheEntries !== undefined ? { maxEntries: options.maxCacheEntries } : {}),
		});
	}

	/** Serialize the read with writes; clone only the requested records. */
	async readSnapshot<T>(operation: (snapshot: StorageReadSnapshot) => Promise<T>): Promise<T> {
		const events = this.subordinateEvents;
		return this.runExclusive(() =>
			operation({
				...(this.trustMarks
					? {
							trustMarks: {
								listCandidates: this.trustMarks.listCandidates.bind(this.trustMarks),
								getByJwt: this.trustMarks.getByJwt.bind(this.trustMarks),
							},
						}
					: {}),
				subordinates: {
					get: (id) => this.subordinates.get(id),
					list: (filter, options) => this.subordinates.list(filter, options),
				},
				...(events
					? {
							subordinateEvents: {
								list: (issuer: EntityId, subject: EntityId) => events.list(issuer, subject),
							},
						}
					: {}),
			}),
		);
	}

	async transaction<T>(operation: (tx: StorageTransaction) => Promise<T>): Promise<T> {
		return this.runExclusive(async () => {
			const draft = detached(this.state);
			const directMutation: StateMutation = async (mutate) => mutate(draft);
			const tx: StorageTransaction = {
				subordinates: new MemorySubordinateStorage(() => draft, directMutation, this.clock),
				...(draft.subordinateEvents
					? { subordinateEvents: new MemorySubordinateEventStorage(() => draft, directMutation) }
					: {}),
				...(draft.trustMarks
					? {
							trustMarks: new MemoryTrustMarkStorage(
								() => trustMarkRecords(draft),
								(op) => directMutation((state) => op(trustMarkRecords(state))),
							),
						}
					: {}),
			};
			const result = await operation(tx);
			this.state = draft;
			return result;
		});
	}

	private async runExclusive<T>(operation: () => Promise<T> | T): Promise<T> {
		const previous = this.tail;
		let release!: () => void;
		this.tail = new Promise<void>((resolve) => {
			release = resolve;
		});
		await previous;
		try {
			return await operation();
		} finally {
			release();
		}
	}
}
