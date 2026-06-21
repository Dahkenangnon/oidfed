import {
	type Clock,
	type EntityId,
	MemoryCache,
	MemoryReplayStore,
	nowSeconds,
} from "@oidfed/core";
import { InvalidMetadata, InvalidSubordinateRecord } from "../errors.js";
import {
	assertMetadataValuesNotNull,
	isFederationEntityOperationalField,
} from "../utils/subordinate-statement-shape.js";
import type {
	ListFilter,
	ListPage,
	ListPageOptions,
	StorageAdapter,
	StorageTransaction,
	SubordinateRecord,
	SubordinateRecordUpdate,
	SubordinateStorage,
	TrustMarkListOptions,
	TrustMarkListPage,
	TrustMarkRecord,
	TrustMarkStorage,
} from "./types.js";

interface MemoryState {
	subordinates: Map<string, SubordinateRecord>;
	trustMarks?: Map<string, TrustMarkRecord>;
}

type StateReader = () => MemoryState;
type StateMutation = <T>(operation: (state: MemoryState) => T | Promise<T>) => Promise<T>;

const detached = <T>(value: T): T => structuredClone(value);

export function validateSubordinateRecord(record: SubordinateRecord): void {
	const metadata = record.metadata;
	if (!metadata) return;
	const fed = (metadata as Record<string, unknown>).federation_entity;
	if (fed && typeof fed === "object" && !Array.isArray(fed)) {
		const offenders = Object.keys(fed as Record<string, unknown>).filter(
			isFederationEntityOperationalField,
		);
		if (offenders.length > 0) {
			throw new InvalidSubordinateRecord(
				`SubordinateRecord.metadata.federation_entity must not carry operational fields (these belong only in the subordinate's own Entity Configuration). Offending field(s): ${offenders.join(", ")}. Apply sanitizeSubordinateMetadata before calling add().`,
			);
		}
	}
	try {
		assertMetadataValuesNotNull(metadata as Record<string, unknown>);
	} catch (error) {
		if (error instanceof InvalidMetadata) {
			throw new InvalidSubordinateRecord(
				`SubordinateRecord.metadata has a null leaf value: ${error.message}`,
			);
		}
		throw error;
	}
}

function isValidTrustMark(record: TrustMarkRecord, validAt: number): boolean {
	return record.active && (record.expiresAt === undefined || record.expiresAt > validAt);
}

function compareStrings(left: string, right: string): number {
	return left < right ? -1 : left > right ? 1 : 0;
}

function isNewerTrustMark(candidate: TrustMarkRecord, current: TrustMarkRecord): boolean {
	return (
		candidate.issuedAt > current.issuedAt ||
		(candidate.issuedAt === current.issuedAt && compareStrings(candidate.jwt, current.jwt) > 0)
	);
}

function latestBySubject(records: TrustMarkRecord[]): TrustMarkRecord[] {
	const latest = new Map<string, TrustMarkRecord>();
	for (const record of records) {
		const existing = latest.get(record.subject);
		if (!existing || isNewerTrustMark(record, existing)) latest.set(record.subject, record);
	}
	return [...latest.values()];
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
		if (filter?.trustMarked !== undefined || filter?.trustMarkType !== undefined) {
			if (filter.validAt === undefined) {
				throw new TypeError("validAt is required for trust mark filters");
			}
			const marks = this.read().trustMarks;
			if (!marks) throw new Error("Trust mark filtering is not supported by this adapter");
			results = results.filter((record) => {
				const valid = [...marks.values()].some(
					(mark) =>
						mark.subject === record.entityId &&
						(filter.trustMarkType === undefined || mark.trustMarkType === filter.trustMarkType) &&
						isValidTrustMark(mark, filter.validAt as number),
				);
				return filter.trustMarked === false ? !valid : valid;
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
		validateSubordinateRecord(record);
		await this.mutate((state) => {
			if (state.subordinates.has(record.entityId)) {
				throw new Error(`Subordinate '${record.entityId}' already exists`);
			}
			state.subordinates.set(record.entityId, detached(record));
		});
	}

	async update(entityId: EntityId, updates: SubordinateRecordUpdate): Promise<void> {
		await this.mutate((state) => {
			const existing = state.subordinates.get(entityId);
			if (!existing) throw new Error(`Subordinate '${entityId}' not found`);
			const updated = {
				...existing,
				...detached(updates),
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

class MemoryTrustMarkStorage implements TrustMarkStorage {
	constructor(
		private readonly read: StateReader,
		private readonly mutate: StateMutation,
	) {}

	private records(): Map<string, TrustMarkRecord> {
		const records = this.read().trustMarks;
		if (!records) throw new Error("Trust mark storage is not enabled");
		return records;
	}

	async getValid(
		trustMarkType: string,
		subject: EntityId,
		validAt: number,
	): Promise<TrustMarkRecord | undefined> {
		const records = [...this.records().values()]
			.filter(
				(record) =>
					record.trustMarkType === trustMarkType &&
					record.subject === subject &&
					isValidTrustMark(record, validAt),
			)
			.sort((a, b) =>
				a.issuedAt === b.issuedAt ? compareStrings(b.jwt, a.jwt) : b.issuedAt - a.issuedAt,
			);
		return records[0] ? detached(records[0]) : undefined;
	}

	async getByJwt(jwt: string): Promise<TrustMarkRecord | undefined> {
		const record = this.records().get(jwt);
		return record ? detached(record) : undefined;
	}

	async listValid(
		trustMarkType: string,
		validAt: number,
		options: TrustMarkListOptions,
	): Promise<TrustMarkListPage> {
		if (!Number.isSafeInteger(options.limit) || options.limit <= 0) {
			throw new RangeError("limit must be a positive safe integer");
		}
		let records = latestBySubject(
			[...this.records().values()].filter(
				(record) =>
					record.trustMarkType === trustMarkType &&
					(options.subject === undefined || record.subject === options.subject) &&
					isValidTrustMark(record, validAt),
			),
		).sort((a, b) => compareStrings(a.subject, b.subject));
		if (options.cursor !== undefined) {
			records = records.filter((record) => record.subject >= (options.cursor as EntityId));
		}
		if (records.length > options.limit) {
			const next = records[options.limit];
			return next
				? { items: detached(records.slice(0, options.limit)), nextCursor: next.subject }
				: { items: detached(records.slice(0, options.limit)) };
		}
		return { items: detached(records) };
	}

	async listValidForSubject(subject: EntityId, validAt: number): Promise<TrustMarkRecord[]> {
		const records = [...this.records().values()].filter(
			(record) => record.subject === subject && isValidTrustMark(record, validAt),
		);
		const latest = new Map<string, TrustMarkRecord>();
		for (const record of records) {
			const existing = latest.get(record.trustMarkType);
			if (!existing || isNewerTrustMark(record, existing)) {
				latest.set(record.trustMarkType, record);
			}
		}
		return detached(
			[...latest.values()].sort((a, b) => compareStrings(a.trustMarkType, b.trustMarkType)),
		);
	}

	async hasAnyValid(subject: EntityId, validAt: number): Promise<boolean> {
		return [...this.records().values()].some(
			(record) => record.subject === subject && isValidTrustMark(record, validAt),
		);
	}

	async issue(record: TrustMarkRecord): Promise<void> {
		await this.mutate((state) => {
			const records = state.trustMarks;
			if (!records) throw new Error("Trust mark storage is not enabled");
			if (!records.has(record.jwt)) records.set(record.jwt, detached(record));
		});
	}

	async revoke(trustMarkType: string, subject: EntityId, revokedAt: number): Promise<void> {
		await this.mutate((state) => {
			const records = state.trustMarks;
			if (!records) throw new Error("Trust mark storage is not enabled");
			let found = false;
			for (const [jwt, record] of records) {
				if (record.trustMarkType === trustMarkType && record.subject === subject && record.active) {
					records.set(jwt, { ...record, active: false, revokedAt });
					found = true;
				}
			}
			if (!found) throw new Error(`Trust mark '${trustMarkType}' for '${subject}' not found`);
		});
	}
}

export interface MemoryStorageAdapterOptions {
	readonly trustMarks?: boolean;
	readonly clock?: Clock;
	readonly maxReplayEntries?: number;
	readonly maxCacheEntries?: number;
}

/** Development-only unified authority storage adapter. */
export class MemoryStorageAdapter implements StorageAdapter {
	private state: MemoryState;
	private tail: Promise<void> = Promise.resolve();
	private readonly clock: Clock | undefined;
	readonly subordinates: SubordinateStorage;
	readonly trustMarks?: TrustMarkStorage;
	readonly replay: MemoryReplayStore;
	readonly cache: MemoryCache;

	constructor(options?: MemoryStorageAdapterOptions) {
		this.clock = options?.clock;
		this.state = {
			subordinates: new Map(),
			...(options?.trustMarks ? { trustMarks: new Map() } : {}),
		};
		const mutate: StateMutation = (operation) => this.runExclusive(() => operation(this.state));
		this.subordinates = new MemorySubordinateStorage(() => this.state, mutate, this.clock);
		if (options?.trustMarks) {
			this.trustMarks = new MemoryTrustMarkStorage(() => this.state, mutate);
		}
		this.replay = new MemoryReplayStore({
			...(options?.clock ? { clock: options.clock } : {}),
			...(options?.maxReplayEntries !== undefined ? { maxEntries: options.maxReplayEntries } : {}),
		});
		const clock = options?.clock;
		const cacheClock = clock ? { now: () => clock.now() * 1_000 } : undefined;
		this.cache = new MemoryCache({
			...(cacheClock ? { clock: cacheClock } : {}),
			...(options?.maxCacheEntries !== undefined ? { maxEntries: options.maxCacheEntries } : {}),
		});
	}

	async transaction<T>(operation: (tx: StorageTransaction) => Promise<T>): Promise<T> {
		return this.runExclusive(async () => {
			const draft = detached(this.state);
			const directMutation: StateMutation = async (mutate) => mutate(draft);
			const tx: StorageTransaction = {
				subordinates: new MemorySubordinateStorage(() => draft, directMutation, this.clock),
				...(draft.trustMarks
					? { trustMarks: new MemoryTrustMarkStorage(() => draft, directMutation) }
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
