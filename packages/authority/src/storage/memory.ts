import type { Clock, EntityId } from "@oidfed/core";
import { nowSeconds } from "@oidfed/core";
import { InvalidMetadata, InvalidSubordinateRecord } from "../errors.js";
import {
	assertMetadataValuesNotNull,
	isFederationEntityOperationalField,
} from "../utils/subordinate-statement-shape.js";
import type {
	ListFilter,
	ListPage,
	ListPageOptions,
	SubordinateRecord,
	SubordinateStore,
	TrustMarkRecord,
	TrustMarkStore,
} from "./types.js";

/**
 * Validates a SubordinateRecord against the shape rules a Subordinate Statement
 * must satisfy. Throws InvalidSubordinateRecord on:
 *   - metadata.federation_entity carrying any operational claim (endpoint URLs,
 *     their _auth_methods companions, or endpoint_auth_signing_alg_values_supported)
 *   - any null leaf value in metadata at any depth
 *
 * Other metadata blocks (openid_relying_party, openid_provider, oauth_*, ...)
 * pass through unchanged. Callers that synthesize records from raw entity
 * metadata should first run their input through `sanitizeSubordinateMetadata`.
 */
export function validateSubordinateRecord(record: SubordinateRecord): void {
	const metadata = record.metadata;
	if (!metadata) return;
	const fed = (metadata as Record<string, unknown>).federation_entity;
	if (fed && typeof fed === "object" && !Array.isArray(fed)) {
		const offenders: string[] = [];
		for (const key of Object.keys(fed as Record<string, unknown>)) {
			if (isFederationEntityOperationalField(key)) offenders.push(key);
		}
		if (offenders.length > 0) {
			throw new InvalidSubordinateRecord(
				`SubordinateRecord.metadata.federation_entity must not carry operational fields (these belong only in the subordinate's own Entity Configuration). Offending field(s): ${offenders.join(", ")}. Apply sanitizeSubordinateMetadata before calling add().`,
			);
		}
	}
	try {
		assertMetadataValuesNotNull(metadata as Record<string, unknown>);
	} catch (err) {
		if (err instanceof InvalidMetadata) {
			throw new InvalidSubordinateRecord(
				`SubordinateRecord.metadata has a null leaf value: ${err.message}`,
			);
		}
		throw err;
	}
}

/**
 * In-memory implementation of the subordinate entity store.
 *
 * **WARNING: Development and testing only.** All data is lost on process restart.
 * For production, implement {@link SubordinateStore} with a persistent backend
 * (PostgreSQL, SQLite, etc.). See `docs/storage-guide.md` for guidance.
 */
export interface MemorySubordinateStoreOptions {
	readonly clock?: Clock;
}

export class MemorySubordinateStore implements SubordinateStore {
	private readonly records = new Map<string, SubordinateRecord>();
	private readonly clock: Clock | undefined;

	constructor(options?: MemorySubordinateStoreOptions) {
		this.clock = options?.clock;
	}

	async get(entityId: EntityId): Promise<SubordinateRecord | undefined> {
		return this.records.get(entityId);
	}

	async list(filter?: ListFilter, options?: ListPageOptions): Promise<ListPage> {
		let results = Array.from(this.records.values());

		if (filter?.entityTypes && filter.entityTypes.length > 0) {
			const ets = filter.entityTypes;
			results = results.filter((r) => r.entityTypes?.some((t) => ets.includes(t)) ?? false);
		}

		if (filter?.intermediate !== undefined) {
			results = results.filter((r) => (r.isIntermediate ?? false) === filter.intermediate);
		}

		if (options?.updatedAfter !== undefined) {
			const after = options.updatedAfter;
			results = results.filter((r) => r.updatedAt >= after);
		}

		if (options?.updatedBefore !== undefined) {
			const before = options.updatedBefore;
			results = results.filter((r) => r.updatedAt <= before);
		}

		results.sort((a, b) => (a.entityId < b.entityId ? -1 : a.entityId > b.entityId ? 1 : 0));

		if (options?.cursor !== undefined) {
			const cursor = options.cursor;
			results = results.filter((r) => r.entityId >= cursor);
		}

		const limit = options?.limit;
		if (limit !== undefined && results.length > limit) {
			const items = results.slice(0, limit);
			const next = results[limit];
			return next !== undefined ? { items, nextCursor: next.entityId } : { items };
		}

		return { items: results };
	}

	async add(record: SubordinateRecord): Promise<void> {
		validateSubordinateRecord(record);
		if (this.records.has(record.entityId)) {
			throw new Error(`Subordinate '${record.entityId}' already exists`);
		}
		this.records.set(record.entityId, record);
	}

	async update(entityId: EntityId, updates: Partial<SubordinateRecord>): Promise<void> {
		const existing = this.records.get(entityId);
		if (!existing) {
			throw new Error(`Subordinate '${entityId}' not found`);
		}
		this.records.set(entityId, {
			...existing,
			...updates,
			entityId: existing.entityId,
			updatedAt: nowSeconds(this.clock),
		});
	}

	async remove(entityId: EntityId): Promise<void> {
		if (!this.records.has(entityId)) {
			throw new Error(`Subordinate '${entityId}' not found`);
		}
		this.records.delete(entityId);
	}
}

/**
 * In-memory implementation of the trust mark store.
 *
 * **WARNING: Development and testing only.** Trust mark revocations are lost on
 * process restart, meaning revoked trust marks will appear valid again.
 * For production, implement {@link TrustMarkStore} with a persistent backend.
 * See `docs/storage-guide.md`.
 */
export class MemoryTrustMarkStore implements TrustMarkStore {
	private readonly records = new Map<string, TrustMarkRecord>();

	private compositeKey(type: string, subject: string): string {
		return `${type}\0${subject}`;
	}

	async get(trustMarkType: string, subject: EntityId): Promise<TrustMarkRecord | undefined> {
		return this.records.get(this.compositeKey(trustMarkType, subject));
	}

	async list(
		trustMarkType: string,
		options?: {
			sub?: EntityId;
			cursor?: string;
			limit?: number;
		},
	): Promise<{ items: TrustMarkRecord[]; nextCursor?: string }> {
		const items: TrustMarkRecord[] = [];
		for (const record of this.records.values()) {
			if (record.trustMarkType !== trustMarkType) continue;
			if (options?.sub && record.subject !== options.sub) continue;
			items.push(record);
		}

		const limit = options?.limit ?? 100;
		const startIndex = options?.cursor ? parseInt(options.cursor, 10) : 0;
		const sliced = items.slice(startIndex, startIndex + limit);
		const nextIndex = startIndex + limit;

		if (nextIndex < items.length) {
			return { items: sliced, nextCursor: String(nextIndex) };
		}
		return { items: sliced };
	}

	async issue(record: TrustMarkRecord): Promise<void> {
		this.records.set(this.compositeKey(record.trustMarkType, record.subject), record);
	}

	async revoke(trustMarkType: string, subject: EntityId): Promise<void> {
		const key = this.compositeKey(trustMarkType, subject);
		const record = this.records.get(key);
		if (!record) {
			throw new Error(`Trust mark '${trustMarkType}' for '${subject}' not found`);
		}
		this.records.set(key, { ...record, active: false });
	}

	async isActive(trustMarkType: string, subject: EntityId): Promise<boolean> {
		const record = this.records.get(this.compositeKey(trustMarkType, subject));
		return record?.active ?? false;
	}

	async hasAnyActive(subject: EntityId): Promise<boolean> {
		for (const record of this.records.values()) {
			if (record.subject === subject && record.active) {
				return true;
			}
		}
		return false;
	}

	async listForSubject(subject: EntityId): Promise<TrustMarkRecord[]> {
		const out: TrustMarkRecord[] = [];
		for (const record of this.records.values()) {
			if (record.subject === subject && record.active) out.push(record);
		}
		return out;
	}
}
