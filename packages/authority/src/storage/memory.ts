import type { EntityId, JWK, JWKSet } from "@oidfed/core";
import { stripPrivateFields } from "../endpoints/helpers.js";
import type {
	KeyStore,
	ListFilter,
	ManagedKey,
	SubordinateRecord,
	SubordinateStore,
	TrustMarkRecord,
	TrustMarkStore,
} from "./types.js";

/**
 * In-memory implementation of the subordinate entity store.
 *
 * **WARNING: Development and testing only.** All data is lost on process restart.
 * For production, implement {@link SubordinateStore} with a persistent backend
 * (PostgreSQL, SQLite, etc.). See `docs/storage-guide.md` for guidance.
 */
export class MemorySubordinateStore implements SubordinateStore {
	private readonly records = new Map<string, SubordinateRecord>();

	async get(entityId: EntityId): Promise<SubordinateRecord | undefined> {
		return this.records.get(entityId);
	}

	async list(filter?: ListFilter): Promise<SubordinateRecord[]> {
		let results = Array.from(this.records.values());

		if (filter?.entityTypes && filter.entityTypes.length > 0) {
			const ets = filter.entityTypes;
			results = results.filter((r) => r.entityTypes?.some((t) => ets.includes(t)) ?? false);
		}

		if (filter?.intermediate !== undefined) {
			results = results.filter((r) => (r.isIntermediate ?? false) === filter.intermediate);
		}

		return results;
	}

	async add(record: SubordinateRecord): Promise<void> {
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
			updatedAt: Date.now(),
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
 * In-memory implementation of the signing key store with lifecycle management.
 *
 * **WARNING: Development and testing only.** All key material and lifecycle state
 * is lost on process restart. Historical keys needed for trust chain verification
 * will disappear. For production, implement {@link KeyStore} backed by a secrets
 * manager (HashiCorp Vault, AWS KMS) or encrypted database. See `docs/storage-guide.md`.
 */
export class MemoryKeyStore implements KeyStore {
	private readonly keys = new Map<string, ManagedKey>();

	/**
	 * Creates a new in-memory key store.
	 * @param initialKeys - Optional key or array of keys to add and activate immediately.
	 *   Each key MUST have a `kid`. Keys are activated in order; the last key becomes
	 *   the current signing key (most recently activated).
	 */
	constructor(initialKeys?: JWK | JWK[]) {
		if (initialKeys) {
			const keysArray = Array.isArray(initialKeys) ? initialKeys : [initialKeys];
			const now = Date.now();
			for (let i = 0; i < keysArray.length; i++) {
				const key = keysArray[i] as JWK;
				if (!key.kid) {
					throw new Error("Initial key must have a kid");
				}
				if (this.keys.has(key.kid)) {
					throw new Error(`Duplicate kid '${key.kid}' in initial keys`);
				}
				this.keys.set(key.kid, {
					key,
					state: "active",
					createdAt: now,
					activatedAt: now + i, // Preserve insertion order for getSigningKey()
				});
			}
		}
	}

	async addKey(key: JWK): Promise<void> {
		if (!key.kid) {
			throw new Error("Key must have a kid");
		}
		if (this.keys.has(key.kid)) {
			throw new Error(`Key '${key.kid}' already exists`);
		}
		this.keys.set(key.kid, { key, state: "pending", createdAt: Date.now() });
	}

	async activateKey(kid: string): Promise<void> {
		const managed = this.keys.get(kid);
		if (!managed) {
			throw new Error(`Key '${kid}' not found`);
		}
		if (managed.state !== "pending") {
			throw new Error(`Key '${kid}' is in state '${managed.state}', expected 'pending'`);
		}
		this.keys.set(kid, {
			...managed,
			state: "active",
			activatedAt: Date.now(),
		});
	}

	async getActiveKeys(): Promise<JWKSet> {
		const keys: JWK[] = [];
		for (const managed of this.keys.values()) {
			if (managed.state === "active" || managed.state === "retiring") {
				keys.push(stripPrivateFields(managed.key));
			}
		}
		return { keys };
	}

	async getSigningKey(): Promise<ManagedKey> {
		let latest: ManagedKey | undefined;
		for (const managed of this.keys.values()) {
			if (managed.state === "active") {
				if (!latest || (managed.activatedAt ?? 0) > (latest.activatedAt ?? 0)) {
					latest = managed;
				}
			}
		}
		if (!latest) {
			throw new Error("No active signing key available");
		}
		return latest;
	}

	async retireKey(kid: string, removeAfter: number): Promise<void> {
		const managed = this.keys.get(kid);
		if (!managed) {
			throw new Error(`Key '${kid}' not found`);
		}
		if (managed.state !== "active") {
			throw new Error(`Key '${kid}' is in state '${managed.state}', expected 'active'`);
		}
		this.keys.set(kid, {
			...managed,
			state: "retiring",
			scheduledRemovalAt: removeAfter,
		});
	}

	async revokeKey(kid: string, reason: string): Promise<void> {
		const managed = this.keys.get(kid);
		if (!managed) {
			throw new Error(`Key '${kid}' not found`);
		}
		this.keys.set(kid, {
			...managed,
			state: "revoked",
			revokedAt: Date.now(),
			revocationReason: reason,
		});
	}

	async getHistoricalKeys(): Promise<ManagedKey[]> {
		return Array.from(this.keys.values());
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
}
