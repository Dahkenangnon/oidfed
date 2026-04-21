/** Storage interfaces for subordinate entity records, key material, and trust marks. */
import type { EntityId, EntityType, JWK, JWKSet, TrustChainConstraints } from "@oidfed/core";

export interface SubordinateStore {
	get(entityId: EntityId): Promise<SubordinateRecord | undefined>;
	list(filter?: ListFilter): Promise<SubordinateRecord[]>;
	add(record: SubordinateRecord): Promise<void>;
	update(entityId: EntityId, updates: Partial<SubordinateRecord>): Promise<void>;
	remove(entityId: EntityId): Promise<void>;
}

export interface SubordinateRecord {
	readonly entityId: EntityId;
	/** The subordinate's public keys, embedded in subordinate statements. */
	readonly jwks: JWKSet;
	/** Metadata overrides applied by this authority to the subordinate. */
	readonly metadata?: Readonly<Record<string, unknown>>;
	/** Metadata policy constraints applied during trust chain resolution. */
	readonly metadataPolicy?: Readonly<Record<string, unknown>>;
	/** Naming constraints limiting further subordination. */
	readonly constraints?: Readonly<TrustChainConstraints>;
	/** Entity types this subordinate is authorized to operate as. */
	readonly entityTypes?: ReadonlyArray<EntityType>;
	/** Whether this subordinate can itself act as an intermediate authority. */
	readonly isIntermediate?: boolean;
	/** The endpoint URL from which this record was originally fetched. */
	readonly sourceEndpoint?: string;
	readonly createdAt: number;
	readonly updatedAt: number;
}

export interface ListFilter {
	entityTypes?: EntityType[];
	trustMarked?: boolean;
	trustMarkType?: string;
	intermediate?: boolean;
}

export type KeyState = "pending" | "active" | "retiring" | "revoked";

export interface ManagedKey {
	readonly key: JWK;
	readonly state: KeyState;
	readonly createdAt?: number;
	/** Timestamp when the key became the active signing key. */
	readonly activatedAt?: number;
	/** Timestamp after which the key should no longer be used for signing. */
	readonly expiresAt?: number;
	/** Timestamp when a retiring key will be removed from the historical JWKS. */
	readonly scheduledRemovalAt?: number;
	readonly revokedAt?: number;
	readonly revocationReason?: string;
}

export interface KeyStore {
	getActiveKeys(): Promise<JWKSet>;
	getSigningKey(): Promise<ManagedKey>;
	getHistoricalKeys(): Promise<ManagedKey[]>;
	addKey(key: JWK): Promise<void>;
	activateKey(kid: string): Promise<void>;
	retireKey(kid: string, removeAfter: number): Promise<void>;
	revokeKey(kid: string, reason: string): Promise<void>;
}

export interface TrustMarkStore {
	get(trustMarkType: string, subject: EntityId): Promise<TrustMarkRecord | undefined>;
	list(
		trustMarkType: string,
		options?: { sub?: EntityId; cursor?: string; limit?: number },
	): Promise<{ items: TrustMarkRecord[]; nextCursor?: string }>;
	issue(record: TrustMarkRecord): Promise<void>;
	revoke(trustMarkType: string, subject: EntityId): Promise<void>;
	isActive(trustMarkType: string, subject: EntityId): Promise<boolean>;
	hasAnyActive(subject: EntityId): Promise<boolean>;
}

export interface TrustMarkRecord {
	/** The trust mark type URI (e.g., "https://example.com/trust-mark/verified"). */
	readonly trustMarkType: string;
	/** The entity this trust mark was issued to. */
	readonly subject: EntityId;
	/** The signed trust mark JWT. */
	readonly jwt: string;
	readonly issuedAt: number;
	readonly expiresAt?: number;
	/** Whether this trust mark is currently valid (false if revoked). */
	readonly active: boolean;
}
