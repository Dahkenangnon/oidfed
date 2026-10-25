import type { Result } from "../errors.js";
import type { ReplayStore } from "../replay-store.js";
import type { EntityCollectionEntity } from "../schemas/entity-collection.js";
import type { JWKSet } from "../schemas/jwk.js";
import type { Clock, EntityId, FederationOptions, TrustAnchorSet } from "../types.js";

/** Evidence is local server state; it is never returned as collection data. */
export interface CollectionEntry {
	entity: EntityCollectionEntity;
	/** Application or collector eligibility deadline, in seconds since the epoch. */
	expiresAt: number;
	/** Present only when core collected a valid chain for this entry. */
	chainExpiresAt?: number;
	verifiedMarks: readonly { type: string; expiresAt: number }[];
}
export interface EntityCollectionSnapshot {
	id: string;
	trustAnchor: EntityId;
	lastUpdated: number;
	entries: readonly CollectionEntry[];
}
export interface EntityCollectionCursor {
	snapshotId: string;
	trustAnchor: EntityId;
	context: string;
	index: number;
	expiresAt: number;
}
/** Implementations must atomically publish snapshots and return detached values. */
export interface EntityCollectionStore {
	publish(snapshot: EntityCollectionSnapshot): Promise<void>;
	getCurrent(trustAnchor: EntityId): Promise<EntityCollectionSnapshot | undefined>;
	getSnapshot(id: string): Promise<EntityCollectionSnapshot | undefined>;
	putCursor(id: string, cursor: EntityCollectionCursor): Promise<void>;
	getCursor(id: string): Promise<EntityCollectionCursor | undefined>;
}
export interface CollectionAuthentication {
	replayStore?: ReplayStore;
	methods: readonly ("none" | "private_key_jwt")[];
	/** Receiver identity used as assertion audience, including standalone providers. */
	receiverEntityId?: EntityId;
	getClientFederationJwks?: (client: EntityId) => Promise<JWKSet | undefined>;
	allowedAlgorithms?: readonly string[];
}
/** Informational input from an application-owned collector; core verifies mark evidence. */
export interface EntityCollectionCandidate {
	entity: EntityCollectionEntity;
	expiresAt: number;
}

/** Refresh context; network calls through options share the refresh limits and cancellation. */
export interface EntityCollectionCollectorContext {
	readonly trustAnchor: EntityId;
	readonly trustAnchorJwks: JWKSet;
	readonly options: Readonly<FederationOptions>;
	readonly signal: AbortSignal;
}

/** Return the complete candidate set; failures leave the previously published snapshot intact. */
export type EntityCollectionCollector = (
	context: EntityCollectionCollectorContext,
) => Promise<Result<readonly EntityCollectionCandidate[]>>;

/** Run once per entry during refresh; an explicit deadline can only shorten eligibility. */
export type EntityCollectionFilter = (
	entry: Readonly<CollectionEntry>,
	context: EntityCollectionCollectorContext,
) => boolean | { expiresAt: number } | Promise<boolean | { expiresAt: number }>;

export interface EntityCollectionConfig {
	trustAnchors: TrustAnchorSet;
	/** Defaults to core's validated federation traversal. */
	collector?: EntityCollectionCollector;
	/** Additional snapshot-time restriction, applied after mark verification. */
	filter?: EntityCollectionFilter;
	/** Optional serving URL, including fixed query components. */
	endpoint?: string;
	store?: EntityCollectionStore;
	responder?: { entityId: EntityId; isTrustAnchor: boolean };
	authentication?: CollectionAuthentication;
	options?: FederationOptions;
	maxPageSize?: number;
	cursorTtlSeconds?: number;
	maxEntities?: number;
	/** Additional claims supported by a custom snapshot producer. */
	entityClaims?: readonly string[];
	infoClaims?: readonly string[];
}
export interface CollectionRefreshOptions {
	signal?: AbortSignal;
}
export interface CollectionRefreshResult {
	snapshotId: string;
	lastUpdated: number;
	entityCount: number;
}
/** Optional integration; responder identity always comes from its hosting class. */
export type EntityCollectionIntegration = Omit<EntityCollectionConfig, "responder">;
export interface MemoryEntityCollectionStoreOptions {
	clock?: Clock;
	retentionSeconds?: number;
	maxSnapshots?: number;
	maxCursors?: number;
}
