import type { ReplayStore } from "../replay-store.js";
import type { EntityCollectionEntity } from "../schemas/entity-collection.js";
import type { JWKSet } from "../schemas/jwk.js";
import type { Clock, EntityId, FederationOptions, TrustAnchorSet } from "../types.js";

/** Evidence is local server state; it is never returned as collection data. */
export interface CollectionEntry {
	entity: EntityCollectionEntity;
	chainExpiresAt: number;
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
export interface EntityCollectionConfig {
	trustAnchors: TrustAnchorSet;
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
