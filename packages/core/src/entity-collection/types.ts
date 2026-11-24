/** Storage, collection, authentication, and query contracts for Entity Collection services. */

import type { EndpointAuthentication } from "../endpoint-authentication.js";
import type { Result } from "../errors.js";
import type { EntityCollectionEntity } from "../schemas/entity-collection.js";
import type { JWKSet } from "../schemas/jwk.js";
import type { CollectionEntry } from "../storage/collection.js";
import type { EntityId, FederationOptions, TrustAnchorSet } from "../types.js";

export interface CollectionAuthentication {
	extensions?: EndpointAuthentication;
	methods: readonly string[];
	/** Receiver identity used as assertion audience, including standalone providers. */
	receiverEntityId?: EntityId;
	getClientFederationJwks?: (client: EntityId) => Promise<JWKSet | undefined>;
	allowedAlgorithms?: readonly string[];
	/** Algorithms published by a host in its Federation metadata. */
	advertisedAlgorithms?: readonly string[];
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

/** Return the complete candidate set; a failed refresh leaves the published snapshot in place. */
export type EntityCollectionCollector = (
	context: EntityCollectionCollectorContext,
) => Promise<Result<readonly EntityCollectionCandidate[]>>;

/** Run once per entry during refresh; an explicit deadline can only shorten eligibility. */
export type EntityCollectionFilter = (
	entry: Readonly<CollectionEntry>,
	context: EntityCollectionCollectorContext,
) => boolean | { expiresAt: number } | Promise<boolean | { expiresAt: number }>;

/** Local, synchronous search. Return the same decision for a fixed query and snapshot. */
export type EntityCollectionQueryMatcher = (
	query: string,
	entity: Readonly<EntityCollectionEntity>,
) => boolean;

export interface EntityCollectionConfig {
	trustAnchors: TrustAnchorSet;
	/** Defaults to core's validated federation traversal. */
	collector?: EntityCollectionCollector;
	/** Additional snapshot-time restriction, applied after mark verification. */
	filter?: EntityCollectionFilter;
	/** Defaults to case-insensitive substring matching. Receives deeply frozen, detached data. */
	queryMatcher?: EntityCollectionQueryMatcher;
	/** Optional serving URL, including fixed query components. */
	endpoint?: string;
	responder?: { entityId: EntityId; isTrustAnchor: boolean };
	authentication?: CollectionAuthentication;
	options: FederationOptions;
	maxPageSize?: number;
	cursorTtlSeconds?: number;
	maxEntities?: number;
	/** Additional claims supported by a custom snapshot producer. */
	entityClaims?: readonly string[];
	infoClaims?: readonly string[];
	/** Defaults used only when the request omits the corresponding selector. */
	defaultEntityClaims?: readonly string[];
	defaultInfoClaims?: readonly string[];
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
export type EntityCollectionIntegration = Omit<EntityCollectionConfig, "responder" | "options"> & {
	readonly options?: import("../types.js").BoundFederationOptions;
};
