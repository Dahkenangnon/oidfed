/** Shared handler context: signing keys, stores, and configuration for all endpoints. */
import type {
	EntityId,
	EntityStatementMetadata,
	EntityType,
	FederationEntityMetadata,
	FederationKeyLifecycleProvider,
	FederationOptions,
	JWKSet,
	TrustAnchorSet,
	TrustMarkOwner,
	TrustMarkRef,
} from "@oidfed/core";
import type { StorageAdapter } from "../storage/types.js";

/** Resolves public Federation Entity Keys for authenticated authority endpoint clients. */
export interface AuthorityClientKeyProvider {
	getClientFederationJwks(entityId: EntityId): Promise<JWKSet | undefined>;
}

export interface HandlerContext {
	/** The entity identifier (URL) for this authority. */
	readonly entityId: EntityId;
	/** Superior authorities this entity is subordinate to. */
	readonly authorityHints?: readonly [EntityId, ...EntityId[]];
	/** Preferred trust anchors this entity hints to resolvers in its Entity Configuration. */
	readonly trustAnchorHints?: readonly [EntityId, ...EntityId[]];
	/** Federation-only signing key provider and lifecycle manager. */
	readonly keyProvider: FederationKeyLifecycleProvider;
	/** Unified persistence adapter for all non-key authority state. */
	readonly storage: StorageAdapter;
	/** Resolves remote client Federation Entity Keys for private_key_jwt endpoint auth. */
	readonly clientKeyProvider: AuthorityClientKeyProvider;
	/** Metadata published in this authority's Entity Configuration. */
	readonly metadata: EntityStatementMetadata & {
		readonly federation_entity: FederationEntityMetadata;
	};
	/** Trust marks this authority claims about itself. */
	readonly trustMarks?: ReadonlyArray<TrustMarkRef>;
	/** Mapping of trust mark type → authorized issuer entity IDs. */
	readonly trustMarkIssuers?: Record<string, string[]>;
	/** Mapping of trust mark type → owner declaration. */
	readonly trustMarkOwners?: Record<string, TrustMarkOwner>;
	/** Pre-signed trust mark delegation JWTs, keyed by trust mark type. */
	readonly trustMarkDelegations?: Record<string, string>;
	/** Trust anchors for trust chain resolution. */
	readonly trustAnchors?: TrustAnchorSet;
	/** Federation-wide options (httpClient, clock, etc.). */
	readonly options?: FederationOptions;
	/** TTL in seconds for the Entity Configuration JWT. */
	readonly entityConfigurationTtlSeconds?: number;
	/** TTL in seconds for subordinate statement JWTs. */
	readonly subordinateStatementTtlSeconds?: number;
	/** TTL in seconds for issued trust mark JWTs. */
	readonly trustMarkTtlSeconds?: number;
	/**
	 * Optional callback returning a previously signed Resolve Response JWT for the
	 * given subject + trust anchors + entity types. When supplied and a JWT is
	 * returned, the resolve handler serves it directly without invoking fresh
	 * trust-chain resolution. Returning `undefined` indicates a cache miss.
	 */
	readonly cachedResolutionLookup?: (
		sub: EntityId,
		trustAnchors: readonly EntityId[],
		entityTypes: readonly EntityType[],
	) => Promise<string | undefined>;
	/**
	 * When true, unauthenticated callers (those whose request lacks a valid
	 * `X-Authenticated-Entity` header) cannot trigger fresh trust-chain
	 * resolution after a cache miss; the resolve handler returns a `not_found`
	 * response instead. Authenticated callers are unaffected. Default: false.
	 */
	readonly requireAuthForFreshResolution?: boolean;
}
