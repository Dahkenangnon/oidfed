/** Shared handler context: signing keys, stores, and configuration for all endpoints. */
import type {
	EntityId,
	EntityType,
	FederationEntityMetadata,
	FederationOptions,
	ManagedFederationKeyProvider,
	TrustAnchorSet,
	TrustMarkOwner,
	TrustMarkRef,
} from "@oidfed/core";
import type { StorageAdapter } from "../storage/types.js";

export interface HandlerContext {
	/** The entity identifier (URL) for this authority. */
	readonly entityId: EntityId;
	/** Superior authorities this entity is subordinate to. */
	readonly authorityHints?: readonly [EntityId, ...EntityId[]];
	/** Federation-only signing key provider and lifecycle manager. */
	readonly keyProvider: ManagedFederationKeyProvider;
	/** Unified persistence adapter for all non-key authority state. */
	readonly storage: StorageAdapter;
	/** Metadata published in this authority's Entity Configuration. */
	readonly metadata: { federation_entity: FederationEntityMetadata } & Partial<
		Record<string, Record<string, unknown>>
	>;
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
