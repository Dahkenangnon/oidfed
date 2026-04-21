/** Shared handler context: signing keys, stores, and configuration for all endpoints. */
import type {
	EntityId,
	FederationEntityMetadata,
	FederationOptions,
	JtiStore,
	JWK,
	RegistrationProtocolAdapter,
	TrustAnchorSet,
	TrustMarkOwner,
	TrustMarkRef,
} from "@oidfed/core";
import type { KeyStore, SubordinateStore, TrustMarkStore } from "../storage/types.js";

export interface HandlerContext {
	/** The entity identifier (URL) for this authority. */
	readonly entityId: EntityId;
	/** Superior authorities this entity is subordinate to. */
	readonly authorityHints?: EntityId[];
	/** Persistent store for signing key lifecycle. */
	readonly keyStore: KeyStore;
	/** Persistent store for subordinate entity records. */
	readonly subordinateStore: SubordinateStore;
	/** Optional store for issued trust marks. */
	readonly trustMarkStore?: TrustMarkStore;
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
	/** TTL in seconds for registration response JWTs. */
	readonly registrationResponseTtlSeconds?: number;
	/** TTL in seconds for issued trust mark JWTs. */
	readonly trustMarkTtlSeconds?: number;
	/** Returns the current active signing key and its kid. */
	readonly getSigningKey: () => Promise<{ key: JWK; kid: string }>;
	/** Registration-specific callbacks. */
	readonly registrationConfig?: {
		readonly generateClientSecret?: (sub: EntityId) => Promise<string | undefined>;
		readonly onRegistrationInvalidation?: (sub: EntityId) => Promise<void>;
	};
	/** Protocol adapter for OIDC-specific registration processing. */
	readonly registrationProtocolAdapter?: RegistrationProtocolAdapter;
	/** Store for JTI replay protection. */
	readonly jtiStore?: JtiStore;
}
