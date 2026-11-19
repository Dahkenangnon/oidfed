/** Shared protocol identifiers, media types, algorithms, and operational defaults. */

export const WELL_KNOWN_OPENID_FEDERATION = "/.well-known/openid-federation";

export const FederationEndpoint = {
	Fetch: "/federation_fetch",
	List: "/federation_list",
	ExtendedList: "/federation_extended_list",
	Collection: "/federation_collection",
	Resolve: "/federation_resolve",
	Registration: "/federation_registration",
	TrustMarkStatus: "/federation_trust_mark_status",
	TrustMarkList: "/federation_trust_mark_list",
	TrustMark: "/federation_trust_mark",
	HistoricalKeys: "/federation_historical_keys",
} as const;
export type FederationEndpoint = (typeof FederationEndpoint)[keyof typeof FederationEndpoint];

export const MediaType = {
	EntityEventsStatement: "application/entity-events-statement+jwt",
	EntityStatement: "application/entity-statement+jwt",
	TrustMark: "application/trust-mark+jwt",
	ResolveResponse: "application/resolve-response+jwt",
	TrustChain: "application/trust-chain+json",
	TrustMarkDelegation: "application/trust-mark-delegation+jwt",
	JwkSet: "application/jwk-set+jwt",
	TrustMarkStatusResponse: "application/trust-mark-status-response+jwt",
	Json: "application/json",
	JwkSetJson: "application/jwk-set+json",
	TextPlain: "text/plain",
} as const;
export type MediaType = (typeof MediaType)[keyof typeof MediaType];

export const JwtTyp = {
	EntityEventsStatement: "entity-events-statement+jwt",
	EntityStatement: "entity-statement+jwt",
	TrustMark: "trust-mark+jwt",
	TrustMarkDelegation: "trust-mark-delegation+jwt",
	ResolveResponse: "resolve-response+jwt",
	JwkSet: "jwk-set+jwt",
	TrustMarkStatusResponse: "trust-mark-status-response+jwt",
} as const;
export type JwtTyp = (typeof JwtTyp)[keyof typeof JwtTyp];

export const EntityType = {
	FederationEntity: "federation_entity",
	OpenIDRelyingParty: "openid_relying_party",
	OpenIDProvider: "openid_provider",
	OAuthAuthorizationServer: "oauth_authorization_server",
	OAuthClient: "oauth_client",
	OAuthResource: "oauth_resource",
	OpenIDWalletProvider: "openid_wallet_provider",
	OpenIDCredentialIssuer: "openid_credential_issuer",
	OpenIDCredentialVerifier: "openid_credential_verifier",
} as const;
export type EntityType = (typeof EntityType)[keyof typeof EntityType];

/**
 * Any Entity Type Identifier, including extensions (Federation 1.0 §§1.2 and 5.1).
 *
 * `EntityType` lists the identifiers from Federation 1.0 §5.1 and Wallet Architectures
 * Draft 05 §6. This type accepts other strings while keeping editor completion for
 * those constants. Federation §20 defines no registry for these identifiers.
 */
export type EntityTypeIdentifier = EntityType | (string & Record<never, never>);

export enum StandardPolicyOperator {
	VALUE = "value",
	ADD = "add",
	DEFAULT = "default",
	ESSENTIAL = "essential",
	ONE_OF = "one_of",
	SUBSET_OF = "subset_of",
	SUPERSET_OF = "superset_of",
}

export const PolicyOperator = {
	Value: StandardPolicyOperator.VALUE,
	Add: StandardPolicyOperator.ADD,
	Default: StandardPolicyOperator.DEFAULT,
	OneOf: StandardPolicyOperator.ONE_OF,
	SubsetOf: StandardPolicyOperator.SUBSET_OF,
	SupersetOf: StandardPolicyOperator.SUPERSET_OF,
	Essential: StandardPolicyOperator.ESSENTIAL,
} as const;
export type PolicyOperator = (typeof PolicyOperator)[keyof typeof PolicyOperator];

export const FederationErrorCode = {
	InvalidRequest: "invalid_request",
	InvalidClient: "invalid_client",
	InvalidIssuer: "invalid_issuer",
	InvalidSubject: "invalid_subject",
	InvalidTrustAnchor: "invalid_trust_anchor",
	InvalidTrustChain: "invalid_trust_chain",
	InvalidMetadata: "invalid_metadata",
	NotFound: "not_found",
	ServerError: "server_error",
	TemporarilyUnavailable: "temporarily_unavailable",
	UnsupportedParameter: "unsupported_parameter",
	UnsupportedClaim: "unsupported_claim",
	EntityIdNotFound: "entity_id_not_found",
	PageNotFound: "page_not_found",
} as const;
export type FederationErrorCode = (typeof FederationErrorCode)[keyof typeof FederationErrorCode];

export const InternalErrorCode = {
	CryptoOperationFailed: "ERR_CRYPTO_OPERATION_FAILED",
	InvalidClock: "ERR_INVALID_CLOCK",
	TrustChainInvalid: "ERR_TRUST_CHAIN_INVALID",
	SignatureInvalid: "ERR_SIGNATURE_INVALID",
	MetadataPolicyError: "ERR_METADATA_POLICY_ERROR",
	MetadataPolicyViolation: "ERR_METADATA_POLICY_VIOLATION",
	ConstraintViolation: "ERR_CONSTRAINT_VIOLATION",
	Network: "ERR_NETWORK",
	RemoteResponse: "ERR_REMOTE_RESPONSE",
	InvalidResponse: "ERR_INVALID_RESPONSE",
	TrustAnchorUnknown: "ERR_TRUST_ANCHOR_UNKNOWN",
	Timeout: "ERR_TIMEOUT",
	UnsupportedAlg: "ERR_UNSUPPORTED_ALG",
	TrustMarkInvalid: "ERR_TRUST_MARK_INVALID",
	Expired: "ERR_EXPIRED",
	LoopDetected: "ERR_LOOP_DETECTED",
} as const;
export type InternalErrorCode = (typeof InternalErrorCode)[keyof typeof InternalErrorCode];

export const CachePrefix = {
	EntityConfiguration: "ec:",
	EntityStatement: "es:",
	TrustChain: "chain:",
} as const;

export const TrustMarkStatus = {
	Active: "active",
	Expired: "expired",
	Revoked: "revoked",
	Invalid: "invalid",
} as const;
export type TrustMarkStatus = (typeof TrustMarkStatus)[keyof typeof TrustMarkStatus];

/** Claims that MUST NOT appear in the `crit` array. */
export const STANDARD_ENTITY_STATEMENT_CLAIMS = new Set([
	"iss",
	"sub",
	"iat",
	"exp",
	"jwks",
	"metadata",
	"metadata_policy",
	"constraints",
	"crit",
	"metadata_policy_crit",
	"authority_hints",
	"trust_anchor_hints",
	"trust_marks",
	"trust_mark_issuers",
	"trust_mark_owners",
	"aud",
	"source_endpoint",
	"trust_anchor",
]);

export const DEFAULT_MAX_RESPONSE_BYTES = 512 * 1024;
export const DEFAULT_MAX_REQUEST_BODY_BYTES = 64 * 1024;
export const DEFAULT_HTTP_TIMEOUT_MS = 10_000;
export const DEFAULT_CLOCK_SKEW_SECONDS = 60;
export const DEFAULT_MAX_CHAIN_LENGTH = 100;
export const DEFAULT_MAX_CHAIN_DEPTH = 8;
export const DEFAULT_MAX_RESOLUTION_STEPS = 1000;
export const DEFAULT_MAX_AUTHORITY_HINTS = 10;
export const DEFAULT_CACHE_TTL_SECONDS = 3600;
export const DEFAULT_CACHE_MAX_TTL_SECONDS = 86400;

export const DEFAULT_ENTITY_STATEMENT_TTL_SECONDS = 86400;
export const DEFAULT_DELEGATION_TTL_SECONDS = 86400;
export const DEFAULT_REQUEST_OBJECT_TTL_SECONDS = 300;
export const DEFAULT_CLIENT_ASSERTION_TTL_SECONDS = 60;

export const JWT_BEARER_CLIENT_ASSERTION_TYPE =
	"urn:ietf:params:oauth:client-assertion-type:jwt-bearer" as const;

/** Default acceptance policy; configured engines and callers may narrow it. */
export {
	CLASSICAL_ALGORITHMS as DEFAULT_ALLOWED_ALGORITHMS,
	INTEROP_RECOMMENDED_ALGORITHMS,
} from "@oidfed/crypto";
/** Algorithms understood by the wire format; this is not the deployment acceptance policy. */
export type SupportedAlgorithm = import("@oidfed/crypto").BuiltinJwsAlgorithm;
