/** Protocol constants: default TTLs, clock skew tolerance, and maximum chain depth. */
export const WELL_KNOWN_OPENID_FEDERATION = "/.well-known/openid-federation";

export const FederationEndpoint = {
	Fetch: "/federation_fetch",
	List: "/federation_list",
	Resolve: "/federation_resolve",
	Registration: "/federation_registration",
	TrustMarkStatus: "/federation_trust_mark_status",
	TrustMarkList: "/federation_trust_mark_list",
	TrustMark: "/federation_trust_mark",
	HistoricalKeys: "/federation_historical_keys",
} as const;
export type FederationEndpoint = (typeof FederationEndpoint)[keyof typeof FederationEndpoint];

export const MediaType = {
	EntityStatement: "application/entity-statement+jwt",
	TrustMark: "application/trust-mark+jwt",
	ResolveResponse: "application/resolve-response+jwt",
	TrustChain: "application/trust-chain+json",
	TrustMarkDelegation: "application/trust-mark-delegation+jwt",
	JwkSet: "application/jwk-set+jwt",
	ExplicitRegistrationResponse: "application/explicit-registration-response+jwt",
	TrustMarkStatusResponse: "application/trust-mark-status-response+jwt",
	Json: "application/json",
	JwkSetJson: "application/jwk-set+json",
	TextPlain: "text/plain",
} as const;
export type MediaType = (typeof MediaType)[keyof typeof MediaType];

export const JwtTyp = {
	EntityStatement: "entity-statement+jwt",
	TrustMark: "trust-mark+jwt",
	TrustMarkDelegation: "trust-mark-delegation+jwt",
	ResolveResponse: "resolve-response+jwt",
	JwkSet: "jwk-set+jwt",
	ExplicitRegistrationResponse: "explicit-registration-response+jwt",
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
} as const;
export type EntityType = (typeof EntityType)[keyof typeof EntityType];

export const ClientRegistrationType = {
	Automatic: "automatic",
	Explicit: "explicit",
} as const;
export type ClientRegistrationType =
	(typeof ClientRegistrationType)[keyof typeof ClientRegistrationType];

export const PolicyOperator = {
	Value: "value",
	Add: "add",
	Default: "default",
	OneOf: "one_of",
	SubsetOf: "subset_of",
	SupersetOf: "superset_of",
	Essential: "essential",
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
} as const;
export type FederationErrorCode = (typeof FederationErrorCode)[keyof typeof FederationErrorCode];

export const InternalErrorCode = {
	TrustChainInvalid: "ERR_TRUST_CHAIN_INVALID",
	SignatureInvalid: "ERR_SIGNATURE_INVALID",
	MetadataPolicyError: "ERR_METADATA_POLICY_ERROR",
	MetadataPolicyViolation: "ERR_METADATA_POLICY_VIOLATION",
	ConstraintViolation: "ERR_CONSTRAINT_VIOLATION",
	Network: "ERR_NETWORK",
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
export const DEFAULT_MAX_CHAIN_DEPTH = 8;
export const DEFAULT_MAX_AUTHORITY_HINTS = 10;
export const DEFAULT_CACHE_TTL_SECONDS = 3600;
export const DEFAULT_CACHE_MAX_TTL_SECONDS = 86400;

export const DEFAULT_ENTITY_STATEMENT_TTL_SECONDS = 86400;
export const DEFAULT_DELEGATION_TTL_SECONDS = 86400;
export const DEFAULT_REQUEST_OBJECT_TTL_SECONDS = 300;
export const DEFAULT_CLIENT_ASSERTION_TTL_SECONDS = 60;
export const DEFAULT_KEY_RETIRE_AFTER_MS = 7 * 24 * 60 * 60 * 1000;

export const JWT_BEARER_CLIENT_ASSERTION_TYPE =
	"urn:ietf:params:oauth:client-assertion-type:jwt-bearer" as const;

export const REQUIRED_ALGORITHMS = ["ES256", "PS256"] as const;
export const SUPPORTED_ALGORITHMS = [
	"ES256",
	"ES384",
	"ES512",
	"PS256",
	"PS384",
	"PS512",
	// RS256 (RSASSA-PKCS1-v1_5) is retained intentionally: it is a recommended signature
	// algorithm, and the PKCS#1 v1.5 deprecation warning applies only to RSA encryption,
	// not signatures.
	"RS256",
] as const;
export type SupportedAlgorithm = (typeof SUPPORTED_ALGORITHMS)[number];
