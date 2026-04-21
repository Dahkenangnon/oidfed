// Registration adapter & JTI store

export { InMemoryJtiStore } from "./in-memory-jti-store.js";
export type { JtiStore } from "./jti-store.js";
export type { RegistrationProtocolAdapter } from "./registration-adapter.js";

// Constants

// Cache
export {
	chainCacheKey,
	ecCacheKey,
	esCacheKey,
	MemoryCache,
} from "./cache/index.js";
export {
	CachePrefix,
	ClientRegistrationType,
	DEFAULT_CACHE_MAX_TTL_SECONDS,
	DEFAULT_CACHE_TTL_SECONDS,
	DEFAULT_CLIENT_ASSERTION_TTL_SECONDS,
	DEFAULT_CLOCK_SKEW_SECONDS,
	DEFAULT_DELEGATION_TTL_SECONDS,
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	DEFAULT_HTTP_TIMEOUT_MS,
	DEFAULT_KEY_RETIRE_AFTER_MS,
	DEFAULT_MAX_AUTHORITY_HINTS,
	DEFAULT_MAX_CHAIN_DEPTH,
	DEFAULT_MAX_REQUEST_BODY_BYTES,
	DEFAULT_REQUEST_OBJECT_TTL_SECONDS,
	EntityType,
	FederationEndpoint,
	FederationErrorCode,
	InternalErrorCode,
	JWT_BEARER_CLIENT_ASSERTION_TYPE,
	JwtTyp,
	MediaType,
	PolicyOperator,
	REQUIRED_ALGORITHMS,
	SUPPORTED_ALGORITHMS,
	type SupportedAlgorithm,
	TrustMarkStatus,
	WELL_KNOWN_OPENID_FEDERATION,
} from "./constants.js";
// Constraints
export {
	applyAllowedEntityTypes,
	checkConstraints,
	checkMaxPathLength,
	checkNamingConstraints,
} from "./constraints/index.js";
// Errors & Result
export {
	err,
	type FederationError,
	federationError,
	flatMap,
	isErr,
	isOk,
	map,
	mapErr,
	ok,
	type Result,
	unwrapOr,
} from "./errors.js";
// Federation API verification
export {
	verifyHistoricalKeysResponse,
	verifyResolveResponse,
	verifySignedJwkSet,
	verifyTrustMarkStatusResponse,
} from "./federation-api/index.js";
// HTTP helpers
export {
	type ExtractedRequestParams,
	errorResponse,
	extractRequestParams,
	jsonResponse,
	jwtResponse,
	parseQueryParams,
	readBodyWithLimit,
	readStreamWithLimit,
	requireMethod,
	requireMethods,
	SECURITY_HEADERS,
	toPublicError,
} from "./http.js";
// JOSE
export {
	assertTypHeader,
	decodeEntityStatement,
	generateSigningKey,
	isValidAlgorithm,
	JWK_PUBLIC_FIELDS,
	jwkThumbprint,
	selectVerificationKey,
	signEntityStatement,
	stripPrivateFields,
	timingSafeEqual,
	type VerifiedClientAssertion,
	verifyClientAssertion,
	verifyEntityStatement,
} from "./jose/index.js";
// Metadata Policy
export {
	applyMetadataPolicy,
	denormalizeScope,
	normalizeScope,
	resolveMetadataPolicy,
} from "./metadata-policy/index.js";
export { operators } from "./metadata-policy/operators.js";
// Schemas
export * from "./schemas/index.js";
export {
	type AnchorKeyComparisonResult,
	compareTrustAnchorKeys,
} from "./trust-chain/anchor-keys.js";
// Trust Chain
export {
	fetchEntityConfiguration,
	fetchSubordinateStatement,
	validateEntityId,
	validateFetchUrl,
} from "./trust-chain/fetch.js";
export {
	type RefreshOptions,
	refreshTrustChain,
} from "./trust-chain/refresh.js";
export {
	createConcurrencyLimiter,
	resolveTrustChains,
} from "./trust-chain/resolve.js";
export {
	calculateChainExpiration,
	chainRemainingTtl,
	describeTrustChain,
	isChainExpired,
	longestExpiry,
	preferTrustAnchor,
	shortestChain,
	validateTrustChain,
} from "./trust-chain/validate.js";
// Trust Marks
export { signTrustMarkDelegation, validateTrustMark } from "./trust-marks/index.js";
// Types
export {
	type CacheProvider,
	type ChainSelectionStrategy,
	type Clock,
	type DiscoveryResult,
	type EntityId,
	entityId,
	type FederationOptions,
	type HttpClient,
	isValidEntityId,
	type Logger,
	nowSeconds,
	type ParsedEntityStatement,
	type PolicyMergeResult,
	type PolicyOperatorDefinition,
	type PolicyOperatorResult,
	type ResolvedMetadataPolicy,
	type TrustAnchorSet,
	type TrustChain,
	type TrustChainResult,
	type UnverifiedEntityStatement,
	type ValidatedTrustChain,
	type ValidatedTrustMark,
	type ValidatedTrustMarkDelegation,
	type ValidationError,
	type ValidationResult,
} from "./types.js";
