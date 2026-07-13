// Replay protection

export {
	MemoryReplayStore,
	type MemoryReplayStoreOptions,
	ReplayStoreCapacityError,
} from "./memory-replay-store.js";
export type { JtiReplayClaim, ReplayStore } from "./replay-store.js";

// Constants

// Cache
export {
	chainCacheKey,
	ecCacheKey,
	esCacheKey,
	MemoryCache,
	type MemoryCacheOptions,
} from "./cache/index.js";
export {
	CachePrefix,
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
	STANDARD_ENTITY_STATEMENT_CLAIMS,
	StandardPolicyOperator,
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
// Federation API verification + remote-endpoint clients
export {
	type FetchHistoricalKeysOptions,
	type FetchTrustMarkListParams,
	fetchExtendedSubordinatesList,
	fetchHistoricalKeys,
	fetchListSubordinates,
	fetchResolveResponse,
	fetchTrustMarkList,
	type ListSubordinatesFilter,
	type ResolveRequestParams,
	type SelectHistoricalVerificationKeyOptions,
	selectHistoricalVerificationKey,
	verifyHistoricalKeysResponse,
	verifyResolveResponse,
	verifySignedJwkSet,
	verifyTrustMarkStatusResponse,
} from "./federation-api/index.js";
export {
	type FederationKeyProvider,
	type FederationKeySet,
	type FederationSigningKey,
	federationKey,
	type ManagedFederationKeyProvider,
	MemoryFederationKeyProvider,
	type MemoryFederationKeyProviderOptions,
	StaticFederationKeyProvider,
	type SwitchActiveFederationKeyOptions,
	validateFederationKeySet,
} from "./federation-keys.js";
// HTTP helpers
export {
	type ExtractedRequestParams,
	errorResponse,
	extractRequestParams,
	isExactContentType,
	jsonResponse,
	jwtResponse,
	type ParsedContentTypeHeader,
	parseContentTypeHeader,
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
	decodeEntityConfiguration,
	decodeEntityStatement,
	decodeSubordinateStatement,
	generateSigningKey,
	isValidAlgorithm,
	JWK_PUBLIC_FIELDS,
	JwkSigner,
	type JwkSignerOptions,
	type JwtSigner,
	jwkThumbprint,
	type SignEntityStatementOptions,
	selectVerificationKey,
	signEntityStatement,
	stripPrivateFields,
	timingSafeEqual,
	type VerifiedClientAssertion,
	validateSigner,
	verifyClientAssertion,
	verifyEntityStatement,
} from "./jose/index.js";
// JWK Set helpers
export { fetchJwkSet } from "./jwks/jwks-uri.js";
export {
	type EntityKeysSource,
	type ResolvedEntityKeys,
	type ResolveEntityKeysOptions,
	resolveEntityKeys,
} from "./jwks/resolve.js";
export { type FetchSignedJwkSetOptions, fetchSignedJwkSet } from "./jwks/signed-jwks-uri.js";
export { validateSignedJwkSetSpecHygiene } from "./jwks/spec-hygiene.js";
export { validateJwkSetUseRequirement } from "./jwks/use-requirement.js";
// Metadata Policy
export {
	applyMetadataPolicy,
	type MetadataPolicyOptions,
	resolveMetadataPolicy,
	validateCustomOperators,
} from "./metadata-policy/index.js";
export { operators } from "./metadata-policy/operators.js";
// Schemas
export * from "./schemas/index.js";
// Statement builders
export {
	type BuildEntityConfigurationPayloadOptions,
	type BuildSubordinateStatementPayloadOptions,
	buildEntityConfigurationPayload,
	buildSubordinateStatementPayload,
	type EntityStatementKind,
	type EntityStatementMetadata,
	type SignEntityConfigurationOptions,
	type SignSubordinateStatementOptions,
	signEntityConfiguration,
	signSubordinateStatement,
	type ValidateEntityStatementClaimsOptions,
	validateEntityStatementClaims,
} from "./statement-builders.js";
export {
	type AnchorKeyComparisonResult,
	compareTrustAnchorKeys,
} from "./trust-chain/anchor-keys.js";
// Trust Chain
export { discoverEntity } from "./trust-chain/discovery.js";
export {
	fetchEntityConfiguration,
	fetchSubordinateStatement,
	validateEntityId,
	validateFetchUrl,
} from "./trust-chain/fetch.js";
export { resolveTrustChainForAnchor } from "./trust-chain/peer.js";
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
export {
	type FetchTrustMarkParams,
	type FetchTrustMarkStatusOptions,
	fetchTrustMark,
	fetchTrustMarkStatus,
	signTrustMarkDelegation,
	type TrustMarkStatusResult,
	type ValidateTrustMarkLogoOptions,
	validateTrustMark,
	validateTrustMarkLogo,
} from "./trust-marks/index.js";
// Types
export {
	type CacheProvider,
	type ChainSelectionStrategy,
	type Clock,
	createTrustAnchorSet,
	type DiscoveryResult,
	type EntityContext,
	type EntityId,
	type EntityRole,
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
