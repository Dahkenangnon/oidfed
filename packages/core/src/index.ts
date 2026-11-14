export { runAsyncOperation } from "./async-operation.js";
export {
	createAttestationChallengeHandler,
	createAttestationChallengeResponse,
	fetchAttestationChallenge,
	readAttestationChallenge,
} from "./attestation-challenge.js";
export { isJsonData } from "./callbacks.js";
export {
	type AuthenticateClientAttestationOptions,
	authenticateClientAttestation,
	type ClientAttestation,
	type ClientAttestationError,
	type ClientAttestationFreshness,
	type ClientAttestationOptions,
	type ClientAttestationReplay,
	type ClientAttestationVerificationOptions,
	type CreateClientAttestationParams,
	type CreateClientAttestationProofParams,
	clientAttestationHeaders,
	createClientAttestation,
	createClientAttestationProof,
	invokeVerificationPolicy,
	parseClientAttestationHeaders,
	parseConcatenatedClientAttestation,
	serializeClientAttestation,
	type TrustedClientAttester,
	type VerifiedAttestationChallenge,
	type VerifiedClientAttestation,
	verifyClientAttestation,
} from "./client-attestation.js";
export {
	checkApplicationJwtHeader,
	decodeApplicationJwt,
	matchesJwtType,
	signApplicationJwt,
	verifyApplicationJwt,
} from "./jose/application-jwt.js";
export { type ClientAssertionOptions, createClientAssertion } from "./jose/client-assertion.js";
// Replay protection

export {
	MemoryReplayStore,
	type MemoryReplayStoreOptions,
	ReplayStoreCapacityError,
} from "./memory-replay-store.js";
export {
	type OAuthAuthorizationServerMetadata,
	type OAuthAuthorizationServerPublicationMetadata,
	parseOAuthAuthorizationServerMetadata,
	parseOAuthAuthorizationServerPublicationMetadata,
} from "./oauth-metadata.js";
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
	DEFAULT_MAX_CHAIN_LENGTH,
	DEFAULT_MAX_REQUEST_BODY_BYTES,
	DEFAULT_MAX_RESOLUTION_STEPS,
	DEFAULT_MAX_RESPONSE_BYTES,
	DEFAULT_REQUEST_OBJECT_TTL_SECONDS,
	EntityType,
	type EntityTypeIdentifier,
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
export {
	authenticatedEndpointCaller,
	authenticateEndpointRequest,
	createEndpointAuthenticatedHandler,
	type EndpointAuthentication,
	type EndpointAuthenticationConfig,
	type EndpointAuthenticationError,
	type EndpointAuthenticationInput,
	type EndpointAuthenticationMethod,
	endpointAuthenticationErrorResponse,
	validateEndpointAuthentication,
} from "./endpoint-authentication.js";
export type {
	CustomEndpointClientAuthentication,
	EndpointAdditionalParameters,
	EndpointAuthenticationContext,
	EndpointAuthenticationProvider,
	EndpointClientAuthentication,
	PrivateKeyJwtEndpointAuthentication,
} from "./endpoint-client.js";
export {
	COLLECTION_UNORDERED_PARAMETERS,
	EXTENDED_LIST_UNORDERED_PARAMETERS,
	endpointParameterValuesMatch,
	LIST_UNORDERED_PARAMETERS,
	RESOLVE_UNORDERED_PARAMETERS,
} from "./endpoint-parameters.js";
export * from "./entity-collection/index.js";
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
export {
	type FetchEntityCollectionOptions,
	fetchEntityCollection,
} from "./federation-api/entity-collection.js";
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
	type VerifyOptions,
	type VerifyResolveResponseOptions,
	type VerifySignedJwkSetOptions,
	type VerifyTrustMarkStatusOptions,
	verifyHistoricalKeysResponse,
	verifyResolveResponse,
	verifySignedJwkSet,
	verifyTrustMarkStatusResponse,
} from "./federation-api/index.js";
export {
	type FetchSubordinateEventsOptions,
	fetchSubordinateEvents,
	type VerifySubordinateEventsOptions,
	verifySubordinateEventsResponse,
} from "./federation-api/subordinate-events.js";
export {
	createFederationSigningKey,
	type FederationKeyLifecycleProvider,
	type FederationKeyProvider,
	type FederationKeySet,
	type FederationSigningKey,
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
	type VerifiedProtocolJwt,
	type VerifyProtocolJwtOptions,
	validateSigner,
	verifyClientAssertion,
	verifyEntityStatement,
	verifyProtocolJwt,
} from "./jose/index.js";
// JWK Set helpers
export { fetchJwkSet } from "./jwks/jwks-uri.js";
export { preparePublicJwkSet, validatePublicJwkSet } from "./jwks/public-material.js";
export {
	type EntityKeysSource,
	type ResolvedEntityKeys,
	type ResolveEntityKeysOptions,
	resolveEntityKeys,
} from "./jwks/resolve.js";
export { type FetchSignedJwkSetOptions, fetchSignedJwkSet } from "./jwks/signed-jwks-uri.js";
export { validateSignedJwkSetSpecHygiene } from "./jwks/spec-hygiene.js";
export { validateJwkSetUseRequirement } from "./jwks/use-requirement.js";
export { isLanguageTag } from "./language-tags.js";
export { safeLogger } from "./logging.js";
// Metadata Policy
export {
	applyMetadataPolicy,
	type MetadataPolicyOptions,
	resolveMetadataPolicy,
	validateCustomOperators,
	validateMetadataPolicy,
} from "./metadata-policy/index.js";
export { operators } from "./metadata-policy/operators.js";
export { findInvalidMetadataNullPaths } from "./metadata-values.js";
export {
	type FederationResolverConfig,
	type FederationResolverIntegration,
	FederationResolverService,
} from "./resolver/service.js";
export { validateRoleMetadata } from "./roles.js";
// Schemas
export * from "./schemas/index.js";
// Statement builders
export {
	type BuildEntityConfigurationPayloadOptions,
	type BuildSubordinateStatementPayloadOptions,
	buildEntityConfigurationPayload,
	buildSubordinateStatementPayload,
	type EntityStatementExtensions,
	type EntityStatementKind,
	type EntityStatementMetadata,
	prepareEntityStatementExtensions,
	type SignEntityConfigurationOptions,
	type SignSubordinateStatementOptions,
	signEntityConfiguration,
	signSubordinateStatement,
	type ValidateEntityStatementClaimsOptions,
	validateEntityStatementClaims,
	validateSubordinateStatementPublicationClaims,
} from "./statement-builders.js";
export {
	validateCriticalClaims,
	validateEntityStatementTimeClaims,
} from "./statement-validation.js";
export {
	compareTrustAnchorKeys,
	type TrustAnchorKeyComparisonResult,
} from "./trust-chain/anchor-keys.js";
export {
	assessEntity,
	type EntityAssessment,
	type EntityAssessmentOptions,
	isEntityAssessment,
	type TrustedResolverConfig,
	type TrustResolutionSource,
} from "./trust-chain/assessment.js";
// Trust Chain
export { discoverEntity, discoverEntityFromChain } from "./trust-chain/discovery.js";
export {
	type FetchSubordinateStatementOptions,
	fetchEntityConfiguration,
	fetchSubordinateStatement,
	validateEntityId,
	validateFetchUrl,
} from "./trust-chain/fetch.js";
export { createTrustChainOperation } from "./trust-chain/operation.js";
export { resolveTrustChainForAnchor } from "./trust-chain/peer.js";
export {
	type RefreshOptions,
	refreshTrustChain,
} from "./trust-chain/refresh.js";
export {
	createConcurrencyLimiter,
	type ResolveTrustChainsOptions,
	resolveTrustChains,
} from "./trust-chain/resolve.js";
export { selectTrustChain } from "./trust-chain/selection.js";
export {
	type ContextualMetadataClaim,
	calculateChainExpiration,
	chainRemainingTtl,
	completeTrustChainValidation,
	describeTrustChain,
	isChainExpired,
	longestExpiry,
	type PreparedTrustChain,
	type PrepareTrustChainOptions,
	preferTrustAnchor,
	prepareTrustChainValidation,
	shortestChain,
	validateTrustChain,
} from "./trust-chain/validate.js";
export {
	type EstablishTrustMarkIssuerOptions,
	establishTrustMarkIssuerTrust,
	type FederationTrustMarkIssuerEvidence,
	type HistoricalTrustMarkOptions,
	type OutOfBandTrustMarkIssuer,
	type TrustMarkIssuerContext,
	type TrustMarkVerificationOptions,
	trustMarkIssuerContext,
	type ValidateTrustMarkWithIssuerOptions,
	validateTrustMarkWithIssuer,
} from "./trust-marks/evidence.js";
export {
	type AttachTrustMarkOptions,
	type FetchAndAttachTrustMarkOptions,
	type RemoveTrustMarkSelector,
	TrustMarkHolder,
} from "./trust-marks/holder.js";
export {
	type FetchTrustMarkParams,
	type FetchTrustMarkStatusInput,
	type FetchTrustMarkStatusOptions,
	fetchTrustMark,
	fetchTrustMarkStatus,
	type SignTrustMarkDelegationOptions,
	type SignTrustMarkOptions,
	signTrustMark,
	signTrustMarkDelegation,
	type TrustMarkLifetime,
	type TrustMarkProfile,
	type TrustMarkStatusResult,
	type TrustMarkValidationOptions,
	type ValidateTrustMarkLogoOptions,
	validateTrustMark,
	validateTrustMarkLogo,
} from "./trust-marks/index.js";
export {
	type TrustMarkIssuanceOptions,
	type TrustMarkIssuerConfig,
	TrustMarkIssuerService,
	type TrustMarkIssuerServiceOptions,
	type TrustMarkRequestContext,
	type TrustMarkRequestExtension,
	type TrustMarkStatusAssessment,
	type TrustMarkStatusPolicy,
	type TrustMarkStatusPolicyContext,
} from "./trust-marks/issuer.js";
export { MemoryTrustMarkStorage, MemoryTrustMarkStore } from "./trust-marks/memory.js";
// Trust Marks
export {
	checkTrustMarkRequirements,
	type TrustMarkRequirements,
} from "./trust-marks/requirements.js";
export type { TrustMarkDelegationIssuanceOptions } from "./trust-marks/sign.js";
export type {
	TrustMarkListOptions,
	TrustMarkListPage,
	TrustMarkRecord,
	TrustMarkStorage,
	TrustMarkStore,
} from "./trust-marks/storage.js";
// Types
export {
	type CacheProvider,
	type ChainSelectionStrategy,
	type Clock,
	type ConstraintCheckContext,
	type ConstraintCheckDefinition,
	createTrustAnchorSet,
	type DecodedFederationJwtPayload,
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
	type TrustMarkEvaluation,
	type TrustMarkEvidence,
	type UnverifiedEntityStatement,
	type ValidatedTrustChain,
	type ValidatedTrustMark,
	type ValidatedTrustMarkDelegation,
	type ValidationError,
	type ValidationResult,
} from "./types.js";
