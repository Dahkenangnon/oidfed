export type { FederationArtifact } from "@oidfed/crypto";
export {
	createConcurrencyLimiter,
	runAsyncOperation,
	waitForOperation,
} from "./async-operation.js";
export {
	createAttestationChallengeHandler,
	createAttestationChallengeResponse,
	fetchAttestationChallenge,
	readAttestationChallenge,
} from "./attestation-challenge.js";
export { freezeSnapshot, isJsonData, setOwn } from "./callbacks.js";
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
	bindFederationOptions,
	federationSigningOptions,
	snapshotCryptoContext,
	validateCryptoContext,
} from "./crypto-context.js";
export { randomUuid, sha256Hex } from "./crypto-runtime.js";
export { cloneData } from "./data-copy.js";
export {
	checkApplicationJwtHeader,
	decodeApplicationJwt,
	matchesJwtType,
	signApplicationJwt,
	verifyApplicationJwt,
} from "./jose/application-jwt.js";
export { type ClientAssertionOptions, createClientAssertion } from "./jose/client-assertion.js";
export {
	JwsService,
	type JwsServiceOptions,
	type JwtTypeRule,
	type JwtVerificationProfile,
	type VerifiedJwt,
} from "./jws-service.js";
export {
	isProtocolSignerPublished,
	type SigningPurposes,
	selectSigningEntry,
	signingPublication,
	validateSigningPurposes,
} from "./signing-purposes.js";

// Replay protection

export {
	type OAuthAuthorizationServerMetadata,
	type OAuthAuthorizationServerPublicationMetadata,
	parseOAuthAuthorizationServerMetadata,
	parseOAuthAuthorizationServerPublicationMetadata,
} from "./oauth-metadata.js";
export { ReplayStoreCapacityError } from "./storage/replay-memory.js";
export type { JtiReplayClaim, ReplayStore } from "./storage/replay-store.js";

// Constants

export {
	CachePrefix,
	DEFAULT_ALLOWED_ALGORITHMS,
	DEFAULT_CACHE_MAX_TTL_SECONDS,
	DEFAULT_CACHE_TTL_SECONDS,
	DEFAULT_CLIENT_ASSERTION_TTL_SECONDS,
	DEFAULT_CLOCK_SKEW_SECONDS,
	DEFAULT_DELEGATION_TTL_SECONDS,
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	DEFAULT_HTTP_TIMEOUT_MS,
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
	INTEROP_RECOMMENDED_ALGORITHMS,
	InternalErrorCode,
	JWT_BEARER_CLIENT_ASSERTION_TYPE,
	JwtTyp,
	MediaType,
	PolicyOperator,
	STANDARD_ENTITY_STATEMENT_CLAIMS,
	StandardPolicyOperator,
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
	endpointCredentialParameterNames,
	validateEndpointAuthentication,
} from "./endpoint-authentication.js";
export type {
	EndpointAuthorizationInput,
	EndpointAuthorizationPolicy,
	FederationEndpointOperation,
} from "./endpoint-authorization.js";
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
	ENDPOINT_OPERATION_PARAMETERS,
	EXTENDED_LIST_UNORDERED_PARAMETERS,
	endpointParameterValuesMatch,
	isReservedEndpointParameter,
	LIST_UNORDERED_PARAMETERS,
	prepareEndpointParameters,
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
export {
	createHistoricalKeysHandler,
	signHistoricalKeysResponse,
} from "./federation-api/historical-keys.js";
// Federation API verification + remote-endpoint clients
export {
	buildExtendedListRequestParameters,
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
	type FederationKeyHistorySource,
	federationEntry,
	federationPublicationJwks,
	historicalKeysFromKeyring,
	isSignerPublished,
	validateFederationKeySet,
} from "./federation-keys.js";
// JOSE
export { BodyLimitExceeded, readBytesWithLimit } from "./http/body-bytes.js";
export { validateFetchUrl } from "./http/fetch-url.js";
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
export {
	assertTypHeader,
	decodeEntityConfiguration,
	decodeEntityStatement,
	decodeSubordinateStatement,
	type FederationJwsOptions,
	isValidAlgorithm,
	JWK_PUBLIC_FIELDS,
	jwkThumbprint,
	type SignEntityStatementOptions,
	selectVerificationKey,
	signEntityStatement,
	stripPrivateFields,
	timingSafeEqual,
	type VerifiedClientAssertion,
	type VerifiedProtocolJwt,
	type VerifyProtocolJwtOptions,
	verifyClientAssertion,
	verifyEntityStatement,
	verifyProtocolJwt,
} from "./jose/index.js";
// JWK Set helpers
export { fetchJwkSet } from "./jwks/jwks-uri.js";
export {
	prepareProtocolJwkSet,
	preparePublicJwkSet,
	validatePublicJwkSet,
} from "./jwks/public-material.js";
export {
	type EntityKeysSource,
	type ResolvedEntityKeys,
	type ResolveEntityKeysOptions,
	resolveEntityKeys,
} from "./jwks/resolve.js";
export { type SignProtocolJwkSetOptions, signProtocolJwkSet } from "./jwks/signed-jwk-set.js";
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
export type { ResolveCacheScopeInput, ResolverCacheOptions } from "./resolver/assessment-cache.js";
export type {
	ResolveTrustMarkCandidateInput,
	ResolveTrustMarkCandidateLimits,
	ResolveTrustMarkCandidates,
	ResolveTrustMarkStatusMaxAge,
} from "./resolver/mark-disclosure.js";
export {
	type FederationResolverConfig,
	type FederationResolverIntegration,
	FederationResolverService,
	type PrimeAnonymousResolveInput,
} from "./resolver/service.js";
export {
	composeEntityMetadata,
	composeRolePublicationMetadata,
	validateRoleMetadata,
} from "./roles.js";
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
// Cache
export {
	chainCacheKey,
	ecCacheKey,
	esCacheKey,
} from "./storage/cache.js";
export {
	type ResolveAssessmentCacheValue,
	ResolveAssessmentCacheValueSchema,
	StatementCacheValueSchema,
} from "./storage/cache-records.js";
export {
	assertStorageCapabilities,
	assertStorageView,
	describeStorageRequirements,
	requireReplayStorage,
	StorageCapabilityError,
	type StorageFeature,
	storageSnapshot,
	storageTransaction,
} from "./storage/capabilities.js";
export type {
	CollectionEntry,
	EntityCollectionCursor,
	EntityCollectionSnapshot,
	EntityCollectionStore,
} from "./storage/collection.js";
export { composeFederationStorage, type FederationStorageParts } from "./storage/compose.js";
export type {
	CacheStore,
	FederationStorage,
	ReadSnapshotView,
	StorageCapability,
	TransactionView,
} from "./storage/contracts.js";
export {
	InvalidMetadata,
	InvalidStorageRecordError,
	InvalidSubordinateRecord,
} from "./storage/errors.js";
export { MemoryFederationStorage, type MemoryFederationStorageOptions } from "./storage/memory.js";
export { parseStoragePayload, type StoragePayloadByKind } from "./storage/payload-schemas.js";
export {
	type CacheWrite,
	CacheWriteSchema,
	CollectionEntrySchema,
	EntityCollectionCursorSchema,
	EntityCollectionSnapshotSchema,
	type JsonObject,
	type JsonValue,
	JtiReplayClaimSchema,
	parseStorageRecord,
	parseStoredSubordinateEvents,
	parseStoredTrustMark,
	parseSubordinateRecord,
	parseSubordinateUpdate,
	StorageEntityIdSchema,
	StorageJsonSchema,
	type StorageValidationOptions,
	StoredSubordinateEventSchema,
	type SubordinateEventHistory,
	SubordinateEventHistorySchema,
	SubordinatePageSchema,
	SubordinateRecordSchema,
	SubordinateRecordUpdateSchema,
	TrustMarkRecordSchema,
	type TrustMarkRevision,
	TrustMarkRevisionSchema,
} from "./storage/record-schemas.js";
export { parsePublishedSubordinateEvent } from "./storage/subordinate-event.js";
export { assertSubordinatePublicationClaims } from "./storage/subordinate-publication.js";
export {
	assertMetadataValuesNotNull,
	isFederationEntityOperationalField,
	sanitizeSubordinateMetadata,
} from "./storage/subordinate-statement-shape.js";
export type {
	ListFilter,
	ListPage,
	ListPageOptions,
	SubordinateEventAnnotations,
	SubordinateEventReadStore,
	SubordinateEventStore,
	SubordinateReadStore,
	SubordinateRecord,
	SubordinateRecordUpdate,
	SubordinateStore,
} from "./storage/subordinates.js";
export type {
	TrustMarkListOptions,
	TrustMarkListPage,
	TrustMarkReadStore,
	TrustMarkRecord,
	TrustMarkStore,
	TrustMarkTransactionStore,
} from "./storage/trust-mark.js";
export { isStoredTrustMarkEligible } from "./storage/trust-mark-eligibility.js";
export { fetchStoredSubordinate, listStoredSubordinates } from "./storage/validated-records.js";
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
	entityConfigurationUrl,
	type FetchSubordinateStatementOptions,
	fetchEntityConfiguration,
	fetchSubordinateStatement,
	validateEntityId,
} from "./trust-chain/fetch.js";
export { createTrustChainOperation } from "./trust-chain/operation.js";
export { resolveTrustChainForAnchor } from "./trust-chain/peer.js";
export {
	type RefreshOptions,
	refreshTrustChain,
} from "./trust-chain/refresh.js";
export {
	type ResolveTrustChainsOptions,
	resolveTrustChains,
} from "./trust-chain/resolve.js";
export {
	longestExpiry,
	preferTrustAnchor,
	selectTrustChain,
	shortestChain,
} from "./trust-chain/selection.js";
export {
	type ContextualMetadataClaim,
	calculateChainExpiration,
	chainRemainingTtl,
	completeTrustChainValidation,
	describeTrustChain,
	isChainExpired,
	type PreparedTrustChain,
	type PrepareTrustChainOptions,
	prepareTrustChainValidation,
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
	type VerifiedTrustMarkDelegation,
	type VerifyTrustMarkDelegationOptions,
	validateTrustMark,
	validateTrustMarkLogo,
	verifyTrustMarkDelegation,
} from "./trust-marks/index.js";
export {
	type TrustMarkExactWithdrawalOptions,
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
// Trust Marks
export {
	checkTrustMarkRequirements,
	type TrustMarkRequirements,
} from "./trust-marks/requirements.js";
export type { TrustMarkDelegationIssuanceOptions } from "./trust-marks/sign.js";
export { assertPositiveTtlSeconds } from "./ttl.js";
// Types
export {
	type BoundFederationOptions,
	type ChainSelectionStrategy,
	type Clock,
	type ConstraintCheckContext,
	type ConstraintCheckDefinition,
	type CryptoContext,
	createTrustAnchorSet,
	type DecodedFederationJwtPayload,
	type DiscoveryResult,
	type EntityContext,
	type EntityId,
	type EntityRole,
	entityId,
	type FederationOptions,
	type HttpClient,
	InvalidClockError,
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
