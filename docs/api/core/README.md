# `@oidfed/core` API

[API reference](../README.md)

Every entry below is exported from `@oidfed/core`; there are no public subpath imports. Class entries cover constructors and library-defined public members. Standard `Error` inheritance is noted beside error classes.

Signatures preserve optional and read-only declarations. An optional property is marked with `?`; `undefined` is included in its declared type only when the source allows it explicitly. Schema field tables describe parsed output, which can differ from raw input. Parsing, decoding, signature verification, and establishing trust are separate steps; each entry states which work it performs.

## Identifiers, results, and host contracts

| API | Kind |
|---|---|
| [`assertPositiveTtlSeconds`](contracts.md#assertpositivettlseconds) | Function |
| [`CacheProvider`](contracts.md#cacheprovider) | Interface |
| [`chainCacheKey`](contracts.md#chaincachekey) | Function |
| [`ChainSelectionStrategy`](contracts.md#chainselectionstrategy) | Type |
| [`Clock`](contracts.md#clock) | Interface |
| [`composeEntityMetadata`](contracts.md#composeentitymetadata) | Function |
| [`ConstraintCheckContext`](contracts.md#constraintcheckcontext) | Interface |
| [`ConstraintCheckDefinition`](contracts.md#constraintcheckdefinition) | Interface |
| [`createTrustAnchorSet`](contracts.md#createtrustanchorset) | Function |
| [`DiscoveryResult`](contracts.md#discoveryresult) | Type |
| [`ecCacheKey`](contracts.md#eccachekey) | Function |
| [`EntityContext`](contracts.md#entitycontext) | Interface |
| [`entityId`](contracts.md#entityid) | Function |
| [`EntityId`](contracts.md#entityid-1) | Type |
| [`EntityRole`](contracts.md#entityrole) | Interface |
| [`err`](contracts.md#err) | Function |
| [`esCacheKey`](contracts.md#escachekey) | Function |
| [`federationError`](contracts.md#federationerror) | Function |
| [`FederationError`](contracts.md#federationerror-1) | Type |
| [`FederationOptions`](contracts.md#federationoptions) | Interface |
| [`findInvalidMetadataNullPaths`](contracts.md#findinvalidmetadatanullpaths) | Function |
| [`flatMap`](contracts.md#flatmap) | Function |
| [`freezeSnapshot`](contracts.md#freezesnapshot) | Function |
| [`HttpClient`](contracts.md#httpclient) | Type |
| [`isErr`](contracts.md#iserr) | Function |
| [`isJsonData`](contracts.md#isjsondata) | Function |
| [`isLanguageTag`](contracts.md#islanguagetag) | Function |
| [`isOk`](contracts.md#isok) | Function |
| [`isValidEntityId`](contracts.md#isvalidentityid) | Function |
| [`JtiReplayClaim`](contracts.md#jtireplayclaim) | Interface |
| [`Logger`](contracts.md#logger) | Interface |
| [`map`](contracts.md#map) | Function |
| [`mapErr`](contracts.md#maperr) | Function |
| [`MemoryCache`](contracts.md#memorycache) | Class |
| [`MemoryCacheOptions`](contracts.md#memorycacheoptions) | Interface |
| [`MemoryReplayStore`](contracts.md#memoryreplaystore) | Class |
| [`MemoryReplayStoreOptions`](contracts.md#memoryreplaystoreoptions) | Interface |
| [`nowSeconds`](contracts.md#nowseconds) | Function |
| [`ok`](contracts.md#ok) | Function |
| [`ParsedEntityStatement`](contracts.md#parsedentitystatement) | Type |
| [`PolicyMergeResult`](contracts.md#policymergeresult) | Type |
| [`PolicyOperatorDefinition`](contracts.md#policyoperatordefinition) | Interface |
| [`PolicyOperatorResult`](contracts.md#policyoperatorresult) | Type |
| [`ReplayStore`](contracts.md#replaystore) | Interface |
| [`ReplayStoreCapacityError`](contracts.md#replaystorecapacityerror) | Class |
| [`ResolvedMetadataPolicy`](contracts.md#resolvedmetadatapolicy) | Type |
| [`Result`](contracts.md#result) | Type |
| [`runAsyncOperation`](contracts.md#runasyncoperation) | Function |
| [`safeLogger`](contracts.md#safelogger) | Function |
| [`setOwn`](contracts.md#setown) | Function |
| [`TrustAnchorSet`](contracts.md#trustanchorset) | Type |
| [`TrustChain`](contracts.md#trustchain) | Interface |
| [`TrustChainResult`](contracts.md#trustchainresult) | Interface |
| [`TrustMarkEvaluation`](contracts.md#trustmarkevaluation) | Type |
| [`TrustMarkEvidence`](contracts.md#trustmarkevidence) | Interface |
| [`UnverifiedEntityStatement`](contracts.md#unverifiedentitystatement) | Type |
| [`unwrapOr`](contracts.md#unwrapor) | Function |
| [`ValidatedTrustChain`](contracts.md#validatedtrustchain) | Interface |
| [`ValidatedTrustMark`](contracts.md#validatedtrustmark) | Interface |
| [`ValidatedTrustMarkDelegation`](contracts.md#validatedtrustmarkdelegation) | Interface |
| [`validateRoleMetadata`](contracts.md#validaterolemetadata) | Function |
| [`ValidationError`](contracts.md#validationerror) | Interface |
| [`ValidationResult`](contracts.md#validationresult) | Type |
| [`waitForOperation`](contracts.md#waitforoperation) | Function |

## Client and endpoint authentication

| API | Kind |
|---|---|
| [`authenticateClientAttestation`](authentication.md#authenticateclientattestation) | Function |
| [`AuthenticateClientAttestationOptions`](authentication.md#authenticateclientattestationoptions) | Interface |
| [`authenticatedEndpointCaller`](authentication.md#authenticatedendpointcaller) | Function |
| [`authenticateEndpointRequest`](authentication.md#authenticateendpointrequest) | Function |
| [`ClientAssertionOptions`](authentication.md#clientassertionoptions) | Interface |
| [`ClientAttestation`](authentication.md#clientattestation) | Type |
| [`ClientAttestationError`](authentication.md#clientattestationerror) | Interface |
| [`ClientAttestationFreshness`](authentication.md#clientattestationfreshness) | Type |
| [`clientAttestationHeaders`](authentication.md#clientattestationheaders) | Function |
| [`ClientAttestationOptions`](authentication.md#clientattestationoptions) | Interface |
| [`ClientAttestationReplay`](authentication.md#clientattestationreplay) | Type |
| [`ClientAttestationVerificationOptions`](authentication.md#clientattestationverificationoptions) | Interface |
| [`createAttestationChallengeHandler`](authentication.md#createattestationchallengehandler) | Function |
| [`createAttestationChallengeResponse`](authentication.md#createattestationchallengeresponse) | Function |
| [`createClientAssertion`](authentication.md#createclientassertion) | Function |
| [`createClientAttestation`](authentication.md#createclientattestation) | Function |
| [`CreateClientAttestationParams`](authentication.md#createclientattestationparams) | Interface |
| [`createClientAttestationProof`](authentication.md#createclientattestationproof) | Function |
| [`CreateClientAttestationProofParams`](authentication.md#createclientattestationproofparams) | Interface |
| [`createEndpointAuthenticatedHandler`](authentication.md#createendpointauthenticatedhandler) | Function |
| [`CustomEndpointClientAuthentication`](authentication.md#customendpointclientauthentication) | Interface |
| [`EndpointAuthentication`](authentication.md#endpointauthentication) | Interface |
| [`EndpointAuthenticationConfig`](authentication.md#endpointauthenticationconfig) | Interface |
| [`EndpointAuthenticationContext`](authentication.md#endpointauthenticationcontext) | Interface |
| [`EndpointAuthenticationError`](authentication.md#endpointauthenticationerror) | Interface |
| [`endpointAuthenticationErrorResponse`](authentication.md#endpointauthenticationerrorresponse) | Function |
| [`EndpointAuthenticationInput`](authentication.md#endpointauthenticationinput) | Interface |
| [`EndpointAuthenticationMethod`](authentication.md#endpointauthenticationmethod) | Interface |
| [`EndpointAuthenticationProvider`](authentication.md#endpointauthenticationprovider) | Type |
| [`EndpointClientAuthentication`](authentication.md#endpointclientauthentication) | Type |
| [`endpointCredentialParameterNames`](authentication.md#endpointcredentialparameternames) | Function |
| [`fetchAttestationChallenge`](authentication.md#fetchattestationchallenge) | Function |
| [`invokeVerificationPolicy`](authentication.md#invokeverificationpolicy) | Function |
| [`parseClientAttestationHeaders`](authentication.md#parseclientattestationheaders) | Function |
| [`parseConcatenatedClientAttestation`](authentication.md#parseconcatenatedclientattestation) | Function |
| [`PrivateKeyJwtEndpointAuthentication`](authentication.md#privatekeyjwtendpointauthentication) | Interface |
| [`readAttestationChallenge`](authentication.md#readattestationchallenge) | Function |
| [`serializeClientAttestation`](authentication.md#serializeclientattestation) | Function |
| [`TrustedClientAttester`](authentication.md#trustedclientattester) | Interface |
| [`validateEndpointAuthentication`](authentication.md#validateendpointauthentication) | Function |
| [`VerifiedAttestationChallenge`](authentication.md#verifiedattestationchallenge) | Interface |
| [`VerifiedClientAssertion`](authentication.md#verifiedclientassertion) | Interface |
| [`VerifiedClientAttestation`](authentication.md#verifiedclientattestation) | Interface |
| [`verifyClientAssertion`](authentication.md#verifyclientassertion) | Function |
| [`verifyClientAttestation`](authentication.md#verifyclientattestation) | Function |

## Entity Statements and signatures

| API | Kind |
|---|---|
| [`assertTypHeader`](statements.md#asserttypheader) | Function |
| [`buildEntityConfigurationPayload`](statements.md#buildentityconfigurationpayload) | Function |
| [`BuildEntityConfigurationPayloadOptions`](statements.md#buildentityconfigurationpayloadoptions) | Interface |
| [`buildSubordinateStatementPayload`](statements.md#buildsubordinatestatementpayload) | Function |
| [`BuildSubordinateStatementPayloadOptions`](statements.md#buildsubordinatestatementpayloadoptions) | Interface |
| [`checkApplicationJwtHeader`](statements.md#checkapplicationjwtheader) | Function |
| [`decodeApplicationJwt`](statements.md#decodeapplicationjwt) | Function |
| [`decodeEntityConfiguration`](statements.md#decodeentityconfiguration) | Function |
| [`decodeEntityStatement`](statements.md#decodeentitystatement) | Function |
| [`decodeSubordinateStatement`](statements.md#decodesubordinatestatement) | Function |
| [`EntityStatementExtensions`](statements.md#entitystatementextensions) | Interface |
| [`EntityStatementKind`](statements.md#entitystatementkind) | Type |
| [`EntityStatementMetadata`](statements.md#entitystatementmetadata) | Type |
| [`JwkSigner`](statements.md#jwksigner) | Class |
| [`JwkSignerOptions`](statements.md#jwksigneroptions) | Interface |
| [`JwtSigner`](statements.md#jwtsigner) | Interface |
| [`matchesJwtType`](statements.md#matchesjwttype) | Function |
| [`prepareEntityStatementExtensions`](statements.md#prepareentitystatementextensions) | Function |
| [`signApplicationJwt`](statements.md#signapplicationjwt) | Function |
| [`signEntityConfiguration`](statements.md#signentityconfiguration) | Function |
| [`SignEntityConfigurationOptions`](statements.md#signentityconfigurationoptions) | Interface |
| [`signEntityStatement`](statements.md#signentitystatement) | Function |
| [`SignEntityStatementOptions`](statements.md#signentitystatementoptions) | Interface |
| [`signSubordinateStatement`](statements.md#signsubordinatestatement) | Function |
| [`SignSubordinateStatementOptions`](statements.md#signsubordinatestatementoptions) | Interface |
| [`validateCriticalClaims`](statements.md#validatecriticalclaims) | Function |
| [`validateEntityStatementClaims`](statements.md#validateentitystatementclaims) | Function |
| [`ValidateEntityStatementClaimsOptions`](statements.md#validateentitystatementclaimsoptions) | Interface |
| [`validateEntityStatementTimeClaims`](statements.md#validateentitystatementtimeclaims) | Function |
| [`validateSigner`](statements.md#validatesigner) | Function |
| [`validateSubordinateStatementPublicationClaims`](statements.md#validatesubordinatestatementpublicationclaims) | Function |
| [`VerifiedProtocolJwt`](statements.md#verifiedprotocoljwt) | Interface |
| [`verifyApplicationJwt`](statements.md#verifyapplicationjwt) | Function |
| [`verifyEntityStatement`](statements.md#verifyentitystatement) | Function |
| [`verifyProtocolJwt`](statements.md#verifyprotocoljwt) | Function |
| [`VerifyProtocolJwtOptions`](statements.md#verifyprotocoljwtoptions) | Interface |

## Keys, rollover, and protocol JWKS

| API | Kind |
|---|---|
| [`createFederationSigningKey`](keys.md#createfederationsigningkey) | Function |
| [`EntityKeysSource`](keys.md#entitykeyssource) | Type |
| [`FederationKeyLifecycleProvider`](keys.md#federationkeylifecycleprovider) | Interface |
| [`FederationKeyProvider`](keys.md#federationkeyprovider) | Interface |
| [`FederationKeySet`](keys.md#federationkeyset) | Interface |
| [`FederationSigningKey`](keys.md#federationsigningkey) | Interface |
| [`fetchJwkSet`](keys.md#fetchjwkset) | Function |
| [`fetchSignedJwkSet`](keys.md#fetchsignedjwkset) | Function |
| [`FetchSignedJwkSetOptions`](keys.md#fetchsignedjwksetoptions) | Interface |
| [`generateSigningKey`](keys.md#generatesigningkey) | Function |
| [`isValidAlgorithm`](keys.md#isvalidalgorithm) | Function |
| [`JWK_PUBLIC_FIELDS`](keys.md#jwk_public_fields) | Value |
| [`jwkThumbprint`](keys.md#jwkthumbprint) | Function |
| [`MemoryFederationKeyProvider`](keys.md#memoryfederationkeyprovider) | Class |
| [`MemoryFederationKeyProviderOptions`](keys.md#memoryfederationkeyprovideroptions) | Interface |
| [`preparePublicJwkSet`](keys.md#preparepublicjwkset) | Function |
| [`ResolvedEntityKeys`](keys.md#resolvedentitykeys) | Interface |
| [`resolveEntityKeys`](keys.md#resolveentitykeys) | Function |
| [`ResolveEntityKeysOptions`](keys.md#resolveentitykeysoptions) | Interface |
| [`selectVerificationKey`](keys.md#selectverificationkey) | Function |
| [`StaticFederationKeyProvider`](keys.md#staticfederationkeyprovider) | Class |
| [`stripPrivateFields`](keys.md#stripprivatefields) | Function |
| [`SwitchActiveFederationKeyOptions`](keys.md#switchactivefederationkeyoptions) | Interface |
| [`timingSafeEqual`](keys.md#timingsafeequal) | Function |
| [`validateFederationKeySet`](keys.md#validatefederationkeyset) | Function |
| [`validateJwkSetUseRequirement`](keys.md#validatejwksetuserequirement) | Function |
| [`validatePublicJwkSet`](keys.md#validatepublicjwkset) | Function |
| [`validateSignedJwkSetSpecHygiene`](keys.md#validatesignedjwksetspechygiene) | Function |

## Federation endpoint clients and responses

| API | Kind |
|---|---|
| [`buildExtendedListRequestParameters`](endpoints.md#buildextendedlistrequestparameters) | Function |
| [`COLLECTION_UNORDERED_PARAMETERS`](endpoints.md#collection_unordered_parameters) | Value |
| [`EndpointAdditionalParameters`](endpoints.md#endpointadditionalparameters) | Type |
| [`endpointParameterValuesMatch`](endpoints.md#endpointparametervaluesmatch) | Function |
| [`errorResponse`](endpoints.md#errorresponse) | Function |
| [`EXTENDED_LIST_UNORDERED_PARAMETERS`](endpoints.md#extended_list_unordered_parameters) | Value |
| [`ExtractedRequestParams`](endpoints.md#extractedrequestparams) | Interface |
| [`extractRequestParams`](endpoints.md#extractrequestparams) | Function |
| [`fetchEntityCollection`](endpoints.md#fetchentitycollection) | Function |
| [`FetchEntityCollectionOptions`](endpoints.md#fetchentitycollectionoptions) | Interface |
| [`fetchExtendedSubordinatesList`](endpoints.md#fetchextendedsubordinateslist) | Function |
| [`fetchHistoricalKeys`](endpoints.md#fetchhistoricalkeys) | Function |
| [`FetchHistoricalKeysOptions`](endpoints.md#fetchhistoricalkeysoptions) | Interface |
| [`fetchListSubordinates`](endpoints.md#fetchlistsubordinates) | Function |
| [`fetchResolveResponse`](endpoints.md#fetchresolveresponse) | Function |
| [`fetchSubordinateEvents`](endpoints.md#fetchsubordinateevents) | Function |
| [`FetchSubordinateEventsOptions`](endpoints.md#fetchsubordinateeventsoptions) | Interface |
| [`fetchTrustMarkList`](endpoints.md#fetchtrustmarklist) | Function |
| [`FetchTrustMarkListParams`](endpoints.md#fetchtrustmarklistparams) | Interface |
| [`isExactContentType`](endpoints.md#isexactcontenttype) | Function |
| [`isReservedEndpointParameter`](endpoints.md#isreservedendpointparameter) | Function |
| [`jsonResponse`](endpoints.md#jsonresponse) | Function |
| [`jwtResponse`](endpoints.md#jwtresponse) | Function |
| [`LIST_UNORDERED_PARAMETERS`](endpoints.md#list_unordered_parameters) | Value |
| [`ListSubordinatesFilter`](endpoints.md#listsubordinatesfilter) | Interface |
| [`parseContentTypeHeader`](endpoints.md#parsecontenttypeheader) | Function |
| [`ParsedContentTypeHeader`](endpoints.md#parsedcontenttypeheader) | Interface |
| [`parseQueryParams`](endpoints.md#parsequeryparams) | Function |
| [`prepareEndpointParameters`](endpoints.md#prepareendpointparameters) | Function |
| [`readBodyWithLimit`](endpoints.md#readbodywithlimit) | Function |
| [`readStreamWithLimit`](endpoints.md#readstreamwithlimit) | Function |
| [`requireMethod`](endpoints.md#requiremethod) | Function |
| [`requireMethods`](endpoints.md#requiremethods) | Function |
| [`RESOLVE_UNORDERED_PARAMETERS`](endpoints.md#resolve_unordered_parameters) | Value |
| [`ResolveRequestParams`](endpoints.md#resolverequestparams) | Interface |
| [`SECURITY_HEADERS`](endpoints.md#security_headers) | Value |
| [`selectHistoricalVerificationKey`](endpoints.md#selecthistoricalverificationkey) | Function |
| [`SelectHistoricalVerificationKeyOptions`](endpoints.md#selecthistoricalverificationkeyoptions) | Interface |
| [`toPublicError`](endpoints.md#topublicerror) | Function |
| [`verifyHistoricalKeysResponse`](endpoints.md#verifyhistoricalkeysresponse) | Function |
| [`VerifyOptions`](endpoints.md#verifyoptions) | Interface |
| [`verifyResolveResponse`](endpoints.md#verifyresolveresponse) | Function |
| [`VerifyResolveResponseOptions`](endpoints.md#verifyresolveresponseoptions) | Interface |
| [`verifySignedJwkSet`](endpoints.md#verifysignedjwkset) | Function |
| [`VerifySignedJwkSetOptions`](endpoints.md#verifysignedjwksetoptions) | Interface |
| [`VerifySubordinateEventsOptions`](endpoints.md#verifysubordinateeventsoptions) | Interface |
| [`verifySubordinateEventsResponse`](endpoints.md#verifysubordinateeventsresponse) | Function |
| [`VerifyTrustMarkStatusOptions`](endpoints.md#verifytrustmarkstatusoptions) | Interface |
| [`verifyTrustMarkStatusResponse`](endpoints.md#verifytrustmarkstatusresponse) | Function |

## Discovery, chain validation, and assessments

| API | Kind |
|---|---|
| [`assessEntity`](chains.md#assessentity) | Function |
| [`calculateChainExpiration`](chains.md#calculatechainexpiration) | Function |
| [`chainRemainingTtl`](chains.md#chainremainingttl) | Function |
| [`compareTrustAnchorKeys`](chains.md#comparetrustanchorkeys) | Function |
| [`completeTrustChainValidation`](chains.md#completetrustchainvalidation) | Function |
| [`ContextualMetadataClaim`](chains.md#contextualmetadataclaim) | Interface |
| [`createConcurrencyLimiter`](chains.md#createconcurrencylimiter) | Function |
| [`createTrustChainOperation`](chains.md#createtrustchainoperation) | Function |
| [`describeTrustChain`](chains.md#describetrustchain) | Function |
| [`discoverEntity`](chains.md#discoverentity) | Function |
| [`discoverEntityFromChain`](chains.md#discoverentityfromchain) | Function |
| [`EntityAssessment`](chains.md#entityassessment) | Type |
| [`EntityAssessmentOptions`](chains.md#entityassessmentoptions) | Interface |
| [`FederationResolverConfig`](chains.md#federationresolverconfig) | Interface |
| [`FederationResolverIntegration`](chains.md#federationresolverintegration) | Type |
| [`FederationResolverService`](chains.md#federationresolverservice) | Class |
| [`fetchEntityConfiguration`](chains.md#fetchentityconfiguration) | Function |
| [`fetchSubordinateStatement`](chains.md#fetchsubordinatestatement) | Function |
| [`FetchSubordinateStatementOptions`](chains.md#fetchsubordinatestatementoptions) | Interface |
| [`isChainExpired`](chains.md#ischainexpired) | Function |
| [`isEntityAssessment`](chains.md#isentityassessment) | Function |
| [`longestExpiry`](chains.md#longestexpiry) | Value |
| [`preferTrustAnchor`](chains.md#prefertrustanchor) | Function |
| [`PreparedTrustChain`](chains.md#preparedtrustchain) | Interface |
| [`PrepareTrustChainOptions`](chains.md#preparetrustchainoptions) | Interface |
| [`prepareTrustChainValidation`](chains.md#preparetrustchainvalidation) | Function |
| [`RefreshOptions`](chains.md#refreshoptions) | Interface |
| [`refreshTrustChain`](chains.md#refreshtrustchain) | Function |
| [`resolveTrustChainForAnchor`](chains.md#resolvetrustchainforanchor) | Function |
| [`resolveTrustChains`](chains.md#resolvetrustchains) | Function |
| [`ResolveTrustChainsOptions`](chains.md#resolvetrustchainsoptions) | Interface |
| [`selectTrustChain`](chains.md#selecttrustchain) | Function |
| [`shortestChain`](chains.md#shortestchain) | Value |
| [`TrustAnchorKeyComparisonResult`](chains.md#trustanchorkeycomparisonresult) | Interface |
| [`TrustedResolverConfig`](chains.md#trustedresolverconfig) | Interface |
| [`TrustResolutionSource`](chains.md#trustresolutionsource) | Type |
| [`validateEntityId`](chains.md#validateentityid) | Function |
| [`validateFetchUrl`](chains.md#validatefetchurl) | Function |
| [`validateTrustChain`](chains.md#validatetrustchain) | Function |

## Metadata policies and constraints

| API | Kind |
|---|---|
| [`applyAllowedEntityTypes`](policy.md#applyallowedentitytypes) | Function |
| [`applyMetadataPolicy`](policy.md#applymetadatapolicy) | Function |
| [`checkConstraints`](policy.md#checkconstraints) | Function |
| [`checkMaxPathLength`](policy.md#checkmaxpathlength) | Function |
| [`checkNamingConstraints`](policy.md#checknamingconstraints) | Function |
| [`MetadataPolicyOptions`](policy.md#metadatapolicyoptions) | Interface |
| [`operators`](policy.md#operators) | Value |
| [`resolveMetadataPolicy`](policy.md#resolvemetadatapolicy) | Function |
| [`validateCustomOperators`](policy.md#validatecustomoperators) | Function |
| [`validateMetadataPolicy`](policy.md#validatemetadatapolicy) | Function |

## Trust Marks

| API | Kind |
|---|---|
| [`AttachTrustMarkOptions`](marks.md#attachtrustmarkoptions) | Interface |
| [`checkTrustMarkRequirements`](marks.md#checktrustmarkrequirements) | Function |
| [`EstablishTrustMarkIssuerOptions`](marks.md#establishtrustmarkissueroptions) | Interface |
| [`establishTrustMarkIssuerTrust`](marks.md#establishtrustmarkissuertrust) | Function |
| [`FederationTrustMarkIssuerEvidence`](marks.md#federationtrustmarkissuerevidence) | Interface |
| [`FetchAndAttachTrustMarkOptions`](marks.md#fetchandattachtrustmarkoptions) | Interface |
| [`fetchTrustMark`](marks.md#fetchtrustmark) | Function |
| [`FetchTrustMarkParams`](marks.md#fetchtrustmarkparams) | Interface |
| [`fetchTrustMarkStatus`](marks.md#fetchtrustmarkstatus) | Function |
| [`FetchTrustMarkStatusInput`](marks.md#fetchtrustmarkstatusinput) | Interface |
| [`FetchTrustMarkStatusOptions`](marks.md#fetchtrustmarkstatusoptions) | Interface |
| [`HistoricalTrustMarkOptions`](marks.md#historicaltrustmarkoptions) | Interface |
| [`isStoredTrustMarkEligible`](marks.md#isstoredtrustmarkeligible) | Function |
| [`MemoryTrustMarkStorage`](marks.md#memorytrustmarkstorage) | Class |
| [`MemoryTrustMarkStore`](marks.md#memorytrustmarkstore) | Class |
| [`OutOfBandTrustMarkIssuer`](marks.md#outofbandtrustmarkissuer) | Interface |
| [`RemoveTrustMarkSelector`](marks.md#removetrustmarkselector) | Type |
| [`signTrustMark`](marks.md#signtrustmark) | Function |
| [`signTrustMarkDelegation`](marks.md#signtrustmarkdelegation) | Function |
| [`SignTrustMarkDelegationOptions`](marks.md#signtrustmarkdelegationoptions) | Interface |
| [`SignTrustMarkOptions`](marks.md#signtrustmarkoptions) | Interface |
| [`TrustMarkDelegationIssuanceOptions`](marks.md#trustmarkdelegationissuanceoptions) | Type |
| [`TrustMarkHolder`](marks.md#trustmarkholder) | Class |
| [`TrustMarkIssuanceOptions`](marks.md#trustmarkissuanceoptions) | Interface |
| [`TrustMarkIssuerConfig`](marks.md#trustmarkissuerconfig) | Interface |
| [`trustMarkIssuerContext`](marks.md#trustmarkissuercontext) | Function |
| [`TrustMarkIssuerContext`](marks.md#trustmarkissuercontext-1) | Type |
| [`TrustMarkIssuerService`](marks.md#trustmarkissuerservice) | Class |
| [`TrustMarkIssuerServiceOptions`](marks.md#trustmarkissuerserviceoptions) | Interface |
| [`TrustMarkLifetime`](marks.md#trustmarklifetime) | Interface |
| [`TrustMarkListOptions`](marks.md#trustmarklistoptions) | Interface |
| [`TrustMarkListPage`](marks.md#trustmarklistpage) | Interface |
| [`TrustMarkProfile`](marks.md#trustmarkprofile) | Interface |
| [`TrustMarkRecord`](marks.md#trustmarkrecord) | Interface |
| [`TrustMarkRequestContext`](marks.md#trustmarkrequestcontext) | Interface |
| [`TrustMarkRequestExtension`](marks.md#trustmarkrequestextension) | Type |
| [`TrustMarkRequirements`](marks.md#trustmarkrequirements) | Interface |
| [`TrustMarkStatusAssessment`](marks.md#trustmarkstatusassessment) | Interface |
| [`TrustMarkStatusPolicy`](marks.md#trustmarkstatuspolicy) | Type |
| [`TrustMarkStatusPolicyContext`](marks.md#trustmarkstatuspolicycontext) | Interface |
| [`TrustMarkStatusResult`](marks.md#trustmarkstatusresult) | Interface |
| [`TrustMarkStorage`](marks.md#trustmarkstorage) | Interface |
| [`TrustMarkStore`](marks.md#trustmarkstore) | Interface |
| [`TrustMarkValidationOptions`](marks.md#trustmarkvalidationoptions) | Interface |
| [`TrustMarkVerificationOptions`](marks.md#trustmarkverificationoptions) | Interface |
| [`validateTrustMark`](marks.md#validatetrustmark) | Function |
| [`validateTrustMarkLogo`](marks.md#validatetrustmarklogo) | Function |
| [`ValidateTrustMarkLogoOptions`](marks.md#validatetrustmarklogooptions) | Interface |
| [`validateTrustMarkWithIssuer`](marks.md#validatetrustmarkwithissuer) | Function |
| [`ValidateTrustMarkWithIssuerOptions`](marks.md#validatetrustmarkwithissueroptions) | Interface |

## Entity Collection

| API | Kind |
|---|---|
| [`CollectionAuthentication`](collection.md#collectionauthentication) | Interface |
| [`CollectionEntry`](collection.md#collectionentry) | Interface |
| [`CollectionRefreshOptions`](collection.md#collectionrefreshoptions) | Interface |
| [`CollectionRefreshResult`](collection.md#collectionrefreshresult) | Interface |
| [`EntityCollectionCandidate`](collection.md#entitycollectioncandidate) | Interface |
| [`EntityCollectionCollector`](collection.md#entitycollectioncollector) | Type |
| [`EntityCollectionCollectorContext`](collection.md#entitycollectioncollectorcontext) | Interface |
| [`EntityCollectionConfig`](collection.md#entitycollectionconfig) | Interface |
| [`EntityCollectionCursor`](collection.md#entitycollectioncursor) | Interface |
| [`EntityCollectionCursorCapacityError`](collection.md#entitycollectioncursorcapacityerror) | Class |
| [`EntityCollectionFilter`](collection.md#entitycollectionfilter) | Type |
| [`EntityCollectionIntegration`](collection.md#entitycollectionintegration) | Type |
| [`EntityCollectionQueryMatcher`](collection.md#entitycollectionquerymatcher) | Type |
| [`EntityCollectionService`](collection.md#entitycollectionservice) | Class |
| [`EntityCollectionSnapshot`](collection.md#entitycollectionsnapshot) | Interface |
| [`EntityCollectionStore`](collection.md#entitycollectionstore) | Interface |
| [`MemoryEntityCollectionStore`](collection.md#memoryentitycollectionstore) | Class |
| [`MemoryEntityCollectionStoreOptions`](collection.md#memoryentitycollectionstoreoptions) | Interface |

## Schemas and wire types

| API | Kind |
|---|---|
| [`BaseEntityStatementSchema`](schemas.md#baseentitystatementschema) | Value |
| [`COLLECTION_INFO_CLAIMS`](schemas.md#collection_info_claims) | Value |
| [`createCollectionSchemas`](schemas.md#createcollectionschemas) | Function |
| [`DecodedFederationJwtPayload`](schemas.md#decodedfederationjwtpayload) | Type |
| [`EntityCollectionEntity`](schemas.md#entitycollectionentity) | Type |
| [`EntityCollectionEntitySchema`](schemas.md#entitycollectionentityschema) | Value |
| [`EntityCollectionRequestParams`](schemas.md#entitycollectionrequestparams) | Type |
| [`EntityCollectionRequestSchema`](schemas.md#entitycollectionrequestschema) | Value |
| [`EntityCollectionResponse`](schemas.md#entitycollectionresponse) | Type |
| [`EntityCollectionResponseSchema`](schemas.md#entitycollectionresponseschema) | Value |
| [`EntityConfigurationPayload`](schemas.md#entityconfigurationpayload) | Type |
| [`EntityConfigurationSchema`](schemas.md#entityconfigurationschema) | Value |
| [`EntityIdSchema`](schemas.md#entityidschema) | Value |
| [`EntityStatementPayload`](schemas.md#entitystatementpayload) | Type |
| [`EntityStatementPayloadSchema`](schemas.md#entitystatementpayloadschema) | Value |
| [`EntityTypeInfo`](schemas.md#entitytypeinfo) | Type |
| [`EntityTypeInfoSchema`](schemas.md#entitytypeinfoschema) | Value |
| [`EntityTypeMetadataMap`](schemas.md#entitytypemetadatamap) | Type |
| [`EntityTypeMetadataPolicy`](schemas.md#entitytypemetadatapolicy) | Type |
| [`EntityTypeMetadataPolicySchema`](schemas.md#entitytypemetadatapolicyschema) | Value |
| [`EXTENDED_LIST_SUPPORTED_CLAIMS`](schemas.md#extended_list_supported_claims) | Value |
| [`ExtendedListClaim`](schemas.md#extendedlistclaim) | Value and type |
| [`ExtendedListEntity`](schemas.md#extendedlistentity) | Type |
| [`ExtendedListEntitySchema`](schemas.md#extendedlistentityschema) | Value |
| [`ExtendedListQuery`](schemas.md#extendedlistquery) | Type |
| [`ExtendedListQuerySchema`](schemas.md#extendedlistqueryschema) | Value |
| [`ExtendedListRequestParams`](schemas.md#extendedlistrequestparams) | Interface |
| [`ExtendedListResponse`](schemas.md#extendedlistresponse) | Type |
| [`ExtendedListResponseSchema`](schemas.md#extendedlistresponseschema) | Value |
| [`FederationEntityMetadata`](schemas.md#federationentitymetadata) | Type |
| [`FederationEntityMetadataSchema`](schemas.md#federationentitymetadataschema) | Value |
| [`FederationMetadata`](schemas.md#federationmetadata) | Type |
| [`FederationMetadataPolicy`](schemas.md#federationmetadatapolicy) | Type |
| [`FederationMetadataPolicySchema`](schemas.md#federationmetadatapolicyschema) | Value |
| [`FederationMetadataSchema`](schemas.md#federationmetadataschema) | Value |
| [`FetchQuerySchema`](schemas.md#fetchqueryschema) | Value |
| [`getEntityTypes`](schemas.md#getentitytypes) | Function |
| [`HistoricalKeyEntry`](schemas.md#historicalkeyentry) | Type |
| [`HistoricalKeyEntrySchema`](schemas.md#historicalkeyentryschema) | Value |
| [`HistoricalKeysPayload`](schemas.md#historicalkeyspayload) | Type |
| [`HistoricalKeysPayloadSchema`](schemas.md#historicalkeyspayloadschema) | Value |
| [`JWK`](schemas.md#jwk) | Type |
| [`JWKSchema`](schemas.md#jwkschema) | Value |
| [`JWKSet`](schemas.md#jwkset) | Type |
| [`JWKSetSchema`](schemas.md#jwksetschema) | Value |
| [`ListQuerySchema`](schemas.md#listqueryschema) | Value |
| [`MetadataJWKSetSchema`](schemas.md#metadatajwksetschema) | Value |
| [`MetadataParameterPolicy`](schemas.md#metadataparameterpolicy) | Type |
| [`MetadataParameterPolicySchema`](schemas.md#metadataparameterpolicyschema) | Value |
| [`NamingConstraints`](schemas.md#namingconstraints) | Type |
| [`NamingConstraintsSchema`](schemas.md#namingconstraintsschema) | Value |
| [`OAuthAuthorizationServerMetadata`](schemas.md#oauthauthorizationservermetadata) | Type |
| [`OAuthAuthorizationServerPublicationMetadata`](schemas.md#oauthauthorizationserverpublicationmetadata) | Type |
| [`parseOAuthAuthorizationServerMetadata`](schemas.md#parseoauthauthorizationservermetadata) | Function |
| [`parseOAuthAuthorizationServerPublicationMetadata`](schemas.md#parseoauthauthorizationserverpublicationmetadata) | Function |
| [`ResolveQuerySchema`](schemas.md#resolvequeryschema) | Value |
| [`ResolveResponsePayload`](schemas.md#resolveresponsepayload) | Type |
| [`ResolveResponsePayloadSchema`](schemas.md#resolveresponsepayloadschema) | Value |
| [`SubordinateEvent`](schemas.md#subordinateevent) | Type |
| [`SubordinateEventSchema`](schemas.md#subordinateeventschema) | Value |
| [`SubordinateEventsResponse`](schemas.md#subordinateeventsresponse) | Type |
| [`SubordinateEventsResponseSchema`](schemas.md#subordinateeventsresponseschema) | Value |
| [`SubordinateEventType`](schemas.md#subordinateeventtype) | Value |
| [`SubordinateStatementPayload`](schemas.md#subordinatestatementpayload) | Type |
| [`SubordinateStatementSchema`](schemas.md#subordinatestatementschema) | Value |
| [`TrustChainConstraints`](schemas.md#trustchainconstraints) | Type |
| [`TrustChainConstraintsSchema`](schemas.md#trustchainconstraintsschema) | Value |
| [`TrustMarkDelegationPayload`](schemas.md#trustmarkdelegationpayload) | Type |
| [`TrustMarkDelegationPayloadSchema`](schemas.md#trustmarkdelegationpayloadschema) | Value |
| [`TrustMarkOwner`](schemas.md#trustmarkowner) | Type |
| [`TrustMarkOwnerSchema`](schemas.md#trustmarkownerschema) | Value |
| [`TrustMarkPayload`](schemas.md#trustmarkpayload) | Type |
| [`TrustMarkPayloadSchema`](schemas.md#trustmarkpayloadschema) | Value |
| [`TrustMarkRef`](schemas.md#trustmarkref) | Type |
| [`TrustMarkRefSchema`](schemas.md#trustmarkrefschema) | Value |
| [`TrustMarkStatusBodySchema`](schemas.md#trustmarkstatusbodyschema) | Value |
| [`TrustMarkStatusResponsePayload`](schemas.md#trustmarkstatusresponsepayload) | Type |
| [`TrustMarkStatusResponsePayloadSchema`](schemas.md#trustmarkstatusresponsepayloadschema) | Value |

## Protocol constants and defaults

| API | Kind |
|---|---|
| [`CachePrefix`](constants.md#cacheprefix) | Value |
| [`DEFAULT_CACHE_MAX_TTL_SECONDS`](constants.md#default_cache_max_ttl_seconds) | Value |
| [`DEFAULT_CACHE_TTL_SECONDS`](constants.md#default_cache_ttl_seconds) | Value |
| [`DEFAULT_CLIENT_ASSERTION_TTL_SECONDS`](constants.md#default_client_assertion_ttl_seconds) | Value |
| [`DEFAULT_CLOCK_SKEW_SECONDS`](constants.md#default_clock_skew_seconds) | Value |
| [`DEFAULT_DELEGATION_TTL_SECONDS`](constants.md#default_delegation_ttl_seconds) | Value |
| [`DEFAULT_ENTITY_STATEMENT_TTL_SECONDS`](constants.md#default_entity_statement_ttl_seconds) | Value |
| [`DEFAULT_HTTP_TIMEOUT_MS`](constants.md#default_http_timeout_ms) | Value |
| [`DEFAULT_KEY_RETIRE_AFTER_MS`](constants.md#default_key_retire_after_ms) | Value |
| [`DEFAULT_MAX_AUTHORITY_HINTS`](constants.md#default_max_authority_hints) | Value |
| [`DEFAULT_MAX_CHAIN_DEPTH`](constants.md#default_max_chain_depth) | Value |
| [`DEFAULT_MAX_CHAIN_LENGTH`](constants.md#default_max_chain_length) | Value |
| [`DEFAULT_MAX_REQUEST_BODY_BYTES`](constants.md#default_max_request_body_bytes) | Value |
| [`DEFAULT_MAX_RESOLUTION_STEPS`](constants.md#default_max_resolution_steps) | Value |
| [`DEFAULT_MAX_RESPONSE_BYTES`](constants.md#default_max_response_bytes) | Value |
| [`DEFAULT_REQUEST_OBJECT_TTL_SECONDS`](constants.md#default_request_object_ttl_seconds) | Value |
| [`EntityType`](constants.md#entitytype) | Value and type |
| [`EntityTypeIdentifier`](constants.md#entitytypeidentifier) | Type |
| [`FederationEndpoint`](constants.md#federationendpoint) | Value and type |
| [`FederationErrorCode`](constants.md#federationerrorcode) | Value and type |
| [`InternalErrorCode`](constants.md#internalerrorcode) | Value and type |
| [`JWT_BEARER_CLIENT_ASSERTION_TYPE`](constants.md#jwt_bearer_client_assertion_type) | Value |
| [`JwtTyp`](constants.md#jwttyp) | Value and type |
| [`MediaType`](constants.md#mediatype) | Value and type |
| [`PolicyOperator`](constants.md#policyoperator) | Value and type |
| [`REQUIRED_ALGORITHMS`](constants.md#required_algorithms) | Value |
| [`STANDARD_ENTITY_STATEMENT_CLAIMS`](constants.md#standard_entity_statement_claims) | Value |
| [`StandardPolicyOperator`](constants.md#standardpolicyoperator) | Enum and type |
| [`SUPPORTED_ALGORITHMS`](constants.md#supported_algorithms) | Value |
| [`SupportedAlgorithm`](constants.md#supportedalgorithm) | Type |
| [`TrustMarkStatus`](constants.md#trustmarkstatus) | Value and type |
| [`WELL_KNOWN_OPENID_FEDERATION`](constants.md#well_known_openid_federation) | Value |

