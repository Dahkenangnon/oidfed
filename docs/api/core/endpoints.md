# Federation endpoint clients and responses

[`@oidfed/core`](README.md)

Use the endpoint-specific clients to build protocol requests and verify signed responses. Keep transport success separate from trust validation. Standalone clients cannot infer a responder's Entity Identifier from its endpoint URL.

Direct fetch calls use authentication and transport controls such as `signal`, `httpTimeoutMs`, `offline`, URL restrictions, and response-size limits. Clients that verify a signed response also use their documented issuer, key, and time-check options. They do not discover or validate a Trust Chain or evaluate published Trust Marks.

The option interfaces below inherit the full `FederationOptions` type. Chain acquisition and selection (`trustResolution`, `chainSelection`, `entityConfigurations`), Trust Mark evaluation options, policy and constraint callbacks, `authorityHintFilter`, and chain traversal limits do not run on these direct clients. In particular, `maxTotalFetches` and `maxConcurrentFetches` do not bound a standalone request, and the clients do not use statement-cache settings. Higher-level discovery operations enforce their shared fetch budget by wrapping the HTTP transport before calling endpoint clients. Pass the same options object to discovery and endpoint clients when they share transport settings.

## `assertEndpointAuthenticationCompanions`

Validate a host's `federation_entity` metadata before publication. Each advertised `*_auth_methods` field for a known endpoint must have the corresponding endpoint URL. Supply an optional error class to preserve the host's configuration error type. [Source](../../../packages/core/src/schemas/metadata.ts#L62)

## `buildExtendedListRequestParameters`

[Source](../../../packages/core/src/federation-api/extended-list.ts#L21)

Build standard Extended Listing selectors for HTTP clients and local authority calls.

```typescript signature
buildExtendedListRequestParameters(endpoint: string, params?: ExtendedListRequestParams): Result<URLSearchParams, FederationError>;
```

## `COLLECTION_UNORDERED_PARAMETERS`

[Source](../../../packages/core/src/endpoint-parameters.ts#L26)

Collection §3.3.1 defines these repeated selectors by membership.

```typescript signature
const COLLECTION_UNORDERED_PARAMETERS: readonly ["entity_type", "trust_mark_type", "entity_claims", "info_claims", "locale"];
```

## `ENDPOINT_OPERATION_PARAMETERS`

Read-only lists of recognized selectors for Fetch, List, Extended Listing, Resolve, Trust Mark Status, Trust Mark List and Retrieval, and Subordinate Events. Historical Keys uses no standard operation selectors. Collection derives its selectors from its request format.

## `EndpointAdditionalParameters`

[Source](../../../packages/core/src/endpoint-parameters.ts#L34)

Extra endpoint parameters represented as single or repeated string values.

```typescript signature
type EndpointAdditionalParameters = Readonly<Record<string, string | readonly string[]>>;
```

## `endpointParameterValuesMatch`

[Source](../../../packages/core/src/endpoint-parameters.ts#L4)

Compare repeated endpoint parameters; unknown parameters retain exact ordering.

```typescript signature
endpointParameterValuesMatch(name: string, fixed: readonly string[], supplied: readonly string[], unorderedParameters: readonly string[]): boolean;
```

## `errorResponse`

[Source](../../../packages/core/src/http.ts#L78)

Creates an OAuth-style JSON error response.

```typescript signature
errorResponse(status: number, code: string, description: string): Response;
```

## `EXTENDED_LIST_UNORDERED_PARAMETERS`

[Source](../../../packages/core/src/endpoint-parameters.ts#L19)

Extended Listing selectors compared by set membership when reconciling fixed and supplied parameters.

```typescript signature
const EXTENDED_LIST_UNORDERED_PARAMETERS: readonly ["entity_type", "trust_mark_type"];
```

## `ExtractedRequestParams`

[Source](../../../packages/core/src/http.ts#L157)

Parameters extracted from an incoming endpoint request.

```typescript signature
interface ExtractedRequestParams {
	params: URLSearchParams;
	clientAssertion?: string | undefined;
	clientAssertionType?: string | undefined;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `params` | `URLSearchParams` | Parsed request parameters supplied to authentication. |
| `clientAssertion?` | `string \| undefined` | Prebuilt client assertion JWT; cannot be combined with static or provider-selected authentication. |
| `clientAssertionType?` | `string \| undefined` | Assertion-type parameter received with the client assertion. |

## `extractRequestParams`

[Source](../../../packages/core/src/http.ts#L163)

Extracts form/query params and client_assertion fields from a request.

```typescript signature
extractRequestParams(request: Request): Promise<ExtractedRequestParams>;
```

## `fetchEntityCollection`

[Source](../../../packages/core/src/federation-api/entity-collection.ts#L31)

Fetch informational collection data; no trust validation is implied.
Configure authentication.audience with the collection provider's Entity Identifier. Neither the endpoint
origin nor a requested Trust Anchor establishes that identity. getEndpointAuthentication receives no responder.
Authenticated requests use POST and never retry anonymously after authentication failure.
Pass `undefined` as the second argument to send a request without selectors.

```typescript signature
fetchEntityCollection(endpoint: string, params: EntityCollectionRequestParams | undefined, options: FetchEntityCollectionOptions): Promise<Result<EntityCollectionResponse>>;
```

## `FetchEntityCollectionOptions`

[Source](../../../packages/core/src/federation-api/entity-collection.ts#L18)

Selectors, authentication, and transport settings for an Entity Collection request. Inherited chain-operation fields have the scope described at the top of this reference; they do not start discovery or validation here.

```typescript signature
interface FetchEntityCollectionOptions extends FederationOptions {
	method?: "GET" | "POST";
	clientAssertion?: string;
	/** Additional exact informational names understood by this consumer. */
	infoClaims?: readonly string[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `method?` | `"GET" \| "POST"` | Authentication method or native HTTP method, as specified by this contract. |
| `clientAssertion?` | `string` | Prebuilt client assertion JWT; cannot be combined with static or provider-selected authentication. |
| `infoClaims?` | `readonly string[]` | Informational metadata claims selected or supported by the collection API. |
| `trustResolution?` | `import("./trust-chain/assessment.js").TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Independently supplied issuer keys for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
| `offline?` | `boolean` | Disallow network access when only supplied evidence is permitted. |
| `httpClient?` | `HttpClient` | Host HTTP transport; defaults to the runtime's fetch implementation. |
| `entityConfigurations?` | `ReadonlyMap<string, string> \| undefined` | Subject Entity Configuration JWTs used during chain validation; signatures and identity bindings still need validation. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `storage?` | `FederationStorage \| undefined` | Storage for standalone calls. Hosted calls inherit storage from their entity. |
| `logger?` | `Logger` | Optional host logger. Library calls are message-only, nonblocking, and protected from sink failures. |
| `httpTimeoutMs?` | `number` | Timeout in milliseconds for bounded transport or host callbacks; defaults to 10000. |
| `clockSkewSeconds?` | `number` | Allowed time-claim leeway in seconds; the default verifier allowance is 60 seconds. |
| `maxChainDepth?` | `number` | Maximum recursive discovery depth; defaults to 8. |
| `maxChainLength?` | `number` | Maximum statements in a validated chain, including both ECs. Default: 100; resource policy, not a protocol limit. |
| `maxResolutionSteps?` | `number` | Maximum eligible branch expansions per resolution, including reused statements. Default: 1000. |
| `maxAuthorityHints?` | `number` | Maximum authority hints examined for an entity; defaults to 10. |
| `maxConcurrentFetches?` | `number` | Maximum concurrent fetches during chain traversal and collection refresh; defaults to 6. |
| `cacheMaxTtlSeconds?` | `number` | Fetched EC and Subordinate Statement cache retention cap in seconds; defaults to 3600 and is bounded by the statement's `exp`. Applies to statement fetchers using a cache. |
| `signal?` | `AbortSignal` | Cancellation signal for the waiting caller and cooperative work started by this operation. |
| `maxResponseBytes?` | `number` | Maximum response or decoded token size in bytes for APIs applying this limit; the shared default is 524288. |
| `blockedCIDRs?` | `string[]` | Additional blocked IP ranges applied by URL fetch validation. |
| `allowedHosts?` | `string[]` | Optional exact hostname allowlist applied before outbound fetching. |
| `authorityHintFilter?` | `(hint: URL, subject: EntityId) => boolean` | Host predicate for accepting an authority hint before traversal. |
| `understoodCriticalClaims?` | `ReadonlySet<string>` | Extension claim names the application actually understands and processes; unknown critical claims are rejected. |
| `maxTotalFetches?` | `number` | Maximum HTTP client calls; discovery helpers share the allowance across discovery and candidate validation. Cached and supplied statements use no allowance. Core accepts zero. Default: 50. |
| `customPolicyOperators?` | `readonly PolicyOperatorDefinition[]` | Federation-defined policy operators in addition to the seven standard ones. Forwarded to `resolveMetadataPolicy` and `applyMetadataPolicy` during trust-chain validation. |
| `customConstraintChecks?` | `readonly ConstraintCheckDefinition[]` | Federation-defined constraints checked against authenticated chains. Unknown names are ignored. |

## `fetchExtendedSubordinatesList`

[Source](../../../packages/core/src/federation-api/extended-list.ts#L99)

Fetch an Extended Subordinate Listing and return the parsed response.
Configure the endpoint and authentication together from trusted configuration or validated metadata.
This standalone client uses authentication.audience without an independent responder identity;
getEndpointAuthentication receives no responder. Authenticated requests use POST and never retry anonymously.

```typescript signature
fetchExtendedSubordinatesList(endpoint: string, params: ExtendedListRequestParams | undefined, options: FederationOptions): Promise<Result<ExtendedListResponse, FederationError>>;
```

## `signHistoricalKeysResponse`

[Source](../../../packages/core/src/federation-api/historical-keys.ts#L39)

Sign the entity's available historical public-key records with its current Federation Entity signer. Supply the entity ID, a crypto context with `history`, and its federation options.

## `createHistoricalKeysHandler`

[Source](../../../packages/core/src/federation-api/historical-keys.ts#L68)

Build the shared HTTP handler for signing Historical Keys responses. The handler accepts `GET` after the host's authentication wrapper has verified and translated any authenticated `POST` request.

## `fetchHistoricalKeys`

[Source](../../../packages/core/src/federation-api/historical-keys.ts#L165)

Fetch and verify a Historical Keys JWT from a federation Historical Keys endpoint.

```typescript signature
fetchHistoricalKeys(endpoint: string, signerJwks: JWKSet, options: FetchHistoricalKeysOptions): Promise<Result<HistoricalKeysPayload, FederationError>>;
```

## `FetchHistoricalKeysOptions`

[Source](../../../packages/core/src/federation-api/historical-keys.ts#L159)

Verification and transport settings for retrieving historical federation keys. Inherited chain-operation fields have the scope described at the top of this reference; they do not start discovery or validation here.

```typescript signature
interface FetchHistoricalKeysOptions extends FederationOptions, VerifyOptions {
	clockSkewSeconds?: number;
	clock?: Clock;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `clockSkewSeconds?` | `number` | Allowed time-claim leeway in seconds; the default verifier allowance is 60 seconds. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `trustResolution?` | `import("./trust-chain/assessment.js").TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Independently supplied issuer keys for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
| `offline?` | `boolean` | Disallow network access when only supplied evidence is permitted. |
| `httpClient?` | `HttpClient` | Host HTTP transport; defaults to the runtime's fetch implementation. |
| `entityConfigurations?` | `ReadonlyMap<string, string> \| undefined` | Subject Entity Configuration JWTs used during chain validation; signatures and identity bindings still need validation. |
| `storage?` | `FederationStorage \| undefined` | Storage for standalone calls. Hosted calls inherit storage from their entity. |
| `logger?` | `Logger` | Optional host logger. Library calls are message-only, nonblocking, and protected from sink failures. |
| `httpTimeoutMs?` | `number` | Timeout in milliseconds for bounded transport or host callbacks; defaults to 10000. |
| `maxChainDepth?` | `number` | Maximum recursive discovery depth; defaults to 8. |
| `maxChainLength?` | `number` | Maximum statements in a validated chain, including both ECs. Default: 100; resource policy, not a protocol limit. |
| `maxResolutionSteps?` | `number` | Maximum eligible branch expansions per resolution, including reused statements. Default: 1000. |
| `maxAuthorityHints?` | `number` | Maximum authority hints examined for an entity; defaults to 10. |
| `maxConcurrentFetches?` | `number` | Maximum concurrent fetches during chain traversal and collection refresh; defaults to 6. |
| `cacheMaxTtlSeconds?` | `number` | Fetched EC and Subordinate Statement cache retention cap in seconds; defaults to 3600 and is bounded by the statement's `exp`. Applies to statement fetchers using a cache. |
| `signal?` | `AbortSignal` | Cancellation signal for the waiting caller and cooperative work started by this operation. |
| `maxResponseBytes?` | `number` | Maximum response or decoded token size in bytes for APIs applying this limit; the shared default is 524288. |
| `blockedCIDRs?` | `string[]` | Additional blocked IP ranges applied by URL fetch validation. |
| `allowedHosts?` | `string[]` | Optional exact hostname allowlist applied before outbound fetching. |
| `authorityHintFilter?` | `(hint: URL, subject: EntityId) => boolean` | Host predicate for accepting an authority hint before traversal. |
| `understoodCriticalClaims?` | `ReadonlySet<string>` | Extension claim names the application actually understands and processes; unknown critical claims are rejected. |
| `maxTotalFetches?` | `number` | Maximum HTTP client calls; discovery helpers share the allowance across discovery and candidate validation. Cached and supplied statements use no allowance. Core accepts zero. Default: 50. |
| `customPolicyOperators?` | `readonly PolicyOperatorDefinition[]` | Federation-defined policy operators in addition to the seven standard ones. Forwarded to `resolveMetadataPolicy` and `applyMetadataPolicy` during trust-chain validation. |
| `customConstraintChecks?` | `readonly ConstraintCheckDefinition[]` | Federation-defined constraints checked against authenticated chains. Unknown names are ignored. |
| `expectedIssuer` | `string` | Issuer identity that must match the verified payload. |

## `fetchListSubordinates`

[Source](../../../packages/core/src/federation-api/subordinate-listing.ts#L25)

Fetch an authority's subordinate listing and return its Entity Identifiers.
Configure the endpoint and authentication together from trusted configuration or validated metadata.
This standalone client uses authentication.audience without an independent responder identity;
getEndpointAuthentication receives no responder. Authenticated requests use POST and never retry anonymously.
Collection traversal supplies its known authority identity for an additional audience check.

```typescript signature
fetchListSubordinates(listEndpoint: string, filter: ListSubordinatesFilter | undefined, options: FederationOptions): Promise<Result<EntityId[], FederationError>>;
```

## `fetchResolveResponse`

[Source](../../../packages/core/src/federation-api/resolve.ts#L83)

Fetch a Resolve Response JWT; use verifyResolveResponse to authenticate the returned statement.
Configure authentication.audience with the resolver's Entity Identifier. Neither the endpoint origin
nor a requested Trust Anchor establishes that identity. getEndpointAuthentication receives no responder.
Authenticated requests use POST and never retry anonymously after authentication failure.

```typescript signature
fetchResolveResponse(resolveEndpoint: string, params: ResolveRequestParams, options: FederationOptions): Promise<Result<string, FederationError>>;
```

## `fetchSubordinateEvents`

[Source](../../../packages/core/src/federation-api/subordinate-events.ts#L65)

Fetch and verify an authority's history about one Immediate Subordinate.

```typescript signature
fetchSubordinateEvents(endpoint: string, subject: EntityId, options: FetchSubordinateEventsOptions): Promise<Result<SubordinateEventsResponse, FederationError>>;
```

## `FetchSubordinateEventsOptions`

[Source](../../../packages/core/src/federation-api/subordinate-events.ts#L56)

Subject, authentication, and verification settings for retrieving subordinate history. Inherited chain-operation fields have the scope described at the top of this reference; they do not start discovery or validation here.

```typescript signature
interface FetchSubordinateEventsOptions extends FederationOptions {
	/** Independently trusted public Federation Entity Keys of the issuer. */
	issuerJwks: JWKSet;
	issuer: EntityId;
	/** A caller-created private_key_jwt assertion, with the issuer Entity Identifier as audience. */
	clientAssertion?: string;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuerJwks` | `JWKSet` | Independently trusted public Federation Entity Keys of the issuer. |
| `issuer` | `EntityId` | Issuer identity for the signed artifact or configured service. |
| `clientAssertion?` | `string` | Prebuilt client assertion JWT; cannot be combined with static or provider-selected authentication. |
| `trustResolution?` | `import("./trust-chain/assessment.js").TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Independently supplied issuer keys for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
| `offline?` | `boolean` | Disallow network access when only supplied evidence is permitted. |
| `httpClient?` | `HttpClient` | Host HTTP transport; defaults to the runtime's fetch implementation. |
| `entityConfigurations?` | `ReadonlyMap<string, string> \| undefined` | Subject Entity Configuration JWTs used during chain validation; signatures and identity bindings still need validation. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `storage?` | `FederationStorage \| undefined` | Storage for standalone calls. Hosted calls inherit storage from their entity. |
| `logger?` | `Logger` | Optional host logger. Library calls are message-only, nonblocking, and protected from sink failures. |
| `httpTimeoutMs?` | `number` | Timeout in milliseconds for bounded transport or host callbacks; defaults to 10000. |
| `clockSkewSeconds?` | `number` | Allowed time-claim leeway in seconds; the default verifier allowance is 60 seconds. |
| `maxChainDepth?` | `number` | Maximum recursive discovery depth; defaults to 8. |
| `maxChainLength?` | `number` | Maximum statements in a validated chain, including both ECs. Default: 100; resource policy, not a protocol limit. |
| `maxResolutionSteps?` | `number` | Maximum eligible branch expansions per resolution, including reused statements. Default: 1000. |
| `maxAuthorityHints?` | `number` | Maximum authority hints examined for an entity; defaults to 10. |
| `maxConcurrentFetches?` | `number` | Maximum concurrent fetches during chain traversal and collection refresh; defaults to 6. |
| `cacheMaxTtlSeconds?` | `number` | Fetched EC and Subordinate Statement cache retention cap in seconds; defaults to 3600 and is bounded by the statement's `exp`. Applies to statement fetchers using a cache. |
| `signal?` | `AbortSignal` | Cancellation signal for the waiting caller and cooperative work started by this operation. |
| `maxResponseBytes?` | `number` | Maximum response or decoded token size in bytes for APIs applying this limit; the shared default is 524288. |
| `blockedCIDRs?` | `string[]` | Additional blocked IP ranges applied by URL fetch validation. |
| `allowedHosts?` | `string[]` | Optional exact hostname allowlist applied before outbound fetching. |
| `authorityHintFilter?` | `(hint: URL, subject: EntityId) => boolean` | Host predicate for accepting an authority hint before traversal. |
| `understoodCriticalClaims?` | `ReadonlySet<string>` | Extension claim names the application actually understands and processes; unknown critical claims are rejected. |
| `maxTotalFetches?` | `number` | Maximum HTTP client calls; discovery helpers share the allowance across discovery and candidate validation. Cached and supplied statements use no allowance. Core accepts zero. Default: 50. |
| `customPolicyOperators?` | `readonly PolicyOperatorDefinition[]` | Federation-defined policy operators in addition to the seven standard ones. Forwarded to `resolveMetadataPolicy` and `applyMetadataPolicy` during trust-chain validation. |
| `customConstraintChecks?` | `readonly ConstraintCheckDefinition[]` | Federation-defined constraints checked against authenticated chains. Unknown names are ignored. |

## `fetchTrustMarkList`

[Source](../../../packages/core/src/federation-api/fetch-trust-mark-list.ts#L16)

Fetch a list of Entity Identifiers with active Trust Marks of the given type.

```typescript signature
fetchTrustMarkList(endpoint: string, params: FetchTrustMarkListParams, options: FederationOptions): Promise<Result<EntityId[], FederationError>>;
```

This is an unsigned JSON endpoint response protected by HTTPS and any configured endpoint authentication. It is not independently validated Trust Mark evidence. Omit `sub` to list by type without identifying a specific holder; the host chooses between that query and a holder-specific Status request according to its privacy and freshness policy.

## `FetchTrustMarkListParams`

[Source](../../../packages/core/src/federation-api/fetch-trust-mark-list.ts#L10)

Trust Mark type and optional subject selectors for a Listing request.

```typescript signature
interface FetchTrustMarkListParams {
	trustMarkType: string;
	sub?: EntityId;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `trustMarkType` | `string` | Trust Mark type identifier used for issuance, verification, or filtering. |
| `sub?` | `EntityId` | Subject of the signed artifact. An Entity Configuration is self-issued; other artifacts name their own subject. |

## `isExactContentType`

[Source](../../../packages/core/src/http.ts#L43)

Check the exact media type required by the protocol, including its prohibition on parameters where applicable.

```typescript signature
isExactContentType(value: string | null | undefined, expectedMediaType: string): boolean;
```

## `isReservedEndpointParameter`

[Source](../../../packages/core/src/endpoint-parameters.ts#L60)

Names owned by federation protocols or their standard authentication fields.

```typescript signature
isReservedEndpointParameter(name: string): boolean;
```

## `jsonResponse`

[Source](../../../packages/core/src/http.ts#L67)

Creates a JSON response with the given body and status.

```typescript signature
jsonResponse(body: unknown, status?: number): Response;
```

## `jwtResponse`

[Source](../../../packages/core/src/http.ts#L56)

Creates a 200 response with the given JWT body and media type.

```typescript signature
jwtResponse(jwt: string, mediaType: string): Response;
```

## `LIST_UNORDERED_PARAMETERS`

[Source](../../../packages/core/src/endpoint-parameters.ts#L18)

Federation §8.2.1 filters by membership in the requested Entity Types.

```typescript signature
const LIST_UNORDERED_PARAMETERS: readonly ["entity_type"];
```

## `ListSubordinatesFilter`

[Source](../../../packages/core/src/federation-api/subordinate-listing.ts#L10)

Optional filters accepted by the subordinate listing endpoint.

```typescript signature
interface ListSubordinatesFilter {
	/** Open value space — Federation §5.1 permits identifiers beyond the published set. */
	entityType?: EntityTypeIdentifier | EntityTypeIdentifier[];
	trustMarked?: boolean;
	trustMarkType?: string;
	intermediate?: boolean;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entityType?` | `EntityTypeIdentifier \| EntityTypeIdentifier[]` | Entity Type Identifier used to select a metadata block or filter entries. |
| `trustMarked?` | `boolean` | Whether to filter a listing by the presence of eligible Trust Marks. |
| `trustMarkType?` | `string` | Trust Mark type identifier used for issuance, verification, or filtering. |
| `intermediate?` | `boolean` | Whether a Listing request is restricted to Intermediate Entities. |

## `parseContentTypeHeader`

[Source](../../../packages/core/src/http.ts#L25)

Parse a Content-Type header for media-type and parameter-aware checks.

```typescript signature
parseContentTypeHeader(value: string | null | undefined): ParsedContentTypeHeader | undefined;
```

## `ParsedContentTypeHeader`

[Source](../../../packages/core/src/http.ts#L19)

A parsed HTTP content type and its parameters.

```typescript signature
interface ParsedContentTypeHeader {
	readonly raw: string;
	readonly mediaType: string;
	readonly parameters: readonly string[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `raw` | `string` | Trimmed Content-Type header value before splitting its components. |
| `mediaType` | `string` | Trimmed media type; the parser preserves its original case. |
| `parameters` | `readonly string[]` | Trimmed semicolon-separated parameters; even an empty parameter prevents an exact match. |

## `parseQueryParams`

[Source](../../../packages/core/src/http.ts#L132)

Extracts query parameters from a request URL.

```typescript signature
parseQueryParams(request: Request): URLSearchParams;
```

## `prepareEndpointParameters`

[Source](../../../packages/core/src/endpoint-parameters.ts#L65)

Copy selectors and add extension parameters without overriding selectors or fixed URL values.

```typescript signature
prepareEndpointParameters(selectors: URLSearchParams, additional?: EndpointAdditionalParameters, fixed?: URLSearchParams): URLSearchParams;
```

### Usage example

Keep custom selectors separate from credentials and reserved parameters. For known set-valued selectors, parameter comparison ignores ordering and duplicate occurrences; unknown parameters keep their ordered comparison.

```ts
import {
  endpointParameterValuesMatch, prepareEndpointParameters, isReservedEndpointParameter,
  LIST_UNORDERED_PARAMETERS,
} from "@oidfed/core";

export function campusSelectors() {
  if (isReservedEndpointParameter("campus")) throw new Error("Choose an extension name");
  const parameters = prepareEndpointParameters(
    new URLSearchParams({ entity_type: "openid_provider" }),
    { campus: "north" },
  );
  const sameTypes = endpointParameterValuesMatch("entity_type",
    ["openid_provider", "oauth_authorization_server"],
    ["oauth_authorization_server", "openid_provider"], LIST_UNORDERED_PARAMETERS);
  return { parameters, sameTypes };
}
```

## `readBytesWithLimit`

Use this reader when you need the original bytes, for example to check a digest before decoding JSON. It returns `null` for an absent body and a zero-length array for an empty stream. A body exactly at the limit is accepted. Overflow cancels the stream and throws `BodyLimitExceeded`. An aborted signal cancels a pending read and propagates its reason. Transport failures propagate to the caller.

```ts
readBytesWithLimit(
  body: ReadableStream<Uint8Array> | null,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<Uint8Array<ArrayBuffer> | null>;
```

## `readBodyWithLimit`

[Source](../../../packages/core/src/http.ts#L207)

Stream-read a request body up to maxBytes, aborting if exceeded.
Checks Content-Length header first to reject oversized bodies early,
then counts actual bytes to catch a mismatched Content-Length.

```typescript signature
readBodyWithLimit(request: Request, maxBytes: number): Promise<{ ok: true; text: string } | { ok: false }>;
```

## `readStreamWithLimit`

[Source](../../../packages/core/src/http.ts#L180)

Read a ReadableStream up to maxBytes, returning the decoded text or failure.
Shared streaming core used by both request and response body readers.

```typescript signature
readStreamWithLimit(body: ReadableStream<Uint8Array>, maxBytes: number): Promise<{ ok: true; text: string } | { ok: false }>;
```

## `requireMethod`

[Source](../../../packages/core/src/http.ts#L138)

Returns a 405 response if the request method does not match, or null if it does.

```typescript signature
requireMethod(request: Request, method: string): Response | null;
```

## `requireMethods`

[Source](../../../packages/core/src/http.ts#L143)

Returns a 405 response if the request method is not in the allowed list, or null if it is.

```typescript signature
requireMethods(request: Request, methods: string[]): Response | null;
```

## `RESOLVE_UNORDERED_PARAMETERS`

[Source](../../../packages/core/src/endpoint-parameters.ts#L23)

Resolve selectors compared by set membership when reconciling fixed and supplied parameters.

```typescript signature
const RESOLVE_UNORDERED_PARAMETERS: readonly ["trust_anchor", "entity_type"];
```

## `ResolveRequestParams`

[Source](../../../packages/core/src/federation-api/resolve.ts#L70)

Resolve-endpoint request parameters. `trustAnchor` and `entityType` may repeat.

```typescript signature
interface ResolveRequestParams {
	sub: EntityId;
	trustAnchor: EntityId | EntityId[];
	/** Open value space — Federation §5.1 permits identifiers beyond the published set. */
	entityType?: EntityTypeIdentifier | EntityTypeIdentifier[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `sub` | `EntityId` | Subject of the signed artifact. An Entity Configuration is self-issued; other artifacts name their own subject. |
| `trustAnchor` | `EntityId \| EntityId[]` | Configured or requested Trust Anchor identity; this does not identify the endpoint responder. |
| `entityType?` | `EntityTypeIdentifier \| EntityTypeIdentifier[]` | Entity Type Identifier used to select a metadata block or filter entries. |

## `SECURITY_HEADERS`

[Source](../../../packages/core/src/http.ts#L10)

Standard security headers applied to all federation responses.

```typescript signature
const SECURITY_HEADERS: Record<string, string>;
```

Response helpers apply these defaults:

| Header | Value |
|---|---|
| `Cache-Control` | `no-store` |
| `X-Content-Type-Options` | `nosniff` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |

## `selectHistoricalVerificationKey`

[Source](../../../packages/core/src/federation-api/historical-keys.ts#L125)

Select a historical key usable for verifying material issued at the supplied NumericDate. Revoked keys are rejected by default. An explicitly allowed non-security reason permits only signatures strictly before revocation and within key validity; security reasons always reject the key.

```typescript signature
selectHistoricalVerificationKey(keys: readonly HistoricalKeyEntry[], options: SelectHistoricalVerificationKeyOptions): Result<HistoricalKeyEntry, FederationError>;
```

## `SelectHistoricalVerificationKeyOptions`

[Source](../../../packages/core/src/federation-api/historical-keys.ts#L115)

Time and revocation policy used to select a historical verification key.

```typescript signature
interface SelectHistoricalVerificationKeyOptions {
	readonly kid: string;
	readonly validAt: number;
	/** Additional security-revocation reasons defined by the federation (§8.7.3), matched exactly. */
	readonly securityRevocationReasons?: readonly string[];
	/** Explicit non-security reasons allowing signatures strictly before revocation. Default rejects all revoked keys. */
	readonly allowedRevocationReasons?: readonly string[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `kid` | `string` | Key identifier used to select a public verification key. |
| `validAt` | `number` | NumericDate at which record eligibility is evaluated, without verifier clock leeway. |
| `securityRevocationReasons?` | `readonly string[]` | Additional exact security-revocation reasons. These extend the built-in reasons and always reject the key, including when also allowlisted. |
| `allowedRevocationReasons?` | `readonly string[]` | Explicit non-security reasons allowing signatures strictly before revocation and within key validity. Omission rejects all revoked keys; absent or unspecified reasons remain rejected. |

## `toPublicError`

[Source](../../../packages/core/src/http.ts#L92)

Sanitizes internal errors into safe public-facing error details.

```typescript signature
toPublicError(error: FederationError): {
	status: number;
	code: string;
	description: string;
};
```

## `verifyHistoricalKeysResponse`

[Source](../../../packages/core/src/federation-api/historical-keys.ts#L90)

Verify and validate a Historical Keys Response JWT.

```typescript signature
verifyHistoricalKeysResponse(jwt: string, issuerJwks: JWKSet, options: VerifyOptions): Promise<Result<HistoricalKeysPayload, FederationError>>;
```

## `VerifyOptions`

[Source](../../../packages/core/src/federation-api/verify-issuer.ts#L10)

Expected signer identity, clock, and clock skew for verifying a signed federation response.

```typescript signature
interface VerifyOptions extends FederationOptions {
	/** Expected signer identity from trusted configuration or validated federation evidence. */
	expectedIssuer: string;
	clockSkewSeconds?: number;
	clock?: Clock;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `expectedIssuer` | `string` | Exact expected response issuer. Verification requires this identity as well as its trusted public keys. |
| `clockSkewSeconds?` | `number` | Allowed time-claim leeway in seconds; the default verifier allowance is 60 seconds. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |

## `verifyResolveResponse`

[Source](../../../packages/core/src/federation-api/resolve.ts#L28)

Verify a Resolve Response's typ, signature, claims, and recipient binding.
Federation §8.3.2 permits aud to be absent, including on authenticated responses.

```typescript signature
verifyResolveResponse(jwt: string, issuerJwks: JWKSet, options: VerifyResolveResponseOptions): Promise<Result<ResolveResponsePayload, FederationError>>;
```

## `VerifyResolveResponseOptions`

[Source](../../../packages/core/src/federation-api/resolve.ts#L18)

Expected resolver, subject, audience, and time settings for a Resolve response.

```typescript signature
interface VerifyResolveResponseOptions extends VerifyOptions {
	expectedSubject: string;
	/** Requesting party's Entity Identifier; required to accept a response containing aud. */
	expectedAudience?: string;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `expectedSubject` | `string` | Subject identity that must match the verified payload. |
| `expectedAudience?` | `string` | Recipient identity used for checking a present aud claim or a required proof audience. |
| `expectedIssuer` | `string` | Issuer identity that must match the verified payload. |
| `clockSkewSeconds?` | `number` | Allowed time-claim leeway in seconds; the default verifier allowance is 60 seconds. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |

## `verifySignedJwkSet`

[Source](../../../packages/core/src/jwks/signed-jwk-set.ts#L24)

Verify and validate a Signed JWK Set JWT (returned by signed_jwks_uri).
Checks typ=jwk-set+jwt, signature, and required payload claims (iss, sub, keys).

```typescript signature
verifySignedJwkSet(jwt: string, signerJwks: JWKSet, options: VerifySignedJwkSetOptions): Promise<Result<SignedJwkSetPayload, FederationError>>;
```

The returned payload has required `iss`, `sub`, and public `keys`, optional finite `iat`/`exp`, and preserved extension claims. Its local declaration name, `SignedJwkSetPayload`, is not a root export; TypeScript infers the payload after narrowing the successful Result.

## `VerifySignedJwkSetOptions`

[Source](../../../packages/core/src/jwks/signed-jwk-set.ts#L15)

Identity and time checks for a signed JWK Set response.

```typescript signature
interface VerifySignedJwkSetOptions extends VerifyOptions {
	/** Key owner from trusted context; §5.2.1 permits an owner distinct from the issuer. */
	expectedOwner: string;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `expectedOwner` | `string` | Key owner from trusted context; §5.2.1 permits an owner distinct from the issuer. |
| `expectedIssuer` | `string` | Issuer identity that must match the verified payload. |
| `clockSkewSeconds?` | `number` | Allowed time-claim leeway in seconds; the default verifier allowance is 60 seconds. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |

## `VerifySubordinateEventsOptions`

[Source](../../../packages/core/src/federation-api/subordinate-events.ts#L16)

Expected authority, subject, and time checks for subordinate history.

```typescript signature
interface VerifySubordinateEventsOptions extends FederationOptions {
	/** Expected authority Entity Identifier, independent of endpoint origin. */
	issuer: EntityId;
	subject: EntityId;
	clockSkewSeconds?: number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuer` | `EntityId` | Issuer identity for the signed artifact or configured service. |
| `subject` | `EntityId` | Subject identity for the statement, mark, or authentication being processed. |
| `clock?` | `FederationOptions["clock"]` | NumericDate time source; omitted clocks use the runtime's current time. |
| `clockSkewSeconds?` | `number` | Allowed time-claim leeway in seconds; the default verifier allowance is 60 seconds. |

## `verifySubordinateEventsResponse`

[Source](../../../packages/core/src/federation-api/subordinate-events.ts#L24)

Verify a history statement with independently trusted keys and expected identities.

```typescript signature
verifySubordinateEventsResponse(jwt: string, issuerJwks: JWKSet, options: VerifySubordinateEventsOptions): Promise<Result<SubordinateEventsResponse, FederationError>>;
```

## `VerifyTrustMarkStatusOptions`

[Source](../../../packages/core/src/federation-api/trust-mark-status.ts#L18)

Expected issuer, exact submitted mark, and freshness checks for a Trust Mark Status response.

```typescript signature
interface VerifyTrustMarkStatusOptions extends VerifyOptions {
	/** The exact JWT submitted to the status endpoint (Federation §8.4.2). */
	expectedTrustMark: string;
	/** Host-selected maximum age; the specification supplies no universal limit. */
	maxAgeSeconds?: number;
	/** Enable future-iat rejection without selecting a maximum age. */
	checkIssuedAt?: boolean;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `expectedTrustMark` | `string` | The exact JWT submitted to the status endpoint (Federation §8.4.2). |
| `maxAgeSeconds?` | `number` | Maximum accepted evidence age in seconds, interpreted by the owning freshness policy. |
| `checkIssuedAt?` | `boolean` | Enable future-iat rejection without selecting a maximum age. |
| `expectedIssuer` | `string` | Issuer identity that must match the verified payload. |
| `clockSkewSeconds?` | `number` | Allowed time-claim leeway in seconds; the default verifier allowance is 60 seconds. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |

## `verifyTrustMarkStatusResponse`

[Source](../../../packages/core/src/federation-api/trust-mark-status.ts#L30)

Verify and validate a Trust Mark Status Response JWT.

```typescript signature
verifyTrustMarkStatusResponse(jwt: string, issuerJwks: JWKSet, options: VerifyTrustMarkStatusOptions): Promise<Result<TrustMarkStatusResponsePayload, FederationError>>;
```

