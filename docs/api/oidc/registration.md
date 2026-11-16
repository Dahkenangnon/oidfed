# Registration and protocol keys

[`@oidfed/oidc`](README.md)

The role methods prepare or process Federation registration evidence. The host protocol engine owns authorization responses, token endpoints, PAR request storage, user sessions, and client persistence. Optional adapter and callback contracts connect those responsibilities. Federation signing keys and protocol signing keys have separate jobs.

Several exported configuration types describe the internal registration workflows assembled by role methods. They do not expose standalone registration functions; the role entries identify the public call sites.

## `AutomaticRegistrationConfig`

[Source](../../../packages/oidc/src/registration/automatic.ts#L50)

Typed client identity, protocol signers, publication metadata, and transport choices assembled by the public client role methods. The underlying automaticRegistration function is not a package-root export. Configure roles with OidcRelyingPartyRoleConfig or OAuthClientRoleConfig; method-specific options override the relevant fields.

```typescript signature
interface AutomaticRegistrationConfig {
	readonly entityId: EntityId;
	readonly protocolKeyProvider: ProtocolSigningKeyProvider;
	readonly authorityHints: readonly [EntityId, ...EntityId[]];
	readonly metadata: Record<string, Record<string, unknown>>;
	/** TTL for the Request Object JWT in seconds (default: 300). */
	readonly requestObjectTtlSeconds?: number;
	/**
	 * When true, attach the peer_trust_chain JWS header — a Trust Chain for
	 * the OP that ends at the same Trust Anchor as the RP chain. Disabled by
	 * default; set to true only when the RP wants the OP to use the
	 * metadata/policy values from the RP-built peer chain (for the
	 * Federation/Metadata Integrity properties). Registration returns an error
	 * if the peer chain to the shared Trust Anchor cannot be built.
	 */
	readonly includePeerTrustChain?: boolean;
	/**
	 * Selects how the signed Request Object reaches the OP's authorization
	 * endpoint. Defaults to `"form_post"` — the safest choice for Request
	 * Objects that carry an embedded `trust_chain` (the JWT can easily exceed
	 * the practical URL/header length limits of HTTP intermediaries).
	 *
	 * Pass `"query"` to preserve the historical 0.3.x GET-query behavior.
	 */
	readonly requestDelivery?: RequestDelivery;
	/**
	 * For `requestDelivery: "request_uri"`: the publicly-reachable URL at
	 * which the RP will host the signed Request Object JWT. REQUIRED in that
	 * mode and ignored otherwise. The library does NOT host the JWT — the
	 * caller must serve the returned `requestObjectJwt` at this URL with
	 * Content-Type `application/oauth-authz-req+jwt`, typically with a short
	 * TTL and single-use semantics.
	 */
	readonly requestUri?: string;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entityId` | `EntityId` | Exact Entity Identifier bound to this object or operation. |
| `protocolKeyProvider` | `ProtocolSigningKeyProvider` | Provider of Request Object and client-assertion signers. These are protocol keys, distinct from Federation Entity Keys. |
| `authorityHints` | `readonly [EntityId, ...EntityId[]]` | Immediate Superior identifiers for the client's publication/registration evidence. Attached host hints take precedence over role-configured hints. |
| `metadata` | `Record<string, Record<string, unknown>>` | Protocol metadata for this configuration or artifact. Use its owning type to distinguish a single role block from an Entity Type map. |
| `requestObjectTtlSeconds?` | `number` | Request Object lifetime in seconds; defaults to 300 and is bounded by the applicable client-chain lifetime. |
| `includePeerTrustChain?` | `boolean` | Include a peer_trust_chain ending at the selected shared anchor. Defaults to false; inability to build it returns a registration error. |
| `requestDelivery?` | `RequestDelivery` | Delivery mode: query, form_post, request_uri, or par. The default is form_post. The result shape depends on this mode. |
| `requestUri?` | `string` | HTTPS URL where the application will serve the returned Request Object for request_uri delivery. It is required in that mode; this library does not host it. |

## `AutomaticRegistrationContext`

[Source](../../../packages/oidc/src/registration/types.ts#L24)

Provider identity, clock, and leeway used for Request Object claim checks. It is a public context type, not a standalone signature-verification or trust-validation API.

```typescript signature
interface AutomaticRegistrationContext {
	/** The OP's own Entity Identifier */
	readonly opEntityId: EntityId;
	/** Maximum allowed clock skew in seconds (default: 60) */
	readonly clockSkewSeconds?: number;
	/** NumericDate clock used for expiry validation. */
	readonly clock?: Clock;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `opEntityId` | `EntityId` | The OP's own Entity Identifier |
| `clockSkewSeconds?` | `number` | Allowed time-claim leeway in seconds; the default verifier allowance is 60 seconds. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |

## `AutomaticRegistrationResult`

[Source](../../../packages/oidc/src/registration/automatic.ts#L96)

Success value discriminated by delivery. All variants contain requestObjectJwt, the selected provider trustChain, and its trustChainExpiresAt. The authorization Request Object also has its own exp, which can be earlier than that chain deadline. Narrow on delivery before accessing transport-specific fields. This result prepares an authorization interaction; it is not confirmation that the provider registered the client.

```typescript signature
type AutomaticRegistrationResult = ({ readonly requestObjectJwt: string; readonly trustChain: ValidatedTrustChain; readonly trustChainExpiresAt: number; } & {
	readonly delivery: "query";
	/** Full authorization-endpoint URL with `?request=…&client_id=…`. Redirect the user-agent here. */
	readonly authorizationUrl: string;
}) | ({ readonly requestObjectJwt: string; readonly trustChain: ValidatedTrustChain; readonly trustChainExpiresAt: number; } & {
	readonly delivery: "form_post";
	/** Bare authorization-endpoint URL. POST `formParams` here. */
	readonly authorizationEndpoint: string;
	/** Form fields to submit as `application/x-www-form-urlencoded` body. */
	readonly formParams: Record<string, string>;
}) | ({ readonly requestObjectJwt: string; readonly trustChain: ValidatedTrustChain; readonly trustChainExpiresAt: number; } & {
	readonly delivery: "request_uri";
	/** Echoes the caller-supplied URI; cache the `requestObjectJwt` under this URL. */
	readonly requestUri: string;
	/** Full authorization-endpoint URL with `?request_uri=…&client_id=…`. Redirect the user-agent here. */
	readonly authorizationUrl: string;
}) | ({ readonly requestObjectJwt: string; readonly trustChain: ValidatedTrustChain; readonly trustChainExpiresAt: number; } & {
	readonly delivery: "par";
	/** PAR endpoint URL the library POSTed to. */
	readonly pushedAuthorizationRequestEndpoint: string;
	/** Full authorization-endpoint URL with `?request_uri=urn:…&client_id=…`. Redirect the user-agent here. */
	readonly authorizationUrl: string;
	/** The `urn:`-style request URI returned by the PAR endpoint. */
	readonly parRequestUri: string;
	/** Absolute expiration time (seconds since epoch) computed from the PAR `expires_in` response. */
	readonly parExpiresAt: number;
});
```

Common fields:

| Field | Type | Description |
|---|---|---|
| `requestObjectJwt` | `string` | Signed Request Object for the client; observe its own expiration. |
| `trustChain` | `ValidatedTrustChain` | Selected provider chain, rather than the client's chain. |
| `trustChainExpiresAt` | `number` | Provider chain expiration as a NumericDate. |

| Delivery | Additional fields and host action |
|---|---|
| `query` | Redirect using `authorizationUrl`, which contains the signed request. |
| `form_post` | Submit `formParams` to `authorizationEndpoint`; the library returns these values without posting them. |
| `request_uri` | Serve `requestObjectJwt` at `requestUri` and redirect using `authorizationUrl`. |
| `par` | The PAR call has already been made. `parRequestUri` and `parExpiresAt` describe its response; redirect using `authorizationUrl`. |

## `ExplicitRegistrationConfig`

[Source](../../../packages/oidc/src/registration/explicit.ts#L39)

Client EC inputs assembled for explicit registration by the public client role. Its keyProvider supplies Federation signing keys, while any protocol keys belong inside metadata. The explicitRegistration implementation is not exported directly; explicitlyRegister supplies the host identity, composed client block, key provider, and hints. Not every field of this internal configuration shape has a corresponding per-call role option.

```typescript signature
interface ExplicitRegistrationConfig {
	readonly entityId: EntityId;
	readonly keyProvider: FederationKeyProvider;
	readonly authorityHints: readonly [EntityId, ...EntityId[]];
	readonly metadata: Record<string, Record<string, unknown>>;
	readonly entityConfigurationTtlSeconds?: number;
	readonly trustMarks?: ReadonlyArray<Record<string, unknown>>;
	/**
	 * Include the OP's chain to the selected shared anchor in the registration
	 * JWT header (§12.2.1). Defaults to false. Returns an error if no peer path
	 * can be resolved. Requests use the Entity Configuration JWT transport.
	 */
	readonly includePeerTrustChain?: boolean;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entityId` | `EntityId` | Exact Entity Identifier bound to this object or operation. |
| `keyProvider` | `FederationKeyProvider` | Current Federation Entity Keys and signer used for explicit-registration ECs or signed registration responses. |
| `authorityHints` | `readonly [EntityId, ...EntityId[]]` | Immediate Superior identifiers for the client's publication/registration evidence. Attached host hints take precedence over role-configured hints. |
| `metadata` | `Record<string, Record<string, unknown>>` | Protocol metadata for this configuration or artifact. Use its owning type to distinguish a single role block from an Entity Type map. |
| `entityConfigurationTtlSeconds?` | `number` | Lifetime in seconds for the client's explicit-registration EC; the internal registration configuration defaults to 86400. |
| `trustMarks?` | `ReadonlyArray<Record<string, unknown>>` | Trust Mark references, verified marks, or evaluations supplied by the owning contract. |
| `includePeerTrustChain?` | `boolean` | Include a peer_trust_chain ending at the selected shared anchor. Defaults to false; inability to build it returns a registration error. |

## `ExplicitRegistrationHandlerConfig`

[Source](../../../packages/oidc/src/registration/handler.ts#L45)

Configuration contract used by the provider role's explicit-registration handler. createExplicitRegistrationHandler is not a root export; use a provider role and its initialization/processing API. The handler validates the request and peer evidence, applies optional adapter and accreditation policy, prepares metadata, signs with Federation keys, then invokes the late invalidation hook followed by onRegistration. registrationManagement defaults to disabled; read-only mode retains adapter-supplied management fields, and the host must enforce the token's permissions.

```typescript signature
interface ExplicitRegistrationHandlerConfig extends RegistrationAccreditationPolicy {
	/** The OP's Entity Identifier — used as the aud check target and as the issuer of the response. */
	readonly opEntityId: EntityId;
	/** Protocol role used to check the server's peer metadata. Defaults to OP. */
	readonly providerMetadataType?: "openid_provider" | "oauth_authorization_server";
	/** Federation-only signing key provider used for the signed registration response. */
	readonly keyProvider: FederationKeyProvider;
	/** Non-empty trust anchors required for RP trust chain resolution. */
	readonly trustAnchors: TrustAnchorSet;
	/** TTL in seconds for the registration response JWT. Capped to chain expiry when a chain is resolved. */
	readonly registrationResponseTtlSeconds?: number;
	/** Optional protocol-specific adapter for metadata validation/enrichment. */
	readonly registrationProtocolAdapter?: RegistrationProtocolAdapter;
	/** Default disabled. In read-only mode the host MUST prevent the adapter-issued token from modifying registration. */
	readonly registrationManagement?: "disabled" | "read-only";
	/** Optional generator producing a client_secret embedded in the response. Returning undefined omits the field. */
	readonly generateClientSecret?: (sub: EntityId) => Promise<string | undefined>;
	/** Explicit-registration hook after response preparation and signing, before onRegistration. A failed hook prevents the HTTP success response. */
	readonly onRegistrationInvalidation?: (sub: EntityId) => Promise<void>;
	/** Optional callback fired when dynamic registration completes successfully. */
	readonly onRegistration?: (sub: EntityId, clientMetadata: Record<string, unknown>, clientSecret?: string) => Promise<void>;
	/** Federation-wide options (httpClient, clock, etc.). */
	readonly options?: FederationOptions;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `opEntityId` | `EntityId` | The OP's Entity Identifier — used as the aud check target and as the issuer of the response. |
| `providerMetadataType?` | `"openid_provider" \| "oauth_authorization_server"` | Protocol role used to check the server's peer metadata. Defaults to OP. |
| `keyProvider` | `FederationKeyProvider` | Current Federation Entity Keys and signer used for explicit-registration ECs or signed registration responses. |
| `trustAnchors` | `TrustAnchorSet` | Independently trusted anchor identities and their public Federation Entity Keys. |
| `registrationResponseTtlSeconds?` | `number` | Signed registration-response lifetime in seconds; defaults to 86400 and is capped by the validated client chain's expiry. |
| `registrationProtocolAdapter?` | `RegistrationProtocolAdapter` | Optional protocol/profile validation and response-enrichment callbacks. The registration flow independently checks the selected protocol schema and federation policy. |
| `registrationManagement?` | `"disabled" \| "read-only"` | Default disabled. In read-only mode the host MUST prevent the adapter-issued token from modifying registration. |
| `generateClientSecret?` | `(sub: EntityId) => Promise<string \| undefined>` | Optional explicit-registration secret generator. A nonempty returned value is added to the response; undefined omits it. |
| `onRegistrationInvalidation?` | `(sub: EntityId) => Promise<void>` | Explicit-registration hook after response preparation and signing, before onRegistration. A failed hook prevents the HTTP success response. |
| `onRegistration?` | `( sub: EntityId, clientMetadata: Record<string, unknown>, clientSecret?: string, ) => Promise<void>` | Optional persistence callback. It receives the client identifier, selected client metadata block, and any client secret. Automatic processing passes the protocol keys actually used for authentication. |
| `options?` | `FederationOptions` | Federation transport, time, validation, and resource settings; role options override host options, and method options override role options. |
| `trustMarkRequirements?` | `TrustMarkRequirements` | Declarative accreditation requirements checked before beforeRegistration and before accepting registration side effects. |
| `beforeRegistration?` | `( context: Readonly<RegistrationAccreditationContext>, signal?: AbortSignal, ) => Result<void> \| Promise<Result<void>>` | Application accreditation callback after declarative Trust Mark checks. A failing requirement prevents the callback; the callback must return a Result with ok set to true to continue. |

## `ExplicitRegistrationResult`

[Source](../../../packages/oidc/src/registration/explicit.ts#L54)

Verified provider registration response, selected client metadata, and credentials when returned. expiresAt bounds the signed response and trustChainExpiresAt bounds the provider evidence; use the registration only until the earlier deadline. Registration persistence and any later renewal are host responsibilities.

```typescript signature
interface ExplicitRegistrationResult {
	readonly registrationStatement: ParsedEntityStatement;
	readonly clientId: string;
	readonly clientSecret?: string;
	readonly expiresAt: number;
	readonly registeredMetadata: Readonly<Record<string, unknown>>;
	/** OP trust chain expiration; use the registration only until the earlier of this and expiresAt (§12.3). */
	readonly trustChainExpiresAt: number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `registrationStatement` | `ParsedEntityStatement` | Verified provider registration statement, containing its decoded header and payload. |
| `clientId` | `string` | Client identifier returned by the provider; Federation registration binds it to the client's Entity Identifier. |
| `clientSecret?` | `string` | Client secret returned by explicit registration when one was issued. Treat it as credential material. |
| `expiresAt` | `number` | Signed registration-response expiration. Stop using it at the earlier of this deadline and trustChainExpiresAt. |
| `registeredMetadata` | `Readonly<Record<string, unknown>>` | Verified selected client metadata block returned in the signed registration response. |
| `trustChainExpiresAt` | `number` | Provider Trust Chain expiration, separate from the signed registration response's expiration. |

## `OIDCRegistrationAdapter`

[Source](../../../packages/oidc/src/registration/adapter.ts#L21)

Optional OIDC-specific adapter implementing RegistrationProtocolAdapter. It validates a nested openid_relying_party block when present and adds a missing client_id during explicit response enrichment. Registration workflows perform their own effective protocol validation; this adapter alone is not a full metadata-map or trust validator.

```typescript signature
new OIDCRegistrationAdapter(): OIDCRegistrationAdapter;
```

### `OIDCRegistrationAdapter#validateClientMetadata`

Inspect raw.openid_relying_party when it is an object, returning InvalidMetadata if that nested block fails the effective RP schema. If the block is absent or non-object, return the original raw object unchanged. A bare client block therefore passes through; this method does not parse it as nested RP metadata. On success it returns the same raw object, not the schema's parsed copy. The concrete method takes only raw, unlike the interface's optional context argument.

[Source](../../../packages/oidc/src/registration/adapter.ts#L22)

```typescript signature
validateClientMetadata(raw: Record<string, unknown>): { ok: false; error: FederationError; } | { ok: true; value: Record<string, unknown>; };
```

- `param`: raw - Request metadata after superior overrides, constraints, and policy
- `param`: context - Optional adapter context (peer chain metadata, etc.)
- `returns`: The validated metadata or a federation error

### `OIDCRegistrationAdapter#enrichResponseMetadata`

Return a shallow copy of the selected RP response block, setting client_id to trustChain.entityId when its existing value is falsy. Nested values remain shared with the input. This does not independently validate the response or chain; the registration handler applies those checks.

[Source](../../../packages/oidc/src/registration/adapter.ts#L46)

```typescript signature
enrichResponseMetadata(rpMeta: Record<string, unknown>, trustChain: ValidatedTrustChain): Record<string, unknown>;
```

- `param`: rpMeta - The RP's resolved metadata
- `param`: trustChain - The validated trust chain for the RP
- `param`: context - Optional adapter context (peer chain metadata, etc.)
- `returns`: The enriched metadata for the response

## `PreparedPushedAuthorizationRequest`

[Source](../../../packages/oidc/src/registration/pushed.ts#L63)

Prepared PAR POST returned by the client role. Send endpoint, parameters, and headers through the application's HTTP/TLS transport; preparation itself sends no PAR request. The value contains the selected provider chain and, for applicable modes, a signed Request Object. The host handles the PAR response and subsequent authorization redirect.

```typescript signature
interface PreparedPushedAuthorizationRequest {
	readonly endpoint: string;
	/** Complete form body, including repeated resource parameters. */
	readonly parameters: URLSearchParams;
	readonly headers: Headers;
	readonly trustChain: ValidatedTrustChain;
	readonly requestObjectJwt?: string;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `endpoint` | `string` | Validated server PAR endpoint to which the host sends the prepared request. |
| `parameters` | `URLSearchParams` | Complete form body, including repeated resource values and the selected proof. Send it with the returned headers to endpoint. |
| `headers` | `Headers` | Complete HTTP headers to send with the prepared form. No HTTP request has been sent by preparation. |
| `trustChain` | `ValidatedTrustChain` | Selected validated provider chain supporting this prepared request. |
| `requestObjectJwt?` | `string` | Signed Request Object, present for request_object or attest_jwt_client_auth proof modes. |

## `ProcessAutomaticRegistrationOptions`

[Source](../../../packages/oidc/src/registration/process-automatic.ts#L58)

Validation inputs used by provider automatic-registration processing. The role supplies its own identity, replay store, and protocol type; callers supply the remaining per-call settings through processAutomaticRegistration. providerMetadata must be effective metadata for algorithm and policy negotiation, rather than an incomplete publication draft.

```typescript signature
interface ProcessAutomaticRegistrationOptions extends FederationOptions, RegistrationAccreditationPolicy {
	/** The OP's own Entity Identifier — REQUIRED to prevent cross-OP replay via `aud` validation. */
	opEntityId: EntityId;
	/** Server role selecting the registration protocol. Defaults to OIDC. */
	providerMetadataType?: "openid_provider" | "oauth_authorization_server";
	/** Effective provider metadata when supplied by a role or host. */
	providerMetadata?: Readonly<Record<string, unknown>>;
	/** Atomic replay protection required for one-time Request Object processing. */
	replayStore: ReplayStore;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `opEntityId` | `EntityId` | The OP's own Entity Identifier — REQUIRED to prevent cross-OP replay via `aud` validation. |
| `providerMetadataType?` | `"openid_provider" \| "oauth_authorization_server"` | Server role selecting the registration protocol. Defaults to OIDC. |
| `providerMetadata?` | `Readonly<Record<string, unknown>>` | Effective provider metadata when supplied by a role or host. |
| `replayStore` | `ReplayStore` | Atomic replay protection for one-time request proofs; processing automatic registration or PAR requires a configured store. |
| `trustResolution?` | `import("./trust-chain/assessment.js").TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Independently supplied issuer keys for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
| `offline?` | `boolean` | Disable network access in core federation retrieval. Host-owned protocol transport and direct protocol HTTP paths require their own transport policy. |
| `httpClient?` | `HttpClient` | Host HTTP transport; defaults to the runtime's fetch implementation. |
| `entityConfigurations?` | `ReadonlyMap<string, string> \| undefined` | Subject Entity Configuration JWTs used during chain validation; signatures and identity bindings still need validation. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `cache?` | `CacheProvider` | Host cache for signed statements or operation results; cache hits do not establish trust. |
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
| `blockedCIDRs?` | `string[]` | Additional blocked IPv4 CIDRs used by core URL validation. DNS resolution and connection-level destination checks remain the host transport's responsibility. |
| `allowedHosts?` | `string[]` | Optional exact hostname allowlist applied before outbound fetching. |
| `authorityHintFilter?` | `(hint: URL, subject: EntityId) => boolean` | Host predicate for accepting an authority hint before traversal. |
| `understoodCriticalClaims?` | `ReadonlySet<string>` | Extension claim names the application actually understands and processes; unknown critical claims are rejected. |
| `maxTotalFetches?` | `number` | Maximum HTTP client calls; discovery helpers share the allowance across discovery and candidate validation. Cached and supplied statements use no allowance. Core accepts zero. Default: 50. |
| `customPolicyOperators?` | `readonly PolicyOperatorDefinition[]` | Federation-defined policy operators in addition to the seven standard ones. Forwarded to `resolveMetadataPolicy` and `applyMetadataPolicy` during trust-chain validation. |
| `customConstraintChecks?` | `readonly ConstraintCheckDefinition[]` | Federation-defined constraints checked against authenticated chains. Unknown names are ignored. |
| `trustMarkRequirements?` | `TrustMarkRequirements` | Declarative accreditation requirements checked before beforeRegistration and before accepting registration side effects. |
| `beforeRegistration?` | `( context: Readonly<RegistrationAccreditationContext>, signal?: AbortSignal, ) => Result<void> \| Promise<Result<void>>` | Application accreditation callback after declarative Trust Mark checks. A failing requirement prevents the callback; the callback must return a Result with ok set to true to continue. |

## `ProcessedAutomaticRegistration`

[Source](../../../packages/oidc/src/registration/process-automatic.ts#L52)

Automatic-registration evidence, including the exact resolved protocol keys used to verify the signed Request Object and authenticationExpiresAt. That deadline includes permitted JWT clock skew while never extending the client chain's expiry. Recheck time-sensitive evidence before using it later.

```typescript signature
interface ProcessedAutomaticRegistration extends ProcessedRegistration {
	readonly protocolKeys: ResolvedEntityKeys;
	/** Acceptance deadline, including JWT clock skew and unextended trust expiry. */
	readonly authenticationExpiresAt: number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `protocolKeys` | `ResolvedEntityKeys` | Resolved public protocol keys used for Request Object signature verification, including their source. |
| `authenticationExpiresAt` | `number` | Acceptance deadline, including JWT clock skew and unextended trust expiry. |
| `rpEntityId` | `EntityId` | Registered client Entity Identifier; the RP field name also applies to the OAuth client profile. |
| `resolvedRpMetadata` | `Readonly<Record<string, unknown>>` | Resolved client metadata for the selected OIDC or OAuth profile; the historical RP field name is retained for both. |
| `trustChain` | `ValidatedTrustChain` | Supplied or validated Trust Chain, in the representation declared by this contract. |
| `peerResolvedOpMetadata?` | `Readonly<Record<string, unknown>>` | When the Request Object carried a `peer_trust_chain` JWS header, the OP's resolved metadata as derived from the RP-supplied peer chain. Integrators may use these RP-chosen values when creating the client registration; the library validates structural integrity but does not auto-apply the values. |

## `ProcessedPushedAuthorizationRequest`

[Source](../../../packages/oidc/src/registration/pushed.ts#L82)

Validated PAR parameters plus the selected client registration evidence and authentication deadline. Repeated resource values are preserved. The provider role can run its persistence callback before returning; the host still creates the PAR success response and stores the pushed request.

```typescript signature
interface ProcessedPushedAuthorizationRequest extends ProcessedAutomaticRegistration {
	readonly parameters: Readonly<Record<string, unknown>>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `parameters` | `Readonly<Record<string, unknown>>` | Validated PAR authorization parameters; repeated resource values are retained. |
| `protocolKeys` | `ResolvedEntityKeys` | Resolved public protocol keys used for Request Object signature verification, including their source. |
| `authenticationExpiresAt` | `number` | Acceptance deadline, including JWT clock skew and unextended trust expiry. |
| `rpEntityId` | `EntityId` | Registered client Entity Identifier; the RP field name also applies to the OAuth client profile. |
| `resolvedRpMetadata` | `Readonly<Record<string, unknown>>` | Resolved client metadata for the selected OIDC or OAuth profile; the historical RP field name is retained for both. |
| `trustChain` | `ValidatedTrustChain` | Supplied or validated Trust Chain, in the representation declared by this contract. |
| `peerResolvedOpMetadata?` | `Readonly<Record<string, unknown>>` | When the Request Object carried a `peer_trust_chain` JWS header, the OP's resolved metadata as derived from the RP-supplied peer chain. Integrators may use these RP-chosen values when creating the client registration; the library validates structural integrity but does not auto-apply the values. |

## `ProcessedRegistration`

[Source](../../../packages/oidc/src/registration/process-automatic.ts#L37)

Validated client registration evidence shared by processing results. Historical rp/op field names also apply to OAuthClientRole and OAuthAuthorizationServerRole. This data does not itself create a client record or a protocol response; public provider role processing invokes configured persistence callbacks.

```typescript signature
interface ProcessedRegistration {
	readonly rpEntityId: EntityId;
	readonly resolvedRpMetadata: Readonly<Record<string, unknown>>;
	readonly trustChain: ValidatedTrustChain;
	/**
	 * When the Request Object carried a `peer_trust_chain` JWS header, the
	 * OP's resolved metadata as derived from the RP-supplied peer chain.
	 * Integrators may use these RP-chosen values when creating the client
	 * registration; the library validates structural integrity but does not
	 * auto-apply the values.
	 */
	readonly peerResolvedOpMetadata?: Readonly<Record<string, unknown>>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `rpEntityId` | `EntityId` | Registered client Entity Identifier; the RP field name also applies to the OAuth client profile. |
| `resolvedRpMetadata` | `Readonly<Record<string, unknown>>` | Resolved client metadata for the selected OIDC or OAuth profile; the historical RP field name is retained for both. |
| `trustChain` | `ValidatedTrustChain` | Supplied or validated Trust Chain, in the representation declared by this contract. |
| `peerResolvedOpMetadata?` | `Readonly<Record<string, unknown>>` | When the Request Object carried a `peer_trust_chain` JWS header, the OP's resolved metadata as derived from the RP-supplied peer chain. Integrators may use these RP-chosen values when creating the client registration; the library validates structural integrity but does not auto-apply the values. |

## `ProcessExplicitRegistrationOptions`

[Source](../../../packages/oidc/src/registration/process-explicit.ts#L44)

Validation inputs used by the internal explicit-registration processor. The public provider role assembles these through its mounted HTTP handler; processExplicitRegistration itself is not a package-root function. The protocol type selects the OIDC or OAuth client metadata. A supplied Trust Chain header remains signed evidence requiring full validation.

```typescript signature
interface ProcessExplicitRegistrationOptions extends FederationOptions, RegistrationAccreditationPolicy {
	/** The OP's own Entity Identifier — REQUIRED for `aud` validation. */
	opEntityId: EntityId;
	/** Protocol role of the local server whose peer metadata is consumed. Defaults to OP. */
	providerMetadataType?: "openid_provider" | "oauth_authorization_server";
	/** Optional `trust_chain` JWS header value supplied with an entity-statement body. */
	trustChainHeader?: readonly string[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `opEntityId` | `EntityId` | The OP's own Entity Identifier — REQUIRED for `aud` validation. |
| `providerMetadataType?` | `"openid_provider" \| "oauth_authorization_server"` | Protocol role of the local server whose peer metadata is consumed. Defaults to OP. |
| `trustChainHeader?` | `readonly string[]` | Optional `trust_chain` JWS header value supplied with an entity-statement body. |
| `trustResolution?` | `import("./trust-chain/assessment.js").TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Independently supplied issuer keys for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
| `offline?` | `boolean` | Disable network access in core federation retrieval. Host-owned protocol transport and direct protocol HTTP paths require their own transport policy. |
| `httpClient?` | `HttpClient` | Host HTTP transport; defaults to the runtime's fetch implementation. |
| `entityConfigurations?` | `ReadonlyMap<string, string> \| undefined` | Subject Entity Configuration JWTs used during chain validation; signatures and identity bindings still need validation. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `cache?` | `CacheProvider` | Host cache for signed statements or operation results; cache hits do not establish trust. |
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
| `blockedCIDRs?` | `string[]` | Additional blocked IPv4 CIDRs used by core URL validation. DNS resolution and connection-level destination checks remain the host transport's responsibility. |
| `allowedHosts?` | `string[]` | Optional exact hostname allowlist applied before outbound fetching. |
| `authorityHintFilter?` | `(hint: URL, subject: EntityId) => boolean` | Host predicate for accepting an authority hint before traversal. |
| `understoodCriticalClaims?` | `ReadonlySet<string>` | Extension claim names the application actually understands and processes; unknown critical claims are rejected. |
| `maxTotalFetches?` | `number` | Maximum HTTP client calls; discovery helpers share the allowance across discovery and candidate validation. Cached and supplied statements use no allowance. Core accepts zero. Default: 50. |
| `customPolicyOperators?` | `readonly PolicyOperatorDefinition[]` | Federation-defined policy operators in addition to the seven standard ones. Forwarded to `resolveMetadataPolicy` and `applyMetadataPolicy` during trust-chain validation. |
| `customConstraintChecks?` | `readonly ConstraintCheckDefinition[]` | Federation-defined constraints checked against authenticated chains. Unknown names are ignored. |
| `trustMarkRequirements?` | `TrustMarkRequirements` | Declarative accreditation requirements checked before beforeRegistration and before accepting registration side effects. |
| `beforeRegistration?` | `( context: Readonly<RegistrationAccreditationContext>, signal?: AbortSignal, ) => Result<void> \| Promise<Result<void>>` | Application accreditation callback after declarative Trust Mark checks. A failing requirement prevents the callback; the callback must return a Result with ok set to true to continue. |

## `ProcessPushedAuthorizationRequestOptions`

[Source](../../../packages/oidc/src/registration/pushed.ts#L71)

Provider PAR validation and authentication inputs. The public provider method supplies its identity, protocol type, and replay store from the initialized role. Effective providerMetadata controls negotiation; a trusted host TLS callback is required for certificate authentication, and Client Attestation requires the host's attester and acceptance policies. The host protocol engine creates and stores any PAR request_uri after successful processing.

```typescript signature
interface ProcessPushedAuthorizationRequestOptions extends ProcessAutomaticRegistrationOptions {
	/** Effective server metadata; partial publication metadata is insufficient for method negotiation. */
	readonly providerMetadata: Readonly<Record<string, unknown>>;
	/** Trusted host TLS integration must return the certificate proven by the connection (base64 DER). */
	readonly clientCertificate?: (request: Request, signal: AbortSignal) => string | undefined | Promise<string | undefined>;
	readonly clientAttestation?: Omit<AuthenticateClientAttestationOptions, "audience" | "clientId">;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `providerMetadata` | `Readonly<Record<string, unknown>>` | Effective server metadata; partial publication metadata is insufficient for method negotiation. |
| `clientCertificate?` | `( request: Request, signal: AbortSignal, ) => string \| undefined \| Promise<string \| undefined>` | Trusted host TLS integration must return the certificate proven by the connection (base64 DER). |
| `clientAttestation?` | `Omit<AuthenticateClientAttestationOptions, "audience" \| "clientId">` | Host-supplied attester trust, freshness, replay, and acceptance policy for PAR attestation authentication. The processing role supplies the provider audience and client identity. |
| `opEntityId` | `EntityId` | The OP's own Entity Identifier — REQUIRED to prevent cross-OP replay via `aud` validation. |
| `providerMetadataType?` | `"openid_provider" \| "oauth_authorization_server"` | Server role selecting the registration protocol. Defaults to OIDC. |
| `replayStore` | `ReplayStore` | Atomic replay protection for one-time request proofs; processing automatic registration or PAR requires a configured store. |
| `trustResolution?` | `import("./trust-chain/assessment.js").TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Independently supplied issuer keys for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
| `offline?` | `boolean` | Disable network access in core federation retrieval. Host-owned protocol transport and direct protocol HTTP paths require their own transport policy. |
| `httpClient?` | `HttpClient` | Host HTTP transport; defaults to the runtime's fetch implementation. |
| `entityConfigurations?` | `ReadonlyMap<string, string> \| undefined` | Subject Entity Configuration JWTs used during chain validation; signatures and identity bindings still need validation. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `cache?` | `CacheProvider` | Host cache for signed statements or operation results; cache hits do not establish trust. |
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
| `blockedCIDRs?` | `string[]` | Additional blocked IPv4 CIDRs used by core URL validation. DNS resolution and connection-level destination checks remain the host transport's responsibility. |
| `allowedHosts?` | `string[]` | Optional exact hostname allowlist applied before outbound fetching. |
| `authorityHintFilter?` | `(hint: URL, subject: EntityId) => boolean` | Host predicate for accepting an authority hint before traversal. |
| `understoodCriticalClaims?` | `ReadonlySet<string>` | Extension claim names the application actually understands and processes; unknown critical claims are rejected. |
| `maxTotalFetches?` | `number` | Maximum HTTP client calls; discovery helpers share the allowance across discovery and candidate validation. Cached and supplied statements use no allowance. Core accepts zero. Default: 50. |
| `customPolicyOperators?` | `readonly PolicyOperatorDefinition[]` | Federation-defined policy operators in addition to the seven standard ones. Forwarded to `resolveMetadataPolicy` and `applyMetadataPolicy` during trust-chain validation. |
| `customConstraintChecks?` | `readonly ConstraintCheckDefinition[]` | Federation-defined constraints checked against authenticated chains. Unknown names are ignored. |
| `trustMarkRequirements?` | `TrustMarkRequirements` | Declarative accreditation requirements checked before beforeRegistration and before accepting registration side effects. |
| `beforeRegistration?` | `( context: Readonly<RegistrationAccreditationContext>, signal?: AbortSignal, ) => Result<void> \| Promise<Result<void>>` | Application accreditation callback after declarative Trust Mark checks. A failing requirement prevents the callback; the callback must return a Result with ok set to true to continue. |

## `ProtocolSigningKeyProvider`

[Source](../../../packages/oidc/src/protocol-keys.ts#L3)

Signing-capability contract for Request Objects and client assertions. Publish the corresponding public protocol keys in the client metadata; these are separate from the host's Federation Entity Keys. A dynamic implementation can select current signers on each call.

```typescript signature
interface ProtocolSigningKeyProvider {
	getRequestObjectSigner(): Promise<JwtSigner>;
	getClientAssertionSigner?(): Promise<JwtSigner>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `getRequestObjectSigner` | `() => Promise<JwtSigner>` | Return the current protocol signer used for signed Request Objects. |
| `getClientAssertionSigner?` | `() => Promise<JwtSigner>` | Return a protocol client-assertion signer; callers fall back to the Request Object signer when this method is absent. |

## `PushedAuthorizationProof`

[Source](../../../packages/oidc/src/registration/pushed.ts#L53)

Client-side proof selection for prepared PAR. request_object signs the Request Object; private_key_jwt creates a published-key assertion; self_signed_tls_client_auth checks that the supplied base64 DER certificate appears in the resolved protocol JWKS, while the host supplies the actual TLS connection. attest_jwt_client_auth supplies an attestation/proof pair and also includes a signed Request Object. Preparation checks client/server binding and declared algorithms, without substituting for receiver-side authentication.

```typescript signature
type PushedAuthorizationProof = {
	readonly mode: "request_object";
} | {
	readonly mode: "private_key_jwt";
} | {
	readonly mode: "self_signed_tls_client_auth";
	readonly certificate: string;
} | {
	readonly mode: "attest_jwt_client_auth";
	readonly attestationJwt: string;
	readonly popJwt: string;
};
```

## `RegistrationAccreditationContext`

[Source](../../../packages/oidc/src/registration/accreditation.ts#L13)

Validated client-chain evidence and the automatic/explicit flow discriminator supplied to beforeRegistration. The callback receives a detached, recursively frozen copy; it cannot alter the original authentication evidence.

```typescript signature
interface RegistrationAccreditationContext {
	readonly chain: ValidatedTrustChain;
	readonly registrationType: "automatic" | "explicit";
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `chain` | `ValidatedTrustChain` | Validated client chain supplied to the accreditation policy as detached, recursively frozen evidence. |
| `registrationType` | `"automatic" \| "explicit"` | Registration flow being evaluated: automatic or explicit. |

## `RegistrationAccreditationPolicy`

[Source](../../../packages/oidc/src/registration/accreditation.ts#L17)

Optional declarative Trust Mark requirements followed by an application callback. A failing declarative check prevents the callback. beforeRegistration receives detached, recursively frozen client-chain evidence and a cancellation signal; it must return a successful Result to continue. A failure, throw, rejection, timeout, or cancellation rejects registration before acceptance side effects. Status queries and external accreditation policy remain explicit host choices.

```typescript signature
interface RegistrationAccreditationPolicy {
	readonly trustMarkRequirements?: TrustMarkRequirements;
	readonly beforeRegistration?: (context: Readonly<RegistrationAccreditationContext>, signal?: AbortSignal) => Result<void> | Promise<Result<void>>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `trustMarkRequirements?` | `TrustMarkRequirements` | Declarative accreditation requirements checked before beforeRegistration and before accepting registration side effects. |
| `beforeRegistration?` | `( context: Readonly<RegistrationAccreditationContext>, signal?: AbortSignal, ) => Result<void> \| Promise<Result<void>>` | Application accreditation callback after declarative Trust Mark checks. A failing requirement prevents the callback; the callback must return a Result with ok set to true to continue. |

## `RegistrationProtocolAdapter`

[Source](../../../packages/oidc/src/registration/adapter-types.ts#L29)

Optional synchronous hooks for protocol/profile metadata checks and explicit-response enrichment. The federation flow independently validates its selected client schema and policy. Explicit validateClientMetadata receives the full resolved Entity Type map; automatic processing receives the selected client block. An adapter supporting both flows must handle those input shapes. Explicit processing uses the successful returned map when preparing response metadata. Automatic processing checks only acceptance; it persists the resolved client block and verified protocol keys rather than the adapter's returned replacement. Explicit enrichment receives the selected block and validated chain; automatic processing does not call enrichResponseMetadata. Exceptions can propagate to the calling role.

```typescript signature
interface RegistrationProtocolAdapter {
	/**
	 * Validate resolved client metadata from the registration request.
	 * Called after federation-layer validation succeeds.
	 *
	 * @param raw - Request metadata after superior overrides, constraints, and policy
	 * @param context - Optional adapter context (peer chain metadata, etc.)
	 * @returns The validated metadata or a federation error
	 */
	validateClientMetadata(raw: Record<string, unknown>, context?: RegistrationProtocolAdapterContext): Result<Record<string, unknown>, FederationError>;
	/**
	 * Enrich the registration response metadata with protocol-specific fields.
	 * Called before the response is signed and returned.
	 *
	 * @param rpMeta - The RP's resolved metadata
	 * @param trustChain - The validated trust chain for the RP
	 * @param context - Optional adapter context (peer chain metadata, etc.)
	 * @returns The enriched metadata for the response
	 */
	enrichResponseMetadata(rpMeta: Record<string, unknown>, trustChain: ValidatedTrustChain, context?: RegistrationProtocolAdapterContext): Record<string, unknown>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `validateClientMetadata` | `(raw: Record<string, unknown>, context?: RegistrationProtocolAdapterContext) => Result<Record<string, unknown>, FederationError>` | Synchronous validation hook. Explicit processing uses the returned metadata map; automatic processing passes the selected client block and uses only the acceptance decision. A failing Result rejects registration. |
| `enrichResponseMetadata` | `(rpMeta: Record<string, unknown>, trustChain: ValidatedTrustChain, context?: RegistrationProtocolAdapterContext) => Record<string, unknown>` | Synchronous explicit-registration response hook receiving the selected client block and validated chain. Its returned block is checked against the response schema and federation policy. |

## `RegistrationProtocolAdapterContext`

[Source](../../../packages/oidc/src/registration/adapter-types.ts#L10)

Optional hook context. Explicit registration supplies peerResolvedOpMetadata when a validated client-provided peer chain exists; these are the provider metadata values chosen by that client's chain. Automatic adapter validation supplies a cancellation signal through the bounded host-operation wrapper. The adapter must not assume every flow supplies both fields.

```typescript signature
interface RegistrationProtocolAdapterContext {
	/**
	 * The OP's resolved metadata as derived from the validated peer chain
	 * (validated by the federation handler before this is passed in). When
	 * absent, no peer chain was supplied. Invalid peer chains fail registration.
	 */
	readonly peerResolvedOpMetadata?: Readonly<Record<string, unknown>>;
	/** Cancellation for asynchronous host integrations, when supplied by the caller. */
	readonly signal?: AbortSignal;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `peerResolvedOpMetadata?` | `Readonly<Record<string, unknown>>` | The OP's resolved metadata as derived from the validated peer chain (validated by the federation handler before this is passed in). When absent, no peer chain was supplied. Invalid peer chains fail registration. |
| `signal?` | `AbortSignal` | Cancellation signal for the waiting caller and cooperative work started by this operation. |

## `RequestDelivery`

[Source](../../../packages/oidc/src/registration/automatic.ts#L36)

String union selecting delivery: query places the signed Request Object in an authorization URL; form_post returns form fields; request_uri returns a URL referencing a caller-hosted JWT; par performs a PAR request and returns the resulting authorization URL. The default is form_post.

```typescript signature
type RequestDelivery = "query" | "form_post" | "request_uri" | "par";
```

## `StaticProtocolSigningKeyProvider`

[Source](../../../packages/oidc/src/protocol-keys.ts#L8)

Return the exact signer objects supplied at construction, retaining their identity without cloning, rotating, or validating them. If no clientAssertionSigner is supplied, getClientAssertionSigner returns the Request Object signer. Registration/signing workflows apply the relevant publication and algorithm checks.

```typescript signature
new StaticProtocolSigningKeyProvider(options: { requestObjectSigner: JwtSigner; clientAssertionSigner?: JwtSigner; }): StaticProtocolSigningKeyProvider;
```

### `StaticProtocolSigningKeyProvider#getRequestObjectSigner`

Return the configured Request Object signer by reference.

[Source](../../../packages/oidc/src/protocol-keys.ts#L17)

```typescript signature
getRequestObjectSigner(): Promise<JwtSigner>;
```

### `StaticProtocolSigningKeyProvider#getClientAssertionSigner`

Return the configured client-assertion signer by reference, falling back to the Request Object signer when omitted.

[Source](../../../packages/oidc/src/protocol-keys.ts#L21)

```typescript signature
getClientAssertionSigner(): Promise<JwtSigner>;
```

## `ValidatedRequestObject`

[Source](../../../packages/oidc/src/registration/types.ts#L4)

Request Object claims after claim-level validation, including asserted client/provider identities and optional attached chains. This type does not itself carry a validated chain or resolved metadata, and its name does not prove full signature or Federation validation. Completed registration evidence is represented by ProcessedAutomaticRegistration.

```typescript signature
interface ValidatedRequestObject {
	/** The RP's Entity Identifier (from `client_id` / `iss`) */
	readonly rpEntityId: EntityId;
	/** The OP's Entity Identifier (from `aud`) */
	readonly opEntityId: string;
	/** JWT expiration timestamp */
	readonly exp: number;
	/** Unique JWT identifier */
	readonly jti: string;
	/** Issued-at timestamp (if present) */
	readonly iat?: number;
	/** All decoded JWT payload claims */
	readonly claims: Readonly<Record<string, unknown>>;
	/** Trust chain from JWT header (if present) */
	readonly trustChainHeader?: readonly string[];
	/** Peer Trust Chain from JWT header (if present) — Trust Chain for the OP. */
	readonly peerTrustChainHeader?: readonly string[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `rpEntityId` | `EntityId` | Registered client Entity Identifier; the RP field name also applies to the OAuth client profile. |
| `opEntityId` | `string` | The OP's Entity Identifier (from `aud`) |
| `exp` | `number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |
| `jti` | `string` | JWT identifier used for replay protection, scoped to issuer and audience. |
| `iat?` | `number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `claims` | `Readonly<Record<string, unknown>>` | Claims associated with the artifact or selected for this operation. |
| `trustChainHeader?` | `readonly string[]` | Trust chain from JWT header (if present) |
| `peerTrustChainHeader?` | `readonly string[]` | Peer Trust Chain from JWT header (if present) — Trust Chain for the OP. |

## `ValidatedRequestObjectResult`

[Source](../../../packages/oidc/src/registration/types.ts#L33)

Result wrapper around ValidatedRequestObject and FederationError. It contains claim-validation output, not a completed client registration or resolved Federation evidence.

```typescript signature
type ValidatedRequestObjectResult = Result<ValidatedRequestObject, FederationError>;
```

