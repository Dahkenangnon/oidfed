# Protocol roles and configuration

[`@oidfed/oidc`](README.md)

Compose a role into a Leaf or Authority, or use its static metadata parsers and assessment helpers independently. Metadata contribution is copied after initialization, with later roles replacing matching host parameters. Full protocol processing remains with the host application.

The client classes share registration methods; the provider classes share processing methods. Static aliases shown below expose the existing core helpers through the role class. They use explicit arguments and do not inherit instance options. Their declarations are followed by a call signature for lookup. Core-owned types in signatures are imported from `@oidfed/core`; OIDC-owned metadata and registration types come from `@oidfed/oidc`.

## `CreateAuthorizationRequestOptions`

[Source](../../../packages/oidc/src/roles.ts#L97)

Per-call settings for client authorization-request creation. These override role and host options where used. requestDelivery defaults to form_post; request_uri requires a caller-hosted Request Object URL, while par mode performs the request. The trustAnchors field overrides the explicit anchor argument of createAuthorizationRequest.

```typescript signature
interface CreateAuthorizationRequestOptions extends FederationOptions {
	readonly requestDelivery?: RequestDelivery;
	readonly requestUri?: string;
	readonly includePeerTrustChain?: boolean;
	readonly requestObjectTtlSeconds?: number;
	readonly trustAnchors?: TrustAnchorSet;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `requestDelivery?` | `RequestDelivery` | Delivery mode: query, form_post, request_uri, or par. The default is form_post. The result shape depends on this mode. |
| `requestUri?` | `string` | HTTPS URL where the application will serve the returned Request Object for request_uri delivery. It is required in that mode; this library does not host it. |
| `includePeerTrustChain?` | `boolean` | Include a peer_trust_chain ending at the selected shared anchor. Defaults to false; inability to build it returns a registration error. |
| `requestObjectTtlSeconds?` | `number` | Request Object lifetime in seconds; defaults to 300 and is bounded by the applicable client-chain lifetime. |
| `trustAnchors?` | `TrustAnchorSet` | Per-call anchors. createAuthorizationRequest uses this value in preference to its explicit trustAnchors argument; other client methods prefer it over role and host defaults. |
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
| `blockedCIDRs?` | `string[]` | Additional blocked IPv4 CIDRs used by core URL validation. DNS resolution and connection-level destination checks remain the host transport's responsibility. |
| `allowedHosts?` | `string[]` | Optional exact hostname allowlist applied before outbound fetching. |
| `authorityHintFilter?` | `(hint: URL, subject: EntityId) => boolean` | Host predicate for accepting an authority hint before traversal. |
| `understoodCriticalClaims?` | `ReadonlySet<string>` | Extension claim names the application actually understands and processes; unknown critical claims are rejected. |
| `maxTotalFetches?` | `number` | Maximum HTTP client calls; discovery helpers share the allowance across discovery and candidate validation. Cached and supplied statements use no allowance. Core accepts zero. Default: 50. |
| `customPolicyOperators?` | `readonly PolicyOperatorDefinition[]` | Federation-defined policy operators in addition to the seven standard ones. Forwarded to `resolveMetadataPolicy` and `applyMetadataPolicy` during trust-chain validation. |
| `customConstraintChecks?` | `readonly ConstraintCheckDefinition[]` | Federation-defined constraints checked against authenticated chains. Unknown names are ignored. |

## `OAuthAuthorizationServerRole`

[Source](../../../packages/oidc/src/roles.ts#L789)

Provider role for `oauth_authorization_server` metadata. Host initialization installs an Explicit Registration endpoint and requires nonempty Trust Anchors. Its composed metadata must declare `client_registration_types_supported` containing `explicit`, including when automatic processing is also used. Automatic registration and PAR processing additionally require a replay store.

Use a fresh stateful role per host. The public API includes inherited members from the internal role base classes; those base classes are not package exports. Configuration and metadata properties marked `readonly` prevent reassignment through TypeScript, but do not freeze their referenced objects.

```typescript signature
new OAuthAuthorizationServerRole(config: OidcProviderRoleConfig): OAuthAuthorizationServerRole;
```

### `OAuthAuthorizationServerRole#type`

Entity Type Identifier `oauth_authorization_server`, used to select this role's metadata block and registration profile.

[Source](../../../packages/oidc/src/roles.ts#L790)

```typescript signature
readonly type: "oauth_authorization_server";
```

### `OAuthAuthorizationServerRole#processPushedAuthorizationRequest`

Process a form-encoded POST using effective provider metadata, configured trust, proof negotiation, and replay storage. Returned parameters include repeated resource values. This is registration/proof processing, not issuance or storage of a PAR request_uri; the host protocol engine owns that response. Initialize the role on a host with replay storage. The method runs configured accreditation and registration persistence; persistence exceptions are converted to a server-error Result.

[Source](../../../packages/oidc/src/roles.ts#L476)

```typescript signature
processPushedAuthorizationRequest(request: Request, options?: ProcessPushedAuthorizationRequestOptions): Promise<Result<ProcessedPushedAuthorizationRequest, ClientAttestationError>>;
```

### `OAuthAuthorizationServerRole#assessEntity`

Assess the target using the requested protocol block and either local validation or an explicitly authorized resolver. The protocol selector is one of `openid_relying_party`, `openid_provider`, `oauth_authorization_server`, `oauth_client`, or `oauth_resource`; it is not inferred from the calling class. Effective server issuer values are bound to the target Entity Identifier. Invalid target identifiers can reject before a Result is returned. This method also works before initialization when role or per-call trust inputs are supplied. Options use call, role, then host precedence; anchors use the same order, followed by an empty set.

[Source](../../../packages/oidc/src/roles.ts#L519)

```typescript signature
assessEntity(target: string, type: "openid_relying_party" | "openid_provider" | "oauth_authorization_server" | "oauth_client" | "oauth_resource", options?: EntityAssessmentOptions & { trustAnchors?: TrustAnchorSet; }): Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```

### `OAuthAuthorizationServerRole#metadata`

Mutable metadata block copied from constructor input. Hosts compose a detached publication snapshot; changing this role object after attachment does not automatically update a Leaf or Authority EC. Validate proposed values with the static publication parser before constructing a new host.

[Source](../../../packages/oidc/src/roles.ts#L531)

```typescript signature
readonly metadata: Record<string, unknown>;
```

### `OAuthAuthorizationServerRole#routes`

Map populated with the explicit-registration handler during initialization. The host copies these routes while composing roles; later map changes are not automatically remounted.

[Source](../../../packages/oidc/src/roles.ts#L532)

```typescript signature
readonly routes: Map<string, (request: Request) => Promise<Response>>;
```

### `OAuthAuthorizationServerRole#config`

Constructor configuration retained by reference. Metadata is copied separately; the configuration object and its service dependencies are not deeply frozen. Treat configuration as immutable after attachment; there is no general configuration-update API.

[Source](../../../packages/oidc/src/roles.ts#L536)

```typescript signature
readonly config: OidcProviderRoleConfig;
```

### `OAuthAuthorizationServerRole#validateMetadata`

Require explicit registration support and validate the composed provider publication block. This check does not retain a replacement copy of metadata for every later protocol operation; those operations accept or use their own effective provider metadata.

[Source](../../../packages/oidc/src/roles.ts#L543)

```typescript signature
validateMetadata(metadata: Readonly<Record<string, unknown>>, context: EntityContext): void;
```

### `OAuthAuthorizationServerRole#initialize`

Bind the role to the host's EntityContext. Reusing it with a different context throws, while the same context can be passed again. Hosts invoke this during composition. Provider initialization also advertises and mounts the explicit-registration route, using role anchors before host anchors.

[Source](../../../packages/oidc/src/roles.ts#L566)

```typescript signature
initialize(context: EntityContext): void;
```

### `OAuthAuthorizationServerRole#processAutomaticRegistration`

Validate the signed Request Object, local recipient, client chain, selected client metadata, protocol signature, accreditation, and replay claim. Then run the optional registration adapter and persistence callback. Initialize the role with host replay storage and nonempty role-or-host anchors. Per-call options override role and host options, while configured accreditation requirements and beforeRegistration take precedence when configured. Adapter or persistence exceptions can reject the promise despite its Result return type.

[Source](../../../packages/oidc/src/roles.ts#L616)

```typescript signature
processAutomaticRegistration(requestObjectJwt: string, options?: ProcessAutomaticRegistrationOptions): Promise<Result<ProcessedAutomaticRegistration, ClientAttestationError>>;
```

### `OAuthAuthorizationServerRole#processExplicitRegistration`

Invoke the explicit-registration HTTP handler installed during initialization. It accepts POST with an exact Entity Statement or Trust Chain media type, validates the client and optional peer evidence, and returns a signed registration response using Federation keys. Validation failures become HTTP errors; adapter, key-provider, signing, or secret-generation failures can still reject. Persistence/invalidation hook failures return a generic HTTP 500. An uninitialized role rejects because its handler is not mounted.

[Source](../../../packages/oidc/src/roles.ts#L721)

```typescript signature
processExplicitRegistration(request: Request): Promise<Response>;
```

### `OAuthAuthorizationServerRole.parseMetadata`

Parse completed metadata and return Zod's `{ success, data }` or `{ success: false, error }` result, without constructing or initializing a role. Conditional protocol requirements are checked; a successful parse establishes neither Federation trust nor key ownership. Unknown extension fields are preserved. 

[Source](../../../packages/oidc/src/roles.ts#L793)

```typescript signature
static parseMetadata(metadata: unknown, options?: MetadataValidationOptions): z.ZodSafeParseResult<OAuthAuthorizationServerMetadata>;
```

### `OAuthAuthorizationServerRole.parsePublicationMetadata`

Parse supplied publication fields while allowing a Superior to complete missing requirements. Supplied values and applicable cross-field consistency rules are still checked. This is independent validation, not publication or trust establishment; success/error uses the Zod parse-result format.

[Source](../../../packages/oidc/src/roles.ts#L800)

```typescript signature
static parsePublicationMetadata(metadata: unknown, options?: MetadataValidationOptions): z.ZodSafeParseResult<OAuthAuthorizationServerPublicationMetadata>;
```

### `OAuthAuthorizationServerRole.assessEntity`

Assess the target using the requested protocol block and either local validation or an explicitly authorized resolver. The protocol selector is one of `openid_relying_party`, `openid_provider`, `oauth_authorization_server`, `oauth_client`, or `oauth_resource`; it is not inferred from the calling class. Effective server issuer values are bound to the target Entity Identifier. Invalid target identifiers can reject before a Result is returned. This static callable takes anchors and options explicitly and uses no role instance.

[Source](../../../packages/oidc/src/roles.ts#L517)

```typescript signature
static assessEntity: (target: string, type: "openid_relying_party" | "openid_provider" | "oauth_authorization_server" | "oauth_client" | "oauth_resource", anchors: TrustAnchorSet, options?: EntityAssessmentOptions) => Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```

Callable signature:

```typescript signature
OAuthAuthorizationServerRole.assessEntity(target: string, type: "openid_relying_party" | "openid_provider" | "oauth_authorization_server" | "oauth_client" | "oauth_resource", anchors: TrustAnchorSet, options?: EntityAssessmentOptions): Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```


## `OAuthAuthorizationServerRoleConfig`

[Source](../../../packages/oidc/src/roles.ts#L788)

Alias of OidcProviderRoleConfig. The OAuth role uses oauth_client and oauth_authorization_server metadata for its registration processing; both provider classes share the configuration and callback contracts.

```typescript signature
type OAuthAuthorizationServerRoleConfig = OidcProviderRoleConfig;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `requestObjectTyping?` | `ProcessAutomaticRegistrationOptions["requestObjectTyping"]` | Automatic registration and signed PAR typing policy. Default strict; method options override this setting. Applies to both provider classes. |
| `registrationManagement?` | `ExplicitRegistrationHandlerConfig["registrationManagement"]` | Opt in to adapter-issued read-only registration access; the host enforces token permissions. Default disabled. |
| `options?` | `FederationOptions` | Federation transport, time, validation, and resource settings; role options override host options, and method options override role options. |
| `registrationPath?` | `string` | Explicit-registration route, defaulting to /registration. Use a leading-slash path or an absolute URL for host route integration. |
| `metadata?` | `Record<string, unknown>` | Authorization-server publication metadata, cloned at construction. Initialization installs the explicit-registration endpoint; composed metadata must declare explicit support. |
| `trustAnchors?` | `TrustAnchorSet` | Independently trusted anchor identities and their public Federation Entity Keys. |
| `registrationResponseTtlSeconds?` | `number` | Signed registration-response lifetime in seconds; defaults to 86400 and is capped by the validated client chain's expiry. |
| `registrationProtocolAdapter?` | `RegistrationProtocolAdapter` | Optional protocol/profile validation and response-enrichment callbacks. The registration flow independently checks the selected protocol schema and federation policy. |
| `generateClientSecret?` | `(sub: EntityId) => Promise<string \| undefined>` | Optional explicit-registration secret generator. A nonempty returned value is added to the response; undefined omits it. |
| `onRegistrationInvalidation?` | `(sub: EntityId) => Promise<void>` | Explicit-registration hook after validation and response signing, immediately before onRegistration. Automatic registration does not invoke this hook. |
| `onRegistration?` | `( sub: EntityId, clientMetadata: Record<string, unknown>, clientSecret?: string, ) => Promise<void>` | Optional persistence callback. It receives the client identifier, selected client metadata block, and any client secret. Automatic processing passes the protocol keys actually used for authentication. |
| `trustMarkRequirements?` | `TrustMarkRequirements` | Declarative accreditation requirements checked before beforeRegistration and before accepting registration side effects. |
| `beforeRegistration?` | `( context: Readonly<RegistrationAccreditationContext>, signal?: AbortSignal, ) => Result<void> \| Promise<Result<void>>` | Application accreditation callback after declarative Trust Mark checks. A failing requirement prevents the callback; the callback must return a Result with ok set to true to continue. |

## `OAuthClientRole`

[Source](../../../packages/oidc/src/roles.ts#L750)

Client role for `oauth_client` metadata. It discovers a server, prepares signed authorization requests, performs Explicit Client Registration, and prepares PAR requests through the selected OIDC or OAuth profile. Constructors copy metadata; registration and instance assertion signing require host initialization. Assessments and static parsers can be used independently.

Use a fresh stateful role per host. The public API includes inherited members from the internal role base classes; those base classes are not package exports. Configuration and metadata properties marked `readonly` prevent reassignment through TypeScript, but do not freeze their referenced objects.

```typescript signature
new OAuthClientRole(config: OidcRelyingPartyRoleConfig): OAuthClientRole;
```

### `OAuthClientRole#type`

Entity Type Identifier `oauth_client`, used to select this role's metadata block and registration profile.

[Source](../../../packages/oidc/src/roles.ts#L751)

```typescript signature
readonly type: "oauth_client";
```

### `OAuthClientRole#automaticallyRegister`

Discover the server named by `authorizationServerEntityId`, choose compatible chains sharing an anchor, and build an authorization-code request (`response_type: "code"`). Request delivery defaults to form_post; par mode also sends the PAR HTTP request. Per-call options override role options and host options. Nonempty delivery/URI values in the options argument override those in params, which override role configuration. Requires initialization and configured anchors; missing setup rejects, while protocol failures generally return a failing Result.

[Source](../../../packages/oidc/src/roles.ts#L768)

```typescript signature
automaticallyRegister(params: { readonly authorizationServerEntityId: string; readonly redirect_uri: string; readonly scope?: string; readonly state?: string; readonly nonce?: string; readonly requestDelivery?: RequestDelivery; readonly requestUri?: string; }, options?: CreateAuthorizationRequestOptions): Promise<Result<AutomaticRegistrationResult>>;
```

### `OAuthClientRole#createPushedAuthorizationRequest`

Prepare a complete PAR endpoint, form body, headers, and selected provider chain from a supplied DiscoveryResult and proof mode. This method does not send the prepared request; the host supplies transport and any TLS client certificate. It checks the client/server metadata, shared anchor, proof, and published protocol keys. Initialization and a nonempty anchor set are required. Options and anchors use call, role, then host precedence.

[Source](../../../packages/oidc/src/roles.ts#L107)

```typescript signature
createPushedAuthorizationRequest(discovery: DiscoveryResult, parameters: Readonly<Record<string, unknown>>, proof: PushedAuthorizationProof, options?: Omit<FederationOptions & { trustAnchors?: TrustAnchorSet; }, "engine">): Promise<Result<PreparedPushedAuthorizationRequest>>;
```

### `OAuthClientRole#assessEntity`

Assess the target using the requested protocol block and either local validation or an explicitly authorized resolver. The protocol selector is one of `openid_relying_party`, `openid_provider`, `oauth_authorization_server`, `oauth_client`, or `oauth_resource`; it is not inferred from the calling class. Effective server issuer values are bound to the target Entity Identifier. Invalid target identifiers can reject before a Result is returned. This method also works before initialization when role or per-call trust inputs are supplied. Options use call, role, then host precedence; anchors use the same order, followed by an empty set.

[Source](../../../packages/oidc/src/roles.ts#L145)

```typescript signature
assessEntity(target: string, type: "openid_relying_party" | "openid_provider" | "oauth_authorization_server" | "oauth_client" | "oauth_resource", options?: EntityAssessmentOptions & { trustAnchors?: TrustAnchorSet; }): Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```

### `OAuthClientRole#metadata`

Mutable metadata block copied from constructor input. Hosts compose a detached publication snapshot; changing this role object after attachment does not automatically update a Leaf or Authority EC. Validate proposed values with the static publication parser before constructing a new host.

[Source](../../../packages/oidc/src/roles.ts#L162)

```typescript signature
readonly metadata: Record<string, unknown>;
```

### `OAuthClientRole#config`

Constructor configuration retained by reference. Metadata is copied separately; the configuration object and its service dependencies are not deeply frozen. Treat configuration as immutable after attachment; there is no general configuration-update API.

[Source](../../../packages/oidc/src/roles.ts#L167)

```typescript signature
readonly config: OidcRelyingPartyRoleConfig;
```

### `OAuthClientRole#validateMetadata`

Check the composed client publication block and retain a detached copy for subsequent client registration operations. Omitted requirements may be completed by a Superior; supplied invalid values throw TypeError.

[Source](../../../packages/oidc/src/roles.ts#L171)

```typescript signature
validateMetadata(metadata: Readonly<Record<string, unknown>>, context?: EntityContext): void;
```

### `OAuthClientRole#initialize`

Bind the role to the host's EntityContext. Reusing it with a different context throws, while the same context can be passed again. Hosts invoke this during composition. Client registration and instance assertion signing use this identity and host services.

[Source](../../../packages/oidc/src/roles.ts#L177)

```typescript signature
initialize(context: EntityContext): void;
```

### `OAuthClientRole#createClientAssertion`

Sign a private_key_jwt assertion using the attached host's Entity Identifier and this role's protocol signing purposes. Configure the clientAssertion signing purpose on the role. To reuse the Request Object key, bind both purposes to the same keyring entry explicitly. Call options inherit the host engine and can narrow the configured verification policy. The default lifetime is 60 seconds. This helper does not prove that the signer is published in the client's metadata; registration workflows perform that binding check. Missing initialization rejects.

[Source](../../../packages/oidc/src/roles.ts#L195)

```typescript signature
createClientAssertion(audience: string, options?: Omit<ClientAssertionOptions, "engine">): Promise<string>;
```

### `OAuthClientRole#explicitlyRegister`

Discover the provider, validate compatible shared-anchor evidence, and POST a self-issued client EC signed with the host's Federation Entity Key. Verify the provider's signed response and return its client metadata and separate registration/chain deadlines. The opEntityId argument also names an OAuth AS when this is an OAuthClientRole. Options and anchors use call, role, then host precedence. Initialization and configured anchors are required.

[Source](../../../packages/oidc/src/roles.ts#L311)

```typescript signature
explicitlyRegister(opEntityId: string, options?: Omit<FederationOptions & { readonly trustAnchors?: TrustAnchorSet; }, "engine">): Promise<Result<ExplicitRegistrationResult>>;
```

### `OAuthClientRole#createAuthorizationRequest`

Build an authorization request from a supplied, locally validated DiscoveryResult and arbitrary supported authorization parameters. The target chain is rechecked for the selected registration profile and shared anchor. options.trustAnchors takes precedence over the explicit trustAnchors argument; other options use call, role, then host precedence. Delivery defaults to form_post; par mode performs HTTP. Initialization is required. Use this entry point when the automaticallyRegister convenience parameters are insufficient.

[Source](../../../packages/oidc/src/roles.ts#L368)

```typescript signature
createAuthorizationRequest(discovery: DiscoveryResult, authzRequestParams: Readonly<Record<string, unknown>>, trustAnchors: TrustAnchorSet, options?: CreateAuthorizationRequestOptions): Promise<Result<AutomaticRegistrationResult>>;
```

### `OAuthClientRole.parseMetadata`

Parse completed metadata and return Zod's `{ success, data }` or `{ success: false, error }` result, without constructing or initializing a role. Conditional protocol requirements are checked; a successful parse establishes neither Federation trust nor key ownership. Unknown extension fields are preserved. 

[Source](../../../packages/oidc/src/roles.ts#L754)

```typescript signature
static parseMetadata(metadata: unknown, options?: MetadataValidationOptions): z.ZodSafeParseResult<OAuthClientMetadata>;
```

### `OAuthClientRole.parsePublicationMetadata`

Parse supplied publication fields while allowing a Superior to complete missing requirements. Supplied values and applicable cross-field consistency rules are still checked. This is independent validation, not publication or trust establishment; success/error uses the Zod parse-result format.

[Source](../../../packages/oidc/src/roles.ts#L761)

```typescript signature
static parsePublicationMetadata(metadata: unknown, options?: MetadataValidationOptions): z.ZodSafeParseResult<OAuthClientPublicationMetadata>;
```

### `OAuthClientRole.assessEntity`

Assess the target using the requested protocol block and either local validation or an explicitly authorized resolver. The protocol selector is one of `openid_relying_party`, `openid_provider`, `oauth_authorization_server`, `oauth_client`, or `oauth_resource`; it is not inferred from the calling class. Effective server issuer values are bound to the target Entity Identifier. Invalid target identifiers can reject before a Result is returned. This static callable takes anchors and options explicitly and uses no role instance.

[Source](../../../packages/oidc/src/roles.ts#L143)

```typescript signature
static assessEntity: (target: string, type: "openid_relying_party" | "openid_provider" | "oauth_authorization_server" | "oauth_client" | "oauth_resource", anchors: TrustAnchorSet, options?: EntityAssessmentOptions) => Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```

Callable signature:

```typescript signature
OAuthClientRole.assessEntity(target: string, type: "openid_relying_party" | "openid_provider" | "oauth_authorization_server" | "oauth_client" | "oauth_resource", anchors: TrustAnchorSet, options?: EntityAssessmentOptions): Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```


## `OAuthClientRoleConfig`

[Source](../../../packages/oidc/src/roles.ts#L749)

Alias of OidcRelyingPartyRoleConfig. OAuthClientRole selects the OAuth client/authorization-server profile while sharing the client configuration contract; the alias does not introduce different defaults.

```typescript signature
type OAuthClientRoleConfig = OidcRelyingPartyRoleConfig;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `options?` | `FederationOptions` | Federation transport, time, validation, and resource settings; role options override host options, and method options override role options. |
| `signing?` | `SigningPurposes` | Explicit Request Object and client assertion purpose names in the host keyring. |
| `metadata?` | `Record<string, unknown>` | Publication metadata for this role, cloned at construction. The host invokes its publication-validation hook. |
| `requestObjectTtlSeconds?` | `number` | Request Object lifetime in seconds; defaults to 300 and is bounded by the applicable client-chain lifetime. |
| `includePeerTrustChain?` | `boolean` | Include a peer_trust_chain ending at the selected shared anchor. Defaults to false; inability to build it returns a registration error. |
| `requestDelivery?` | `RequestDelivery` | Delivery mode: query, form_post, request_uri, or par. The default is form_post. The result shape depends on this mode. |
| `requestUri?` | `string` | HTTPS URL where the application will serve the returned Request Object for request_uri delivery. It is required in that mode; this library does not host it. |
| `trustAnchors?` | `TrustAnchorSet` | Independently trusted anchor identities and their public Federation Entity Keys. |
| `authorityHints?` | `readonly EntityId[]` | Fallback Immediate Superior identifiers when the attached host context has no authorityHints. Host context takes precedence. |

## `OAuthResourceRole`

[Source](../../../packages/oidc/src/roles.ts#L813)

Publish `oauth_resource` metadata and assess other protocol entities. This role has no token-validation, authorization-enforcement, or resource HTTP handler. Construction copies metadata and any separately supplied protocol JWKS; the latter overrides `metadata.jwks`.

Use a fresh stateful role per host. The public API includes inherited members from the internal role base classes; those base classes are not package exports. Configuration and metadata properties marked `readonly` prevent reassignment through TypeScript, but do not freeze their referenced objects.

```typescript signature
new OAuthResourceRole(config: OAuthResourceRoleConfig): OAuthResourceRole;
```

### `OAuthResourceRole#assessEntity`

Assess the target using the requested protocol block and either local validation or an explicitly authorized resolver. The protocol selector is one of `openid_relying_party`, `openid_provider`, `oauth_authorization_server`, `oauth_client`, or `oauth_resource`; it is not inferred from the calling class. Effective server issuer values are bound to the target Entity Identifier. Invalid target identifiers can reject before a Result is returned. This method also works before initialization when role or per-call trust inputs are supplied. Options use call, role, then host precedence; anchors use the same order, followed by an empty set.

[Source](../../../packages/oidc/src/roles.ts#L816)

```typescript signature
assessEntity(target: string, type: "openid_relying_party" | "openid_provider" | "oauth_authorization_server" | "oauth_client" | "oauth_resource", options?: EntityAssessmentOptions & { trustAnchors?: TrustAnchorSet; }): Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```

### `OAuthResourceRole#validateMetadata`

Validate supplied resource publication fields and inline-key requirements. Required fields for a full RFC 9728 document are handled by the explicit rfc9728 parser profile. Invalid fields throw TypeError.

[Source](../../../packages/oidc/src/roles.ts#L850)

```typescript signature
validateMetadata(metadata: Readonly<Record<string, unknown>>, context?: EntityContext): void;
```

### `OAuthResourceRole#type`

Entity Type Identifier `oauth_resource`, used to select this role's metadata block and registration profile.

[Source](../../../packages/oidc/src/roles.ts#L855)

```typescript signature
readonly type: "oauth_resource";
```

### `OAuthResourceRole#metadata`

Mutable metadata block copied from constructor input. Hosts compose a detached publication snapshot; changing this role object after attachment does not automatically update a Leaf or Authority EC. Validate proposed values with the static publication parser before constructing a new host.

[Source](../../../packages/oidc/src/roles.ts#L856)

```typescript signature
readonly metadata: Record<string, unknown>;
```

### `OAuthResourceRole#routes`

Empty route map supplied to satisfy the host composition contract. This resource role installs no protocol endpoint by itself.

[Source](../../../packages/oidc/src/roles.ts#L857)

```typescript signature
readonly routes: Map<string, (request: Request) => Promise<Response>>;
```

### `OAuthResourceRole#config`

Constructor configuration retained by reference. Metadata is copied separately; the configuration object and its service dependencies are not deeply frozen. Treat configuration as immutable after attachment; there is no general configuration-update API.

[Source](../../../packages/oidc/src/roles.ts#L862)

```typescript signature
readonly config: OAuthResourceRoleConfig;
```

### `OAuthResourceRole#initialize`

Bind the role to the host's EntityContext. Reusing it with a different context throws, while the same context can be passed again. Hosts invoke this during composition. Assessment methods can use this host's default options and anchors.

[Source](../../../packages/oidc/src/roles.ts#L870)

```typescript signature
initialize(context: EntityContext): void;
```

### `OAuthResourceRole.assessEntity`

Assess the target using the requested protocol block and either local validation or an explicitly authorized resolver. The protocol selector is one of `openid_relying_party`, `openid_provider`, `oauth_authorization_server`, `oauth_client`, or `oauth_resource`; it is not inferred from the calling class. Effective server issuer values are bound to the target Entity Identifier. Invalid target identifiers can reject before a Result is returned. This static callable takes anchors and options explicitly and uses no role instance.

[Source](../../../packages/oidc/src/roles.ts#L814)

```typescript signature
static assessEntity: (target: string, type: "openid_relying_party" | "openid_provider" | "oauth_authorization_server" | "oauth_client" | "oauth_resource", anchors: TrustAnchorSet, options?: EntityAssessmentOptions) => Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```

Callable signature:

```typescript signature
OAuthResourceRole.assessEntity(target: string, type: "openid_relying_party" | "openid_provider" | "oauth_authorization_server" | "oauth_client" | "oauth_resource", anchors: TrustAnchorSet, options?: EntityAssessmentOptions): Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```


### `OAuthResourceRole.parseMetadata`

Parse completed metadata and return Zod's `{ success, data }` or `{ success: false, error }` result, without constructing or initializing a role. Conditional protocol requirements are checked; a successful parse establishes neither Federation trust nor key ownership. Unknown extension fields are preserved. The default federation profile permits resource to be absent. Pass `{ profile: "rfc9728" }` when validating a complete Protected Resource Metadata document; that profile requires resource.

[Source](../../../packages/oidc/src/roles.ts#L829)

```typescript signature
static parseMetadata(metadata: unknown, options?: MetadataValidationOptions & { profile?: "federation" | "rfc9728"; }): z.ZodSafeParseResult<OAuthResourceMetadata>;
```

### `OAuthResourceRole.parsePublicationMetadata`

Parse supplied publication fields while allowing a Superior to complete missing requirements. Supplied values and applicable cross-field consistency rules are still checked. This is independent validation, not publication or trust establishment; success/error uses the Zod parse-result format.

[Source](../../../packages/oidc/src/roles.ts#L843)

```typescript signature
static parsePublicationMetadata(metadata: unknown, options?: MetadataValidationOptions): z.ZodSafeParseResult<OAuthResourcePublicationMetadata>;
```

## `OAuthResourceRoleConfig`

[Source](../../../packages/oidc/src/roles.ts#L806)

Resource metadata, optional protocol keys, and trust defaults. Supplied jwks replaces metadata.jwks in the copied role block. This role publishes metadata and assesses entities; it does not install a protected-resource API or process access tokens.

```typescript signature
interface OAuthResourceRoleConfig {
	readonly trustAnchors?: TrustAnchorSet;
	readonly options?: BoundFederationOptions;
	readonly metadata?: Record<string, unknown>;
	readonly jwks?: JWKSet;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `trustAnchors?` | `TrustAnchorSet` | Independently trusted anchor identities and their public Federation Entity Keys. |
| `options?` | `FederationOptions` | Federation transport, time, validation, and resource settings; role options override host options, and method options override role options. |
| `metadata?` | `Record<string, unknown>` | Resource publication metadata, cloned at construction. Supplied jwks overrides an inline jwks value in this block. |
| `jwks?` | `JWKSet` | Protocol public key set, cloned into metadata.jwks and taking precedence over the metadata block's inline keys. |

## `OidcProviderRole`

[Source](../../../packages/oidc/src/roles.ts#L732)

Provider role for `openid_provider` metadata. Host initialization installs an Explicit Registration endpoint and requires nonempty Trust Anchors. Its composed metadata must declare `client_registration_types_supported` containing `explicit`, including when automatic processing is also used. Automatic registration and PAR processing additionally require a replay store.

Use a fresh stateful role per host. The public API includes inherited members from the internal role base classes; those base classes are not package exports. Configuration and metadata properties marked `readonly` prevent reassignment through TypeScript, but do not freeze their referenced objects.

```typescript signature
new OidcProviderRole(config: OidcProviderRoleConfig): OidcProviderRole;
```

### `OidcProviderRole#type`

Entity Type Identifier `openid_provider`, used to select this role's metadata block and registration profile.

[Source](../../../packages/oidc/src/roles.ts#L733)

```typescript signature
readonly type: "openid_provider";
```

### `OidcProviderRole#processPushedAuthorizationRequest`

Process a form-encoded POST using effective provider metadata, configured trust, proof negotiation, and replay storage. Returned parameters include repeated resource values. This is registration/proof processing, not issuance or storage of a PAR request_uri; the host protocol engine owns that response. Initialize the role on a host with replay storage. The method runs configured accreditation and registration persistence; persistence exceptions are converted to a server-error Result.

[Source](../../../packages/oidc/src/roles.ts#L476)

```typescript signature
processPushedAuthorizationRequest(request: Request, options?: ProcessPushedAuthorizationRequestOptions): Promise<Result<ProcessedPushedAuthorizationRequest, ClientAttestationError>>;
```

### `OidcProviderRole#assessEntity`

Assess the target using the requested protocol block and either local validation or an explicitly authorized resolver. The protocol selector is one of `openid_relying_party`, `openid_provider`, `oauth_authorization_server`, `oauth_client`, or `oauth_resource`; it is not inferred from the calling class. Effective server issuer values are bound to the target Entity Identifier. Invalid target identifiers can reject before a Result is returned. This method also works before initialization when role or per-call trust inputs are supplied. Options use call, role, then host precedence; anchors use the same order, followed by an empty set.

[Source](../../../packages/oidc/src/roles.ts#L519)

```typescript signature
assessEntity(target: string, type: "openid_relying_party" | "openid_provider" | "oauth_authorization_server" | "oauth_client" | "oauth_resource", options?: EntityAssessmentOptions & { trustAnchors?: TrustAnchorSet; }): Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```

### `OidcProviderRole#metadata`

Mutable metadata block copied from constructor input. Hosts compose a detached publication snapshot; changing this role object after attachment does not automatically update a Leaf or Authority EC. Validate proposed values with the static publication parser before constructing a new host.

[Source](../../../packages/oidc/src/roles.ts#L531)

```typescript signature
readonly metadata: Record<string, unknown>;
```

### `OidcProviderRole#routes`

Map populated with the explicit-registration handler during initialization. The host copies these routes while composing roles; later map changes are not automatically remounted.

[Source](../../../packages/oidc/src/roles.ts#L532)

```typescript signature
readonly routes: Map<string, (request: Request) => Promise<Response>>;
```

### `OidcProviderRole#config`

Constructor configuration retained by reference. Metadata is copied separately; the configuration object and its service dependencies are not deeply frozen. Treat configuration as immutable after attachment; there is no general configuration-update API.

[Source](../../../packages/oidc/src/roles.ts#L536)

```typescript signature
readonly config: OidcProviderRoleConfig;
```

### `OidcProviderRole#validateMetadata`

Require explicit registration support and validate the composed provider publication block. This check does not retain a replacement copy of metadata for every later protocol operation; those operations accept or use their own effective provider metadata.

[Source](../../../packages/oidc/src/roles.ts#L543)

```typescript signature
validateMetadata(metadata: Readonly<Record<string, unknown>>, context: EntityContext): void;
```

### `OidcProviderRole#initialize`

Bind the role to the host's EntityContext. Reusing it with a different context throws, while the same context can be passed again. Hosts invoke this during composition. Provider initialization also advertises and mounts the explicit-registration route, using role anchors before host anchors.

[Source](../../../packages/oidc/src/roles.ts#L566)

```typescript signature
initialize(context: EntityContext): void;
```

### `OidcProviderRole#processAutomaticRegistration`

Validate the signed Request Object, local recipient, client chain, selected client metadata, protocol signature, accreditation, and replay claim. Then run the optional registration adapter and persistence callback. Initialize the role with host replay storage and nonempty role-or-host anchors. Per-call options override role and host options, while configured accreditation requirements and beforeRegistration take precedence when configured. Adapter or persistence exceptions can reject the promise despite its Result return type.

[Source](../../../packages/oidc/src/roles.ts#L616)

```typescript signature
processAutomaticRegistration(requestObjectJwt: string, options?: ProcessAutomaticRegistrationOptions): Promise<Result<ProcessedAutomaticRegistration, ClientAttestationError>>;
```

### `OidcProviderRole#processExplicitRegistration`

Invoke the explicit-registration HTTP handler installed during initialization. It accepts POST with an exact Entity Statement or Trust Chain media type, validates the client and optional peer evidence, and returns a signed registration response using Federation keys. Validation failures become HTTP errors; adapter, key-provider, signing, or secret-generation failures can still reject. Persistence/invalidation hook failures return a generic HTTP 500. An uninitialized role rejects because its handler is not mounted.

[Source](../../../packages/oidc/src/roles.ts#L721)

```typescript signature
processExplicitRegistration(request: Request): Promise<Response>;
```

### `OidcProviderRole.parseMetadata`

Parse completed metadata and return Zod's `{ success, data }` or `{ success: false, error }` result, without constructing or initializing a role. Conditional protocol requirements are checked; a successful parse establishes neither Federation trust nor key ownership. Unknown extension fields are preserved. 

[Source](../../../packages/oidc/src/roles.ts#L736)

```typescript signature
static parseMetadata(metadata: unknown, options?: MetadataValidationOptions): z.ZodSafeParseResult<OpenIDProviderMetadata>;
```

### `OidcProviderRole.parsePublicationMetadata`

Parse supplied publication fields while allowing a Superior to complete missing requirements. Supplied values and applicable cross-field consistency rules are still checked. This is independent validation, not publication or trust establishment; success/error uses the Zod parse-result format.

[Source](../../../packages/oidc/src/roles.ts#L743)

```typescript signature
static parsePublicationMetadata(metadata: unknown, options?: MetadataValidationOptions): z.ZodSafeParseResult<OpenIDProviderPublicationMetadata>;
```

### `OidcProviderRole.assessEntity`

Assess the target using the requested protocol block and either local validation or an explicitly authorized resolver. The protocol selector is one of `openid_relying_party`, `openid_provider`, `oauth_authorization_server`, `oauth_client`, or `oauth_resource`; it is not inferred from the calling class. Effective server issuer values are bound to the target Entity Identifier. Invalid target identifiers can reject before a Result is returned. This static callable takes anchors and options explicitly and uses no role instance.

[Source](../../../packages/oidc/src/roles.ts#L517)

```typescript signature
static assessEntity: (target: string, type: "openid_relying_party" | "openid_provider" | "oauth_authorization_server" | "oauth_client" | "oauth_resource", anchors: TrustAnchorSet, options?: EntityAssessmentOptions) => Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```

Callable signature:

```typescript signature
OidcProviderRole.assessEntity(target: string, type: "openid_relying_party" | "openid_provider" | "oauth_authorization_server" | "oauth_client" | "oauth_resource", anchors: TrustAnchorSet, options?: EntityAssessmentOptions): Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```


## `OidcProviderRoleConfig`

[Source](../../../packages/oidc/src/roles.ts#L437)

Provider role settings, also used by OAuthAuthorizationServerRole. Initialization mounts an Explicit Registration endpoint, supplies federation_registration_endpoint, and requires nonempty role-or-host anchors. Final composed metadata must declare explicit registration support. A replay store is required for automatic registration and PAR processing, rather than for mounting the explicit endpoint alone. Metadata is copied; callbacks and service dependencies are retained.

```typescript signature
interface OidcProviderRoleConfig extends RegistrationAccreditationPolicy {
	/** Automatic registration and PAR typing policy; method options override this strict default. */
	readonly requestObjectTyping?: ProcessAutomaticRegistrationOptions["requestObjectTyping"];
	/** Opt in to adapter-issued read-only registration access; the host enforces token permissions. Default disabled. */
	readonly registrationManagement?: ExplicitRegistrationHandlerConfig["registrationManagement"];
	readonly options?: BoundFederationOptions;
	readonly registrationPath?: string;
	readonly metadata?: Record<string, unknown>;
	readonly trustAnchors?: TrustAnchorSet;
	readonly registrationResponseTtlSeconds?: number;
	readonly registrationProtocolAdapter?: RegistrationProtocolAdapter;
	readonly generateClientSecret?: (sub: EntityId) => Promise<string | undefined>;
	/** Late pre-commit hook called after validation and response preparation, before `onRegistration`. */
	readonly onRegistrationInvalidation?: (sub: EntityId) => Promise<void>;

	readonly onRegistration?: (
		sub: EntityId,
		clientMetadata: Record<string, unknown>,
		clientSecret?: string,
	) => Promise<void>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `requestObjectTyping?` | `ProcessAutomaticRegistrationOptions["requestObjectTyping"]` | Automatic registration and signed PAR typing policy. Default strict; method options override this setting. Applies to both provider classes. |
| `registrationManagement?` | `ExplicitRegistrationHandlerConfig["registrationManagement"]` | Opt in to adapter-issued read-only registration access; the host enforces token permissions. Default disabled. |
| `options?` | `FederationOptions` | Federation transport, time, validation, and resource settings; role options override host options, and method options override role options. |
| `registrationPath?` | `string` | Explicit-registration route, defaulting to /registration. Use a leading-slash path or an absolute URL for host route integration. |
| `metadata?` | `Record<string, unknown>` | Provider publication metadata, cloned at construction. Initialization supplies federation_registration_endpoint; composed metadata must declare explicit registration support. |
| `trustAnchors?` | `TrustAnchorSet` | Independently trusted anchor identities and their public Federation Entity Keys. |
| `registrationResponseTtlSeconds?` | `number` | Signed registration-response lifetime in seconds; defaults to 86400 and is capped by the validated client chain's expiry. |
| `registrationProtocolAdapter?` | `RegistrationProtocolAdapter` | Optional protocol/profile validation and response-enrichment callbacks. The registration flow independently checks the selected protocol schema and federation policy. |
| `generateClientSecret?` | `(sub: EntityId) => Promise<string \| undefined>` | Optional explicit-registration secret generator. A nonempty returned value is added to the response; undefined omits it. |
| `onRegistrationInvalidation?` | `(sub: EntityId) => Promise<void>` | Explicit-registration hook after validation and response signing, immediately before onRegistration. Automatic registration does not invoke this hook. |
| `onRegistration?` | `( sub: EntityId, clientMetadata: Record<string, unknown>, clientSecret?: string, ) => Promise<void>` | Optional persistence callback. It receives the client identifier, selected client metadata block, and any client secret. Automatic processing passes the protocol keys actually used for authentication. |
| `trustMarkRequirements?` | `TrustMarkRequirements` | Declarative accreditation requirements checked before beforeRegistration and before accepting registration side effects. |
| `beforeRegistration?` | `( context: Readonly<RegistrationAccreditationContext>, signal?: AbortSignal, ) => Result<void> \| Promise<Result<void>>` | Application accreditation callback after declarative Trust Mark checks. A failing requirement prevents the callback; the callback must return a Result with ok set to true to continue. |

## `OidcRelyingPartyRole`

[Source](../../../packages/oidc/src/roles.ts#L404)

Client role for `openid_relying_party` metadata. It discovers a server, prepares signed authorization requests, performs Explicit Client Registration, and prepares PAR requests through the selected OIDC or OAuth profile. Constructors copy metadata; registration and instance assertion signing require host initialization. Assessments and static parsers can be used independently.

Use a fresh stateful role per host. The public API includes inherited members from the internal role base classes; those base classes are not package exports. Configuration and metadata properties marked `readonly` prevent reassignment through TypeScript, but do not freeze their referenced objects.

```typescript signature
new OidcRelyingPartyRole(config: OidcRelyingPartyRoleConfig): OidcRelyingPartyRole;
```

### `OidcRelyingPartyRole#type`

Entity Type Identifier `openid_relying_party`, used to select this role's metadata block and registration profile.

[Source](../../../packages/oidc/src/roles.ts#L405)

```typescript signature
readonly type: "openid_relying_party";
```

### `OidcRelyingPartyRole#automaticallyRegister`

Discover the server named by `opEntityId`, choose compatible chains sharing an anchor, and build an authorization-code request (`response_type: "code"`). Request delivery defaults to form_post; par mode also sends the PAR HTTP request. Per-call options override role options and host options. Nonempty delivery/URI values in the options argument override those in params, which override role configuration. Requires initialization and configured anchors; missing setup rejects, while protocol failures generally return a failing Result.

[Source](../../../packages/oidc/src/roles.ts#L419)

```typescript signature
automaticallyRegister(params: { readonly opEntityId: string; readonly redirect_uri: string; readonly scope?: string; readonly state?: string; readonly nonce?: string; readonly requestDelivery?: RequestDelivery; readonly requestUri?: string; }, options?: CreateAuthorizationRequestOptions): Promise<Result<AutomaticRegistrationResult>>;
```

### `OidcRelyingPartyRole#createPushedAuthorizationRequest`

Prepare a complete PAR endpoint, form body, headers, and selected provider chain from a supplied DiscoveryResult and proof mode. This method does not send the prepared request; the host supplies transport and any TLS client certificate. It checks the client/server metadata, shared anchor, proof, and published protocol keys. Initialization and a nonempty anchor set are required. Options and anchors use call, role, then host precedence.

[Source](../../../packages/oidc/src/roles.ts#L107)

```typescript signature
createPushedAuthorizationRequest(discovery: DiscoveryResult, parameters: Readonly<Record<string, unknown>>, proof: PushedAuthorizationProof, options?: Omit<FederationOptions & { trustAnchors?: TrustAnchorSet; }, "engine">): Promise<Result<PreparedPushedAuthorizationRequest>>;
```

### `OidcRelyingPartyRole#assessEntity`

Assess the target using the requested protocol block and either local validation or an explicitly authorized resolver. The protocol selector is one of `openid_relying_party`, `openid_provider`, `oauth_authorization_server`, `oauth_client`, or `oauth_resource`; it is not inferred from the calling class. Effective server issuer values are bound to the target Entity Identifier. Invalid target identifiers can reject before a Result is returned. This method also works before initialization when role or per-call trust inputs are supplied. Options use call, role, then host precedence; anchors use the same order, followed by an empty set.

[Source](../../../packages/oidc/src/roles.ts#L145)

```typescript signature
assessEntity(target: string, type: "openid_relying_party" | "openid_provider" | "oauth_authorization_server" | "oauth_client" | "oauth_resource", options?: EntityAssessmentOptions & { trustAnchors?: TrustAnchorSet; }): Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```

### `OidcRelyingPartyRole#metadata`

Mutable metadata block copied from constructor input. Hosts compose a detached publication snapshot; changing this role object after attachment does not automatically update a Leaf or Authority EC. Validate proposed values with the static publication parser before constructing a new host.

[Source](../../../packages/oidc/src/roles.ts#L162)

```typescript signature
readonly metadata: Record<string, unknown>;
```

### `OidcRelyingPartyRole#config`

Constructor configuration retained by reference. Metadata is copied separately; the configuration object and its service dependencies are not deeply frozen. Treat configuration as immutable after attachment; there is no general configuration-update API.

[Source](../../../packages/oidc/src/roles.ts#L167)

```typescript signature
readonly config: OidcRelyingPartyRoleConfig;
```

### `OidcRelyingPartyRole#validateMetadata`

Check the composed client publication block and retain a detached copy for subsequent client registration operations. Omitted requirements may be completed by a Superior; supplied invalid values throw TypeError.

[Source](../../../packages/oidc/src/roles.ts#L171)

```typescript signature
validateMetadata(metadata: Readonly<Record<string, unknown>>, context?: EntityContext): void;
```

### `OidcRelyingPartyRole#initialize`

Bind the role to the host's EntityContext. Reusing it with a different context throws, while the same context can be passed again. Hosts invoke this during composition. Client registration and instance assertion signing use this identity and host services.

[Source](../../../packages/oidc/src/roles.ts#L177)

```typescript signature
initialize(context: EntityContext): void;
```

### `OidcRelyingPartyRole#createClientAssertion`

Sign a private_key_jwt assertion using the attached host's Entity Identifier and this role's protocol signing purposes. Configure the clientAssertion signing purpose on the role. To reuse the Request Object key, bind both purposes to the same keyring entry explicitly. Call options inherit the host engine and can narrow the configured verification policy. The default lifetime is 60 seconds. This helper does not prove that the signer is published in the client's metadata; registration workflows perform that binding check. Missing initialization rejects.

[Source](../../../packages/oidc/src/roles.ts#L195)

```typescript signature
createClientAssertion(audience: string, options?: Omit<ClientAssertionOptions, "engine">): Promise<string>;
```

### `OidcRelyingPartyRole#explicitlyRegister`

Discover the provider, validate compatible shared-anchor evidence, and POST a self-issued client EC signed with the host's Federation Entity Key. Verify the provider's signed response and return its client metadata and separate registration/chain deadlines. The opEntityId argument also names an OAuth AS when this is an OAuthClientRole. Options and anchors use call, role, then host precedence. Initialization and configured anchors are required.

[Source](../../../packages/oidc/src/roles.ts#L311)

```typescript signature
explicitlyRegister(opEntityId: string, options?: Omit<FederationOptions & { readonly trustAnchors?: TrustAnchorSet; }, "engine">): Promise<Result<ExplicitRegistrationResult>>;
```

### `OidcRelyingPartyRole#createAuthorizationRequest`

Build an authorization request from a supplied, locally validated DiscoveryResult and arbitrary supported authorization parameters. The target chain is rechecked for the selected registration profile and shared anchor. options.trustAnchors takes precedence over the explicit trustAnchors argument; other options use call, role, then host precedence. Delivery defaults to form_post; par mode performs HTTP. Initialization is required. Use this entry point when the automaticallyRegister convenience parameters are insufficient.

[Source](../../../packages/oidc/src/roles.ts#L368)

```typescript signature
createAuthorizationRequest(discovery: DiscoveryResult, authzRequestParams: Readonly<Record<string, unknown>>, trustAnchors: TrustAnchorSet, options?: CreateAuthorizationRequestOptions): Promise<Result<AutomaticRegistrationResult>>;
```

### `OidcRelyingPartyRole.parseMetadata`

Parse completed metadata and return Zod's `{ success, data }` or `{ success: false, error }` result, without constructing or initializing a role. Conditional protocol requirements are checked; a successful parse establishes neither Federation trust nor key ownership. Unknown extension fields are preserved. 

[Source](../../../packages/oidc/src/roles.ts#L408)

```typescript signature
static parseMetadata(metadata: unknown, options?: MetadataValidationOptions): z.ZodSafeParseResult<OpenIDRelyingPartyMetadata>;
```

### `OidcRelyingPartyRole.parsePublicationMetadata`

Parse supplied publication fields while allowing a Superior to complete missing requirements. Supplied values and applicable cross-field consistency rules are still checked. This is independent validation, not publication or trust establishment; success/error uses the Zod parse-result format.

[Source](../../../packages/oidc/src/roles.ts#L415)

```typescript signature
static parsePublicationMetadata(metadata: unknown, options?: MetadataValidationOptions): z.ZodSafeParseResult<OpenIDRelyingPartyPublicationMetadata>;
```

### `OidcRelyingPartyRole.assessEntity`

Assess the target using the requested protocol block and either local validation or an explicitly authorized resolver. The protocol selector is one of `openid_relying_party`, `openid_provider`, `oauth_authorization_server`, `oauth_client`, or `oauth_resource`; it is not inferred from the calling class. Effective server issuer values are bound to the target Entity Identifier. Invalid target identifiers can reject before a Result is returned. This static callable takes anchors and options explicitly and uses no role instance.

[Source](../../../packages/oidc/src/roles.ts#L143)

```typescript signature
static assessEntity: (target: string, type: "openid_relying_party" | "openid_provider" | "oauth_authorization_server" | "oauth_client" | "oauth_resource", anchors: TrustAnchorSet, options?: EntityAssessmentOptions) => Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```

Callable signature:

```typescript signature
OidcRelyingPartyRole.assessEntity(target: string, type: "openid_relying_party" | "openid_provider" | "oauth_authorization_server" | "oauth_client" | "oauth_resource", anchors: TrustAnchorSet, options?: EntityAssessmentOptions): Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```


## `OidcRelyingPartyRoleConfig`

[Source](../../../packages/oidc/src/roles.ts#L84)

Client role settings shared by OIDC relying parties and OAuth clients. Metadata is copied at construction; the remaining configuration and service dependencies retain their identity. Registration and instance assertion signing require host initialization; assessments can use explicit or role-configured anchors before attachment. Per-call options override role options, which override host options.

```typescript signature
interface OidcRelyingPartyRoleConfig {
	readonly options?: BoundFederationOptions;
	readonly signing?: SigningPurposes;
	readonly metadata?: Record<string, unknown>;
	readonly requestObjectTtlSeconds?: number;
	readonly includePeerTrustChain?: boolean;
	readonly requestDelivery?: RequestDelivery;
	readonly requestUri?: string;
	readonly trustAnchors?: TrustAnchorSet;
	readonly authorityHints?: readonly EntityId[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `options?` | `FederationOptions` | Federation transport, time, validation, and resource settings; role options override host options, and method options override role options. |
| `signing?` | `SigningPurposes` | Explicit Request Object and client assertion purpose names in the host keyring. |
| `metadata?` | `Record<string, unknown>` | Publication metadata for this role, cloned at construction. Full validation occurs through the host publication hook; the static parsers can validate input independently. |
| `requestObjectTtlSeconds?` | `number` | Request Object lifetime in seconds; defaults to 300 and is bounded by the applicable client-chain lifetime. |
| `includePeerTrustChain?` | `boolean` | Include a peer_trust_chain ending at the selected shared anchor. Defaults to false; inability to build it returns a registration error. |
| `requestDelivery?` | `RequestDelivery` | Delivery mode: query, form_post, request_uri, or par. The default is form_post. The result shape depends on this mode. |
| `requestUri?` | `string` | HTTPS URL where the application will serve the returned Request Object for request_uri delivery. It is required in that mode; this library does not host it. |
| `trustAnchors?` | `TrustAnchorSet` | Independently trusted anchor identities and their public Federation Entity Keys. |
| `authorityHints?` | `readonly EntityId[]` | Fallback Immediate Superior identifiers when the attached host context has no authorityHints. Host context takes precedence. |

