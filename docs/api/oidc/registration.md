# Registration and protocol keys

[`@oidfed/oidc`](README.md)

The role methods prepare or process Federation registration evidence. The host protocol engine owns authorization responses, token endpoints, PAR request storage, user sessions, and client persistence. Optional adapter and callback contracts connect those responsibilities. Federation signing keys and protocol signing keys have separate jobs.

Several exported configuration types describe the internal registration workflows assembled by role methods. They do not expose standalone registration functions; the role entries identify the public call sites.

## `AutomaticRegistrationResult`

[Source](../../../packages/oidc/src/registration/automatic-client.ts#L98)

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

Automatic PAR includes a signed Request Object. When both parties support `private_key_jwt`, it also sends a client assertion if the provider's advertised algorithms permit the selected signing key. If the provider omits its list, the assertion follows local protocol policy. If the list excludes the algorithm, automatic PAR sends the signed Request Object alone. Explicitly preparing PAR with `private_key_jwt` returns an error for an excluded algorithm.

## `ExplicitRegistrationResult`

[Source](../../../packages/oidc/src/registration/explicit-client.ts#L59)

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

## `PreparedPushedAuthorizationRequest`

[Source](../../../packages/oidc/src/registration/pushed.ts#L74)

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

Per-call options for `provider.processAutomaticRegistration()`. The attached host supplies the engine, registry, storage, and receiver identity. The role selects the provider profile.

```typescript signature
interface ProcessAutomaticRegistrationOptions extends BoundFederationOptions, RegistrationAccreditationPolicy {
  requestObjectTyping?: "strict" | "compatible";
  providerMetadata?: Readonly<Record<string, unknown>>;
}
```

## `ProcessedAutomaticRegistration`

[Source](../../../packages/oidc/src/registration/automatic-server.ts#L73)

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

[Source](../../../packages/oidc/src/registration/pushed.ts#L98)

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

[Source](../../../packages/oidc/src/registration/automatic-server.ts#L58)

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

## `ProcessPushedAuthorizationRequestOptions`

Per-call policy and trusted transport evidence for `provider.processPushedAuthorizationRequest()`. Supply effective provider metadata when it differs from the role’s publication fields. For client certificate authentication, the host callback supplies the certificate verified by the TLS connection.

```typescript signature
interface ProcessPushedAuthorizationRequestOptions extends ProcessAutomaticRegistrationOptions {
  readonly clientCertificate?: (
    request: Request, signal: AbortSignal,
  ) => string | undefined | Promise<string | undefined>;
  readonly clientAttestation?: Omit<
    AuthenticateClientAttestationOptions,
    "audience" | "clientId" | "engine" | "algorithmRegistry" | "storage"
  >;
}
```

## `PushedAuthorizationProof`

[Source](../../../packages/oidc/src/registration/pushed.ts#L64)

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

[Source](../../../packages/oidc/src/registration/accreditation.ts#L16)

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

[Source](../../../packages/oidc/src/registration/accreditation.ts#L20)

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

The adapter can reject authenticated client metadata in explicit, automatic, and pushed authorization registration. The optional enrichment callback customizes explicit response metadata before policy validation, signing, and persistence.

```typescript signature
interface RegistrationProtocolAdapter {
  validateClientMetadata(
    metadata: Readonly<Record<string, Readonly<Record<string, unknown>>>>,
    context: RegistrationProtocolAdapterContext,
  ): Result<void, FederationError>;
  enrichResponseMetadata?(
    metadata: Record<string, Record<string, unknown>>,
    trustChain: ValidatedTrustChain,
    context: RegistrationProtocolAdapterContext & { readonly flow: "explicit" },
  ): Record<string, Record<string, unknown>>;
}
```

## `RegistrationProtocolAdapterContext`

Use `clientMetadataType` to select the client block in the metadata map. `peerResolvedOpMetadata` is present when processing supplied and validated peer evidence. The signal identifies the operation’s cancellation context.

```typescript signature
interface RegistrationProtocolAdapterContext {
  readonly flow: "explicit" | "automatic" | "par";
  readonly clientMetadataType: "openid_relying_party" | "oauth_client";
  readonly peerResolvedOpMetadata?: Readonly<Record<string, unknown>>;
  readonly signal?: AbortSignal;
}
```

## `RequestDelivery`

[Source](../../../packages/oidc/src/registration/automatic-client.ts#L44)

String union selecting delivery: query places the signed Request Object in an authorization URL; form_post returns form fields; request_uri returns a URL referencing a caller-hosted JWT; par performs a PAR request and returns the resulting authorization URL. The default is form_post.

```typescript signature
type RequestDelivery = "query" | "form_post" | "request_uri" | "par";
```

