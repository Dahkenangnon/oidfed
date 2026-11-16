# Client and endpoint authentication

[`@oidfed/core`](README.md)

Choose endpoint authentication independently from application sessions. Private-key JWT assertions, Client Attestation proofs, challenge storage, and custom method handlers have different trust inputs. Supply the responder's Entity Identifier as the audience; an endpoint URL is not a replacement.

## `authenticateClientAttestation`

[Source](../../../packages/core/src/client-attestation.ts#L623)

Verify an attestation and proof pair with attester trust, audience, freshness, replay, and the optional host acceptance policy. Handle the returned failure before accepting the client.

```typescript signature
authenticateClientAttestation(attestationJwt: string, popJwt: string, options: AuthenticateClientAttestationOptions): Promise<Result<VerifiedClientAttestation, ClientAttestationError>>;
```

## `AuthenticateClientAttestationOptions`

[Source](../../../packages/core/src/client-attestation.ts#L127)

Trust, freshness, audience, and replay settings for client-attestation authentication.

```typescript signature
interface AuthenticateClientAttestationOptions
	extends Omit<ClientAttestationVerificationOptions, "expectedAudience"> {
	readonly allowedProofAlgorithms?: readonly string[];
	readonly audience: string;
	readonly clientId?: string;
	readonly expectedChallenge?: string;
	readonly maxProofAgeSeconds?: number;
	readonly replayStore?: ReplayStore;
	readonly freshness?: ClientAttestationFreshness;
	readonly replay?: ClientAttestationReplay;
	readonly acceptClient: (
		verified: VerifiedClientAttestation,
		signal?: AbortSignal,
	) => boolean | Promise<boolean>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `allowedProofAlgorithms?` | `readonly string[]` | Proof-of-possession signing algorithms accepted in addition to backend support. |
| `audience` | `string` | Expected recipient identity. Federation endpoint assertions use the responder's Entity Identifier, not its URL origin. |
| `clientId?` | `string` | Optional expected client instance identifier; it must match the verified attestation subject. |
| `expectedChallenge?` | `string` | Challenge value the verifier expects to see in the proof. |
| `maxProofAgeSeconds?` | `number` | Maximum accepted age in seconds of the proof's iat. |
| `replayStore?` | `ReplayStore` | Atomic replay store for consuming one-time JWT identifiers. |
| `freshness?` | `ClientAttestationFreshness` | Attestation freshness policy: a maximum iat age or host-verified challenge. This is separate from proof replay protection. |
| `replay?` | `ClientAttestationReplay` | Proof replay policy using an atomic JWT identifier store, challenge consumption, or freshness alone. |
| `acceptClient` | `( verified: VerifiedClientAttestation, signal?: AbortSignal, ) => boolean \| Promise<boolean>` | Final host acceptance policy after cryptographic attestation and proof verification. |
| `signal?` | `AbortSignal` | Cancellation signal for the waiting caller and cooperative work started by this operation. |
| `httpTimeoutMs?` | `number` | Timeout in milliseconds for bounded transport or host callbacks; defaults to 10000. |
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
| `cache?` | `CacheProvider` | Host cache for signed statements or operation results; cache hits do not establish trust. |
| `logger?` | `Logger` | Optional host logger. Library calls are message-only, nonblocking, and protected from sink failures. |
| `clockSkewSeconds?` | `number` | Allowed time-claim leeway in seconds; the default verifier allowance is 60 seconds. |
| `maxChainDepth?` | `number` | Maximum recursive discovery depth; defaults to 8. |
| `maxChainLength?` | `number` | Maximum statements in a validated chain, including both ECs. Default: 100; resource policy, not a protocol limit. |
| `maxResolutionSteps?` | `number` | Maximum eligible branch expansions per resolution, including reused statements. Default: 1000. |
| `maxAuthorityHints?` | `number` | Maximum authority hints examined for an entity; defaults to 10. |
| `maxConcurrentFetches?` | `number` | Maximum concurrent fetches during chain traversal and collection refresh; defaults to 6. |
| `cacheMaxTtlSeconds?` | `number` | Fetched EC and Subordinate Statement cache retention cap in seconds; defaults to 3600 and is bounded by the statement's `exp`. Applies to statement fetchers using a cache. |
| `maxResponseBytes?` | `number` | Maximum response or decoded token size in bytes for APIs applying this limit; the shared default is 524288. |
| `blockedCIDRs?` | `string[]` | Additional blocked IP ranges applied by URL fetch validation. |
| `allowedHosts?` | `string[]` | Optional exact hostname allowlist applied before outbound fetching. |
| `authorityHintFilter?` | `(hint: URL, subject: EntityId) => boolean` | Host predicate for accepting an authority hint before traversal. |
| `understoodCriticalClaims?` | `ReadonlySet<string>` | Extension claim names the application actually understands and processes; unknown critical claims are rejected. |
| `maxTotalFetches?` | `number` | Maximum HTTP client calls; discovery helpers share the allowance across discovery and candidate validation. Cached and supplied statements use no allowance. Core accepts zero. Default: 50. |
| `customPolicyOperators?` | `readonly PolicyOperatorDefinition[]` | Federation-defined policy operators in addition to the seven standard ones. Forwarded to `resolveMetadataPolicy` and `applyMetadataPolicy` during trust-chain validation. |
| `customConstraintChecks?` | `readonly ConstraintCheckDefinition[]` | Federation-defined constraints checked against authenticated chains. Unknown names are ignored. |
| `trustChain?` | `readonly string[]` | Supplied or validated Trust Chain, in the representation declared by this contract. |
| `allowedAttestationAlgorithms?` | `readonly string[]` | Attestation signing algorithms accepted in addition to backend support. |
| `getAttester` | `( issuer: string, header: Readonly<jose.ProtectedHeaderParameters>, signal: AbortSignal, ) => Result<TrustedClientAttester> \| Promise<Result<TrustedClientAttester>>` | The issuer and header are unverified lookup hints, never trust evidence. |

## `authenticatedEndpointCaller`

[Source](../../../packages/core/src/endpoint-authentication.ts#L112)

Read authentication context established for a request by the endpoint authentication layer.

```typescript signature
authenticatedEndpointCaller(request: Request): string | undefined;
```

## `authenticateEndpointRequest`

[Source](../../../packages/core/src/endpoint-authentication.ts#L178)

Shared credential verification for Authority, Leaf, and Collection endpoints.

```typescript signature
authenticateEndpointRequest(request: Request, form: URLSearchParams, config: EndpointAuthenticationConfig, options?: FederationOptions): Promise<Result<string | undefined, EndpointAuthenticationError>>;
```

## `ClientAssertionOptions`

[Source](../../../packages/core/src/jose/client-assertion.ts#L9)

Lifetime, clock, timeout, and cancellation settings for creating a client assertion.

```typescript signature
interface ClientAssertionOptions
	extends Pick<FederationOptions, "signal" | "httpTimeoutMs"> {
	readonly expiresInSeconds?: number;
	/** NumericDate clock used for iat and exp. */
	readonly clock?: Clock;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `expiresInSeconds?` | `number` | Assertion lifetime in seconds; defaults to 60 and must be finite and positive. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `signal?` | `AbortSignal` | Cancellation signal for the waiting caller and cooperative work started by this operation. |
| `httpTimeoutMs?` | `number` | Timeout in milliseconds for bounded transport or host callbacks; defaults to 10000. |

## `ClientAttestation`

[Source](../../../packages/core/src/client-attestation.ts#L71)

Claims carried by a client attestation, including its confirmation key.

```typescript signature
type ClientAttestation = {
	[key: string]: unknown;
	iss: string;
	sub: string;
	exp: number;
	cnf: { [key: string]: unknown; jwk: JWK; };
	iat?: undefined | number;
	nbf?: undefined | number;
	wallet_name?: undefined | string;
	wallet_link?: undefined | string;
};
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `iss` | `string` | Issuer of the signed artifact. Its required identity relationship depends on the artifact being validated. |
| `sub` | `string` | Client instance identifier attested by the issuer. |
| `exp` | `number` | Expiration time as a finite NumericDate in seconds since the Unix epoch. |
| `cnf` | `{ [key: string]: unknown; jwk: JWK; }` | Public confirmation JWK binding the attestation to the client instance's proof key. |
| `iat?` | `undefined \| number` | Issuance time as a finite NumericDate in seconds since the Unix epoch. |
| `nbf?` | `undefined \| number` | NumericDate before which the JWT must not be accepted. |
| `wallet_name?` | `undefined \| string` | Human-readable wallet name published in relying-party metadata. |
| `wallet_link?` | `undefined \| string` | URL for wallet information published in relying-party metadata. |

## `ClientAttestationError`

[Source](../../../packages/core/src/client-attestation.ts#L29)

Stable failure reason for a host's draft-07 HTTP response policy.

```typescript signature
interface ClientAttestationError extends FederationError {
	readonly attestationError?: "use_attestation_challenge" | "use_fresh_attestation" | "invalid_client_attestation";
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `attestationError?` | `\| "use_attestation_challenge" \| "use_fresh_attestation" \| "invalid_client_attestation"` | Draft-07 error indicating an invalid attestation or the need for a challenge or fresher evidence. |
| `code` | `FederationErrorCode \| InternalErrorCode` | Error code for the failure; use the declared union for the allowed values. |
| `description` | `string` | Human-readable explanation or informational description, according to the owning contract. |
| `cause?` | `unknown` | Original diagnostic cause, when retained. Do not expose it directly in an HTTP error response. |
| `remoteError?` | `{ readonly code: string; readonly status: number }` | Untrusted responder details; code remains a typed local classification. |

## `ClientAttestationFreshness`

[Source](../../../packages/core/src/client-attestation.ts#L90)

Policy for deciding whether attestation evidence is recent enough.

```typescript signature
type ClientAttestationFreshness = {
	readonly mode: "iat";
	readonly maxAgeSeconds?: number;
} | {
	readonly mode: "challenge";
	readonly verify: (challenge: string, signal: AbortSignal) => Result<VerifiedAttestationChallenge> | Promise<Result<VerifiedAttestationChallenge>>;
};
```

## `clientAttestationHeaders`

[Source](../../../packages/core/src/client-attestation.ts#L683)

Build the HTTP header representation of a Client Attestation and proof pair.

```typescript signature
clientAttestationHeaders(attestationJwt: string, popJwt: string): Result<Headers>;
```

## `ClientAttestationOptions`

[Source](../../../packages/core/src/client-attestation.ts#L72)

Shared federation settings and an optional chain used by client-attestation operations.

```typescript signature
interface ClientAttestationOptions extends FederationOptions {
	readonly trustChain?: readonly string[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `trustChain?` | `readonly string[]` | Supplied or validated Trust Chain, in the representation declared by this contract. |
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
| `blockedCIDRs?` | `string[]` | Additional blocked IP ranges applied by URL fetch validation. |
| `allowedHosts?` | `string[]` | Optional exact hostname allowlist applied before outbound fetching. |
| `authorityHintFilter?` | `(hint: URL, subject: EntityId) => boolean` | Host predicate for accepting an authority hint before traversal. |
| `understoodCriticalClaims?` | `ReadonlySet<string>` | Extension claim names the application actually understands and processes; unknown critical claims are rejected. |
| `maxTotalFetches?` | `number` | Maximum HTTP client calls; discovery helpers share the allowance across discovery and candidate validation. Cached and supplied statements use no allowance. Core accepts zero. Default: 50. |
| `customPolicyOperators?` | `readonly PolicyOperatorDefinition[]` | Federation-defined policy operators in addition to the seven standard ones. Forwarded to `resolveMetadataPolicy` and `applyMetadataPolicy` during trust-chain validation. |
| `customConstraintChecks?` | `readonly ConstraintCheckDefinition[]` | Federation-defined constraints checked against authenticated chains. Unknown names are ignored. |

## `ClientAttestationReplay`

[Source](../../../packages/core/src/client-attestation.ts#L99)

Replay-protection settings for attestation proofs.

```typescript signature
type ClientAttestationReplay = {
	readonly mode: "jti";
	readonly store: ReplayStore;
} | {
	readonly mode: "challenge";
	readonly consume: (challenge: string, expiresAt: number, signal: AbortSignal) => boolean | Promise<boolean>;
} | {
	readonly mode: "freshness-only";
};
```

## `ClientAttestationVerificationOptions`

[Source](../../../packages/core/src/client-attestation.ts#L117)

Receiver binding for an attestation that supplies aud (RFC 7519 §4.1.3).

```typescript signature
interface ClientAttestationVerificationOptions extends ClientAttestationOptions {
	readonly expectedAudience?: string;
	readonly allowedAttestationAlgorithms?: readonly string[];
	/** The issuer and header are unverified lookup hints, never trust evidence. */
	readonly getAttester: (
		issuer: string,
		header: Readonly<jose.ProtectedHeaderParameters>,
		signal: AbortSignal,
	) => Result<TrustedClientAttester> | Promise<Result<TrustedClientAttester>>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `expectedAudience?` | `string` | Recipient identity used for checking a present aud claim or a required proof audience. |
| `allowedAttestationAlgorithms?` | `readonly string[]` | Attestation signing algorithms accepted in addition to backend support. |
| `getAttester` | `( issuer: string, header: Readonly<jose.ProtectedHeaderParameters>, signal: AbortSignal, ) => Result<TrustedClientAttester> \| Promise<Result<TrustedClientAttester>>` | The issuer and header are unverified lookup hints, never trust evidence. |
| `trustChain?` | `readonly string[]` | Supplied or validated Trust Chain, in the representation declared by this contract. |
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
| `blockedCIDRs?` | `string[]` | Additional blocked IP ranges applied by URL fetch validation. |
| `allowedHosts?` | `string[]` | Optional exact hostname allowlist applied before outbound fetching. |
| `authorityHintFilter?` | `(hint: URL, subject: EntityId) => boolean` | Host predicate for accepting an authority hint before traversal. |
| `understoodCriticalClaims?` | `ReadonlySet<string>` | Extension claim names the application actually understands and processes; unknown critical claims are rejected. |
| `maxTotalFetches?` | `number` | Maximum HTTP client calls; discovery helpers share the allowance across discovery and candidate validation. Cached and supplied statements use no allowance. Core accepts zero. Default: 50. |
| `customPolicyOperators?` | `readonly PolicyOperatorDefinition[]` | Federation-defined policy operators in addition to the seven standard ones. Forwarded to `resolveMetadataPolicy` and `applyMetadataPolicy` during trust-chain validation. |
| `customConstraintChecks?` | `readonly ConstraintCheckDefinition[]` | Federation-defined constraints checked against authenticated chains. Unknown names are ignored. |

## `createAttestationChallengeHandler`

[Source](../../../packages/core/src/attestation-challenge.ts#L54)

Create a POST-only challenge handler around the host's issuance callback. The callback receives a bounded cancellation signal; issuance failures produce a generic HTTP 500 response. The host owns challenge generation, expiration, and any one-time consumption.

```typescript signature
createAttestationChallengeHandler(issue: (request: Request, signal: AbortSignal) => string | Promise<string>, options?: FederationOptions): (request: Request) => Promise<Response>;
```

## `createAttestationChallengeResponse`

[Source](../../../packages/core/src/attestation-challenge.ts#L47)

Create a JSON response containing the supplied challenge and `Cache-Control: no-store`. Empty challenges and values containing carriage returns or newlines throw `TypeError`. The host generates and tracks the challenge.

```typescript signature
createAttestationChallengeResponse(challenge: string): Response;
```

## `createClientAssertion`

[Source](../../../packages/core/src/jose/client-assertion.ts#L22)

Create a `private_key_jwt` assertion with `iss` and `sub` set to `clientId`, a single `aud`, a fresh random `jti`, and `iat`/`exp`. The default lifetime is 60 seconds. Invalid identifiers, clocks, or lifetimes reject before signing; signing is bounded by timeout and cancellation. Federation endpoint clients and OIDC/OAuth clients share this helper.

```typescript signature
createClientAssertion(clientId: string, audience: string, signer: JwtSigner, options?: ClientAssertionOptions): Promise<string>;
```

## `createClientAttestation`

[Source](../../../packages/core/src/client-attestation.ts#L592)

Create a draft-07 attestation using the caller's trusted attester signing key.

```typescript signature
createClientAttestation(issuer: string, params: CreateClientAttestationParams, signer: JwtSigner, options?: ClientAttestationOptions): Promise<Result<string>>;
```

## `CreateClientAttestationParams`

[Source](../../../packages/core/src/client-attestation.ts#L110)

Subject, confirmation key, expiry, and additional claims for creating a client attestation.

```typescript signature
interface CreateClientAttestationParams {
	readonly subject: string;
	readonly confirmationKey: JWK;
	readonly expiresAt: number;
	readonly claims?: Readonly<Record<string, unknown>>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `subject` | `string` | Subject identity for the statement, mark, or authentication being processed. |
| `confirmationKey` | `JWK` | Public key bound to the client instance by the attestation. |
| `expiresAt` | `number` | Expiration or eligibility deadline as a NumericDate in seconds; the owning API defines the evidence it bounds. |
| `claims?` | `Readonly<Record<string, unknown>>` | Claims associated with the artifact or selected for this operation. |

## `createClientAttestationProof`

[Source](../../../packages/core/src/client-attestation.ts#L641)

Each invocation creates a new jti. Reuse the attestation, never its proof.

```typescript signature
createClientAttestationProof(params: CreateClientAttestationProofParams, signer: JwtSigner, options?: FederationOptions): Promise<Result<string>>;
```

## `CreateClientAttestationProofParams`

[Source](../../../packages/core/src/client-attestation.ts#L634)

Client identity, audience, and signing inputs for an attestation proof of possession.

```typescript signature
interface CreateClientAttestationProofParams {
	readonly clientId: string;
	readonly audience: string;
	readonly challenge?: string;
	readonly claims?: Readonly<Record<string, unknown>>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `clientId` | `string` | Client Entity Identifier used as the assertion issuer and subject. |
| `audience` | `string` | Expected recipient identity. Federation endpoint assertions use the responder's Entity Identifier, not its URL origin. |
| `challenge?` | `string` | Challenge supplied for attestation freshness or proof replay checks. |
| `claims?` | `Readonly<Record<string, unknown>>` | Claims associated with the artifact or selected for this operation. |

## `createEndpointAuthenticatedHandler`

[Source](../../../packages/core/src/endpoint-authentication.ts#L330)

Wrap an endpoint handler with configured method and credential checks before invoking the protected handler.

```typescript signature
createEndpointAuthenticatedHandler(config: EndpointAuthenticationConfig, inner: (request: Request) => Promise<Response>, options?: FederationOptions, nativeMethod?: "GET" | "POST", unorderedParameters?: readonly string[]): (request: Request) => Promise<Response>;
```

## `CustomEndpointClientAuthentication`

[Source](../../../packages/core/src/endpoint-client.ts#L27)

A host-supplied authentication method for an outgoing federation endpoint request.

```typescript signature
interface CustomEndpointClientAuthentication {
	readonly method: string;
	/** Responder Entity Identifier for credential audience binding; do not infer it from the URL origin. */
	readonly audience: string;
	readonly prepare: (input: Readonly<{
		endpoint: string;
		audience: string;
		signal: AbortSignal;
	}>) => {
		readonly parameters?: Readonly<Record<string, string>>;
		readonly headers?: Readonly<Record<string, string>>;
	} | Promise<{
		readonly parameters?: Readonly<Record<string, string>>;
		readonly headers?: Readonly<Record<string, string>>;
	}>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `method` | `string` | Authentication method or native HTTP method, as specified by this contract. |
| `audience` | `string` | Expected recipient identity. Federation endpoint assertions use the responder's Entity Identifier, not its URL origin. |
| `prepare` | `( input: Readonly<{ endpoint: string; audience: string; signal: AbortSignal }>, ) => \| { readonly parameters?: Readonly<Record<string, string>>; readonly headers?: Readonly<Record<string, string>>; } \| Promise<{ readonly parameters?: Readonly<Record<string, string>>; readonly headers?: Readonly<Record<string, string>>; }>` | Prepare authentication headers or form fields for the exact endpoint and configured audience. |

## `EndpointAuthentication`

[Source](../../../packages/core/src/endpoint-authentication.ts#L97)

Custom endpoint authentication methods and the hook for obtaining trusted transport evidence.

```typescript signature
interface EndpointAuthentication {
	readonly methods?: Readonly<Record<string, EndpointAuthenticationMethod>>;
	/** May return evidence synchronously or asynchronously; failures reject authentication. */
	readonly transportEvidence?: (request: Request) => unknown | Promise<unknown>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `methods?` | `Readonly<Record<string, EndpointAuthenticationMethod>>` | Own-name registry of custom authentication methods; private_key_jwt and none are handled by core. |
| `transportEvidence?` | `(request: Request) => unknown \| Promise<unknown>` | May return evidence synchronously or asynchronously; failures reject authentication. |

## `EndpointAuthenticationConfig`

[Source](../../../packages/core/src/endpoint-authentication.ts#L102)

Accepted methods and verification dependencies for a federation endpoint.

```typescript signature
interface EndpointAuthenticationConfig {
	readonly receiverEntityId: string;
	readonly methods: readonly string[];
	readonly replayStore?: ReplayStore;
	readonly getClientFederationJwks?: (client: EntityId) => Promise<JWKSet | undefined>;
	readonly allowedAlgorithms?: readonly string[];
	readonly extensions?: EndpointAuthentication;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `receiverEntityId` | `string` | Entity Identifier of the receiving endpoint used as the client-assertion audience. |
| `methods` | `readonly string[]` | Authentication methods accepted by the endpoint; include none to permit anonymous requests. |
| `replayStore?` | `ReplayStore` | Atomic replay store for consuming one-time JWT identifiers. |
| `getClientFederationJwks?` | `(client: EntityId) => Promise<JWKSet \| undefined>` | Look up independently trusted Federation Entity Keys for the authenticating client. |
| `allowedAlgorithms?` | `readonly string[]` | Optional algorithm allowlist, applied in addition to the library's supported algorithms. |
| `extensions?` | `EndpointAuthentication` | Host authentication-method implementations and optional transport evidence. |

## `EndpointAuthenticationContext`

[Source](../../../packages/core/src/endpoint-client.ts#L47)

Request context from traversal; standalone clients may not know the responder identity.

```typescript signature
interface EndpointAuthenticationContext {
	readonly endpoint: string;
	/** Entity Identifier from the calling operation, never inferred from the endpoint origin. */
	readonly responder?: EntityId;
	readonly signal?: AbortSignal;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `endpoint` | `string` | Serving or remote endpoint URL; request extension contexts use status, list, or retrieval instead. |
| `responder?` | `EntityId` | Known hosting entity identity and anchor role used to bind serving and authentication behavior. |
| `signal?` | `AbortSignal` | Cancellation signal for the waiting caller and cooperative work started by this operation. |

## `EndpointAuthenticationError`

[Source](../../../packages/core/src/endpoint-authentication.ts#L20)

Controlled protocol response from a host authentication verifier.

```typescript signature
interface EndpointAuthenticationError extends FederationError {
	readonly authenticationResponse?: {
		readonly error: "invalid_client" | "invalid_client_attestation" | "use_attestation_challenge" | "use_fresh_attestation";
		readonly status?: 400 | 401;
		readonly headers?: Readonly<Record<string, string>>;
	};
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `authenticationResponse?` | `{ readonly error: \| "invalid_client" \| "invalid_client_attestation" \| "use_attestation_challenge" \| "use_fresh_attestation"; readonly status?: 400 \| 401; readonly headers?: Readonly<Record<string, string>>; }` | Approved authentication error details used when constructing the HTTP response. |
| `code` | `FederationErrorCode \| InternalErrorCode` | Error code for the failure; use the declared union for the allowed values. |
| `description` | `string` | Human-readable explanation or informational description, according to the owning contract. |
| `cause?` | `unknown` | Original diagnostic cause, when retained. Do not expose it directly in an HTTP error response. |
| `remoteError?` | `{ readonly code: string; readonly status: number }` | Untrusted responder details; code remains a typed local classification. |

## `endpointAuthenticationErrorResponse`

[Source](../../../packages/core/src/endpoint-authentication.ts#L33)

Render only approved authentication headers; arbitrary host errors remain private.

```typescript signature
endpointAuthenticationErrorResponse(error: EndpointAuthenticationError): Response;
```

## `EndpointAuthenticationInput`

[Source](../../../packages/core/src/endpoint-authentication.ts#L89)

Request information supplied to endpoint authentication.

```typescript signature
interface EndpointAuthenticationInput {
	readonly signal?: AbortSignal;
	readonly receiverEntityId: string;
	readonly parameters: Readonly<Record<string, readonly string[]>>;
	readonly headers: Readonly<Record<string, string>>;
	/** Supplied by the host transport integration, never inferred from identity headers. */
	readonly transport?: unknown;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `signal?` | `AbortSignal` | Cancellation signal for the waiting caller and cooperative work started by this operation. |
| `receiverEntityId` | `string` | Entity Identifier of the receiving endpoint used as the client-assertion audience. |
| `parameters` | `Readonly<Record<string, readonly string[]>>` | Detached request form values, preserving repeated values for custom verification. |
| `headers` | `Readonly<Record<string, string>>` | HTTP request headers supplied to the custom verifier. |
| `transport?` | `unknown` | Supplied by the host transport integration, never inferred from identity headers. |

## `EndpointAuthenticationMethod`

[Source](../../../packages/core/src/endpoint-authentication.ts#L79)

A registered authentication method and the parameters or headers it understands.

```typescript signature
interface EndpointAuthenticationMethod {
	readonly parameters?: readonly string[];
	readonly headers?: readonly string[];
	readonly detect?: (input: EndpointAuthenticationInput) => boolean;
	readonly authenticate: (input: EndpointAuthenticationInput) => Result<{
		entityId: string;
	}, EndpointAuthenticationError> | Promise<Result<{
		entityId: string;
	}, EndpointAuthenticationError>>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `parameters?` | `readonly string[]` | Credential parameter names this custom method recognizes. They must be carried in the POST form rather than the URL. |
| `headers?` | `readonly string[]` | HTTP credential header names this custom method recognizes. |
| `detect?` | `(input: EndpointAuthenticationInput) => boolean` | Return whether the request contains credentials belonging to this authentication method. |
| `authenticate` | `( input: EndpointAuthenticationInput, ) => \| Result<{ entityId: string }, EndpointAuthenticationError> \| Promise<Result<{ entityId: string }, EndpointAuthenticationError>>` | Verify this method's credentials and return the authenticated Entity Identifier or a controlled error. |

## `EndpointAuthenticationProvider`

[Source](../../../packages/core/src/endpoint-client.ts#L54)

Return undefined to request anonymous access. Failure never falls back to anonymous access.

```typescript signature
type EndpointAuthenticationProvider = (
	context: Readonly<EndpointAuthenticationContext>,
) => EndpointClientAuthentication | undefined | Promise<EndpointClientAuthentication | undefined>;
```

## `EndpointClientAuthentication`

[Source](../../../packages/core/src/endpoint-client.ts#L43)

Authentication settings for an outgoing federation endpoint request.

```typescript signature
type EndpointClientAuthentication = PrivateKeyJwtEndpointAuthentication | CustomEndpointClientAuthentication;
```

## `endpointCredentialParameterNames`

[Source](../../../packages/core/src/endpoint-authentication.ts#L315)

Credentials declared by authentication methods belong in the POST form, never the URL.

```typescript signature
endpointCredentialParameterNames(extensions?: EndpointAuthentication): ReadonlySet<string>;
```

## `fetchAttestationChallenge`

[Source](../../../packages/core/src/attestation-challenge.ts#L16)

POST to a challenge endpoint and return its nonempty `attestation_challenge` value. The request requires HTTP 200, rejects redirects, and does not cache a challenge or retry the protected operation automatically.

```typescript signature
fetchAttestationChallenge(endpoint: string, options?: FederationOptions): Promise<Result<string>>;
```

## `invokeVerificationPolicy`

[Source](../../../packages/core/src/client-attestation.ts#L144)

Bound application verification hooks and release the caller promptly on cancellation.

```typescript signature
invokeVerificationPolicy<T>(policy: (context: T, signal?: AbortSignal) => boolean | Promise<boolean>, context: T, options: ClientAttestationOptions, operation?: string): Promise<Result<true>>;
```

## `parseClientAttestationHeaders`

[Source](../../../packages/core/src/client-attestation.ts#L695)

Fetch Headers combines duplicates; combined values fail the single-JWT grammar.

```typescript signature
parseClientAttestationHeaders(headers: Headers, options?: Pick<FederationOptions, "maxResponseBytes">): Result<{
	attestationJwt: string;
	popJwt: string;
}, ClientAttestationError>;
```

## `parseConcatenatedClientAttestation`

[Source](../../../packages/core/src/client-attestation.ts#L562)

ACA §7.2 syntax parsing; authenticate the returned pair before accepting its claims.

```typescript signature
parseConcatenatedClientAttestation(value: string, options?: Pick<ClientAttestationOptions, "maxResponseBytes">): Result<{
	attestationJwt: string;
	popJwt: string;
}>;
```

## `PrivateKeyJwtEndpointAuthentication`

[Source](../../../packages/core/src/endpoint-client.ts#L20)

Client identity, responder audience, and signing credentials for `private_key_jwt` authentication.

```typescript signature
interface PrivateKeyJwtEndpointAuthentication {
	readonly method: "private_key_jwt";
	readonly clientId: string;
	/** Entity Identifier of the responder, which may differ from the endpoint origin (§8.8). */
	readonly audience: string;
	readonly signer: JwtSigner;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `method` | `"private_key_jwt"` | Authentication method or native HTTP method, as specified by this contract. |
| `clientId` | `string` | Client Entity Identifier used as the assertion issuer and subject. |
| `audience` | `string` | Expected recipient identity. Federation endpoint assertions use the responder's Entity Identifier, not its URL origin. |
| `signer` | `JwtSigner` | Signing capability and its public algorithm/key identifier. Private-key custody stays with the implementation. |

## `readAttestationChallenge`

[Source](../../../packages/core/src/attestation-challenge.ts#L42)

A returned challenge replaces the previous challenge for the next request (draft-07 §8.1).

```typescript signature
readAttestationChallenge(headers: Headers): Result<string | undefined>;
```

## `serializeClientAttestation`

[Source](../../../packages/core/src/client-attestation.ts#L678)

Syntactic serialization only; receivers must authenticate the pair.

```typescript signature
serializeClientAttestation(attestationJwt: string, popJwt: string): Result<string>;
```

## `TrustedClientAttester`

[Source](../../../packages/core/src/client-attestation.ts#L75)

Verification keys accepted for an attester, with an optional trust-evidence deadline.

```typescript signature
interface TrustedClientAttester {
	readonly jwks: JWKSet;
	/** Expiry of the attester's trust evidence, independently of the attestation lifetime. */
	readonly expiresAt?: number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `jwks` | `JWKSet` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `expiresAt?` | `number` | Expiration or eligibility deadline as a NumericDate in seconds; the owning API defines the evidence it bounds. |

## `validateEndpointAuthentication`

[Source](../../../packages/core/src/endpoint-authentication.ts#L119)

Validate the endpoint's method configuration and extension handlers before accepting requests.

```typescript signature
validateEndpointAuthentication(config: EndpointAuthenticationConfig): EndpointAuthenticationConfig;
```

## `VerifiedAttestationChallenge`

[Source](../../../packages/core/src/client-attestation.ts#L86)

Challenge evidence returned after verification.

```typescript signature
interface VerifiedAttestationChallenge {
	readonly issuedAt: number;
	readonly expiresAt: number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuedAt` | `number` | Issuance time as a NumericDate in seconds. |
| `expiresAt` | `number` | Expiration or eligibility deadline as a NumericDate in seconds; the owning API defines the evidence it bounds. |

## `VerifiedClientAssertion`

[Source](../../../packages/core/src/jose/client-auth.ts#L12)

The client identity and claims obtained from a verified client assertion.

```typescript signature
interface VerifiedClientAssertion {
	readonly clientId: string;
	readonly issuedAt?: number;
	readonly expiresAt: number;
	readonly jti: string;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `clientId` | `string` | Client Entity Identifier used as the assertion issuer and subject. |
| `issuedAt?` | `number` | Issuance time as a NumericDate in seconds. |
| `expiresAt` | `number` | Expiration or eligibility deadline as a NumericDate in seconds; the owning API defines the evidence it bounds. |
| `jti` | `string` | JWT identifier used for replay protection, scoped to issuer and audience. |

## `VerifiedClientAttestation`

[Source](../../../packages/core/src/client-attestation.ts#L80)

The attestation and proof information returned after successful client authentication.

```typescript signature
interface VerifiedClientAttestation {
	readonly attestation: ClientAttestation;
	readonly attester: TrustedClientAttester;
	/** Current verification deadline, including trust and proof freshness where applicable. */
	readonly expiresAt: number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `attestation` | `ClientAttestation` | Verified client-attestation claims and their confirmation key. |
| `attester` | `TrustedClientAttester` | Independently trusted attester identity, public keys, and evidence deadline. |
| `expiresAt` | `number` | Expiration or eligibility deadline as a NumericDate in seconds; the owning API defines the evidence it bounds. |

## `verifyClientAssertion`

[Source](../../../packages/core/src/jose/client-auth.ts#L20)

Verify a `private_key_jwt` client assertion against the client's JWKS and expected audience.

```typescript signature
verifyClientAssertion(assertion: string, jwks: JWKSet, expectedAudience: string, options?: {
	clockSkewSeconds?: number;
	clock?: Clock;
	allowedAlgorithms?: readonly string[];
	replayStore?: ReplayStore;
	signal?: AbortSignal;
	httpTimeoutMs?: number;
}): Promise<Result<VerifiedClientAssertion, FederationError>>;
```

## `verifyClientAttestation`

[Source](../../../packages/core/src/client-attestation.ts#L609)

Verify the attestation JWT against an independently trusted attester and the configured freshness policy. Authentication also requires the instance's proof.

```typescript signature
verifyClientAttestation(jwt: string, options: ClientAttestationVerificationOptions): Promise<Result<VerifiedClientAttestation, ClientAttestationError>>;
```

