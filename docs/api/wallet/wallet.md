# Wallet federation operations

Use these public roles and contracts for participant trust, Wallet Attestations, and federation-backed request checks. The host's OpenID4VCI/OpenID4VP engine owns exchanges, sessions, consent, credential selection, and format processing. Keep the original prepared-request handle until completion.

Operational methods return core `Result` values, inspected through `ok`, `value`, and `error`. Metadata parsers return Zod results, inspected through `success`, `data`, and `error.issues`. Constructors, initialization, publication hooks, and missing instance-anchor configuration can throw. Signatures below use public types from `@oidfed/core`, this package, and the `z` namespace from `zod`; package-private schema objects are not required. Static attestation helpers alias the linked core functions.

## Build wallet client attestation headers

Use Core to sign the wallet instance’s proof and build the pair of attestation headers.

<!-- oidfed-example -->
```typescript
import type { CryptoEngine, KeyringEntry } from "@oidfed/crypto";
import { clientAttestationHeaders, createClientAttestationProof } from "@oidfed/core";

async function walletHeaders(
  engine: CryptoEngine,
  attestationJwt: string,
  clientId: string,
  authorizationServer: string,
  instanceSigner: KeyringEntry,
) {
  const proof = await createClientAttestationProof(
    { clientId, audience: authorizationServer }, instanceSigner,
    { engine },
  );
  if (!proof.ok) return proof;
  return clientAttestationHeaders(attestationJwt, proof.value);
}
// Each invocation creates a new proof. The host sends the returned headers.
```

## `AttestationVerificationOptions`

[Source](../../../packages/wallet/src/roles.ts)

Trust options and the host verifier for an alternative Wallet Provider attestation format. The callback receives trusted evidence and protocol keys; the library does not infer how to verify an opaque format.

```typescript signature
interface AttestationVerificationOptions extends WalletTrustOptions {
	/** Verify the attestation with the supplied keys and apply format-specific checks before accepting it. */
	readonly verifyAttestation: (
		context: { attestation: unknown; provider: TrustedWalletEntity; keys: JWKSet },
		signal?: AbortSignal,
	) => boolean | Promise<boolean>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `verifyAttestation` | `( context: { attestation: unknown; provider: TrustedWalletEntity; keys: JWKSet }, signal?: AbortSignal, ) => boolean \| Promise<boolean>` | Required host verifier for an alternative attestation format. Receives the opaque attestation, trusted provider evidence, resolved protocol keys, and an abort signal; only true accepts. |
| `trustAnchors?` | `TrustAnchorSet` | Pinned local anchors. Instance precedence is per-call trustAnchors, config.trustAnchors, config.options.trustAnchors, then host anchors. Static discovery and verification take their anchors argument explicitly. |
| `trustChain?` | `readonly string[]` | Raw JWT chain for the target, validated before acceptance. For signing, use this field explicitly to attach a chain and supply pinned anchors. |
| `entityChains?` | `ReadonlyMap<string, readonly string[]>` | Additional raw chains keyed by exact subject identifier, for offline or pre-supplied discovery. Explicit trustChain takes precedence. |
| `offline?` | `boolean` | Block library transport and require supplied chains. Multi-hop validation may also need intermediate ECs from entityConfigurations or a preloaded cache; protocol verification requires inline effective keys. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Authenticated issuer key sets keyed by Entity Identifier, forwarded to Trust Mark checks during trust-chain validation. The host is responsible for their provenance. |
| `trustResolution?` | `TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
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

## `AuthenticateWalletOptions`

[Source](../../../packages/wallet/src/attestation.ts)

Wallet authentication policy for a JWT attestation/PoP pair. audience and acceptWallet are required. Choose an explicit replay policy or the bound replay storage; freshness defaults to an iat window of 300 seconds when neither freshness nor maxProofAgeSeconds overrides it. See the [core authentication contracts](../core/authentication.md#authenticateclientattestationoptions) for challenge and replay modes.

```typescript signature
interface AuthenticateWalletOptions
	extends WalletTrustOptions,
		Omit<
			AuthenticateClientAttestationOptions,
			"getAttester" | "acceptClient" | keyof WalletTrustOptions
		> {
	readonly acceptWallet: (
		verified: VerifiedWalletAttestation,
		signal?: AbortSignal,
	) => boolean | Promise<boolean>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `acceptWallet` | `( verified: VerifiedWalletAttestation, signal?: AbortSignal, ) => boolean \| Promise<boolean>` | Required host acceptance callback, called after attestation and PoP checks with copied provider evidence. Only true accepts; a throw, rejection, timeout, or cancellation fails the operation. |
| `trustAnchors?` | `TrustAnchorSet` | Pinned local anchors. Instance precedence is per-call trustAnchors, config.trustAnchors, config.options.trustAnchors, then host anchors. Static discovery and verification take their anchors argument explicitly. |
| `trustChain?` | `readonly string[]` | Raw JWT chain for the target, validated before acceptance. For signing, use this field explicitly to attach a chain and supply pinned anchors. |
| `entityChains?` | `ReadonlyMap<string, readonly string[]>` | Additional raw chains keyed by exact subject identifier, for offline or pre-supplied discovery. Explicit trustChain takes precedence. |
| `offline?` | `boolean` | Block library transport and require supplied chains. Multi-hop validation may also need intermediate ECs from entityConfigurations or a preloaded cache; protocol verification requires inline effective keys. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Authenticated issuer key sets keyed by Entity Identifier, forwarded to Trust Mark checks during trust-chain validation. The host is responsible for their provenance. |
| `trustResolution?` | `TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
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
| `audience` | `string` | Expected AS receiver issuer identifier for the PoP aud claim and any attestation aud. Must be a valid HTTPS Entity Identifier without query or fragment. |
| `freshness?` | `ClientAttestationFreshness` | PoP freshness policy: maximum age from its iat, or a host-verified challenge validity interval. Separate from replay policy; do not combine with maxProofAgeSeconds. |
| `clientId?` | `string` | Optional expected Wallet Instance identifier. The PoP iss must equal this value when supplied and always equals the Wallet Attestation sub. |
| `allowedAttestationAlgorithms?` | `readonly string[]` | Attestation signing algorithms. An explicit general protocol allowlist further restricts this list. |
| `allowedProofAlgorithms?` | `readonly string[]` | Proof-of-possession signing algorithms. An explicit general protocol allowlist further restricts this list. |
| `expectedChallenge?` | `string` | Challenge value the verifier expects to see in the proof. |
| `maxProofAgeSeconds?` | `number` | Positive, finite PoP iat-age window in seconds, default 300. Shorthand alternative to freshness; do not configure both. |
| `replay?` | `ClientAttestationReplay` | Explicit PoP replay policy: atomic jti storage, challenge consumption, or an intentional freshness-only choice. Supply this or storage.replay. |

## `AuthorizationRequestContext`

[Source](../../../packages/wallet/src/authorization-request.ts)

Context known after the host retrieves a Request Object: the expected wallet nonce and application mapping for its signed scope. It does not fetch the JWT or establish a new verifier identity.

```typescript signature
interface AuthorizationRequestContext {
	readonly walletNonce?: string;
	/** Query resolved by the application's configured mapping for the signed scope. */
	readonly scopeQuery?: DcqlQuery;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `walletNonce?` | `string` | Expected wallet_nonce in the signed Request Object; creation inserts this value when provided. Completion rejects a different value supplied in its context. |
| `scopeQuery?` | `DcqlQuery` | Application-resolved DCQL query for the signed scope. Used locally without replacing the signed scope; a validated immediate-Superior query override takes priority. |

## `AuthorizationRequestCreationOptions`

[Source](../../../packages/wallet/src/authorization-request.ts)

Request Object creation settings, including an optional application mapping for a signed scope. scopeQuery is local validation input and is not serialized into the JWT. The supplied request must already carry the protocol fields and any desired date claims.

```typescript signature
interface AuthorizationRequestCreationOptions extends AuthorizationRequestOptions {
	/**
	 * Application mapping for the signed scope. Required for transaction validation
	 * when scope selects the query and a validated superior override supplies none.
	 * Used locally; the Request Object retains its original scope parameter.
	 */
	readonly scopeQuery?: DcqlQuery;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `scopeQuery?` | `DcqlQuery` | Application-resolved DCQL query for the signed scope. Used locally without replacing the signed scope; a validated immediate-Superior query override takes priority. |
| `walletIssuer?` | `string` | Wallet metadata issuer used as the Request Object audience. Defaults to https://self-issued.me/v2; this option does not retrieve Wallet metadata. |
| `walletNonce?` | `string` | Expected wallet_nonce in the signed Request Object; creation inserts this value when provided. Completion rejects a different value supplied in its context. |
| `maxRequestAgeSeconds?` | `number` | Optional positive, finite Request Object age limit in seconds. Requires an applicable iat and uses clock skew during verification. No maximum age is imposed by default. |
| `queryPolicy?` | `( context: { queries: readonly DcqlQuery[]; request: Readonly<Record<string, unknown>>; chain: ValidatedTrustChain; }, signal?: AbortSignal, ) => boolean \| Promise<boolean>` | Optional host matching or refinement policy for effective queries and the sanitized request after federation and transaction checks. Only true accepts; failures, timeouts, and cancellation reject. |
| `verifyTransactionData?` | `( context: { data: readonly Record<string, unknown>[]; queries: readonly DcqlQuery[] }, signal?: AbortSignal, ) => boolean \| Promise<boolean>` | Required when completing a request containing transaction_data. Receives decoded transaction entries and active queries after applicable Superior overrides; the host approves transaction types and contents. Creation checks structure without invoking this callback. |
| `trustAnchors?` | `TrustAnchorSet` | Pinned local anchors. Instance precedence is per-call trustAnchors, config.trustAnchors, config.options.trustAnchors, then host anchors. Static discovery and verification take their anchors argument explicitly. |
| `trustChain?` | `readonly string[]` | Raw JWT chain for the target, validated before acceptance. For signing, use this field explicitly to attach a chain and supply pinned anchors. |
| `entityChains?` | `ReadonlyMap<string, readonly string[]>` | Additional raw chains keyed by exact subject identifier, for offline or pre-supplied discovery. Explicit trustChain takes precedence. |
| `offline?` | `boolean` | Block library transport and require supplied chains. Multi-hop validation may also need intermediate ECs from entityConfigurations or a preloaded cache; protocol verification requires inline effective keys. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Authenticated issuer key sets keyed by Entity Identifier, forwarded to Trust Mark checks during trust-chain validation. The host is responsible for their provenance. |
| `trustResolution?` | `TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
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

## `AuthorizationRequestOptions`

[Source](../../../packages/wallet/src/authorization-request.ts)

Shared federation and local validation inputs for preparing/completing Request Objects. Audience, nonce, freshness, optional query matching, and transaction approval are local policy. The host owns Request URI GET/POST transport and the OpenID4VP exchange.

```typescript signature
interface AuthorizationRequestOptions extends WalletTrustOptions {
	/** Wallet metadata issuer when dynamic discovery is used; absent means static discovery. */
	readonly walletIssuer?: string;
	readonly walletNonce?: string;
	/** Optional local freshness policy; requires iat when configured. */
	readonly maxRequestAgeSeconds?: number;
	/**
	 * Apply framework matching or refinement rules to the active request and effective queries.
	 * Wallet §6.3.1 leaves this profile choice open; contextual policy input alone
	 * does not authorize a different active query.
	 */
	readonly queryPolicy?: (
		context: {
			queries: readonly DcqlQuery[];
			request: Readonly<Record<string, unknown>>;
			chain: ValidatedTrustChain;
		},
		signal?: AbortSignal,
	) => boolean | Promise<boolean>;
	/**
	 * Approve transaction types and contents after request-level checks pass.
	 * Receives decoded data and active queries after any superior metadata override.
	 * Invoked during completion; the protocol engine handles presentation verification.
	 */
	readonly verifyTransactionData?: (
		context: { data: readonly Record<string, unknown>[]; queries: readonly DcqlQuery[] },
		signal?: AbortSignal,
	) => boolean | Promise<boolean>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `walletIssuer?` | `string` | Wallet metadata issuer used as the Request Object audience. Defaults to https://self-issued.me/v2; this option does not retrieve Wallet metadata. |
| `walletNonce?` | `string` | Expected wallet_nonce in the signed Request Object; creation inserts this value when provided. Completion rejects a different value supplied in its context. |
| `maxRequestAgeSeconds?` | `number` | Optional positive, finite Request Object age limit in seconds. Requires an applicable iat and uses clock skew during verification. No maximum age is imposed by default. |
| `queryPolicy?` | `( context: { queries: readonly DcqlQuery[]; request: Readonly<Record<string, unknown>>; chain: ValidatedTrustChain; }, signal?: AbortSignal, ) => boolean \| Promise<boolean>` | Optional host matching or refinement policy for effective queries and the sanitized request after federation and transaction checks. Only true accepts; failures, timeouts, and cancellation reject. |
| `verifyTransactionData?` | `( context: { data: readonly Record<string, unknown>[]; queries: readonly DcqlQuery[] }, signal?: AbortSignal, ) => boolean \| Promise<boolean>` | Required when completing a request containing transaction_data. Receives decoded transaction entries and active queries after applicable Superior overrides; the host approves transaction types and contents. Creation checks structure without invoking this callback. |
| `trustAnchors?` | `TrustAnchorSet` | Pinned local anchors. Instance precedence is per-call trustAnchors, config.trustAnchors, config.options.trustAnchors, then host anchors. Static discovery and verification take their anchors argument explicitly. |
| `trustChain?` | `readonly string[]` | Raw JWT chain for the target, validated before acceptance. For signing, use this field explicitly to attach a chain and supply pinned anchors. |
| `entityChains?` | `ReadonlyMap<string, readonly string[]>` | Additional raw chains keyed by exact subject identifier, for offline or pre-supplied discovery. Explicit trustChain takes precedence. |
| `offline?` | `boolean` | Block library transport and require supplied chains. Multi-hop validation may also need intermediate ECs from entityConfigurations or a preloaded cache; protocol verification requires inline effective keys. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Authenticated issuer key sets keyed by Entity Identifier, forwarded to Trust Mark checks during trust-chain validation. The host is responsible for their provenance. |
| `trustResolution?` | `TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
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

## `CredentialIssuerDiscoveryOptions`

[Source](../../../packages/wallet/src/roles.ts)

Trust and authorization-server discovery settings for a Credential Issuer.

```typescript signature
interface CredentialIssuerDiscoveryOptions extends WalletTrustOptions {
	/** VCI §12.2.4 permits server selection; all preserves strict discovery. */
	readonly authorizationServerPolicy?: "all" | "available";
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `authorizationServerPolicy?` | `"all" \| "available"` | Default all requires every listed AS to validate. available records individual failures and keeps usable servers; at least one must remain. Cancellation and an exhausted shared fetch budget still fail. |
| `trustAnchors?` | `TrustAnchorSet` | Pinned local anchors. Instance precedence is per-call trustAnchors, config.trustAnchors, config.options.trustAnchors, then host anchors. Static discovery and verification take their anchors argument explicitly. |
| `trustChain?` | `readonly string[]` | Raw JWT chain for the target, validated before acceptance. For signing, use this field explicitly to attach a chain and supply pinned anchors. |
| `entityChains?` | `ReadonlyMap<string, readonly string[]>` | Additional raw chains keyed by exact subject identifier, for offline or pre-supplied discovery. Explicit trustChain takes precedence. |
| `offline?` | `boolean` | Block library transport and require supplied chains. Multi-hop validation may also need intermediate ECs from entityConfigurations or a preloaded cache; protocol verification requires inline effective keys. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Authenticated issuer key sets keyed by Entity Identifier, forwarded to Trust Mark checks during trust-chain validation. The host is responsible for their provenance. |
| `trustResolution?` | `TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
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

## `CredentialIssuerMetadata`

[Source](../../../packages/wallet/src/metadata.ts)

Effective Credential Issuer metadata output type. CredentialIssuerRole.parseMetadata checks supplied values, nested format rules, encryption relationships, and required top-level fields. Standalone parsing does not bind credential_issuer to a known federation subject; discovery and publication hooks add that check. Unknown extensions are preserved.

<details>
<summary>Type declaration</summary>

```typescript signature
type CredentialIssuerMetadata = {
	[key: string]: unknown;
	credential_issuer: string;
	credential_endpoint: string;
	credential_configurations_supported: Record<string, {
		[key: string]: unknown;
		format: string;
		scope?: undefined | string;
		credential_signing_alg_values_supported?: undefined | Array<string | number>;
		cryptographic_binding_methods_supported?: undefined | Array<string>;
		proof_types_supported?: undefined | Record<string, {
			[key: string]: unknown;
			proof_signing_alg_values_supported: Array<string | number>;
			key_attestations_required?: undefined | {
				[key: string]: unknown;
				key_storage?: undefined | Array<string>;
				user_authentication?: undefined | Array<string>;
			};
		}>;
		credential_metadata?: undefined | {
			[key: string]: unknown;
			display?: undefined | Array<{
				[key: string]: unknown;
				name: string;
				locale?: undefined | string;
				logo?: undefined | {
					[key: string]: unknown;
					uri: string;
					alt_text?: undefined | string;
				};
				description?: undefined | string;
				background_color?: undefined | string;
				text_color?: undefined | string;
				background_image?: undefined | {
					[key: string]: unknown;
					uri: string;
				};
			}>;
			claims?: undefined | Array<{
				[key: string]: unknown;
				path: Array<null | string | number>;
				mandatory?: undefined | boolean;
				display?: undefined | Array<{
					[key: string]: unknown;
					name?: undefined | string;
					locale?: undefined | string;
				}>;
			}>;
		};
	}>;
	jwks?: undefined | {
		keys: Array<JWK>;
	};
	jwks_uri?: undefined | string;
	signed_jwks_uri?: undefined | string;
	authorization_servers?: undefined | Array<string>;
	nonce_endpoint?: undefined | string;
	deferred_credential_endpoint?: undefined | string;
	notification_endpoint?: undefined | string;
	credential_request_encryption?: undefined | {
		[key: string]: unknown;
		jwks: JWKSet;
		enc_values_supported: Array<string>;
		encryption_required: boolean;
		zip_values_supported?: undefined | Array<string>;
	};
	credential_response_encryption?: undefined | {
		[key: string]: unknown;
		alg_values_supported: Array<string>;
		enc_values_supported: Array<string>;
		encryption_required: boolean;
		zip_values_supported?: undefined | Array<string>;
	};
	batch_credential_issuance?: undefined | {
		[key: string]: unknown;
		batch_size: number;
	};
	display?: undefined | Array<{
		[key: string]: unknown;
		name?: undefined | string;
		locale?: undefined | string;
		logo?: undefined | {
			[key: string]: unknown;
			uri: string;
			alt_text?: undefined | string;
		};
	}>;
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `credential_issuer` | `string` | HTTPS Credential Issuer identifier without query, fragment, or userinfo. Federation-aware use binds it to the statement subject and requested Entity Identifier. |
| `credential_endpoint` | `string` | HTTPS credential issuance endpoint without userinfo; the host OpenID4VCI engine performs issuance. |
| `credential_configurations_supported` | `Record<string, { [key: string]: unknown; format: string; scope?: undefined \| string; credential_signing_alg_values_supported?: undefined \| Array<string \| number>; cryptographic_binding_methods_supported?: undefined \| Array<string>; proof_types_supported?: undefined \| Record<string, { [key: string]: unknown; proof_signing_alg_values_supported: Array<string \| number>; key_attestations_required?: undefined \| { [key: string]: unknown; key_storage?: undefined \| Array<string>; user_authentication?: undefined \| Array<string>; }; }>; credential_metadata?: undefined \| { [key: string]: unknown; display?: undefined \| Array<{ [key: string]: unknown; name: string; locale?: undefined \| string; logo?: undefined \| { [key: string]: unknown; uri: string; alt_text?: undefined \| string; }; description?: undefined \| string; background_color?: undefined \| string; text_color?: undefined \| string; background_image?: undefined \| { [key: string]: unknown; uri: string; }; }>; claims?: undefined \| Array<{ [key: string]: unknown; path: Array<null \| string \| number>; mandatory?: undefined \| boolean; display?: undefined \| Array<{ [key: string]: unknown; name?: undefined \| string; locale?: undefined \| string; }>; }>; }; }>` | Configuration identifier to supported credential format, scope, proof/binding capabilities, and display/claim metadata. Recognized formats receive additional runtime validation; unknown extensions are preserved. |
| `jwks?` | `undefined \| { keys: Array<JWK>; }` | Inline public protocol keys; `kid` is optional. Effective inline keys take precedence during wallet verification. These are separate from Federation Entity Keys. |
| `jwks_uri?` | `undefined \| string` | HTTPS source of public protocol keys, without userinfo. Offline verification needs the effective inline jwks instead. |
| `signed_jwks_uri?` | `undefined \| string` | HTTPS source of a signed protocol key set, authenticated with Federation Entity Keys. Offline verification needs effective inline keys. |
| `authorization_servers?` | `undefined \| Array<string>` | Optional nonempty list of AS issuer identifiers. Discovery defaults to the Credential Issuer itself when this field is absent. |
| `nonce_endpoint?` | `undefined \| string` | Optional HTTPS endpoint for credential-proof nonce retrieval; the host protocol engine calls it. |
| `deferred_credential_endpoint?` | `undefined \| string` | Optional HTTPS deferred issuance endpoint; the host protocol engine manages polling and responses. |
| `notification_endpoint?` | `undefined \| string` | Optional HTTPS issuance notification endpoint, used by the host protocol engine. |
| `credential_request_encryption?` | `undefined \| { [key: string]: unknown; jwks: JWKSet; enc_values_supported: Array<string>; encryption_required: boolean; zip_values_supported?: undefined \| Array<string>; }` | Request encryption capabilities. The `jwks` set must be nonempty, with unique, nonempty `kid` values. Effective metadata also requires an alg-bearing encryption/key-agreement key; the host performs encryption. |
| `credential_response_encryption?` | `undefined \| { [key: string]: unknown; alg_values_supported: Array<string>; enc_values_supported: Array<string>; encryption_required: boolean; zip_values_supported?: undefined \| Array<string>; }` | Response encryption algorithms, methods, optional compression, and requirement flag. Required response encryption also requires request encryption metadata. |
| `batch_credential_issuance?` | `undefined \| { [key: string]: unknown; batch_size: number; }` | Optional batch capability with integer batch_size of at least two; the host protocol engine implements batching. |
| `display?` | `undefined \| Array<{ [key: string]: unknown; name?: undefined \| string; locale?: undefined \| string; logo?: undefined \| { [key: string]: unknown; uri: string; alt_text?: undefined \| string; }; }>` | Optional nonempty issuer display list, with valid, case-insensitively unique locale tags when supplied. |

## `CredentialIssuerPublicationMetadata`

[Source](../../../packages/wallet/src/metadata.ts)

Partial top-level Credential Issuer publication metadata. Missing requirements may be completed by a Superior. Supplied nested configuration, key, and format metadata still receive structural and applicable relationship checks; effective encryption relationships run after completion.

<details>
<summary>Type declaration</summary>

```typescript signature
type CredentialIssuerPublicationMetadata = {
	[key: string]: unknown;
	jwks?: undefined | {
		keys: Array<JWK>;
	};
	jwks_uri?: undefined | string;
	signed_jwks_uri?: undefined | string;
	credential_issuer?: undefined | string;
	authorization_servers?: undefined | Array<string>;
	credential_endpoint?: undefined | string;
	nonce_endpoint?: undefined | string;
	deferred_credential_endpoint?: undefined | string;
	notification_endpoint?: undefined | string;
	credential_request_encryption?: undefined | {
		[key: string]: unknown;
		jwks: JWKSet;
		enc_values_supported: Array<string>;
		encryption_required: boolean;
		zip_values_supported?: undefined | Array<string>;
	};
	credential_response_encryption?: undefined | {
		[key: string]: unknown;
		alg_values_supported: Array<string>;
		enc_values_supported: Array<string>;
		encryption_required: boolean;
		zip_values_supported?: undefined | Array<string>;
	};
	batch_credential_issuance?: undefined | {
		[key: string]: unknown;
		batch_size: number;
	};
	display?: undefined | Array<{
		[key: string]: unknown;
		name?: undefined | string;
		locale?: undefined | string;
		logo?: undefined | {
			[key: string]: unknown;
			uri: string;
			alt_text?: undefined | string;
		};
	}>;
	credential_configurations_supported?: undefined | Record<string, {
		[key: string]: unknown;
		format: string;
		scope?: undefined | string;
		credential_signing_alg_values_supported?: undefined | Array<string | number>;
		cryptographic_binding_methods_supported?: undefined | Array<string>;
		proof_types_supported?: undefined | Record<string, {
			[key: string]: unknown;
			proof_signing_alg_values_supported: Array<string | number>;
			key_attestations_required?: undefined | {
				[key: string]: unknown;
				key_storage?: undefined | Array<string>;
				user_authentication?: undefined | Array<string>;
			};
		}>;
		credential_metadata?: undefined | {
			[key: string]: unknown;
			display?: undefined | Array<{
				[key: string]: unknown;
				name: string;
				locale?: undefined | string;
				logo?: undefined | {
					[key: string]: unknown;
					uri: string;
					alt_text?: undefined | string;
				};
				description?: undefined | string;
				background_color?: undefined | string;
				text_color?: undefined | string;
				background_image?: undefined | {
					[key: string]: unknown;
					uri: string;
				};
			}>;
			claims?: undefined | Array<{
				[key: string]: unknown;
				path: Array<null | string | number>;
				mandatory?: undefined | boolean;
				display?: undefined | Array<{
					[key: string]: unknown;
					name?: undefined | string;
					locale?: undefined | string;
				}>;
			}>;
		};
	}>;
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `jwks?` | `undefined \| { keys: Array<JWK>; }` | Inline public protocol keys; `kid` is optional. Effective inline keys take precedence during wallet verification. These are separate from Federation Entity Keys. |
| `jwks_uri?` | `undefined \| string` | HTTPS source of public protocol keys, without userinfo. Offline verification needs the effective inline jwks instead. |
| `signed_jwks_uri?` | `undefined \| string` | HTTPS source of a signed protocol key set, authenticated with Federation Entity Keys. Offline verification needs effective inline keys. |
| `credential_issuer?` | `undefined \| string` | HTTPS Credential Issuer identifier without query, fragment, or userinfo. Federation-aware use binds it to the statement subject and requested Entity Identifier. |
| `authorization_servers?` | `undefined \| Array<string>` | Optional nonempty list of AS issuer identifiers. Discovery defaults to the Credential Issuer itself when this field is absent. |
| `credential_endpoint?` | `undefined \| string` | HTTPS credential issuance endpoint without userinfo; the host OpenID4VCI engine performs issuance. |
| `nonce_endpoint?` | `undefined \| string` | Optional HTTPS endpoint for credential-proof nonce retrieval; the host protocol engine calls it. |
| `deferred_credential_endpoint?` | `undefined \| string` | Optional HTTPS deferred issuance endpoint; the host protocol engine manages polling and responses. |
| `notification_endpoint?` | `undefined \| string` | Optional HTTPS issuance notification endpoint, used by the host protocol engine. |
| `credential_request_encryption?` | `undefined \| { [key: string]: unknown; jwks: JWKSet; enc_values_supported: Array<string>; encryption_required: boolean; zip_values_supported?: undefined \| Array<string>; }` | Request encryption capabilities. The `jwks` set must be nonempty, with unique, nonempty `kid` values. Effective metadata also requires an alg-bearing encryption/key-agreement key; the host performs encryption. |
| `credential_response_encryption?` | `undefined \| { [key: string]: unknown; alg_values_supported: Array<string>; enc_values_supported: Array<string>; encryption_required: boolean; zip_values_supported?: undefined \| Array<string>; }` | Response encryption algorithms, methods, optional compression, and requirement flag. Required response encryption also requires request encryption metadata. |
| `batch_credential_issuance?` | `undefined \| { [key: string]: unknown; batch_size: number; }` | Optional batch capability with integer batch_size of at least two; the host protocol engine implements batching. |
| `display?` | `undefined \| Array<{ [key: string]: unknown; name?: undefined \| string; locale?: undefined \| string; logo?: undefined \| { [key: string]: unknown; uri: string; alt_text?: undefined \| string; }; }>` | Optional nonempty issuer display list, with valid, case-insensitively unique locale tags when supplied. |
| `credential_configurations_supported?` | `undefined \| Record<string, { [key: string]: unknown; format: string; scope?: undefined \| string; credential_signing_alg_values_supported?: undefined \| Array<string \| number>; cryptographic_binding_methods_supported?: undefined \| Array<string>; proof_types_supported?: undefined \| Record<string, { [key: string]: unknown; proof_signing_alg_values_supported: Array<string \| number>; key_attestations_required?: undefined \| { [key: string]: unknown; key_storage?: undefined \| Array<string>; user_authentication?: undefined \| Array<string>; }; }>; credential_metadata?: undefined \| { [key: string]: unknown; display?: undefined \| Array<{ [key: string]: unknown; name: string; locale?: undefined \| string; logo?: undefined \| { [key: string]: unknown; uri: string; alt_text?: undefined \| string; }; description?: undefined \| string; background_color?: undefined \| string; text_color?: undefined \| string; background_image?: undefined \| { [key: string]: unknown; uri: string; }; }>; claims?: undefined \| Array<{ [key: string]: unknown; path: Array<null \| string \| number>; mandatory?: undefined \| boolean; display?: undefined \| Array<{ [key: string]: unknown; name?: undefined \| string; locale?: undefined \| string; }>; }>; }; }>` | Configuration identifier to supported credential format, scope, proof/binding capabilities, and display/claim metadata. Recognized formats receive additional runtime validation; unknown extensions are preserved. |

## `CredentialIssuerRole`

[Source](../../../packages/wallet/src/roles.ts)

Role for `openid_credential_issuer` publication, trusted issuer/AS discovery, and Wallet Attestation verification or authentication. Its inherited attestation consumers do not issue credentials; the host OpenID4VCI engine owns issuance and protocol endpoints. Construction deep-copies initial metadata without validating it. An attached Leaf or Authority invokes the publication hook; use the static parsers for independent validation. Only instance operations needing a signing identity require initialization; discovery/verification can run with configured anchors before attachment.

```typescript signature
new CredentialIssuerRole(config?: WalletRoleConfig): CredentialIssuerRole;
```

### `CredentialIssuerRole#type`

The literal Entity Type Identifier for CredentialIssuerRole, used by host composition and metadata validation.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
readonly type: "openid_credential_issuer";
```

### `CredentialIssuerRole#discover`

Establish issuer federation trust and validate complete Credential Issuer metadata, then discover the declared AS entities (or the co-located AS if absent). Every accepted AS uses validated OpenID4VCI-profile AS metadata and an exact issuer binding. Default all fails on any AS failure; available records failures but still requires a usable AS and necessary openid_credential authorization-details support for scopeless configurations. Results share one fetch budget and carry separate chain expirations. Instance options merge host, role, then per-call values. Pinned anchors are selected from per-call, role config, role options, then host; missing anchors throw before returning a Result.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
discover(id: string, options?: BoundFederationOptions<CredentialIssuerDiscoveryOptions>): Promise<Result<DiscoveredCredentialIssuer>>;
```

### `CredentialIssuerRole#verifyWalletAttestation`

Establish the signing Wallet Provider's federation trust, resolve its protocol keys, and verify the JWT attestation signature, type, claims, times, and any supplied audience binding. Returns the attestation claims and provider evidence. This does not verify instance-key possession or call a host wallet-acceptance policy; use authenticateWallet for that. Instance options merge host, role, then per-call values. Pinned anchors are selected from per-call, role config, role options, then host; missing anchors throw before returning a Result.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
verifyWalletAttestation(jwt: string, options?: BoundFederationOptions<WalletAttestationVerificationOptions>): Promise<Result<VerifiedWalletAttestation, ClientAttestationError>>;
```

### `CredentialIssuerRole#authenticateWallet`

Verify the Wallet Attestation and its instance-signed PoP, including receiver binding, configured freshness, replay policy, and required acceptWallet callback. JTI mode uses the receiver’s replay storage. Challenge consumption and freshness-only are explicit policies. Configure either freshness or maxProofAgeSeconds. Returns a Federation Result with ClientAttestationError on failure. The host enforces its own wallet acceptance policy and protocol HTTP error response. Instance options merge host, role, then per-call values. Pinned anchors are selected from per-call, role config, role options, then host; missing anchors throw before returning a Result.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
authenticateWallet(attestation: string, proof: string, options: BoundFederationOptions<AuthenticateWalletOptions>): Promise<Result<VerifiedWalletAttestation, ClientAttestationError>>;
```

### `CredentialIssuerRole#verifyProviderAttestation`

Establish provider federation trust and resolve provider protocol keys, then call the required verifyAttestation callback with copied input/evidence and a bounded abort signal. Only true accepts; throws, rejection, timeout, or cancellation produce a failed Result. The callback owns format-specific cryptographic verification. Success returns current provider evidence, not a parsed attestation. Instance options merge host, role, then per-call values. Pinned anchors are selected from per-call, role config, role options, then host; missing anchors throw before returning a Result.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
verifyProviderAttestation(attestation: unknown, providerId: string, options: BoundFederationOptions<AttestationVerificationOptions>): Promise<Result<TrustedWalletEntity>>;
```

### `CredentialIssuerRole#assessEntity`

Assess target under bottom-up validation or an explicitly configured trusted-resolver mode, then validate effective metadata for the supplied wallet Entity Type. This type argument is explicit even on a concrete role. Accreditation issuers need not publish the target's protocol metadata. Returns a core EntityAssessment Result; no Request Object, attestation, or credential is verified by this call. Instance options merge host, role, then per-call values. Pinned anchors are selected from per-call, role config, role options, then host; missing anchors throw before returning a Result.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
assessEntity(target: string, type: WalletRoleType, options?: Omit<EntityAssessmentOptions & WalletTrustOptions, "engine">): Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```

### `CredentialIssuerRole#metadata`

Mutable role metadata record deep-copied from config.metadata at construction. The readonly property prevents reassignment, not edits to the record. Leaf and Authority snapshot this block during host composition and invoke validateMetadata. Later edits to the role or its original input do not update the host's published metadata.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
readonly metadata: Record<string, unknown>;
```

### `CredentialIssuerRole#config`

The original configuration object, retained by reference. Metadata has a separate deep copy; options and anchor collections are not deeply snapshotted by construction. A readonly property does not freeze the referenced configuration.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
readonly config: WalletRoleConfig;
```

### `CredentialIssuerRole#initialize`

Bind the role to an EntityContext. Hosts call this during composition. Reusing the same context is allowed; rebinding the role to a different context throws. This method does not itself validate metadata.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
initialize(context: EntityContext): void;
```

### `CredentialIssuerRole#validateMetadata`

Validate a composed publication block with the matching partial schema. Missing top-level requirements may be completed by a Superior; supplied values and nested requirements are checked. Credential Issuer credential_issuer, when supplied, must equal context.entityId. Invalid metadata throws TypeError.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
validateMetadata(metadata: Readonly<Record<string, unknown>>, context: EntityContext): void;
```

### `CredentialIssuerRole.parseMetadata`

Validate completed effective metadata and return a Zod safe-parse result: success/data or success: false/error.issues. Unknown extension fields are preserved. Parsing establishes no federation trust; for Credential Issuers, standalone parsing does not bind credential_issuer to an independently known Entity Identifier.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
static parseMetadata(metadata: unknown, options?: MetadataValidationOptions): z.ZodSafeParseResult<CredentialIssuerMetadata>;
```

### `CredentialIssuerRole.parsePublicationMetadata`

Validate supplied publication fields while permitting a Superior to complete missing top-level requirements. Supplied nested objects still receive their full checks. Returns a Zod safe-parse result, not a Federation Result, and establishes no trust.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
static parsePublicationMetadata(metadata: unknown, options?: MetadataValidationOptions): z.ZodSafeParseResult<CredentialIssuerPublicationMetadata>;
```

### `CredentialIssuerRole.discover`

Establish issuer federation trust and validate complete Credential Issuer metadata, then discover the declared AS entities (or the co-located AS if absent). Every accepted AS uses validated OpenID4VCI-profile AS metadata and an exact issuer binding. Default all fails on any AS failure; available records failures but still requires a usable AS and necessary openid_credential authorization-details support for scopeless configurations. Results share one fetch budget and carry separate chain expirations.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
static discover(id: string, anchors: TrustAnchorSet, options: CredentialIssuerDiscoveryOptions): Promise<Result<DiscoveredCredentialIssuer>>;
```

Example:

<!-- oidfed-example -->
```typescript
import type { CryptoEngine } from "@oidfed/crypto";
import type { TrustAnchorSet } from "@oidfed/core";
import { CredentialIssuerRole } from "@oidfed/wallet";

async function discoverIssuer(engine: CryptoEngine, id: string, anchors: TrustAnchorSet) {
  const result = await CredentialIssuerRole.discover(id, anchors, {
    engine,
    authorizationServerPolicy: "available",
  });
  if (!result.ok) return result;
  for (const server of result.value.authorizationServers) {
    console.info(server.entityId, server.metadata.token_endpoint);
  }
  return result; // Inspect authorizationServerErrors for skipped servers.
}
```

### `CredentialIssuerRole.verifyProviderAttestation`

Establish provider federation trust and resolve provider protocol keys, then call the required verifyAttestation callback with copied input/evidence and a bounded abort signal. Only true accepts; throws, rejection, timeout, or cancellation produce a failed Result. The callback owns format-specific cryptographic verification. Success returns current provider evidence, not a parsed attestation.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
static verifyProviderAttestation(attestation: unknown, providerId: string, anchors: TrustAnchorSet, options: AttestationVerificationOptions): Promise<Result<TrustedWalletEntity>>;
```

### `CredentialIssuerRole.verifyWalletAttestation`

Establish the signing Wallet Provider's federation trust, resolve its protocol keys, and verify the JWT attestation signature, type, claims, times, and any supplied audience binding. Returns the attestation claims and provider evidence. This does not verify instance-key possession or call a host wallet-acceptance policy; use authenticateWallet for that.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
CredentialIssuerRole.verifyWalletAttestation(jwt: string, anchors: TrustAnchorSet, options: WalletAttestationVerificationOptions): Promise<Result<VerifiedWalletAttestation, ClientAttestationError>>;
```

### `CredentialIssuerRole.authenticateWallet`

Verify the Wallet Attestation and its instance-signed PoP, including receiver binding, configured freshness, replay policy, and required acceptWallet callback. JTI mode uses the receiver’s replay storage. Challenge consumption and freshness-only are explicit policies. Configure either freshness or maxProofAgeSeconds. Returns a Federation Result with ClientAttestationError on failure. The host enforces its own wallet acceptance policy and protocol HTTP error response.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
CredentialIssuerRole.authenticateWallet(attestation: string, proof: string, anchors: TrustAnchorSet, options: AuthenticateWalletOptions): Promise<Result<VerifiedWalletAttestation, ClientAttestationError>>;
```

Example:

<!-- oidfed-example -->
```typescript
import type { CryptoEngine } from "@oidfed/crypto";
import { MemoryFederationStorage, type TrustAnchorSet } from "@oidfed/core";
import { CredentialIssuerRole, type AuthenticateWalletOptions } from "@oidfed/wallet";

const storage = new MemoryFederationStorage({ namespace: "https://issuer.example", capabilities: ["replay"] });
async function authenticateInstance(
  engine: CryptoEngine,
  attestation: string,
  proof: string,
  anchors: TrustAnchorSet,
  receiverId: string,
  acceptWallet: AuthenticateWalletOptions["acceptWallet"],
) {
  return CredentialIssuerRole.authenticateWallet(attestation, proof, anchors, {
    engine,
    audience: receiverId,
    storage,
    acceptWallet,
  });
}
// A distributed deployment supplies a shared durable ReplayStore instead.
```

### `CredentialIssuerRole.assessEntity`

Assess target under bottom-up validation or an explicitly configured trusted-resolver mode, then validate effective metadata for the supplied wallet Entity Type. This type argument is explicit even on a concrete role. Accreditation issuers need not publish the target's protocol metadata. Returns a core EntityAssessment Result; no Request Object, attestation, or credential is verified by this call.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
CredentialIssuerRole.assessEntity(target: string, type: WalletRoleType, anchors: TrustAnchorSet, options: EntityAssessmentOptions & WalletTrustOptions): Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```

## `CredentialVerificationOptions`

[Source](../../../packages/wallet/src/roles.ts)

Trust inputs and host callbacks used to verify a credential.

```typescript signature
interface CredentialVerificationOptions extends WalletTrustOptions {
	readonly verifyCredential: (
		context: { credential: unknown; issuer: TrustedWalletEntity; keys: JWKSet | undefined },
		signal?: AbortSignal,
	) => boolean | Promise<boolean>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `verifyCredential` | `( context: { credential: unknown; issuer: TrustedWalletEntity; keys: JWKSet \| undefined }, signal?: AbortSignal, ) => boolean \| Promise<boolean>` | Required host verifier for the credential format, proofs, and status. Receives trusted issuer evidence and optional protocol keys; only true accepts. The library does not parse the credential itself. |
| `trustAnchors?` | `TrustAnchorSet` | Pinned local anchors. Instance precedence is per-call trustAnchors, config.trustAnchors, config.options.trustAnchors, then host anchors. Static discovery and verification take their anchors argument explicitly. |
| `trustChain?` | `readonly string[]` | Raw JWT chain for the target, validated before acceptance. For signing, use this field explicitly to attach a chain and supply pinned anchors. |
| `entityChains?` | `ReadonlyMap<string, readonly string[]>` | Additional raw chains keyed by exact subject identifier, for offline or pre-supplied discovery. Explicit trustChain takes precedence. |
| `offline?` | `boolean` | Block library transport and require supplied chains. Multi-hop validation may also need intermediate ECs from entityConfigurations or a preloaded cache; protocol verification requires inline effective keys. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Authenticated issuer key sets keyed by Entity Identifier, forwarded to Trust Mark checks during trust-chain validation. The host is responsible for their provenance. |
| `trustResolution?` | `TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
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

## `CredentialVerifierMetadata`

[Source](../../../packages/wallet/src/metadata.ts)

Effective Credential Verifier metadata. CredentialVerifierRole.parseMetadata validates it without establishing trust. Verifier keys need unique, nonempty kid values. Received repeated claim paths are permitted and normalized during request completion; publication and creation reject repeated paths. Unknown extensions remain available.

<details>
<summary>Type declaration</summary>

```typescript signature
type CredentialVerifierMetadata = {
	[key: string]: unknown;
	vp_formats_supported: Record<string, {
		[key: string]: unknown;
		alg_values?: undefined | Array<string>;
		proof_type_values?: undefined | Array<string>;
		cryptosuite_values?: undefined | Array<string>;
		issuerauth_alg_values?: undefined | Array<string | number>;
		deviceauth_alg_values?: undefined | Array<string | number>;
		"sd-jwt_alg_values"?: undefined | Array<string>;
		"kb-jwt_alg_values"?: undefined | Array<string>;
	}>;
	jwks?: undefined | JWKSet;
	request_uris?: undefined | Array<string>;
	response_uris?: undefined | Array<string>;
	redirect_uris?: undefined | Array<string>;
	dcql_queries?: undefined | Array<DcqlQuery>;
	jwks_uri?: undefined | string;
	signed_jwks_uri?: undefined | string;
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `vp_formats_supported` | `Record<string, { [key: string]: unknown; alg_values?: undefined \| Array<string>; proof_type_values?: undefined \| Array<string>; cryptosuite_values?: undefined \| Array<string>; issuerauth_alg_values?: undefined \| Array<string \| number>; deviceauth_alg_values?: undefined \| Array<string \| number>; "sd-jwt_alg_values"?: undefined \| Array<string>; "kb-jwt_alg_values"?: undefined \| Array<string>; }>` | Format identifier to presentation-verification capabilities. Unknown format identifiers and extension fields are preserved. |
| `jwks?` | `undefined \| JWKSet` | Inline public protocol keys. The set must be nonempty, with unique, nonempty `kid` values. Effective inline keys take precedence during wallet verification. These are separate from Federation Entity Keys. |
| `request_uris?` | `undefined \| Array<string>` | Nonempty list of HTTPS Request Object retrieval URIs. A request_uri must exactly match an entry; retrieval transport belongs to the host. |
| `response_uris?` | `undefined \| Array<string>` | Nonempty list of HTTPS response POST URIs without fragments. A request response_uri must exactly match an entry. |
| `redirect_uris?` | `undefined \| Array<string>` | Nonempty list of HTTPS redirect URIs without userinfo. Supplied request redirects must match exactly and cannot contain a fragment. |
| `dcql_queries?` | `undefined \| Array<DcqlQuery>` | Nonempty list of federation-published query scenarios. Immediate-Superior metadata takes priority over the active request query; policies and the host queryPolicy determine other applicability rules. |
| `jwks_uri?` | `undefined \| string` | HTTPS source of public protocol keys, without userinfo. Offline verification needs the effective inline jwks instead. |
| `signed_jwks_uri?` | `undefined \| string` | HTTPS source of a signed protocol key set, authenticated with Federation Entity Keys. Offline verification needs effective inline keys. |

## `CredentialVerifierPublicationMetadata`

[Source](../../../packages/wallet/src/metadata.ts)

Partial top-level verifier publication fields. The publication parser validates supplied fields with the creation/publication DCQL rules and permits a Superior to complete missing top-level requirements.

<details>
<summary>Type declaration</summary>

```typescript signature
type CredentialVerifierPublicationMetadata = {
	[key: string]: unknown;
	jwks?: undefined | JWKSet;
	request_uris?: undefined | Array<string>;
	response_uris?: undefined | Array<string>;
	redirect_uris?: undefined | Array<string>;
	dcql_queries?: undefined | Array<DcqlQuery>;
	jwks_uri?: undefined | string;
	signed_jwks_uri?: undefined | string;
	vp_formats_supported?: undefined | Record<string, {
		[key: string]: unknown;
		alg_values?: undefined | Array<string>;
		proof_type_values?: undefined | Array<string>;
		cryptosuite_values?: undefined | Array<string>;
		issuerauth_alg_values?: undefined | Array<string | number>;
		deviceauth_alg_values?: undefined | Array<string | number>;
		"sd-jwt_alg_values"?: undefined | Array<string>;
		"kb-jwt_alg_values"?: undefined | Array<string>;
	}>;
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `jwks?` | `undefined \| JWKSet` | Inline public protocol keys. The set must be nonempty, with unique, nonempty `kid` values. Effective inline keys take precedence during wallet verification. These are separate from Federation Entity Keys. |
| `request_uris?` | `undefined \| Array<string>` | Nonempty list of HTTPS Request Object retrieval URIs. A request_uri must exactly match an entry; retrieval transport belongs to the host. |
| `response_uris?` | `undefined \| Array<string>` | Nonempty list of HTTPS response POST URIs without fragments. A request response_uri must exactly match an entry. |
| `redirect_uris?` | `undefined \| Array<string>` | Nonempty list of HTTPS redirect URIs without userinfo. Supplied request redirects must match exactly and cannot contain a fragment. |
| `dcql_queries?` | `undefined \| Array<DcqlQuery>` | Nonempty list of federation-published query scenarios. Immediate-Superior metadata takes priority over the active request query; policies and the host queryPolicy determine other applicability rules. |
| `jwks_uri?` | `undefined \| string` | HTTPS source of public protocol keys, without userinfo. Offline verification needs the effective inline jwks instead. |
| `signed_jwks_uri?` | `undefined \| string` | HTTPS source of a signed protocol key set, authenticated with Federation Entity Keys. Offline verification needs effective inline keys. |
| `vp_formats_supported?` | `undefined \| Record<string, { [key: string]: unknown; alg_values?: undefined \| Array<string>; proof_type_values?: undefined \| Array<string>; cryptosuite_values?: undefined \| Array<string>; issuerauth_alg_values?: undefined \| Array<string \| number>; deviceauth_alg_values?: undefined \| Array<string \| number>; "sd-jwt_alg_values"?: undefined \| Array<string>; "kb-jwt_alg_values"?: undefined \| Array<string>; }>` | Format identifier to presentation-verification capabilities. Unknown format identifiers and extension fields are preserved. |

## `CredentialVerifierRole`

[Source](../../../packages/wallet/src/roles.ts)

Role for `openid_credential_verifier` publication, federation-backed Request Object creation and validation, and host-adapted credential verification. The host owns Request Object retrieval, presentation processing, consent, and response transport. Construction deep-copies initial metadata without validating it. An attached Leaf or Authority invokes the publication hook; use the static parsers for independent validation. Only instance operations needing a signing identity require initialization; discovery/verification can run with configured anchors before attachment.

```typescript signature
new CredentialVerifierRole(config?: WalletRoleConfig): CredentialVerifierRole;
```

### `CredentialVerifierRole#type`

The literal Entity Type Identifier for CredentialVerifierRole, used by host composition and metadata validation.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
readonly type: "openid_credential_verifier";
```

### `CredentialVerifierRole#discover`

Establish federation trust for the requested participant and validate completed Credential Verifier metadata. Explicit trustChain or entityChains evidence takes precedence over discovery. Offline use requires supplied evidence; a custom chain selector runs only on eligible validated candidates. Returns trusted metadata and its supporting chain. Instance options merge host, role, then per-call values. Pinned anchors are selected from per-call, role config, role options, then host; missing anchors throw before returning a Result.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
discover(id: string, options?: BoundFederationOptions<WalletTrustOptions>): Promise<Result<TrustedWalletEntity>>;
```

### `CredentialVerifierRole#prepareAuthorizationRequest`

Prepare candidate verifier chains and protocol keys, validate the federation-prefixed client identifier, and bind any request_uri to effective verifier metadata. Returns a process-local handle, not an accepted request. Inline JWT hints are inspected, but signature and contextual query checks are completed later. Explicit supplied evidence takes precedence; an unusable embedded hint may fall back to bounded online discovery. Instance options merge host, role, then per-call values. Pinned anchors are selected from per-call, role config, role options, then host; missing anchors throw before returning a Result.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
prepareAuthorizationRequest(outer: WalletAuthorizationRequest, options?: BoundFederationOptions<AuthorizationRequestOptions>): Promise<Result<PreparedAuthorizationRequest>>;
```

### `CredentialVerifierRole#completeAuthorizationRequest`

Complete the original preparation handle with its signed Request Object and optional retrieval context. Verify the signature, audience, wallet nonce, endpoint bindings, query/policy context, and configured transaction checks before selecting an eligible chain. Copied/deserialized, expired, or cancelled handles fail. An inline prepared request must use the identical JWT. Success returns federation-validated request context; the host still verifies presentations and processes the exchange.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
completeAuthorizationRequest(prepared: PreparedAuthorizationRequest, jwt: string, context?: AuthorizationRequestContext): Promise<Result<ValidatedWalletRequest>>;
```

### `CredentialVerifierRole#createAuthorizationRequest`

Create an oauth-authz-req+jwt Request Object with client_id set to openid_federation:<signing Entity Identifier> and aud set from walletIssuer or https://self-issued.me/v2. Configure `signing.authorizationRequest` on the role to select a protocol signing purpose from the host keyring. Set request dates in the payload when your flow requires them. An explicit options.trustChain is validated against pinned anchors before attachment; restrict those anchors to the intended Wallet's trusted anchors. The host supplies scope mappings and protocol exchange transport. Instance signing requires host initialization. Options merge host, role, then per-call; attaching an explicit chain also requires pinned anchors.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
createAuthorizationRequest(request: Readonly<Record<string, unknown>>, options?: BoundFederationOptions<AuthorizationRequestCreationOptions>): Promise<Result<string>>;
```

### `CredentialVerifierRole#verifyCredential`

Establish Credential Issuer federation trust and validate its effective issuer metadata, then call verifyCredential with copied credential/evidence and protocol keys when published. The callback owns credential-format, proof, and status checks; only true accepts. Missing key metadata yields keys: undefined. Returns current issuer evidence on success and does not perform AS discovery. Instance options merge host, role, then per-call values. Pinned anchors are selected from per-call, role config, role options, then host; missing anchors throw before returning a Result.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
verifyCredential(credential: unknown, issuerId: string, options: BoundFederationOptions<CredentialVerificationOptions>): Promise<Result<TrustedWalletEntity>>;
```

### `CredentialVerifierRole#verifyWalletAttestation`

Establish the signing Wallet Provider's federation trust, resolve its protocol keys, and verify the JWT attestation signature, type, claims, times, and any supplied audience binding. Returns the attestation claims and provider evidence. This does not verify instance-key possession or call a host wallet-acceptance policy; use authenticateWallet for that. Instance options merge host, role, then per-call values. Pinned anchors are selected from per-call, role config, role options, then host; missing anchors throw before returning a Result.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
verifyWalletAttestation(jwt: string, options?: BoundFederationOptions<WalletAttestationVerificationOptions>): Promise<Result<VerifiedWalletAttestation, ClientAttestationError>>;
```

### `CredentialVerifierRole#authenticateWallet`

Verify the Wallet Attestation and its instance-signed PoP, including receiver binding, configured freshness, replay policy, and required acceptWallet callback. JTI mode uses the receiver’s replay storage. Challenge consumption and freshness-only are explicit policies. Configure either freshness or maxProofAgeSeconds. Returns a Federation Result with ClientAttestationError on failure. The host enforces its own wallet acceptance policy and protocol HTTP error response. Instance options merge host, role, then per-call values. Pinned anchors are selected from per-call, role config, role options, then host; missing anchors throw before returning a Result.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
authenticateWallet(attestation: string, proof: string, options: BoundFederationOptions<AuthenticateWalletOptions>): Promise<Result<VerifiedWalletAttestation, ClientAttestationError>>;
```

### `CredentialVerifierRole#verifyProviderAttestation`

Establish provider federation trust and resolve provider protocol keys, then call the required verifyAttestation callback with copied input/evidence and a bounded abort signal. Only true accepts; throws, rejection, timeout, or cancellation produce a failed Result. The callback owns format-specific cryptographic verification. Success returns current provider evidence, not a parsed attestation. Instance options merge host, role, then per-call values. Pinned anchors are selected from per-call, role config, role options, then host; missing anchors throw before returning a Result.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
verifyProviderAttestation(attestation: unknown, providerId: string, options: BoundFederationOptions<AttestationVerificationOptions>): Promise<Result<TrustedWalletEntity>>;
```

### `CredentialVerifierRole#assessEntity`

Assess target under bottom-up validation or an explicitly configured trusted-resolver mode, then validate effective metadata for the supplied wallet Entity Type. This type argument is explicit even on a concrete role. Accreditation issuers need not publish the target's protocol metadata. Returns a core EntityAssessment Result; no Request Object, attestation, or credential is verified by this call. Instance options merge host, role, then per-call values. Pinned anchors are selected from per-call, role config, role options, then host; missing anchors throw before returning a Result.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
assessEntity(target: string, type: WalletRoleType, options?: Omit<EntityAssessmentOptions & WalletTrustOptions, "engine">): Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```

### `CredentialVerifierRole#metadata`

Mutable role metadata record deep-copied from config.metadata at construction. The readonly property prevents reassignment, not edits to the record. Leaf and Authority snapshot this block during host composition and invoke validateMetadata. Later edits to the role or its original input do not update the host's published metadata.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
readonly metadata: Record<string, unknown>;
```

### `CredentialVerifierRole#config`

The original configuration object, retained by reference. Metadata has a separate deep copy; options and anchor collections are not deeply snapshotted by construction. A readonly property does not freeze the referenced configuration.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
readonly config: WalletRoleConfig;
```

### `CredentialVerifierRole#initialize`

Bind the role to an EntityContext. Hosts call this during composition. Reusing the same context is allowed; rebinding the role to a different context throws. This method does not itself validate metadata.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
initialize(context: EntityContext): void;
```

### `CredentialVerifierRole#validateMetadata`

Validate a composed publication block with the matching partial schema. Missing top-level requirements may be completed by a Superior; supplied values and nested requirements are checked. Credential Issuer credential_issuer, when supplied, must equal context.entityId. Invalid metadata throws TypeError.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
validateMetadata(metadata: Readonly<Record<string, unknown>>, context: EntityContext): void;
```

### `CredentialVerifierRole.parseMetadata`

Validate completed effective metadata and return a Zod safe-parse result: success/data or success: false/error.issues. Unknown extension fields are preserved. Parsing establishes no federation trust; for Credential Issuers, standalone parsing does not bind credential_issuer to an independently known Entity Identifier.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
static parseMetadata(metadata: unknown, options?: MetadataValidationOptions): z.ZodSafeParseResult<CredentialVerifierMetadata>;
```

### `CredentialVerifierRole.parsePublicationMetadata`

Validate supplied publication fields while permitting a Superior to complete missing top-level requirements. Supplied nested objects still receive their full checks. Returns a Zod safe-parse result, not a Federation Result, and establishes no trust.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
static parsePublicationMetadata(metadata: unknown, options?: MetadataValidationOptions): z.ZodSafeParseResult<CredentialVerifierPublicationMetadata>;
```

### `CredentialVerifierRole.discover`

Establish federation trust for the requested participant and validate completed Credential Verifier metadata. Explicit trustChain or entityChains evidence takes precedence over discovery. Offline use requires supplied evidence; a custom chain selector runs only on eligible validated candidates. Returns trusted metadata and its supporting chain.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
CredentialVerifierRole.discover(id: string, anchors: TrustAnchorSet, options: WalletTrustOptions): Promise<Result<TrustedWalletEntity>>;
```

### `CredentialVerifierRole.prepareAuthorizationRequest`

Prepare candidate verifier chains and protocol keys, validate the federation-prefixed client identifier, and bind any request_uri to effective verifier metadata. Returns a process-local handle, not an accepted request. Inline JWT hints are inspected, but signature and contextual query checks are completed later. Explicit supplied evidence takes precedence; an unusable embedded hint may fall back to bounded online discovery.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
static prepareAuthorizationRequest(outer: WalletAuthorizationRequest, anchors: TrustAnchorSet, options: AuthorizationRequestOptions): Promise<Result<PreparedAuthorizationRequest>>;
```

### `CredentialVerifierRole.completeAuthorizationRequest`

Complete the original preparation handle with its signed Request Object and optional retrieval context. Verify the signature, audience, wallet nonce, endpoint bindings, query/policy context, and configured transaction checks before selecting an eligible chain. Copied/deserialized, expired, or cancelled handles fail. An inline prepared request must use the identical JWT. Success returns federation-validated request context; the host still verifies presentations and processes the exchange.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
static completeAuthorizationRequest(prepared: PreparedAuthorizationRequest, jwt: string, context?: AuthorizationRequestContext): Promise<Result<ValidatedWalletRequest>>;
```

Example:

<!-- oidfed-example -->
```typescript
import type { CryptoEngine } from "@oidfed/crypto";
import type { TrustAnchorSet } from "@oidfed/core";
import { CredentialVerifierRole, type WalletAuthorizationRequest } from "@oidfed/wallet";

async function validateRequest(
  engine: CryptoEngine,
  outer: WalletAuthorizationRequest,
  requestJwt: string, // Retrieved by the host, or the original inline request.
  anchors: TrustAnchorSet,
  expectedWalletNonce: string,
) {
  const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
    outer, anchors, { engine, walletNonce: expectedWalletNonce },
  );
  if (!prepared.ok) return prepared;
  const completed = await CredentialVerifierRole.completeAuthorizationRequest(
    prepared.value, requestJwt,
  );
  if (!completed.ok) return completed;
  // Hand effectiveQueries to the presentation engine, not directly to a response.
  console.info(completed.value.querySource);
  return completed;
}
```

### `CredentialVerifierRole.createAuthorizationRequest`

Create an oauth-authz-req+jwt Request Object with client_id set to openid_federation:<signing Entity Identifier> and aud set from walletIssuer or https://self-issued.me/v2. The supplied signer is a protocol signer, not implicitly the host Federation signer. Dates are not added automatically. An explicit options.trustChain is validated against pinned anchors before attachment; restrict those anchors to the intended Wallet's trusted anchors. The host supplies scope mappings and protocol exchange transport.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
CredentialVerifierRole.createAuthorizationRequest(id: string, request: Readonly<Record<string, unknown>>, signer: KeyringEntry, options: AuthorizationRequestCreationOptions): Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: string; }>;
```

### `CredentialVerifierRole.validateResponseRedirect`

Check an exact redirect URI match against the verifier metadata retained for an original, completed request result. Copies/deserialized results fail because they lack retained evidence. Expired or cancelled request evidence also fails; success does not send a response or verify a presentation.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
static validateResponseRedirect(result: ValidatedWalletRequest, uri: string): { ok: false; error: FederationError; } | { ok: true; value: true; };
```

### `CredentialVerifierRole.verifyCredential`

Establish Credential Issuer federation trust and validate its effective issuer metadata, then call verifyCredential with copied credential/evidence and protocol keys when published. The callback owns credential-format, proof, and status checks; only true accepts. Missing key metadata yields keys: undefined. Returns current issuer evidence on success and does not perform AS discovery.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
static verifyCredential(credential: unknown, issuerId: string, anchors: TrustAnchorSet, options: CredentialVerificationOptions): Promise<Result<TrustedWalletEntity>>;
```

Example:

<!-- oidfed-example -->
```typescript
import type { CryptoEngine } from "@oidfed/crypto";
import type { TrustAnchorSet } from "@oidfed/core";
import { CredentialVerifierRole, type CredentialVerificationOptions } from "@oidfed/wallet";

async function verifyMembershipCredential(
  engine: CryptoEngine,
  credential: unknown,
  issuerId: string,
  anchors: TrustAnchorSet,
  verifyCredential: CredentialVerificationOptions["verifyCredential"],
) {
  const result = await CredentialVerifierRole.verifyCredential(
    credential, issuerId, anchors, { engine, verifyCredential },
  );
  if (!result.ok) console.error(result.error.description);
  return result; // Trusted issuer evidence, not a parsed credential.
}
```

### `CredentialVerifierRole.verifyProviderAttestation`

Establish provider federation trust and resolve provider protocol keys, then call the required verifyAttestation callback with copied input/evidence and a bounded abort signal. Only true accepts; throws, rejection, timeout, or cancellation produce a failed Result. The callback owns format-specific cryptographic verification. Success returns current provider evidence, not a parsed attestation.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
static verifyProviderAttestation(attestation: unknown, providerId: string, anchors: TrustAnchorSet, options: AttestationVerificationOptions): Promise<Result<TrustedWalletEntity>>;
```

### `CredentialVerifierRole.verifyWalletAttestation`

Establish the signing Wallet Provider's federation trust, resolve its protocol keys, and verify the JWT attestation signature, type, claims, times, and any supplied audience binding. Returns the attestation claims and provider evidence. This does not verify instance-key possession or call a host wallet-acceptance policy; use authenticateWallet for that.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
CredentialVerifierRole.verifyWalletAttestation(jwt: string, anchors: TrustAnchorSet, options: WalletAttestationVerificationOptions): Promise<Result<VerifiedWalletAttestation, ClientAttestationError>>;
```

### `CredentialVerifierRole.authenticateWallet`

Verify the Wallet Attestation and its instance-signed PoP, including receiver binding, configured freshness, replay policy, and required acceptWallet callback. JTI mode uses the receiver’s replay storage. Challenge consumption and freshness-only are explicit policies. Configure either freshness or maxProofAgeSeconds. Returns a Federation Result with ClientAttestationError on failure. The host enforces its own wallet acceptance policy and protocol HTTP error response.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
CredentialVerifierRole.authenticateWallet(attestation: string, proof: string, anchors: TrustAnchorSet, options: AuthenticateWalletOptions): Promise<Result<VerifiedWalletAttestation, ClientAttestationError>>;
```

### `CredentialVerifierRole.assessEntity`

Assess target under bottom-up validation or an explicitly configured trusted-resolver mode, then validate effective metadata for the supplied wallet Entity Type. This type argument is explicit even on a concrete role. Accreditation issuers need not publish the target's protocol metadata. Returns a core EntityAssessment Result; no Request Object, attestation, or credential is verified by this call.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
CredentialVerifierRole.assessEntity(target: string, type: WalletRoleType, anchors: TrustAnchorSet, options: EntityAssessmentOptions & WalletTrustOptions): Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```

## `DcqlQuery`

[Source](../../../packages/wallet/src/metadata.ts)

Public structural DCQL query type used in metadata, local scope mappings, and completed request contexts. Runtime checks enforce identifiers, references, format-specific metadata, and creation/publication path uniqueness beyond this TypeScript shape. Unknown format and extension fields remain open.

<details>
<summary>Type declaration</summary>

```typescript signature
type DcqlQuery = {
	[key: string]: unknown;
	credentials: Array<{
		[key: string]: unknown;
		id: string;
		format: string;
		meta: Record<string, unknown>;
		multiple?: undefined | boolean;
		trusted_authorities?: undefined | Array<{
			[key: string]: unknown;
			type: string;
			values: Array<string>;
		}>;
		require_cryptographic_holder_binding?: undefined | boolean;
		claims?: undefined | Array<{
			[key: string]: unknown;
			path: Array<null | string | number>;
			id?: undefined | string;
			values?: undefined | Array<string | number | boolean>;
		}>;
		claim_sets?: undefined | Array<Array<string>>;
	}>;
	credential_sets?: undefined | Array<{
		[key: string]: unknown;
		options: Array<Array<string>>;
		required?: undefined | boolean;
	}>;
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `credentials` | `Array<{ [key: string]: unknown; id: string; format: string; meta: Record<string, unknown>; multiple?: undefined \| boolean; trusted_authorities?: undefined \| Array<{ [key: string]: unknown; type: string; values: Array<string>; }>; require_cryptographic_holder_binding?: undefined \| boolean; claims?: undefined \| Array<{ [key: string]: unknown; path: Array<null \| string \| number>; id?: undefined \| string; values?: undefined \| Array<string \| number \| boolean>; }>; claim_sets?: undefined \| Array<Array<string>>; }>` | Nonempty credential-query list with unique identifiers, format-specific metadata, optional claim queries, and optional trusted-authority hints. Input creation rejects repeated claim paths; inbound completion normalizes them. |
| `credential_sets?` | `undefined \| Array<{ [key: string]: unknown; options: Array<Array<string>>; required?: undefined \| boolean; }>` | Optional nonempty alternative credential-set requirements. Each option references credential identifiers declared in credentials. |

## `DiscoveredCredentialIssuer`

[Source](../../../packages/wallet/src/roles.ts)

Trusted issuer metadata with usable AS evidence and, under the available policy, individual AS failures. Each chain has its own expiration; this value is not an OAuth session, credential response, or token-verification result.

```typescript signature
interface DiscoveredCredentialIssuer extends TrustedWalletEntity {
	readonly authorizationServerErrors: readonly {
		entityId: string;
		error: FederationError;
	}[];
	readonly authorizationServers: readonly TrustedWalletEntity[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `authorizationServerErrors` | `readonly { entityId: string; error: FederationError }[]` | Individual AS discovery failures retained only under authorizationServerPolicy: available. |
| `authorizationServers` | `readonly TrustedWalletEntity[]` | Usable, federation-validated AS entities, in declaration order with duplicate identifiers removed. Absence of authorization_servers on the issuer selects the co-located AS. |
| `entityId` | `string` | Exact Federation Entity Identifier of the validated participant. |
| `metadata` | `Readonly<Record<string, unknown>>` | Effective role metadata after federation overrides, policies, and matching protocol validation. |
| `trustChain` | `ValidatedTrustChain` | Validated Credential Issuer chain. Each authorizationServers entry carries its own chain, which may have an earlier deadline. |

## `PreparedAuthorizationRequest`

[Source](../../../packages/wallet/src/authorization-request.ts)

Opaque process-local preparation handle. Keep the original object for completeAuthorizationRequest before expiresAt. Copying or serializing it loses the retained candidate chains and keys. Preparation alone does not authorize the request. The private brand shown below is descriptive and is not a package export.

```typescript signature
// Package-private marker, shown to explain the opaque handle.
declare const requestPreparationBrand: unique symbol;
interface PreparedAuthorizationRequest {
	readonly [requestPreparationBrand]: true;
	readonly verifierId: string;
	readonly expiresAt: number;
	readonly requestUri?: string;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `verifierId` | `string` | Exact verifier Entity Identifier retained by preparation, without the openid_federation: prefix. |
| `expiresAt` | `number` | Latest available candidate chain deadline, in epoch seconds. Each candidate and the completed Request Object are checked again at completion. |
| `requestUri?` | `string` | Request URI checked against verifier metadata during preparation. The host retrieves its JWT. |
| `[requestPreparationBrand]` | `true` | Package-private type marker. Obtain this handle from preparation and retain the original object; callers cannot construct the retained validation evidence. |

## `TrustedWalletEntity`

[Source](../../../packages/wallet/src/trust.ts)

Validated participant identifier, effective role metadata, and its supporting chain. readonly declarations constrain assignments in TypeScript; they do not freeze the returned nested metadata or chain. A declared object of this type is not proof that validation ran.

```typescript signature
interface TrustedWalletEntity {
	readonly entityId: string;
	readonly metadata: Readonly<Record<string, unknown>>;
	readonly trustChain: ValidatedTrustChain;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entityId` | `string` | Exact Federation Entity Identifier of the validated participant. |
| `metadata` | `Readonly<Record<string, unknown>>` | Effective role metadata after federation overrides, policies, and matching protocol validation. |
| `trustChain` | `ValidatedTrustChain` | Validated subject chain supporting this metadata, including its expiration deadline. |

## `ValidatedWalletRequest`

[Source](../../../packages/wallet/src/authorization-request.ts)

Completed federation-backed Request Object context, including normalized query scenarios and the validated verifier metadata/chain. The returned request is sanitized for federation overrides; it is not a verified presentation. Retain the original result when using validateResponseRedirect because that method checks private evidence and request-specific deadlines.

```typescript signature
interface ValidatedWalletRequest {
	/** Protocol fields with request-supplied metadata and overridden query fields removed. */
	readonly request: Readonly<Record<string, unknown>>;
	readonly effectiveQueries: readonly DcqlQuery[];
	readonly querySource: "superior_metadata" | "verifier_metadata" | "metadata_policy" | "request";
	readonly verifierMetadata: Readonly<Record<string, unknown>>;
	readonly trustChain: ValidatedTrustChain;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `request` | `Readonly<Record<string, unknown>>` | Sanitized Request Object fields. client_metadata, iss, and payload trust_chain are removed; immediate-Superior query overrides also remove request query/scope fields. |
| `effectiveQueries` | `readonly DcqlQuery[]` | Normalized effective DCQL query scenarios. Completion establishes federation context; the host still performs credential selection and presentation processing. |
| `querySource` | `"superior_metadata" \| "verifier_metadata" \| "metadata_policy" \| "request"` | Origin of effective query scenarios: immediate-Superior metadata, verifier publication, metadata policy, or active request. |
| `verifierMetadata` | `Readonly<Record<string, unknown>>` | Validated, policy-resolved Credential Verifier metadata associated with this request. |
| `trustChain` | `ValidatedTrustChain` | Completed verifier chain. Request expiration, freshness policy, and cancellation can invalidate request evidence before this chain expires. |

## `VerifiedWalletAttestation`

[Source](../../../packages/wallet/src/attestation.ts)

Wallet Attestation claims and the trusted provider evidence supporting them. verifyWalletAttestation verifies the attestation alone; authenticateWallet additionally verifies the instance PoP and invokes the host acceptance callback. This result has no aggregate expiresAt property: the attestation and provider chain retain separate deadlines.

```typescript signature
interface VerifiedWalletAttestation {
	readonly attestation: ClientAttestation;
	readonly provider: TrustedWalletEntity;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `attestation` | `ClientAttestation` | Verified Wallet Attestation claims. Attestation-only verification does not establish possession of the instance key. |
| `provider` | `TrustedWalletEntity` | Federation-validated Wallet Provider evidence associated with the verified attestation. |

## `WalletAttestationVerificationOptions`

[Source](../../../packages/wallet/src/attestation.ts)

Federation, protocol-key, and algorithm settings for verifying a Wallet Attestation without a PoP. expectedAudience is needed if the attestation carries aud; the recipient-specific PoP check is performed by authenticateWallet.

```typescript signature
interface WalletAttestationVerificationOptions extends WalletTrustOptions {
	readonly expectedAudience?: string;
	readonly allowedAttestationAlgorithms?: readonly string[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `expectedAudience?` | `string` | Expected recipient when the Wallet Attestation includes aud. If aud is present, omitting this option rejects the attestation; no PoP is checked by attestation verification alone. |
| `allowedAttestationAlgorithms?` | `readonly string[]` | Attestation signing algorithms. An explicit general protocol allowlist further restricts this list. |
| `trustAnchors?` | `TrustAnchorSet` | Pinned local anchors. Instance precedence is per-call trustAnchors, config.trustAnchors, config.options.trustAnchors, then host anchors. Static discovery and verification take their anchors argument explicitly. |
| `trustChain?` | `readonly string[]` | Raw JWT chain for the target, validated before acceptance. For signing, use this field explicitly to attach a chain and supply pinned anchors. |
| `entityChains?` | `ReadonlyMap<string, readonly string[]>` | Additional raw chains keyed by exact subject identifier, for offline or pre-supplied discovery. Explicit trustChain takes precedence. |
| `offline?` | `boolean` | Block library transport and require supplied chains. Multi-hop validation may also need intermediate ECs from entityConfigurations or a preloaded cache; protocol verification requires inline effective keys. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Authenticated issuer key sets keyed by Entity Identifier, forwarded to Trust Mark checks during trust-chain validation. The host is responsible for their provenance. |
| `trustResolution?` | `TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
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

## `WalletAuthorizationRequest`

[Source](../../../packages/wallet/src/authorization-request.ts)

Outer Request Object delivery parameters. Use the federation-prefixed client_id with either an inline request JWT or a request_uri. This package validates federation evidence but leaves Request URI HTTP retrieval to the host; completion requires the signed JWT.

```typescript signature
interface WalletAuthorizationRequest {
	readonly client_id: string;
	readonly request_uri?: string;
	readonly request_uri_method?: "get" | "post";
	readonly request?: string;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `client_id` | `string` | Full openid_federation: client identifier, including the verifier Entity Identifier. |
| `request_uri?` | `string` | Optional HTTPS Request Object URI. It must match effective verifier metadata; this package does not fetch the request JWT. |
| `request_uri_method?` | `"get" \| "post"` | Request retrieval method hint. Requires request_uri; the host implements GET or POST and supplies the retrieved JWT for completion. |
| `request?` | `string` | Optional inline Request Object JWT, mutually exclusive with request_uri. If provided, completion must use this exact JWT. |

## `WalletProviderMetadata`

[Source](../../../packages/wallet/src/metadata.ts)

Completed Wallet Provider metadata, validated independently by WalletProviderRole.parseMetadata. vp_formats_supported is required; protocol-key references are an integration convention used by JWT Wallet Attestation verification. Shape validity does not establish federation trust.

<details>
<summary>Type declaration</summary>

```typescript signature
type WalletProviderMetadata = {
	[key: string]: unknown;
	vp_formats_supported: Record<string, {
		[key: string]: unknown;
		alg_values?: undefined | Array<string>;
		proof_type_values?: undefined | Array<string>;
		cryptosuite_values?: undefined | Array<string>;
		issuerauth_alg_values?: undefined | Array<string | number>;
		deviceauth_alg_values?: undefined | Array<string | number>;
		"sd-jwt_alg_values"?: undefined | Array<string>;
		"kb-jwt_alg_values"?: undefined | Array<string>;
	}>;
	jwks?: undefined | {
		keys: Array<JWK>;
	};
	jwks_uri?: undefined | string;
	signed_jwks_uri?: undefined | string;
	client_id_prefixes_supported?: undefined | Array<string>;
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `vp_formats_supported` | `Record<string, { [key: string]: unknown; alg_values?: undefined \| Array<string>; proof_type_values?: undefined \| Array<string>; cryptosuite_values?: undefined \| Array<string>; issuerauth_alg_values?: undefined \| Array<string \| number>; deviceauth_alg_values?: undefined \| Array<string \| number>; "sd-jwt_alg_values"?: undefined \| Array<string>; "kb-jwt_alg_values"?: undefined \| Array<string>; }>` | Format identifier to presentation-verification capabilities. Unknown format identifiers and extension fields are preserved. |
| `jwks?` | `undefined \| { keys: Array<JWK>; }` | Inline public protocol keys; `kid` is optional. Effective inline keys take precedence during wallet verification. These are separate from Federation Entity Keys. |
| `jwks_uri?` | `undefined \| string` | HTTPS source of public protocol keys, without userinfo. Offline verification needs the effective inline jwks instead. |
| `signed_jwks_uri?` | `undefined \| string` | HTTPS source of a signed protocol key set, authenticated with Federation Entity Keys. Offline verification needs effective inline keys. |
| `client_id_prefixes_supported?` | `undefined \| Array<string>` | Optional nonempty list of supported client identifier prefixes; this package validates federation-prefixed requests. |

## `WalletProviderPublicationMetadata`

[Source](../../../packages/wallet/src/metadata.ts)

Wallet Provider publication fields with missing top-level requirements permitted for Superior completion. Supplied nested capability and key values are still checked.

<details>
<summary>Type declaration</summary>

```typescript signature
type WalletProviderPublicationMetadata = {
	[key: string]: unknown;
	jwks?: undefined | {
		keys: Array<JWK>;
	};
	jwks_uri?: undefined | string;
	signed_jwks_uri?: undefined | string;
	vp_formats_supported?: undefined | Record<string, {
		[key: string]: unknown;
		alg_values?: undefined | Array<string>;
		proof_type_values?: undefined | Array<string>;
		cryptosuite_values?: undefined | Array<string>;
		issuerauth_alg_values?: undefined | Array<string | number>;
		deviceauth_alg_values?: undefined | Array<string | number>;
		"sd-jwt_alg_values"?: undefined | Array<string>;
		"kb-jwt_alg_values"?: undefined | Array<string>;
	}>;
	client_id_prefixes_supported?: undefined | Array<string>;
};
```

</details>

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `jwks?` | `undefined \| { keys: Array<JWK>; }` | Inline public protocol keys; `kid` is optional. Effective inline keys take precedence during wallet verification. These are separate from Federation Entity Keys. |
| `jwks_uri?` | `undefined \| string` | HTTPS source of public protocol keys, without userinfo. Offline verification needs the effective inline jwks instead. |
| `signed_jwks_uri?` | `undefined \| string` | HTTPS source of a signed protocol key set, authenticated with Federation Entity Keys. Offline verification needs effective inline keys. |
| `vp_formats_supported?` | `undefined \| Record<string, { [key: string]: unknown; alg_values?: undefined \| Array<string>; proof_type_values?: undefined \| Array<string>; cryptosuite_values?: undefined \| Array<string>; issuerauth_alg_values?: undefined \| Array<string \| number>; deviceauth_alg_values?: undefined \| Array<string \| number>; "sd-jwt_alg_values"?: undefined \| Array<string>; "kb-jwt_alg_values"?: undefined \| Array<string>; }>` | Format identifier to presentation-verification capabilities. Unknown format identifiers and extension fields are preserved. |
| `client_id_prefixes_supported?` | `undefined \| Array<string>` | Optional nonempty list of supported client identifier prefixes; this package validates federation-prefixed requests. |

## `WalletProviderRole`

[Source](../../../packages/wallet/src/roles.ts)

Role for `openid_wallet_provider` publication, trusted provider discovery, and Wallet Attestation creation. It exposes shared attestation-PoP and challenge helpers, but does not expose the attestation-verification instance methods available on the issuer and verifier roles. Construction deep-copies initial metadata without validating it. An attached Leaf or Authority invokes the publication hook; use the static parsers for independent validation. Only instance operations needing a signing identity require initialization; discovery/verification can run with configured anchors before attachment.

```typescript signature
new WalletProviderRole(config?: WalletRoleConfig): WalletProviderRole;
```

### `WalletProviderRole#type`

The literal Entity Type Identifier for WalletProviderRole, used by host composition and metadata validation.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
readonly type: "openid_wallet_provider";
```

### `WalletProviderRole#discover`

Establish federation trust for the requested participant and validate completed Wallet Provider metadata. Explicit trustChain or entityChains evidence takes precedence over discovery. Offline use requires supplied evidence; a custom chain selector runs only on eligible validated candidates. Returns trusted metadata and its supporting chain. Instance options merge host, role, then per-call values. Pinned anchors are selected from per-call, role config, role options, then host; missing anchors throw before returning a Result.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
discover(id: string, options?: BoundFederationOptions<WalletTrustOptions>): Promise<Result<TrustedWalletEntity>>;
```

### `WalletProviderRole#createWalletAttestation`

Sign a JWT Wallet Attestation with the supplied provider protocol signer, instance subject, public confirmation key, explicit expiresAt, and optional additional claims. No default expiration is inserted. iss/sub/exp/cnf cannot be replaced by additional claims. When options.trustChain is supplied, validate its subject and signatures against pinned anchors before attaching it. Issue separately per desired anchor; this method does not select an audience-specific anchor. Instance signing requires host initialization. Options merge host, role, then per-call; attaching an explicit chain also requires pinned anchors.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
createWalletAttestation(params: CreateClientAttestationParams, options?: BoundFederationOptions<WalletTrustOptions>): Promise<Result<string>>;
```

### `WalletProviderRole#assessEntity`

Assess target under bottom-up validation or an explicitly configured trusted-resolver mode, then validate effective metadata for the supplied wallet Entity Type. This type argument is explicit even on a concrete role. Accreditation issuers need not publish the target's protocol metadata. Returns a core EntityAssessment Result; no Request Object, attestation, or credential is verified by this call. Instance options merge host, role, then per-call values. Pinned anchors are selected from per-call, role config, role options, then host; missing anchors throw before returning a Result.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
assessEntity(target: string, type: WalletRoleType, options?: Omit<EntityAssessmentOptions & WalletTrustOptions, "engine">): Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```

### `WalletProviderRole#metadata`

Mutable role metadata record deep-copied from config.metadata at construction. The readonly property prevents reassignment, not edits to the record. Leaf and Authority snapshot this block during host composition and invoke validateMetadata. Later edits to the role or its original input do not update the host's published metadata.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
readonly metadata: Record<string, unknown>;
```

### `WalletProviderRole#config`

The original configuration object, retained by reference. Metadata has a separate deep copy; options and anchor collections are not deeply snapshotted by construction. A readonly property does not freeze the referenced configuration.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
readonly config: WalletRoleConfig;
```

### `WalletProviderRole#initialize`

Bind the role to an EntityContext. Hosts call this during composition. Reusing the same context is allowed; rebinding the role to a different context throws. This method does not itself validate metadata.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
initialize(context: EntityContext): void;
```

### `WalletProviderRole#validateMetadata`

Validate a composed publication block with the matching partial schema. Missing top-level requirements may be completed by a Superior; supplied values and nested requirements are checked. Credential Issuer credential_issuer, when supplied, must equal context.entityId. Invalid metadata throws TypeError.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
validateMetadata(metadata: Readonly<Record<string, unknown>>, context: EntityContext): void;
```

### `WalletProviderRole.parseMetadata`

Validate completed effective metadata and return a Zod safe-parse result: success/data or success: false/error.issues. Unknown extension fields are preserved. Parsing establishes no federation trust; for Credential Issuers, standalone parsing does not bind credential_issuer to an independently known Entity Identifier.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
static parseMetadata(metadata: unknown, options?: MetadataValidationOptions): z.ZodSafeParseResult<WalletProviderMetadata>;
```

### `WalletProviderRole.parsePublicationMetadata`

Validate supplied publication fields while permitting a Superior to complete missing top-level requirements. Supplied nested objects still receive their full checks. Returns a Zod safe-parse result, not a Federation Result, and establishes no trust.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
static parsePublicationMetadata(metadata: unknown, options?: MetadataValidationOptions): z.ZodSafeParseResult<WalletProviderPublicationMetadata>;
```

Example:

```typescript
import { WalletProviderRole } from "@oidfed/wallet";

const draft = WalletProviderRole.parsePublicationMetadata({
  client_id_prefixes_supported: ["openid_federation"],
});
if (!draft.success) {
  for (const issue of draft.error.issues) {
    console.error(issue.path.join("."), issue.message);
  }
}
// The missing vp_formats_supported may be supplied by a Superior.
// parseMetadata checks the completed effective object instead.
```

### `WalletProviderRole.discover`

Establish federation trust for the requested participant and validate completed Wallet Provider metadata. Explicit trustChain or entityChains evidence takes precedence over discovery. Offline use requires supplied evidence; a custom chain selector runs only on eligible validated candidates. Returns trusted metadata and its supporting chain.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
WalletProviderRole.discover(id: string, anchors: TrustAnchorSet, options: WalletTrustOptions): Promise<Result<TrustedWalletEntity>>;
```

### `WalletProviderRole.createWalletAttestation`

Sign a JWT Wallet Attestation with the supplied provider protocol signer, instance subject, public confirmation key, explicit expiresAt, and optional additional claims. No default expiration is inserted. iss/sub/exp/cnf cannot be replaced by additional claims. When options.trustChain is supplied, validate its subject and signatures against pinned anchors before attaching it. Issue separately per desired anchor; this method does not select an audience-specific anchor.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
WalletProviderRole.createWalletAttestation(id: string, params: CreateClientAttestationParams, signer: KeyringEntry, options: WalletTrustOptions): Promise<Result<string>>;
```

Example:

<!-- oidfed-example -->
```typescript
import type { CryptoEngine, KeyringEntry } from "@oidfed/crypto";
import type { JWK } from "@oidfed/core";
import { WalletProviderRole } from "@oidfed/wallet";

async function issueWalletAttestation(
  engine: CryptoEngine,
  providerId: string,
  instanceId: string,
  confirmationKey: JWK,
  providerProtocolSigner: KeyringEntry,
) {
  const result = await WalletProviderRole.createWalletAttestation(
    providerId,
    {
      subject: instanceId,
      confirmationKey,
      expiresAt: Date.now() / 1000 + 600,
      claims: { wallet_name: "Membership Wallet" },
    },
    providerProtocolSigner,
    { engine },
  );
  if (!result.ok) console.error(result.error.description);
  return result; // value is the signed JWT when ok is true.
}
```

### `WalletProviderRole.assessEntity`

Assess target under bottom-up validation or an explicitly configured trusted-resolver mode, then validate effective metadata for the supplied wallet Entity Type. This type argument is explicit even on a concrete role. Accreditation issuers need not publish the target's protocol metadata. Returns a core EntityAssessment Result; no Request Object, attestation, or credential is verified by this call.

[Source](../../../packages/wallet/src/roles.ts)

```typescript signature
WalletProviderRole.assessEntity(target: string, type: WalletRoleType, anchors: TrustAnchorSet, options: EntityAssessmentOptions & WalletTrustOptions): Promise<{ readonly ok: false; readonly error: FederationError; } | { readonly ok: true; readonly value: EntityAssessment; }>;
```

## `WalletRoleConfig`

[Source](../../../packages/wallet/src/roles.ts)

Shared role configuration. Initial metadata is deep-copied, while config itself, options, and anchor references are retained. Instance option precedence is per-call over role over host. Instance signing requires host initialization; discovery and verification can run beforehand when role/per-call anchors are available.

```typescript signature
interface WalletRoleConfig {
	readonly signing?: SigningPurposes;
	readonly options?: BoundFederationOptions<WalletTrustOptions>;
	readonly metadata?: Readonly<Record<string, unknown>>;
	readonly trustAnchors?: TrustAnchorSet;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `options?` | `WalletTrustOptions` | Role-default trust and transport options, shallowly merged after host options and before per-call options. |
| `metadata?` | `Readonly<Record<string, unknown>>` | Initial role publication fields, deep-copied at construction. Validation occurs through the host publication hook or the matching static parser. |
| `trustAnchors?` | `TrustAnchorSet` | Role-default pinned anchors, ahead of config.options.trustAnchors and host defaults but behind per-call anchors. |

## `WalletTrustOptions`

[Source](../../../packages/wallet/src/trust.ts)

Shared federation, supplied-evidence, and offline settings for wallet operations. Static discovery and verification receive an explicit anchor argument; instance methods resolve anchor defaults separately. Wallet operations share a fetch budget across discovery, candidate validation, AS discovery, and protocol-key retrieval. A supplied chain remains untrusted until validation succeeds.

```typescript signature
interface WalletTrustOptions extends FederationOptions {
	/** Local anchor configuration for signed-object creation and role defaults. */
	readonly trustAnchors?: TrustAnchorSet;
	/** Preconstructed statements for the target; untrusted until validation succeeds. */
	readonly trustChain?: readonly string[];
	/** Additional supplied chains, keyed by their subjects, for offline integrations. */
	readonly entityChains?: ReadonlyMap<string, readonly string[]>;
	/** Block library network calls. Multi-hop chains also need intermediate ECs in entityConfigurations or a preloaded cache. */
	readonly offline?: boolean;
	readonly trustMarkIssuerKeys?: ReadonlyMap<string, JWKSet>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `trustAnchors?` | `TrustAnchorSet` | Pinned local anchors. Instance precedence is per-call trustAnchors, config.trustAnchors, config.options.trustAnchors, then host anchors. Static discovery and verification take their anchors argument explicitly. |
| `trustChain?` | `readonly string[]` | Raw JWT chain for the target, validated before acceptance. For signing, use this field explicitly to attach a chain and supply pinned anchors. |
| `entityChains?` | `ReadonlyMap<string, readonly string[]>` | Additional raw chains keyed by exact subject identifier, for offline or pre-supplied discovery. Explicit trustChain takes precedence. |
| `offline?` | `boolean` | Block library transport and require supplied chains. Multi-hop validation may also need intermediate ECs from entityConfigurations or a preloaded cache; protocol verification requires inline effective keys. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Authenticated issuer key sets keyed by Entity Identifier, forwarded to Trust Mark checks during trust-chain validation. The host is responsible for their provenance. |
| `trustResolution?` | `TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
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

