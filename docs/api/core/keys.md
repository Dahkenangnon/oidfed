# Keys, rollover, and protocol JWKS

[`@oidfed/core`](README.md)

Federation key providers supply the current signer and public keys. Lifecycle providers also publish replacements, switch the active signer, and retain history. Protocol-key resolution follows the entity type's metadata and is separate from federation key pinning.

## `createFederationSigningKey`

[Source](../../../packages/core/src/federation-keys.ts#L273)

Create a federation signing-key record from a private JWK for a key provider. Publish only the record's public material.

```typescript signature
createFederationSigningKey(jwk: JWK): FederationSigningKey;
```

## `EntityKeysSource`

[Source](../../../packages/core/src/jwks/resolve.ts#L27)

The metadata key source selected during protocol-key resolution.

```typescript signature
type EntityKeysSource = "jwks" | "jwks_uri" | "signed_jwks_uri";
```

## `FederationKeyLifecycleProvider`

[Source](../../../packages/core/src/federation-keys.ts#L31)

A federation key provider with operations for publishing, activating, retiring, and revoking keys.

```typescript signature
interface FederationKeyLifecycleProvider extends FederationKeyProvider {
	/** Return historical public keys with recorded lifetimes (Federation §8.7.2). */
	getHistoricalFederationKeys(): Promise<HistoricalKeyEntry[]>;
	/** Publish a next key without changing the signer (Federation §11.2). */
	publishKey(key: FederationSigningKey): Promise<void>;
	/**
	 * Switch after the application's publication/propagation interval has elapsed.
	 * A published replacement can also restore signing after all active keys are revoked.
	 */
	switchActiveKey(kid: string, options?: SwitchActiveFederationKeyOptions): Promise<void>;
	/** Apply local revocation policy; this does not invalidate remote cached statements. */
	revokeKey(kid: string, reason: string): Promise<void>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `getHistoricalFederationKeys` | `() => Promise<HistoricalKeyEntry[]>` | Return historical public keys with recorded lifetimes (Federation §8.7.2). |
| `publishKey` | `(key: FederationSigningKey) => Promise<void>` | Publish a next key without changing the signer (Federation §11.2). |
| `switchActiveKey` | `(kid: string, options?: SwitchActiveFederationKeyOptions) => Promise<void>` | Switch after the application's publication/propagation interval has elapsed. A published replacement can also restore signing after all active keys are revoked. |
| `revokeKey` | `(kid: string, reason: string) => Promise<void>` | Apply local revocation policy; this does not invalidate remote cached statements. |
| `getFederationKeySet` | `() => Promise<FederationKeySet>` | Read the current public Federation Entity Keys and active signing capability. |

## `FederationKeyProvider`

[Source](../../../packages/core/src/federation-keys.ts#L15)

The interface used to obtain current federation public keys and a signer.

```typescript signature
interface FederationKeyProvider {
	getFederationKeySet(): Promise<FederationKeySet>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `getFederationKeySet` | `() => Promise<FederationKeySet>` | Read the current public Federation Entity Keys and active signing capability. |

## `FederationKeySet`

[Source](../../../packages/core/src/federation-keys.ts#L10)

The public federation keys and signing information returned by a key provider.

```typescript signature
interface FederationKeySet {
	readonly signer: JwtSigner;
	readonly jwks: JWKSet;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `signer` | `JwtSigner` | Signing capability and its public algorithm/key identifier. Private-key custody stays with the implementation. |
| `jwks` | `JWKSet` | Public Federation Entity Keys, including a key matching the active signer. |

## `FederationSigningKey`

[Source](../../../packages/core/src/federation-keys.ts#L19)

A public federation signing key paired with the signer that holds its private-key capability.

```typescript signature
interface FederationSigningKey {
	readonly signer: JwtSigner;
	readonly publicJwk: JWK;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `signer` | `JwtSigner` | Signing capability and its public algorithm/key identifier. Private-key custody stays with the implementation. |
| `publicJwk` | `JWK` | Public JWK corresponding to the signer; private material must not be published. |

## `fetchJwkSet`

[Source](../../../packages/core/src/jwks/jwks-uri.ts#L24)

Fetch and parse a plain JWK Set from `jwks_uri`.

- URL MUST use https and MUST NOT contain a fragment.
- HTTP GET; non-2xx is rejected by the underlying fetcher.
- Body MUST parse as JSON and conform to `MetadataJWKSetSchema`.
- The conditional `use` rule is enforced (mixed signing/encryption keys
  require `use` on every key).

```typescript signature
fetchJwkSet(url: string, options?: FederationOptions): Promise<Result<JWKSet, FederationError>>;
```

## `fetchSignedJwkSet`

[Source](../../../packages/core/src/jwks/signed-jwks-uri.ts#L34)

Fetch and verify a Signed JWK Set from `signed_jwks_uri`.

- URL MUST use https and MUST NOT contain a fragment.
- HTTP response Content-Type MUST be `application/jwk-set+jwt`.
- The returned JWT is then verified via `verifySignedJwkSet`
  (typ, signature against `signerJwks`, REQUIRED payload claims).

```typescript signature
fetchSignedJwkSet(url: string, signerJwks: JWKSet, options: FetchSignedJwkSetOptions): Promise<Result<SignedJwkSetPayload, FederationError>>;
```

## `FetchSignedJwkSetOptions`

[Source](../../../packages/core/src/jwks/signed-jwks-uri.ts#L21)

Identity, verification, and transport settings for fetching a signed JWK Set.

```typescript signature
interface FetchSignedJwkSetOptions extends FederationOptions, VerifySignedJwkSetOptions {
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
| `cache?` | `CacheProvider` | Host cache for signed statements or operation results; cache hits do not establish trust. |
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
| `expectedOwner` | `string` | Key owner from trusted context; §5.2.1 permits an owner distinct from the issuer. |
| `expectedIssuer` | `string` | Issuer identity that must match the verified payload. |

## `generateSigningKey`

[Source](../../../packages/core/src/jose/keys.ts#L27)

Generate an asymmetric signing key pair for the given algorithm.

```typescript signature
generateSigningKey(alg?: SupportedAlgorithm): Promise<{
	publicKey: JWK;
	privateKey: JWK;
}>;
```

## `isValidAlgorithm`

[Source](../../../packages/core/src/jose/keys.ts#L8)

Returns true if the given value is a supported asymmetric signing algorithm (not "none").

```typescript signature
isValidAlgorithm(alg: unknown): alg is string;
```

## `JWK_PUBLIC_FIELDS`

[Source](../../../packages/core/src/jose/keys.ts#L99)

Allowlist of JWK fields that are safe to expose publicly.

```typescript signature
const JWK_PUBLIC_FIELDS: ReadonlySet<string>;
```

The allowlist contains `kty`, `use`, `key_ops`, `alg`, `kid`, `x5u`, `x5c`, `x5t`, `x5t#S256`, `crv`, `x`, `y`, `n`, and `e`.

## `jwkThumbprint`

[Source](../../../packages/core/src/jose/keys.ts#L43)

Compute JWK thumbprint (SHA-256) for the given key.

```typescript signature
jwkThumbprint(key: JWK): Promise<string>;
```

## `MemoryFederationKeyProvider`

[Source](../../../packages/core/src/federation-keys.ts#L89)

In-memory key lifecycle state. Applications drive Federation §11.2's
publish, propagate, and switch stages; this provider schedules JWKS retirement.
Production providers must share durable state and protect signing-key custody.

```typescript signature
new MemoryFederationKeyProvider(initial: FederationSigningKey | readonly [FederationSigningKey, ...FederationSigningKey[]], options?: MemoryFederationKeyProviderOptions): MemoryFederationKeyProvider;
```

### `MemoryFederationKeyProvider#getFederationKeySet`

Read the current federation signer and public-key set from the provider.

[Source](../../../packages/core/src/federation-keys.ts#L134)

```typescript signature
getFederationKeySet(): Promise<FederationKeySet>;
```

### `MemoryFederationKeyProvider#getHistoricalFederationKeys`

Return historical public keys with recorded lifetimes (Federation §8.7.2).

[Source](../../../packages/core/src/federation-keys.ts#L166)

```typescript signature
getHistoricalFederationKeys(): Promise<HistoricalKeyEntry[]>;
```

### `MemoryFederationKeyProvider#publishKey`

Publish a next key without changing the signer (Federation §11.2).

[Source](../../../packages/core/src/federation-keys.ts#L179)

```typescript signature
publishKey(key: FederationSigningKey): Promise<void>;
```

### `MemoryFederationKeyProvider#switchActiveKey`

Switch after the application's publication/propagation interval has elapsed.
A published replacement can also restore signing after all active keys are revoked.

[Source](../../../packages/core/src/federation-keys.ts#L194)

```typescript signature
switchActiveKey(kid: string, options?: SwitchActiveFederationKeyOptions): Promise<void>;
```

### `MemoryFederationKeyProvider#revokeKey`

Apply local revocation policy; this does not invalidate remote cached statements.

[Source](../../../packages/core/src/federation-keys.ts#L240)

```typescript signature
revokeKey(kid: string, reason: string): Promise<void>;
```

### `MemoryFederationKeyProvider.fromJWK`

Construct an in-memory federation key provider from the supplied private JWK.

[Source](../../../packages/core/src/federation-keys.ts#L91)

```typescript signature
static fromJWK(jwk: JWK, options?: MemoryFederationKeyProviderOptions): MemoryFederationKeyProvider;
```

## `MemoryFederationKeyProviderOptions`

[Source](../../../packages/core/src/federation-keys.ts#L79)

Lifecycle and time settings for the in-memory federation key provider.

```typescript signature
interface MemoryFederationKeyProviderOptions {
	/** Current Unix time in milliseconds for key-lifecycle scheduling. */
	readonly nowMs?: () => number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `nowMs?` | `() => number` | Current Unix time in milliseconds for key-lifecycle scheduling. |

## `preparePublicJwkSet`

[Source](../../../packages/core/src/jwks/public-material.ts#L35)

Capture the JSON data once so publishers store and sign exactly what was validated.

```typescript signature
preparePublicJwkSet(value: unknown): Result<JWKSet, FederationError>;
```

## `ResolvedEntityKeys`

[Source](../../../packages/core/src/jwks/resolve.ts#L36)

Protocol keys together with the source from which they were resolved.

```typescript signature
interface ResolvedEntityKeys {
	keys: JWK[];
	source: EntityKeysSource;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `keys` | `JWK[]` | Public keys in the set; metadata sets may be empty, while Federation signing-key sets require at least one key. |
| `source` | `EntityKeysSource` | Source from which the protocol keys were resolved: inline, signed_jwks_uri, or jwks_uri. |

## `resolveEntityKeys`

[Source](../../../packages/core/src/jwks/resolve.ts#L42)

Resolve public protocol keys in this order: `signed_jwks_uri`, inline `jwks`, then `jwks_uri`. Signed sets are checked against the supplied Federation Entity Keys and expected signer/owner. Default behavior stops at the first error. `allowFallback` advances only after recognized availability failures; signature, identity, payload, and response-format failures stop resolution.

```typescript signature
resolveEntityKeys(entityMetadata: Record<string, unknown>, federationEntityKeys: JWKSet, options: ResolveEntityKeysOptions): Promise<Result<ResolvedEntityKeys, FederationError>>;
```

## `ResolveEntityKeysOptions`

[Source](../../../packages/core/src/jwks/resolve.ts#L29)

Key-source selection, fallback, verification, and transport settings.

```typescript signature
interface ResolveEntityKeysOptions extends FederationOptions, VerifySignedJwkSetOptions {
	clockSkewSeconds?: number;
	clock?: Clock;
	/** Try the next source after transport/timeouts, HTTP 404/410 or transient 5xx; never after integrity failures. Default: false. */
	allowFallback?: boolean;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `clockSkewSeconds?` | `number` | Allowed time-claim leeway in seconds; the default verifier allowance is 60 seconds. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `allowFallback?` | `boolean` | Try the next source after transport/timeouts, HTTP 404/410 or transient 5xx; never after integrity failures. Default: false. |
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
| `expectedOwner` | `string` | Key owner from trusted context; §5.2.1 permits an owner distinct from the issuer. |
| `expectedIssuer` | `string` | Issuer identity that must match the verified payload. |

## `selectVerificationKey`

[Source](../../../packages/core/src/jose/keys.ts#L51)

Select a supported asymmetric verification key whose `key_ops` permits verification and whose `use` is absent or `sig`. A supplied `kid` must match; it never falls back to another key when missing or algorithm-incompatible. With no `kid`, selection can use the supported algorithm and key type. This helper selects a candidate; it does not verify a signature.

```typescript signature
selectVerificationKey(header: { kid?: string; alg?: string }, jwks: JWKSet): JWK | undefined;
```

## `StaticFederationKeyProvider`

[Source](../../../packages/core/src/federation-keys.ts#L65)

Supply a fixed federation key set through the provider interface. Use a lifecycle provider when keys must be published, activated, or retired while the service runs.

```typescript signature
new StaticFederationKeyProvider(keySet: FederationKeySet): StaticFederationKeyProvider;
```

### `StaticFederationKeyProvider#getFederationKeySet`

Read the current federation signer and public-key set from the provider.

[Source](../../../packages/core/src/federation-keys.ts#L74)

```typescript signature
getFederationKeySet(): Promise<FederationKeySet>;
```

## `stripPrivateFields`

[Source](../../../packages/core/src/jose/keys.ts#L123)

Strip private key material from a JWK, returning only spec-defined public fields.

Uses an allowlist strategy so that unknown or future private parameters are excluded by default.

Throws TypeError for symmetric keys (kty "oct") which have no public representation.

```typescript signature
stripPrivateFields(key: JWK): JWK;
```

## `SwitchActiveFederationKeyOptions`

[Source](../../../packages/core/src/federation-keys.ts#L45)

Controls how the previous signing key retires when a new key becomes active.

```typescript signature
interface SwitchActiveFederationKeyOptions {
	/** Post-switch overlap in milliseconds; the memory provider requires a finite, nonnegative value and defaults to seven days. */
	readonly retirePreviousAfterMs?: number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `retirePreviousAfterMs?` | `number` | Post-switch overlap in milliseconds; the memory provider requires a finite, nonnegative value and defaults to seven days. |

## `timingSafeEqual`

[Source](../../../packages/core/src/jose/keys.ts#L84)

Compare the UTF-8 encodings of two strings without an early exit for a differing byte when lengths match. Different lengths return false immediately; use it for the documented public identifiers, not as a general secret-comparison guarantee.

```typescript signature
timingSafeEqual(a: string, b: string): boolean;
```

## `validateFederationKeySet`

[Source](../../../packages/core/src/federation-keys.ts#L284)

Check the relationship between the federation key set and its signer before publication or signing.

```typescript signature
validateFederationKeySet(keySet: FederationKeySet): void;
```

## `validateJwkSetUseRequirement`

[Source](../../../packages/core/src/jwks/use-requirement.ts#L86)

Returns ok if the JWK Set satisfies the `use` conditional REQUIRED rule.

Returns InvalidMetadata when both a signing-capable and an encryption-capable
key are present in the set, but at least one key has no nonempty `use` value.
RFC 7517 permits extension values in addition to sig and enc.

```typescript signature
validateJwkSetUseRequirement(jwks: readonly JWK[]): Result<void, FederationError>;
```

## `validatePublicJwkSet`

[Source](../../../packages/core/src/jwks/public-material.ts#L29)

Check the JSON representation before publishing a federation JWK Set. Includes the
federation schema's unique, nonempty kid requirement. RFC 7518 §6 and RFC 8037
§2 define the public parameters; key import and cryptographic operations
establish whether the key is usable with the chosen backend and algorithm.

Received sets use the existing schemas and verification-key selection:
RFC 7517 §5 recommends ignoring unusable keys when consuming a set.

```typescript signature
validatePublicJwkSet(value: unknown): Result<void, FederationError>;
```

## `validateSignedJwkSetSpecHygiene`

[Source](../../../packages/core/src/jwks/spec-hygiene.ts#L20)

Apply an opt-in stricter deployment profile to a verified Signed JWK Set: sub should equal iss, and aud, nbf, and jti should be omitted. These recommendations are separate from required signature and claim validation.

```typescript signature
validateSignedJwkSetSpecHygiene(payload: SignedJwkSetPayload): Result<void, FederationError>;
```

### Usage example

`validateSignedJwkSetSpecHygiene` checks recommendations separately from the normal required signature and claim checks. Call it only if your deployment chooses those stricter requirements; do not present a recommendation as a universal protocol prohibition.

```ts
import { validateSignedJwkSetSpecHygiene } from "@oidfed/core";

export function acceptStrictSignedKeyMetadata(verifiedPayload: Parameters<typeof validateSignedJwkSetSpecHygiene>[0]) {
  return validateSignedJwkSetSpecHygiene(verifiedPayload);
}
```

