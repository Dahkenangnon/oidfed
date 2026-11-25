# Keys, rollover, and protocol JWKS

[`@oidfed/core`](README.md)

Hosts receive an explicit `CryptoContext` containing a `CryptoEngine` and `Keyring` from `@oidfed/crypto`. A single `KeyringEntry` carries its signing binding and published public keys. Protocol-key resolution follows the entity type's metadata and is separate from federation key pinning.

## `EntityKeysSource`

[Source](../../../packages/core/src/jwks/resolve.ts#L28)

The metadata key source selected during protocol-key resolution.

```typescript signature
type EntityKeysSource = "jwks" | "jwks_uri" | "signed_jwks_uri";
```

## `fetchJwkSet`

[Source](../../../packages/core/src/jwks/jwks-uri.ts#L24)

Fetch and parse a plain JWK Set from `jwks_uri`.

- URL MUST use https and MUST NOT contain a fragment.
- HTTP GET; non-2xx is rejected by the underlying fetcher.
- Body MUST parse as JSON and conform to `MetadataJWKSetSchema`.
- The conditional `use` rule is enforced (mixed signing/encryption keys
  require `use` on every key).

```typescript signature
fetchJwkSet(url: string, options: FederationOptions): Promise<Result<JWKSet, FederationError>>;
```

## `fetchSignedJwkSet`

[Source](../../../packages/core/src/jwks/signed-jwks-uri.ts#L31)

Fetch and verify a Signed JWK Set from `signed_jwks_uri`.

- URL MUST use https and MUST NOT contain a fragment.
- HTTP response Content-Type MUST be `application/jwk-set+jwt`.
- The returned JWT is then verified via `verifySignedJwkSet`
  (typ, signature against `signerJwks`, REQUIRED payload claims).

```typescript signature
fetchSignedJwkSet(url: string, signerJwks: JWKSet, options: FetchSignedJwkSetOptions): Promise<Result<SignedJwkSetPayload, FederationError>>;
```

## `FetchSignedJwkSetOptions`

[Source](../../../packages/core/src/jwks/signed-jwks-uri.ts#L18)

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
| `expectedOwner` | `string` | Key owner from trusted context; §5.2.1 permits an owner distinct from the issuer. |
| `expectedIssuer` | `string` | Issuer identity that must match the verified payload. |

## `isValidAlgorithm`

[Source](../../../packages/core/src/jose/keys.ts#L13)

Returns true if the algorithm is registered. Pass the host registry to recognize a custom algorithm. The default registry contains the built-ins.

```typescript signature
isValidAlgorithm(alg: unknown, registry?: JwsAlgorithmRegistry): alg is string;
```

## `JWK_PUBLIC_FIELDS`

[Source](../../../packages/core/src/jose/keys.ts#L75)

Allowlist of JWK fields that are safe to expose publicly.

```typescript signature
const JWK_PUBLIC_FIELDS: ReadonlySet<string>;
```

The allowlist contains `kty`, `use`, `key_ops`, `alg`, `kid`, `x5u`, `x5c`, `x5t`, `x5t#S256`, `crv`, `x`, `y`, `n`, and `e`.

## `jwkThumbprint`

[Source](../../../packages/core/src/jose/keys.ts#L18)

Compute the RFC 7638 SHA-256 thumbprint for the given key. Pass the host registry for a custom JWK format.

```typescript signature
jwkThumbprint(key: JWK, engine: CryptoEngine, registry?: JwsAlgorithmRegistry): Promise<string>;
```

## `preparePublicJwkSet`

[Source](../../../packages/core/src/jwks/public-material.ts#L39)

Capture the JSON data once so publishers store and sign exactly what was validated.

```typescript signature
preparePublicJwkSet(value: unknown, registry?: JwsAlgorithmRegistry): Result<JWKSet, FederationError>;
```

## `ResolvedEntityKeys`

[Source](../../../packages/core/src/jwks/resolve.ts#L37)

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

[Source](../../../packages/core/src/jwks/resolve.ts#L43)

Resolve public protocol keys in this order: `signed_jwks_uri`, inline `jwks`, then `jwks_uri`. Signed sets are checked against the supplied Federation Entity Keys and expected signer/owner. Default behavior stops at the first error. `allowFallback` advances only after recognized availability failures; signature, identity, payload, and response-format failures stop resolution.

```typescript signature
resolveEntityKeys(entityMetadata: Record<string, unknown>, federationEntityKeys: JWKSet, options: ResolveEntityKeysOptions): Promise<Result<ResolvedEntityKeys, FederationError>>;
```

## `ResolveEntityKeysOptions`

[Source](../../../packages/core/src/jwks/resolve.ts#L30)

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
| `expectedOwner` | `string` | Key owner from trusted context; §5.2.1 permits an owner distinct from the issuer. |
| `expectedIssuer` | `string` | Issuer identity that must match the verified payload. |

## `selectVerificationKey`

[Source](../../../packages/core/src/jose/keys.ts#L27)

Select a supported asymmetric verification key whose `key_ops` permits verification and whose `use` is absent or `sig`. A supplied `kid` must match; it never falls back to another key when missing or algorithm-incompatible. With no `kid`, selection can use the supported algorithm and key type. This helper selects a candidate; it does not verify a signature.

```typescript signature
selectVerificationKey(header: { kid?: string; alg?: string }, jwks: JWKSet, registry?: JwsAlgorithmRegistry): JWK | undefined;
```

## `stripPrivateFields`

[Source](../../../packages/core/src/jose/keys.ts#L99)

Strip private key material from a JWK, returning only spec-defined public fields.

Uses an allowlist strategy so that unknown or future private parameters are excluded by default.

Throws TypeError for symmetric keys (kty "oct") which have no public representation.

```typescript signature
stripPrivateFields(key: JWK): JWK;
```

## `timingSafeEqual`

[Source](../../../packages/core/src/jose/keys.ts#L61)

Compare the UTF-8 encodings of two strings without an early exit for a differing byte when lengths match. Different lengths return false immediately; use it for the documented public identifiers, not as a general secret-comparison guarantee.

```typescript signature
timingSafeEqual(a: string, b: string): boolean;
```

## `validateFederationKeySet`

[Source](../../../packages/core/src/federation-keys.ts#L99)

Check the relationship between the federation key set and its signer before publication or signing.

```typescript signature
validateFederationKeySet(entry: KeyringEntry, registry?: JwsAlgorithmRegistry): void;
```

## `validateJwkSetUseRequirement`

[Source](../../../packages/core/src/jwks/use-requirement.ts#L88)

Returns ok if the JWK Set satisfies the `use` conditional REQUIRED rule.

Returns InvalidMetadata when both a signing-capable and an encryption-capable
key are present in the set, but at least one key has no nonempty `use` value.
RFC 7517 permits extension values in addition to sig and enc.

```typescript signature
validateJwkSetUseRequirement(jwks: readonly JWK[], registry?: JwsAlgorithmRegistry): Result<void, FederationError>;
```

## `validatePublicJwkSet`

[Source](../../../packages/core/src/jwks/public-material.ts#L30)

Check the JSON representation before publishing a federation JWK Set. Includes the
federation schema's unique, nonempty kid requirement. RFC 7518 §6 and RFC 8037
§2 define the public parameters; key import and cryptographic operations
establish whether the key is usable with the chosen backend and algorithm.

Received sets use the existing schemas and verification-key selection:
RFC 7517 §5 recommends ignoring unusable keys when consuming a set.

```typescript signature
validatePublicJwkSet(value: unknown, registry?: JwsAlgorithmRegistry): Result<void, FederationError>;
```

## `signProtocolJwkSet`

Signs one Entity Type's public protocol keys with the issuer's published Federation signing key. It returns a compact JWT with protected `typ: jwk-set+jwt` and the signer's `kid`. Serve it at the host's HTTPS `signed_jwks_uri` with `MediaType.JwkSet`.

### `SignProtocolJwkSetOptions`

Provide `issuer`, `jwks`, and a host `crypto` context. Set `owner` to override the issuer as the key owner. `options` accepts bound Federation signing policy and a clock. `issuedAt` adds `iat`. A positive finite `ttlSeconds` also sets `exp` and uses the clock for `iat` if omitted. See the [publication example](../../features/4.4.protocol-keys.md#publish-a-signed-protocol-jwk-set).

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


## `historicalKeysFromKeyring`

Convert recorded keyring events into the Federation historical-key response shape.

<!-- oidfed-example -->
```ts
import type { RotatingKeyring } from "@oidfed/crypto";
import { historicalKeysFromKeyring } from "@oidfed/core";

export function readFederationKeyHistory(keyring: RotatingKeyring) {
  return historicalKeysFromKeyring(keyring, "federation").getHistoricalKeys();
}
```

Only retired or revoked keys enter this response. Per-key `exp` is the earlier recorded retirement or revocation. Publication and activation do not imply a key's creation time or validity start. A custom `FederationKeyHistorySource` can supply known `iat` and `nbf` facts.

See the [crypto contracts](../crypto/README.md) and [host migration](../migration-v3.md#host-provided-crypto) for backend selection, signing purposes, snapshots and lifecycle operations.
