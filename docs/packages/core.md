# @oidfed/core

Federation primitives for JavaScript — entity statements, trust chain resolution, metadata policy, cryptographic verification, and federation signing abstractions. The foundational layer of the complete OpenID Federation 1.0 implementation.

## Role

Provides trust chain resolution and validation, JOSE operations, metadata policy, typed schemas, caching, trust mark support, and federation signing/key-provider primitives. Use directly when you need federation logic without OIDC-specific code. Serves as the foundation for `@oidfed/authority`, `@oidfed/leaf`, and `@oidfed/oidc`.

## Install

```bash
pnpm add @oidfed/core
```

## API

### Result Type

```ts
import { ok, err, isOk, isErr, map, flatMap, unwrapOr, federationError } from "@oidfed/core";
import type { Result, FederationError } from "@oidfed/core";
```

Error codes: `FederationErrorCode` (spec-defined) and `InternalErrorCode` (implementation-specific).

### Entity IDs

```ts
import { entityId, isValidEntityId } from "@oidfed/core";
import type { EntityId } from "@oidfed/core";
```

```ts
const id: EntityId = entityId("https://op.example.com");
// Throws TypeError if not a valid HTTPS URL (no credentials, query, or fragment)

if (isValidEntityId("https://valid.example.com")) {
  // type narrows to EntityId
}
```

### Trust Chain Resolution

```ts
import {
  resolveTrustChains,
  validateTrustChain,
  fetchEntityConfiguration,
  fetchSubordinateStatement,
  createConcurrencyLimiter,
} from "@oidfed/core";
import type {
  TrustAnchorSet,
  TrustChainResult,
  ValidatedTrustChain,
  FederationOptions,
} from "@oidfed/core";
```

```ts
const trustAnchors: TrustAnchorSet = new Map([
  [entityId("https://ta.example.org"), { jwks: { keys: [taKey] } }],
]);

const result = await resolveTrustChains(
  entityId("https://leaf.example.com"),
  trustAnchors,
  { httpClient: fetch, maxChainDepth: 8, clockSkewSeconds: 60 },
);

for (const chain of result.chains) {
  const validated = await validateTrustChain(chain.statements, trustAnchors, options);
  if (validated.valid) {
    console.log(validated.chain.resolvedMetadata);
    console.log("Expires:", new Date(validated.chain.expiresAt * 1000));
  }
}
```

### Trust Chain Selection & Utilities

```ts
import {
  shortestChain,
  longestExpiry,
  preferTrustAnchor,
  isChainExpired,
  chainRemainingTtl,
  describeTrustChain,
} from "@oidfed/core";
import type { ChainSelectionStrategy } from "@oidfed/core";
```

### Trust Chain Refresh

```ts
import { refreshTrustChain } from "@oidfed/core";
import type { RefreshOptions } from "@oidfed/core";
```

### JOSE and Federation Signing

```ts
import {
  generateSigningKey,
  signEntityStatement,
  verifyEntityStatement,
  decodeEntityStatement,
  selectVerificationKey,
  assertTypHeader,
  verifyClientAssertion,
  JwkSigner,
} from "@oidfed/core";
import type { JwtSigner, VerifiedClientAssertion } from "@oidfed/core";
```

`JwtSigner` is the low-level signing boundary for compact JWT production:

```ts
interface JwtSigner {
  readonly kid: string;
  readonly alg: SupportedAlgorithm;
  signJwt(
    payload: Uint8Array,
    protectedHeader: Readonly<Record<string, unknown>>,
  ): Promise<string>;
}
```

`JwkSigner` is the built-in software-key implementation. It is backed entirely by `jose`, so the package stays runtime-agnostic and does not ship a packaged Web Crypto signer implementation.

```ts
const keyPair = await generateSigningKey("ES256");
const signer: JwtSigner = new JwkSigner(keyPair.privateKey);

const jwt = await signEntityStatement(payload, signer);
const verified = await verifyEntityStatement(jwt, { keys: [keyPair.publicKey] });
const decoded = decodeEntityStatement(jwt);
```

### Federation Key Providers

Federation entity keys are distinct from OIDC/OAuth protocol keys. `@oidfed/core` owns federation signing and federation public-key publication through provider types:

```ts
import {
  JwkSigner,
  MemoryFederationKeyProvider,
  StaticFederationKeyProvider,
} from "@oidfed/core";
import type {
  FederationKeyProvider,
  FederationKeySet,
  FederationSigningKey,
  ManagedFederationKeyProvider,
} from "@oidfed/core";
```

```ts
interface FederationKeySet {
  readonly signer: JwtSigner;
  readonly jwks: JWKSet;
}

interface FederationSigningKey {
  readonly signer: JwtSigner;
  readonly publicJwk: JWK;
}
```

Use `StaticFederationKeyProvider` when the active federation signer and published JWKS are externally managed. Use `MemoryFederationKeyProvider` for in-memory rotation flows and tests.

```ts
const keyPair = await generateSigningKey("ES256");

const keyProvider: ManagedFederationKeyProvider = new MemoryFederationKeyProvider({
  signer: new JwkSigner(keyPair.privateKey),
  publicJwk: keyPair.publicKey,
});

const keySet = await keyProvider.getFederationKeySet();
console.log(keySet.signer.kid);
console.log(keySet.jwks.keys);
```

Managed providers own federation key lifecycle:

```ts
await keyProvider.addKey({
  signer: new JwkSigner(nextKeyPair.privateKey),
  publicJwk: nextKeyPair.publicKey,
});
await keyProvider.activateKey(nextKeyPair.privateKey.kid!);
await keyProvider.retireKey(currentKid, Date.now() + 7 * 24 * 60 * 60 * 1000);
```

The federation provider is the source of truth for published federation public keys. Generic signers do not publish keys themselves.

### Schemas

```ts
import {
  EntityConfigurationSchema,
  SubordinateStatementSchema,
  EntityStatementPayloadSchema,
  FederationMetadataSchema,
  FederationEntityMetadataSchema,
  JWKSchema,
  JWKSetSchema,
  TrustMarkPayloadSchema,
} from "@oidfed/core";
```

`openid_relying_party` and `openid_provider` fields in core schemas are `z.record()` (loose). For typed OIDC validation and the `ExplicitRegistrationRequestPayloadSchema` / `ExplicitRegistrationResponsePayloadSchema` schemas, use `@oidfed/oidc`.

### Metadata Policy

```ts
import { resolveMetadataPolicy, applyMetadataPolicy } from "@oidfed/core";
import type { ResolvedMetadataPolicy, PolicyMergeResult } from "@oidfed/core";
```

`resolveMetadataPolicy` merges policies from a chain's statements into `Result<ResolvedMetadataPolicy, FederationError>`.
`applyMetadataPolicy` applies the merged policy to entity metadata into `Result<FederationMetadata, FederationError>`.

### Constraints

```ts
import {
  checkConstraints,
  checkMaxPathLength,
  checkNamingConstraints,
  applyAllowedEntityTypes,
} from "@oidfed/core";
```

### Federation API Verification

```ts
import {
  verifyHistoricalKeysResponse,
  verifyResolveResponse,
  verifyTrustMarkStatusResponse,
} from "@oidfed/core";
```

### Caching

```ts
import { MemoryCache, ecCacheKey, esCacheKey, chainCacheKey } from "@oidfed/core";
import type { CacheProvider } from "@oidfed/core";
```

```ts
const cache = new MemoryCache({ maxEntries: 1000 });

const ecKey = await ecCacheKey(entityId("https://example.com"));
const esKey = await esCacheKey(issuer, subject);
const chainKey = await chainCacheKey(entityId, trustAnchorId);
```

### Trust Marks

```ts
import { validateTrustMark, signTrustMarkDelegation } from "@oidfed/core";
import type { ValidatedTrustMark, ValidatedTrustMarkDelegation } from "@oidfed/core";
```

### Replay Store

```ts
import { MemoryReplayStore } from "@oidfed/core";
import type { JtiReplayClaim, ReplayStore } from "@oidfed/core";
```

The `RegistrationProtocolAdapter` interface and the `OIDCRegistrationAdapter` implementation are exported from [`@oidfed/oidc`](./oidc.md#registration-adapter), not from this package.

`ReplayStore.useJti({ issuer, audience, jti, expiresAt })` atomically returns `true` for a newly accepted claim and `false` for replay. Issuer and audience are part of the identity so shared deployments do not create cross-tenant collisions. `MemoryReplayStore` is development-only and fails closed when its capacity is full. See the [Storage Guide](../guide/storage-guide.md) for production implementations.

## Configuration

`FederationOptions` controls all configurable behavior:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `httpClient` | `HttpClient` | — | Fetch-compatible HTTP client |
| `clock` | `Clock` | `Date.now` | Custom clock (testing) |
| `cache` | `CacheProvider` | — | Cache implementation |
| `logger` | `Logger` | — | Structured logger |
| `httpTimeoutMs` | `number` | `10000` | HTTP request timeout (ms) |
| `clockSkewSeconds` | `number` | `60` | Allowed clock drift |
| `maxChainDepth` | `number` | `8` | Maximum trust chain length |
| `maxAuthorityHints` | `number` | `10` | Max authority hints per entity |
| `maxConcurrentFetches` | `number` | — | Concurrent HTTP fetch limit |
| `maxConcurrentResolutions` | `number` | — | Concurrent chain resolution limit |
| `cacheMaxTtlSeconds` | `number` | `86400` | Maximum cache entry TTL |
