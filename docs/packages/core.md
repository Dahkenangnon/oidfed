# @oidfed/core

Federation primitives for JavaScript — entity statements, trust chain resolution, metadata policy, and cryptographic verification. The foundational layer of the complete OpenID Federation 1.0 implementation.

## Role

Provides trust chain resolution and validation, JOSE operations, metadata policy, typed schemas, caching, and trust mark support. Use directly when you need federation logic without OIDC-specific code. Serves as the foundation for `@oidfed/authority`, `@oidfed/leaf`, and `@oidfed/oidc`.

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

### JOSE

```ts
import {
  generateSigningKey,
  signEntityStatement,
  verifyEntityStatement,
  decodeEntityStatement,
  selectVerificationKey,
  assertTypHeader,
  verifyClientAssertion,
} from "@oidfed/core";
import type { VerifiedClientAssertion } from "@oidfed/core";
```

```ts
const key = await generateSigningKey("ES256");
const jwt = await signEntityStatement(payload, key);
const verified = await verifyEntityStatement(jwt, jwks); // checks sig, typ, exp, iss
const decoded = decodeEntityStatement(jwt);              // no verification
```

### Schemas

```ts
import {
  EntityConfigurationSchema,
  SubordinateStatementSchema,
  EntityStatementPayloadSchema,
  FederationMetadataSchema,
  FederationEntityMetadataSchema,
  ExplicitRegistrationRequestPayloadSchema,
  ExplicitRegistrationResponsePayloadSchema,
  JWKSchema,
  JWKSetSchema,
  TrustMarkPayloadSchema,
} from "@oidfed/core";
```

`openid_relying_party` and `openid_provider` fields in core schemas are `z.record()` (loose). For typed OIDC validation use `@oidfed/oidc`.

### Metadata Policy

```ts
import { resolveMetadataPolicy, applyMetadataPolicy } from "@oidfed/core";
import type { ResolvedMetadataPolicy, PolicyMergeResult } from "@oidfed/core";
```

`resolveMetadataPolicy` merges policies from a chain's statements → `Result<ResolvedMetadataPolicy, FederationError>`.
`applyMetadataPolicy` applies the merged policy to entity metadata → `Result<FederationMetadata, FederationError>`.

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
const cache = new MemoryCache({ maxEntries: 1000 }); // LRU eviction

const ecKey    = await ecCacheKey(entityId("https://example.com"));
const esKey    = await esCacheKey(issuer, subject);
const chainKey = await chainCacheKey(entityId, trustAnchorId);
```

### Trust Marks

```ts
import { validateTrustMark, signTrustMarkDelegation } from "@oidfed/core";
import type { ValidatedTrustMark, ValidatedTrustMarkDelegation } from "@oidfed/core";
```

### Registration Adapter & JTI Store

```ts
import { InMemoryJtiStore } from "@oidfed/core";
import type { JtiStore, RegistrationProtocolAdapter } from "@oidfed/core";
```

`RegistrationProtocolAdapter` — implement to plug protocol-specific metadata validation into the authority server. `@oidfed/oidc` provides `OIDCRegistrationAdapter`.

`InMemoryJtiStore` is for development only. See the [Storage Guide](../guide/storage-guide.md) for production implementations.

## Configuration

`FederationOptions` controls all configurable behaviour:

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
| `maxResponseBytes` | `number` | — | Maximum HTTP response size |
| `signal` | `AbortSignal` | — | Cancellation signal |
| `blockedCIDRs` | `string[]` | — | Additional CIDR ranges to block beyond the built-in IANA IPv4/IPv6 special-use list |
| `allowedHosts` | `string[]` | — | Host allowlist |
| `authorityHintFilter` | `(hint, subject) => boolean` | — | Filter authority hints during resolution |
| `understoodCriticalClaims` | `ReadonlySet<string>` | — | Critical claims this implementation understands |
