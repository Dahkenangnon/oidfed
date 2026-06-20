# @oidfed/authority

Trust Anchor and Intermediate Authority operations — subordinate management, statement issuance, federation endpoint serving, and policy enforcement for the complete OpenID Federation 1.0 implementation.

## Role

Use when building a Trust Anchor or Intermediate Authority. Provides all spec-defined federation endpoints as a single fetch-compatible handler, pluggable subordinate and trust-mark storage, and managed federation key rotation. Combine with `@oidfed/oidc` for OIDC-aware registration processing.

## Install

```bash
pnpm add @oidfed/core @oidfed/authority
```

## Quick Start

```ts
import { createAuthorityServer, MemorySubordinateStore } from "@oidfed/authority";
import { entityId, generateSigningKey, JwkSigner, MemoryFederationKeyProvider } from "@oidfed/core";
import express from "express";

const keyPair = await generateSigningKey("ES256");
const keyProvider = new MemoryFederationKeyProvider({
  signer: new JwkSigner(keyPair.privateKey),
  publicJwk: keyPair.publicKey,
});

const server = createAuthorityServer({
  entityId: entityId("https://ta.example.org"),
  keyProvider,
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: "https://ta.example.org/federation_fetch",
      federation_list_endpoint: "https://ta.example.org/federation_list",
      federation_resolve_endpoint: "https://ta.example.org/federation_resolve",
    },
  },
  subordinateStore: new MemorySubordinateStore(),
});

const handler = server.handler();

const app = express();
app.use(async (req, res) => {
  const response = await handler(req as unknown as Request);
  res.status(response.status);
  response.headers.forEach((value, key) => res.setHeader(key, value));
  res.send(await response.text());
});
```

## API

### Server

```ts
import { createAuthorityServer } from "@oidfed/authority";
import type { AuthorityConfig, AuthorityServer } from "@oidfed/authority";
import type { FederationSigningKey } from "@oidfed/core";
```

`createAuthorityServer(config)` returns an `AuthorityServer`:

```ts
interface AuthorityServer {
  getEntityConfiguration(): Promise<string>;
  getSubordinateStatement(sub: EntityId): Promise<string>;
  listSubordinates(filter?: ListFilter): Promise<EntityId[]>;
  listSubordinatesExtended(params?: ExtendedListInProcessParams): Promise<Result<ExtendedListInProcessResult, FederationError>>;
  resolveEntity(sub: EntityId, ta?: EntityId): Promise<string>;
  getTrustMarkStatus(trustMark: string): Promise<TrustMarkStatusResponsePayload>;
  listTrustMarkedEntities(trustMarkType: string): Promise<string[]>;
  issueTrustMark(sub: string, trustMarkType: string): Promise<string>;
  issueTrustMarkDelegation(subject: string, trustMarkType: string): Promise<string>;
  getHistoricalKeys(): Promise<string>;
  rotateSigningKey(newKey: FederationSigningKey): Promise<void>;
  handler(): (request: Request) => Promise<Response>;
}
```

`handler()` routes all spec-defined federation endpoints:

| Path | Method | Description |
|------|--------|-------------|
| `/.well-known/openid-federation` | GET | Entity Configuration |
| `/federation_fetch` | GET | Subordinate Statement |
| `/federation_list` | GET | List subordinates |
| `/federation_extended_list` | GET | Paginated subordinate listing with audit timestamps and bulk claim retrieval |
| `/federation_resolve` | GET | Resolve trust chain |
| `/federation_trust_mark_status` | POST | Trust mark validity |
| `/federation_trust_mark_list` | GET | Entities with trust mark |
| `/federation_trust_mark` | GET | Issue trust mark |
| `/federation_historical_keys` | GET | Historical federation signing keys |

Explicit registration (`/federation_registration`, section 12) is not routed by `AuthorityServer`. Mount `createExplicitRegistrationHandler` from [`@oidfed/oidc`](./oidc.md#op--processing-explicit-registration) yourself.

### Storage Interfaces

`@oidfed/authority` no longer owns private federation signing key storage. Federation signing and federation public-key publication come from `ManagedFederationKeyProvider` in `@oidfed/core`. Authority storage is now limited to subordinate records and trust marks.

```ts
import {
  MemorySubordinateStore,
  MemoryTrustMarkStore,
} from "@oidfed/authority";
import type {
  ListFilter,
  ListPage,
  ListPageOptions,
  SubordinateRecord,
  SubordinateStore,
  TrustMarkRecord,
  TrustMarkStore,
} from "@oidfed/authority";
```

```ts
interface SubordinateStore {
  get(entityId: EntityId): Promise<SubordinateRecord | undefined>;
  list(filter?: ListFilter, options?: ListPageOptions): Promise<ListPage>;
  add(record: SubordinateRecord): Promise<void>;
  update(entityId: EntityId, updates: Partial<SubordinateRecord>): Promise<void>;
  remove(entityId: EntityId): Promise<void>;
}

interface ListPageOptions {
  cursor?: EntityId;
  limit?: number;
  updatedAfter?: number;
  updatedBefore?: number;
}

interface ListPage {
  readonly items: SubordinateRecord[];
  readonly nextCursor?: EntityId;
}

interface TrustMarkStore {
  get(trustMarkType: string, subject: EntityId): Promise<TrustMarkRecord | undefined>;
  list(trustMarkType: string, options?: { sub?: EntityId; cursor?: string; limit?: number }): Promise<{ items: TrustMarkRecord[]; nextCursor?: string }>;
  issue(record: TrustMarkRecord): Promise<void>;
  revoke(trustMarkType: string, subject: EntityId): Promise<void>;
  isActive(trustMarkType: string, subject: EntityId): Promise<boolean>;
  hasAnyActive(subject: EntityId): Promise<boolean>;
  listForSubject?(subject: EntityId): Promise<TrustMarkRecord[]>;
}
```

### Federation Key Provider

Authorities sign federation artifacts only, using federation keys only.

```ts
import type {
  FederationSigningKey,
  ManagedFederationKeyProvider,
} from "@oidfed/core";
```

`AuthorityConfig.keyProvider` must be a `ManagedFederationKeyProvider`. It is responsible for:

- providing the active signer used for Entity Configurations, subordinate statements, resolve responses, trust marks, trust mark status responses, and historical-keys responses
- publishing the federation public keys that appear in top-level Entity Statement `jwks`
- tracking historical federation key state for `/federation_historical_keys`

### Extended Subordinate Listing

The `/federation_extended_list` endpoint implements the OpenID Federation Extended Subordinate Listing specification. It is enabled by default and configurable per authority:

```ts
const server = createAuthorityServer({
  // ...
  metadata: {
    federation_entity: {
      federation_extended_list_endpoint: "https://ta.example.org/federation_extended_list",
    },
  },
  extendedListing: {
    enabled: true,
    defaultPageSize: 100,
    maxPageSize: 500,
    supportTimeFilters: true,
    supportAuditTimestamps: true,
    defaultClaims: ["subordinate_statement"],
    maxStorePagesPerRequest: 16,
    storeBatchSize: 100,
  },
});
```

The request parameters, pagination, and error semantics remain as documented by the endpoint behavior in the package tests and guide. Production subordinate stores must return deterministic ordering and correct `nextCursor` semantics.

### Key Rotation

```ts
import { rotateKey, rotateKeyCompromise } from "@oidfed/authority";
import { JwkSigner } from "@oidfed/core";
```

```ts
const nextKeyPair = await generateSigningKey("ES256");
const nextFederationKey = {
  signer: new JwkSigner(nextKeyPair.privateKey),
  publicJwk: nextKeyPair.publicKey,
};

await rotateKey(keyProvider, nextFederationKey);
await rotateKeyCompromise(keyProvider, nextFederationKey, compromisedKid);
```

Rotation uses explicit `FederationSigningKey { signer, publicJwk }` input. The provider validates that the published public JWK matches the new signer `kid` and `alg`.

### Middleware and Endpoint Handlers

```ts
import { compose } from "@oidfed/authority";
import type { FederationHandler, Middleware } from "@oidfed/authority";
```

```ts
const logging: Middleware = async (req, next) => {
  console.log(req.method, req.url);
  return next(req);
};

const composed = compose(logging, rateLimiting);
```

Individual endpoint factories and HTTP helpers are also exported for custom routing and composition.

## Configuration

`AuthorityConfig` fields:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `entityId` | `EntityId` | — | Required. This authority's entity identifier |
| `keyProvider` | `ManagedFederationKeyProvider` | — | Required. Federation signer selection, public-key publication, and key lifecycle |
| `metadata` | `object` | — | Required. Must include `federation_entity` |
| `subordinateStore` | `SubordinateStore` | — | Required. Subordinate entity records |
| `trustMarkStore` | `TrustMarkStore` | — | Trust mark issuance store |
| `trustMarks` | `TrustMarkRef[]` | — | Trust marks this authority claims about itself |
| `trustMarkIssuers` | `Record<string, string[]>` | — | Trust mark type to authorized issuer IDs |
| `trustMarkOwners` | `Record<string, TrustMarkOwner>` | — | Delegated trust mark owners |
| `trustMarkDelegations` | `Record<string, string>` | — | Pre-signed delegation JWTs |
| `authorityHints` | `EntityId[]` | — | Omit for Trust Anchors; required for Intermediates |
| `trustAnchors` | `TrustAnchorSet` | — | Used for chain resolution |
| `entityConfigurationTtlSeconds` | `number` | — | Entity Configuration JWT lifetime |
| `subordinateStatementTtlSeconds` | `number` | — | Subordinate Statement JWT lifetime |
| `trustMarkTtlSeconds` | `number` | — | Issued trust mark lifetime |
| `options` | `FederationOptions` | — | Core federation options |
| `extendedListing` | `ExtendedListingConfig` | endpoint enabled, `maxPageSize=500`, `defaultPageSize=100` | Per-authority configuration for `/federation_extended_list` |
