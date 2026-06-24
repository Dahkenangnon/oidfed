# @oidfed/authority

Trust Anchor and Intermediate Authority operations — subordinate management, statement issuance, federation endpoint serving, and policy enforcement for the complete OpenID Federation 1.0 implementation.

## Role

Use when building a Trust Anchor or Intermediate Authority. Provides all spec-defined federation endpoints as a single fetch-compatible class, pluggable subordinate and trust-mark storage, and managed federation key rotation. Combine with `@oidfed/oidc` for OIDC-aware registration processing.

## Install

```bash
pnpm add @oidfed/core @oidfed/authority
```

## Quick Start

```ts
import { TrustAnchor, MemoryStorageAdapter } from "@oidfed/authority";
import { generateSigningKey, MemoryFederationKeyProvider, federationKey } from "@oidfed/core";
import express from "express";

const keyPair = await generateSigningKey("ES256");
const keyProvider = new MemoryFederationKeyProvider(federationKey({
  ...keyPair.privateKey,
  kid: "key-1",
}));

const ta = new TrustAnchor({
  entityId: "https://ta.example.org",
  keyProvider,
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: "https://ta.example.org/federation_fetch",
      federation_list_endpoint: "https://ta.example.org/federation_list",
      federation_resolve_endpoint: "https://ta.example.org/federation_resolve",
    },
  },
  storage: new MemoryStorageAdapter(),
});

const app = express();
app.use(async (req, res) => {
  const request = new Request(`https://${req.headers.host}${req.url}`, {
    method: req.method,
    headers: req.headers as any,
    body: req.method !== "GET" && req.method !== "HEAD" ? req : undefined,
  });

  const response = await ta.handleRequest(request);
  res.status(response.status);
  response.headers.forEach((value, key) => res.setHeader(key, value));
  res.send(await response.text());
});
```

## API

### TrustAnchor & Intermediate Classes

```ts
import { TrustAnchor, Intermediate } from "@oidfed/authority";
import type { AuthorityConfig } from "@oidfed/authority";
```

`new TrustAnchor(config)` and `new Intermediate(config)` return the authority entity instances:

```ts
export class TrustAnchor {
  constructor(config: AuthorityConfig);
  entityId: EntityId;
  getEntityConfiguration(): Promise<string>;
  getSubordinateStatement(sub: EntityId): Promise<string>;
  listSubordinates(filter?: ListFilter): Promise<EntityId[]>;
  listSubordinatesExtended(
    params?: ExtendedListInProcessParams,
  ): Promise<Result<ExtendedListInProcessResult, FederationError>>;
  resolveEntity(sub: EntityId, ta?: EntityId): Promise<string>;
  getTrustMarkStatus(trustMark: string): Promise<TrustMarkStatusResponsePayload>;
  listTrustMarkedEntities(trustMarkType: string): Promise<string[]>;
  issueTrustMark(sub: string, trustMarkType: string): Promise<string>;
  issueTrustMarkDelegation(subject: string, trustMarkType: string): Promise<string>;
  getHistoricalKeys(): Promise<string>;
  rotateSigningKey(newKey: FederationSigningKey): Promise<void>;
  handleRequest(request: Request): Promise<Response>;
}

export class Intermediate {
  constructor(config: AuthorityConfig);
  entityId: EntityId;
  getEntityConfiguration(): Promise<string>;
  getSubordinateStatement(sub: EntityId): Promise<string>;
  listSubordinates(filter?: ListFilter): Promise<EntityId[]>;
  listSubordinatesExtended(
    params?: ExtendedListInProcessParams,
  ): Promise<Result<ExtendedListInProcessResult, FederationError>>;
  resolveEntity(sub: EntityId, ta?: EntityId): Promise<string>;
  getTrustMarkStatus(trustMark: string): Promise<TrustMarkStatusResponsePayload>;
  listTrustMarkedEntities(trustMarkType: string): Promise<string[]>;
  issueTrustMark(sub: string, trustMarkType: string): Promise<string>;
  issueTrustMarkDelegation(subject: string, trustMarkType: string): Promise<string>;
  getHistoricalKeys(): Promise<string>;
  rotateSigningKey(newKey: FederationSigningKey): Promise<void>;
  handleRequest(request: Request): Promise<Response>;
}
```

`handleRequest()` routes all spec-defined federation endpoints:

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

Explicit registration (`/federation_registration`, section 12) is not routed natively by `TrustAnchor`. Mount `FedOidcProvider` or `FedOidcClient` from `@oidfed/oidc` via `roles` composition to enable OIDC federation endpoints automatically.

### Unified Storage Adapter

`@oidfed/authority` accepts one adapter for all non-key persistence. Federation signing and public-key publication remain exclusively behind `ManagedFederationKeyProvider`.

```ts
import { MemoryStorageAdapter } from "@oidfed/authority";
import type {
  StorageAdapter,
  StorageTransaction,
  SubordinateStorage,
  TrustMarkStorage,
} from "@oidfed/authority";
import type { CacheProvider, ReplayStore } from "@oidfed/core";
```

```ts
interface StorageAdapter {
  readonly subordinates: SubordinateStorage;
  readonly trustMarks?: TrustMarkStorage;
  readonly replay?: ReplayStore;
  readonly cache?: CacheProvider;
  transaction<T>(operation: (tx: StorageTransaction) => Promise<T>): Promise<T>;
}
```

Transactions include only authoritative authority records. Replay claims are independently atomic and cache entries are non-authoritative. Transaction callbacks may be retried, so signing and external side effects must happen outside them.

`MemoryStorageAdapter` always supplies subordinate, replay, and cache capabilities. Trust marks are opt-in with `{ trustMarks: true }`. The memory adapter is only for development and tests.

`SubordinateRecord.entityId`, `createdAt`, and `updatedAt` are adapter-managed and excluded from `SubordinateRecordUpdate`. Subordinate pages are ordered lexicographically by `entityId`; their inclusive cursor identifies the first unreturned entity. Trust-mark pages are ordered by subject and use the same inclusive cursor rule.

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
const ta = new TrustAnchor({
  // ...
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: "https://ta.example.org/federation_fetch",
      federation_list_endpoint: "https://ta.example.org/federation_list",
      federation_extended_list_endpoint: "https://ta.example.org/federation_extended_list",
    },
  },
  storage: new MemoryStorageAdapter(),
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

## Configuration

`AuthorityConfig` fields:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `entityId` | `EntityId \| string` | — | Required. This authority's entity identifier |
| `keyProvider` | `ManagedFederationKeyProvider` | — | Required. Federation signer selection, public-key publication, and key lifecycle |
| `metadata` | `object` | — | Required. Must include `federation_entity` |
| `storage` | `StorageAdapter` | — | Required. Unified non-key persistence, replay, cache, and transactions |
| `roles` | `EntityRole[]` | — | Array of composition roles (e.g. OIDC Client/Provider roles) bound to this entity |
| `trustMarks` | `TrustMarkRef[]` | — | Trust marks this authority claims about itself |
| `trustMarkIssuers` | `Record<string, string[]>` | — | Trust mark type to authorized issuer IDs |
| `trustMarkOwners` | `Record<string, TrustMarkOwner>` | — | Delegated trust mark owners |
| `trustMarkDelegations` | `Record<string, string>` | — | Pre-signed delegation JWTs |
| `authorityHints` | `readonly (EntityId \| string)[]` | — | Omit for Trust Anchors; required for Intermediates |
| `trustAnchors` | `TrustAnchorSet` | — | Used for chain resolution |
| `entityConfigurationTtlSeconds` | `number` | — | Entity Configuration JWT lifetime |
| `subordinateStatementTtlSeconds` | `number` | — | Subordinate Statement JWT lifetime |
| `trustMarkTtlSeconds` | `number` | — | Issued trust mark lifetime |
| `options` | `Omit<FederationOptions, "cache">` | — | Core options; authority cache comes from `storage.cache` |
| `extendedListing` | `ExtendedListingConfig` | endpoint enabled, `maxPageSize=500`, `defaultPageSize=100` | Per-authority configuration for `/federation_extended_list` |
