# @oidfed/authority

Trust Anchor and Intermediate Authority operations — subordinate management, statement issuance, federation endpoint serving, and policy enforcement for the complete OpenID Federation 1.0 implementation.

## Role

Use when building a **Trust Anchor** or **Intermediate Authority**. Provides all spec-defined federation endpoints as a single fetch-compatible handler, pluggable storage, and key lifecycle management. Combine with `@oidfed/oidc` for OIDC-aware registration processing.

## Install

```bash
pnpm add @oidfed/core @oidfed/authority
```

## Quick Start

```ts
import {
  createAuthorityServer,
  MemoryKeyStore,
  MemorySubordinateStore,
} from "@oidfed/authority";
import { entityId, generateSigningKey } from "@oidfed/core";
import express from "express";

const signingKey = await generateSigningKey("ES256");

const server = createAuthorityServer({
  entityId: entityId("https://ta.example.org"),
  signingKeys: [signingKey],
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: "https://ta.example.org/federation_fetch",
      federation_list_endpoint:  "https://ta.example.org/federation_list",
      federation_resolve_endpoint: "https://ta.example.org/federation_resolve",
    },
  },
  subordinateStore: new MemorySubordinateStore(),
  keyStore: new MemoryKeyStore(signingKey),
  // Omit authorityHints for Trust Anchors; include for Intermediates
});

const handler = server.handler(); // fetch-compatible

const app = express();
app.use(async (req, res) => {
  const response = await handler(req as unknown as Request);
  res.status(response.status);
  response.headers.forEach((v, k) => res.setHeader(k, v));
  res.send(await response.text());
});
```

## API

### Server

```ts
import { createAuthorityServer } from "@oidfed/authority";
import type { AuthorityServer, AuthorityConfig } from "@oidfed/authority";
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
  rotateSigningKey(newKey: JWK): Promise<void>;
  handler(): (request: Request) => Promise<Response>;
}
```

`handler()` routes all spec-defined endpoints:

| Path | Method | Description |
|------|--------|-------------|
| `/.well-known/openid-federation` | GET | Entity Configuration |
| `/federation_fetch` | GET | Subordinate Statement |
| `/federation_list` | GET | List subordinates |
| `/federation_extended_list` | GET | Paginated subordinate listing with audit timestamps and bulk claim retrieval (OpenID Federation Extended Subordinate Listing 1.0) |
| `/federation_resolve` | GET | Resolve trust chain |
| `/federation_trust_mark_status` | POST | Trust mark validity |
| `/federation_trust_mark_list` | GET | Entities with trust mark |
| `/federation_trust_mark` | GET | Issue trust mark |
| `/federation_historical_keys` | GET | Historical signing keys |

Explicit registration (`/federation_registration`, §12) is **not** routed by `AuthorityServer`. Wire it yourself by mounting `createExplicitRegistrationHandler` from [`@oidfed/oidc`](./oidc.md#op--processing-explicit-registration) at the path of your choice (typically `/federation_registration`).

### Storage Interfaces

```ts
import {
  MemoryKeyStore,
  MemorySubordinateStore,
  MemoryTrustMarkStore,
} from "@oidfed/authority";
import type {
  KeyState,
  KeyStore,
  ListFilter,
  ManagedKey,
  SubordinateRecord,
  SubordinateStore,
  TrustMarkRecord,
  TrustMarkStore,
} from "@oidfed/authority";
```

```ts
interface SubordinateStore {
  get(entityId: EntityId): Promise<SubordinateRecord | undefined>;
  /**
   * Records MUST be returned in deterministic order (lexicographic by entityId).
   * When `options.cursor` is provided, results resume from that entityId (inclusive).
   * When `options.limit` caps the page, `nextCursor` is the entityId of the first
   * record that would have appeared after the returned page, and is undefined when
   * the page exhausts the filtered set.
   */
  list(filter?: ListFilter, options?: ListPageOptions): Promise<ListPage>;
  add(record: SubordinateRecord): Promise<void>;
  update(entityId: EntityId, updates: Partial<SubordinateRecord>): Promise<void>;
  remove(entityId: EntityId): Promise<void>;
}

interface ListPageOptions {
  cursor?: EntityId;       // Resume cursor (entityId, inclusive)
  limit?: number;          // Maximum records returned in this page
  updatedAfter?: number;   // Return only records with updatedAt ≥ this NumericDate
  updatedBefore?: number;  // Return only records with updatedAt ≤ this NumericDate
}

interface ListPage {
  readonly items: SubordinateRecord[];
  readonly nextCursor?: EntityId;
}

// Key lifecycle: pending → active → retiring → revoked
interface KeyStore {
  getActiveKeys(): Promise<JWKSet>;
  getSigningKey(): Promise<ManagedKey>;
  getHistoricalKeys(): Promise<ManagedKey[]>;
  addKey(key: JWK): Promise<void>;
  activateKey(kid: string): Promise<void>;
  retireKey(kid: string, removeAfter: number): Promise<void>;
  revokeKey(kid: string, reason: string): Promise<void>;
}

interface TrustMarkStore {
  get(trustMarkType: string, subject: EntityId): Promise<TrustMarkRecord | undefined>;
  list(trustMarkType: string, options?: { sub?: EntityId; cursor?: string; limit?: number }): Promise<{ items: TrustMarkRecord[]; nextCursor?: string }>;
  issue(record: TrustMarkRecord): Promise<void>;
  revoke(trustMarkType: string, subject: EntityId): Promise<void>;
  isActive(trustMarkType: string, subject: EntityId): Promise<boolean>;
  hasAnyActive(subject: EntityId): Promise<boolean>;
  /** Optional: enumerate all active trust marks for a subject across all types.
   *  Used by `/federation_extended_list` when `claims=trust_marks` is requested. */
  listForSubject?(subject: EntityId): Promise<TrustMarkRecord[]>;
}
```

### Extended Subordinate Listing

The `/federation_extended_list` endpoint implements the OpenID Federation Extended Subordinate Listing specification (draft-02). It is enabled by default and can be configured per authority:

```ts
import { createAuthorityServer } from "@oidfed/authority";

const server = createAuthorityServer({
  // ...
  metadata: {
    federation_entity: {
      // Publish the endpoint in your Entity Configuration so peers can discover it:
      federation_extended_list_endpoint: "https://ta.example.org/federation_extended_list",
      // ...
    },
  },
  extendedListing: {
    enabled: true,                       // false → endpoint returns 404
    defaultPageSize: 100,                // page size when client omits `limit`
    maxPageSize: 500,                    // hard cap; client `limit` is clamped to this
    supportTimeFilters: true,            // honour `updated_after` / `updated_before`
    supportAuditTimestamps: true,        // honour `audit_timestamps`
    defaultClaims: ["subordinate_statement"], // substituted when the client omits `claims`
    maxStorePagesPerRequest: 16,         // inner store-fetch cap when post-filters drop records
    storeBatchSize: 100,                 // inner store batch size (defaults to defaultPageSize)
  },
});
```

Request parameters (all OPTIONAL):

| Parameter | Type | Notes |
|---|---|---|
| `from_entity_id` | Entity Identifier | Resume cursor (inclusive). Unknown value → `400 entity_id_not_found`. |
| `limit` | positive integer | Page size; server clamps to `maxPageSize`. When omitted, `defaultPageSize` applies. |
| `updated_after` | NumericDate (seconds) | Filter to records updated at or after this time. When present without `audit_timestamps`, the response auto-includes `registered`/`updated` per entity. |
| `updated_before` | NumericDate (seconds) | Filter to records updated at or before this time. Same auto-include behaviour as `updated_after`. |
| `audit_timestamps` | boolean | When `true`, every entity includes `registered` and `updated`. Explicit `audit_timestamps=false` suppresses the auto-include from `updated_after`/`updated_before`. |
| `claims` | array of strings | Comma-separated (`?claims=a,b`) or repeated (`?claims=a&claims=b`) — both forms accepted. Supported top-level Subordinate Statement claims: `subordinate_statement`, `iss`, `sub`, `iat`, `exp`, `jwks`, `metadata`, `metadata_policy`, `constraints`, `crit`, `metadata_policy_crit`, `source_endpoint`, `trust_marks`. Other top-level Entity Statement claims (e.g. `authority_hints`, `trust_mark_issuers`) are intentionally out of scope and silently dropped per the spec's "if available" wording. When the client does NOT send `claims` at all, `defaultClaims` is substituted (default `["subordinate_statement"]`). When the client sends `claims=` (even empty), no substitution happens. |
| `entity_type`, `trust_marked`, `trust_mark_type`, `intermediate` | inherited from `/federation_list` | Same semantics as the base endpoint. |

Response: `200 application/json` containing `immediate_subordinate_entities` (array) and OPTIONAL `next_entity_id` cursor. Synthetic `iat`/`exp` claims are snapshot once per request and align with the `iat`/`exp` inside the same response's `subordinate_statement` JWT.

Error responses use `400 application/json` with `error` in `{ entity_id_not_found, unsupported_parameter, invalid_request }`. Note: requesting `claims=trust_marks` against a deployment whose `TrustMarkStore` does not implement `listForSubject(subject)` returns `400 unsupported_parameter` (operator-facing policy; the spec permits silent omission via "if available", but we surface misconfiguration explicitly).

In-process access (skipping HTTP) is available via `server.listSubordinatesExtended(params)`, returning `Promise<Result<ExtendedListInProcessResult, FederationError>>` so error codes are preserved instead of being thrown.

See [storage-guide.md](../guide/storage-guide.md) for production implementations.

### Key Rotation

```ts
import { rotateKey, rotateKeyCompromise } from "@oidfed/authority";
```

```ts
await rotateKey(keyStore, newKey);              // retires old key after 7 days, activates new
await rotateKeyCompromise(keyStore, newKey, compromisedKid); // immediately revokes compromised key
```

### Middleware

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

### Endpoint Handlers

```ts
import {
  createEntityConfigurationHandler,
  createFetchHandler,
  createListHandler,
  createExtendedListHandler,
  createResolveHandler,
  createHistoricalKeysHandler,
  createTrustMarkHandler,
  createTrustMarkStatusHandler,
  createTrustMarkListHandler,
  buildHistoricalKeys,
  requireMethod,
  requireMethods,
  createAuthenticatedHandler,
  toPublicError,
  jwtResponse,
  jsonResponse,
  errorResponse,
  extractRequestParams,
  parseQueryParams,
  stripPrivateFields,
  SECURITY_HEADERS,
} from "@oidfed/authority";
import type { HandlerContext } from "@oidfed/authority";
```

Individual handlers are available for custom routing. Response helpers: `jwtResponse`, `jsonResponse`, `errorResponse`, `extractRequestParams`, `parseQueryParams`, `stripPrivateFields`, `SECURITY_HEADERS`.

- `requireMethod(method)` — rejects requests with wrong HTTP method
- `requireMethods(...methods)` — variadic version accepting multiple allowed methods
- `createAuthenticatedHandler` — wraps a handler with client authentication
- `toPublicError` — sanitizes internal errors for safe client responses
- `HandlerContext` — type for the context object passed to handlers

## Configuration

`AuthorityConfig` fields:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `entityId` | `EntityId` | — | **Required.** This authority's entity identifier |
| `signingKeys` | `JWK[]` | — | **Required.** Signing keys (first is active) |
| `metadata` | `object` | — | **Required.** Must include `federation_entity` |
| `subordinateStore` | `SubordinateStore` | — | **Required.** Subordinate entity records |
| `keyStore` | `KeyStore` | — | **Required.** Key lifecycle store |
| `trustMarkStore` | `TrustMarkStore` | — | Trust mark issuance store |
| `trustMarks` | `TrustMarkRef[]` | — | Trust marks this authority claims about itself |
| `trustMarkIssuers` | `Record<string, string[]>` | — | Trust mark type → authorized issuer IDs |
| `trustMarkOwners` | `Record<string, TrustMarkOwner>` | — | Delegated trust mark owners |
| `trustMarkDelegations` | `Record<string, string>` | — | Pre-signed delegation JWTs |
| `authorityHints` | `EntityId[]` | — | Omit for Trust Anchors; required for Intermediates |
| `trustAnchors` | `TrustAnchorSet` | — | For chain resolution (resolve endpoint) |
| `entityConfigurationTtlSeconds` | `number` | — | Entity Configuration JWT lifetime |
| `subordinateStatementTtlSeconds` | `number` | — | Subordinate Statement JWT lifetime |
| `trustMarkTtlSeconds` | `number` | — | Issued trust mark lifetime |
| `options` | `FederationOptions` | — | Core federation options (HTTP, cache, etc.) |
| `extendedListing` | `ExtendedListingConfig` | enabled, `maxPageSize=500`, `defaultPageSize=100` | Per-authority configuration for `/federation_extended_list` (see [Extended Subordinate Listing](#extended-subordinate-listing)) |
