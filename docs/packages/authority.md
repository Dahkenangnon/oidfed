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
| `/federation_resolve` | GET | Resolve trust chain |
| `/federation_registration` | POST | Explicit registration (§12) |
| `/federation_trust_mark_status` | POST | Trust mark validity |
| `/federation_trust_mark_list` | GET | Entities with trust mark |
| `/federation_trust_mark` | GET | Issue trust mark |
| `/federation_historical_keys` | GET | Historical signing keys |

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
  list(filter?: ListFilter): Promise<SubordinateRecord[]>;
  add(record: SubordinateRecord): Promise<void>;
  update(entityId: EntityId, updates: Partial<SubordinateRecord>): Promise<void>;
  remove(entityId: EntityId): Promise<void>;
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
}
```

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
  createResolveHandler,
  createRegistrationHandler,
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
| `registrationResponseTtlSeconds` | `number` | — | Registration response JWT lifetime |
| `trustMarkTtlSeconds` | `number` | — | Issued trust mark lifetime |
| `options` | `FederationOptions` | — | Core federation options (HTTP, cache, etc.) |
| `registrationConfig` | `object` | — | `generateClientSecret` hook for explicit registration |

## Dependencies

- `@oidfed/core` — federation primitives
