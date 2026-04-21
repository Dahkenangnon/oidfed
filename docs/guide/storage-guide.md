# Storage Guide

In-memory storage implementations are provided for development and testing. They are **not suitable for production** — state is lost on restart and cannot be shared across processes.

## Overview

| Interface | Package | In-memory default | Purpose |
|-----------|---------|-------------------|---------|
| `SubordinateStore` | `@oidfed/authority` | `MemorySubordinateStore` | Subordinate entity records |
| `KeyStore` | `@oidfed/authority` | `MemoryKeyStore` | Signing key lifecycle |
| `TrustMarkStore` | `@oidfed/authority` | `MemoryTrustMarkStore` | Issued trust marks and revocations |
| `JtiStore` | `@oidfed/core` | `InMemoryJtiStore` | JWT replay prevention |
| `CacheProvider` | `@oidfed/core` | `MemoryCache` | Entity config / trust chain cache |

## SubordinateStore

```ts
import type { SubordinateStore, SubordinateRecord, ListFilter } from "@oidfed/authority";
```

```ts
interface SubordinateStore {
  get(entityId: EntityId): Promise<SubordinateRecord | undefined>;
  list(filter?: ListFilter): Promise<SubordinateRecord[]>;
  add(record: SubordinateRecord): Promise<void>;
  update(entityId: EntityId, updates: Partial<SubordinateRecord>): Promise<void>;
  remove(entityId: EntityId): Promise<void>;
}
```

**Contract:**
- `add()` MUST reject if `entityId` already exists.
- `update()` and `remove()` MUST reject if `entityId` does not exist.
- `list()` MUST support filtering by `entityTypes` (intersection) and `intermediate` (boolean).
- `metadata`, `metadataPolicy`, `constraints` are JSON objects — store as JSONB or embedded documents.
- `jwks` is a JWK Set — store as JSON/BSON.

**Minimal schema hint (PostgreSQL columns):** `entity_id TEXT PK`, `jwks JSONB`, `metadata JSONB`, `metadata_policy JSONB`, `constraints JSONB`, `entity_types TEXT[]`, `is_intermediate BOOLEAN`, `source_endpoint TEXT`, `created_at FLOAT8`, `updated_at FLOAT8`. Index `entity_types` with GIN.

**Minimal schema hint (MongoDB fields):** `entityId` (unique index), `entityTypes` (index), `isIntermediate` (index), `jwks`, `metadata`, `metadataPolicy`, `constraints`, `sourceEndpoint`, `createdAt`, `updatedAt`.

## KeyStore

```ts
import type { KeyStore, KeyState, ManagedKey } from "@oidfed/authority";
```

```ts
// Key lifecycle: pending → active → retiring → revoked
interface KeyStore {
  getActiveKeys(): Promise<JWKSet>;              // active + retiring keys (public only)
  getSigningKey(): Promise<ManagedKey>;           // most recently activated key
  getHistoricalKeys(): Promise<ManagedKey[]>;     // all keys ever (for historical JWKS endpoint)
  addKey(key: JWK): Promise<void>;               // adds in "pending" state
  activateKey(kid: string): Promise<void>;        // pending → active
  retireKey(kid: string, removeAfter: number): Promise<void>; // active → retiring
  revokeKey(kid: string, reason: string): Promise<void>;      // any → revoked
}
```

**Contract:**
- `getSigningKey()` MUST return the most recently activated key (by `activatedAt`).
- `getActiveKeys()` MUST strip private key fields (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`).
- `addKey()` MUST reject duplicate `kid` values.
- `activateKey()` MUST reject if key is not in `pending` state.
- `retireKey()` MUST reject if key is not in `active` state.

**Minimal schema hint (PostgreSQL columns):** `kid TEXT PK`, `public_jwk JSONB`, `private_key_ref TEXT` (secrets manager reference), `state TEXT CHECK(pending|active|retiring|revoked)`, `created_at FLOAT8`, `activated_at FLOAT8`, `expires_at FLOAT8`, `scheduled_removal_at FLOAT8`, `revoked_at FLOAT8`, `revocation_reason TEXT`. Index `(state, activated_at DESC)`.

**Minimal schema hint (MongoDB fields):** `kid` (unique index), `publicJwk`, `privateKeyRef`, `state` (index with `activatedAt`), `createdAt`, `activatedAt`, `expiresAt`, `scheduledRemovalAt`, `revokedAt`, `revocationReason`.

## TrustMarkStore

```ts
import type { TrustMarkStore, TrustMarkRecord } from "@oidfed/authority";
```

```ts
interface TrustMarkStore {
  get(trustMarkType: string, subject: EntityId): Promise<TrustMarkRecord | undefined>;
  list(trustMarkType: string, options?: {
    sub?: EntityId; cursor?: string; limit?: number;
  }): Promise<{ items: TrustMarkRecord[]; nextCursor?: string }>;
  issue(record: TrustMarkRecord): Promise<void>;
  revoke(trustMarkType: string, subject: EntityId): Promise<void>;
  isActive(trustMarkType: string, subject: EntityId): Promise<boolean>;
  hasAnyActive(subject: EntityId): Promise<boolean>;
}
```

**Contract:**
- `issue()` MUST upsert — re-issuing replaces the previous record.
- `revoke()` MUST set `active = false` but keep the record (audit trail).
- `list()` MUST support cursor-based pagination.
- `isActive()` and `hasAnyActive()` are hot-path — index accordingly.

**Minimal schema hint (PostgreSQL columns):** `trust_mark_type TEXT`, `subject TEXT`, PK `(trust_mark_type, subject)`, `jwt TEXT`, `issued_at FLOAT8`, `expires_at FLOAT8`, `active BOOLEAN`. Index `(subject, active)`.

**Minimal schema hint (MongoDB fields):** `trustMarkType` + `subject` (compound unique index), `subject` + `active` (index), `jwt`, `issuedAt`, `expiresAt`, `active`.

## JtiStore

```ts
import type { JtiStore } from "@oidfed/core";
```

```ts
interface JtiStore {
  hasSeenAndRecord(jti: string, expiresAt: number): Promise<boolean>;
}
```

**Contract:**
- `hasSeenAndRecord()` MUST be **atomic** — check and record with no race window. Exactly one concurrent caller for the same JTI MUST receive `false`; all others MUST receive `true`.
- Implementations SHOULD auto-purge entries after `expiresAt`.
- For multi-process deployments the store MUST be shared (Redis or database).

**Minimal schema hint (PostgreSQL columns):** `jti TEXT PK`, `expires_at FLOAT8`. Schedule `DELETE FROM seen_jtis WHERE expires_at < extract(epoch from now())`.

**Minimal schema hint (MongoDB fields):** `jti` (unique index for atomic insert), `expiresAt` (TTL index with `expireAfterSeconds: 0`, store as `Date`).

**Minimal schema hint (Redis):** `SET jti:<value> 1 EX <ttl> NX` — `NX` provides atomicity; TTL handles auto-purge.

## CacheProvider

```ts
import type { CacheProvider } from "@oidfed/core";
```

```ts
interface CacheProvider {
  get<T>(key: string): Promise<T | undefined>;
  set<T>(key: string, value: T, ttlSeconds: number): Promise<void>;
  delete(key: string): Promise<void>;
  clear(): Promise<void>;
}
```

**Contract:**
- `get()` MUST return `undefined` for expired or missing entries.
- `set()` MUST respect `ttlSeconds`.
- The cache is optional. Omitting it causes fresh fetches every time — the safest store to leave as in-memory even in production.

A shared cache is beneficial when running multiple Node.js processes, in serverless environments, or to reduce load on federation endpoints during high traffic.

## Security Considerations

Private key material (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`) MUST be encrypted at rest. The recommended pattern is to store only public key components in the database and keep private key material in a secrets manager (HashiCorp Vault, AWS KMS, Azure Key Vault), referencing keys by ID in the `private_key_ref` / `privateKeyRef` column.

## Production Checklist

- [ ] **SubordinateStore** — backed by a persistent database
- [ ] **KeyStore** — private keys in a secrets manager; public keys + state in database
- [ ] **TrustMarkStore** — backed by a persistent database with revocation preserved
- [ ] **JtiStore** — backed by Redis or database with atomic check-and-set
- [ ] **CacheProvider** — optional; use a shared cache if running multiple processes
- [ ] All stores survive process restarts
- [ ] All stores are accessible from all processes in your deployment
- [ ] JtiStore atomicity verified under concurrent load
- [ ] Key material encrypted at rest
