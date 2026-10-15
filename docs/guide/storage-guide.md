# Storage guide

`@oidfed/authority` accepts one `StorageAdapter` for all non-key state. The bundled `MemoryStorageAdapter` is for development and tests only; production deployments need shared, durable implementations.

Federation key custody, public-key publication, and rollover use the separate `FederationKeyLifecycleProvider` contract.

## Adapter shape

```ts
import type {
  SubordinateStorage,
  TrustMarkStorage,
} from "@oidfed/authority";
import type { CacheProvider, ReplayStore } from "@oidfed/core";

interface StorageAdapter {
  readonly subordinates: SubordinateStorage;
  readonly trustMarks?: TrustMarkStorage;
  readonly replay?: ReplayStore;
  readonly cache?: CacheProvider;
  transaction<T>(operation: (tx: StorageTransaction) => Promise<T>): Promise<T>;
}

interface StorageTransaction {
  readonly subordinates: SubordinateStorage;
  readonly trustMarks?: TrustMarkStorage;
}
```

A production adapter should bind the nested repositories to one ORM/database client. `transaction()` must pass transaction-bound repositories, commit atomically, roll back on failure, and provide serializable isolation. The callback may be retried after serialization conflicts, so it must contain storage operations only.

Replay and cache are excluded from `StorageTransaction`: replay claiming is independently atomic, while cache data is non-authoritative.

## Subordinates

`SubordinateStorage` provides `get`, `list`, `add`, `update`, and `remove`.

- `entityId` is immutable; adapters preserve `createdAt` and manage `updatedAt` on updates. All three fields are excluded from `SubordinateRecordUpdate`. Direct `add()` calls supply a complete record, including timestamps; `registerSubordinate()` supplies those timestamps for you.
- Duplicate `add` and update/remove of unknown entities throw.
- Returned values are detached; mutation does not persist data.
- Listing is lexicographic by `entityId` with an inclusive first-unreturned cursor.
- Trust-mark filters include `validAt` and are evaluated by the adapter, allowing one database query instead of endpoint-level N+1 checks.
- `createdAt` and `updatedAt` are NumericDates.

Suggested relational columns: `entity_id TEXT PRIMARY KEY`, `jwks JSONB`, `metadata JSONB`, `metadata_policy JSONB`, `constraints JSONB`, `entity_types TEXT[]`, `is_intermediate BOOLEAN`, `source_endpoint TEXT`, `created_at DOUBLE PRECISION`, `updated_at DOUBLE PRECISION`.

## Trust marks

Trust-mark storage is optional. If an authority advertises a trust-mark endpoint, the capability is required at startup.

```ts
interface TrustMarkStorage {
  getValid(type: string, subject: EntityId, validAt: number): Promise<TrustMarkRecord | undefined>;
  getByJwt(jwt: string): Promise<TrustMarkRecord | undefined>;
  listValid(type: string, validAt: number, options: TrustMarkListOptions): Promise<TrustMarkListPage>;
  listValidForSubject(subject: EntityId, validAt: number): Promise<TrustMarkRecord[]>;
  hasAnyValid(subject: EntityId, validAt: number): Promise<boolean>;
  issue(record: TrustMarkRecord): Promise<void>;
  revoke(type: string, subject: EntityId, revokedAt: number): Promise<void>;
}
```

- A record is valid when it is active and either has no expiry or has `expiresAt > validAt`.
- Every issued JWT is preserved. Reissuance must not overwrite historical records.
- `getByJwt` identifies the exact issued token used by status responses.
- Issuing the same JWT is idempotent.
- Revocation records `active: false` and `revokedAt` without deleting the JWT.
- Listing is deterministic by subject. Its inclusive cursor identifies the first unreturned subject and must support complete traversal.

Suggested relational columns: `jwt_hash BYTEA PRIMARY KEY`, `jwt TEXT NOT NULL`, `trust_mark_type TEXT`, `subject TEXT`, `issued_at DOUBLE PRECISION`, `expires_at DOUBLE PRECISION`, `active BOOLEAN`, `revoked_at DOUBLE PRECISION`. Index `(trust_mark_type, subject, active, expires_at)` and `(subject, active, expires_at)`.

Hashing the JWT for indexing is acceptable, but `getByJwt` must compare the exact token and handle hash collisions safely.

## Replay protection

```ts
interface ReplayStore {
  useJti(claim: {
    issuer: string;
    audience: string;
    jti: string;
    expiresAt: number;
  }): Promise<boolean>;
}
```

`useJti` returns `true` only for a newly accepted tuple and `false` for replay. The operation must be atomic across every process serving the same OP tenant.

Use a unique database key on `(issuer, audience, jti)`, or an equivalent Redis key. Redis implementations should use one atomic `SET key 1 NX EX ttl` operation. Backend failures must fail closed; never evict unexpired claims to make capacity.

## Cache

`storage.cache` implements the existing `CacheProvider`. It is optional and non-authoritative. Authorities use it for federation fetch and trust-chain caching; it never participates in transactions.

Use a shared cache when processes should reuse remote Entity Configurations or statements. Cache loss must affect performance only, never correctness.

Cache TTLs are durations in seconds. `Clock.now()` returns NumericDate seconds since the Unix epoch, as do replay expiry, subordinate timestamps, and trust-mark timestamps.

## Keys

Federation key lifecycle remains separate from storage. A database may hold public key metadata and KMS references internally, but `FederationKeyLifecycleProvider` is the package contract that exposes signing, active federation JWKS publication, rotation, retirement, revocation, and historical federation keys.

Never place private JWK material in `StorageAdapter` or published federation JWKS.

The authority package exports the storage contracts and `MemoryStorageAdapter`. Its nested in-memory repository implementations are internal.

## Production checklist

- [ ] One adapter object owns all configured non-key capabilities.
- [ ] Authority transactions are serializable and roll back atomically.
- [ ] Subordinate cursors and ordering are deterministic.
- [ ] Trust-mark expiry, revocation history, and exact-JWT lookup are preserved.
- [ ] Replay claims are atomic and namespaced by issuer and audience.
- [ ] Replay failures fail closed.
- [ ] Cache is treated as disposable, non-authoritative data.
- [ ] All authoritative state is shared across deployment processes and survives restarts.
- [ ] Federation signer custody remains behind `FederationKeyLifecycleProvider`.
