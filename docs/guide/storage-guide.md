# Storage guide

`@oidfed/authority` accepts one `StorageAdapter` for its authority-owned state: subordinate records and configured Trust Mark, event, collection, replay, and cache capabilities. OIDC registrations and sessions, wallet protocol state, and role-specific replay stores use separate integration points. The bundled `MemoryStorageAdapter` is for development and tests only; production deployments need shared, durable implementations.

Federation key custody, public-key publication, and rollover use the separate `FederationKeyLifecycleProvider` contract.

See [operator and application responsibilities](operator-responsibilities.md) for ownership boundaries and specification requirements.

## Adapter shape

```ts
import type {
  SubordinateStorage,
  SubordinateEventStorage,
  TrustMarkStorage,
} from "@oidfed/authority";
import type { CacheProvider, EntityCollectionStore, ReplayStore } from "@oidfed/core";

interface StorageAdapter {
  readonly subordinates: SubordinateStorage;
  readonly trustMarks?: TrustMarkStorage;
  readonly subordinateEvents?: SubordinateEventStorage;
  readonly collections?: EntityCollectionStore;
  readonly replay?: ReplayStore;
  readonly cache?: CacheProvider;
  transaction<T>(operation: (tx: StorageTransaction) => Promise<T>): Promise<T>;
}

interface StorageTransaction {
  readonly subordinates: SubordinateStorage;
  readonly trustMarks?: TrustMarkStorage;
  readonly subordinateEvents?: SubordinateEventStorage;
}
```

Each adapter represents one logical authority namespace. Processes serving the same authority must share that state; distinct authority identifiers need separate namespaces. The subordinate and trust-mark contracts do not receive an authority identifier on each call, so a shared database adapter must bind its queries to the configured authority.

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

Suggested relational columns: `authority_id TEXT`, `entity_id TEXT`, `PRIMARY KEY (authority_id, entity_id)`, `jwks JSONB`, `metadata JSONB`, `metadata_policy JSONB`, `constraints JSONB`, `entity_types TEXT[]`, `is_intermediate BOOLEAN`, `source_endpoint TEXT`, `created_at DOUBLE PRECISION`, `updated_at DOUBLE PRECISION`.

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

Suggested relational columns: `authority_id TEXT`, `jwt_hash BYTEA`, `PRIMARY KEY (authority_id, jwt_hash)`, `jwt TEXT NOT NULL`, `trust_mark_type TEXT`, `subject TEXT`, `issued_at DOUBLE PRECISION`, `expires_at DOUBLE PRECISION`, `active BOOLEAN`, `revoked_at DOUBLE PRECISION`. Prefix trust-mark indexes with `authority_id`, for example `(authority_id, trust_mark_type, subject, active, expires_at)` and `(authority_id, subject, active, expires_at)`.

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

`useJti` returns `true` only for a newly accepted tuple and `false` for replay. The operation must be atomic across every process serving the same receiver, including Federation Entities and OPs. Authority endpoint authentication middleware requires `storage.replay` when `private_key_jwt` is configured; anonymous endpoints do not. The shared Collection service accepts its own replay store, uses authority replay storage when available, or falls back to memory. Production instances must share the configured replay state. Replay records remain live through the accepted clock-skew window.

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

- [ ] Each adapter binds its repositories to one logical authority namespace.
- [ ] One adapter object owns the authority's configured storage capabilities; protocol-role stores are configured separately.
- [ ] Authority transactions are serializable and roll back atomically.
- [ ] Subordinate cursors and ordering are deterministic.
- [ ] Trust-mark expiry, revocation history, and exact-JWT lookup are preserved.
- [ ] Replay claims are atomic and namespaced by issuer and audience.
- [ ] Replay failures fail closed.
- [ ] Cache is treated as disposable, non-authoritative data.
- [ ] All authoritative state is shared across deployment processes and survives restarts.
- [ ] Federation signer custody remains behind `FederationKeyLifecycleProvider`.

## Subordinate events

`subordinateEvents` is an optional history repository scoped by authority issuer and subordinate subject. Authorities advertising the Subordinate Events endpoint require it. Configure the memory implementation with `new MemoryStorageAdapter({ subordinateEvents: true })`.

```ts
interface SubordinateEventStorage {
  append(issuer: EntityId, subject: EntityId, events: readonly SubordinateEvent[]): Promise<void>;
  list(issuer: EntityId, subject: EntityId): Promise<readonly SubordinateEvent[]>;
}
```

`SubordinateEvent` comes from `@oidfed/core`. Events use numeric epoch seconds in `iat`, an extensible `event` string, and optional `event_description` and `information_uri`. Preserve supplied occurrence times and append order, including ties and repeated event types. Return detached values. A caller must not be able to mutate persisted events through input objects or returned values.

Keep history independent of the current subordinate row. Removing that row must not delete events, and re-registration extends its existing history. Do not backfill from `createdAt` or `updatedAt`, silently prune records, or truncate responses. Durable retention and issuer/subject isolation are responsibilities of the production adapter.

Automatic capture occurs through `registerSubordinate`, `updateSubordinate`, and `revokeSubordinate`. Registration and updates snapshot caller inputs before waiting for a transaction. Their callbacks use transaction-bound repositories and commit state and generated events together. An events-enabled adapter must supply `tx.subordinateEvents`; otherwise the authority fails before mutation. Rollback and serialization retries must leave no changes from failed attempts.

Direct storage writes remain untracked. Applications using them can explicitly append in the same transaction:

```ts
await storage.transaction(async (tx) => {
  if (!tx.subordinateEvents) throw new Error("Event storage is required");
  await tx.subordinates.remove(subject);
  await tx.subordinateEvents.append(issuer, subject, [
    { iat: Math.floor(Date.now() / 1000), event: "revocation" },
  ]);
});
```

Only record `revocation` when the removal represents an actual revocation. Technical cleanup alone does not establish that meaning. The transaction callback may run again after a conflict; keep signing and network operations outside it.

## Collection snapshots

Entity Collection stores snapshots separately from subordinate registration records, using the core `EntityCollectionStore` contract. The service uses `collection.store` when supplied, then `storage.collections`, then its own memory store. Enable the storage capability with `MemoryStorageAdapter({ collections: true })`.

The service publishes each snapshot atomically after collection, outside registration transactions. A store shared across instances must isolate anchors, retain snapshots and opaque cursors, enforce expiry, and return detached values. See [Entity Collection](entity-collection.md#refresh-and-storage).

Collection entries have an `expiresAt` eligibility deadline and may also carry `chainExpiresAt` evidence. Custom collectors do not need to provide chain evidence. Core derives the mark evidence used for filtering during refresh. Keep these internal fields separate from the public entity data when persisting snapshots.
