# Federation storage

Import the storage contract, errors, and development adapter from `@oidfed/core`. See the [adapter guide](../../features/11.6.storage-adapters.md) for startup requirements and the PostgreSQL example.

## `FederationStorage`

A handle represents one stable namespace. Its capability list describes the methods and guarantees available in that namespace. Supply it as `storage` on a Trust Anchor, Intermediate, or Leaf configuration. Standalone operations that take `FederationOptions` receive it in `options.storage`. A standalone `TrustMarkIssuerService` takes it in its service configuration.

```typescript signature
interface FederationStorage {
  readonly namespace: string;
  readonly capabilities: readonly StorageCapability[];
  readonly isolation?: "serializable";
  readonly subordinate?: SubordinateReadStore | SubordinateStore;
  readonly trustMark?: TrustMarkReadStore | TrustMarkStore;
  readonly subordinateEvent?: SubordinateEventReadStore | SubordinateEventStore;
  readonly entityCollection?: EntityCollectionStore;
  readonly replay?: ReplayStore;
  readonly cache?: CacheStore;

  withNamespace?(namespace: string): FederationStorage;
  transaction?<T>(operation: (view: TransactionView) => Promise<T>): Promise<T>;
  readSnapshot?<T>(operation: (view: ReadSnapshotView) => Promise<T>): Promise<T>;
  [Symbol.asyncDispose]?(): Promise<void>;
}
```

| Repository or boundary | Capabilities | Contract |
|---|---|---|
| `subordinate` | `subordinate:read`, `subordinate:write` | `fetch`, `list`, `register`, `update`, `remove`. Mutation rejects duplicate registration and updates or removal of an unknown subject. |
| `trustMark` | `trustMark:read`, `trustMark:write` | `candidates` includes inactive records for the selected issuer. `status(jwt)` reads the exact issuance. `valid`, `listSubjects`, `forSubject`, and `hasAny` use stored eligibility. `issue` and `revoke` change the revision on effective writes. |
| `subordinateEvent` | `subordinateEvent:read`, `subordinateEvent:write` | `append` and `history` scope events by issuer and subject. Preserve append order and retain history after registration removal. |
| `entityCollection` | `entityCollection` | `publish`, `current`, `snapshot`, `saveCursor`, `cursor`. Publish an immutable snapshot and advance its anchor pointer atomically. |
| `replay` | `replay` | `useJti` atomically claims an issuer, audience, and JTI through its absolute acceptance deadline. Either the first claim succeeds, replay and expiry return false, or storage rejects the operation. |
| `cache` | `cache` | `get`, `set`, `delete`, `clear`. Values are detached JSON and TTLs are positive durations in seconds. Missing or expired entries return undefined. |
| `transaction` | `transaction` | Set `isolation: "serializable"`. Commit all callback writes or roll them back. The backend can rerun the callback after a confirmed abort. |
| `readSnapshot` | `snapshot` | Use one consistent read-only view across subordinate, Trust Mark, and event data. |
| `withNamespace` | `namespace` | Return a handle for the requested namespace using the same backend. |
| `[Symbol.asyncDispose]` | Optional method | Dispose resources owned by this adapter. A namespace view borrows supplied clients. |

## Record validation

`StorageEntityIdSchema` uses the same validator and `EntityId` type as the protocol schema and `entityId()`. A Collection snapshot can use the returned identifier directly in `trustAnchor` and each `entity_id`.

Import the record schemas and parsers from `@oidfed/core`. Validate records after decoding and before committing a write.

| Data | Schema or parser |
|---|---|
| Subordinate | `SubordinateRecordSchema` checks shape. `parseSubordinateRecord` also checks publication claims, inline protocol JWKS, and the configured Federation key registry. `parseSubordinateUpdate` captures a patch before the repository merges it. |
| Trust Mark | `TrustMarkRecordSchema` checks the record against its compact JWT with the base Trust Mark profile, default registry, and default size limit. `parseStoredTrustMark` applies the configured limits and profile and can check expected identity. The ingestion flow verifies the signature and establishes issuer trust. |
| Trust Mark revision | `TrustMarkRevisionSchema` |
| Subordinate Events | `StoredSubordinateEventSchema` validates individual events. `SubordinateEventHistorySchema` validates a history payload. |
| Entity Collection | `CollectionEntrySchema`, `EntityCollectionSnapshotSchema`, and `EntityCollectionCursorSchema`. Each verified mark names the exact published JWT in its entry. |
| Replay claim | `JtiReplayClaimSchema` |
| Cache | `StorageJsonSchema` and `CacheWriteSchema` |

A durable lookup must also match its key to the returned record. The PostgreSQL example uses `parseStoragePayload` for this check and for payload validation.

```ts
import { parseStoragePayload, type StorageValidationOptions } from "@oidfed/core";

const validation: StorageValidationOptions = {};
const id = "https://member.example";
const write = (input: unknown) => parseStoragePayload("subordinate", id, input, "write", validation);
const read = (payload: unknown) => parseStoragePayload("subordinate", id, payload, "read", validation);
```

Use the record's optional `extensions` object for private JSON data. Put protocol extension claims in their protocol fields, such as a subordinate's `additionalClaims` or a published event object. A Subordinate Events history payload can hold private `extensions` beside its `events` array. The repository exchanges the event objects through `append` and `history`.

Reject malformed durable records. Core treats malformed cache values as misses under the operation’s fetch policy. Resolve checks the request identity, configured anchor, and evidence reuse deadline after parsing the cache value. Restrict write access to the resolver's cache.

## Scoped repositories

`ReadSnapshotView` exposes read methods on the declared subordinate, Trust Mark, and event repositories. `TransactionView` adds mutations declared by the parent. It uses `TrustMarkTransactionStore` for Trust Mark writes. The repository's `checkRevision(expected)` runs under the same serialization boundary as `issue` and `revoke`.

```typescript signature
interface ReadSnapshotView {
  readonly subordinate?: SubordinateReadStore;
  readonly trustMark?: TrustMarkReadStore;
  readonly subordinateEvent?: SubordinateEventReadStore;
}

interface TransactionView extends ReadSnapshotView {
  readonly subordinate?: SubordinateReadStore | SubordinateStore;
  readonly trustMark?: TrustMarkReadStore | TrustMarkTransactionStore;
  readonly subordinateEvent?: SubordinateEventReadStore | SubordinateEventStore;
}
```

Use `storageSnapshot(storage, callback, options?)` and `storageTransaction(storage, callback, options?)` to validate and guard adapter views. Supply `algorithmRegistry`, `customPolicyOperators`, `trustMarkProfiles`, and `maxCompactBytes` when Core needs to apply deployment settings at the call boundary. With no options, the helpers check record shape and leave contextual validation to the adapter. A snapshot can set `allowTransaction: true` to use a read-only view of a serializable transaction.

Use only the supplied view and await every repository call. Keep network requests, signing, key lookups, and application callbacks outside the scope.

Use `assertStorageView(tx, ["trustMark:write"], "Issue Trust Mark")` inside a transaction to narrow the repository before calling `tx.trustMark.checkRevision(expected)`. Capture `expected` with the candidates in a consistent read snapshot. [Storage contract](../../../packages/core/src/storage/contracts.ts)

## Validation and composition

- `describeStorageRequirements(...features)` returns the capabilities implied by the named features. Subordinate Events history also requires either a read snapshot or a serializable transaction.
- `assertStorageCapabilities(storage, required, operation?)` validates the handle and required methods. `assertStorageView` checks and narrows a scoped view.
- `StorageCapabilityError` names the operation, capability, and missing method when applicable.
- `composeFederationStorage({ base, entityCollection?, replay?, cache? })` combines handles with the same namespace. Keep repositories used in the same transaction or snapshot on `base`. The composition borrows each part and leaves client ownership with the application.

## `MemoryFederationStorage`

`new MemoryFederationStorage({ namespace, capabilities?, clock?, engine?, algorithmRegistry?, customPolicyOperators?, trustMarkProfiles?, maxReplayEntries?, maxCacheEntries?, maxCompactBytes?, collection? })`

The constructor enables all capabilities by default. A capability list lets you use only the repositories and boundaries you need. Rebinding through `withNamespace` shares the adapter's in-process backing state for each name. Separate adapter instances have separate state. Use an explicit `clock` to test expiration. An optional crypto engine hashes replay keys to fixed-size digests. Match the host’s registry, policy operators, Trust Mark profiles, and compact token limit. Use durable replay storage if the receiver accepts proofs across restarts. A memory store loses live claims even when only one process serves the receiver.

See the [PostgreSQL example](../../../examples/adapters/README.md) and the [storage migration guide](../migration-v3.md#federation-storage).
