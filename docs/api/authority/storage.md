# Storage and transactions

[`@oidfed/authority`](README.md)

Adapters own authoritative subordinate, Trust Mark, and event state. Keep transaction updates atomic and return independent snapshots. Memory implementations serve a single process and are useful for tests and local deployments.

## `ListFilter`

[Source](../../../packages/authority/src/storage/types.ts#L104)

Filters for subordinate storage. Entity types and Trust Mark types use OR semantics within each list; different filters combine. `intermediate: false` selects non-intermediates, while `trustMarked: false` adds no mark restriction. Trust Mark filtering requires both an enabled mark repository and `validAt`. Custom Entity Type Identifiers remain valid filter values.

```typescript signature
interface ListFilter {
	/**
	 * Matches records having ANY of the listed types (union semantics).
	 * Federation §8.2.1's "include all specified Entity Types" condenses
	 * explicitly-OR drafting (openid/federation ee7a372f → 49d194e3), and
	 * Entity Collection Draft 01 clarifies the same sentence to "any of".
	 * Values are open-ended identifiers (Federation §5.1, no registry):
	 * custom adapters must not reject unknown values — filter and report no
	 * matches instead.
	 */
	entityTypes?: EntityTypeIdentifier[];
	/** When true, require a valid issued mark. False adds no restriction. */
	trustMarked?: boolean;
	/** Match any of the supplied Trust Mark types. */
	trustMarkType?: string | ReadonlyArray<string>;
	/** True selects intermediates; false selects non-intermediates; omission selects both. */
	intermediate?: boolean;
	/** Required when trustMarked is true or trustMarkType is provided. */
	validAt?: number;
}
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `entityTypes?` | `EntityTypeIdentifier[]` | Matches records having ANY of the listed types (union semantics). Federation §8.2.1's "include all specified Entity Types" condenses explicitly-OR drafting (openid/federation ee7a372f → 49d194e3), and Entity Collection Draft 01 clarifies the same sentence to "any of". Values are open-ended identifiers (Federation §5.1, no registry): custom adapters must not reject unknown values — filter and report no matches instead. |
| `trustMarked?` | `boolean` | When true, require a valid issued mark. False adds no restriction. |
| `trustMarkType?` | `string \| ReadonlyArray<string>` | Match any of the supplied Trust Mark types. |
| `intermediate?` | `boolean` | True selects intermediates; false selects non-intermediates; omission selects both. |
| `validAt?` | `number` | Required when trustMarked is true or trustMarkType is provided. |

## `ListPage`

[Source](../../../packages/authority/src/storage/types.ts#L65)

A detached page of subordinate records in lexicographic Entity Identifier order. `nextCursor` names the first unreturned position and is inclusive on the next call. An empty filtered page can still carry a continuation; omission means the scan is exhausted.

```typescript signature
interface ListPage {
	readonly items: SubordinateRecord[];
	/**
	 * First unreturned position, strictly after the incoming cursor and returned records.
	 * May accompany an empty page. Omission means the scan is exhausted.
	 */
	readonly nextCursor?: EntityId;
}
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `items` | `SubordinateRecord[]` | Detached matching records in lexicographic Entity Identifier order. |
| `nextCursor?` | `EntityId` | First unreturned position, strictly after the incoming cursor and returned records. May accompany an empty page. Omission means the scan is exhausted. |

## `ListPageOptions`

[Source](../../../packages/authority/src/storage/types.ts#L57)

Storage-level pagination and time filters. The cursor is inclusive. `updatedAfter` and `updatedBefore` compare NumericDates inclusively against `updatedAt`. With no page options, the storage contract returns every matching record. HTTP page-size validation is a separate endpoint concern.

```typescript signature
interface ListPageOptions {
	/** EntityId of the first record to return. */
	cursor?: EntityId;
	limit?: number;
	updatedAfter?: number;
	updatedBefore?: number;
}
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `cursor?` | `EntityId` | Inclusive Entity Identifier of the first record to return. |
| `limit?` | `number` | Optional storage page cap. Without page options the contract returns all matches; endpoint page-size rules are separate. |
| `updatedAfter?` | `number` | Inclusive lower bound on a record's updatedAt NumericDate. |
| `updatedBefore?` | `number` | Inclusive upper bound on a record's updatedAt NumericDate. |

## `MemoryStorageAdapter`

[Source](../../../packages/authority/src/storage/memory.ts#L236)

Process-local storage with subordinate records, replay protection, and cache always available. Trust Mark, subordinate-event, and collection repositories are opt-in. State is lost on restart and is not shared across processes.

Transactions serialize access, apply writes to a detached draft, and commit that draft only when the callback succeeds. `readSnapshot` serializes a read with writes. Use only the callback’s repositories inside either boundary; waiting for a queued parent mutation there can deadlock. Neither callback boundary includes replay, cache, or collection state.

```typescript signature
new MemoryStorageAdapter(options?: MemoryStorageAdapterOptions): MemoryStorageAdapter;
```

### `MemoryStorageAdapter#collections`

The adapter's Entity Collection snapshot storage.

[Source](../../../packages/authority/src/storage/memory.ts#L237)

```typescript signature
readonly collections?: EntityCollectionStore;
```

### `MemoryStorageAdapter#subordinates`

The adapter's subordinate-record repository.

[Source](../../../packages/authority/src/storage/memory.ts#L241)

```typescript signature
readonly subordinates: SubordinateStorage;
```

### `MemoryStorageAdapter#trustMarks`

The adapter's Trust Mark record repository.

[Source](../../../packages/authority/src/storage/memory.ts#L242)

```typescript signature
readonly trustMarks?: TrustMarkStorage;
```

### `MemoryStorageAdapter#subordinateEvents`

The optional subordinate-event repository.

[Source](../../../packages/authority/src/storage/memory.ts#L243)

```typescript signature
readonly subordinateEvents?: SubordinateEventStorage;
```

### `MemoryStorageAdapter#replay`

The adapter's replay-protection capability.

[Source](../../../packages/authority/src/storage/memory.ts#L244)

```typescript signature
readonly replay: MemoryReplayStore;
```

### `MemoryStorageAdapter#cache`

Cache used by the owning adapter or service. Callers choose retention; consumers must still enforce signed evidence lifetimes.

[Source](../../../packages/authority/src/storage/memory.ts#L245)

```typescript signature
readonly cache: MemoryCache;
```

### `MemoryStorageAdapter#readSnapshot`

Serialize the read with writes; clone only the requested records.

[Source](../../../packages/authority/src/storage/memory.ts#L279)

```typescript signature
readSnapshot<T>(operation: (snapshot: StorageReadSnapshot) => Promise<T>): Promise<T>;
```

### `MemoryStorageAdapter#transaction`

Commit callback writes atomically, or roll them back on failure. Use only tx repositories: awaiting a parent queued mutation inside the callback can deadlock.

[Source](../../../packages/authority/src/storage/memory.ts#L310)

```typescript signature
transaction<T>(operation: (tx: StorageTransaction) => Promise<T>): Promise<T>;
```

## `MemoryStorageAdapterOptions`

[Source](../../../packages/authority/src/storage/memory.ts#L226)

Options for the bundled in-memory adapter. Omitted repository flags leave those repositories unavailable. `clock` controls adapter update times, replay checks, and cache expiry; configure the authority’s own clock separately through `AuthorityConfig.options` when they must agree.

```typescript signature
interface MemoryStorageAdapterOptions {
	readonly collections?: boolean;
	readonly subordinateEvents?: boolean;
	readonly trustMarks?: boolean;
	readonly clock?: Clock;
	readonly maxReplayEntries?: number;
	readonly maxCacheEntries?: number;
}
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `collections?` | `boolean` | Enable process-local collection snapshots and cursors. Omitted/false leaves collections undefined. |
| `subordinateEvents?` | `boolean` | Enable retained subordinate history. Omitted/false leaves subordinateEvents undefined. |
| `trustMarks?` | `boolean` | Enable Trust Mark records and issuer operations. Omitted/false leaves trustMarks undefined. |
| `clock?` | `Clock` | NumericDate clock used by adapter updates, replay storage, cache, and optional collection storage. Defaults to the underlying components' system clocks. |
| `maxReplayEntries?` | `number` | Replay-store capacity. Defaults to 10,000; must be a positive safe integer. Live claims are not evicted to admit another claim. |
| `maxCacheEntries?` | `number` | LRU cache entry limit forwarded to MemoryCache. Defaults to 1,000. |

## `StorageAdapter`

[Source](../../../packages/authority/src/storage/types.ts#L16)

Persistence contract supplied to an authority. `subordinates` and `transaction` are required. Trust Mark, event, replay, cache, collection, and read-snapshot capabilities are optional in the type but required by operations that use them. Trust Mark listing and issuance selection require `readSnapshot` with its Trust Mark view.

Transactions must commit all supplied repository writes atomically or roll them back on failure. Repositories return detached data. Cache, replay, and collection repositories are not part of `StorageTransaction`.

```typescript signature
interface StorageAdapter {
	readonly collections?: EntityCollectionStore;
	readonly subordinateEvents?: SubordinateEventStorage;
	readonly subordinates: SubordinateStorage;
	readonly trustMarks?: TrustMarkStorage;
	readonly replay?: ReplayStore;
	readonly cache?: CacheProvider;
	/** Commit callback writes atomically, or roll them back on failure. Use only tx repositories: awaiting a parent queued mutation inside the callback can deadlock. */
	transaction<T>(operation: (tx: StorageTransaction) => Promise<T>): Promise<T>;
	/** Read one consistent, detached view. Use only supplied repositories; do not await parent writes from inside the callback. */
	readSnapshot?<T>(operation: (snapshot: StorageReadSnapshot) => Promise<T>): Promise<T>;
}
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `collections?` | `EntityCollectionStore` | Optional collection snapshot/cursor store, outside subordinate transactions. |
| `subordinateEvents?` | `SubordinateEventStorage` | Optional retained history repository; required when publishing the Events endpoint or recording history. |
| `subordinates` | `SubordinateStorage` | Required authoritative subordinate-record repository. |
| `trustMarks?` | `TrustMarkStorage` | Optional issuer record repository; required for hosted Trust Mark endpoints and managed issuer operations. |
| `replay?` | `ReplayStore` | Optional shared assertion-replay store; required for authority endpoints configured with private_key_jwt. |
| `cache?` | `CacheProvider` | Optional cache used by hosted endpoint operations. Cache state is outside subordinate transactions. |
| `transaction` | `<T>(operation: (tx: StorageTransaction) => Promise<T>) => Promise<T>` | Execute against transaction-bound repositories and commit all writes together, or roll back on rejection. |
| `readSnapshot?` | `<T>(operation: (snapshot: StorageReadSnapshot) => Promise<T>) => Promise<T>` | Read detached records from one consistent view. Trust Mark selection operations require this capability and its Trust Mark view. |

## `StorageReadSnapshot`

[Source](../../../packages/authority/src/storage/types.ts#L30)

Read-only repository view containing subordinate `get`/`list`, optional Trust Mark `listCandidates`/`getByJwt`, and optional subordinate-event `list`. It exposes no mutations. Implementations must return detached data from one consistent view.

```typescript signature
interface StorageReadSnapshot {
	readonly trustMarks?: Pick<TrustMarkStorage, "listCandidates" | "getByJwt">;
	readonly subordinates: Pick<SubordinateStorage, "get" | "list">;
	readonly subordinateEvents?: Pick<SubordinateEventStorage, "list">;
}
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `trustMarks?` | `Pick<TrustMarkStorage, "listCandidates" \| "getByJwt">` | Optional read-only Trust Mark candidate enumeration and JWT lookup. |
| `subordinates` | `Pick<SubordinateStorage, "get" \| "list">` | Read-only subordinate get/list operations. |
| `subordinateEvents?` | `Pick<SubordinateEventStorage, "list">` | Optional read-only event-history lookup. |

## `StorageTransaction`

[Source](../../../packages/authority/src/storage/types.ts#L36)

Repositories available inside an atomic write transaction: subordinates, plus Trust Marks and subordinate events when enabled. Replay, cache, and collection operations are not included. Use the transaction-bound repositories, not the parent adapter.

```typescript signature
interface StorageTransaction {
	readonly subordinateEvents?: SubordinateEventStorage;
	readonly subordinates: SubordinateStorage;
	readonly trustMarks?: TrustMarkStorage;
}
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `subordinateEvents?` | `SubordinateEventStorage` | Transaction-bound history reads and appends when enabled. |
| `subordinates` | `SubordinateStorage` | Transaction-bound subordinate reads and mutations. |
| `trustMarks?` | `TrustMarkStorage` | Transaction-bound Trust Mark operations when that capability is enabled. |

## `SubordinateEventAnnotations`

[Source](../../../packages/authority/src/storage/types.ts#L95)

Optional descriptions applied to every event generated by one authority lifecycle call. Supplying annotations requires event storage. `informationUri` must be a valid event URI; non-HTTPS values are permitted and produce an informational recommendation after a successful event commit.

```typescript signature
interface SubordinateEventAnnotations {
	readonly eventDescription?: string;
	readonly informationUri?: string;
}
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `eventDescription?` | `string` | Description attached to every event generated by the lifecycle call. |
| `informationUri?` | `string` | Event information URI. HTTPS is recommended; valid non-HTTPS URIs are accepted and logged after commit. |

## `SubordinateEventStorage`

[Source](../../../packages/authority/src/storage/types.ts#L135)

History repository scoped by issuer and subject. Preserve append order, equal timestamps, duplicate events, and nested extension data. Reads and writes detach values. Removing a registration must retain its history. Transaction-bound appends commit with the associated registration changes.

```typescript signature
interface SubordinateEventStorage {
	append(issuer: EntityId, subject: EntityId, events: readonly SubordinateEvent[]): Promise<void>;
	list(issuer: EntityId, subject: EntityId): Promise<readonly SubordinateEvent[]>;
}
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `append` | `(issuer: EntityId, subject: EntityId, events: readonly SubordinateEvent[]) => Promise<void>` | Append detached validated events under the issuer/subject pair, preserving order and duplicates. |
| `list` | `(issuer: EntityId, subject: EntityId) => Promise<readonly SubordinateEvent[]>` | Return a detached history array for the issuer/subject pair. |

## `SubordinateRecord`

[Source](../../../packages/authority/src/storage/types.ts#L74)

Complete stored subordinate state, including the immutable Entity Identifier, attested keys, publication claims, and creation/update NumericDates. `registerSubordinate()` accepts the record without timestamps and supplies them; a direct adapter `add()` requires both timestamps. Operational federation endpoint metadata belongs in the subordinate’s own Entity Configuration, not this record’s Superior-supplied metadata.

```typescript signature
interface SubordinateRecord extends EntityStatementExtensions {
	/** Immutable entity identifier. */
	readonly entityId: EntityId;
	readonly jwks: JWKSet;
	readonly metadata?: Readonly<Record<string, unknown>>;
	readonly metadataPolicy?: Readonly<Record<string, unknown>>;
	readonly constraints?: Readonly<TrustChainConstraints>;
	/** Entity Types published by the subordinate. Open value space — Federation §5.1 permits identifiers beyond the published set. */
	readonly entityTypes?: ReadonlyArray<EntityTypeIdentifier>;
	readonly isIntermediate?: boolean;
	readonly sourceEndpoint?: string;
	readonly metadataPolicyCrit?: ReadonlyArray<string>;
	/** Adapter-managed creation NumericDate. */
	readonly createdAt: number;
	/** Adapter-managed update NumericDate. */
	readonly updatedAt: number;
}
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `entityId` | `EntityId` | Immutable registered subordinate identifier. |
| `jwks` | `JWKSet` | Attested subordinate public Federation Entity Keys embedded in the Subordinate Statement. The authority signs it with its own key provider. |
| `metadata?` | `Readonly<Record<string, unknown>>` | Optional Superior-supplied protocol/informational metadata. Operational federation fields are prohibited in stored federation_entity metadata. |
| `metadataPolicy?` | `Readonly<Record<string, unknown>>` | Metadata-policy declaration included in the subordinate's statement. |
| `constraints?` | `Readonly<TrustChainConstraints>` | Constraints declared on this subordinate and applicable downstream paths. |
| `entityTypes?` | `ReadonlyArray<EntityTypeIdentifier>` | Published Entity Type Identifiers used for storage filtering. Custom values remain valid. |
| `isIntermediate?` | `boolean` | Stored Intermediate classification used by listing filters. |
| `sourceEndpoint?` | `string` | Optional source_endpoint claim identifying where this Subordinate Statement is available. |
| `metadataPolicyCrit?` | `ReadonlyArray<string>` | Nonstandard policy operators recipients must understand. Standard operator names are prohibited. |
| `createdAt` | `number` | Required creation NumericDate for raw storage insertion; the authority registration method supplies it. |
| `updatedAt` | `number` | Required update NumericDate for raw insertion; memory updates replace it with the adapter clock. |
| `additionalClaims?` | `Readonly<Record<string, unknown>> \| undefined` | Custom top-level claims; standard Entity Statement claims cannot be overridden. |
| `crit?` | `readonly string[] \| undefined` | Extension claims recipients MUST understand and process (Federation §13.4). |

## `SubordinateRecordUpdate`

[Source](../../../packages/authority/src/storage/types.ts#L100)

Partial update excluding `entityId`, `createdAt`, and `updatedAt`. Omitted fields retain their current values. The memory adapter merges updates inside the write transaction and sets `updatedAt` from its own clock. Direct repository updates do not generate lifecycle events.

```typescript signature
type SubordinateRecordUpdate = Partial<
	Omit<SubordinateRecord, "entityId" | "createdAt" | "updatedAt">
>;
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `jwks?` | `JWKSet` | Attested subordinate public Federation Entity Keys embedded in the Subordinate Statement. The authority signs it with its own key provider. |
| `metadata?` | `Readonly<Record<string, unknown>>` | Optional Superior-supplied protocol/informational metadata. Operational federation fields are prohibited in stored federation_entity metadata. |
| `constraints?` | `Readonly<TrustChainConstraints>` | Constraints declared on this subordinate and applicable downstream paths. |
| `crit?` | `readonly string[] \| undefined` | Extension claims recipients MUST understand and process (Federation §13.4). |
| `additionalClaims?` | `Readonly<Record<string, unknown>> \| undefined` | Custom top-level claims; standard Entity Statement claims cannot be overridden. |
| `metadataPolicy?` | `Readonly<Record<string, unknown>>` | Metadata-policy declaration included in the subordinate's statement. |
| `sourceEndpoint?` | `string` | Optional source_endpoint claim identifying where this Subordinate Statement is available. |
| `metadataPolicyCrit?` | `ReadonlyArray<string>` | Nonstandard policy operators recipients must understand. Standard operator names are prohibited. |
| `entityTypes?` | `ReadonlyArray<EntityTypeIdentifier>` | Published Entity Type Identifiers used for storage filtering. Custom values remain valid. |
| `isIntermediate?` | `boolean` | Stored Intermediate classification used by listing filters. |

## `SubordinateStorage`

[Source](../../../packages/authority/src/storage/types.ts#L42)

Subordinate repository contract. Reads return detached data; writes capture input before queued work. `add` rejects duplicate identifiers; `update` rejects unknown identifiers and validates the merged record inside the write transaction. The memory adapter’s `remove` also rejects an unknown identifier.

Direct adapter writes do not run the authority’s enrollment lifecycle, sanitize metadata, or append lifecycle events. Use authority lifecycle methods when those operations must accompany the write.

```typescript signature
interface SubordinateStorage {
	/** Return a detached record; changing it does not update storage. */
	get(entityId: EntityId): Promise<SubordinateRecord | undefined>;
	/**
	 * Return matching records ordered lexicographically by entityId; cursors are inclusive.
	 * A filtered page may be empty with a continuation. Without options, return all matches.
	 */
	list(filter?: ListFilter, options?: ListPageOptions): Promise<ListPage>;
	/** Capture and validate input before queuing. Reject duplicate identifiers. */
	add(record: SubordinateRecord): Promise<void>;
	/** Capture changes before queuing, then merge and validate against the current record inside the write transaction. Reject unknown identifiers. */
	update(entityId: EntityId, updates: SubordinateRecordUpdate): Promise<void>;
	remove(entityId: EntityId): Promise<void>;
}
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `get` | `(entityId: EntityId) => Promise<SubordinateRecord \| undefined>` | Return a detached record; changing it does not update storage. |
| `list` | `(filter?: ListFilter, options?: ListPageOptions) => Promise<ListPage>` | Return matching records ordered lexicographically by entityId; cursors are inclusive. A filtered page may be empty with a continuation. Without options, return all matches. |
| `add` | `(record: SubordinateRecord) => Promise<void>` | Capture and validate input before queuing. Reject duplicate identifiers. |
| `update` | `(entityId: EntityId, updates: SubordinateRecordUpdate) => Promise<void>` | Capture changes before queuing, then merge and validate against the current record inside the write transaction. Reject unknown identifiers. |
| `remove` | `(entityId: EntityId) => Promise<void>` | Remove the current registration. The memory adapter rejects an unknown identifier and preserves event history; lifecycle event recording is separate. |

