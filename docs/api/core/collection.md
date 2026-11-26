# Entity Collection

A collection is a searchable snapshot of federation participants. Refresh collects and filters evidence; serving a snapshot does not turn its entries into a consumer's trusted metadata. Consumers still establish trust for the operation they intend to perform.

## `CollectionAuthentication`

[Source](../../../packages/core/src/entity-collection/types.ts)

Authentication configuration for an Entity Collection service.

```typescript signature
interface CollectionAuthentication {
	extensions?: EndpointAuthentication;

	methods: readonly string[];
	/** Receiver identity used as assertion audience, including standalone providers. */
	receiverEntityId?: EntityId;
	getClientFederationJwks?: (client: EntityId) => Promise<JWKSet | undefined>;
	allowedAlgorithms?: readonly string[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `extensions?` | `EndpointAuthentication` | Host authentication-method implementations and optional transport evidence. |
| `methods` | `readonly string[]` | Authentication methods accepted by the endpoint; include none to permit anonymous requests. |
| `receiverEntityId?` | `EntityId` | Entity Identifier of the receiving endpoint used as the client-assertion audience. |
| `getClientFederationJwks?` | `(client: EntityId) => Promise<JWKSet \| undefined>` | Look up independently trusted Federation Entity Keys for the authenticating client. |
| `allowedAlgorithms?` | `readonly string[]` | Optional algorithm allowlist, applied in addition to the library's supported algorithms. |

## `CollectionEntry`

[Source](../../../packages/core/src/storage/collection.ts)

Evidence is local server state; it is never returned as collection data.

```typescript signature
interface CollectionEntry {
	entity: EntityCollectionEntity;
	/** Application or collector eligibility deadline, in seconds since the epoch. */
	expiresAt: number;
	/** Present only when core collected a valid chain for this entry. */
	chainExpiresAt?: number;
	verifiedMarks: readonly { type: string; jwt: string; expiresAt: number }[];
	readonly extensions?: JsonObject;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entity` | `EntityCollectionEntity` | Informational collection entry; verified local evidence is stored separately. |
| `expiresAt` | `number` | Application or collector eligibility deadline in seconds since the Unix epoch. |
| `chainExpiresAt?` | `number` | Present only when core collected a valid chain for this entry. |
| `verifiedMarks` | `readonly { type: string; jwt: string; expiresAt: number }[]` | Verified type, exact published JWT, and eligibility deadline. The endpoint keeps this evidence private. |
| `extensions?` | `JsonObject` | Private JSON data for the storage adapter. |


## `CollectionRefreshOptions`

[Source](../../../packages/core/src/entity-collection/types.ts)

Controls for a collection snapshot refresh, including cancellation.

```typescript signature
interface CollectionRefreshOptions {
	signal?: AbortSignal;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `signal?` | `AbortSignal` | Cancellation signal for the waiting caller and cooperative work started by this operation. |

## `CollectionRefreshResult`

[Source](../../../packages/core/src/entity-collection/types.ts)

The outcome of a collection refresh and the snapshot it produced.

```typescript signature
interface CollectionRefreshResult {
	snapshotId: string;
	lastUpdated: number;
	entityCount: number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `snapshotId` | `string` | Identifier of the immutable collection snapshot. |
| `lastUpdated` | `number` | NumericDate when this collection snapshot was last updated. |
| `entityCount` | `number` | Number of entities in the newly published snapshot. |

## `EntityCollectionCandidate`

[Source](../../../packages/core/src/entity-collection/types.ts)

Informational input from an application-owned collector; core verifies mark evidence.

```typescript signature
interface EntityCollectionCandidate {
	entity: EntityCollectionEntity;
	expiresAt: number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entity` | `EntityCollectionEntity` | Informational collection entry; verified local evidence is stored separately. |
| `expiresAt` | `number` | Collector-supplied eligibility deadline in seconds since the Unix epoch. |

## `EntityCollectionCollector`

[Source](../../../packages/core/src/entity-collection/types.ts)

Return the complete candidate set; failures leave the previously published snapshot intact.

```typescript signature
type EntityCollectionCollector = (
	context: EntityCollectionCollectorContext,
) => Promise<Result<readonly EntityCollectionCandidate[]>>;
```

## `EntityCollectionCollectorContext`

[Source](../../../packages/core/src/entity-collection/types.ts)

Refresh context; network calls through options share the refresh limits and cancellation.

```typescript signature
interface EntityCollectionCollectorContext {
	readonly trustAnchor: EntityId;
	readonly trustAnchorJwks: JWKSet;
	readonly options: Readonly<FederationOptions>;
	readonly signal: AbortSignal;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `trustAnchor` | `EntityId` | Configured or requested Trust Anchor identity; this does not identify the endpoint responder. |
| `trustAnchorJwks` | `JWKSet` | Independently configured public Federation Entity Keys for the collection's anchor. |
| `options` | `Readonly<FederationOptions>` | Shared federation transport and validation settings for this operation. |
| `signal` | `AbortSignal` | Cancellation signal for the waiting caller and cooperative work started by this operation. |

## `EntityCollectionConfig`

[Source](../../../packages/core/src/entity-collection/types.ts)

Collection scope, storage, refresh, filtering, and endpoint settings.

```typescript signature
interface EntityCollectionConfig {
	trustAnchors: TrustAnchorSet;
	/** Defaults to core's validated federation traversal. */
	collector?: EntityCollectionCollector;
	/** Additional snapshot-time restriction, applied after mark verification. */
	filter?: EntityCollectionFilter;
	/** Defaults to case-insensitive substring matching. Receives deeply frozen, detached data. */
	queryMatcher?: EntityCollectionQueryMatcher;
	/** Optional serving URL, including fixed query components. */
	endpoint?: string;
	responder?: { entityId: EntityId; isTrustAnchor: boolean };
	authentication?: CollectionAuthentication;
	options: FederationOptions;
	maxPageSize?: number;
	cursorTtlSeconds?: number;
	maxEntities?: number;
	/** Additional claims supported by a custom snapshot producer. */
	entityClaims?: readonly string[];
	infoClaims?: readonly string[];
	/** Defaults used only when the request omits the corresponding selector. */
	defaultEntityClaims?: readonly string[];
	defaultInfoClaims?: readonly string[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `trustAnchors` | `TrustAnchorSet` | Independently trusted anchor identities and their public Federation Entity Keys. |
| `collector?` | `EntityCollectionCollector` | Defaults to core's validated federation traversal. |
| `filter?` | `EntityCollectionFilter` | Additional snapshot-time restriction, applied after mark verification. |
| `queryMatcher?` | `EntityCollectionQueryMatcher` | Defaults to case-insensitive substring matching. Receives deeply frozen, detached data. |
| `endpoint?` | `string` | Serving or remote endpoint URL; request extension contexts use status, list, or retrieval instead. |
| `responder?` | `{ entityId: EntityId; isTrustAnchor: boolean }` | Known hosting entity identity and anchor role used to bind serving and authentication behavior. |
| `authentication?` | `CollectionAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `options` | `FederationOptions` | Standalone federation settings. Supply `options.storage` with the Collection capability. |
| `maxPageSize?` | `number` | Maximum number of entries returned in one collection page. |
| `cursorTtlSeconds?` | `number` | Lifetime of a collection pagination cursor in seconds. |
| `maxEntities?` | `number` | Maximum entities retained by one collection refresh. |
| `entityClaims?` | `readonly string[]` | Entity-level claims selected or supported by the collection API. |
| `infoClaims?` | `readonly string[]` | Informational metadata claims selected or supported by the collection API. |
| `defaultEntityClaims?` | `readonly string[]` | Defaults used only when the request omits the corresponding selector. |
| `defaultInfoClaims?` | `readonly string[]` | Informational claims selected when the request omits info_claims. |

## `EntityCollectionCursor`

[Source](../../../packages/core/src/storage/collection.ts)

The continuation information used to resume a collection page.

```typescript signature
interface EntityCollectionCursor {
	snapshotId: string;
	trustAnchor: EntityId;
	context: string;
	index: number;
	expiresAt: number;
	readonly extensions?: JsonObject;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `snapshotId` | `string` | Identifier of the immutable collection snapshot. |
| `trustAnchor` | `EntityId` | Configured or requested Trust Anchor identity; this does not identify the endpoint responder. |
| `context` | `string` | Context that binds a saved cursor to its query. |
| `index` | `number` | Zero-based continuation position within the retained snapshot. |
| `expiresAt` | `number` | Expiration or eligibility deadline as a NumericDate in seconds; the owning API defines the evidence it bounds. |
| `extensions?` | `JsonObject` | Private JSON data for the storage adapter. |


## `EntityCollectionCursorCapacityError`

[Source](../../../packages/core/src/storage/collection-memory.ts)

Cursor allocation exceeded capacity after expired cursors were removed. This class extends the standard `Error` class, including its `name` and `message`.

```typescript signature
new EntityCollectionCursorCapacityError(maxCursors: number): EntityCollectionCursorCapacityError;
```

### `EntityCollectionCursorCapacityError#maxCursors`

The configured upper bound on retained listing cursors.

[Source](../../../packages/core/src/storage/collection-memory.ts)

```typescript signature
readonly maxCursors: number;
```

## `EntityCollectionFilter`

[Source](../../../packages/core/src/entity-collection/types.ts)

Run once per entry during refresh; an explicit deadline can only shorten eligibility.

```typescript signature
type EntityCollectionFilter = (
	entry: Readonly<CollectionEntry>,
	context: EntityCollectionCollectorContext,
) => boolean | { expiresAt: number } | Promise<boolean | { expiresAt: number }>;
```

## `EntityCollectionIntegration`

[Source](../../../packages/core/src/entity-collection/types.ts)

Optional integration; responder identity always comes from its hosting class.

```typescript signature
type EntityCollectionIntegration = Omit<EntityCollectionConfig, "responder" | "options"> & {
	readonly options?: import("../types.js").BoundFederationOptions;
};
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `filter?` | `EntityCollectionFilter` | Additional snapshot-time restriction, applied after mark verification. |
| `options?` | `BoundFederationOptions` | Per-integration settings. The service uses the host’s storage and crypto. |
| `authentication?` | `CollectionAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `endpoint?` | `string` | Serving or remote endpoint URL; request extension contexts use status, list, or retrieval instead. |
| `entityClaims?` | `readonly string[]` | Entity-level claims selected or supported by the collection API. |
| `infoClaims?` | `readonly string[]` | Informational metadata claims selected or supported by the collection API. |
| `trustAnchors` | `TrustAnchorSet` | Independently trusted anchor identities and their public Federation Entity Keys. |
| `collector?` | `EntityCollectionCollector` | Defaults to core's validated federation traversal. |
| `queryMatcher?` | `EntityCollectionQueryMatcher` | Defaults to case-insensitive substring matching. Receives deeply frozen, detached data. |
| `maxPageSize?` | `number` | Maximum number of entries returned in one collection page. |
| `cursorTtlSeconds?` | `number` | Lifetime of a collection pagination cursor in seconds. |
| `maxEntities?` | `number` | Maximum entities retained by one collection refresh. |
| `defaultEntityClaims?` | `readonly string[]` | Defaults used only when the request omits the corresponding selector. |
| `defaultInfoClaims?` | `readonly string[]` | Informational claims selected when the request omits info_claims. |

## `EntityCollectionQueryMatcher`

[Source](../../../packages/core/src/entity-collection/types.ts)

Local, synchronous search. Return the same decision for a fixed query and snapshot.

```typescript signature
type EntityCollectionQueryMatcher = (
	query: string,
	entity: Readonly<EntityCollectionEntity>,
) => boolean;
```

## `EntityCollectionService`

[Source](../../../packages/core/src/entity-collection/service.ts)

Shared unsigned collection service for federation entities and independent providers.

```typescript signature
new EntityCollectionService(config: EntityCollectionConfig): EntityCollectionService;
```

### `EntityCollectionService#store`

Storage used for this component's authoritative records.

[Source](../../../packages/core/src/entity-collection/service.ts)

```typescript signature
readonly store: EntityCollectionStore;
```

### `EntityCollectionService#refresh`

Collect, validate, and publish a replacement collection snapshot. A cancelled queued caller is released without cancelling another caller's refresh.

[Source](../../../packages/core/src/entity-collection/service.ts)

```typescript signature
refresh(anchor: EntityId, options?: CollectionRefreshOptions): Promise<Result<CollectionRefreshResult>>;
```

### `EntityCollectionService#query`

Query the published collection snapshot using the supplied selectors.

[Source](../../../packages/core/src/entity-collection/service.ts)

```typescript signature
query(params?: EntityCollectionRequestParams): Promise<Result<EntityCollectionResponse>>;
```

### `EntityCollectionService#handleRequest`

Handle a Web API Request and return the protocol Response. The application supplies external HTTPS routing.

[Source](../../../packages/core/src/entity-collection/service.ts)

```typescript signature
handleRequest(request: Request): Promise<Response>;
```

## `EntityCollectionSnapshot`

[Source](../../../packages/core/src/storage/collection.ts)

A stored collection of entity entries and the information needed to serve it.

```typescript signature
interface EntityCollectionSnapshot {
	id: string;
	trustAnchor: EntityId;
	lastUpdated: number;
	entries: readonly CollectionEntry[];
	readonly extensions?: JsonObject;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `id` | `string` | Identifier of the key, subordinate, or snapshot described by this entry. |
| `trustAnchor` | `EntityId` | Configured or requested Trust Anchor identity; this does not identify the endpoint responder. |
| `lastUpdated` | `number` | NumericDate when this collection snapshot was last updated. |
| `entries` | `readonly CollectionEntry[]` | Collection entries and their local eligibility evidence, ordered by published Entity Identifier. |
| `extensions?` | `JsonObject` | Private JSON data for the storage adapter. |


## `EntityCollectionStore`

[Source](../../../packages/core/src/storage/collection.ts)

Atomically publish snapshots and return detached values. Keep entries in their
published Entity Identifier order (§3.1.1). Snapshot identifiers name immutable
contents; current is isolated by anchor. A cursor retains its snapshot identity
and position. Expired or unavailable snapshots must not resolve to newer contents.

```typescript signature
interface EntityCollectionStore {
	publish(snapshot: EntityCollectionSnapshot): Promise<void>;
	current(trustAnchor: EntityId): Promise<EntityCollectionSnapshot | undefined>;
	snapshot(id: string): Promise<EntityCollectionSnapshot | undefined>;
	/** May throw EntityCollectionCursorCapacityError to report temporary capacity exhaustion. */
	saveCursor(id: string, cursor: EntityCollectionCursor): Promise<void>;
	cursor(id: string): Promise<EntityCollectionCursor | undefined>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `publish` | `(snapshot: EntityCollectionSnapshot) => Promise<void>` | Atomically publish the supplied collection snapshot. |
| `current` | `(trustAnchor: EntityId) => Promise<EntityCollectionSnapshot \| undefined>` | Read the currently published snapshot for the requested anchor. |
| `snapshot` | `(id: string) => Promise<EntityCollectionSnapshot \| undefined>` | Read an immutable retained snapshot by identifier. |
| `saveCursor` | `(id: string, cursor: EntityCollectionCursor) => Promise<void>` | Store a cursor bound to its snapshot, query context, and expiration. |
| `cursor` | `(id: string) => Promise<EntityCollectionCursor \| undefined>` | Read an unexpired cursor, without substituting a newer snapshot. |

