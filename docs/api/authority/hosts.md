# Federation hosts

[`@oidfed/authority`](README.md)

Construct one host for an Entity Identifier and compose fresh protocol-role instances into it. Hosts accept Web API requests; the application supplies HTTPS routing and durable infrastructure. Constructors can throw `InvalidAuthorityConfig`, `InvalidMetadata`, `TypeError`, or ordinary errors, depending on the failed check. Local operations use their declared return shape: signed JWT strings, payloads, arrays, or `Result` values. Errors are not uniformly returned as `Result`.

Shared types such as `EntityId`, `FederationOptions`, `DiscoveryResult`, and Trust Mark options are exported by `@oidfed/core`. The static discovery properties are callable aliases; the instance methods add host configuration defaults.

## `AuthorityClientKeyProvider`

[Source](../../../packages/authority/src/endpoints/context.ts#L21)

Resolves the caller’s public Federation Entity Keys for endpoint `private_key_jwt` verification. Return `undefined` for an unknown client. Without a custom provider, the authority reads the caller’s registered subordinate `jwks`; it does not establish remote client trust through discovery automatically.

```typescript signature
interface AuthorityClientKeyProvider {
	getClientFederationJwks(entityId: EntityId): Promise<JWKSet | undefined>;
}
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `getClientFederationJwks` | `(entityId: EntityId) => Promise<JWKSet \| undefined>` | Return independently trusted public federation keys for the caller, or undefined when unavailable. Lookup failures prevent authentication. |

## `AuthorityConfig`

[Source](../../../packages/authority/src/server.ts#L139)

Configuration for a `TrustAnchor`. `metadata.federation_entity` must advertise Fetch and Listing endpoints. A Trust Anchor can publish both Superior hints and Trust Mark policy maps.

Metadata and extension claims are captured at construction. Initialized roles override metadata parameters in role order. Providers, stores, and callbacks remain service references. Construct a replacement host to change general metadata; the dedicated policy, holder, and subordinate methods update their own state. Hosted endpoint operations use `storage.cache`; `options` deliberately excludes `cache`. Instance discovery can receive a cache in its per-call options.

```typescript signature
interface AuthorityConfig extends EntityStatementExtensions {
	trustMarkDefaults?: TrustMarkIssuerConfig["trustMarkDefaults"];
	trustMarkStatusPolicy?: TrustMarkIssuerConfig["trustMarkStatusPolicy"];
	trustMarkRequestExtensions?: TrustMarkIssuerConfig["trustMarkRequestExtensions"];
	endpointAuthentication?: EndpointAuthentication;
	trustMarkIssuer?: Omit<TrustMarkIssuerConfig, "storage">;
	/**
	 * Require authentication for fresh HTTP Resolve discovery (default: true).
	 * Anonymous requests use cached assessments, per Federation §18.1.
	 * Local resolveEntity() calls can discover and warm the cache.
	 */
	requireAuthForFreshResolution?: boolean;
	/** Optional shared collection service; snapshots are independent of registrations. */
	collection?: EntityCollectionIntegration;
	/** The entity identifier (URL) for this authority. */
	entityId: EntityId | string;
	/** Copied at construction; must include federation_entity. Initialized roles override parameters in role order. Re-create the host to change general metadata. */
	metadata: { federation_entity: FederationEntityMetadata } & Partial<{
		[K in EntityType]: EntityTypeMetadataMap[K];
	}>;
	/** Unified persistence adapter for all non-key authority state. */
	storage: FederationStorage;
	/** Host crypto engine, signing keyring and optional key history. */
	crypto: CryptoContext;
	/**
	 * Resolves public Federation Entity Keys for authenticated remote authority
	 * endpoint clients. Defaults to `storage.subordinate.fetch(entityId)?.jwks`.
	 */
	clientKeyProvider?: AuthorityClientKeyProvider;
	/** Roles (like OIDC OP, RP etc.) bound to this authority. */
	roles?: EntityRole[];
	/** Trust marks this authority claims about itself. */
	trustMarks?: TrustMarkRef[];
	/** Mapping of trust mark type → authorized issuer entity IDs. */
	trustMarkIssuers?: Record<string, string[]>;
	/** Mapping of trust mark type → owner declaration (for delegated trust marks). */
	trustMarkOwners?: Record<string, TrustMarkOwner>;
	/** Pre-signed trust mark delegation JWTs, keyed by trust mark type. */
	trustMarkDelegations?: Record<string, string>;
	/** Superior authorities this entity is subordinate to. */
	authorityHints?: readonly (EntityId | string)[];
	/** Preferred trust anchors this entity hints to resolvers in its Entity Configuration. */
	trustAnchorHints?: readonly (EntityId | string)[];
	/** Trust anchors used for trust chain resolution (e.g., during registration). */
	trustAnchors?: TrustAnchorSet;
	/** Positive safe-integer TTL in seconds for the Entity Configuration JWT. */
	entityConfigurationTtlSeconds?: number;
	/** Positive safe-integer TTL in seconds for subordinate statement JWTs. */
	subordinateStatementTtlSeconds?: number;
	/** Optional positive, finite history-response TTL; omission leaves exp absent. */
	subordinateEventsTtlSeconds?: number;
	/** Positive finite TTL in seconds for issued Trust Marks; fractional values are allowed. */
	trustMarkTtlSeconds?: number;
	/** Federation-wide options (httpClient, clock, etc.). */
	options?: BoundFederationOptions;
	/**
	 * Configuration for the Extended Subordinate Listing endpoint. Set
	 * `enabled: false` to keep the endpoint disabled (router returns 404) and
	 * omit `federation_extended_list_endpoint` from your metadata. Defaults
	 * enable the endpoint with `maxPageSize=500`, `defaultPageSize=100`,
	 * time-filters and audit timestamps supported.
	 */
	extendedListing?: ExtendedListingConfig;
}
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `trustMarkDefaults?` | `TrustMarkIssuerConfig["trustMarkDefaults"]` | Per-type issuance defaults. A supplied top-level map takes precedence over `trustMarkIssuer.trustMarkDefaults`. |
| `trustMarkStatusPolicy?` | `TrustMarkIssuerConfig["trustMarkStatusPolicy"]` | Issuer policy for Status responses and local Resolve status assessments. A top-level callback overrides the nested callback and cannot reactivate an ineligible mark. |
| `trustMarkRequestExtensions?` | `TrustMarkIssuerConfig["trustMarkRequestExtensions"]` | Additional Trust Mark request-parameter validators. A supplied top-level map overrides the nested map. |
| `endpointAuthentication?` | `EndpointAuthentication` | Custom federation endpoint authentication methods and trusted transport-evidence lookup. Advertise accepted method names in each endpoint's metadata. |
| `trustMarkIssuer?` | `Omit<TrustMarkIssuerConfig, "storage">` | Shared issuer-service options. Storage always comes from `storage.trustMarks`. Top-level issuer callback/maps override their nested equivalents; nested `defaults` override the global `trustMarkTtlSeconds` fallback. |
| `requireAuthForFreshResolution?` | `boolean` | Defaults to `true`: anonymous HTTP Resolve requests use cached assessments. Local `resolveEntity()` and authenticated calls may discover fresh evidence. |
| `collection?` | `EntityCollectionIntegration` | Optional collection service configuration. Publishing the collection endpoint requires this configuration; creating the service alone does not advertise the endpoint. |
| `entityId` | `EntityId \| string` | HTTPS Entity Identifier without userinfo, query, or fragment. The authority validates and preserves the configured value. |
| `metadata` | `{ federation_entity: FederationEntityMetadata } & Partial<{ [K in EntityType]: EntityTypeMetadataMap[K]; }>` | Copied metadata, including required fetch/list endpoints in `federation_entity`. Initialized roles replace conflicting parameters in role order. Entity-type blocks and direct metadata parameters cannot be null. |
| `storage` | `FederationStorage` | Persistence adapter for subordinate records and any optional Trust Mark, event, replay, cache, and collection capabilities required by enabled operations. |
| `crypto` | `RotatingKeyring` | Current federation signer and public keys, plus rollover and historical-key operations. Retained as a live service reference. |
| `clientKeyProvider?` | `AuthorityClientKeyProvider` | Client federation-key lookup for endpoint authentication. Defaults to the caller's `storage.subordinate` record; it performs no automatic remote discovery. |
| `roles?` | `EntityRole[]` | Fresh protocol-role instances initialized once for this host. Their metadata and routes are composed during construction. |
| `trustMarks?` | `TrustMarkRef[]` | Initial Trust Mark references held by this authority and published in its own EC; distinct from records issued by its Trust Mark service. |
| `trustMarkIssuers?` | `Record<string, string[]>` | Anchor policy mapping types to accepted issuers. Allowed on Trust Anchors, including anchors with Superiors; rejected by Intermediate construction. |
| `trustMarkOwners?` | `Record<string, TrustMarkOwner>` | Anchor policy mapping types to owner identities and public keys. Allowed on Trust Anchors and rejected by Intermediate construction. |
| `trustMarkDelegations?` | `Record<string, string>` | Pre-signed delegation JWTs keyed by type. Used by the issuer service; setting the map does not verify the JWTs or establish owner authorization. |
| `authorityHints?` | `readonly (EntityId \| string)[]` | Nonempty Superior list required for an Intermediate. A Trust Anchor may also have Superiors; omit the option when it has none. An explicit empty array is rejected. |
| `trustAnchorHints?` | `readonly (EntityId \| string)[]` | Optional nonempty preferred-anchor list. Allowed when the host has Superiors, including a Trust Anchor; rejected on anchors without Superiors. |
| `trustAnchors?` | `TrustAnchorSet` | Pins available to composed roles and local trust operations. The host is not automatically inserted into this set. |
| `entityConfigurationTtlSeconds?` | `number` | Positive safe-integer EC lifetime in seconds. Defaults to 86,400. |
| `subordinateStatementTtlSeconds?` | `number` | Positive safe-integer Subordinate Statement lifetime in seconds. Defaults to 86,400. |
| `subordinateEventsTtlSeconds?` | `number` | Optional positive finite history-response lifetime in seconds; fractions are accepted. Omission leaves the optional response `exp` absent. |
| `trustMarkTtlSeconds?` | `number` | Positive finite issuer lifetime fallback in seconds; fractions are accepted. Defaults ultimately to 86,400 when no nested defaults, per-type, or per-call lifetime applies. Also supplies the default for `issueTrustMarkDelegation()`. |
| `options?` | `BoundFederationOptions` | Federation defaults. The host binds crypto and storage. Per-call policies may narrow these defaults. |
| `extendedListing?` | `ExtendedListingConfig` | Extended Listing behavior and limits. The handler defaults to enabled, but an HTTP route requires an advertised endpoint. `enabled: false` makes handler/local page requests return not_found. |
| `additionalClaims?` | `Readonly<Record<string, unknown>> \| undefined` | Custom top-level claims; standard Entity Statement claims cannot be overridden. |
| `crit?` | `readonly string[] \| undefined` | Extension claims recipients MUST understand and process (Federation §13.4). |

## `ExtendedListingConfig`

[Source](../../../packages/authority/src/endpoints/extended-list.ts#L37)

Configuration controlling Extended Listing; numeric limits must be positive safe integers.

```typescript signature
interface ExtendedListingConfig {
	/** Optional request selectors, parsed once and applied before page limits. Unknown selectors are ignored. */
	requestFilters?: Readonly<Record<string, ExtendedListingRequestFilter>>;
	/** Maximum UTF-8 JSON success-response bytes, including next; defaults to 512 KiB. */
	maxResponseBytes?: number;
	/** Whether the endpoint is wired in at all. When false, handler returns 404. */
	enabled?: boolean;
	/** Hard cap applied to the per-page result size; client `limit` is clamped to this. */
	maxPageSize?: number;
	/** Page size when `limit` is omitted; defaults to min(100, maxPageSize). */
	defaultPageSize?: number;
	/** Whether to honour `updated_after` / `updated_before`. Defaults to true. */
	supportTimeFilters?: boolean;
	/** Support explicit `audit_timestamps=true` requests. Time filters independently recommend timestamps. Defaults to true. */
	supportAuditTimestamps?: boolean;
	/**
	 * Claims substituted per-entity when the client does NOT send the `claims`
	 * parameter at all. When the client sends `claims=` (even empty), no
	 * substitution happens and the user-supplied value wins. Default:
	 * `["subordinate_statement"]`. Set to `[]` to make bare requests id-only.
	 */
	defaultClaims?: ReadonlyArray<string>;
	/**
	 * Maximum number of inner store `list()` calls allowed per HTTP request
	 * before the handler stops accumulating and returns whatever it has plus a
	 * resume cursor. Bounds worst-case work when post-filters (trust-marked,
	 * etc.) drop most records. Default: 16.
	 */
	maxStorePagesPerRequest?: number;
	/**
	 * Inner store batch size used when filling a page. Larger values reduce
	 * round-trips when post-filters are strict, smaller values bound memory.
	 * Default: `defaultPageSize`.
	 */
	storeBatchSize?: number;
}
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `requestFilters?` | `Readonly<Record<string, ExtendedListingRequestFilter>>` | Additional selector definitions, captured when the handler is created. Standard selectors and credential names cannot be replaced. Only supplied registered selectors run. |
| `maxResponseBytes?` | `number` | Positive safe-integer UTF-8 JSON success-body limit, including next. Defaults to 524,288 bytes. |
| `enabled?` | `boolean` | Defaults to true. False makes the handler return HTTP 404, including through local Extended Listing calls. It does not edit published metadata. |
| `maxPageSize?` | `number` | Positive safe-integer page cap; request limit is clamped to it. Defaults to 500. |
| `defaultPageSize?` | `number` | Positive safe-integer page size when limit is absent. Defaults to min(100, maxPageSize) and must not exceed maxPageSize. |
| `supportTimeFilters?` | `boolean` | Defaults to true. False rejects supplied updated_after or updated_before selectors. |
| `supportAuditTimestamps?` | `boolean` | Defaults to true. Controls explicit audit_timestamps=true; time filters can independently imply timestamps unless audit_timestamps=false. |
| `defaultClaims?` | `ReadonlyArray<string>` | Claims used only when claims is omitted. Defaults to [subordinate_statement]. An explicit empty claims list suppresses this substitution. |
| `maxStorePagesPerRequest?` | `number` | Positive safe-integer storage scan limit per request. Defaults to 16; reaching it can return an empty page with continuation. |
| `storeBatchSize?` | `number` | Positive safe-integer storage batch size. Defaults to defaultPageSize. |

## `ExtendedListingFilterContext`

[Source](../../../packages/authority/src/endpoints/extended-list-filters.ts#L19)

Context passed to a custom filter: its only field is the operation’s `AbortSignal`. It does not contain a request or authenticated caller identity.

```typescript signature
interface ExtendedListingFilterContext {
	readonly signal: AbortSignal;
}
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `signal` | `AbortSignal` | Cancellation and timeout signal for the filter operation. |

## `ExtendedListingRequestFilter`

[Source](../../../packages/authority/src/endpoints/extended-list-filters.ts#L24)

Defines one additional query selector. A nonempty name must not replace a standard selector or credential parameter. `parse` runs once for each supplied registered selector, even when storage is empty. Its successful value must be JSON data or `undefined` for a flag. `matches` receives a detached, deeply frozen record and parsed value. All supplied custom filters must match in addition to the standard filters.

A parser error becomes `invalid_request`; a thrown exception, malformed result, or nonboolean match result fails the request. Callbacks can be asynchronous and receive the cancellation signal. Unknown, unregistered selectors are ignored.

```typescript signature
interface ExtendedListingRequestFilter {
	/** Parse once, including for empty stores. Values must be JSON data (or undefined for a flag). */
	readonly parse: (
		values: readonly string[],
		context: Readonly<ExtendedListingFilterContext>,
	) => Result<unknown> | Promise<Result<unknown>>;
	readonly matches: (
		record: Readonly<SubordinateRecord>,
		value: unknown,
		context: Readonly<ExtendedListingFilterContext>,
	) => boolean | Promise<boolean>;
}
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `parse` | `( values: readonly string[], context: Readonly<ExtendedListingFilterContext>, ) => Result<unknown> \| Promise<Result<unknown>>` | Parse the selector's repeated string values once. Return a Result containing JSON data or undefined for a flag; an error result becomes invalid_request. |
| `matches` | `( record: Readonly<SubordinateRecord>, value: unknown, context: Readonly<ExtendedListingFilterContext>, ) => boolean \| Promise<boolean>` | Test a frozen detached subordinate record against the frozen parsed value. Return a boolean, synchronously or asynchronously; false excludes the record. |

## `ExtendedSubordinateListingOptions`

[Source](../../../packages/authority/src/server.ts#L110)

Per-call options for local Extended Listing: extension selectors and cancellation only. This type does not accept HTTP credentials, a transport, or trust anchors. The call uses the authority’s existing Extended Listing handler and configuration.

```typescript signature
type ExtendedSubordinateListingOptions = Pick<
	FederationOptions,
	"additionalParameters" | "signal"
>;
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `signal?` | `AbortSignal` | Per-call cancellation signal passed to the local request and handler. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extra string or repeated-string selector values. Cannot override standard protocol selectors or credential names. |

## `ExtendedSubordinateListingResult`

[Source](../../../packages/authority/src/server.ts#L116)

The decoded JSON success body from local Extended Listing. Each item has an `id` plus any selected claims. `next`, when present, is an opaque inclusive continuation; it can accompany an empty page. Keep filters and claim selections unchanged when continuing.

```typescript signature
interface ExtendedSubordinateListingResult {
	immediate_subordinate_entities: Array<Record<string, unknown> & { id: string }>;
	next?: string;
}
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `immediate_subordinate_entities` | `Array<Record<string, unknown> & { id: string }>` | Returned subordinate entries, each with id and any selected available claims. |
| `next?` | `string` | Opaque cursor for the first unreturned position. May accompany an empty page; omission ends the scan. |

## `FederationHandler`

[Source](../../../packages/authority/src/handler.ts#L3)

An asynchronous Web API request handler: accepts one `Request` and returns a `Response`. This type is a function, not a route map.

```typescript signature
type FederationHandler = (request: Request) => Promise<Response>;
```

## `IntermediateConfig`

`Intermediate.create(config)` takes the common authority settings and requires a nonempty `authorityHints` tuple. It excludes `trustMarkIssuers` and `trustMarkOwners`, which belong to Trust Anchor policy. Intermediates can publish and use Trust Mark delegations where configured.

## `Intermediate`

[Source](../../../packages/authority/src/server.ts#L1342)

Authority host with at least one Superior. It issues statements for registered subordinates and can issue and hold Trust Marks. It rejects anchor issuer/owner policy configuration; its `setTrustMarkIssuers()` and `setTrustMarkOwners()` methods exist but always reject.

The factory requires advertised fetch and list endpoints, initializes roles, and rejects conflicting routes. Publication is signed on demand. Local methods do not authenticate an HTTP caller; authorize administrative access in the host application.

```typescript signature
static create(config: IntermediateConfig): Promise<Intermediate>;
```

### `Intermediate#assessEntity`

Assess the target locally or through an explicitly trusted resolver. Instance calls use per-call anchors first, then configured host anchors, then an empty set. Per-call options override host options; no implicit self-anchor trust is added. Returns a `Result<EntityAssessment>`.

[Source](../../../packages/authority/src/server.ts#L1108)

```typescript signature
assessEntity(target: EntityId, options?: EntityAssessmentOptions & {
		trustAnchors?: TrustAnchorSet;
	}): Promise<Result<import("@oidfed/core").EntityAssessment>>;
```

### `Intermediate#discoverEntity`

Discover candidates, validate their chains, and select a result. Instance calls use per-call anchors first, then configured host anchors, then an empty set; per-call federation options override host options. Returns a `Result<DiscoveryResult>`.

[Source](../../../packages/authority/src/server.ts#L1123)

```typescript signature
discoverEntity(target: EntityId, options?: BoundFederationOptions & { trustAnchors?: TrustAnchorSet; }): Promise<Result<DiscoveryResult>>;
```

### `Intermediate#discoverEntityFromChain`

Validate supplied readonly statements for the target and return a `DiscoveryResult` in a `Result`. Instance calls inherit host anchors and options unless overridden. Supply supporting Entity Configurations through the options when the path needs them.

[Source](../../../packages/authority/src/server.ts#L1134)

```typescript signature
discoverEntityFromChain(target: EntityId, statements: readonly string[], options?: BoundFederationOptions & { trustAnchors?: TrustAnchorSet; }): Promise<Result<DiscoveryResult>>;
```

### `Intermediate#collection`

Readonly getter for the configured `EntityCollectionService`; `undefined` when `AuthorityConfig.collection` was omitted. Configuring a service does not advertise its HTTP endpoint automatically.

[Source](../../../packages/authority/src/server.ts#L1148)

```typescript signature
get collection(): EntityCollectionService | undefined;
```

### `Intermediate#entityId`

The exact configured Entity Identifier used in Entity Configurations, role context, and hosted services. The authority removes a trailing slash when constructing the well-known URL.

[Source](../../../packages/authority/src/server.ts#L1152)

```typescript signature
readonly entityId: EntityId;
```

### `Intermediate#getEntityConfiguration`

Build and sign a compact Entity Configuration JWT using the current key-provider state. This authority method does not reuse a Leaf-style EC cache. Rejects if keys, publication validation, or signing fail.

[Source](../../../packages/authority/src/server.ts#L1168)

```typescript signature
getEntityConfiguration(): Promise<string>;
```

### `Intermediate#getSubordinateStatement`

Load the registered subordinate and build a compact signed Subordinate Statement with the authority’s current signer, policy, and lifetime. Rejects for an unknown subordinate or invalid/unavailable publication data.

[Source](../../../packages/authority/src/server.ts#L1173)

```typescript signature
getSubordinateStatement(sub: EntityId): Promise<string>;
```

### `Intermediate#listSubordinates`

Return matching subordinate identifiers from `storage.subordinate.list(filter)` without paging options. This is a local storage read, not an HTTP request, and returns identifiers rather than records.

[Source](../../../packages/authority/src/server.ts#L1178)

```typescript signature
listSubordinates(filter?: ListFilter): Promise<EntityId[]>;
```

### `Intermediate#listSubordinatesExtended`

Invoke the existing Extended Listing handler locally and return its decoded body in a `Result`. Routing and HTTP client authentication are bypassed, and no advertised endpoint is required for this local call. Handler validation and configured limits still apply; `enabled: false` returns a `not_found` error result.

[Source](../../../packages/authority/src/server.ts#L1183)

```typescript signature
listSubordinatesExtended(params?: ExtendedListRequestParams, options?: ExtendedSubordinateListingOptions): Promise<Result<ExtendedSubordinateListingResult, FederationError>>;
```

### `Intermediate#resolveEntity`

Return a compact signed Resolve response JWT for the subject and optional requested anchor. A trusted local call can perform fresh discovery and warm the resolver cache. Per-call federation options are forwarded to the service. An unsuccessful resolver response rejects this promise with its error description.

[Source](../../../packages/authority/src/server.ts#L1191)

```typescript signature
resolveEntity(sub: EntityId, ta?: EntityId, options?: BoundFederationOptions): Promise<string>;
```

### `Intermediate#getTrustMarkStatus`

Build a local signed Trust Mark Status response, decode it, and return its payload object, not the JWT. Requires `storage.trustMarks`. Rejects when the mark instance is unknown or the status response cannot be produced; configured status policy applies.

[Source](../../../packages/authority/src/server.ts#L1200)

```typescript signature
getTrustMarkStatus(trustMark: string): Promise<TrustMarkStatusResponsePayload>;
```

### `Intermediate#listTrustMarkedEntities`

Return sorted, deduplicated subject identifiers with an eligible mark of the requested type issued by this authority. Requires Trust Mark storage and a consistent read snapshot. This does not make an external Status request.

[Source](../../../packages/authority/src/server.ts#L1205)

```typescript signature
listTrustMarkedEntities(trustMarkType: string): Promise<string[]>;
```

### `Intermediate#getTrustMarks`

Return a detached copy of the holder’s current Trust Mark references. This does not revoke, retrieve, or revalidate their issuer records.

[Source](../../../packages/authority/src/server.ts#L1210)

```typescript signature
getTrustMarks(): { trust_mark_type: string; trust_mark: string; }[];
```

### `Intermediate#attachTrustMark`

Verify the mark for this host with the supplied issuer evidence, then sign the prospective EC before replacing the holder references. Duplicate attachment is idempotent; the requested replacement policy can remove older references. A failed publication leaves the previous holder state intact.

[Source](../../../packages/authority/src/server.ts#L1216)

```typescript signature
attachTrustMark(jwt: string, options: AttachTrustMarkOptions): Promise<void>;
```

### `Intermediate#fetchAndAttachTrustMark`

Establish the requested issuer’s trust, retrieve a mark, validate it for this holder, and publish it through the same attachment operation. Trust and transport settings come from the supplied options; retrieval does not establish trust by itself.

[Source](../../../packages/authority/src/server.ts#L1220)

```typescript signature
fetchAndAttachTrustMark(options: Omit<FetchAndAttachTrustMarkOptions, "options"> & { readonly options?: BoundFederationOptions; }): Promise<void>;
```

### `Intermediate#removeTrustMark`

Remove matching holder references through a signed publication update. It can remove an expired mark without fetching or validating it again. It does not revoke the issuer’s stored mark; a failed publication leaves the previous references intact.

[Source](../../../packages/authority/src/server.ts#L1228)

```typescript signature
removeTrustMark(selector: RemoveTrustMarkSelector): Promise<void>;
```

### `Intermediate#setTrustMarkDelegations`

Replace the issuer’s delegation map with an owned copy after map/value shape checks. Requires Trust Mark storage. This setter does not verify delegation signatures or expiry; applicable issuance and mark-validation operations perform those checks.

[Source](../../../packages/authority/src/server.ts#L1232)

```typescript signature
setTrustMarkDelegations(delegations: Record<string, string>): Promise<void>;
```

### `Intermediate#revokeTrustMark`

Revoke every matching active record issued by this authority for the type and subject, inside a storage transaction. Requires Trust Mark storage. Historical records remain stored; holder EC references and remote caches are not removed.

[Source](../../../packages/authority/src/server.ts#L1236)

```typescript signature
revokeTrustMark(type: string, subject: string): Promise<void>;
```

### `Intermediate#listTrustMarksForSubject`

Return detached eligible records issued by this authority for the subject, ordered newest first. Multiple eligible records of the same type can be returned. Requires Trust Mark storage and a consistent read snapshot.

[Source](../../../packages/authority/src/server.ts#L1240)

```typescript signature
listTrustMarksForSubject(subject: string): Promise<TrustMarkRecord[]>;
```

### `Intermediate#issueTrustMark`

Issue a compact Trust Mark JWT or reuse an eligible stored JWT. Requires Trust Mark storage, transactions, and a read snapshot. The default renewal mode is `"reuse"`; conflicting explicit options reject reuse. `"renew"` requests issuance while retaining earlier records. The selected signer must verify against the issuer’s published keys before the record is stored.

[Source](../../../packages/authority/src/server.ts#L1244)

```typescript signature
issueTrustMark(sub: string, trustMarkType: string, options?: TrustMarkIssuanceOptions): Promise<string>;
```

### `Intermediate#issueTrustMarkDelegation`

Sign a compact delegation JWT with this host as owner and `subject` as the delegated issuer. This operation does not require Trust Mark storage or publish owner policy. Per-call lifetime options override `trustMarkTtlSeconds`; otherwise the signing helper defaults to 86,400 seconds. Delivery to the issuer is arranged by the host.

[Source](../../../packages/authority/src/server.ts#L1253)

```typescript signature
issueTrustMarkDelegation(subject: string, trustMarkType: string, options?: TrustMarkDelegationIssuanceOptions): Promise<string>;
```

### `Intermediate#getHistoricalKeys`

Build a compact signed Historical Keys response JWT from the provider’s recorded public-key history. The return value is a string, not a key array. The response can contain `keys: []` when the provider has no historical keys. Provider and signer failures reject the call.

[Source](../../../packages/authority/src/server.ts#L1262)

```typescript signature
getHistoricalKeys(): Promise<string>;
```

### `Intermediate#registerSubordinate`

Validate publication claims, sanitize Superior-supplied metadata, supply timestamps from the authority clock, and add the subordinate in one transaction. Configured event storage receives a registration event atomically. Annotations require event storage; duplicate identifiers fail through storage.

[Source](../../../packages/authority/src/server.ts#L1267)

```typescript signature
registerSubordinate(record: Omit<SubordinateRecord, "createdAt" | "updatedAt">, annotations?: SubordinateEventAnnotations): Promise<void>;
```

### `Intermediate#updateSubordinate`

Update an existing subordinate through the lifecycle transaction. The input is captured and sanitized, and merged publication claims are checked. Configured event storage records relevant metadata, policy, and key changes; a no-op update creates no update event. Rejects for an unknown subordinate or invalid update.

[Source](../../../packages/authority/src/server.ts#L1276)

```typescript signature
updateSubordinate(subject: EntityId, updates: SubordinateRecordUpdate, annotations?: SubordinateEventAnnotations): Promise<void>;
```

### `Intermediate#revokeSubordinate`

Remove the registration in a transaction and append a revocation event when event storage is enabled. History remains available. Previously distributed statements and remote caches are not invalidated by the local removal.

[Source](../../../packages/authority/src/server.ts#L1284)

```typescript signature
revokeSubordinate(subject: EntityId, annotations?: SubordinateEventAnnotations): Promise<void>;
```

### `Intermediate#recordSubordinateEvents`

Validate and capture manually supplied observations, including nested extension data, then append them transactionally. Requires subordinate-event storage. This method does not modify enrollment state, suspend a participant, or revoke a registration.

[Source](../../../packages/authority/src/server.ts#L1293)

```typescript signature
recordSubordinateEvents(subject: EntityId, events: readonly SubordinateEvent[]): Promise<void>;
```

### `Intermediate#getSubordinateEvents`

Return a compact signed history JWT for the subject. Requires event storage and known registration or retained history. Its optional `exp` is controlled by `subordinateEventsTtlSeconds`; storage, cancellation, and signing failures reject the call.

[Source](../../../packages/authority/src/server.ts#L1300)

```typescript signature
getSubordinateEvents(subject: EntityId): Promise<string>;
```

### `Intermediate#handleRequest`

Dispatch a Web API `Request` to a composed role route or a federation endpoint. Endpoint routes use advertised paths and fixed selectors; Entity Configuration discovery stays anonymous GET. Ordinary protocol failures return HTTP responses. A role handler can still reject; the host provides HTTPS serving and external request policy.

[Source](../../../packages/authority/src/server.ts#L1305)

```typescript signature
handleRequest(request: Request): Promise<Response>;
```

## `InvalidAuthorityConfig`

[Source](../../../packages/authority/src/errors.ts#L4)

Configuration error used by authority validation. Its constructor takes a message and sets `name` to `"InvalidAuthorityConfig"`. Configuration checks can also throw ordinary `Error` or `TypeError`; callers must not assume every invalid configuration uses this class.

```typescript signature
new InvalidAuthorityConfig(message: string): InvalidAuthorityConfig;
```

## `TrustAnchor`

[Source](../../../packages/authority/src/server.ts#L1317)

Authority host whose identifier and keys consumers can configure as an anchor. It may also have Superiors. Without Superiors, omit `authorityHints` and `trustAnchorHints`; with Superiors, both hints may be supplied as nonempty arrays. It can publish and replace Trust Mark issuer/owner policy.

The factory requires advertised fetch and list endpoints, initializes roles, and rejects conflicting routes. Being a Trust Anchor does not automatically add this host to the anchors used by its discovery methods. Publication is signed on demand. Authorize local administrative calls in the host application.

```typescript signature
static create(config: AuthorityConfig): Promise<TrustAnchor>;
```

### `TrustAnchor#assessEntity`

Assess the target locally or through an explicitly trusted resolver. Instance calls use per-call anchors first, then configured host anchors, then an empty set. Per-call options override host options; no implicit self-anchor trust is added. Returns a `Result<EntityAssessment>`.

[Source](../../../packages/authority/src/server.ts#L1108)

```typescript signature
assessEntity(target: EntityId, options?: EntityAssessmentOptions & {
		trustAnchors?: TrustAnchorSet;
	}): Promise<Result<import("@oidfed/core").EntityAssessment>>;
```

### `TrustAnchor#discoverEntity`

Discover candidates, validate their chains, and select a result. Instance calls use per-call anchors first, then configured host anchors, then an empty set; per-call federation options override host options. Returns a `Result<DiscoveryResult>`.

[Source](../../../packages/authority/src/server.ts#L1123)

```typescript signature
discoverEntity(target: EntityId, options?: BoundFederationOptions & { trustAnchors?: TrustAnchorSet; }): Promise<Result<DiscoveryResult>>;
```

### `TrustAnchor#discoverEntityFromChain`

Validate supplied readonly statements for the target and return a `DiscoveryResult` in a `Result`. Instance calls inherit host anchors and options unless overridden. Supply supporting Entity Configurations through the options when the path needs them.

[Source](../../../packages/authority/src/server.ts#L1134)

```typescript signature
discoverEntityFromChain(target: EntityId, statements: readonly string[], options?: BoundFederationOptions & { trustAnchors?: TrustAnchorSet; }): Promise<Result<DiscoveryResult>>;
```

### `TrustAnchor#collection`

Readonly getter for the configured `EntityCollectionService`; `undefined` when `AuthorityConfig.collection` was omitted. Configuring a service does not advertise its HTTP endpoint automatically.

[Source](../../../packages/authority/src/server.ts#L1148)

```typescript signature
get collection(): EntityCollectionService | undefined;
```

### `TrustAnchor#entityId`

The exact configured Entity Identifier used in Entity Configurations, role context, and hosted services. The authority removes a trailing slash when constructing the well-known URL.

[Source](../../../packages/authority/src/server.ts#L1152)

```typescript signature
readonly entityId: EntityId;
```

### `TrustAnchor#getEntityConfiguration`

Build and sign a compact Entity Configuration JWT using the current key-provider state. This authority method does not reuse a Leaf-style EC cache. Rejects if keys, publication validation, or signing fail.

[Source](../../../packages/authority/src/server.ts#L1168)

```typescript signature
getEntityConfiguration(): Promise<string>;
```

### `TrustAnchor#getSubordinateStatement`

Load the registered subordinate and build a compact signed Subordinate Statement with the authority’s current signer, policy, and lifetime. Rejects for an unknown subordinate or invalid/unavailable publication data.

[Source](../../../packages/authority/src/server.ts#L1173)

```typescript signature
getSubordinateStatement(sub: EntityId): Promise<string>;
```

### `TrustAnchor#listSubordinates`

Return matching subordinate identifiers from `storage.subordinate.list(filter)` without paging options. This is a local storage read, not an HTTP request, and returns identifiers rather than records.

[Source](../../../packages/authority/src/server.ts#L1178)

```typescript signature
listSubordinates(filter?: ListFilter): Promise<EntityId[]>;
```

### `TrustAnchor#listSubordinatesExtended`

Invoke the existing Extended Listing handler locally and return its decoded body in a `Result`. Routing and HTTP client authentication are bypassed, and no advertised endpoint is required for this local call. Handler validation and configured limits still apply; `enabled: false` returns a `not_found` error result.

[Source](../../../packages/authority/src/server.ts#L1183)

```typescript signature
listSubordinatesExtended(params?: ExtendedListRequestParams, options?: ExtendedSubordinateListingOptions): Promise<Result<ExtendedSubordinateListingResult, FederationError>>;
```

### `TrustAnchor#resolveEntity`

Return a compact signed Resolve response JWT for the subject and optional requested anchor. A trusted local call can perform fresh discovery and warm the resolver cache. Per-call federation options are forwarded to the service. An unsuccessful resolver response rejects this promise with its error description.

[Source](../../../packages/authority/src/server.ts#L1191)

```typescript signature
resolveEntity(sub: EntityId, ta?: EntityId, options?: BoundFederationOptions): Promise<string>;
```

### `TrustAnchor#getTrustMarkStatus`

Build a local signed Trust Mark Status response, decode it, and return its payload object, not the JWT. Requires `storage.trustMarks`. Rejects when the mark instance is unknown or the status response cannot be produced; configured status policy applies.

[Source](../../../packages/authority/src/server.ts#L1200)

```typescript signature
getTrustMarkStatus(trustMark: string): Promise<TrustMarkStatusResponsePayload>;
```

### `TrustAnchor#listTrustMarkedEntities`

Return sorted, deduplicated subject identifiers with an eligible mark of the requested type issued by this authority. Requires Trust Mark storage and a consistent read snapshot. This does not make an external Status request.

[Source](../../../packages/authority/src/server.ts#L1205)

```typescript signature
listTrustMarkedEntities(trustMarkType: string): Promise<string[]>;
```

### `TrustAnchor#getTrustMarks`

Return a detached copy of the holder’s current Trust Mark references. This does not revoke, retrieve, or revalidate their issuer records.

[Source](../../../packages/authority/src/server.ts#L1210)

```typescript signature
getTrustMarks(): { trust_mark_type: string; trust_mark: string; }[];
```

### `TrustAnchor#attachTrustMark`

Verify the mark for this host with the supplied issuer evidence, then sign the prospective EC before replacing the holder references. Duplicate attachment is idempotent; the requested replacement policy can remove older references. A failed publication leaves the previous holder state intact.

[Source](../../../packages/authority/src/server.ts#L1216)

```typescript signature
attachTrustMark(jwt: string, options: AttachTrustMarkOptions): Promise<void>;
```

### `TrustAnchor#fetchAndAttachTrustMark`

Establish the requested issuer’s trust, retrieve a mark, validate it for this holder, and publish it through the same attachment operation. Trust and transport settings come from the supplied options; retrieval does not establish trust by itself.

[Source](../../../packages/authority/src/server.ts#L1220)

```typescript signature
fetchAndAttachTrustMark(options: Omit<FetchAndAttachTrustMarkOptions, "options"> & { readonly options?: BoundFederationOptions; }): Promise<void>;
```

### `TrustAnchor#removeTrustMark`

Remove matching holder references through a signed publication update. It can remove an expired mark without fetching or validating it again. It does not revoke the issuer’s stored mark; a failed publication leaves the previous references intact.

[Source](../../../packages/authority/src/server.ts#L1228)

```typescript signature
removeTrustMark(selector: RemoveTrustMarkSelector): Promise<void>;
```

### `TrustAnchor#setTrustMarkIssuers`

Deep-copy the replacement issuer map, validate and sign a prospective EC, then replace the anchor policy and update its issuer service. A validation/signing failure preserves the old policy. Does not invalidate already distributed ECs.

[Source](../../../packages/authority/src/server.ts#L1319)

```typescript signature
setTrustMarkIssuers(issuers: Record<string, string[]>): Promise<void>;
```

### `TrustAnchor#setTrustMarkOwners`

Deep-copy the replacement owner declarations, including nested keys, validate and sign a prospective EC, then replace the anchor policy and update its issuer service. A validation/signing failure preserves the old policy. Does not create or deliver owner delegation JWTs.

[Source](../../../packages/authority/src/server.ts#L1323)

```typescript signature
setTrustMarkOwners(owners: Record<string, TrustMarkOwner>): Promise<void>;
```

### `TrustAnchor#setTrustMarkDelegations`

Replace the issuer’s delegation map with an owned copy after map/value shape checks. Requires Trust Mark storage. This setter does not verify delegation signatures or expiry; applicable issuance and mark-validation operations perform those checks.

[Source](../../../packages/authority/src/server.ts#L1232)

```typescript signature
setTrustMarkDelegations(delegations: Record<string, string>): Promise<void>;
```

### `TrustAnchor#revokeTrustMark`

Revoke every matching active record issued by this authority for the type and subject, inside a storage transaction. Requires Trust Mark storage. Historical records remain stored; holder EC references and remote caches are not removed.

[Source](../../../packages/authority/src/server.ts#L1236)

```typescript signature
revokeTrustMark(type: string, subject: string): Promise<void>;
```

### `TrustAnchor#listTrustMarksForSubject`

Return detached eligible records issued by this authority for the subject, ordered newest first. Multiple eligible records of the same type can be returned. Requires Trust Mark storage and a consistent read snapshot.

[Source](../../../packages/authority/src/server.ts#L1240)

```typescript signature
listTrustMarksForSubject(subject: string): Promise<TrustMarkRecord[]>;
```

### `TrustAnchor#issueTrustMark`

Issue a compact Trust Mark JWT or reuse an eligible stored JWT. Requires Trust Mark storage, transactions, and a read snapshot. The default renewal mode is `"reuse"`; conflicting explicit options reject reuse. `"renew"` requests issuance while retaining earlier records. The selected signer must verify against the issuer’s published keys before the record is stored.

[Source](../../../packages/authority/src/server.ts#L1244)

```typescript signature
issueTrustMark(sub: string, trustMarkType: string, options?: TrustMarkIssuanceOptions): Promise<string>;
```

### `TrustAnchor#issueTrustMarkDelegation`

Sign a compact delegation JWT with this host as owner and `subject` as the delegated issuer. This operation does not require Trust Mark storage or publish owner policy. Per-call lifetime options override `trustMarkTtlSeconds`; otherwise the signing helper defaults to 86,400 seconds. Delivery to the issuer is arranged by the host.

[Source](../../../packages/authority/src/server.ts#L1253)

```typescript signature
issueTrustMarkDelegation(subject: string, trustMarkType: string, options?: TrustMarkDelegationIssuanceOptions): Promise<string>;
```

### `TrustAnchor#getHistoricalKeys`

Build a compact signed Historical Keys response JWT from the provider’s recorded public-key history. The return value is a string, not a key array. The response can contain `keys: []` when the provider has no historical keys. Provider and signer failures reject the call.

[Source](../../../packages/authority/src/server.ts#L1262)

```typescript signature
getHistoricalKeys(): Promise<string>;
```

### `TrustAnchor#registerSubordinate`

Validate publication claims, sanitize Superior-supplied metadata, supply timestamps from the authority clock, and add the subordinate in one transaction. Configured event storage receives a registration event atomically. Annotations require event storage; duplicate identifiers fail through storage.

[Source](../../../packages/authority/src/server.ts#L1267)

```typescript signature
registerSubordinate(record: Omit<SubordinateRecord, "createdAt" | "updatedAt">, annotations?: SubordinateEventAnnotations): Promise<void>;
```

### `TrustAnchor#updateSubordinate`

Update an existing subordinate through the lifecycle transaction. The input is captured and sanitized, and merged publication claims are checked. Configured event storage records relevant metadata, policy, and key changes; a no-op update creates no update event. Rejects for an unknown subordinate or invalid update.

[Source](../../../packages/authority/src/server.ts#L1276)

```typescript signature
updateSubordinate(subject: EntityId, updates: SubordinateRecordUpdate, annotations?: SubordinateEventAnnotations): Promise<void>;
```

### `TrustAnchor#revokeSubordinate`

Remove the registration in a transaction and append a revocation event when event storage is enabled. History remains available. Previously distributed statements and remote caches are not invalidated by the local removal.

[Source](../../../packages/authority/src/server.ts#L1284)

```typescript signature
revokeSubordinate(subject: EntityId, annotations?: SubordinateEventAnnotations): Promise<void>;
```

### `TrustAnchor#recordSubordinateEvents`

Validate and capture manually supplied observations, including nested extension data, then append them transactionally. Requires subordinate-event storage. This method does not modify enrollment state, suspend a participant, or revoke a registration.

[Source](../../../packages/authority/src/server.ts#L1293)

```typescript signature
recordSubordinateEvents(subject: EntityId, events: readonly SubordinateEvent[]): Promise<void>;
```

### `TrustAnchor#getSubordinateEvents`

Return a compact signed history JWT for the subject. Requires event storage and known registration or retained history. Its optional `exp` is controlled by `subordinateEventsTtlSeconds`; storage, cancellation, and signing failures reject the call.

[Source](../../../packages/authority/src/server.ts#L1300)

```typescript signature
getSubordinateEvents(subject: EntityId): Promise<string>;
```

### `TrustAnchor#handleRequest`

Dispatch a Web API `Request` to a composed role route or a federation endpoint. Endpoint routes use advertised paths and fixed selectors; Entity Configuration discovery stays anonymous GET. Ordinary protocol failures return HTTP responses. A role handler can still reject; the host provides HTTPS serving and external request policy.

[Source](../../../packages/authority/src/server.ts#L1305)

```typescript signature
handleRequest(request: Request): Promise<Response>;
```

