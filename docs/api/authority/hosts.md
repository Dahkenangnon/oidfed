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

[Source](../../../packages/authority/src/server.ts#L132)

Configuration shared by `TrustAnchor` and `Intermediate`. `metadata.federation_entity` must advertise fetch and list endpoints. An Intermediate requires nonempty `authorityHints` and rejects `trustMarkIssuers` and `trustMarkOwners`; a Trust Anchor permits Superiors and those policy maps together.

Metadata and extension claims are captured at construction. Initialized roles override metadata parameters in role order. Providers, stores, and callbacks remain service references. Construct a replacement host to change general metadata; the dedicated policy, holder, and subordinate methods update their own state. Hosted endpoint operations use `storage.cache`; `options` deliberately excludes `cache`. Instance discovery can receive a cache in its per-call options.

```typescript signature
interface AuthorityConfig extends EntityStatementExtensions {
	trustMarkDefaults?: TrustMarkIssuerConfig["trustMarkDefaults"];
	trustMarkSigner?: TrustMarkIssuerConfig["trustMarkSigner"];
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
	storage: StorageAdapter;
	/** Federation-only signing key provider and lifecycle manager. */
	keyProvider: FederationKeyLifecycleProvider;
	/**
	 * Resolves public Federation Entity Keys for authenticated remote authority
	 * endpoint clients. Defaults to `storage.subordinates.get(entityId)?.jwks`.
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
	options?: Omit<FederationOptions, "cache">;
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
| `trustMarkSigner?` | `TrustMarkIssuerConfig["trustMarkSigner"]` | Optional signer selector for issued marks; takes precedence over the nested selector. The resulting mark must verify with the issuer's published federation keys. |
| `trustMarkStatusPolicy?` | `TrustMarkIssuerConfig["trustMarkStatusPolicy"]` | Issuer policy for Status responses and local Resolve status assessments. A top-level callback overrides the nested callback and cannot reactivate an ineligible mark. |
| `trustMarkRequestExtensions?` | `TrustMarkIssuerConfig["trustMarkRequestExtensions"]` | Additional Trust Mark request-parameter validators. A supplied top-level map overrides the nested map. |
| `endpointAuthentication?` | `EndpointAuthentication` | Custom federation endpoint authentication methods and trusted transport-evidence lookup. Advertise accepted method names in each endpoint's metadata. |
| `trustMarkIssuer?` | `Omit<TrustMarkIssuerConfig, "storage">` | Shared issuer-service options. Storage always comes from `storage.trustMarks`. Top-level issuer callback/maps override their nested equivalents; nested `defaults` override the global `trustMarkTtlSeconds` fallback. |
| `requireAuthForFreshResolution?` | `boolean` | Defaults to `true`: anonymous HTTP Resolve requests use cached assessments. Local `resolveEntity()` and authenticated calls may discover fresh evidence. |
| `collection?` | `EntityCollectionIntegration` | Optional collection service configuration. Publishing the collection endpoint requires this configuration; creating the service alone does not advertise the endpoint. |
| `entityId` | `EntityId \| string` | HTTPS Entity Identifier without userinfo, query, or fragment. Construction removes one trailing slash before exposing the published identifier. |
| `metadata` | `{ federation_entity: FederationEntityMetadata } & Partial<{ [K in EntityType]: EntityTypeMetadataMap[K]; }>` | Copied metadata, including required fetch/list endpoints in `federation_entity`. Initialized roles replace conflicting parameters in role order. Entity-type blocks and direct metadata parameters cannot be null. |
| `storage` | `StorageAdapter` | Persistence adapter for subordinate records and any optional Trust Mark, event, replay, cache, and collection capabilities required by enabled operations. |
| `keyProvider` | `FederationKeyLifecycleProvider` | Current federation signer and public keys, plus rollover and historical-key operations. Retained as a live service reference. |
| `clientKeyProvider?` | `AuthorityClientKeyProvider` | Client federation-key lookup for endpoint authentication. Defaults to the caller's `storage.subordinates` record; it performs no automatic remote discovery. |
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
| `options?` | `Omit<FederationOptions, "cache">` | Federation defaults. Hosted endpoint contexts use `storage.cache`; this configuration type excludes a `cache` option. Per-call trust options can override host defaults. |
| `extendedListing?` | `ExtendedListingConfig` | Extended Listing behavior and limits. The handler defaults to enabled, but an HTTP route requires an advertised endpoint. `enabled: false` makes handler/local page requests return not_found. |
| `additionalClaims?` | `Readonly<Record<string, unknown>> \| undefined` | Custom top-level claims; standard Entity Statement claims cannot be overridden. |
| `crit?` | `readonly string[] \| undefined` | Extension claims recipients MUST understand and process (Federation §13.4). |

## `AuthorityServer`

[Source](../../../packages/authority/src/server.ts#L198)

The exported type contract for the authority server delegate, including local lifecycle operations and `handler()`. There is no root-package factory returning this interface. `TrustAnchor` and `Intermediate` expose `handleRequest(request)` directly and do not expose `handler()`.

Local methods call the corresponding service without HTTP client authentication. Methods returning plain values reject on failure. `listSubordinatesExtended()` returns a `Result` for the handler’s success or error response.

```typescript signature
interface AuthorityServer {
	readonly collection?: EntityCollectionService;
	registerSubordinate(
		record: Omit<SubordinateRecord, "createdAt" | "updatedAt">,
		annotations?: SubordinateEventAnnotations,
	): Promise<void>;
	updateSubordinate(
		subject: EntityId,
		updates: SubordinateRecordUpdate,
		annotations?: SubordinateEventAnnotations,
	): Promise<void>;
	revokeSubordinate(subject: EntityId, annotations?: SubordinateEventAnnotations): Promise<void>;
	recordSubordinateEvents(subject: EntityId, events: readonly SubordinateEvent[]): Promise<void>;
	getSubordinateEvents(subject: EntityId): Promise<string>;

	getEntityConfiguration(): Promise<string>;
	getSubordinateStatement(sub: EntityId): Promise<string>;
	listSubordinates(filter?: ListFilter): Promise<EntityId[]>;
	/**
	 * Direct access to the Extended Subordinate Listing response (skipping HTTP).
	 * Mirrors the wire-level handler — used for in-process pagination,
	 * server-side rendering, and tests.
	 */
	listSubordinatesExtended(
		params?: ExtendedSubordinateListingParams,
		options?: ExtendedSubordinateListingOptions,
	): Promise<Result<ExtendedSubordinateListingResult, FederationError>>;
	resolveEntity(sub: EntityId, ta?: EntityId, options?: FederationOptions): Promise<string>;
	getTrustMarkStatus(trustMark: string): Promise<TrustMarkStatusResponsePayload>;
	listTrustMarkedEntities(trustMarkType: string): Promise<string[]>;
	revokeTrustMark(type: string, subject: string): Promise<void>;
	listTrustMarksForSubject(subject: string): Promise<TrustMarkRecord[]>;
	getTrustMarks(): TrustMarkRef[];
	attachTrustMark(jwt: string, options: AttachTrustMarkOptions): Promise<void>;
	fetchAndAttachTrustMark(options: FetchAndAttachTrustMarkOptions): Promise<void>;
	removeTrustMark(selector: RemoveTrustMarkSelector): Promise<void>;
	setTrustMarkIssuers(issuers: Record<string, string[]>): Promise<void>;
	setTrustMarkOwners(owners: Record<string, TrustMarkOwner>): Promise<void>;
	setTrustMarkDelegations(delegations: Record<string, string>): Promise<void>;
	issueTrustMark(
		sub: string,
		trustMarkType: string,
		options?: TrustMarkIssuanceOptions,
	): Promise<string>;
	issueTrustMarkDelegation(
		subject: string,
		trustMarkType: string,
		options?: TrustMarkDelegationIssuanceOptions,
	): Promise<string>;
	getHistoricalKeys(): Promise<string>;
	handler(): (request: Request) => Promise<Response>;
}
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `collection?` | `EntityCollectionService` | Optional collection service on the delegate; absent when no collection service was configured. |
| `registerSubordinate` | `(record: Omit<SubordinateRecord, "createdAt" \| "updatedAt">, annotations?: SubordinateEventAnnotations) => Promise<void>` | Validate publication claims, sanitize Superior-supplied metadata, supply timestamps from the authority clock, and add the subordinate in one transaction. Configured event storage receives a registration event atomically. Annotations require event storage; duplicate identifiers fail through storage. |
| `updateSubordinate` | `(subject: EntityId, updates: SubordinateRecordUpdate, annotations?: SubordinateEventAnnotations) => Promise<void>` | Update an existing subordinate through the lifecycle transaction. The input is captured and sanitized, and merged publication claims are checked. Configured event storage records relevant metadata, policy, and key changes; a no-op update creates no update event. Rejects for an unknown subordinate or invalid update. |
| `revokeSubordinate` | `(subject: EntityId, annotations?: SubordinateEventAnnotations) => Promise<void>` | Remove the registration in a transaction and append a revocation event when event storage is enabled. History remains available. Previously distributed statements and remote caches are not invalidated by the local removal. |
| `recordSubordinateEvents` | `(subject: EntityId, events: readonly SubordinateEvent[]) => Promise<void>` | Validate and capture manually supplied observations, including nested extension data, then append them transactionally. Requires subordinate-event storage. This method does not modify enrollment state, suspend a participant, or revoke a registration. |
| `getSubordinateEvents` | `(subject: EntityId) => Promise<string>` | Return a compact signed history JWT for the subject. Requires event storage and known registration or retained history. Its optional `exp` is controlled by `subordinateEventsTtlSeconds`; storage, cancellation, and signing failures reject the call. |
| `getEntityConfiguration` | `() => Promise<string>` | Build and sign a compact Entity Configuration JWT using the current key-provider state. This authority method does not reuse a Leaf-style EC cache. Rejects if keys, publication validation, or signing fail. |
| `getSubordinateStatement` | `(sub: EntityId) => Promise<string>` | Load the registered subordinate and build a compact signed Subordinate Statement with the authority’s current signer, policy, and lifetime. Rejects for an unknown subordinate or invalid/unavailable publication data. |
| `listSubordinates` | `(filter?: ListFilter) => Promise<EntityId[]>` | Return matching subordinate identifiers from `storage.subordinates.list(filter)` without paging options. This is a local storage read, not an HTTP request, and returns identifiers rather than records. |
| `listSubordinatesExtended` | `(params?: ExtendedSubordinateListingParams, options?: ExtendedSubordinateListingOptions) => Promise<Result<ExtendedSubordinateListingResult, FederationError>>` | Invoke the existing Extended Listing handler locally and return its decoded body in a `Result`. Routing and HTTP client authentication are bypassed, and no advertised endpoint is required for this local call. Handler validation and configured limits still apply; `enabled: false` returns a `not_found` error result. |
| `resolveEntity` | `(sub: EntityId, ta?: EntityId, options?: FederationOptions) => Promise<string>` | Return a compact signed Resolve response JWT for the subject and optional requested anchor. A trusted local call can perform fresh discovery and warm the resolver cache. Per-call federation options are forwarded to the service. An unsuccessful resolver response rejects this promise with its error description. |
| `getTrustMarkStatus` | `(trustMark: string) => Promise<TrustMarkStatusResponsePayload>` | Build a local signed Trust Mark Status response, decode it, and return its payload object, not the JWT. Requires `storage.trustMarks`. Rejects when the mark instance is unknown or the status response cannot be produced; configured status policy applies. |
| `listTrustMarkedEntities` | `(trustMarkType: string) => Promise<string[]>` | Return sorted, deduplicated subject identifiers with an eligible mark of the requested type issued by this authority. Requires Trust Mark storage and a consistent read snapshot. This does not make an external Status request. |
| `revokeTrustMark` | `(type: string, subject: string) => Promise<void>` | Revoke every matching active record issued by this authority for the type and subject, inside a storage transaction. Requires Trust Mark storage. Historical records remain stored; holder EC references and remote caches are not removed. |
| `listTrustMarksForSubject` | `(subject: string) => Promise<TrustMarkRecord[]>` | Return detached eligible records issued by this authority for the subject, ordered newest first. Multiple eligible records of the same type can be returned. Requires Trust Mark storage and a consistent read snapshot. |
| `getTrustMarks` | `() => TrustMarkRef[]` | Return a detached copy of the holder’s current Trust Mark references. This does not revoke, retrieve, or revalidate their issuer records. |
| `attachTrustMark` | `(jwt: string, options: AttachTrustMarkOptions) => Promise<void>` | Verify the mark for this host with the supplied issuer evidence, then sign the prospective EC before replacing the holder references. Duplicate attachment is idempotent; the requested replacement policy can remove older references. A failed publication leaves the previous holder state intact. |
| `fetchAndAttachTrustMark` | `(options: FetchAndAttachTrustMarkOptions) => Promise<void>` | Establish the requested issuer’s trust, retrieve a mark, validate it for this holder, and publish it through the same attachment operation. Trust and transport settings come from the supplied options; retrieval does not establish trust by itself. |
| `removeTrustMark` | `(selector: RemoveTrustMarkSelector) => Promise<void>` | Remove matching holder references through a signed publication update. It can remove an expired mark without fetching or validating it again. It does not revoke the issuer’s stored mark; a failed publication leaves the previous references intact. |
| `setTrustMarkIssuers` | `(issuers: Record<string, string[]>) => Promise<void>` | Replace anchor issuer policy after successful EC preparation. Rejects when the delegate is an Intermediate. |
| `setTrustMarkOwners` | `(owners: Record<string, TrustMarkOwner>) => Promise<void>` | Replace anchor owner policy after successful EC preparation. Rejects when the delegate is an Intermediate. |
| `setTrustMarkDelegations` | `(delegations: Record<string, string>) => Promise<void>` | Replace the issuer’s delegation map with an owned copy after map/value shape checks. Requires Trust Mark storage. This setter does not verify delegation signatures or expiry; applicable issuance and mark-validation operations perform those checks. |
| `issueTrustMark` | `(sub: string, trustMarkType: string, options?: TrustMarkIssuanceOptions) => Promise<string>` | Issue a compact Trust Mark JWT or reuse an eligible stored JWT. Requires Trust Mark storage, transactions, and a read snapshot. The default renewal mode is `"reuse"`; conflicting explicit options reject reuse. `"renew"` requests issuance while retaining earlier records. The selected signer must verify against the issuer’s published keys before the record is stored. |
| `issueTrustMarkDelegation` | `(subject: string, trustMarkType: string, options?: TrustMarkDelegationIssuanceOptions) => Promise<string>` | Sign a compact delegation JWT with this host as owner and `subject` as the delegated issuer. This operation does not require Trust Mark storage or publish owner policy. Per-call lifetime options override `trustMarkTtlSeconds`; otherwise the signing helper defaults to 86,400 seconds. Delivery to the issuer is arranged by the host. |
| `getHistoricalKeys` | `() => Promise<string>` | Build a compact signed Historical Keys response JWT from the provider’s recorded public-key history. The return value is a string, not a key array. The response can contain `keys: []` when the provider has no historical keys. Provider and signer failures reject the call. |
| `handler` | `() => (request: Request) => Promise<Response>` | Return the delegate router as a FederationHandler. The concrete host classes expose handleRequest instead. |

## `ExtendedListingConfig`

[Source](../../../packages/authority/src/endpoints/extended-list.ts#L32)

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

[Source](../../../packages/authority/src/endpoints/extended-list-filters.ts#L17)

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

[Source](../../../packages/authority/src/endpoints/extended-list-filters.ts#L22)

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

[Source](../../../packages/authority/src/server.ts#L103)

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

## `ExtendedSubordinateListingParams`

[Source](../../../packages/authority/src/server.ts#L100)

Alias of core’s `ExtendedListRequestParams`. These are local camel-case parameters; the implementation serializes them to the endpoint’s wire names before invoking the handler. Omitted values retain the configured defaults.

```typescript signature
type ExtendedSubordinateListingParams = ExtendedListRequestParams;
```

Fields (including inherited fields). `?` marks an optional member; types below retain the declared aliases and readonly arrays.

| Field | Declared type | Description |
|---|---|---|
| `from?` | `string` | Opaque inclusive continuation returned as next. Keep other selectors unchanged when continuing. |
| `limit?` | `number` | Positive integer requested page size, capped by maxPageSize. Omission uses defaultPageSize. |
| `updatedAfter?` | `number` | Inclusive lower NumericDate bound on updatedAt. Finite fractional and negative values are accepted. |
| `updatedBefore?` | `number` | Inclusive upper NumericDate bound on updatedAt. Finite fractional and negative values are accepted. |
| `auditTimestamps?` | `boolean` | True requests registered/updated timestamps; false suppresses them, including when time filters otherwise imply them. |
| `claims?` | `ReadonlyArray<ExtendedListClaim \| string>` | Selected subordinate claims. Omission uses defaultClaims; [] explicitly suppresses that default. |
| `entityType?` | `string \| ReadonlyArray<string>` | One or more Entity Type Identifiers; any matching type qualifies. Custom nonempty identifiers are accepted. |
| `trustMarked?` | `boolean` | True requires an eligible issued mark; false adds no mark restriction. Trust Mark filters require mark storage. |
| `trustMarkType?` | `string \| ReadonlyArray<string>` | One or more mark types; any requested type qualifies. Requires Trust Mark storage. |
| `intermediate?` | `boolean` | True selects Intermediates, false selects non-Intermediates, and omission selects both. |

## `ExtendedSubordinateListingResult`

[Source](../../../packages/authority/src/server.ts#L109)

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

## `Intermediate`

[Source](../../../packages/authority/src/server.ts#L1267)

Authority host with at least one Superior. It issues statements for registered subordinates and can issue and hold Trust Marks. It rejects anchor issuer/owner policy configuration; its `setTrustMarkIssuers()` and `setTrustMarkOwners()` methods exist but always reject.

The constructor requires advertised fetch and list endpoints, initializes roles, and rejects conflicting routes. Publication is signed on demand. Local methods do not authenticate an HTTP caller; authorize administrative access in the host application.

```typescript signature
new Intermediate(config: AuthorityConfig): Intermediate;
```

### `Intermediate#assessEntity`

Assess the target locally or through an explicitly trusted resolver. Instance calls use per-call anchors first, then configured host anchors, then an empty set. Per-call options override host options; no implicit self-anchor trust is added. Returns a `Result<EntityAssessment>`.

[Source](../../../packages/authority/src/server.ts#L1042)

```typescript signature
assessEntity(target: EntityId, options?: EntityAssessmentOptions & {
		trustAnchors?: TrustAnchorSet;
	}): Promise<Result<import("@oidfed/core").EntityAssessment>>;
```

### `Intermediate#discoverEntity`

Discover candidates, validate their chains, and select a result. Instance calls use per-call anchors first, then configured host anchors, then an empty set; per-call federation options override host options. Returns a `Result<DiscoveryResult>`.

[Source](../../../packages/authority/src/server.ts#L1055)

```typescript signature
discoverEntity(target: EntityId, options?: FederationOptions & {
		trustAnchors?: TrustAnchorSet;
	}): Promise<Result<import("@oidfed/core").DiscoveryResult>>;
```

### `Intermediate#discoverEntityFromChain`

Validate supplied readonly statements for the target and return a `DiscoveryResult` in a `Result`. Instance calls inherit host anchors and options unless overridden. Supply supporting Entity Configurations through the options when the path needs them.

[Source](../../../packages/authority/src/server.ts#L1066)

```typescript signature
discoverEntityFromChain(target: EntityId, statements: readonly string[], options?: FederationOptions & {
		trustAnchors?: TrustAnchorSet;
	}): Promise<Result<import("@oidfed/core").DiscoveryResult>>;
```

### `Intermediate#collection`

Readonly getter for the configured `EntityCollectionService`; `undefined` when `AuthorityConfig.collection` was omitted. Configuring a service does not advertise its HTTP endpoint automatically.

[Source](../../../packages/authority/src/server.ts#L1080)

```typescript signature
get collection(): EntityCollectionService | undefined;
```

### `Intermediate#entityId`

Readonly published Entity Identifier. Construction removes one trailing slash from the configured value and validates the result. EC claims, role context, and hosted services use this identifier.

[Source](../../../packages/authority/src/server.ts#L1084)

```typescript signature
readonly entityId: EntityId;
```

### `Intermediate#getEntityConfiguration`

Build and sign a compact Entity Configuration JWT using the current key-provider state. This authority method does not reuse a Leaf-style EC cache. Rejects if keys, publication validation, or signing fail.

[Source](../../../packages/authority/src/server.ts#L1100)

```typescript signature
getEntityConfiguration(): Promise<string>;
```

### `Intermediate#getSubordinateStatement`

Load the registered subordinate and build a compact signed Subordinate Statement with the authority’s current signer, policy, and lifetime. Rejects for an unknown subordinate or invalid/unavailable publication data.

[Source](../../../packages/authority/src/server.ts#L1105)

```typescript signature
getSubordinateStatement(sub: EntityId): Promise<string>;
```

### `Intermediate#listSubordinates`

Return matching subordinate identifiers from `storage.subordinates.list(filter)` without paging options. This is a local storage read, not an HTTP request, and returns identifiers rather than records.

[Source](../../../packages/authority/src/server.ts#L1110)

```typescript signature
listSubordinates(filter?: ListFilter): Promise<EntityId[]>;
```

### `Intermediate#listSubordinatesExtended`

Invoke the existing Extended Listing handler locally and return its decoded body in a `Result`. Routing and HTTP client authentication are bypassed, and no advertised endpoint is required for this local call. Handler validation and configured limits still apply; `enabled: false` returns a `not_found` error result.

[Source](../../../packages/authority/src/server.ts#L1115)

```typescript signature
listSubordinatesExtended(params?: ExtendedSubordinateListingParams, options?: ExtendedSubordinateListingOptions): Promise<Result<ExtendedSubordinateListingResult, FederationError>>;
```

### `Intermediate#resolveEntity`

Return a compact signed Resolve response JWT for the subject and optional requested anchor. A trusted local call can perform fresh discovery and warm the resolver cache. Per-call federation options are forwarded to the service. An unsuccessful resolver response rejects this promise with its error description.

[Source](../../../packages/authority/src/server.ts#L1123)

```typescript signature
resolveEntity(sub: EntityId, ta?: EntityId, options?: FederationOptions): Promise<string>;
```

### `Intermediate#getTrustMarkStatus`

Build a local signed Trust Mark Status response, decode it, and return its payload object, not the JWT. Requires `storage.trustMarks`. Rejects when the mark instance is unknown or the status response cannot be produced; configured status policy applies.

[Source](../../../packages/authority/src/server.ts#L1128)

```typescript signature
getTrustMarkStatus(trustMark: string): Promise<TrustMarkStatusResponsePayload>;
```

### `Intermediate#listTrustMarkedEntities`

Return sorted, deduplicated subject identifiers with an eligible mark of the requested type issued by this authority. Requires Trust Mark storage and a consistent read snapshot. This does not make an external Status request.

[Source](../../../packages/authority/src/server.ts#L1133)

```typescript signature
listTrustMarkedEntities(trustMarkType: string): Promise<string[]>;
```

### `Intermediate#getTrustMarks`

Return a detached copy of the holder’s current Trust Mark references. This does not revoke, retrieve, or revalidate their issuer records.

[Source](../../../packages/authority/src/server.ts#L1138)

```typescript signature
getTrustMarks(): { trust_mark_type: string; trust_mark: string; }[];
```

### `Intermediate#attachTrustMark`

Verify the mark for this host with the supplied issuer evidence, then sign the prospective EC before replacing the holder references. Duplicate attachment is idempotent; the requested replacement policy can remove older references. A failed publication leaves the previous holder state intact.

[Source](../../../packages/authority/src/server.ts#L1144)

```typescript signature
attachTrustMark(jwt: string, options: AttachTrustMarkOptions): Promise<void>;
```

### `Intermediate#fetchAndAttachTrustMark`

Establish the requested issuer’s trust, retrieve a mark, validate it for this holder, and publish it through the same attachment operation. Trust and transport settings come from the supplied options; retrieval does not establish trust by itself.

[Source](../../../packages/authority/src/server.ts#L1148)

```typescript signature
fetchAndAttachTrustMark(options: FetchAndAttachTrustMarkOptions): Promise<void>;
```

### `Intermediate#removeTrustMark`

Remove matching holder references through a signed publication update. It can remove an expired mark without fetching or validating it again. It does not revoke the issuer’s stored mark; a failed publication leaves the previous references intact.

[Source](../../../packages/authority/src/server.ts#L1152)

```typescript signature
removeTrustMark(selector: RemoveTrustMarkSelector): Promise<void>;
```

### `Intermediate#setTrustMarkIssuers`

Always rejects: an `Intermediate` cannot publish `trust_mark_issuers`. This method exists on the class but does not update its state.

[Source](../../../packages/authority/src/server.ts#L1156)

```typescript signature
setTrustMarkIssuers(issuers: Record<string, string[]>): Promise<void>;
```

### `Intermediate#setTrustMarkOwners`

Always rejects: an `Intermediate` cannot publish `trust_mark_owners`. This method exists on the class but does not update its state.

[Source](../../../packages/authority/src/server.ts#L1160)

```typescript signature
setTrustMarkOwners(owners: Record<string, TrustMarkOwner>): Promise<void>;
```

### `Intermediate#setTrustMarkDelegations`

Replace the issuer’s delegation map with an owned copy after map/value shape checks. Requires Trust Mark storage. This setter does not verify delegation signatures or expiry; applicable issuance and mark-validation operations perform those checks.

[Source](../../../packages/authority/src/server.ts#L1164)

```typescript signature
setTrustMarkDelegations(delegations: Record<string, string>): Promise<void>;
```

### `Intermediate#revokeTrustMark`

Revoke every matching active record issued by this authority for the type and subject, inside a storage transaction. Requires Trust Mark storage. Historical records remain stored; holder EC references and remote caches are not removed.

[Source](../../../packages/authority/src/server.ts#L1168)

```typescript signature
revokeTrustMark(type: string, subject: string): Promise<void>;
```

### `Intermediate#listTrustMarksForSubject`

Return detached eligible records issued by this authority for the subject, ordered newest first. Multiple eligible records of the same type can be returned. Requires Trust Mark storage and a consistent read snapshot.

[Source](../../../packages/authority/src/server.ts#L1172)

```typescript signature
listTrustMarksForSubject(subject: string): Promise<TrustMarkRecord[]>;
```

### `Intermediate#issueTrustMark`

Issue a compact Trust Mark JWT or reuse an eligible stored JWT. Requires Trust Mark storage, transactions, and a read snapshot. The default renewal mode is `"reuse"`; conflicting explicit options reject reuse. `"renew"` requests issuance while retaining earlier records. The selected signer must verify against the issuer’s published keys before the record is stored.

[Source](../../../packages/authority/src/server.ts#L1176)

```typescript signature
issueTrustMark(sub: string, trustMarkType: string, options?: TrustMarkIssuanceOptions): Promise<string>;
```

### `Intermediate#issueTrustMarkDelegation`

Sign a compact delegation JWT with this host as owner and `subject` as the delegated issuer. This operation does not require Trust Mark storage or publish owner policy. Per-call lifetime options override `trustMarkTtlSeconds`; otherwise the signing helper defaults to 86,400 seconds. Delivery to the issuer is arranged by the host.

[Source](../../../packages/authority/src/server.ts#L1185)

```typescript signature
issueTrustMarkDelegation(subject: string, trustMarkType: string, options?: TrustMarkDelegationIssuanceOptions): Promise<string>;
```

### `Intermediate#getHistoricalKeys`

Build a compact signed Historical Keys response JWT from the provider’s recorded public-key history. The return value is a string, not a key array. The response can contain `keys: []` when the provider has no historical keys. Provider and signer failures reject the call.

[Source](../../../packages/authority/src/server.ts#L1194)

```typescript signature
getHistoricalKeys(): Promise<string>;
```

### `Intermediate#registerSubordinate`

Validate publication claims, sanitize Superior-supplied metadata, supply timestamps from the authority clock, and add the subordinate in one transaction. Configured event storage receives a registration event atomically. Annotations require event storage; duplicate identifiers fail through storage.

[Source](../../../packages/authority/src/server.ts#L1199)

```typescript signature
registerSubordinate(record: Omit<SubordinateRecord, "createdAt" | "updatedAt">, annotations?: SubordinateEventAnnotations): Promise<void>;
```

### `Intermediate#updateSubordinate`

Update an existing subordinate through the lifecycle transaction. The input is captured and sanitized, and merged publication claims are checked. Configured event storage records relevant metadata, policy, and key changes; a no-op update creates no update event. Rejects for an unknown subordinate or invalid update.

[Source](../../../packages/authority/src/server.ts#L1208)

```typescript signature
updateSubordinate(subject: EntityId, updates: SubordinateRecordUpdate, annotations?: SubordinateEventAnnotations): Promise<void>;
```

### `Intermediate#revokeSubordinate`

Remove the registration in a transaction and append a revocation event when event storage is enabled. History remains available. Previously distributed statements and remote caches are not invalidated by the local removal.

[Source](../../../packages/authority/src/server.ts#L1216)

```typescript signature
revokeSubordinate(subject: EntityId, annotations?: SubordinateEventAnnotations): Promise<void>;
```

### `Intermediate#recordSubordinateEvents`

Validate and capture manually supplied observations, including nested extension data, then append them transactionally. Requires subordinate-event storage. This method does not modify enrollment state, suspend a participant, or revoke a registration.

[Source](../../../packages/authority/src/server.ts#L1225)

```typescript signature
recordSubordinateEvents(subject: EntityId, events: readonly SubordinateEvent[]): Promise<void>;
```

### `Intermediate#getSubordinateEvents`

Return a compact signed history JWT for the subject. Requires event storage and known registration or retained history. Its optional `exp` is controlled by `subordinateEventsTtlSeconds`; storage, cancellation, and signing failures reject the call.

[Source](../../../packages/authority/src/server.ts#L1232)

```typescript signature
getSubordinateEvents(subject: EntityId): Promise<string>;
```

### `Intermediate#handleRequest`

Dispatch a Web API `Request` to a composed role route or a federation endpoint. Endpoint routes use advertised paths and fixed selectors; Entity Configuration discovery stays anonymous GET. Ordinary protocol failures return HTTP responses. A role handler can still reject; the host provides HTTPS serving and external request policy.

[Source](../../../packages/authority/src/server.ts#L1237)

```typescript signature
handleRequest(request: Request): Promise<Response>;
```

### `Intermediate.assessEntity`

Static callable property aliasing core’s [`assessEntity`](../core/chains.md#assessentity). Supply explicit anchors and options; this call does not inherit any authority instance’s configuration. The property is writable in the public declaration.

[Source](../../../packages/authority/src/server.ts#L1269)

```typescript signature
static assessEntity: typeof assessEntity;
```

Callable signature:

```typescript signature
Intermediate.assessEntity(subject: EntityId, anchors: TrustAnchorSet, options?: EntityAssessmentOptions): Promise<Result<EntityAssessment>>;
```

### `Intermediate.discoverEntity`

Static callable property aliasing core’s [`discoverEntity`](../core/chains.md#discoverentity). Supply explicit anchors and options; this call does not inherit any authority instance’s configuration. The property is writable in the public declaration.

[Source](../../../packages/authority/src/server.ts#L1271)

```typescript signature
static discoverEntity: typeof discoverEntity;
```

Callable signature:

```typescript signature
Intermediate.discoverEntity(entityId: EntityId, trustAnchors: TrustAnchorSet, options?: FederationOptions): Promise<Result<DiscoveryResult>>;
```

### `Intermediate.discoverEntityFromChain`

Static callable property aliasing core’s [`discoverEntityFromChain`](../core/chains.md#discoverentityfromchain). Supply explicit anchors and options; this call does not inherit any authority instance’s configuration. The property is writable in the public declaration.

[Source](../../../packages/authority/src/server.ts#L1273)

```typescript signature
static discoverEntityFromChain: typeof discoverEntityFromChain;
```

Callable signature:

```typescript signature
Intermediate.discoverEntityFromChain(entityId: EntityId, statements: readonly string[], trustAnchors: TrustAnchorSet, options?: FederationOptions): Promise<Result<DiscoveryResult>>;
```

### `Intermediate.sanitizeSubordinateMetadata`

Return a new outer metadata object with operational `federation_entity` fields removed. Return `undefined` for absent/nonobject input or when no entity-type blocks remain. Non-federation blocks and retained nested values are shared with the input; this helper is not a deep clone or a publication validator.

[Source](../../../packages/authority/src/server.ts#L1275)

```typescript signature
static sanitizeSubordinateMetadata: typeof sanitizeSubordinateMetadata;
```

Callable signature:

```typescript signature
Intermediate.sanitizeSubordinateMetadata(metadata: Readonly<Record<string, unknown>> | undefined): Record<string, unknown> | undefined;
```

## `InvalidAuthorityConfig`

[Source](../../../packages/authority/src/errors.ts#L4)

Configuration error used by authority validation. Its constructor takes a message and sets `name` to `"InvalidAuthorityConfig"`. Configuration checks can also throw ordinary `Error` or `TypeError`; callers must not assume every invalid configuration uses this class.

```typescript signature
new InvalidAuthorityConfig(message: string): InvalidAuthorityConfig;
```

## `InvalidMetadata`

[Source](../../../packages/authority/src/errors.ts#L30)

Reports a null entity-type block or direct metadata parameter. Its `path` is a metadata location such as `federation_entity.organization_name`, not an HTTP route. This null check does not reject nulls nested inside parameter objects or arrays; protocol validators can apply additional rules. The constructor builds the diagnostic message and sets `name` to `"InvalidMetadata"`.

```typescript signature
new InvalidMetadata(path: string): InvalidMetadata;
```

### `InvalidMetadata#path`

Readonly metadata location passed to the constructor and included in the error message.

[Source](../../../packages/authority/src/errors.ts#L31)

```typescript signature
readonly path: string;
```

## `InvalidSubordinateRecord`

[Source](../../../packages/authority/src/errors.ts#L12)

Error used when validating a stored subordinate record, including invalid identifiers and publication claims. The constructor takes a message and sets `name` to `"InvalidSubordinateRecord"`. Other lifecycle and adapter failures may use ordinary errors.

```typescript signature
new InvalidSubordinateRecord(message: string): InvalidSubordinateRecord;
```

## `InvalidSubordinateStatementShape`

[Source](../../../packages/authority/src/errors.ts#L20)

Exported error class for reporting Entity Configuration-only claims in a Subordinate Statement. The current authority publication paths use core claim validation and do not instantiate this class. It remains constructible by integrations; `forbiddenClaims` is included in its message and its `name` is `"InvalidSubordinateStatementShape"`.

```typescript signature
new InvalidSubordinateStatementShape(forbiddenClaims: readonly string[]): InvalidSubordinateStatementShape;
```

### `InvalidSubordinateStatementShape#forbiddenClaims`

Readonly reference to the constructor-supplied readonly array of forbidden top-level claim names. The constructor retains that array; it does not clone it.

[Source](../../../packages/authority/src/errors.ts#L21)

```typescript signature
readonly forbiddenClaims: readonly string[];
```

## `Middleware`

[Source](../../../packages/authority/src/handler.ts#L5)

An asynchronous HTTP middleware callback receiving a request and a `next` handler. The host integration invokes or composes these callbacks; the authority constructors do not take a middleware list.

```typescript signature
type Middleware = (
	request: Request,
	next: (request: Request) => Promise<Response>,
) => Promise<Response>;
```

## `TrustAnchor`

[Source](../../../packages/authority/src/server.ts#L1249)

Authority host whose identifier and keys consumers can configure as an anchor. It may also have Superiors. Without Superiors, omit `authorityHints` and `trustAnchorHints`; with Superiors, both hints may be supplied as nonempty arrays. It can publish and replace Trust Mark issuer/owner policy.

The constructor requires advertised fetch and list endpoints, initializes roles, and rejects conflicting routes. Being a Trust Anchor does not automatically add this host to the anchors used by its discovery methods. Publication is signed on demand. Authorize local administrative calls in the host application.

```typescript signature
new TrustAnchor(config: AuthorityConfig): TrustAnchor;
```

### `TrustAnchor#assessEntity`

Assess the target locally or through an explicitly trusted resolver. Instance calls use per-call anchors first, then configured host anchors, then an empty set. Per-call options override host options; no implicit self-anchor trust is added. Returns a `Result<EntityAssessment>`.

[Source](../../../packages/authority/src/server.ts#L1042)

```typescript signature
assessEntity(target: EntityId, options?: EntityAssessmentOptions & {
		trustAnchors?: TrustAnchorSet;
	}): Promise<Result<import("@oidfed/core").EntityAssessment>>;
```

### `TrustAnchor#discoverEntity`

Discover candidates, validate their chains, and select a result. Instance calls use per-call anchors first, then configured host anchors, then an empty set; per-call federation options override host options. Returns a `Result<DiscoveryResult>`.

[Source](../../../packages/authority/src/server.ts#L1055)

```typescript signature
discoverEntity(target: EntityId, options?: FederationOptions & {
		trustAnchors?: TrustAnchorSet;
	}): Promise<Result<import("@oidfed/core").DiscoveryResult>>;
```

### `TrustAnchor#discoverEntityFromChain`

Validate supplied readonly statements for the target and return a `DiscoveryResult` in a `Result`. Instance calls inherit host anchors and options unless overridden. Supply supporting Entity Configurations through the options when the path needs them.

[Source](../../../packages/authority/src/server.ts#L1066)

```typescript signature
discoverEntityFromChain(target: EntityId, statements: readonly string[], options?: FederationOptions & {
		trustAnchors?: TrustAnchorSet;
	}): Promise<Result<import("@oidfed/core").DiscoveryResult>>;
```

### `TrustAnchor#collection`

Readonly getter for the configured `EntityCollectionService`; `undefined` when `AuthorityConfig.collection` was omitted. Configuring a service does not advertise its HTTP endpoint automatically.

[Source](../../../packages/authority/src/server.ts#L1080)

```typescript signature
get collection(): EntityCollectionService | undefined;
```

### `TrustAnchor#entityId`

Readonly published Entity Identifier. Construction removes one trailing slash from the configured value and validates the result. EC claims, role context, and hosted services use this identifier.

[Source](../../../packages/authority/src/server.ts#L1084)

```typescript signature
readonly entityId: EntityId;
```

### `TrustAnchor#getEntityConfiguration`

Build and sign a compact Entity Configuration JWT using the current key-provider state. This authority method does not reuse a Leaf-style EC cache. Rejects if keys, publication validation, or signing fail.

[Source](../../../packages/authority/src/server.ts#L1100)

```typescript signature
getEntityConfiguration(): Promise<string>;
```

### `TrustAnchor#getSubordinateStatement`

Load the registered subordinate and build a compact signed Subordinate Statement with the authority’s current signer, policy, and lifetime. Rejects for an unknown subordinate or invalid/unavailable publication data.

[Source](../../../packages/authority/src/server.ts#L1105)

```typescript signature
getSubordinateStatement(sub: EntityId): Promise<string>;
```

### `TrustAnchor#listSubordinates`

Return matching subordinate identifiers from `storage.subordinates.list(filter)` without paging options. This is a local storage read, not an HTTP request, and returns identifiers rather than records.

[Source](../../../packages/authority/src/server.ts#L1110)

```typescript signature
listSubordinates(filter?: ListFilter): Promise<EntityId[]>;
```

### `TrustAnchor#listSubordinatesExtended`

Invoke the existing Extended Listing handler locally and return its decoded body in a `Result`. Routing and HTTP client authentication are bypassed, and no advertised endpoint is required for this local call. Handler validation and configured limits still apply; `enabled: false` returns a `not_found` error result.

[Source](../../../packages/authority/src/server.ts#L1115)

```typescript signature
listSubordinatesExtended(params?: ExtendedSubordinateListingParams, options?: ExtendedSubordinateListingOptions): Promise<Result<ExtendedSubordinateListingResult, FederationError>>;
```

### `TrustAnchor#resolveEntity`

Return a compact signed Resolve response JWT for the subject and optional requested anchor. A trusted local call can perform fresh discovery and warm the resolver cache. Per-call federation options are forwarded to the service. An unsuccessful resolver response rejects this promise with its error description.

[Source](../../../packages/authority/src/server.ts#L1123)

```typescript signature
resolveEntity(sub: EntityId, ta?: EntityId, options?: FederationOptions): Promise<string>;
```

### `TrustAnchor#getTrustMarkStatus`

Build a local signed Trust Mark Status response, decode it, and return its payload object, not the JWT. Requires `storage.trustMarks`. Rejects when the mark instance is unknown or the status response cannot be produced; configured status policy applies.

[Source](../../../packages/authority/src/server.ts#L1128)

```typescript signature
getTrustMarkStatus(trustMark: string): Promise<TrustMarkStatusResponsePayload>;
```

### `TrustAnchor#listTrustMarkedEntities`

Return sorted, deduplicated subject identifiers with an eligible mark of the requested type issued by this authority. Requires Trust Mark storage and a consistent read snapshot. This does not make an external Status request.

[Source](../../../packages/authority/src/server.ts#L1133)

```typescript signature
listTrustMarkedEntities(trustMarkType: string): Promise<string[]>;
```

### `TrustAnchor#getTrustMarks`

Return a detached copy of the holder’s current Trust Mark references. This does not revoke, retrieve, or revalidate their issuer records.

[Source](../../../packages/authority/src/server.ts#L1138)

```typescript signature
getTrustMarks(): { trust_mark_type: string; trust_mark: string; }[];
```

### `TrustAnchor#attachTrustMark`

Verify the mark for this host with the supplied issuer evidence, then sign the prospective EC before replacing the holder references. Duplicate attachment is idempotent; the requested replacement policy can remove older references. A failed publication leaves the previous holder state intact.

[Source](../../../packages/authority/src/server.ts#L1144)

```typescript signature
attachTrustMark(jwt: string, options: AttachTrustMarkOptions): Promise<void>;
```

### `TrustAnchor#fetchAndAttachTrustMark`

Establish the requested issuer’s trust, retrieve a mark, validate it for this holder, and publish it through the same attachment operation. Trust and transport settings come from the supplied options; retrieval does not establish trust by itself.

[Source](../../../packages/authority/src/server.ts#L1148)

```typescript signature
fetchAndAttachTrustMark(options: FetchAndAttachTrustMarkOptions): Promise<void>;
```

### `TrustAnchor#removeTrustMark`

Remove matching holder references through a signed publication update. It can remove an expired mark without fetching or validating it again. It does not revoke the issuer’s stored mark; a failed publication leaves the previous references intact.

[Source](../../../packages/authority/src/server.ts#L1152)

```typescript signature
removeTrustMark(selector: RemoveTrustMarkSelector): Promise<void>;
```

### `TrustAnchor#setTrustMarkIssuers`

Deep-copy the replacement issuer map, validate and sign a prospective EC, then replace the anchor policy and update its issuer service. A validation/signing failure preserves the old policy. Does not invalidate already distributed ECs.

[Source](../../../packages/authority/src/server.ts#L1156)

```typescript signature
setTrustMarkIssuers(issuers: Record<string, string[]>): Promise<void>;
```

### `TrustAnchor#setTrustMarkOwners`

Deep-copy the replacement owner declarations, including nested keys, validate and sign a prospective EC, then replace the anchor policy and update its issuer service. A validation/signing failure preserves the old policy. Does not create or deliver owner delegation JWTs.

[Source](../../../packages/authority/src/server.ts#L1160)

```typescript signature
setTrustMarkOwners(owners: Record<string, TrustMarkOwner>): Promise<void>;
```

### `TrustAnchor#setTrustMarkDelegations`

Replace the issuer’s delegation map with an owned copy after map/value shape checks. Requires Trust Mark storage. This setter does not verify delegation signatures or expiry; applicable issuance and mark-validation operations perform those checks.

[Source](../../../packages/authority/src/server.ts#L1164)

```typescript signature
setTrustMarkDelegations(delegations: Record<string, string>): Promise<void>;
```

### `TrustAnchor#revokeTrustMark`

Revoke every matching active record issued by this authority for the type and subject, inside a storage transaction. Requires Trust Mark storage. Historical records remain stored; holder EC references and remote caches are not removed.

[Source](../../../packages/authority/src/server.ts#L1168)

```typescript signature
revokeTrustMark(type: string, subject: string): Promise<void>;
```

### `TrustAnchor#listTrustMarksForSubject`

Return detached eligible records issued by this authority for the subject, ordered newest first. Multiple eligible records of the same type can be returned. Requires Trust Mark storage and a consistent read snapshot.

[Source](../../../packages/authority/src/server.ts#L1172)

```typescript signature
listTrustMarksForSubject(subject: string): Promise<TrustMarkRecord[]>;
```

### `TrustAnchor#issueTrustMark`

Issue a compact Trust Mark JWT or reuse an eligible stored JWT. Requires Trust Mark storage, transactions, and a read snapshot. The default renewal mode is `"reuse"`; conflicting explicit options reject reuse. `"renew"` requests issuance while retaining earlier records. The selected signer must verify against the issuer’s published keys before the record is stored.

[Source](../../../packages/authority/src/server.ts#L1176)

```typescript signature
issueTrustMark(sub: string, trustMarkType: string, options?: TrustMarkIssuanceOptions): Promise<string>;
```

### `TrustAnchor#issueTrustMarkDelegation`

Sign a compact delegation JWT with this host as owner and `subject` as the delegated issuer. This operation does not require Trust Mark storage or publish owner policy. Per-call lifetime options override `trustMarkTtlSeconds`; otherwise the signing helper defaults to 86,400 seconds. Delivery to the issuer is arranged by the host.

[Source](../../../packages/authority/src/server.ts#L1185)

```typescript signature
issueTrustMarkDelegation(subject: string, trustMarkType: string, options?: TrustMarkDelegationIssuanceOptions): Promise<string>;
```

### `TrustAnchor#getHistoricalKeys`

Build a compact signed Historical Keys response JWT from the provider’s recorded public-key history. The return value is a string, not a key array. The response can contain `keys: []` when the provider has no historical keys. Provider and signer failures reject the call.

[Source](../../../packages/authority/src/server.ts#L1194)

```typescript signature
getHistoricalKeys(): Promise<string>;
```

### `TrustAnchor#registerSubordinate`

Validate publication claims, sanitize Superior-supplied metadata, supply timestamps from the authority clock, and add the subordinate in one transaction. Configured event storage receives a registration event atomically. Annotations require event storage; duplicate identifiers fail through storage.

[Source](../../../packages/authority/src/server.ts#L1199)

```typescript signature
registerSubordinate(record: Omit<SubordinateRecord, "createdAt" | "updatedAt">, annotations?: SubordinateEventAnnotations): Promise<void>;
```

### `TrustAnchor#updateSubordinate`

Update an existing subordinate through the lifecycle transaction. The input is captured and sanitized, and merged publication claims are checked. Configured event storage records relevant metadata, policy, and key changes; a no-op update creates no update event. Rejects for an unknown subordinate or invalid update.

[Source](../../../packages/authority/src/server.ts#L1208)

```typescript signature
updateSubordinate(subject: EntityId, updates: SubordinateRecordUpdate, annotations?: SubordinateEventAnnotations): Promise<void>;
```

### `TrustAnchor#revokeSubordinate`

Remove the registration in a transaction and append a revocation event when event storage is enabled. History remains available. Previously distributed statements and remote caches are not invalidated by the local removal.

[Source](../../../packages/authority/src/server.ts#L1216)

```typescript signature
revokeSubordinate(subject: EntityId, annotations?: SubordinateEventAnnotations): Promise<void>;
```

### `TrustAnchor#recordSubordinateEvents`

Validate and capture manually supplied observations, including nested extension data, then append them transactionally. Requires subordinate-event storage. This method does not modify enrollment state, suspend a participant, or revoke a registration.

[Source](../../../packages/authority/src/server.ts#L1225)

```typescript signature
recordSubordinateEvents(subject: EntityId, events: readonly SubordinateEvent[]): Promise<void>;
```

### `TrustAnchor#getSubordinateEvents`

Return a compact signed history JWT for the subject. Requires event storage and known registration or retained history. Its optional `exp` is controlled by `subordinateEventsTtlSeconds`; storage, cancellation, and signing failures reject the call.

[Source](../../../packages/authority/src/server.ts#L1232)

```typescript signature
getSubordinateEvents(subject: EntityId): Promise<string>;
```

### `TrustAnchor#handleRequest`

Dispatch a Web API `Request` to a composed role route or a federation endpoint. Endpoint routes use advertised paths and fixed selectors; Entity Configuration discovery stays anonymous GET. Ordinary protocol failures return HTTP responses. A role handler can still reject; the host provides HTTPS serving and external request policy.

[Source](../../../packages/authority/src/server.ts#L1237)

```typescript signature
handleRequest(request: Request): Promise<Response>;
```

### `TrustAnchor.assessEntity`

Static callable property aliasing core’s [`assessEntity`](../core/chains.md#assessentity). Supply explicit anchors and options; this call does not inherit any authority instance’s configuration. The property is writable in the public declaration.

[Source](../../../packages/authority/src/server.ts#L1251)

```typescript signature
static assessEntity: typeof assessEntity;
```

Callable signature:

```typescript signature
TrustAnchor.assessEntity(subject: EntityId, anchors: TrustAnchorSet, options?: EntityAssessmentOptions): Promise<Result<EntityAssessment>>;
```

### `TrustAnchor.discoverEntity`

Static callable property aliasing core’s [`discoverEntity`](../core/chains.md#discoverentity). Supply explicit anchors and options; this call does not inherit any authority instance’s configuration. The property is writable in the public declaration.

[Source](../../../packages/authority/src/server.ts#L1253)

```typescript signature
static discoverEntity: typeof discoverEntity;
```

Callable signature:

```typescript signature
TrustAnchor.discoverEntity(entityId: EntityId, trustAnchors: TrustAnchorSet, options?: FederationOptions): Promise<Result<DiscoveryResult>>;
```

### `TrustAnchor.discoverEntityFromChain`

Static callable property aliasing core’s [`discoverEntityFromChain`](../core/chains.md#discoverentityfromchain). Supply explicit anchors and options; this call does not inherit any authority instance’s configuration. The property is writable in the public declaration.

[Source](../../../packages/authority/src/server.ts#L1255)

```typescript signature
static discoverEntityFromChain: typeof discoverEntityFromChain;
```

Callable signature:

```typescript signature
TrustAnchor.discoverEntityFromChain(entityId: EntityId, statements: readonly string[], trustAnchors: TrustAnchorSet, options?: FederationOptions): Promise<Result<DiscoveryResult>>;
```

### `TrustAnchor.sanitizeSubordinateMetadata`

Return a new outer metadata object with operational `federation_entity` fields removed. Return `undefined` for absent/nonobject input or when no entity-type blocks remain. Non-federation blocks and retained nested values are shared with the input; this helper is not a deep clone or a publication validator.

[Source](../../../packages/authority/src/server.ts#L1257)

```typescript signature
static sanitizeSubordinateMetadata: typeof sanitizeSubordinateMetadata;
```

Callable signature:

```typescript signature
TrustAnchor.sanitizeSubordinateMetadata(metadata: Readonly<Record<string, unknown>> | undefined): Record<string, unknown> | undefined;
```

