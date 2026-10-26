# Entity Collection

The [Entity Collection Endpoint, Draft 01](https://openid.net/specs/openid-federation-entity-collection-1_0-01.html) lists direct and indirect subordinates of a selected Trust Anchor. It returns unsigned JSON for discovery and display. Validate a selected entity through normal federation trust processing before relying on it. Clients must treat returned Trust Marks as unverified, even when the responder verified them to filter its results.

`@oidfed/core` provides `EntityCollectionService`, `MemoryEntityCollectionStore`, storage contracts, schemas, and the `fetchEntityCollection` client. Trust Anchors, Intermediates, and leaves use this service for their optional endpoint. An independent application can also serve collections using core, without becoming a Federation Entity.

See [collection responsibilities](operator-responsibilities.md#entity-collection-draft-01) for scope policy, scheduled refreshes, shared storage, and consumer trust checks.

## Independent providers

Supply the anchors and public Federation Entity Keys your application already trusts. In this example, the application supplies `anchorPublicJwks`. Do not use an unverified Entity Configuration as the source of those initial keys.

```ts
import {
  createTrustAnchorSet,
  EntityCollectionService,
  entityId,
} from "@oidfed/core";

const anchor = entityId("https://anchor.example");
export const collection = new EntityCollectionService({
  endpoint: "https://directory.example/collect?version=1",
  trustAnchors: createTrustAnchorSet([
    { entityId: anchor, jwks: anchorPublicJwks },
  ]),
});

// Run explicitly from an application-owned job or administrative operation.
const refreshed = await collection.refresh(anchor);
if (!refreshed.ok) throw new Error(refreshed.error.description);

const page = await collection.query({
  trustAnchor: anchor,
  entityType: ["openid_provider", "custom_entity_type"],
  entityClaims: ["entity_types", "entity_infos"],
  infoClaims: ["display_name", "logo_uri"],
  locale: ["en", "de"],
  limit: 20,
});
if (!page.ok) throw new Error(page.error.description);
```

Route Web-standard `Request` objects to `collection.handleRequest(request)` and return its `Response`. The application handles routing for an independent provider. Set `endpoint` to identify fixed query components such as `version=1`.

To request another page, repeat the filters and selectors and pass the returned `next` as `from`. You may change the page size. Cursors are opaque and can expire or be evicted. An unavailable cursor returns `page_not_found`.

## Federation entity integration

Pass `collection: { trustAnchors, ... }` in `AuthorityConfig` or `LeafConfig` and publish `metadata.federation_entity.federation_collection_endpoint`. The hosting class advertises that URL and routes its requests to core. Publishing the endpoint without collection configuration is an error. You can configure the service without publishing a URL to use it in process.

Access the service through `entity.collection` on `TrustAnchor`, `Intermediate`, or `Leaf`, or through the object returned by `createAuthorityServer`. Call `refresh(anchor)` explicitly. Requests to configured leaf collection routes go through `Leaf.handleRequest`. A leaf serving collections keeps its leaf role; it gains no Fetch, List, Extended Listing, or Subordinate Events endpoints.

A Federation Entity publishing the endpoint should also publish a Resolve endpoint, following [§3](https://openid.net/specs/openid-federation-entity-collection-1_0-01.html#section-3). The collection feature does not add a Resolve endpoint to a leaf automatically.

### Selecting an anchor

| Request | Result |
|---|---|
| Explicit supported `trust_anchor` | The selected anchor's collection, regardless of the responder's role. |
| Omitted on a Trust Anchor | Its own anchor collection. |
| Omitted on an identified Intermediate or leaf | An empty collection. |
| Omitted on a provider without an Entity Identifier | `invalid_request`. |
| Explicit unsupported anchor | `invalid_trust_anchor`. |

The anchor rules come from [§3.3.1](https://openid.net/specs/openid-federation-entity-collection-1_0-01.html#section-3.3.1).

## Collection policy

The default collector walks the federation and requires valid chains. You can replace it with a `collector` callback to use an application-owned inventory or another collection method, as permitted by [§5.1](https://openid.net/specs/openid-federation-entity-collection-1_0-01.html#section-5.1). The responder chooses which entities it exposes under [§5.3](https://openid.net/specs/openid-federation-entity-collection-1_0-01.html#section-5.3).

A custom collector returns `Result<readonly EntityCollectionCandidate[]>`. Each candidate contains an `entity` object and a finite `expiresAt` value in seconds since the epoch. Core supplies the snapshot identifier and refresh timestamp, validates the output, sorts by Entity Identifier, and publishes it atomically. Duplicate identifiers, malformed entries, unsupported evidence fields, and candidate sets above `maxEntities` fail refresh and preserve the previous snapshot.

For example, an independent application can publish an inventory without collecting trust chains for its entries:

```ts
import {
  createTrustAnchorSet,
  EntityCollectionEntitySchema,
  EntityCollectionService,
  entityId,
  nowSeconds,
  ok,
} from "@oidfed/core";

const anchor = entityId("https://anchor.example");
const trustAnchors = createTrustAnchorSet([
  { entityId: anchor, jwks: anchorPublicJwks },
]);

const directory = new EntityCollectionService({
  trustAnchors,
  collector: async ({ options }) => ok([
    {
      entity: EntityCollectionEntitySchema.parse({
        entity_id: "https://rp.example",
        entity_types: ["openid_relying_party"],
        entity_infos: {
          openid_relying_party: { display_name: "Example service" },
        },
      }),
      expiresAt: nowSeconds(options.clock) + 300,
    },
  ]),
});
```

The callback receives the selected `trustAnchor`, its pinned `trustAnchorJwks`, effective `options`, and a cancellation `signal`. Use this context to select entities associated with the requested anchor; the inventory source is responsible for that association. Network calls through the supplied options share the refresh budget and redirect policy. Core rejects unsupported anchors before invoking the callback.

Custom entries do not gain chain evidence. If they include Trust Marks, core confirms publication in the entity's self-signed Entity Configuration and verifies each qualifying mark using trusted issuer keys in the selected anchor context. The publication check alone does not establish a chain for the entry. Collectors cannot supply `verifiedMarks` or `chainExpiresAt` as proof. Verification happens during refresh; queries never fetch or verify marks on demand.

Use `filter` for an additional application restriction. It runs once per eligible entry after mark verification, with a detached, frozen entry and the same anchor context. Return `false` to exclude an entry, `true` to retain it, or `{ expiresAt }` to shorten its eligibility. Filtering an intermediate does not prevent collection of its descendants.

This example keeps entries with a particular verified mark and expires them when that evidence expires:

```ts
const curated = new EntityCollectionService({
  trustAnchors,
  filter: (entry) => {
    const matches = entry.verifiedMarks.filter(
      (mark) => mark.type === "https://marks.example/member",
    );
    return matches.length
      ? { expiresAt: Math.max(...matches.map((mark) => mark.expiresAt)) }
      : false;
  },
});
```

Filters may be asynchronous, so an application can consult its Resolve service or other policy data using the refresh context. Results are stored in the snapshot. If the policy depends on evidence that expires, return its expiry; the filter cannot extend the candidate's deadline. Filters and collectors never run while serving pages.

A callback failure or cancellation prevents publication. Cancellation releases the refresh queue even if a callback has not settled. Callbacks are trusted application code and must use the supplied signal to stop their own I/O. Shorten entry lifetimes or refresh explicitly when inventory or policy changes.

## Refresh and storage

By default, refresh walks the configured anchor's subordinate hierarchy and validates chains against pinned anchor keys. It collects informational metadata from Entity Configurations. The default collector includes only entities with a valid chain at refresh time, an oidfed policy permitted by [§5.3](https://openid.net/specs/openid-federation-entity-collection-1_0-01.html#section-5.3).

The default collector excludes entities with invalid chains or malformed Entity Configurations. An expired or untrusted Trust Mark does not invalidate an otherwise valid chain for collection purposes; it cannot satisfy a mark filter. If a branch is unreachable, traversal is incomplete, a mandatory work limit is reached, or the caller cancels, refresh fails and keeps the previous snapshot. The service publishes snapshots atomically and runs refreshes for each anchor in sequence within one `EntityCollectionService` instance. Shared storage does not coordinate refreshes across instances; the application must arrange that coordination, for example with a single scheduled writer or an external lock. Queries read stored snapshots without starting traversal or a scheduler. The `last_updated` value records the successful refresh time and stays unchanged when a page is read.

An empty list for a mark type in `trust_mark_issuers` permits any issuer for that type under [Federation §3.1.2](https://openid.net/specs/openid-federation-1_0.html#section-3.1.2). Core still establishes issuer trust and verifies the mark, following [§7.3](https://openid.net/specs/openid-federation-1_0.html#section-7.3).

Refresh completes entity traversal, publication checks, and explicitly listed issuer checks before resolving open issuers. Open-issuer lookups allow at most 50 fetches per issuer and 100 network calls in total per refresh, within the remaining `options.maxTotalFetches` allowance. An unreachable issuer or a lookup that reaches these limits leaves its marks unverified and allows publication. An incomplete lookup for an explicitly listed issuer still fails refresh. These are oidfed availability policies; cancellation, incomplete entity traversal, and mandatory fetch-budget exhaustion prevent publication.

Refresh checks alternate valid paths through shared intermediates and returns each entity once. It reuses fetched statements and listings within the refresh. Chain and mark expiry times reflect the verified paths in that snapshot. Exploring alternate paths counts toward the work limits; reaching a limit fails refresh and prevents publication of a partial collection. Cached subordinate attestations use the actual issuer identifier to keep authorities on the same origin separate.

| Setting | Default |
|---|---|
| `maxPageSize` | 100; also used when `limit` is omitted. |
| `cursorTtlSeconds` | 900 seconds. |
| `maxEntities` | 10,000 examined candidates; custom inventories have the same entry cap. |
| `options.maxTotalFetches` | 1,000 network calls across the refresh, including issuer resolution. |
| `options.maxConcurrentFetches` | 6. |
| `options.maxChainDepth` | 8. |
| `options.maxResponseBytes` | 512 KiB for network reads and collection pages. |
| `options.httpTimeoutMs` | 10 seconds per network operation and request-body read. |

To fit the byte cap, a response may contain fewer entities than requested. Each included entity keeps all requested claims that are available. If a single entry cannot fit, the query returns an availability error. Setting `limit=0` returns no entities, with a continuation value if results remain.

The default memory store retains superseded snapshots for 900 seconds. It holds up to 100 snapshots and 10,000 cursors; eviction at capacity can invalidate cursors sooner. Current snapshots remain available until replaced; queries exclude entries whose eligibility or applicable chain evidence has expired. Each process has its own memory store, which is lost on restart.

Implement `EntityCollectionStore` for durable or shared storage. Its `publish` operation must atomically select the new snapshot for the anchor. Return detached values from reads, retain referenced snapshots and cursors, enforce expiry, and isolate anchors. Keep entries ordered by Entity Identifier. A `CollectionEntry` stores public `entity` data, an `expiresAt` eligibility deadline, optional `chainExpiresAt` evidence, and `verifiedMarks`. The default collector sets eligibility to its verified chain expiry. Custom collectors supply an eligibility deadline without claiming that a chain was validated. Core derives verified mark evidence during refresh; unsigned collection responses cannot supply it.

Authorities can supply the store through `storage.collections`, or enable the core memory store with `MemoryStorageAdapter({ collections: true })`. An explicit `collection.store` takes precedence. If neither is supplied, the service creates its own memory store. Publishing a snapshot runs separately from subordinate registration transactions and leaves registration records unchanged.

## Filters and informational claims

- Repeating `entity_type` matches entities with any requested type. Repeating `trust_mark_type` requires every requested mark type. The responder checks published, verified marks and their expiry times, including marks from trusted issuers outside the entity's chain. A mark issuance record alone does not qualify.
- `query` uses case-insensitive substring matching across Entity Identifiers and mapped informational text in all available languages.
- By default, the built-in collector returns all available standard entity and informational claims. With selectors, it returns the requested available claims and required `entity_id`. An unsupported requested claim produces `unsupported_claim`. A supported claim that is unavailable for one entity is omitted.
- When included, `entity_types` contains all known types. An `entity_type` filter limits `entity_infos` to the requested types, plus the permitted `federation_entity` entry.
- Informational fields include organization and display names, descriptions, keywords, contacts, and informational URLs. When `display_name` is missing, the collector uses `client_name` for RP/client types and `resource_name` for resource types. These fallbacks also apply to language variants.
- Without `locale`, selected claims keep all available languages. With locales, the service uses case-insensitive RFC 4647 basic filtering to keep matching variants and selected untagged values. Claim selection applies before language filtering, so filtering cannot restore an excluded claim.

Declare additional claims for custom snapshot producers in the `entityClaims` and `infoClaims` configuration lists. The service checks exact declared names before interpreting language suffixes, including URI names containing `#`. To name a language variant, append `#` and the tag to the complete declared name. Response schemas preserve extension fields and custom Entity Type Identifiers. The service and client do not fetch informational URLs automatically.

In-process queries accept empty selector arrays. Use `entityClaims: []` to return only `entity_id`, or `infoClaims: []` to select no informational values. Draft 01 defines no wire representation for an empty list of claim names, so the HTTP client returns `invalid_request` for either empty selector array before fetching. Omit the selector to use the responder's defaults.

Queries exclude entries with an expired eligibility deadline or expired chain evidence when present. Expired marks no longer satisfy mark filters. Cursors expire before the evidence they depend on can change their result set. Choose a refresh schedule that keeps your application's collection data useful.

## Authentication and HTTP clients

The service accepts anonymous GET and form POST. Authenticated requests use POST with `private_key_jwt`. For a Federation Entity, `federation_collection_endpoint_auth_methods` declares the accepted methods and defaults to `["none"]`. If the hosted collection configuration also lists methods, they must match the metadata; conflicting settings fail construction. Independent providers configure methods directly on the service. Using `["none", "private_key_jwt"]` allows anonymous POST as well as authenticated requests. Supplied invalid credentials always produce an error.

Independent providers and leaves use `authentication.getClientFederationJwks` to supply trusted client keys. On an independent provider, set `authentication.receiverEntityId` to its identifier and assertion audience. This gives it an identified non-anchor responder, so requests that omit `trust_anchor` receive an empty collection. Hosted entities use their own identifier. Authorities use their existing `clientKeyProvider`.

The endpoint configuration controls allowed signing algorithms. Assertions require `exp` and a unique `jti`. The service checks for replays with the supplied `authentication.replayStore` or a memory store; authorities use `storage.replay` when available. Use shared replay storage across production instances.

```ts
import { fetchEntityCollection } from "@oidfed/core";

const result = await fetchEntityCollection(
  "https://directory.example/collect",
  { trustAnchor: anchor, entityType: ["openid_provider"], locale: ["en"] },
);
```

Use `method: "POST"` for anonymous POST. Supplying `clientAssertion` selects authenticated POST and puts credentials in the body. The client accepts JSON responses with a charset parameter and applies byte and time limits to both success and error bodies. It uses the existing URL, TLS, SSRF, timeout, size, and cancellation protections, and rejects redirects. Supply `options.httpClient` and a host/network policy when your deployment needs further restrictions.

Unknown extension parameters are ignored, as required by [Federation §8](https://openid.net/specs/openid-federation-1_0.html#section-8). Recognized parameters and supplied credentials are still validated.

Success responses use HTTP 200 and `application/json`. Errors include `error` and `error_description`. Malformed requests, unsupported defined features, and unsupported claims return 400. Unavailable cursors and unsupported anchors return 404; an unavailable initial snapshot returns 503.

## CLI

```sh
oidfed collection https://directory.example/collect \
  --trust-anchor https://anchor.example \
  --entity-type openid_provider --entity-type custom_entity_type \
  --info-claims display_name --locale en --limit 20
```

You can repeat `--trust-mark-type`, `--entity-claims`, `--info-claims`, and `--locale`. Use `--from` for the next page, `--post` for anonymous POST, or `--client-assertion-file` for authenticated POST. The endpoint can belong to an independent provider. The command does not require Entity Configuration discovery.
