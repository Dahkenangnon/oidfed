# `@oidfed/authority`

<p align="center">
  <a href="https://www.npmjs.com/package/@oidfed/authority"><img alt="npm" src="https://img.shields.io/npm/v/@oidfed/authority.svg" /></a>
  <a href="https://www.npmjs.com/package/@oidfed/authority"><img alt="downloads" src="https://img.shields.io/npm/dm/@oidfed/authority.svg" /></a>
  <a href="https://github.com/Dahkenangnon/oidfed/blob/main/packages/authority/LICENSE"><img alt="license" src="https://img.shields.io/npm/l/@oidfed/authority.svg" /></a>
  <a href="https://packagephobia.com/result?p=@oidfed/authority"><img alt="install size" src="https://packagephobia.com/badge?p=@oidfed/authority" /></a>
</p>

`@oidfed/authority` runs Trust Anchors and Intermediate Authorities. It issues Subordinate Statements and serves federation fetch, list, extended-list, subordinate-events, resolve, historical-key, and trust-mark endpoints through Web API handlers. Storage and federation signing keys come from injected providers.

See [operator and application responsibilities](../guide/operator-responsibilities.md) for authentication policy, key rollover, and the storage and capture contracts of optional endpoints.

Supply `options.logger` for [host-supplied logging](core.md#host-supplied-logging). Registration, update, revocation, and event-recording failures identify the operation; completion messages follow a successful transaction commit. Logging leaves rollback and exception handling unchanged. A committed event with a non-HTTPS `information_uri` produces an info notice because HTTPS is RECOMMENDED. No-op updates produce no event recommendation notice.

## Configuration ownership

A `TrustAnchor` or `Intermediate` copies its metadata at construction. Each role initializes once, then contributes its metadata in configuration order. Role parameters replace matching host parameters, and later roles win conflicts. Neither composition nor later changes to the caller's object modify another host's metadata.

To change general metadata, construct a replacement host with the new configuration. Existing methods for Trust Marks, anchor policy, and subordinate records remain the supported ways to update those specific resources. Key providers and storage adapters retain their identity, so their normal lifecycle operations continue to work.

Entity Configuration and Subordinate Statement TTLs must be positive safe integers. Trust Mark and Subordinate Events response TTLs must be positive finite numbers and may contain fractions. Invalid configured values fail during construction, before an endpoint needs to sign a response.

When implementing storage, follow the [transaction and snapshot contract](../guide/storage-guide.md). Use the repositories supplied to a transaction callback; awaiting a write through the parent adapter inside that callback can wait on the transaction itself.


## Usage

Later fragments reuse `ta`, `storage`, and `keyProvider` from the first example. Supply the subordinate's public federation key as `subordinatePublicKey` when enrolling it.

### Creating a Trust Anchor or Intermediate

This development example creates two authorities. Enrollment and HTTP serving are separate steps; see the [wiring guide](../guide/wiring-guide.md).
A Trust Anchor can have Superiors when it also participates as an Intermediate in another federation. An Intermediate lists at least one superior in `authorityHints`. Both must advertise federation fetch and list endpoints. Construction rejects missing required endpoints. Core trust validation also rejects checked Entity Configurations missing those endpoints when the entity is known to be an authority. These validation checks apply whether or not a logger is supplied.

```ts
import { TrustAnchor, Intermediate, MemoryStorageAdapter } from "@oidfed/authority";
import {
  createFederationSigningKey,
  generateSigningKey,
  MemoryFederationKeyProvider,
} from "@oidfed/core";

// 1. Generate keys and key provider
const keyPair = await generateSigningKey("ES256");
const keyProvider = new MemoryFederationKeyProvider(
  createFederationSigningKey(keyPair.privateKey),
);

const storage = new MemoryStorageAdapter({ trustMarks: true });

// 2. Initialize a Trust Anchor (no authorityHints)
const ta = new TrustAnchor({
  entityId: "https://ta.example.org",
  keyProvider,
  storage,
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: "https://ta.example.org/federation_fetch",
      federation_list_endpoint: "https://ta.example.org/federation_list",
      federation_resolve_endpoint: "https://ta.example.org/federation_resolve"
    }
  }
});

// 3. Give the Intermediate its own keys and storage.
const intermediateKeys = await generateSigningKey("ES256");
const intermediateKeyProvider = new MemoryFederationKeyProvider(
  createFederationSigningKey(intermediateKeys.privateKey),
);
const intermediate = new Intermediate({
  entityId: "https://intermediate.example.org",
  keyProvider: intermediateKeyProvider,
  storage: new MemoryStorageAdapter(),
  authorityHints: ["https://ta.example.org"],
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: "https://intermediate.example.org/federation_fetch",
      federation_list_endpoint: "https://intermediate.example.org/federation_list"
    }
  }
});
```

### Enrolling and managing subordinates

Use `ta.registerSubordinate(record)` or `intermediate.registerSubordinate(record)` to validate the Entity Identifier, sanitize metadata, and add timestamps. The memory store also checks identifiers on direct writes. Listing endpoints return a server error if a custom adapter supplies invalid identifiers; adapters must store and return valid Entity Identifiers. Direct adapter writes are also supported, as shown below. In that case, remove operational fields from `metadata.federation_entity` before writing the record; these fields belong in the subordinate's own Entity Configuration.

```ts
import { TrustAnchor } from "@oidfed/authority";
import { entityId } from "@oidfed/core";

const subordinateId = entityId("https://leaf.example.com");

// Sanitize metadata to strip operational fields
const rawMetadata = {
  federation_entity: {
    organization_name: "Example Leaf Entity",
    federation_fetch_endpoint: "https://leaf.example.com/federation_fetch" // Will be stripped
  }
};
const sanitized = TrustAnchor.sanitizeSubordinateMetadata(rawMetadata);

// Add the record directly using your storage adapter reference
await storage.subordinates.add({
  entityId: subordinateId,
  jwks: {
    keys: [subordinatePublicKey]
  },
  ...(sanitized ? { metadata: sanitized } : {}),
  createdAt: Math.floor(Date.now() / 1000),
  updatedAt: Math.floor(Date.now() / 1000)
});
```

### Supplying storage

Pass one `StorageAdapter` for subordinate records and any trust-mark, replay, and cache capabilities. `MemoryStorageAdapter` is for development and tests. Production adapters must provide serializable transactions with atomic commit and rollback; forwarding a transaction callback to ordinary repositories does not meet that contract.

See the [storage guide](../guide/storage-guide.md) for repository interfaces, cursor rules, expiry handling, and replay guarantees.

### Federation key rotation

Applications drive rollover through the injected `FederationKeyLifecycleProvider`. [Federation §11.2](https://openid.net/specs/openid-federation-1_0.html#section-11.2) describes four stages: publish the new keys, continue signing with the old keys while participants refresh, switch signers, then remove the old keys after a suitable overlap.

First, publish the next key:

```ts
import { createFederationSigningKey, generateSigningKey } from "@oidfed/core";

const nextKeyPair = await generateSigningKey("ES256");
const nextSigningKey = createFederationSigningKey(nextKeyPair.privateKey);
await keyProvider.publishKey(nextSigningKey);
```

The authority's next Entity Configuration contains the new public key and is still signed by the current signer. Authority configuration requests read the provider's current state. If a proxy caches those responses, account for its cache lifetime when choosing the propagation interval.

After the federation's publication and propagation interval, run the switch as a separate administrative step:

```ts
await keyProvider.switchActiveKey(nextSigningKey.signer.kid, {
  retirePreviousAfterMs: 7 * 24 * 60 * 60 * 1000,
});
```

The memory provider now signs with the new key and keeps the previous signer's public key available until the retirement deadline. Subsequent key-set reads exclude that old key at the deadline; its historical record remains. No background deletion timer runs. Other active keys, if supplied during initialization, are unaffected by this switch.

With the memory provider, the Historical Keys endpoint publishes retired and revoked keys. Before any such event, it returns a signed response with `keys: []`. Each key retains its recorded `exp` across requests; the response's `iat` identifies when that response was signed. The [core key lifecycle documentation](core.md#federation-key-providers) explains retirement and revocation timestamps. The endpoint signs the history supplied by a custom provider, whose records must describe actual key lifetimes under [§8.7.2](https://openid.net/specs/openid-federation-1_0.html#section-8.7.2).

The propagation interval before switching and the retirement interval after switching serve different stages. The application chooses when to switch; `retirePreviousAfterMs` controls only the post-switch overlap. Seven days is the memory provider's default, not a duration prescribed by the specification. Choose both intervals and Entity Configuration expiry according to the federation's security profile. A Leaf using the same provider must refresh its cached configuration after key-set changes; see [Leaf configuration caching](leaf.md#how-does-the-entity-configuration-caching-work).

Production key providers must preserve lifecycle state across restarts and coordinate serving processes. The in-memory provider does not persist or distribute changes.

`revokeKey(kid, reason)` applies the provider's local revocation policy. It excludes the key from current publication and signer selection and retains historical revocation information under [§8.7.2](https://openid.net/specs/openid-federation-1_0.html#section-8.7.2). It does not invalidate statements already held by other participants. [§11.4](https://openid.net/specs/openid-federation-1_0.html#section-11.4) leaves the federation-wide revocation process to the trust framework.

### Resolve discovery and caching

Anonymous HTTP Resolve requests use cached assessments by default, following the denial-of-service guidance in [Federation §18.1](https://openid.net/specs/openid-federation-1_0.html#section-18.1). A cold or expired cache returns `404 not_found` without discovery. Authenticated requests and local `resolveEntity(subject, anchor)` calls can perform discovery and populate the cache. Set `requireAuthForFreshResolution: false` to allow fresh anonymous discovery with the configured network limits.

The authority stores audience-neutral snapshots in `storage.cache`, or a bounded in-memory cache when none is provided. Snapshots are isolated to the authority instance and expire at the earliest of `options.cacheMaxTtlSeconds` (default 3,600 seconds), chain expiry, and included evidence expiry. Restarting an instance requires warming its Resolve cache again, even when its storage cache is shared.

Each response is signed with the current key. Its `exp` remains the minimum expiry of the subject's Trust Chain and included Trust Marks, as required by [§8.3.2](https://openid.net/specs/openid-federation-1_0.html#section-8.3.2). Delegation and issuer/history evidence expiry also cap the usable assessment. The cache reuse deadline controls how long the authority serves that assessment. Cached responses omit the optional issuer-chain header, which may describe an older signing key. Only authenticated responses carry the current caller's `aud`. Cache failures never enable anonymous discovery.

### Resolving Trust Marks

Resolve includes only marks authorized by the selected Trust Anchor, as required by [Federation §8.3.2](https://openid.net/specs/openid-federation-1_0.html#section-8.3.2). Independently established or out-of-band issuer evidence cannot replace that anchor's issuer and owner/delegation policy. An expired, unauthorized, or unverifiable mark is omitted while an otherwise valid holder chain can still resolve.

The resolver also checks active status before inclusion. For locally issued marks it uses the same assessment as the Status endpoint, including a configured `trustMarkStatusPolicy`; a `suspended` result is not active. For external issuers it uses authenticated issuer evidence to locate and verify the Status response, even when the issuer is absent from the holder's chain. The response expiration follows the chain and included marks; cache reuse also stops at earlier evidence deadlines. Applications enforce required accreditations using the [core requirement helper](core.md#trust-marks).

### Issuing and revoking Trust Marks

Authorities with `storage.trustMarks` use the shared issuer service for issuance, status, retrieval, and listing. A Trust Anchor can declare accepted issuers and owners; an Intermediate can issue marks without becoming a Trust Anchor.

```ts
const jwt = await ta.issueTrustMark(subject, type, {
  ttlSeconds: 600,
  renewal: "renew",
  logoUri: "https://auditor.example/logo.png",
  additionalClaims: { "organization_name#fr": "CornerShop" },
});
await ta.revokeTrustMark(type, subject);
const remaining = await ta.listTrustMarksForSubject(subject);
```

Default `renewal: "reuse"` returns an eligible stored JWT. Explicit options that conflict with that JWT fail; use `renewal: "renew"` to request new issuance. Renewal preserves earlier records and does not promise different JWT bytes within one clock tick. Revocation covers every active record issued by this authority for the type and subject. Listing and retrieval consider all candidates before selecting the newest eligible mark, so an expired delegation in a newer record cannot hide an older valid one. Selection uses exact issuer time and includes signature, profile, and delegation validity.

Lifetime precedence is per-call, per-type `trustMarkDefaults`, global `trustMarkTtlSeconds`, then the library default. `noExpiry: true` is an explicit alternative to a TTL. Changing defaults affects new issuance. `trustMarkSigner` can select a compatible signer, but the resulting mark must verify against the issuer's currently published Federation Entity Keys before storage.

Use `trustMarkIssuer.issuerEvidence` to supply independently trusted owner policy for delegated issuance. Configure delegation JWTs with `trustMarkDelegations`, or replace them through `setTrustMarkDelegations()`. Owner approval and delivery happen outside Federation; listing an issuer in anchor policy does not replace a required owner delegation. `issueTrustMarkDelegation(subject, type, options)` supports explicit lifetime, reference, and extension claims.

`setTrustMarkIssuers()` and `setTrustMarkOwners()` are Trust Anchor operations. They validate and sign a prospective EC before replacing owned configuration. Inputs are copied, including nested owner keys. Local changes do not invalidate already cached evidence at other entities.

As holders, both authority classes expose `getTrustMarks()`, `attachTrustMark()`, `fetchAndAttachTrustMark()`, and `removeTrustMark()`. Attachment verifies the subject and issuer evidence before publishing. Removal changes the EC and does not revoke the issuer's record.

`trustMarkStatusPolicy` receives frozen `{ baseStatus, record }` and may return a custom status and additional claims. It cannot revive an inactive mark or replace reserved response claims. `trustMarkRequestExtensions` registers per-parameter validation callbacks for the three endpoints; unknown parameters remain ignored. Callback failures produce controlled errors.

For shared advanced configuration, `trustMarkIssuer` accepts `defaults`, `trustMarkDefaults`, `issuerEvidence`, `trustMarkSigner`, `trustMarkStatusPolicy`, and `trustMarkRequestExtensions`. When both are supplied, the top-level authority option overrides its nested equivalent. Prefer one location for each setting.

## Configuration

When constructing a `TrustAnchor` or `Intermediate`, you pass an `AuthorityConfig` configuration object.

| Configuration Field | Type | Required | Description & Constraints |
|:---|:---|:---|:---|
| `entityId` | `EntityId \| string` | **Yes** | The entity identifier URL for this authority. Must be a valid HTTPS URL without query parameters or fragments. |
| `metadata` | `AuthorityConfig["metadata"]` | **Yes** | Structured object-valued metadata blocks published in the authority's self-signed configuration. Must include `federation_entity`; no leaf value within the metadata may be `null`. |
| `storage` | `StorageAdapter` | **Yes** | Persistence adapter for subordinates, trust marks, cache, and replays. |
| `keyProvider` | `FederationKeyLifecycleProvider`| **Yes** | Key provider exposing active federation signing keys, rollover lifecycle, and historical keys (e.g., `MemoryFederationKeyProvider` implements `FederationKeyLifecycleProvider`). |
| `clientKeyProvider` | `AuthorityClientKeyProvider` | No | Resolves public Federation Entity Keys for `private_key_jwt` federation endpoint callers. Defaults to `storage.subordinates.get(entityId)?.jwks`. |
| `authorityHints` | `readonly (EntityId \| string)[]` | *Conditional* | List of superior authorities this entity is subordinate to. Omit when the Trust Anchor has no Superiors. Otherwise supply a non-empty array; required for an `Intermediate`. |
| `trustAnchorHints` | `readonly (EntityId \| string)[]` | No | Optional non-empty list of preferred anchors. Available to entities with Superiors, including a `TrustAnchor`; rejected for anchors without Superiors. |
| `roles` | `EntityRole[]` | No | Optional composition roles (like OIDC Provider or Relying Party roles) bound to this entity context. |
| `trustMarks` | `TrustMarkRef[]` | No | Trust marks this authority claims about itself in its Entity Configuration. |
| `trustMarkIssuers` | `Record<string, string[]>` | No | Mapping of trust mark type URLs to authorized issuer entity IDs. Trust Anchors only; the Intermediate constructor rejects this field. |
| `trustMarkOwners` | `Record<string, TrustMarkOwner>`| No | Mapping of trust mark type URLs to owner declarations. Trust Anchors only; the Intermediate constructor rejects this field. |
| `trustMarkDelegations` | `Record<string, string>` | No | Pre-signed trust mark delegation JWTs, keyed by trust mark type. |
| `trustAnchors` | `TrustAnchorSet` | No | Configured trust anchors used for validating chains (e.g. during RP registration). |
| `entityConfigurationTtlSeconds`| `number` | No | TTL in seconds for the Entity Configuration JWT. Must be positive if defined. |
| `subordinateStatementTtlSeconds`| `number` | No | TTL in seconds for subordinate statement JWTs. Must be positive if defined. |
| `trustMarkTtlSeconds` | `number` | No | TTL in seconds for issued trust marks. Must be positive if defined. |
| `options` | `Omit<FederationOptions, "cache">`| No | Core federation options (e.g. custom clock skew, http timeouts, etc.). |
| `extendedListing` | `ExtendedListingConfig` | No | Settings for the advertised `federation_extended_list_endpoint` route. Set `enabled: false` to disable handling. |

Federation endpoint `private_key_jwt` authentication verifies the remote caller's assertion with keys returned by `clientKeyProvider`. If omitted, the authority uses the caller Entity Identifier to read the subordinate record from `storage.subordinates` and uses that record's `jwks`. Configure a custom provider when caller keys live in an external registry or key service; invalid, missing, or mismatched keys fail closed.

Each hosted federation endpoint uses its own `*_auth_methods` metadata, following [§8.8.1](https://openid.net/specs/openid-federation-1_0.html#section-8.8.1):

| Methods | Access |
|---|---|
| Omitted or `["none"]` | Anonymous requests |
| `["private_key_jwt"]` | Authenticated form POST required |
| `["none", "private_key_jwt"]` | Anonymous requests or authenticated form POST |

The built-in authority rejects empty lists and unsupported method names during construction, including unsupported names mixed with recognized methods. This hosting implementation supports `none` and `private_key_jwt`; core metadata schemas remain extensible for other implementations.

Most anonymous federation endpoints use GET. Trust Mark Status uses form POST with `trust_mark` whether authentication is enabled or not, as defined in [§8.4.1](https://openid.net/specs/openid-federation-1_0.html#section-8.4.1). Under optional authentication, omitting both credential fields allows anonymous access. Supplied empty, partial, invalid, or replayed assertions are rejected. Requests containing assertions must use POST. Form reads are bounded before dispatch.

Authority endpoints using this middleware require `storage.replay` when `private_key_jwt` is configured. Assertions must include `exp` and a non-empty `jti`; `iat` is optional. After signature and claim validation, the authority atomically claims the assertion before dispatch. Reuse across endpoints sharing that replay store is rejected, and replay-storage failures prevent dispatch. [Collection authentication](../guide/entity-collection.md#authentication-and-http-clients) uses the core service; it accepts a configured replay store or falls back to memory. Production instances must share replay state.

Entity Configuration discovery uses unauthenticated GET independently of these settings, following [§9.1](https://openid.net/specs/openid-federation-1_0.html#section-9.1). Federation defines no discovery auth-method parameter or client-assertion flow for it. The specification does not explicitly prohibit profile-specific network or TLS access controls; deployments using them need matching client transport support.

Authorities remove one trailing `/` from their own configured `entityId` at construction. The resulting published identifier is used consistently by the public `entityId` property, composed roles, Entity Configuration claims, and hosted services. Remote identifiers and authority hints are kept unchanged.

Discovery URL construction is a separate step: remove one trailing `/` from the published identifier, then append `/.well-known/openid-federation`, as §9 specifies. For example, configuring `https://ta.example.org/tenant///` publishes the identifier `https://ta.example.org/tenant//`, whose discovery URL is `https://ta.example.org/tenant//.well-known/openid-federation`. Use the host's published `entityId` when configuring other participants. Port numbers and encoded path components are preserved.

Role routes cannot replace Entity Configuration discovery, another role's route, or a registered federation endpoint. Construction fails with the conflicting path. Because role routes dispatch by pathname, a role also conflicts with an endpoint on that pathname when the endpoint has fixed query selectors. Choose a separate path for the role's handler.

Federation endpoint HTTP routes are derived from the paths advertised in `metadata.federation_entity`, not from fixed defaults. For example, advertising `federation_fetch_endpoint: "https://ta.example.org/custom/fetch"` mounts fetch handling at `/custom/fetch`. Optional endpoints are mounted only when their corresponding endpoint URL is advertised. Endpoint URLs must use HTTPS, must not contain fragments, and their route paths must be distinct.

### Extended subordinate listing

The endpoint implements Draft 03. Advertise `federation_extended_list_endpoint` in `metadata.federation_entity` to mount it, and leave `extendedListing.enabled` enabled. Enabling the handler alone does not add the metadata or route.

Read `next` from each response and pass it unchanged as `from` to resume from that entry, inclusive. Treat it as an opaque string; its encoding is chosen by the server. Unknown cursors return HTTP 404 with the JSON error `page_not_found`.

Continue while `next` is present, including after an empty response page. The handler scans through empty storage pages until it fills the response, exhausts storage, or reaches `maxStorePagesPerRequest`. At that work limit it returns the continuation, as required when more results remain by [Extended Listing §3.3](https://openid.net/specs/openid-federation-extended-listing-1_0.html#section-3.3). Repeated or backward storage cursors return `server_error`.

```typescript
const first = await ta.listSubordinatesExtended({ limit: 50, claims: [] });
if (first.ok && first.value.next !== undefined) {
  const second = await ta.listSubordinatesExtended({ from: first.value.next, limit: 50, claims: [] });
}
```

The same parameters are supported by `fetchExtendedSubordinatesList` in `@oidfed/core`. `trustMarkType` accepts a string or an array of strings. An entity matches if the authority has issued a still-valid mark of any requested type. On the wire, send one `trust_mark_type` parameter per type. Custom storage adapters must apply the same OR semantics to `ListFilter.trustMarkType`; adapters that filter scanned batches follow the [storage continuation rules](../guide/storage-guide.md#subordinates).

Repeated `entity_type` values filter with union semantics: an entity matches when it has any of the requested types. Federation §8.2.1's "include all specified Entity Types" wording condenses an explicitly-OR drafting history (openid/federation commits ee7a372f → 49d194e3), and Entity Collection Draft 01 clarifies the same inherited sentence to "any of". Entity Type Identifier values are open-ended (Federation §5.1 permits additional identifiers and no registry exists): both listing endpoints accept any non-empty identifier and return an empty result when no subordinate carries it, rather than rejecting unknown values. Custom storage adapters must apply the same union, open-value semantics to `ListFilter.entityTypes`.

Both listing endpoints treat `trust_marked=true` as requiring a valid issued mark. They treat `false` as adding no mark restriction; any supplied `trust_mark_type` filter still applies. The base specification defines the true case and leaves the false case unspecified. Custom storage adapters should follow the same policy for `ListFilter.trustMarked`. For `intermediate`, true selects intermediates, false selects non-intermediates, and omission selects both. These false-value meanings are oidfed policies; [Federation §8.2.1](https://openid.net/specs/openid-federation-1_0.html#section-8.2.1) specifies the true cases.

Extended Listing time filters and audit timestamps use NumericDate seconds. Fractional and negative values are accepted, and `updated_after` and `updated_before` include records exactly at the boundary. Query values also accept decimal exponent notation. Values must be finite numbers.

Omitting `claims` uses `defaultClaims`. An explicit `claims: []` sends `claims=` and suppresses the default statements. If a claim selection is present, `subordinate_statement` is returned only when requested; other requested statement claims are included when available.

`claims=trust_marks` returns references with `trust_mark_type` and the original `trust_mark` JWT, following [Federation §3.1.2](https://openid.net/specs/openid-federation-1_0.html#section-3.1.2). An undecodable JWT, wrong Trust Mark `typ`, or inconsistent reference type or subject produces `server_error`. These references appear in the listing JSON; the embedded signed Subordinate Statement retains Federation's claim restrictions. Subjects with no currently valid marks have an empty `trust_marks` array. The same empty array is returned when no Trust Mark store is configured. Trust Mark filters still require that store and otherwise return `unsupported_parameter`.

Requested `jwks` values pass the same public-key publication checks as signed Subordinate Statements. This follows [Draft 03 §3.2](https://openid.net/specs/openid-federation-extended-listing-1_0.html#section-3.2) and [Federation §3.1.1](https://openid.net/specs/openid-federation-1_0.html#section-3.1.1). If a stored set contains private material or fails validation, the whole request returns HTTP 500 with a generic JSON `server_error`; `listSubordinatesExtended()` returns an error `Result`. This handling of invalid server data uses [Federation §8.9](https://openid.net/specs/openid-federation-1_0.html#section-8.9). Validation preserves stored records and publishes a detached snapshot of valid keys, including their JSON extension members.

Leaf entities cannot advertise this endpoint.

The `extendedListing` object supports:

- `enabled` (`boolean`): Whether the advertised endpoint accepts requests. Defaults to `true`.
- `maxPageSize` (`number`): Upper limit on page sizes. Defaults to `500`.
- `maxResponseBytes` (`number`): UTF-8 JSON success-response limit, including `next`. Defaults to `524288` (512 KiB).
- `defaultPageSize` (`number`): Default page size if the client omits `limit`. Defaults to the smaller of `100` and `maxPageSize`.
- `supportTimeFilters` (`boolean`): Whether to honor `updated_after` and `updated_before` queries. Defaults to `true`.
- `supportAuditTimestamps` (`boolean`): Whether to honor `audit_timestamps` query. Defaults to `true`.
- `defaultClaims` (`ReadonlyArray<string>`): Claims fetched when the client sends no `claims` query. Defaults to `["subordinate_statement"]`.
- `maxStorePagesPerRequest` (`number`): Maximum index page lookups allowed per request to protect performance. Defaults to `16`.
- `storeBatchSize` (`number`): Page batch sizes retrieved during filtering. Defaults to `defaultPageSize`.

All five numeric limits must be positive safe integers. An explicit `defaultPageSize` must not exceed `maxPageSize`. Invalid configuration fails when the handler is created.

Extended Listing accepts repeated `entity_type` filters. The CLI mirrors this with repeated `--entity-type` options. Use `--claims ""` for identifier-only entries. `supportAuditTimestamps` controls explicit timestamp requests; time filters can also include timestamps unless the caller sends `audit_timestamps=false`. Disable both timestamp requests and time filters when neither facility should disclose dates.

## Common questions

### What is the difference between `TrustAnchor` and `Intermediate`?

A `TrustAnchor` represents a root of trust for its participants and can also specify `authorityHints` to participate under another federation. Its Trust Mark issuer/owner policy remains available in this configuration. An `Intermediate` is a subordinate authority that must list at least one superior authority in `authorityHints`. Intermediates also cannot carry `trustMarkIssuers` or `trustMarkOwners` metadata block configurations since those claims are reserved for Trust Anchors.

### How do I enroll a subordinate entity?

Use `await ta.registerSubordinate(record)` to sanitize metadata and add timestamps. Use `await storage.subordinates.add(record)` when managing those fields yourself.

### Why does subordinate storage reject my metadata?

A subordinate's metadata block in the storage record must not carry operational fields (such as `federation_fetch_endpoint` or `federation_list_endpoint`) inside `metadata.federation_entity`. Use `TrustAnchor.sanitizeSubordinateMetadata(metadata)` or `Intermediate.sanitizeSubordinateMetadata(metadata)` to strip these fields before calling `.add()` or `.update()`.

Subordinate metadata excludes operational endpoint fields. Federation §§8.1, 8.2, and 8.4 require Entity Configuration publication for fetch, list, and Trust Mark Status endpoints; Extended Listing §4 imports the list restriction. oidfed also reserves the other operational endpoint fields and authentication companions to the host's Entity Configuration as a library policy.

### Is explicit client registration handled automatically?

Compose an `OidcProviderRole` from `@oidfed/oidc` into the entity's `roles`. The parent initializes its registration handler and dispatches matching requests through `handleRequest()`. Connect registration hooks to your OP's client store. Automatic registration still needs a call from the OP's authorization or PAR flow.

Extended Listing bounds the UTF-8 JSON success response, including its continuation cursor, through `extendedListing.maxResponseBytes` (default: 512 KiB). This complements the count and scan limits and follows [Draft 03 §3.1.2](https://openid.net/specs/openid-federation-extended-listing-1_0-03.html#section-3.1.2). A full byte budget produces a shorter page with `next` pointing to the first omitted entity. An entry that cannot fit alone returns `server_error`; reduce the requested claims or increase the server and client byte budgets. The endpoint preserves the requested claims and stops building further entries when the page is full.

### Select stored extension claims

A subordinate's `additionalClaims` can be requested directly, without downloading its signed statement. For example, after registering a subordinate with `additionalClaims: { campus: "north" }`, request `claims: ["campus"]`. The field also remains inside `subordinate_statement` when that statement is requested.

Only selected fields are projected. Missing claims are omitted, and `claims: []` still gives identifier-only entries. Standard listing fields keep their meanings: an extension named `id`, `registered`, `updated`, or `subordinate_statement` cannot replace the listing's own field. Such extensions remain available in the signed statement where permitted. All projected values count toward the response byte limit. This uses the extension allowance in [Extended Listing §3.2–3.3](https://openid.net/specs/openid-federation-extended-listing-1_0-03.html#section-3.2); it does not introduce another metadata store.

### Filter by your federation's own fields

**Campus Alliance** can let callers ask for registrations from a particular campus. Configure the filter on `TrustAnchor` or `Intermediate` through `extendedListing.requestFilters`:

```ts
import type { ExtendedListingConfig } from "@oidfed/authority";
import { err, federationError, FederationErrorCode, fetchExtendedSubordinatesList, ok } from "@oidfed/core";

const extendedListing: ExtendedListingConfig = {
  requestFilters: {
    campus: {
      parse(values) {
        if (!values.length || values.some(value => !["north", "south"].includes(value))) {
          return err(federationError(FederationErrorCode.InvalidRequest, "Unknown campus"));
        }
        return ok([...values]);
      },
      matches(record, campuses) {
        return Array.isArray(campuses) && campuses.includes(record.additionalClaims?.campus);
      },
    },
  },
};
// Pass extendedListing alongside the authority's other construction options.
```

The library parses each present registered parameter once, even when there are no registrations. The parser returns a `Result`; an error becomes HTTP 400 `invalid_request`. The parsed value must be JSON data, or `undefined` for a flag. A predicate returns a boolean. Both callbacks may be asynchronous and receive a second/third `context` argument containing an `AbortSignal`.

Filters see frozen copies of records and parsed values. Honor the signal when doing asynchronous work. One `options.httpTimeoutMs` deadline covers the whole custom-filter operation; cancellation releases the caller even when a callback does not settle. Exceptions, rejected promises, and malformed callback results produce generic `server_error` responses.

Different custom filters are combined with AND, alongside the standard filters. Each parser decides how repeated values of its own parameter work; the example treats campuses as alternatives. This is an oidfed extension convention, not a new specification rule. Unknown, unregistered parameters remain ignored. Filter names cannot replace standard protocol selectors or registered authentication credentials.

For an HTTP client, use the existing `additionalParameters` option:

```ts
const page = await fetchExtendedSubordinatesList(endpoint, {
  entityType: "custom_academic_service",
  claims: ["campus"],
  limit: 25,
}, {
  additionalParameters: { campus: ["north", "south"] },
});
if (!page.ok) throw new Error(page.error.description);
```

For a local call, use the optional second argument:

```ts
const page = await authority.listSubordinatesExtended(
  { claims: ["campus"], limit: 25 },
  { additionalParameters: { campus: "north" }, signal },
);
if (!page.ok) throw new Error(page.error.description);
```

Keep the same filters when following `next`. Custom predicates run before counting matches toward the page limit, but scanning remains bounded by `maxStorePagesPerRequest`. A sparse page can be empty and still have `next`; continue until `next` is absent. Storage adapters need no new methods, and still apply the standard filters. For large datasets, account for the cost of examining records that custom predicates exclude.

An unknown `from` value returns `page_not_found`. A failed storage lookup instead returns `server_error`, including through the local Result API; a database outage is not evidence that a cursor is unknown.

## Subordinate event history

Automatic `jwks_update` capture compares the published public JWK Set, including lifecycle dates and extension members. Reordering keys alone creates no event. Invalid replacement keys fail within the transaction, preserving both the record and its history.

The optional [Subordinate Events Endpoint, Draft 01](https://openid.net/specs/openid-federation-subordinate-events-1_0.html) publishes an authority's recorded history about its Immediate Subordinates. Both `TrustAnchor` and `Intermediate` support it. Enable event storage and advertise `federation_subordinate_events_endpoint` in the authority's own metadata:

```ts
const storage = new MemoryStorageAdapter({ subordinateEvents: true });

// In the authority configuration's metadata.federation_entity:
// federation_subordinate_events_endpoint: "https://ta.example.org/history"
```

The memory adapter is for development and tests. Production adapters implement the optional `subordinateEvents` repository in both the adapter and its transactions. Advertising the endpoint without event storage fails at construction.

Use the authority instance's lifecycle methods to record changes automatically:

| Method | Behavior |
|---|---|
| `registerSubordinate(record)` | Adds a registration and records `registration`, including its initial configuration. |
| `updateSubordinate(subject, updates)` | Records changes to attested metadata, metadata policy, and registered public keys as `metadata_update`, `metadata_policy_update`, or `jwks_update`. |
| `revokeSubordinate(subject)` | Removes the current registration and records `revocation`, preserving history. |
| `recordSubordinateEvents(subject, events)` | Appends explicit observations or imported events, including `suspension` and custom event types. It does not change registration state. |
| `getSubordinateEvents(subject)` | Returns a signed history JWT for local use. Throws for unknown history or unavailable storage. |

State changes and generated events commit in one transaction. Registration and updates copy their inputs before asynchronous work, so later changes to the caller’s object cannot alter the stored record or its events. No-op updates, reordered object properties, reordered key sets, and authority signing-key rotation do not produce subordinate update events. Initial registration produces only its registration event. Draft 01 §2.3.3's "at the same time" exclusion is interpreted as applying to initial updates within the registration operation; a later change retains its event even if the clock gives it the same timestamp.

Manual event recording also copies nested extension values before waiting for storage, so changing an input object after calling `recordSubordinateEvents()` cannot change the recorded observation.

An aborted Events request stops waiting for storage or key lookup and does not start signing after that wait. The handler returns a Federation JSON server error. An already-running storage operation or signing operation may finish independently; cancellation does not roll back committed history. The configured `options.signal` also applies to local `getSubordinateEvents()` calls, which reject on cancellation.

Direct `storage.subordinates` writes remain supported and do not automatically record events. Enabling event storage does not reconstruct past history from record timestamps. See the [storage contract](../guide/storage-guide.md#subordinate-events) for explicit transactional appends.

The endpoint accepts GET with a required `sub` Entity Identifier. If authentication is configured through `federation_subordinate_events_endpoint_auth_methods`, it uses the existing federation client-authentication middleware and authenticated form POST. A `private_key_jwt` assertion names the authority's Entity Identifier as its audience, which can differ from the endpoint URL. The authenticated client and requested subject need not be identical.

Unsupported methods receive HTTP 405 with `Allow` and a Federation JSON error containing `error: "invalid_request"` and `error_description`. This applies to both the anonymous handler and authenticated route. The advertised URL must have no fragment, including an empty trailing `#`.

Successful responses are compact JWTs with media type `application/entity-events-statement+jwt` and JWT type `entity-events-statement+jwt`, signed with the authority's Federation Entity Key. They contain `iss`, `sub`, a fresh response `iat`, and `federation_registration_events`. By default, the authority omits the optional `exp`. Set `subordinateEventsTtlSeconds` on `TrustAnchor` or `Intermediate` to a positive, finite number to include it, as permitted by Draft 01 §2.3.2. For example, `subordinateEventsTtlSeconds: 300` gives each response a five-minute lifetime measured from its own `iat`. Event occurrence times remain unchanged when a new response is issued.

A current subordinate with no recorded events receives a signed empty history. Retained history remains available after removal and re-registration. A subject with neither a current record nor history receives HTTP 404 JSON `not_found`. Storage failures produce a server error, not empty history. These lookup and retention rules are oidfed policies; the draft does not prescribe them.

Published events require a nonempty name; custom names and empty descriptions are supported. This publication check applies to lifecycle imports, memory-store appends, and histories returned by custom adapters. Received event names retain the draft’s open string format.

`information_uri` is descriptive data. [Draft 01 §2.3.2.1](https://openid.net/specs/openid-federation-subordinate-events-1_0-01.html#section-2.3.2.1) recommends HTTPS. The library preserves URL schemes and does not fetch these links. Applications should allow only suitable navigation schemes, such as HTTPS, before rendering a clickable link; a valid signature does not make a URL safe to open.

History contains the authority's recorded observations and may be incomplete. A suspension event does not enforce suspension, and event history alone does not prove past trust-chain validity. The endpoint provides no pagination or notifications.

Lifecycle methods accept optional event annotations: `registerSubordinate(record, annotations)`, `updateSubordinate(subject, updates, annotations)`, and `revokeSubordinate(subject, annotations)`. Use `{ eventDescription, informationUri }` for the optional fields in [Subordinate Events §2.3.2.1](https://openid.net/specs/openid-federation-subordinate-events-1_0-01.html#section-2.3.2.1). Event storage is required when annotations are supplied. Updates apply the annotations to each generated event; a no-op update produces no event. Validation and event writes share the lifecycle operation's failure boundary.

## Entity Collection

To serve the optional Draft 01 endpoint from a Trust Anchor or Intermediate, supply `collection` configuration and publish `federation_collection_endpoint`. Use the `collection` property to refresh snapshots and query the shared core service in process. Snapshots use `storage.collections` or `collection.store`, separately from registration records. See the [Entity Collection guide](../guide/entity-collection.md).

The `collection.collector` and `collection.filter` callbacks configure the shared service's collection policy. Authorities can use application inventories or additional restrictions while keeping registration records separate. See [collection policy](../guide/entity-collection.md#collection-policy). Use `collection.queryMatcher` for synchronous search, and `collection.options.trustMarkVerification` for explicit accreditation policy. These options use the same core implementation as an independent collection provider.

## Subordinate policies and constraints

`registerSubordinate()` and `updateSubordinate()` validate supplied publication claims before writing the resulting record. Invalid critical claims, malformed constraints, and incompatible standard policy operators produce configuration errors. Updates fail before persistence or lifecycle-event creation, including with custom storage adapters. Publication checks remain in place for records loaded from existing stores and for Extended Listing.

`TrustAnchor` and `Intermediate` configurations also accept `additionalClaims` and `crit` for their **own EC**. Construction validates and deeply copies them. Subordinate extensions belong to each registration record instead:

```ts
await authority.registerSubordinate({
  entityId: subordinateId,
  jwks: subordinateKeys,
  additionalClaims: { "https://campus.example/claims/access-profile": "research-v1" },
  crit: ["https://campus.example/claims/access-profile"],
});

await authority.updateSubordinate(subordinateId, {
  additionalClaims: { "https://campus.example/claims/access-profile": "research-v2" },
});
```

An update replaces the supplied `additionalClaims` map; it does not merge individual extension values. The resulting record must still contain every claim named in its `crit`. If you remove an extension, update `crit` in the same call (omit it from new records, or set it to `undefined` in an update when none remain). Empty `crit` arrays are rejected. Custom storage adapters must persist both fields unchanged. Signed Fetch responses and the `subordinate_statement` returned by Extended Listing carry the extensions.

These publication checks protect the statement's shape. They do not decide your extension's meaning. Recipients still need to implement it before declaring it understood, as [Federation §13.4](https://openid.net/specs/openid-federation-1_0.html#section-13.4) requires. See [core's extension API](core.md#publishing-extension-claims).

Policies are validated as declarations; missing subordinate metadata may still be supplied by a Superior. The host may reuse a policy across registrations or provide a different `metadataPolicy` per subordinate. Custom constraints remain in the published statement:

```ts
await authority.registerSubordinate({
  entityId: subordinateId,
  jwks: subordinateKeys,
  constraints: {
    allowed_trust_anchors: ["https://anchor.example"],
  },
});
```

Set `options.customConstraintChecks` on an authority to enforce registered constraints when it validates received chains, including Resolve requests. Publication preserves extension constraints without running chain-dependent checks. See [custom constraints](core.md#custom-constraints) for the receiving application’s checker.

## Protocol metadata validation

Attached OIDC/OAuth and wallet roles validate their composed publication metadata through the existing role hook. Missing top-level fields may be supplied by a Superior; supplied fields must pass the role's publication checks. Without a matching role, the host applies federation checks only.

For independent checks, use the matching role's `parsePublicationMetadata()` before publication and `parseMetadata()` on completed effective metadata. The protocol packages also export named publication types. See the [OIDC/OAuth parser examples](oidc.md#validate-metadata-independently) and [wallet metadata guidance](wallet.md).

## Wallet roles

Attach `WalletProviderRole`, `CredentialIssuerRole`, or `CredentialVerifierRole` from `@oidfed/wallet` through `roles`. Hosts validate the final composed role metadata before publication. Wallet capabilities remain separate from the host's position in the federation. See the [wallet guide](wallet.md) for configuration and protocol integration.

### Additional endpoint authentication methods

Pass `endpointAuthentication: { methods: { [methodName]: implementation }, transportEvidence? }` and advertise the method in the endpoint's `*_auth_methods` metadata. The shared core verifier authenticates credentials before endpoint extensions run. `none` and `private_key_jwt` retain their built-in behavior; unsupported advertised methods fail at construction. See [core authentication](core.md#signing-hosting-and-authenticated-clients) for the callback contract. Collection uses the same verifier through `collection.authentication.extensions`.

Outgoing federation requests use the shared `options.getEndpointAuthentication` callback when credentials differ by responder. This applies to Resolve discovery and Collection refresh as well as Trust Mark operations. It is separate from the server's `endpointAuthentication` configuration, which authenticates incoming callers. See [credentials for each authority](../guide/entity-collection.md#credentials-for-each-authority).

## Resolve results and their lifetime

Resolve tries discovered candidate chains until one validates. A bad path does not hide a valid path to another requested anchor. Discovery and validation attempts share the request's fetch budget and cancellation signal.

A missing subject or absent chain returns `404 not_found`. When discovery has no outstanding operational failures, discovered chains that all fail validation return `400 invalid_trust_chain`; metadata-only failures return `400 invalid_metadata`. When no valid candidate is available, incomplete discovery caused by temporary upstream failures or exhausted limits returns `503 temporarily_unavailable`. Unexpected internal failures return `500 server_error`. Responses contain generic descriptions rather than validation details or signed evidence.

The response's `exp` is the minimum expiration of the selected chain and the included Trust Marks, as [§8.3.2](https://openid.net/specs/openid-federation-1_0.html#section-8.3.2) specifies. Auxiliary intermediate Entity Configurations, delegations, and other issuer evidence must still be valid when the response is produced. These auxiliary documents do not shorten the expiration calculated from statements in the returned chain. Their earlier deadlines limit cache reuse independently of the wire `exp`: an anonymous request can therefore encounter a cache miss before a previously issued response expires. Fresh resolution reassesses the evidence and omits marks that can no longer be verified as active.

Fixed routing selectors use the endpoint's parameter rules. Known membership filters accept reordered or repeated identical values; scalar selectors and unknown extensions keep exact comparison. Authority construction rejects overlapping routes under those same rules, including routes whose parameter rules differ.

### Choosing paths and using a resolver

Set `options.chainSelection` on either authority class to choose among eligible chains. `shortestChain`, `longestExpiry`, and `preferTrustAnchor` are available from core. Without this option, each operation retains its existing selection rule. `resolveEntity(subject, anchor, options)` accepts per-call overrides; assessments produced with overrides use an isolated cache namespace.

Both classes also expose `discoverEntity`, `discoverEntityFromChain`, and `assessEntity` as instance and static methods. Instance methods inherit the host's anchors and options; per-call values take precedence. A configured resolver changes where chains are acquired. These discovery methods still validate the subject's chain locally. Only `assessEntity` with explicit `mode: "resolver"` delegates that assessment.

For a service that only resolves trust, use core's `FederationResolverService`, or attach it to a Leaf. Such a service does not need subordinate storage. Actual Authority hosts continue requiring Fetch and Listing endpoints. See [core assessment and resolver hosting](core.md#trust-establishment-options).
