# `@oidfed/authority`

<p align="center">
  <a href="https://www.npmjs.com/package/@oidfed/authority"><img alt="npm" src="https://img.shields.io/npm/v/@oidfed/authority.svg" /></a>
  <a href="https://www.npmjs.com/package/@oidfed/authority"><img alt="downloads" src="https://img.shields.io/npm/dm/@oidfed/authority.svg" /></a>
  <a href="https://github.com/Dahkenangnon/oidfed/blob/main/packages/authority/LICENSE"><img alt="license" src="https://img.shields.io/npm/l/@oidfed/authority.svg" /></a>
  <a href="https://packagephobia.com/result?p=@oidfed/authority"><img alt="install size" src="https://packagephobia.com/badge?p=@oidfed/authority" /></a>
</p>

`@oidfed/authority` runs Trust Anchors and Intermediate Authorities. It issues Subordinate Statements and serves federation fetch, list, extended-list, subordinate-events, resolve, historical-key, and trust-mark endpoints through Web API handlers. Storage and federation signing keys come from injected providers.

See [operator and application responsibilities](../guide/operator-responsibilities.md) for authentication policy, key rollover, and the storage and capture contracts of optional endpoints.

## Usage

Later fragments reuse `ta`, `storage`, and `keyProvider` from the first example. Supply the subordinate's public federation key as `subordinatePublicKey` when enrolling it.

### Creating a Trust Anchor or Intermediate

This development example creates two authorities. Enrollment and HTTP serving are separate steps; see the [wiring guide](../guide/wiring-guide.md).
A Trust Anchor has no superior authorities. An Intermediate lists at least one superior in `authorityHints`. Both must advertise federation fetch and list endpoints.

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

Use `ta.registerSubordinate(record)` or `intermediate.registerSubordinate(record)` to sanitize metadata and add timestamps. Direct adapter writes are also supported, as shown below. In that case, remove operational fields from `metadata.federation_entity` before writing the record; these fields belong in the subordinate's own Entity Configuration.

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

The propagation interval before switching and the retirement interval after switching serve different stages. The application chooses when to switch; `retirePreviousAfterMs` controls only the post-switch overlap. Seven days is the memory provider's default, not a duration prescribed by the specification. Choose both intervals and Entity Configuration expiry according to the federation's security profile. A Leaf using the same provider must refresh its cached configuration after key-set changes; see [Leaf configuration caching](leaf.md#how-does-the-entity-configuration-caching-work).

Production key providers must preserve lifecycle state across restarts and coordinate serving processes. The in-memory provider does not persist or distribute changes.

`revokeKey(kid, reason)` applies the provider's local revocation policy. It excludes the key from current publication and signer selection and retains historical revocation information under [§8.7.2](https://openid.net/specs/openid-federation-1_0.html#section-8.7.2). It does not invalidate statements already held by other participants. [§11.4](https://openid.net/specs/openid-federation-1_0.html#section-11.4) leaves the federation-wide revocation process to the trust framework.

### Issuing and revoking Trust Marks

Authorities with `storage.trustMarks` can issue and track Trust Marks. Trust Anchors declare authorized issuers and owners for the trust-mark types recognized by their federation.

```ts
import { entityId } from "@oidfed/core";

// 1. Issue a trust mark
const trustMarkJwt = await ta.issueTrustMark(
  "https://leaf.example.com",
  "https://profile.example.org/bronze"
);

// 2. Revoke an issued trust mark via the storage adapter reference
await storage.trustMarks?.revoke(
  "https://profile.example.org/bronze",
  entityId("https://leaf.example.com"),
  Math.floor(Date.now() / 1000)
);
```

### HTTP routing

`TrustAnchor.handleRequest()` and `Intermediate.handleRequest()` accept a Web API `Request` and return a `Promise<Response>`. They dispatch composed role routes, including OIDC explicit registration, before federation routes.

Use the [Express adapter in the wiring guide](../guide/wiring-guide.md#5-adapt-the-web-api-handler-to-express). It preserves request bytes and response content types and handles POST bodies without passing a Node stream directly to `Request`.

## Configuration

When constructing a `TrustAnchor` or `Intermediate`, you pass an `AuthorityConfig` configuration object.

| Configuration Field | Type | Required | Description & Constraints |
|:---|:---|:---|:---|
| `entityId` | `EntityId \| string` | **Yes** | The entity identifier URL for this authority. Must be a valid HTTPS URL without query parameters or fragments. |
| `metadata` | `AuthorityConfig["metadata"]` | **Yes** | Structured object-valued metadata blocks published in the authority's self-signed configuration. Must include `federation_entity`; no leaf value within the metadata may be `null`. |
| `storage` | `StorageAdapter` | **Yes** | Persistence adapter for subordinates, trust marks, cache, and replays. |
| `keyProvider` | `FederationKeyLifecycleProvider`| **Yes** | Key provider exposing active federation signing keys, rollover lifecycle, and historical keys (e.g., `MemoryFederationKeyProvider` implements `FederationKeyLifecycleProvider`). |
| `clientKeyProvider` | `AuthorityClientKeyProvider` | No | Resolves public Federation Entity Keys for `private_key_jwt` federation endpoint callers. Defaults to `storage.subordinates.get(entityId)?.jwks`. |
| `authorityHints` | `readonly (EntityId \| string)[]` | *Conditional* | List of superior authorities this entity is subordinate to. Must be `undefined` or omitted for a `TrustAnchor`. Must be a non-empty array for an `Intermediate`. |
| `trustAnchorHints` | `readonly (EntityId \| string)[]` | No | Optional non-empty list of preferred trust anchors to publish as `trust_anchor_hints` for an `Intermediate`. Rejected on `TrustAnchor` configurations. |
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

Authorities normalize only their own configured `entityId` by removing a trailing `/`. The Entity Configuration HTTP route is then derived from that normalized Entity Identifier path: `https://ta.example.org/tenant` serves `https://ta.example.org/tenant/.well-known/openid-federation`, while `https://ta.example.org` serves `https://ta.example.org/.well-known/openid-federation`.

Federation endpoint HTTP routes are derived from the paths advertised in `metadata.federation_entity`, not from fixed defaults. For example, advertising `federation_fetch_endpoint: "https://ta.example.org/custom/fetch"` mounts fetch handling at `/custom/fetch`. Optional endpoints are mounted only when their corresponding endpoint URL is advertised. Endpoint URLs must use HTTPS, must not contain fragments, and their route paths must be distinct.

### Extended subordinate listing

The endpoint implements Draft 03. Advertise `federation_extended_list_endpoint` in `metadata.federation_entity` to mount it, and leave `extendedListing.enabled` enabled. Enabling the handler alone does not add the metadata or route.

Read `next` from each response and pass it unchanged as `from` to resume from that entry, inclusive. Treat it as an opaque string; its encoding is chosen by the server. Unknown cursors return HTTP 404 with the JSON error `page_not_found`.

```typescript
const first = await ta.listSubordinatesExtended({ limit: 50, claims: [] });
if (first.ok && first.value.next !== undefined) {
  const second = await ta.listSubordinatesExtended({ from: first.value.next, limit: 50, claims: [] });
}
```

The same parameters are supported by `fetchExtendedSubordinatesList` in `@oidfed/core`. `trustMarkType` accepts a string or an array of strings. An entity matches if the authority has issued a still-valid mark of any requested type. On the wire, send one `trust_mark_type` parameter per type. Custom storage adapters must handle the array form of `ListFilter.trustMarkType` with the same OR semantics before paginating results.

Both listing endpoints treat `trust_marked=true` as requiring a valid issued mark. They treat `false` as adding no mark restriction; any supplied `trust_mark_type` filter still applies. The base specification defines the true case and leaves the false case unspecified. Custom storage adapters should follow the same policy for `ListFilter.trustMarked`.

Extended Listing time filters and audit timestamps use NumericDate seconds. Fractional and negative values are accepted, and `updated_after` and `updated_before` include records exactly at the boundary. Query values also accept decimal exponent notation. Values must be finite numbers.

Omitting `claims` uses `defaultClaims`. An explicit `claims: []` sends `claims=` and suppresses the default statements. If a claim selection is present, `subordinate_statement` is returned only when requested; other requested statement claims are included when available.

Leaf entities cannot advertise this endpoint.

The `extendedListing` object supports:

- `enabled` (`boolean`): Whether the advertised endpoint accepts requests. Defaults to `true`.
- `maxPageSize` (`number`): Upper limit on page sizes. Defaults to `500`.
- `defaultPageSize` (`number`): Default page size if client omits the `limit` query. Defaults to `100`.
- `supportTimeFilters` (`boolean`): Whether to honor `updated_after` and `updated_before` queries. Defaults to `true`.
- `supportAuditTimestamps` (`boolean`): Whether to honor `audit_timestamps` query. Defaults to `true`.
- `defaultClaims` (`ReadonlyArray<string>`): Claims fetched when the client sends no `claims` query. Defaults to `["subordinate_statement"]`.
- `maxStorePagesPerRequest` (`number`): Maximum index page lookups allowed per request to protect performance. Defaults to `16`.
- `storeBatchSize` (`number`): Page batch sizes retrieved during filtering. Defaults to `defaultPageSize`.

## Common questions

### What is the difference between `TrustAnchor` and `Intermediate`?

A `TrustAnchor` represents a root of trust and cannot specify `authorityHints`. An `Intermediate` is a subordinate authority that must list at least one superior authority in `authorityHints`. Intermediates also cannot carry `trustMarkIssuers` or `trustMarkOwners` metadata block configurations since those claims are reserved for Trust Anchors.

### How do I enroll a subordinate entity?

Use `await ta.registerSubordinate(record)` to sanitize metadata and add timestamps. Use `await storage.subordinates.add(record)` when managing those fields yourself.

### Why does subordinate storage reject my metadata?

A subordinate's metadata block in the storage record must not carry operational fields (such as `federation_fetch_endpoint` or `federation_list_endpoint`) inside `metadata.federation_entity`. Use `TrustAnchor.sanitizeSubordinateMetadata(metadata)` or `Intermediate.sanitizeSubordinateMetadata(metadata)` to strip these fields before calling `.add()` or `.update()`.

### Is explicit client registration handled automatically?

Compose an `OidcProviderRole` from `@oidfed/oidc` into the entity's `roles`. The parent initializes its registration handler and dispatches matching requests through `handleRequest()`. Connect registration hooks to your OP's client store. Automatic registration still needs a call from the OP's authorization or PAR flow.

## Subordinate event history

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

Direct `storage.subordinates` writes remain supported and do not automatically record events. Enabling event storage does not reconstruct past history from record timestamps. See the [storage contract](../guide/storage-guide.md#subordinate-events) for explicit transactional appends.

The endpoint accepts GET with a required `sub` Entity Identifier. If authentication is configured through `federation_subordinate_events_endpoint_auth_methods`, it uses the existing federation client-authentication middleware and authenticated form POST. A `private_key_jwt` assertion names the authority's Entity Identifier as its audience, which can differ from the endpoint URL. The authenticated client and requested subject need not be identical.

Unsupported methods receive HTTP 405 with `Allow` and a Federation JSON error containing `error: "invalid_request"` and `error_description`. This applies to both the anonymous handler and authenticated route. The advertised URL must have no fragment, including an empty trailing `#`.

Successful responses are compact JWTs with media type `application/entity-events-statement+jwt` and JWT type `entity-events-statement+jwt`, signed with the authority's Federation Entity Key. They contain `iss`, `sub`, a fresh response `iat`, and `federation_registration_events`. The authority omits the optional `exp`; event occurrence times remain unchanged when a new response is issued.

A current subordinate with no recorded events receives a signed empty history. Retained history remains available after removal and re-registration. A subject with neither a current record nor history receives HTTP 404 JSON `not_found`. Storage failures produce a server error, not empty history. These lookup and retention rules are oidfed policies; the draft does not prescribe them.

History contains the authority's recorded observations and may be incomplete. A suspension event does not enforce suspension, and event history alone does not prove past trust-chain validity. The endpoint provides no pagination or notifications.

## Entity Collection

To serve the optional Draft 01 endpoint from a Trust Anchor or Intermediate, supply `collection` configuration and publish `federation_collection_endpoint`. Use the `collection` property to refresh snapshots and query the shared core service in process. Snapshots use `storage.collections` or `collection.store`, separately from registration records. See the [Entity Collection guide](../guide/entity-collection.md).

The `collection.collector` and `collection.filter` callbacks configure the shared service's collection policy. Authorities can use application inventories or additional restrictions while keeping registration records separate. See [collection policy](../guide/entity-collection.md#collection-policy).

## Wallet roles

Attach `WalletProviderRole`, `CredentialIssuerRole`, or `CredentialVerifierRole` from `@oidfed/wallet` through `roles`. Hosts validate the final composed role metadata before publication. Wallet capabilities remain separate from the host's position in the federation. See the [wallet guide](wallet.md) for configuration and protocol integration.
