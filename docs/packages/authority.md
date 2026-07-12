# `@oidfed/authority`

Trust Anchor and Intermediate Authority operations — subordinate management, statement issuance, federation endpoint serving, and policy enforcement for the complete OpenID Federation 1.0/1.1 implementation.

## Overview

The `@oidfed/authority` package enables the construction of Trust Anchors (root authorities) and Intermediates (intermediate authorities). It routes all spec-defined federation endpoints (fetch, list, resolve, historical keys, and trust mark status/list) as a single, fetch-compatible engine. Key management and persistence layers are decoupled through pluggable provider interfaces.

---

## Capabilities & Usage Guide

### Creating a Trust Anchor or Intermediate
A **Trust Anchor** is a root authority with no superiors, which serves as the trust source for the federation. An **Intermediate** represents a delegated authority that must specify one or more superior parent entity IDs.

```ts
import { TrustAnchor, Intermediate, MemoryStorageAdapter } from "@oidfed/authority";
import { federationKey, generateSigningKey, MemoryFederationKeyProvider } from "@oidfed/core";

// 1. Generate keys and key provider
const keyPair = await generateSigningKey("ES256");
const keyProvider = new MemoryFederationKeyProvider(federationKey(keyPair.privateKey));

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

// 3. Initialize an Intermediate (requires authorityHints)
const intermediate = new Intermediate({
  entityId: "https://intermediate.example.org",
  keyProvider,
  storage,
  authorityHints: ["https://ta.example.org"],
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: "https://intermediate.example.org/federation_fetch",
      federation_list_endpoint: "https://intermediate.example.org/federation_list"
    }
  }
});
```

---

### Enrolling and Managing Subordinates
Authorities attest to subordinate entities by issuing Subordinate Statements. Because subordinates own their own operational endpoints, their `metadata.federation_entity` must be sanitized to strip operational endpoints (e.g. `federation_fetch_endpoint`) before enrollment.

```ts
import { TrustAnchor } from "@oidfed/authority";
import { entityId } from "@oidfed/core";

const subordinateId = entityId("https://leaf.example.com");

// Sanitize metadata to strip operational fields
const rawMetadata = {
  federation_entity: {
    name: "Example Leaf Entity",
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
  metadata: sanitized,
  createdAt: Math.floor(Date.now() / 1000),
  updatedAt: Math.floor(Date.now() / 1000)
});
```

---

### Plugging a Custom Storage Adapter
Persistence is decoupled via the `StorageAdapter` interface. You can inject custom databases by implementing this contract.

```ts
import type { StorageAdapter, SubordinateStorage, StorageTransaction } from "@oidfed/authority";

class CustomStorageAdapter implements StorageAdapter {
  readonly subordinates: SubordinateStorage;

  constructor() {
    this.subordinates = {
      async get(entityId) { /* Retrieve from DB */ return undefined; },
      async list(filter, options) { /* Return paginated items */ return { items: [] }; },
      async add(record) { /* Insert into DB */ },
      async update(entityId, updates) { /* Update record in DB */ },
      async remove(entityId) { /* Delete from DB */ }
    };
  }

  async transaction<T>(operation: (tx: StorageTransaction) => Promise<T>): Promise<T> {
    const tx: StorageTransaction = { subordinates: this.subordinates };
    return operation(tx);
  }
}
```

---

### Federation Key Rotation
Federation signing keys are managed by the `ManagedFederationKeyProvider`. The authority supports dynamic signing key rotations and records the history for the historical keys endpoint.

```ts
import { federationKey, generateSigningKey } from "@oidfed/core";

// Generate new rotation key
const nextKeyPair = await generateSigningKey("ES256");
const newSigningKey = federationKey(nextKeyPair.privateKey);

// Rotate active key through the authority instance.
await ta.rotateSigningKey(newSigningKey);
```

---

### Issuing and Revoking Trust Marks
Trust Anchors can issue and track Trust Marks to indicate subordinate compliance with federation profiles.

```ts
// 1. Issue a trust mark
const trustMarkJwt = await ta.issueTrustMark(
  "https://leaf.example.com",
  "https://profile.example.org/bronze"
);

// 2. Revoke an issued trust mark via the storage adapter reference
await storage.trustMarks?.revoke(
  "https://profile.example.org/bronze",
  "https://leaf.example.com",
  Math.floor(Date.now() / 1000)
);
```

---

### HTTP Routing and Request Handling
Both `TrustAnchor` and `Intermediate` provide a `handleRequest` method that parses standard Web API `Request` objects and returns `Response` objects.

```ts
import express from "express";

const app = express();

app.use(async (req, res) => {
  // Translate Express request to Web standard Request
  const webRequest = new Request(`https://${req.headers.host}${req.url}`, {
    method: req.method,
    headers: req.headers as any,
    body: req.method !== "GET" && req.method !== "HEAD" ? req : undefined
  });

  const webResponse = await ta.handleRequest(webRequest);

  res.status(webResponse.status);
  webResponse.headers.forEach((value, key) => res.setHeader(key, value));
  res.send(await webResponse.text());
});
```

---

## Configuration API Reference

When constructing a `TrustAnchor` or `Intermediate`, you pass an `AuthorityConfig` configuration object.

| Configuration Field | Type | Required | Description & Constraints |
|:---|:---|:---|:---|
| `entityId` | `EntityId \| string` | **Yes** | The entity identifier URL for this authority. Must be a valid HTTPS URL without query parameters or fragments. |
| `metadata` | `object` | **Yes** | Metadata block published in the authority's self-signed configuration. Must include a `federation_entity` sub-object. No leaf value within the metadata may be `null`. |
| `storage` | `StorageAdapter` | **Yes** | Persistence adapter for subordinates, trust marks, cache, and replays. |
| `keyProvider` | `ManagedFederationKeyProvider`| **Yes** | Key provider managing active federation signing keys and key history (e.g., `MemoryFederationKeyProvider` implements `ManagedFederationKeyProvider`). |
| `clientKeyProvider` | `AuthorityClientKeyProvider` | No | Resolves public Federation Entity Keys for `private_key_jwt` federation endpoint callers. Defaults to `storage.subordinates.get(entityId)?.jwks`. |
| `authorityHints` | `readonly (EntityId \| string)[]` | *Conditional* | List of superior authorities this entity is subordinate to. Must be `undefined` or omitted for a `TrustAnchor`. Must be a non-empty array for an `Intermediate`. |
| `roles` | `EntityRole[]` | No | Optional composition roles (like OIDC Provider or Relying Party roles) bound to this entity context. |
| `trustMarks` | `TrustMarkRef[]` | No | Trust marks this authority claims about itself in its Entity Configuration. |
| `trustMarkIssuers` | `Record<string, string[]>` | No | Mapping of trust mark type URLs to authorized issuer entity IDs. Rejected on Intermediates (this implementation throws an error to enforce strict configuration separation, which is stricter than the spec's "MUST be ignored" rule). |
| `trustMarkOwners` | `Record<string, TrustMarkOwner>`| No | Mapping of trust mark type URLs to owner declarations. Rejected on Intermediates (this implementation throws an error to enforce strict configuration separation, which is stricter than the spec's "MUST be ignored" rule). |
| `trustMarkDelegations` | `Record<string, string>` | No | Pre-signed trust mark delegation JWTs, keyed by trust mark type. |
| `trustAnchors` | `TrustAnchorSet` | No | Configured trust anchors used for validating chains (e.g. during RP registration). |
| `entityConfigurationTtlSeconds`| `number` | No | TTL in seconds for the Entity Configuration JWT. Must be positive if defined. |
| `subordinateStatementTtlSeconds`| `number` | No | TTL in seconds for subordinate statement JWTs. Must be positive if defined. |
| `trustMarkTtlSeconds` | `number` | No | TTL in seconds for issued trust marks. Must be positive if defined. |
| `options` | `Omit<FederationOptions, "cache">`| No | Core federation options (e.g. custom clock skew, http timeouts, etc.). |
| `extendedListing` | `ExtendedListingConfig` | No | Configuration for `/federation_extended_list`. Can set `enabled: false` to disable. |

Federation endpoint `private_key_jwt` authentication verifies the remote caller's assertion with keys returned by `clientKeyProvider`. If omitted, the authority uses the caller Entity Identifier to read the subordinate record from `storage.subordinates` and uses that record's `jwks`. Configure a custom provider when caller keys live in an external registry or key service; invalid, missing, or mismatched keys fail closed.

### Extended Listing Config Options
The `extendedListing` configuration object supports the following fields:
- `enabled` (`boolean`): Whether the `/federation_extended_list` endpoint is active. Defaults to `true`.
- `maxPageSize` (`number`): Upper limit on page sizes. Defaults to `500`.
- `defaultPageSize` (`number`): Default page size if client omits the `limit` query. Defaults to `100`.
- `supportTimeFilters` (`boolean`): Whether to honor `updated_after` and `updated_before` queries. Defaults to `true`.
- `supportAuditTimestamps` (`boolean`): Whether to honor `audit_timestamps` query. Defaults to `true`.
- `defaultClaims` (`ReadonlyArray<string>`): Claims fetched when the client sends no `claims` query. Defaults to `["subordinate_statement"]`.
- `maxStorePagesPerRequest` (`number`): Maximum index page lookups allowed per request to protect performance. Defaults to `16`.
- `storeBatchSize` (`number`): Page batch sizes retrieved during filtering. Defaults to `defaultPageSize`.

---

## Frequently Asked Questions (FAQ)

### Q: What is the difference between `TrustAnchor` and `Intermediate`?
**A:** A `TrustAnchor` represents a root of trust and cannot specify `authorityHints`. An `Intermediate` is a subordinate authority that must list at least one superior authority in `authorityHints`. Intermediates also cannot carry `trustMarkIssuers` or `trustMarkOwners` metadata block configurations since those claims are reserved for Trust Anchors.

### Q: How do I enroll a subordinate entity?
**A:** Subordinates are added directly to the subordinates store using the storage adapter: `await storage.subordinates.add(record)`.

### Q: Why does `validateSubordinateRecord` reject my metadata?
**A:** A subordinate's metadata block in the storage record must not carry operational fields (such as `federation_fetch_endpoint` or `federation_list_endpoint`) inside `metadata.federation_entity`. Use `TrustAnchor.sanitizeSubordinateMetadata(metadata)` or `Intermediate.sanitizeSubordinateMetadata(metadata)` to strip these fields before calling `.add()` or `.update()`.

### Q: Is explicit client registration handled automatically?
**A:** No. `handleRequest()` handles only core federation endpoints (fetch, list, resolve, historical keys, trust mark status, etc.). To handle OIDC explicit client registration, you must mount OIDC role adapters (e.g. from `@oidfed/oidc`) to bind `roles` on the entity context.
