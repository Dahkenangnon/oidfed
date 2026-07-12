# `@oidfed/leaf`

Leaf Entity toolkit — Entity Configuration serving, authority discovery, and trust chain participation for any entity at the edge of an OpenID Federation.

## Overview

The `@oidfed/leaf` package provides components to configure and run entities at the bottom (edge) of a trust chain, typically Relying Parties (RPs) or OpenID Providers (OPs) that do not issue subordinate statements themselves. It manages self-signed Entity Configuration generation, signature creation, caching, and provides authority discovery features to validate trust chains up to configured Trust Anchors.

---

## Capabilities & Usage Guide

### Creating a Leaf Entity
A Leaf entity publishes its own self-signed configuration but relies on superior authorities (authority hints) to attest to its status. It must not publish authority endpoints like list or fetch endpoints.

```ts
import { Leaf } from "@oidfed/leaf";
import { FedOidcClient, StaticOidcProtocolKeyProvider } from "@oidfed/oidc";
import { federationKey, generateSigningKey, JwkSigner, MemoryFederationKeyProvider } from "@oidfed/core";

// 1. Generate keys and key providers
const keyPair = await generateSigningKey("ES256");
const keyProvider = new MemoryFederationKeyProvider(federationKey(keyPair.privateKey));

// 2. Generate OIDC protocol keys and initialize the protocol key provider
const protocolKeyPair = await generateSigningKey("ES256");
const protocolKeyProvider = new StaticOidcProtocolKeyProvider({
  requestObjectSigner: new JwkSigner(protocolKeyPair.privateKey)
});

// 3. Initialize the Leaf Entity
const leaf = new Leaf({
  entityId: "https://rp.example.com",
  authorityHints: ["https://federation.example.org"],
  keyProvider,
  metadata: {
    federation_entity: {
      organization_name: "My Relying Party",
    },
  },
  roles: [
    new FedOidcClient({
      protocolKeyProvider,
      metadata: {
        redirect_uris: ["https://rp.example.com/callback"],
        response_types: ["code"],
        client_registration_types: ["automatic"],
        jwks: { keys: [protocolKeyPair.publicKey] },
      }
    })
  ]
});
```

---

### Serving the Entity Configuration
The `Leaf` class manages internal caching of the signed configuration token. It routes standard federation path requests and delegate role requests to appropriate handlers.

```ts
import express from "express";

const app = express();

app.use(async (req, res) => {
  // Translate Node request to standard Web Request
  const webRequest = new Request(`https://${req.headers.host}${req.url}`, {
    method: req.method,
    headers: req.headers as any,
    body: req.method !== "GET" && req.method !== "HEAD" ? req : undefined
  });

  const webResponse = await leaf.handleRequest(webRequest);

  res.status(webResponse.status);
  webResponse.headers.forEach((value, key) => res.setHeader(key, value));
  res.send(await webResponse.text());
});
```

---

### Discovering Entities and Trust Chains
Leaf entities can discover other entities in the federation and validate their trust chains up to configured anchors using the static `Leaf.discoverEntity` method.

```ts
import { Leaf } from "@oidfed/leaf";
import { createTrustAnchorSet, entityId, isOk } from "@oidfed/core";

const trustAnchors = createTrustAnchorSet([
  {
    entityId: entityId("https://ta.example.org"),
    jwks: { keys: [taPublicKey] }
  }
]);

const result = await Leaf.discoverEntity(
  entityId("https://op.example.com"),
  trustAnchors,
  { httpClient: fetch }
);

if (isOk(result)) {
  const discovery = result.value;
  console.log("Metadata:", discovery.resolvedMetadata);
  console.log("Trust Chain Expires At:", new Date(discovery.trustChain.expiresAt * 1000));
} else {
  console.error("Discovery failed:", result.error.description);
}
```

---

## Configuration API Reference

When constructing a `Leaf` entity, you pass a `LeafConfig` configuration object.

| Configuration Field | Type | Required | Description & Constraints |
|:---|:---|:---|:---|
| `entityId` | `EntityId \| string` | **Yes** | The entity identifier URL for this leaf. Must be a valid HTTPS URL without query parameters or fragments. Normalizes trailing slashes. |
| `authorityHints` | `readonly (EntityId \| string)[]` | **Yes** | Non-empty list of superior authority entity IDs this leaf is registered with. Every entry must be a valid HTTPS URL. |
| `metadata` | `Record<string, any>` | **Yes** | The metadata block to publish. Must contain at least one Entity Type Identifier. The `federation_entity` block **must not** contain operational authority fields like `federation_fetch_endpoint` or `federation_list_endpoint`. |
| `keyProvider` | `FederationKeyProvider` | **Yes** | Key provider managing active federation signing keys. |
| `roles` | `EntityRole[]` | No | Composition roles (like OIDC Client/Provider roles) bound to this entity context. |
| `options` | `FederationOptions` | No | Core federation options (e.g. clock configurations). |
| `trustMarks` | `TrustMarkRef[]` | No | Trust marks this leaf claims about itself in its Entity Configuration. |
| `entityConfigurationTtlSeconds`| `number` | No | TTL in seconds for the self-signed Entity Configuration JWT. Must be positive if defined. Defaults to 86400 (24 hours). |

---

## Frequently Asked Questions (FAQ)

### Q: Why does the Leaf constructor throw when my metadata block contains endpoints?
**A:** Leaf entities are client or provider endpoints at the edge of the trust tree and do not issue subordinate statements or list subordinates. Therefore, they are forbidden from publishing `federation_fetch_endpoint` or `federation_list_endpoint` in their `federation_entity` metadata block.

### Q: How does the Entity Configuration caching work?
**A:** The Leaf class signs and caches the Entity Configuration JWT internally. When `getEntityConfiguration()` is called, it returns the cached JWT if it has not expired yet. If it has expired or if `refreshEntityConfiguration()` is called, it re-queries the `keyProvider` for keys and generates a new signature.

### Q: What is `DiscoveryResult` and how is it used?
**A:** `DiscoveryResult` is a branded type returned by `Leaf.discoverEntity` containing the validated trust chain metadata and marks. RP registration flows in `@oidfed/oidc` require this branded type to guarantee that only fully resolved and validated metadata is used for automatic or explicit client registrations.
