# @oidfed/leaf

Leaf Entity toolkit — Entity Configuration serving, authority discovery, and trust chain participation for any entity at the edge of an OpenID Federation.

## Role

Use for any entity at the bottom of a trust chain (typically an **RP** or **OP**) that does not issue Subordinate Statements. Combine with `@oidfed/oidc` for OIDC registration flows.

## Install

```bash
pnpm add @oidfed/core @oidfed/leaf
```

## Quick Start

```ts
import { createLeafEntity } from "@oidfed/leaf";
import { entityId } from "@oidfed/core";
import express from "express";

const leaf = createLeafEntity({
  entityId: entityId("https://rp.example.com"),
  authorityHints: [entityId("https://federation.example.org")],
  signingKeys: [mySigningKey],
  metadata: {
    openid_relying_party: {
      redirect_uris: ["https://rp.example.com/callback"],
      response_types: ["code"],
      client_registration_types: ["automatic"],
    },
  },
});

const handler = leaf.handler(); // fetch-compatible

const app = express();
app.use(async (req, res) => {
  const response = await handler(req as unknown as Request);
  res.status(response.status);
  response.headers.forEach((v, k) => res.setHeader(k, v));
  res.send(await response.text());
});
```

## API

### Entity & Handler

```ts
import { createLeafEntity, createLeafHandler } from "@oidfed/leaf";
import type { LeafConfig, LeafEntity } from "@oidfed/leaf";
```

`createLeafEntity(config)` throws synchronously if `authorityHints` or `signingKeys` is empty, any key lacks `kid`, or `kid` values are duplicated. Private key material is stripped from the Entity Configuration JWKS automatically.

```ts
interface LeafConfig {
  entityId: EntityId;
  signingKeys: JWK[];
  authorityHints: EntityId[];         // must not be empty
  metadata: FederationMetadata;
  trustMarks?: TrustMarkRef[];
  entityConfigurationTtlSeconds?: number; // default: 86400
}

interface LeafEntity {
  getEntityConfiguration(): Promise<string>;
  isEntityConfigurationExpired(): boolean;
  refreshEntityConfiguration(): Promise<string>;
  discoverEntity(
    entityId: EntityId,
    trustAnchors: TrustAnchorSet,
    options?: FederationOptions,
  ): Promise<DiscoveryResult>;
  handler(): (request: Request) => Promise<Response>;
}
```

`createLeafHandler(entity)` — standalone handler for `/.well-known/openid-federation`. Responds 405 for non-GET, 404 for unknown paths. Sets `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, and HSTS headers.

### Discovery

```ts
import { discoverEntity } from "@oidfed/leaf";
import type { DiscoveryResult } from "@oidfed/leaf";
```

```ts
const discovery = await discoverEntity(
  entityId("https://op.example.com"),
  trustAnchors,
  { httpClient: fetch },
);

// Branded DiscoveryResult — required by @oidfed/oidc registration functions.
// Only discoverEntity can produce it; prevents unvalidated data from reaching registration.
console.log(discovery.entityId);
console.log(discovery.resolvedMetadata);
console.log(discovery.trustChain);
console.log(discovery.trustMarks);
```
