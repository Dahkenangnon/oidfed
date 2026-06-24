# @oidfed/leaf

Leaf Entity toolkit — Entity Configuration serving, authority discovery, and trust chain participation for any entity at the edge of an OpenID Federation.

## Role

Use for any entity at the bottom of a trust chain, typically an RP or OP that does not issue subordinate statements. Combine with `@oidfed/oidc` for OIDC registration flows.

## Install

```bash
pnpm add @oidfed/core @oidfed/leaf
```

## Quick Start

```ts
import { Leaf } from "@oidfed/leaf";
import { FedOidcClient } from "@oidfed/oidc";
import { MemoryFederationKeyProvider, federationKey } from "@oidfed/core";
import express from "express";

const leaf = new Leaf({
  entityId: "https://rp.example.com",
  authorityHints: ["https://federation.example.org"],
  keyProvider: new MemoryFederationKeyProvider(federationKey(myFederationSigningKey)),
  metadata: {
    federation_entity: {
      organization_name: "My Relying Party",
    },
  },
  roles: [
    new FedOidcClient({
      redirect_uris: ["https://rp.example.com/callback"],
      response_types: ["code"],
      client_registration_types: ["automatic"],
      jwks: { keys: [protocolPublicKey] },
      protocolKeyProvider,
    })
  ]
});

const app = express();
app.use(async (req, res) => {
  // Convert Node HTTP req to Web Request, then handle
  const request = new Request(`https://${req.headers.host}${req.url}`, {
    method: req.method,
    headers: req.headers as any,
    body: req.method !== "GET" && req.method !== "HEAD" ? req : undefined,
  });

  const response = await leaf.handleRequest(request);
  res.status(response.status);
  response.headers.forEach((value, key) => res.setHeader(key, value));
  res.send(await response.text());
});
```

## API

### Leaf Class

```ts
import { Leaf } from "@oidfed/leaf";
import type { LeafConfig } from "@oidfed/leaf";
import type { FederationKeyProvider, EntityId } from "@oidfed/core";
```

`new Leaf(config)` throws synchronously if `authorityHints` is empty, any authority hint is not a valid Entity Identifier, or `keyProvider` is missing. It performs strict validation on initialization.

```ts
export class Leaf {
  constructor(config: LeafConfig);
  entityId: EntityId;
  getEntityConfiguration(): Promise<string>;
  isEntityConfigurationExpired(): boolean;
  refreshEntityConfiguration(): Promise<string>;
  handleRequest(request: Request): Promise<Response>;
}

interface LeafConfig {
  entityId: EntityId | string;
  authorityHints: readonly (EntityId | string)[];
  metadata: Record<string, any>;
  keyProvider: FederationKeyProvider;
  roles?: EntityRole[];
  options?: FederationOptions;
  trustMarks?: TrustMarkRef[];
  entityConfigurationTtlSeconds?: number;
}
```

The published top-level Entity Statement `jwks` comes from `keyProvider.getFederationKeySet()`. The provider, not the leaf config, is the source of truth for federation public keys.

Configure time through `options.clock`. Like every core `Clock`, it returns Unix NumericDate seconds and controls Entity Configuration generation and expiry.

`leaf.handleRequest(request: Request): Promise<Response>` matches incoming requests to:
- `/.well-known/openid-federation`: responds with the signed Entity Configuration JWT.
- Routes dynamically registered by composition roles (e.g. OIDC Client/Provider routes).
- Returns `404` for unmatched paths.

### Discovery

```ts
import { discoverEntity } from "@oidfed/leaf";
import { isOk } from "@oidfed/core";
```

```ts
const result = await discoverEntity(
  "https://op.example.com",
  trustAnchors,
  { httpClient: fetch },
);

if (isOk(result)) {
  const discovery = result.value;
  console.log(discovery.entityId);
  console.log(discovery.resolvedMetadata);
  console.log(discovery.trustChain);
  console.log(discovery.trustMarks);
} else {
  console.error("Discovery failed:", result.error.description);
}
```

`DiscoveryResult` is branded so only `discoverEntity()` can produce it. RP registration functions in `@oidfed/oidc` require this type to prevent unvalidated data from entering registration flows.
