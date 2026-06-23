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
import { createLeafEntity } from "@oidfed/leaf";
import { entityId, JwkSigner, MemoryFederationKeyProvider } from "@oidfed/core";
import express from "express";

const leaf = createLeafEntity({
  entityId: entityId("https://rp.example.com"),
  authorityHints: [entityId("https://federation.example.org")],
  keyProvider: new MemoryFederationKeyProvider({
    signer: new JwkSigner(myFederationSigningKey),
    publicJwk: myFederationPublicKey,
  }),
  metadata: {
    openid_relying_party: {
      redirect_uris: ["https://rp.example.com/callback"],
      response_types: ["code"],
      client_registration_types: ["automatic"],
    },
  },
});

const handler = leaf.handler();

const app = express();
app.use(async (req, res) => {
  const response = await handler(req as unknown as Request);
  res.status(response.status);
  response.headers.forEach((value, key) => res.setHeader(key, value));
  res.send(await response.text());
});
```

## API

### Entity and Handler

```ts
import { createLeafEntity, createLeafHandler } from "@oidfed/leaf";
import type { LeafConfig, LeafEntity } from "@oidfed/leaf";
import type { FederationKeyProvider } from "@oidfed/core";
```

`createLeafEntity(config)` throws synchronously if `authorityHints` is empty, any authority hint is not a valid Entity Identifier, or `keyProvider` is missing. At runtime it also validates that the active federation signer is published exactly once in the provider's federation JWKS.

```ts
interface LeafConfig {
  entityId: EntityId;
  keyProvider: FederationKeyProvider;
  authorityHints: readonly [EntityId, ...EntityId[]];
  metadata: FederationMetadata;
  trustMarks?: TrustMarkRef[];
  entityConfigurationTtlSeconds?: number;
  options?: FederationOptions;
}

interface LeafEntity {
  getEntityConfiguration(): Promise<string>;
  isEntityConfigurationExpired(): boolean;
  refreshEntityConfiguration(): Promise<string>;
  handler(): (request: Request) => Promise<Response>;
}
```

The published top-level Entity Statement `jwks` comes from `keyProvider.getFederationKeySet()`. The provider, not the leaf config, is the source of truth for federation public keys.

Configure time through `options.clock`. Like every core `Clock`, it returns Unix NumericDate seconds and controls Entity Configuration generation and expiry.

`createLeafHandler(entity)` is the standalone handler for `/.well-known/openid-federation`. It responds `405` for non-GET, `404` for unknown paths, and sets `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, and HSTS headers.

### Discovery

```ts
import { discoverEntity } from "@oidfed/leaf";
import { isOk } from "@oidfed/core";
```

```ts
const result = await discoverEntity(
  entityId("https://op.example.com"),
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
