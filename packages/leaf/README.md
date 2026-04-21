# @oidfed/leaf

Leaf Entity toolkit — Entity Configuration serving, authority discovery, and trust chain participation for any entity at the edge of an [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html).

> **Status:** `v0.1.0` pre-release — API may change before the first stable `1.0` release.

## Install

```bash
npm install @oidfed/core @oidfed/leaf
```

## Quick Start

```ts
import { createLeafEntity } from "@oidfed/leaf";
import { entityId } from "@oidfed/core";

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

const handler = leaf.handler(); // fetch-compatible (Request → Response)
```

## What's Included

- Entity Configuration serving at `/.well-known/openid-federation`
- Authority discovery with branded `DiscoveryResult` type
- Automatic key stripping (private fields removed from published JWKS)
- Lazy EC generation with caching and refresh

## Documentation

Full API reference: [docs/packages/leaf.md](https://github.com/Dahkenangnon/oidfed/blob/main/docs/packages/leaf.md)

## Part of @oidfed

| Package | Role |
|---------|------|
| [@oidfed/core](https://www.npmjs.com/package/@oidfed/core) | Federation primitives |
| [@oidfed/authority](https://www.npmjs.com/package/@oidfed/authority) | Trust Anchor & Intermediate operations |
| **@oidfed/leaf** | Leaf Entity toolkit (this package) |
| [@oidfed/oidc](https://www.npmjs.com/package/@oidfed/oidc) | OIDC/OAuth 2.0 federation flows |
| [@oidfed/cli](https://www.npmjs.com/package/@oidfed/cli) | CLI for federation debugging |

## License

[MIT](./LICENSE)
