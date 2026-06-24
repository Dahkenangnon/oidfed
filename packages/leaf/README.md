# @oidfed/leaf

[![npm](https://img.shields.io/npm/v/@oidfed/leaf.svg)](https://www.npmjs.com/package/@oidfed/leaf)
[![downloads](https://img.shields.io/npm/dm/@oidfed/leaf.svg)](https://www.npmjs.com/package/@oidfed/leaf)
[![license](https://img.shields.io/npm/l/@oidfed/leaf.svg)](https://github.com/Dahkenangnon/oidfed/blob/main/packages/leaf/LICENSE)
[![install size](https://packagephobia.com/badge?p=@oidfed/leaf)](https://packagephobia.com/result?p=@oidfed/leaf)

Leaf Entity toolkit — Entity Configuration serving, authority discovery, and trust chain participation for any entity at the edge of an [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html).

> **Status:** prerelease — API may change before the upcoming stable `1.0.0` release.

## Install

```bash
npm install @oidfed/core @oidfed/leaf
```

## Quick Start

```ts
import { Leaf } from "@oidfed/leaf";
import { MemoryFederationKeyProvider, federationKey } from "@oidfed/core";

const leaf = new Leaf({
  entityId: "https://rp.example.com",
  authorityHints: ["https://federation.example.org"],
  keyProvider: new MemoryFederationKeyProvider(federationKey(myFederationSigningKey)),
  metadata: {
    openid_relying_party: {
      redirect_uris: ["https://rp.example.com/callback"],
      response_types: ["code"],
      client_registration_types: ["automatic"],
    },
  },
});

// Serve the request directly using a fetch-compatible interface:
const response = await leaf.handleRequest(request);
```

## What's Included

- Entity Configuration serving at `/.well-known/openid-federation`
- Authority discovery with branded `DiscoveryResult` type
- Federation JWKS publication from `FederationKeyProvider`
- Lazy EC generation with caching and refresh

Configure a custom NumericDate-seconds clock through `LeafConfig.options.clock`.

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

[Apache-2.0](./LICENSE) — see [`NOTICE`](./NOTICE) for attribution.
