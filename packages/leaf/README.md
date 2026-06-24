# @oidfed/leaf

[![npm](https://img.shields.io/npm/v/@oidfed/leaf.svg)](https://www.npmjs.com/package/@oidfed/leaf)
[![downloads](https://img.shields.io/npm/dm/@oidfed/leaf.svg)](https://www.npmjs.com/package/@oidfed/leaf)
[![license](https://img.shields.io/npm/l/@oidfed/leaf.svg)](https://github.com/Dahkenangnon/oidfed/blob/main/packages/leaf/LICENSE)
[![install size](https://packagephobia.com/badge?p=@oidfed/leaf)](https://packagephobia.com/result?p=@oidfed/leaf)
[![coverage](https://img.shields.io/badge/coverage-%E2%89%A590%25-brightgreen)](https://github.com/Dahkenangnon/oidfed/blob/main/scripts/coverage-check.sh)

<div align="center">
  <img src="https://raw.githubusercontent.com/Dahkenangnon/oidfed/main/internal/assets/leaf.png" alt="@oidfed/leaf banner" width="600" />
</div>

<p align="center">
  <a href="https://www.npmjs.com/package/@oidfed/core">@oidfed/core</a> &nbsp;•&nbsp;
  <a href="https://www.npmjs.com/package/@oidfed/authority">@oidfed/authority</a> &nbsp;•&nbsp;
  <b>@oidfed/leaf</b> &nbsp;•&nbsp;
  <a href="https://www.npmjs.com/package/@oidfed/oidc">@oidfed/oidc</a> &nbsp;•&nbsp;
  <a href="https://www.npmjs.com/package/@oidfed/cli">@oidfed/cli</a>
</p>

Leaf Entity toolkit — Entity Configuration serving, authority discovery, and trust chain participation for any entity at the edge of an OpenID Federation.

Implements the final [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) specification and its successor specifications:
* [OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html) (protocol-independent layer)
* [OpenID Federation for OpenID Connect 1.1](https://openid.net/specs/openid-federation-connect-1_1.html) (protocol-specific layer)

> **Status:** prerelease — API may change before the upcoming stable `1.0.0` release.

## Install

Choose the command for your preferred JavaScript package manager or runtime:

```bash
# npm
npm install @oidfed/core @oidfed/leaf

# pnpm
pnpm add @oidfed/core @oidfed/leaf

# yarn
yarn add @oidfed/core @oidfed/leaf

# bun
bun add @oidfed/core @oidfed/leaf

# Deno (Deno 2.0+ / JSR/npm specifier auto-resolution)
deno add npm:@oidfed/core npm:@oidfed/leaf
```

## Quick Start

```ts
import { Leaf } from "@oidfed/leaf";
import { FedOidcClient } from "@oidfed/oidc";
import { MemoryFederationKeyProvider, federationKey } from "@oidfed/core";

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

// Serve the request directly using a fetch-compatible interface:
const response = await leaf.handleRequest(request);
```

## Documentation

For a detailed API reference, entity configuration setups, and authority discovery guides, see the [docs/packages/leaf.md](https://github.com/Dahkenangnon/oidfed/blob/main/docs/packages/leaf.md) file.

## License

[Apache-2.0](./LICENSE) — see [`NOTICE`](./NOTICE) for attribution.
