# @oidfed/authority

[![npm](https://img.shields.io/npm/v/@oidfed/authority.svg)](https://www.npmjs.com/package/@oidfed/authority)
[![downloads](https://img.shields.io/npm/dm/@oidfed/authority.svg)](https://www.npmjs.com/package/@oidfed/authority)
[![license](https://img.shields.io/npm/l/@oidfed/authority.svg)](https://github.com/Dahkenangnon/oidfed/blob/main/packages/authority/LICENSE)
[![install size](https://packagephobia.com/badge?p=@oidfed/authority)](https://packagephobia.com/result?p=@oidfed/authority)
[![coverage](https://img.shields.io/badge/coverage-%E2%89%A590%25-brightgreen)](https://github.com/Dahkenangnon/oidfed/blob/main/scripts/coverage-check.sh)

<div align="center">
  <img src="https://raw.githubusercontent.com/Dahkenangnon/oidfed/main/internal/assets/authority.png" alt="@oidfed/authority banner" width="600" />
</div>

<p align="center">
  <a href="https://www.npmjs.com/package/@oidfed/core">@oidfed/core</a> &nbsp;•&nbsp;
  <b>@oidfed/authority</b> &nbsp;•&nbsp;
  <a href="https://www.npmjs.com/package/@oidfed/leaf">@oidfed/leaf</a> &nbsp;•&nbsp;
  <a href="https://www.npmjs.com/package/@oidfed/oidc">@oidfed/oidc</a> &nbsp;•&nbsp;
  <a href="https://www.npmjs.com/package/@oidfed/cli">@oidfed/cli</a>
</p>

Trust Anchor and Intermediate Authority operations — subordinate management, statement issuance, federation endpoint serving, and policy enforcement for the complete OpenID Federation 1.0 implementation.

Implements the final [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) specification and its successor specifications:
* [OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html) (protocol-independent layer)
* [OpenID Federation for OpenID Connect 1.1](https://openid.net/specs/openid-federation-connect-1_1.html) (protocol-specific layer)
* [OpenID Federation Extended Subordinate Listing 1.0](https://openid.net/specs/openid-federation-extended-listing-1_0.html) (tracks draft-02)

> **Status:** prerelease — API may change before the upcoming stable `1.0.0` release.

## Install

Choose the command for your preferred JavaScript package manager or runtime:

```bash
# npm
npm install @oidfed/core @oidfed/authority

# pnpm
pnpm add @oidfed/core @oidfed/authority

# yarn
yarn add @oidfed/core @oidfed/authority

# bun
bun add @oidfed/core @oidfed/authority

# Deno (Deno 2.0+ / JSR/npm specifier auto-resolution)
deno add npm:@oidfed/core npm:@oidfed/authority
```

## Quick Start

```ts
import { TrustAnchor, MemoryStorageAdapter } from "@oidfed/authority";
import { generateSigningKey, MemoryFederationKeyProvider, federationKey } from "@oidfed/core";

const signingKey = await generateSigningKey("ES256");
const keyProvider = new MemoryFederationKeyProvider(federationKey({
  ...signingKey.privateKey,
  kid: "key-1",
}));

const ta = new TrustAnchor({
  entityId: "https://ta.example.org",
  keyProvider,
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: "https://ta.example.org/federation_fetch",
      federation_list_endpoint: "https://ta.example.org/federation_list",
      federation_extended_list_endpoint: "https://ta.example.org/federation_extended_list",
    },
  },
  storage: new MemoryStorageAdapter(),
});

// Serve requests directly with fetch-compatible handleRequest:
const response = await ta.handleRequest(request);
```

Federation endpoint `private_key_jwt` authentication uses `AuthorityConfig.clientKeyProvider`
to resolve a caller's public Federation Entity Keys. Omit it to use the default
subordinate-storage lookup: `storage.subordinates.get(entityId)?.jwks`.

## Documentation

For a detailed API reference, subordinate management APIs, and unified storage adapter setups, see the [docs/packages/authority.md](https://github.com/Dahkenangnon/oidfed/blob/main/docs/packages/authority.md) file.

## License

[Apache-2.0](./LICENSE) — see [`NOTICE`](./NOTICE) for attribution.
