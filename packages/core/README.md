# @oidfed/core

[![npm](https://img.shields.io/npm/v/@oidfed/core.svg)](https://www.npmjs.com/package/@oidfed/core)
[![downloads](https://img.shields.io/npm/dm/@oidfed/core.svg)](https://www.npmjs.com/package/@oidfed/core)
[![license](https://img.shields.io/npm/l/@oidfed/core.svg)](https://github.com/Dahkenangnon/oidfed/blob/main/packages/core/LICENSE)
[![install size](https://packagephobia.com/badge?p=@oidfed/core)](https://packagephobia.com/result?p=@oidfed/core)
[![coverage](https://img.shields.io/badge/coverage-%E2%89%A590%25-brightgreen)](https://github.com/Dahkenangnon/oidfed/blob/main/scripts/coverage-check.sh)

<div align="center">
  <img src="https://raw.githubusercontent.com/Dahkenangnon/oidfed/main/internal/assets/core.png" alt="@oidfed/core banner" width="600" />
</div>

<p align="center">
  <b>@oidfed/core</b> &nbsp;•&nbsp;
  <a href="https://www.npmjs.com/package/@oidfed/authority">@oidfed/authority</a> &nbsp;•&nbsp;
  <a href="https://www.npmjs.com/package/@oidfed/leaf">@oidfed/leaf</a> &nbsp;•&nbsp;
  <a href="https://www.npmjs.com/package/@oidfed/oidc">@oidfed/oidc</a> &nbsp;•&nbsp;
  <a href="https://www.npmjs.com/package/@oidfed/cli">@oidfed/cli</a>
</p>

Federation primitives for JavaScript — entity statements, trust chain resolution, metadata policy, and cryptographic verification. The foundational layer for OpenID Federation 1.0 deployments.

Targets the final [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) specification and its successor specifications:
* [OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html) (protocol-independent layer)
* [OpenID Federation for OpenID Connect 1.1](https://openid.net/specs/openid-federation-connect-1_1.html) (protocol-specific layer)
* [OpenID Federation Extended Subordinate Listing 1.0](https://openid.net/specs/openid-federation-extended-listing-1_0.html) (tracks draft-02)

## Install

Choose the command for your preferred JavaScript package manager or runtime:

```bash
# npm
npm install @oidfed/core

# pnpm
pnpm add @oidfed/core

# yarn
yarn add @oidfed/core

# bun
bun add @oidfed/core

# Deno (Deno 2.0+ / JSR/npm specifier auto-resolution)
deno add npm:@oidfed/core
```

## Quick Start

```ts
import {
  entityId,
  generateSigningKey,
  resolveTrustChains,
  validateTrustChain,
  createTrustAnchorSet,
} from "@oidfed/core";

const trustAnchors = createTrustAnchorSet([
  { entityId: "https://ta.example.org", jwks: { keys: [taKey] } },
]);

const result = await resolveTrustChains(
  entityId("https://leaf.example.com"),
  trustAnchors,
);

for (const chain of result.chains) {
  const validated = await validateTrustChain(chain.statements, trustAnchors);
  if (validated.valid) {
    console.log(validated.chain.resolvedMetadata);
  }
}
```

## Documentation

For a detailed API reference, configuration options, and core architectural guides, see the [docs/packages/core.md](https://github.com/Dahkenangnon/oidfed/blob/main/docs/packages/core.md) file.

## License

[Apache-2.0](./LICENSE) — see [`NOTICE`](./NOTICE) for attribution.
