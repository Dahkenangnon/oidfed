# @oidfed/oidc

[![npm](https://img.shields.io/npm/v/@oidfed/oidc.svg)](https://www.npmjs.com/package/@oidfed/oidc)
[![downloads](https://img.shields.io/npm/dm/@oidfed/oidc.svg)](https://www.npmjs.com/package/@oidfed/oidc)
[![license](https://img.shields.io/npm/l/@oidfed/oidc.svg)](https://github.com/Dahkenangnon/oidfed/blob/main/packages/oidc/LICENSE)
[![install size](https://packagephobia.com/badge?p=@oidfed/oidc)](https://packagephobia.com/result?p=@oidfed/oidc)
[![coverage](https://img.shields.io/badge/coverage-%E2%89%A585%25-brightgreen)](https://github.com/Dahkenangnon/oidfed/blob/main/scripts/coverage-check.sh)

<div align="center">
  <img src="https://raw.githubusercontent.com/Dahkenangnon/oidfed/main/internal/assets/oidc.png" alt="@oidfed/oidc banner" width="600" />
</div>

<p align="center">
  <a href="https://www.npmjs.com/package/@oidfed/core">@oidfed/core</a> &nbsp;•&nbsp;
  <a href="https://www.npmjs.com/package/@oidfed/authority">@oidfed/authority</a> &nbsp;•&nbsp;
  <a href="https://www.npmjs.com/package/@oidfed/leaf">@oidfed/leaf</a> &nbsp;•&nbsp;
  <b>@oidfed/oidc</b> &nbsp;•&nbsp;
  <a href="https://www.npmjs.com/package/@oidfed/cli">@oidfed/cli</a>
</p>

OpenID Connect and OAuth 2.0 federation flows — automatic and explicit client registration, Request Object validation, and RP/OP metadata processing as defined in OpenID Federation 1.0.

Implements the final [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) specification and its successor specifications:
* [OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html) (protocol-independent layer)
* [OpenID Federation for OpenID Connect 1.1](https://openid.net/specs/openid-federation-connect-1_1.html) (protocol-specific layer)

> **Status:** prerelease — API may change before the upcoming stable `1.0.0` release.

## Install

Choose the command for your preferred JavaScript package manager or runtime:

```bash
# npm
npm install @oidfed/core @oidfed/oidc

# pnpm
pnpm add @oidfed/core @oidfed/oidc

# yarn
yarn add @oidfed/core @oidfed/oidc

# bun
bun add @oidfed/core @oidfed/oidc

# Deno (Deno 2.0+ / JSR/npm specifier auto-resolution)
deno add npm:@oidfed/core npm:@oidfed/oidc
```

## Quick Start

This package provides role classes that compose directly with `Leaf`, `TrustAnchor`, or `Intermediate` instances.

OIDC/OAuth protocol keys are separate from federation entity keys:
- OIDC/OAuth roles publish OIDC/OAuth protocol public keys via `jwks` inside the role `metadata` configuration.
- Federation Entity Configurations and other federation artifacts stay on federation key providers from `@oidfed/core`.

### RP Composition Example

```ts
import { Leaf } from "@oidfed/leaf";
import { FedOidcClient, StaticOidcProtocolKeyProvider } from "@oidfed/oidc";
import { JwkSigner, MemoryFederationKeyProvider, federationKey } from "@oidfed/core";

const rpEntity = new Leaf({
  entityId: "https://rp.example.com",
  authorityHints: ["https://ta.example.org"],
  keyProvider: new MemoryFederationKeyProvider(federationKey(federationSigningKey)),
  metadata: {
    federation_entity: {
      organization_name: "My Relying Party",
    },
  },
  roles: [
    new FedOidcClient({
      protocolKeyProvider: new StaticOidcProtocolKeyProvider({
        requestObjectSigner: new JwkSigner(protocolSigningKey),
      }),
      metadata: {
        redirect_uris: ["https://rp.example.com/callback"],
        response_types: ["code"],
        client_registration_types: ["automatic"],
        jwks: { keys: [protocolPublicKey] },
      },
    })
  ]
});
```

### OP Composition Example

```ts
import { TrustAnchor, MemoryStorageAdapter } from "@oidfed/authority";
import { FedOidcProvider } from "@oidfed/oidc";

const opEntity = new TrustAnchor({
  entityId: "https://op.example.com",
  keyProvider,
  storage: new MemoryStorageAdapter(),
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: "https://op.example.com/federation_fetch",
      federation_list_endpoint: "https://op.example.com/federation_list",
    },
  },
  roles: [
    new FedOidcProvider({
      registrationPath: "/register",
      metadata: {
        issuer: "https://op.example.com",
        authorization_endpoint: "https://op.example.com/auth",
        token_endpoint: "https://op.example.com/token",
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["ES256"],
        client_registration_types_supported: ["automatic", "explicit"],
        jwks: { keys: [protocolPublicKey] },
      },
    })
  ]
});
```

## Documentation

For a detailed API reference, OIDC role classes, automatic/explicit registration details, and metadata types, see the [docs/packages/oidc.md](https://github.com/Dahkenangnon/oidfed/blob/main/docs/packages/oidc.md) file.

## License

[Apache-2.0](./LICENSE) — see [`NOTICE`](./NOTICE) for attribution.
