# @oidfed/oidc

[![npm](https://img.shields.io/npm/v/@oidfed/oidc.svg)](https://www.npmjs.com/package/@oidfed/oidc)
[![downloads](https://img.shields.io/npm/dm/@oidfed/oidc.svg)](https://www.npmjs.com/package/@oidfed/oidc)
[![license](https://img.shields.io/npm/l/@oidfed/oidc.svg)](https://github.com/Dahkenangnon/oidfed/blob/main/packages/oidc/LICENSE)
[![install size](https://packagephobia.com/badge?p=@oidfed/oidc)](https://packagephobia.com/result?p=@oidfed/oidc)
[![coverage](https://img.shields.io/badge/coverage-%E2%89%A585%25-brightgreen)](https://github.com/Dahkenangnon/oidfed/blob/main/scripts/coverage-check.sh)

OpenID Connect and OAuth 2.0 federation flows — automatic and explicit client registration, Request Object validation, and RP/OP metadata processing as defined in [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html).

> **Status:** prerelease — API may change before the upcoming stable `1.0.0` release.

## Install

```bash
npm install @oidfed/core @oidfed/oidc
```

## Quick Start

This package provides role classes that compose directly with `Leaf`, `TrustAnchor`, or `Intermediate` instances.

OIDC/OAuth protocol keys are separate from federation entity keys:
- OIDC/OAuth roles publish OIDC/OAuth protocol public keys via `jwks` inside the role configuration.
- Federation Entity Configurations and other federation artifacts stay on federation key providers from `@oidfed/core`.

### RP Composition Example

```ts
import { Leaf } from "@oidfed/leaf";
import { FedOidcClient } from "@oidfed/oidc";
import { MemoryFederationKeyProvider, federationKey } from "@oidfed/core";

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
      redirect_uris: ["https://rp.example.com/callback"],
      response_types: ["code"],
      client_registration_types: ["automatic"],
      jwks: { keys: [protocolPublicKey] },
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
      authorization_endpoint: "https://op.example.com/auth",
      token_endpoint: "https://op.example.com/token",
      federation_registration_endpoint: "https://op.example.com/register",
      client_registration_types_supported: ["automatic", "explicit"],
      jwks: { keys: [protocolPublicKey] },
    })
  ]
});
```

## What's Included

- OIDC Provider Role (`FedOidcProvider`)
- OIDC Relying Party Role (`FedOidcClient`)
- OAuth Authorization Server Role (`FedOauthProvider`)
- OAuth Client Role (`FedOauthClient`)
- OAuth Resource Server Role (`FedOauthResource`)
- Automatic and Explicit client registration processing
- Typed OP/RP/AS/Client metadata schemas
- OIDC protocol signing and Request Object validation

## Documentation

Full API reference: [docs/packages/oidc.md](https://github.com/Dahkenangnon/oidfed/blob/main/docs/packages/oidc.md)

## Part of @oidfed

| Package | Role |
|---------|------|
| [@oidfed/core](https://www.npmjs.com/package/@oidfed/core) | Federation primitives |
| [@oidfed/authority](https://www.npmjs.com/package/@oidfed/authority) | Trust Anchor & Intermediate operations |
| [@oidfed/leaf](https://www.npmjs.com/package/@oidfed/leaf) | Leaf Entity toolkit |
| **@oidfed/oidc** | OIDC/OAuth 2.0 federation flows (this package) |
| [@oidfed/cli](https://www.npmjs.com/package/@oidfed/cli) | CLI for federation debugging |

## License

[Apache-2.0](./LICENSE) — see [`NOTICE`](./NOTICE) for attribution.
