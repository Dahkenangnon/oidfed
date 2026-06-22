# @oidfed/authority

[![npm](https://img.shields.io/npm/v/@oidfed/authority.svg)](https://www.npmjs.com/package/@oidfed/authority)
[![downloads](https://img.shields.io/npm/dm/@oidfed/authority.svg)](https://www.npmjs.com/package/@oidfed/authority)
[![license](https://img.shields.io/npm/l/@oidfed/authority.svg)](https://github.com/Dahkenangnon/oidfed/blob/main/packages/authority/LICENSE)
[![install size](https://packagephobia.com/badge?p=@oidfed/authority)](https://packagephobia.com/result?p=@oidfed/authority)

Trust Anchor and Intermediate Authority operations — subordinate management, statement issuance, federation endpoint serving, and policy enforcement for the complete [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) implementation.

> **Status:** prerelease — API may change before the upcoming stable `1.0.0` release.

## Install

```bash
npm install @oidfed/core @oidfed/authority
```

## Quick Start

```ts
import {
  createAuthorityServer,
  MemoryStorageAdapter,
} from "@oidfed/authority";
import { entityId, generateSigningKey, JwkSigner, MemoryFederationKeyProvider } from "@oidfed/core";

const signingKey = await generateSigningKey("ES256");
const keyProvider = new MemoryFederationKeyProvider({
  signer: new JwkSigner(signingKey.privateKey),
  publicJwk: signingKey.publicKey,
});

const server = createAuthorityServer({
  entityId: entityId("https://ta.example.org"),
  keyProvider,
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: "https://ta.example.org/federation_fetch",
      federation_list_endpoint: "https://ta.example.org/federation_list",
      federation_extended_list_endpoint:
        "https://ta.example.org/federation_extended_list",
    },
  },
  storage: new MemoryStorageAdapter(),
});

const handler = server.handler(); // fetch-compatible (Request → Response)
```

## What's Included

- All spec-defined federation endpoints as a single fetch-compatible handler
- Subordinate management — add, update, remove, list (ordered, paginated)
- Extended Subordinate Listing (`/federation_extended_list`) — cursor pagination, time-window filtering, audit timestamps, and bulk per-entity claim retrieval (signed subordinate statements, trust marks, metadata, …) per the [OpenID Federation Extended Subordinate Listing](https://openid.net/specs/openid-federation-extended-listing-1_0.html) spec
- Federation-only signing and public-key lifecycle via `ManagedFederationKeyProvider`
- Trust mark issuance, delegation, and status checking
- Middleware composition for logging, rate limiting, auth
- One transactional `StorageAdapter` with subordinate, optional trust-mark, replay, and cache capabilities

## Unified Storage

`createAuthorityServer` accepts one `storage` adapter instead of separate stores. It owns subordinate records, optional trust marks, optional replay, optional cache, and serializable authority-record transactions. Federation key custody remains exclusively behind `ManagedFederationKeyProvider`. See [the authority reference](https://github.com/Dahkenangnon/oidfed/blob/main/docs/packages/authority.md#unified-storage-adapter).

The stable package exports `StorageAdapter`, `StorageTransaction`, `SubordinateStorage`, `TrustMarkStorage`, `MemoryStorageAdapter`, and their record/page/option types. It does not expose compatibility aliases for pre-v1 store names. Generic HTTP helpers are imported from `@oidfed/core`; authority keeps endpoint factories and `HandlerContext` public for custom routing.

## Documentation

Full API reference: [docs/packages/authority.md](https://github.com/Dahkenangnon/oidfed/blob/main/docs/packages/authority.md)

## Part of @oidfed

| Package | Role |
|---------|------|
| [@oidfed/core](https://www.npmjs.com/package/@oidfed/core) | Federation primitives |
| **@oidfed/authority** | Trust Anchor & Intermediate operations (this package) |
| [@oidfed/leaf](https://www.npmjs.com/package/@oidfed/leaf) | Leaf Entity toolkit |
| [@oidfed/oidc](https://www.npmjs.com/package/@oidfed/oidc) | OIDC/OAuth 2.0 federation flows |
| [@oidfed/cli](https://www.npmjs.com/package/@oidfed/cli) | CLI for federation debugging |

## License

[Apache-2.0](./LICENSE) — see [`NOTICE`](./NOTICE) for attribution.
