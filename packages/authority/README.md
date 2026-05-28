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
  MemoryKeyStore,
  MemorySubordinateStore,
} from "@oidfed/authority";
import { entityId, generateSigningKey } from "@oidfed/core";

const signingKey = await generateSigningKey("ES256");

const server = createAuthorityServer({
  entityId: entityId("https://ta.example.org"),
  signingKeys: [signingKey],
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: "https://ta.example.org/federation_fetch",
      federation_list_endpoint: "https://ta.example.org/federation_list",
      federation_extended_list_endpoint:
        "https://ta.example.org/federation_extended_list",
    },
  },
  subordinateStore: new MemorySubordinateStore(),
  keyStore: new MemoryKeyStore(signingKey),
});

const handler = server.handler(); // fetch-compatible (Request → Response)
```

## What's Included

- All spec-defined federation endpoints as a single fetch-compatible handler
- Subordinate management — add, update, remove, list (ordered, paginated)
- Extended Subordinate Listing (`/federation_extended_list`) — cursor pagination, time-window filtering, audit timestamps, and bulk per-entity claim retrieval (signed subordinate statements, trust marks, metadata, …) per the [OpenID Federation Extended Subordinate Listing](https://openid.net/specs/openid-federation-extended-listing-1_0.html) spec
- Key lifecycle — pending → active → retiring → revoked
- Trust mark issuance, delegation, and status checking
- Middleware composition for logging, rate limiting, auth
- Pluggable storage interfaces (memory implementations included)

## Breaking changes from 0.2.x

- `SubordinateStore.list(filter)` now returns `Promise<{ items: SubordinateRecord[]; nextCursor?: EntityId }>` (was `Promise<SubordinateRecord[]>`) and accepts a second `ListPageOptions` argument with `cursor`, `limit`, `updatedAfter`, `updatedBefore`. Custom store implementations MUST be migrated to the new shape; see [docs/packages/authority.md](https://github.com/Dahkenangnon/oidfed/blob/main/docs/packages/authority.md#storage-interfaces).
- `TrustMarkStore.listForSubject?(subject)` is a new OPTIONAL method consumed only by `/federation_extended_list` with `claims=trust_marks`.

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
