# @oidfed/authority

Trust Anchor and Intermediate Authority operations — subordinate management, statement issuance, federation endpoint serving, and policy enforcement for the complete [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) implementation.

> **Status:** `v0.1.0` pre-release — API may change before the first stable `1.0` release.

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
    },
  },
  subordinateStore: new MemorySubordinateStore(),
  keyStore: new MemoryKeyStore(signingKey),
});

const handler = server.handler(); // fetch-compatible (Request → Response)
```

## What's Included

- All spec-defined federation endpoints as a single fetch-compatible handler
- Subordinate management — add, update, remove, list
- Key lifecycle — pending → active → retiring → revoked
- Trust mark issuance, delegation, and status checking
- Middleware composition for logging, rate limiting, auth
- Pluggable storage interfaces (memory implementations included)

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

[MIT](./LICENSE)
