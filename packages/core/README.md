# @oidfed/core

Federation primitives for JavaScript — entity statements, trust chain resolution, metadata policy, and cryptographic verification. The foundational layer of the complete [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) implementation.

> **Status:** `v0.1.0` pre-release — API may change before the first stable `1.0` release.

## Install

```bash
npm install @oidfed/core
```

## Quick Start

```ts
import {
  entityId,
  generateSigningKey,
  resolveTrustChains,
  validateTrustChain,
} from "@oidfed/core";
import type { TrustAnchorSet } from "@oidfed/core";

const trustAnchors: TrustAnchorSet = new Map([
  [entityId("https://ta.example.org"), { jwks: { keys: [taKey] } }],
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

## What's Included

- Trust chain resolution, validation, refresh, and selection strategies
- JOSE operations — sign, verify, decode entity statements; key generation
- Metadata policy — merge and apply across trust chains
- Constraint checking — path length, naming constraints, allowed entity types
- Typed Zod schemas for all federation data structures
- Trust mark validation and delegation signing
- LRU cache, Result type, pluggable storage interfaces
- Fetch-compatible HTTP primitives (`Request` → `Response`)

## Documentation

Full API reference: [docs/packages/core.md](https://github.com/Dahkenangnon/oidfed/blob/main/docs/packages/core.md)

## Part of @oidfed

| Package | Role |
|---------|------|
| **@oidfed/core** | Federation primitives (this package) |
| [@oidfed/authority](https://www.npmjs.com/package/@oidfed/authority) | Trust Anchor & Intermediate operations |
| [@oidfed/leaf](https://www.npmjs.com/package/@oidfed/leaf) | Leaf Entity toolkit |
| [@oidfed/oidc](https://www.npmjs.com/package/@oidfed/oidc) | OIDC/OAuth 2.0 federation flows |
| [@oidfed/cli](https://www.npmjs.com/package/@oidfed/cli) | CLI for federation debugging |

## License

[MIT](./LICENSE)
