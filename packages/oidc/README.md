# @oidfed/oidc

OpenID Connect and OAuth 2.0 federation flows — automatic and explicit client registration, Request Object validation, and RP/OP metadata processing as defined in [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html).

> **Status:** `v0.2.0` pre-release — API may change before the first stable `1.0` release.

## Install

```bash
npm install @oidfed/core @oidfed/oidc
```

## Quick Start

### RP — Automatic Registration

```ts
import { automaticRegistration } from "@oidfed/oidc";
import { discoverEntity } from "@oidfed/leaf";

const opDiscovery = await discoverEntity(opEntityId, trustAnchors);

const result = await automaticRegistration(
  opDiscovery,
  rpConfig,
  { scope: "openid profile", state: "xyz" },
  trustAnchors,
);
// result.authorizationUrl — redirect the user here
```

### OP — Processing Registration

```ts
import { processAutomaticRegistration } from "@oidfed/oidc";

const result = await processAutomaticRegistration(requestObjectJwt, trustAnchors, {
  opEntityId: entityId("https://op.example.com"),
  jtiStore,
});
// Result<ProcessedRegistration, FederationError> — never throws
```

## What's Included

- RP-side automatic registration (Request Object + trust chain embedding)
- RP-side explicit registration (Entity Configuration POST)
- OP-side processing for both registration types (returns `Result`, never throws)
- Typed OP/RP metadata schemas (extends core's loose `z.record()`)
- Request Object validation
- Client assertion creation (`private_key_jwt`)
- `OIDCRegistrationAdapter` for plugging into `@oidfed/authority`

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
