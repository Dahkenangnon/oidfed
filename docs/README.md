# Documentation

Use `@oidfed/*` to add federation trust and registration to an existing service. Your OP still owns authentication and token issuance; your RP still owns its login session, callback, and token validation.

## Start with your role

| You are building… | Read first | Next step |
|---|---|---|
| A Trust Anchor or Intermediate Authority | [Authority](packages/authority.md) | [Storage](guide/storage-guide.md) and [HTTP wiring](guide/wiring-guide.md) |
| An OP joining a federation | [Leaf](packages/leaf.md) and [OIDC roles](packages/oidc.md) | Connect registration processing to your OP's client store |
| An RP joining a federation | [Leaf](packages/leaf.md) and [OIDC roles](packages/oidc.md) | Discover an OP and choose automatic or explicit registration |
| A federation inspector or validator | [CLI](tools/cli.md) or [explorer](apps/explorer.md) | [Core](packages/core.md) for programmatic access |
| A contributor running the repository | [Local development](guide/dev.md) | [E2E tests](test/e2e.md) and [shared UI](internal/ui.md) |

## Packages

| Package | Responsibility |
|---|---|
| [`@oidfed/core`](packages/core.md) | Entity Statements, signatures, trust-chain discovery and validation, metadata policies, constraints, trust marks, and federation key contracts |
| [`@oidfed/authority`](packages/authority.md) | Trust Anchors and Intermediates: subordinate records, statement issuance, federation endpoints, and key lifecycle integration |
| [`@oidfed/leaf`](packages/leaf.md) | Self-signed Entity Configurations for participants that do not issue Subordinate Statements |
| [`@oidfed/oidc`](packages/oidc.md) | OIDC/OAuth roles and federation registration methods composed into a parent entity |
| [`@oidfed/cli`](tools/cli.md) | Terminal inspection, validation, signing, and health checks |

```text
@oidfed/authority ─┐
@oidfed/leaf      ─┼─→ @oidfed/core
@oidfed/oidc      ─┘
@oidfed/cli       ──→ @oidfed/core
```

The three libraries beside `core` use it as a peer dependency and do not depend on one another. Install `core` alongside the libraries you use.

## Integration model

Choose one parent entity for each Entity Identifier: `TrustAnchor`, `Intermediate`, or `Leaf`. Add OIDC/OAuth roles to that parent. For example, an OP that has no federation subordinates uses `Leaf` with `OidcProviderRole`; an OP that also issues Subordinate Statements can use `Intermediate` with the same role.

Parent handlers accept a Web API `Request` and return a `Promise<Response>`. Parents merge role metadata and dispatch role routes. Your application adapts these handlers to its HTTP framework and connects registration hooks to its OIDC implementation.

Keep federation signing keys separate from OIDC/OAuth protocol keys. Federation key providers expose the federation signer and public JWKS; protocol key providers supply Request Object and client-assertion signers. In-memory providers and adapters support local development; production deployments need durable keys and shared authoritative state.

## Guides

- [Wiring guide](guide/wiring-guide.md): configure entities, enroll subordinates, adapt HTTP requests, and connect OP/RP registration.
- [Storage guide](guide/storage-guide.md): persistence, transaction, replay, and cache contracts.
- [Development guide](guide/dev.md): workspace commands, local federation topologies, DNS, and TLS.
- [E2E tests](test/e2e.md): HTTPS test infrastructure and scenario lifecycle.
- [Project README](../README.md): requirements, specification support, security, and licensing.
