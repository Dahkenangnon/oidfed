# @oidfed Documentation

Welcome. These docs help you add OpenID Federation 1.0 behavior to systems you already run: Trust Anchors, Intermediate Authorities, OpenID Providers, Relying Parties, command-line tools, and browser tools.

The important boundary: `@oidfed/*` provides the federation-participation layer. It does not replace your OP, RP, authorization server, database, key vault, reverse proxy, rate limiter, or deployment platform. Instead, it gives those systems the OpenID Federation pieces they need: Entity Configurations, Subordinate Statements, trust-chain resolution, metadata policy, Trust Marks, federation endpoints, and OpenID Connect client registration.

If you are not sure where to start, use the paths below.

## Start Here

| Goal | Start with | Then read |
|---|---|---|
| Learn the concepts first | [Learn OpenID Federation](https://learn.oidfed.com) | [`@oidfed/core`](packages/core.md) |
| Inspect a live federation | [Explorer app](apps/explorer.md) or [`explore.oidfed.com`](https://explore.oidfed.com) | [`@oidfed/cli`](tools/cli.md) |
| Build a Trust Anchor or Intermediate | [`@oidfed/authority`](packages/authority.md) | [Wiring guide](guide/wiring-guide.md), [Storage guide](guide/storage-guide.md) |
| Federation-enable an OP | [`@oidfed/leaf`](packages/leaf.md) + [`@oidfed/oidc`](packages/oidc.md) | [Wiring guide](guide/wiring-guide.md) |
| Federation-enable an RP | [`@oidfed/leaf`](packages/leaf.md) + [`@oidfed/oidc`](packages/oidc.md) | [`@oidfed/core`](packages/core.md) for trust-chain validation |
| Prepare production storage and keys | [Storage guide](guide/storage-guide.md) | [`@oidfed/authority`](packages/authority.md) key lifecycle notes |
| Run the local reference federation | [Dev guide](guide/dev.md) | [E2E test infrastructure](test/e2e.md) |

## What Each Package Is For

| Package | Use it when you need to |
|---|---|
| [`@oidfed/core`](packages/core.md) | Decode, sign, fetch, resolve, and validate federation artifacts; apply metadata policy; manage federation signing-key contracts. |
| [`@oidfed/authority`](packages/authority.md) | Operate a Trust Anchor or Intermediate Authority that enrolls subordinates and serves federation endpoints. |
| [`@oidfed/leaf`](packages/leaf.md) | Publish a leaf Entity Configuration and participate in federation discovery from an OP, RP, resource server, or other edge entity. |
| [`@oidfed/oidc`](packages/oidc.md) | Add OpenID Connect / OAuth federation roles, OP metadata, RP metadata, automatic registration, and explicit registration handling. |
| [`@oidfed/cli`](tools/cli.md) | Inspect, debug, validate, and script federation artifacts from the terminal. |

## Choose By Role

### I am building a Trust Anchor or Intermediate Authority

Read [`@oidfed/authority`](packages/authority.md) first. It covers subordinate management, statement issuance, federation endpoint routing, policy enforcement, Trust Marks, historical keys, and federation signing-key lifecycle.

Then use:

- [Wiring guide](guide/wiring-guide.md) for an end-to-end HTTP integration.
- [Storage guide](guide/storage-guide.md) for subordinate, key, trust-mark, cache, and replay stores.
- [Dev guide](guide/dev.md) if you want to run the local multi-topology federation while building.

### I have an OpenID Provider and want to federate it

`@oidfed/*` federation-enables an OP you already operate. It does not implement the OP itself.

Read:

- [`@oidfed/leaf`](packages/leaf.md) for Entity Configuration serving and federation discovery.
- [`@oidfed/oidc`](packages/oidc.md) for OP federation metadata, automatic-registration request processing, and explicit-registration handling.
- [Wiring guide](guide/wiring-guide.md) for integration patterns, including `node-oidc-provider`.

### I have a Relying Party and want to federate it

`@oidfed/*` federation-enables an RP you already operate. It does not implement the RP application.

Read:

- [`@oidfed/leaf`](packages/leaf.md) for Entity Configuration serving and trust-chain participation.
- [`@oidfed/oidc`](packages/oidc.md) for automatic and explicit client-registration flows the RP drives against an OP.
- [`@oidfed/core`](packages/core.md) when you need lower-level trust-chain resolution and validation behavior.

### I want to validate or inspect a federation

Use whichever interface fits your workflow:

- [`explore.oidfed.com`](https://explore.oidfed.com) for a browser-based federation explorer.
- [`@oidfed/cli`](tools/cli.md) for terminal commands such as `resolve`, `fetch`, `decode`, `verify`, `validate`, `sign`, `keygen`, `chain`, `list`, `list-extended`, `trust-mark-status`, `expiry`, and `health`.
- [`@oidfed/core`](packages/core.md) for programmatic trust-chain resolution, signature validation, and metadata-policy handling.

### I want to understand the repo's apps and test beds

- [Explorer app](apps/explorer.md) documents the browser explorer and its source.
- [`@oidfed/ui`](internal/ui.md) documents the private shared component library used by the apps.
- [E2E test infrastructure](test/e2e.md) explains the local topology launcher, vhost dispatcher, and declarative test beds.

## Core Concepts To Keep Straight

- Federation keys and protocol keys are separate. Federation Entity Keys live in `@oidfed/core`; OpenID Connect / OAuth protocol signing keys live behind `@oidfed/oidc` protocol-key providers.
- Storage is pluggable. The packages expose interfaces for persistence and replay protection instead of choosing a database.
- HTTP handlers use Web API primitives. Package handlers accept `Request` and return `Response`, which keeps them portable across runtimes and frameworks.
- Roles are composable. A single deployment can combine authority, leaf, and OIDC roles when that entity plays more than one federation role.

## Package Dependency Map

```
@oidfed/authority ─┐
@oidfed/leaf      ─┼─→ @oidfed/core
@oidfed/oidc      ─┘
@oidfed/cli       ──→ @oidfed/core
```

`@oidfed/authority`, `@oidfed/leaf`, and `@oidfed/oidc` are siblings at the dependency level: each depends on `@oidfed/core`, never on each other. That keeps package boundaries clean, but it does not limit deployment composition. An OP can use `@oidfed/leaf` plus `@oidfed/oidc`; an Intermediate Authority can also publish its own leaf metadata; and an entity can act as both OP and RP when its trust model requires that.

## Repository Guides

- [Wiring guide](guide/wiring-guide.md) — framework integration and request routing.
- [Storage guide](guide/storage-guide.md) — production adapters, key references, and secrets-manager patterns.
- [Dev guide](guide/dev.md) — local federation server, wildcard DNS, TLS, and workspace commands.
- [E2E test infrastructure](test/e2e.md) — topology launcher and scenario structure.
- [Project README](../README.md) — package badges, install overview, related specifications, security, and licensing.
