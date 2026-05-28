# Documentation

The `@oidfed/*` monorepo splits OpenID Federation 1.0 into focused packages plus a CLI and three apps. `oidfed` provides the federation-participation layer — it does not implement OpenID Provider or Relying Party application logic on its own. Pick the path that matches the federation role your entity plays.

## Choose your path

### I am building a Trust Anchor or Intermediate Authority

- [`@oidfed/authority` reference](packages/authority.md) — subordinate management, statement issuance, federation endpoint serving, policy enforcement.
- [Wiring guide](guide/wiring-guide.md) — end-to-end Express integration.
- [Storage guide](guide/storage-guide.md) — pluggable subordinate / key / trust-mark stores.

### I have an OpenID Provider and want to federate it

`oidfed` does not implement OP application logic; it federation-enables an OP you already operate (for example one built on `node-oidc-provider`).

- [`@oidfed/leaf` reference](packages/leaf.md) — Entity Configuration serving and OP-side discovery.
- [`@oidfed/oidc` reference](packages/oidc.md) — explicit-registration handler and automatic-registration request processing for the OP.
- [Wiring guide](guide/wiring-guide.md) — `node-oidc-provider` integration patterns.

### I have a Relying Party and want to federate it

`oidfed` does not implement RP application logic; it federation-enables an RP you already operate.

- [`@oidfed/leaf` reference](packages/leaf.md) — Entity Configuration serving and OP discovery for the RP.
- [`@oidfed/oidc` reference](packages/oidc.md) — automatic / explicit client-registration flows the RP drives against an OP.

### I want to validate a trust chain or inspect any federation

- [`@oidfed/core` reference](packages/core.md) — entity-statement decoding, trust-chain resolution and validation, metadata policy.
- [`@oidfed/cli` reference](tools/cli.md) — `oidfed` command-line tool (e.g. `resolve`, `fetch`, `decode`, `verify`, `validate`, `sign`, `keygen`, `chain`, `list`, `list-extended`, `trust-mark-status`, `expiry`, `health`).
- [`explore.oidfed.com`](https://explore.oidfed.com) — browser-based federation explorer if you'd rather click than type.

### I want production storage or secrets-manager-backed keys

- [Storage guide](guide/storage-guide.md) — adapter interfaces and recipes for the subordinate, key, trust-mark, and JTI stores (PostgreSQL / MongoDB / Redis), plus the pattern for keeping private keys in a secrets manager (HashiCorp Vault, AWS KMS, Azure Key Vault) and referencing them by ID.

### I want to run a local multi-topology federation

- [Dev guide](guide/dev.md) — `pnpm dev:federation` with wildcard DNS and TLS.
- [E2E test infrastructure](test/e2e.md) — topology launcher, vhost dispatcher, declarative test beds.

### I want to read or visualize live federations

- [Explorer app](apps/explorer.md) — `explore.oidfed.com` and its source.
- [`@oidfed/ui`](internal/ui.md) — private shared component library backing the apps.

## Package dependency map

```
@oidfed/authority ─┐
@oidfed/leaf      ─┼─→ @oidfed/core
@oidfed/oidc      ─┘
@oidfed/cli       ──→ @oidfed/core
```

`authority`, `leaf`, and `oidc` are siblings at the dependency level: each depends only on `core`, never on each other. That isolation is about the dependency graph, not deployment — a single entity can compose any combination of these packages based on the federation roles it plays. An OP that federation-enables itself with `@oidfed/leaf` + `@oidfed/oidc` may also act as an RP against another OP using the same `@oidfed/oidc` registration flows; an Intermediate Authority running `@oidfed/authority` may also serve OIDC metadata for its own leaf-side participation; and so on. `@oidfed/core` is always present underneath whatever you compose.
