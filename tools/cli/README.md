# @oidfed/cli

[![npm](https://img.shields.io/npm/v/@oidfed/cli.svg)](https://www.npmjs.com/package/@oidfed/cli)
[![downloads](https://img.shields.io/npm/dm/@oidfed/cli.svg)](https://www.npmjs.com/package/@oidfed/cli)
[![license](https://img.shields.io/npm/l/@oidfed/cli.svg)](https://github.com/Dahkenangnon/oidfed/blob/main/tools/cli/LICENSE)
[![Node](https://img.shields.io/node/v/@oidfed/cli)](https://nodejs.org)

Command-line interface for inspecting, validating, and debugging [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html) deployments — resolve trust chains, decode entity statements, verify signatures, and more.

> **Status:** prerelease — API may change before the upcoming stable `1.0.0` release.

## Install

Requires Node.js ≥ 22.

```bash
npm install -g @oidfed/cli
```

Installs two equivalent binaries: `oidfed` and `openidfed`.

## Usage

```bash
# Fetch an entity configuration
oidfed entity https://ta.example.org

# Resolve and validate a trust chain
oidfed chain https://rp.example.com

# Verify a JWT signature
oidfed verify eyJ... --entity-id https://rp.example.com

# Check trust mark status
oidfed trust-mark-status https://ta.example.org --trust-mark eyJ...

# Machine-readable output (decode the JWT first so `jq` sees the payload)
oidfed entity https://ta.example.org --decode --json | jq '.metadata'

# Generate a signing key
oidfed keygen --algorithm ES256

# Health check
oidfed health https://ta.example.org

# Page through a large federation with extended listing
oidfed list-extended https://ta.example.org \
  --limit 50 --audit-timestamps \
  --claims subordinate_statement --claims trust_marks
```

## Commands

| Command | Description |
|---------|-------------|
| `entity <entity-id>` | Fetch and display an entity configuration |
| `fetch --issuer <url> --subject <url>` | Fetch a subordinate statement from an authority |
| `list <entity-id>` | List subordinate entities |
| `list-extended <entity-id>` | Paginated subordinate listing with audit timestamps and bulk claim retrieval |
| `resolve <entity-id>` | Resolve trust chains for an entity |
| `chain <entity-id>` | Resolve and validate trust chains for an entity |
| `validate <jwt-or-entity-id...>` | Validate a trust chain from JWTs or by resolving an entity ID |
| `verify <jwt>` | Verify a JWT signature |
| `trust-mark-status <entity-id>` | Check trust mark status at its issuer |
| `trust-mark-list <entity-id> --trust-mark-type <id>` | List entities holding an active Trust Mark of the given type |
| `decode <jwt>` | Decode a JWT without verification |
| `keygen` | Generate a signing key pair |
| `sign` | Sign a JSON payload as a JWT |
| `health <entity-id>` | Check federation endpoint health |
| `expiry <jwt-or-entity-id>` | Show expiration details for a JWT or entity trust chain |

## Global flags

Apply to every command:

| Flag | Description |
|------|-------------|
| `--json` | Output raw JSON (machine-readable, suitable for piping to `jq`) |
| `-c, --config <path>` | Path to a config file (overrides default discovery) |
| `-q, --quiet` | Suppress informational output |
| `-v, --verbose` | Enable debug output |

## Configuration

Config file: `~/.oidfed/config.yaml` (override with `--config <path>` or the `OIDFED_CONFIG_PATH` environment variable).

```yaml
trust_anchors:
  - entity_id: https://ta.example.org
    jwks:
      keys:
        - kty: EC
          crv: P-256
          x: "..."
          y: "..."

http_timeout_ms: 10000
max_chain_depth: 10
```

## Documentation

Full reference: [docs/tools/cli.md](https://github.com/Dahkenangnon/oidfed/blob/main/docs/tools/cli.md)

## Part of @oidfed

| Package | Role |
|---------|------|
| [@oidfed/core](https://www.npmjs.com/package/@oidfed/core) | Federation primitives |
| [@oidfed/authority](https://www.npmjs.com/package/@oidfed/authority) | Trust Anchor & Intermediate operations |
| [@oidfed/leaf](https://www.npmjs.com/package/@oidfed/leaf) | Leaf Entity toolkit |
| [@oidfed/oidc](https://www.npmjs.com/package/@oidfed/oidc) | OIDC/OAuth 2.0 federation flows |
| **@oidfed/cli** | CLI for federation debugging (this package) |

## License

[Apache-2.0](./LICENSE) — see [`NOTICE`](./NOTICE) for attribution.
