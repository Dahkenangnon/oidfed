# @oidfed/cli

Command-line interface for inspecting, validating, and debugging [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html) deployments — resolve trust chains, decode entity statements, verify signatures, and more.

> **Status:** `v0.2.0` pre-release — API may change before the first stable `1.0` release.

## Install

```bash
npm install -g @oidfed/cli
```

## Usage

```bash
# Fetch an entity configuration
oidfed entity https://ta.example.org

# Resolve and validate a trust chain
oidfed resolve https://rp.example.com

# Verify a JWT signature
oidfed verify eyJ... --entity-id https://rp.example.com

# Check trust mark status
oidfed trust-mark-status https://ta.example.org --trust-mark eyJ...

# Machine-readable output
oidfed entity https://ta.example.org --json | jq '.metadata'

# Generate a signing key
oidfed keygen --alg ES256

# Health check
oidfed health https://ta.example.org
```

## Commands

| Command | Description |
|---------|-------------|
| `entity <id>` | Fetch and display an entity configuration |
| `fetch <id>` | Fetch a subordinate statement |
| `list <id>` | List subordinate entities |
| `resolve <id>` | Resolve and validate trust chains |
| `chain <id>` | Resolve trust chains |
| `validate <jwt...>` | Validate a trust chain from JWTs |
| `verify <jwt>` | Verify a JWT signature |
| `trust-mark-status` | Check trust mark status |
| `trust-mark-list` | List entities with a trust mark |
| `decode <jwt>` | Decode a JWT without verification |
| `keygen` | Generate a signing key pair |
| `sign` | Sign a JSON payload as a JWT |
| `health <id>` | Check federation endpoint health |
| `expiry <id>` | Show trust chain expiration details |

## Configuration

Config file: `~/.oidfed/config.yaml`

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
