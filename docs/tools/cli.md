# @oidfed/cli

Command-line interface for inspecting, validating, and debugging OpenID Federation deployments — resolve trust chains, decode entity statements, verify signatures, and more.

## Role

Command-line tool for operators and developers working with an OpenID Federation. Useful for inspecting entity configurations, resolving trust chains, verifying signatures, checking trust mark status, and diagnosing federation health — all from the terminal.

## Install

```bash
# Global
pnpm add -g @oidfed/cli

# Or run via workspace
pnpm oidfed <command>
```

## Global Options

```
    --json              Output raw JSON (machine-readable, suitable for piping to jq)
-q, --quiet             Suppress informational output
-v, --verbose           Enable debug output
-c, --config <path>     Path to config file
```

## Commands

### Discovery

| Command | Description |
|---------|-------------|
| `entity <entity-id>` | Fetch and display an entity configuration |
| `fetch <authority-id>` | Fetch a subordinate statement from an authority |
| `list <authority-id>` | List subordinate entities of an authority |
| `resolve <entity-id>` | Resolve and validate trust chains for an entity |

### Trust

| Command | Description |
|---------|-------------|
| `chain <entity-id>` | Resolve trust chains for an entity |
| `validate <jwt...>` | Validate a trust chain from a list of JWTs |
| `verify <jwt>` | Verify a JWT signature (resolves JWKS from `--entity-id`, `--jwks-file`, or JWT `iss`) |

### Trust Marks

| Command | Description |
|---------|-------------|
| `trust-mark-status <entity-id> --trust-mark <jwt>` | Check trust mark status |
| `trust-mark-list <entity-id> [--trust-mark-type <type>]` | List entities with a given trust mark type |

### Tooling

| Command | Description |
|---------|-------------|
| `decode <jwt>` | Decode a federation JWT without verification |
| `keygen [--alg <algorithm>]` | Generate a signing key pair (ES256, PS256, etc.) |
| `sign -p <file> -k <file>` | Sign a JSON payload as a JWT entity statement |

### Ops

| Command | Description |
|---------|-------------|
| `health <entity-id>` | Check health of federation endpoints for an entity |
| `expiry <entity-id>` | Show expiration details for an entity's trust chain |

## Configuration

Config file: `~/.oidfed/config.yaml` (auto-created on first use if missing).

```yaml
# Known trust anchors for chain resolution
trust_anchors:
  - entity_id: https://ta.example.org
    jwks:
      keys:
        - kty: EC
          crv: P-256
          x: "..."
          y: "..."

# HTTP settings
http_timeout_ms: 10000
max_chain_depth: 10
```

Override with `-c /path/to/config.yaml` or per-option flags.

## Examples

```bash
# Fetch an entity configuration
oidfed entity https://ta.example.org

# Resolve and validate a trust chain
oidfed resolve https://rp.example.com

# Build a trust chain with policy and constraints
oidfed chain https://rp.example.com --trust-anchor https://ta.example.org

# Verify a JWT signature (resolves JWKS from entity-id)
oidfed verify eyJ... --entity-id https://rp.example.com

# Check trust mark status
oidfed trust-mark-status https://ta.example.org --trust-mark eyJ...

# Machine-readable output piped to jq
oidfed entity https://ta.example.org --json | jq '.metadata'

# Generate a signing key
oidfed keygen --alg ES256

# Health check
oidfed health https://ta.example.org

# Check trust chain expiration
oidfed expiry https://rp.example.com --trust-anchor https://ta.example.org
```

## Command pattern

Each command exports `handler(args, deps) → Result<string>` and `register(program, deps)` — dependencies injected, commands independently testable.
