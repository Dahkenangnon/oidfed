# @oidfed/cli

<p align="center">
  <a href="https://www.npmjs.com/package/@oidfed/cli"><img alt="npm" src="https://img.shields.io/npm/v/@oidfed/cli.svg" /></a>
  <a href="https://www.npmjs.com/package/@oidfed/cli"><img alt="downloads" src="https://img.shields.io/npm/dm/@oidfed/cli.svg" /></a>
  <a href="https://github.com/Dahkenangnon/oidfed/blob/main/tools/cli/LICENSE"><img alt="license" src="https://img.shields.io/npm/l/@oidfed/cli.svg" /></a>
  <a href="https://nodejs.org"><img alt="Node" src="https://img.shields.io/node/v/@oidfed/cli" /></a>
</p>

Inspect Entity Configurations, find and validate trust chains, verify signatures, and check federation endpoints from the terminal. The CLI declares Node.js `>=22.12.0`; development in this repository requires `>=22.22.0`.

## Install

```bash
# Global
pnpm add -g @oidfed/cli

# From a built checkout, with normal TLS verification:
node tools/cli/dist/bin.js <command>
```

The workspace shortcuts `pnpm oidfed` and `pnpm cli` disable TLS certificate verification through `NODE_TLS_REJECT_UNAUTHORIZED=0`. They are local test helpers. Use the installed `oidfed` command or the direct Node invocation above when inspecting remote deployments. To trust the local test CA without disabling verification, set `NODE_EXTRA_CA_CERTS` as described in the [development guide](../guide/dev.md#tls-trust).

## Global options

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
| `fetch --issuer <url> --subject <url>` | Fetch a subordinate statement from an authority |
| `list <entity-id>` | List subordinate entities of an authority |
| `list-extended <entity-id>` | Paginated subordinate listing with audit timestamps and bulk claim retrieval (`/federation_extended_list`) |
| `resolve <entity-id>` | Resolve trust chains for an entity |

### Trust

| Command | Description |
|---------|-------------|
| `chain <entity-id>` | Resolve and validate trust chains for an entity |
| `validate <jwt-or-entity-id...>` | Validate a trust chain from JWTs or by resolving an entity ID |
| `verify <jwt>` | Verify a JWT signature (resolves JWKS from `--entity-id`, `--jwks-file`, or JWT `iss`) |

### Trust marks

| Command | Description |
|---------|-------------|
| `trust-mark-status <entity-id> --trust-mark <jwt>` | Check trust mark status at its issuer |
| `trust-mark-list <entity-id> --trust-mark-type <id>` | List entities holding an active Trust Mark of the given type (`--trust-mark-type` is required) |

### Tooling

| Command | Description |
|---------|-------------|
| `decode <jwt>` | Decode a federation JWT without verification |
| `keygen [-a, --algorithm <alg>]` | Generate a signing key pair (default `ES256`; also supports the other algorithms in `SUPPORTED_ALGORITHMS`) |
| `sign -p <file> -k <file>` | Sign a JSON payload as a JWT entity statement |

### Ops

| Command | Description |
|---------|-------------|
| `health <entity-id>` | Check health of federation endpoints for an entity |
| `expiry <jwt-or-entity-id>` | Show expiration details for a JWT or entity trust chain |

## Configuration

The default path is `~/.oidfed/config.yaml`. A missing file uses defaults and is not created automatically. Create it when you need saved trust anchors or HTTP settings. The abbreviated JWK below is a placeholder; replace it with the anchor's public key obtained through your trusted configuration process.

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

Configuration path precedence is `-c /path/to/config.yaml`, then `OIDFED_CONFIG_PATH`, then the default path. Command-specific flags such as `--trust-anchor` override the corresponding saved value where supported.

## Examples

```bash
# Fetch an entity configuration
oidfed entity https://ta.example.org

# Page through subordinates of a large TA, embedding signed subordinate statements
oidfed list-extended https://ta.example.org \
  --limit 50 \
  --audit-timestamps \
  --claims subordinate_statement --claims trust_marks

# Resume from a cursor returned by the previous page
oidfed list-extended https://ta.example.org \
  --from https://leaf-100.example.org --limit 50

# Filter to entities updated in a time window
oidfed list-extended https://ta.example.org \
  --updated-after 1700000000 --updated-before 1700604800

# Find candidate trust chains
oidfed resolve https://rp.example.com

# Build a trust chain with policy and constraints
oidfed chain https://rp.example.com --trust-anchor https://ta.example.org

# Verify a JWT signature (resolves JWKS from entity-id)
oidfed verify eyJ... --entity-id https://rp.example.com

# Check trust mark status
oidfed trust-mark-status https://ta.example.org --trust-mark eyJ...

# Machine-readable output piped to jq (decode first so jq sees the payload)
oidfed entity https://ta.example.org --decode --json | jq '.metadata'

# Generate a signing key
oidfed keygen --algorithm ES256

# Health check
oidfed health https://ta.example.org

# Check trust chain expiration
oidfed expiry https://rp.example.com --trust-anchor https://ta.example.org
```

`decode` inspects a token without verifying it. `verify` checks a signature against the selected keys; discovering those keys from the JWT issuer does not establish trust in that issuer. Use `chain` or `validate` with trusted anchors for federation trust validation.

## Command pattern

Commands expose an asynchronous `handler(args, deps)` returning `Promise<Result<string>>` and a `register(program, deps)` function. Injected dependencies let tests run command handlers without network access.
