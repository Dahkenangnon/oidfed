# @oidfed/cli

<p align="center">
  <a href="https://www.npmjs.com/package/@oidfed/cli"><img alt="npm" src="https://img.shields.io/npm/v/@oidfed/cli.svg" /></a>
  <a href="https://www.npmjs.com/package/@oidfed/cli"><img alt="downloads" src="https://img.shields.io/npm/dm/@oidfed/cli.svg" /></a>
  <a href="https://github.com/Dahkenangnon/oidfed/blob/main/tools/cli/LICENSE"><img alt="license" src="https://img.shields.io/npm/l/@oidfed/cli.svg" /></a>
  <a href="https://nodejs.org"><img alt="Node" src="https://img.shields.io/node/v/@oidfed/cli" /></a>
</p>

<div align="center">
  <img src="https://raw.githubusercontent.com/Dahkenangnon/oidfed/main/internal/assets/cli.png" alt="@oidfed/cli banner" width="600" />
</div>

<p align="center">
  <a href="https://www.npmjs.com/package/@oidfed/core">@oidfed/core</a> &nbsp;•&nbsp;
  <a href="https://www.npmjs.com/package/@oidfed/authority">@oidfed/authority</a> &nbsp;•&nbsp;
  <a href="https://www.npmjs.com/package/@oidfed/leaf">@oidfed/leaf</a> &nbsp;•&nbsp;
  <a href="https://www.npmjs.com/package/@oidfed/oidc">@oidfed/oidc</a> &nbsp;•&nbsp;
  <b>@oidfed/cli</b>
</p>

Command-line interface for inspecting, validating, and debugging OpenID Federation deployments — resolve trust chains, decode entity statements, verify signatures, and more.

Implements command-line inspection and debugging utilities for the final [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) / [1.1](https://openid.net/specs/openid-federation-1_1.html) specifications, and [Extended Subordinate Listing 1.0](https://openid.net/specs/openid-federation-extended-listing-1_0.html) (tracks draft-02).

## Install

Requires Node.js ≥ 22 or Bun or Deno.

Choose the command for your preferred JavaScript package manager or runtime:

```bash
# npm (global install)
npm install -g @oidfed/cli

# pnpm (global install)
pnpm add -g @oidfed/cli

# yarn (global install)
yarn global add @oidfed/cli

# bun (global install)
bun add -g @oidfed/cli

# Deno (global install)
deno install --allow-read --allow-net --global npm:@oidfed/cli
```

Alternatively, run commands directly without installation:

```bash
# npx
npx @oidfed/cli --help

# bunx
bunx @oidfed/cli --help
```

Installs two equivalent binaries: `oidfed` and `openidfed`.

## Usage

You can try the following commands immediately against `@oidfed`'s live reference deployment ([fed.oidfed.com](https://fed.oidfed.com/)):

```bash
# Fetch an entity configuration
oidfed entity https://ta.single.fed.oidfed.com

# Resolve and validate a trust chain
oidfed chain https://rp1.single.fed.oidfed.com

# Verify a JWT signature
oidfed verify eyJ... --entity-id https://rp1.single.fed.oidfed.com

# Check trust mark status
oidfed trust-mark-status https://ta.single.fed.oidfed.com --trust-mark eyJ...

# Machine-readable output (decode the JWT first so `jq` sees the payload)
oidfed entity https://ta.single.fed.oidfed.com --decode --json | jq '.metadata'

# Generate a signing key
oidfed keygen --algorithm ES256

# Health check
oidfed health https://ta.single.fed.oidfed.com

# Page through a large federation with extended listing
oidfed list-extended https://ta.single.fed.oidfed.com \
  --limit 50 --audit-timestamps \
  --claims subordinate_statement --claims trust_marks
```

## Documentation

For a complete CLI command reference, configuration parameters, global flags, and debugging workflows, see the [docs/tools/cli.md](https://github.com/Dahkenangnon/oidfed/blob/main/docs/tools/cli.md) file.

## License

[Apache-2.0](./LICENSE) — see [`NOTICE`](./NOTICE) for attribution.
