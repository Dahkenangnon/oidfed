# Local development

Use the Node range and pnpm version in the root `package.json`.

```sh
corepack pnpm install --frozen-lockfile
pnpm build
pnpm release:verify
```

`release:verify` checks the publishable packages. Run
[package security checks](security-checks.md) separately. For app changes, use
`pnpm build:apps`, `pnpm typecheck:apps`, and `pnpm test:apps`.

Mark standalone TypeScript fences in `docs/api/` or `docs/features/` with
`<!-- oidfed-example -->`. To compile them against the packed packages, run
`node scripts/check-crypto-isolation.mjs` after `pnpm build:publish`.

## Storage checks

```sh
pnpm typecheck:contracts
pnpm test:storage:memory
pnpm test:storage:adapters
```

The adapter suite requires Docker. Its PostgreSQL job must pass on the release commit.

## Run the local federation

Install [mkcert](https://github.com/FiloSottile/mkcert#installation), then run:

```sh
pnpm build
pnpm setup:e2e
pnpm dev:federation
```

The server prints the URLs for its six [topologies](../../scripts/dev-federation.ts).
It uses port `8443` by default. Pass `-- --port 9443` to change it.

For browser tests, map the required `*.ofed.test` names to `127.0.0.1` using
local DNS or add each hostname to your hosts file. On Linux, use
`getent hosts ta-sa.ofed.test` to check what the browser’s system resolver sees.

## TLS trust

Trust the development CA in the browser using `mkcert -install`. For a direct
Node command, set `NODE_EXTRA_CA_CERTS` to the CA’s PEM file.

```sh
export NODE_EXTRA_CA_CERTS="$(cat .certs/ca-path.txt)/rootCA.pem"
openssl verify -CAfile "$NODE_EXTRA_CA_CERTS" .certs/ofed.pem
```

If the server certificate and CA differ, move `.certs/` aside and rerun
`pnpm setup:e2e`. Setup reuses the certificate and key when both are present.
