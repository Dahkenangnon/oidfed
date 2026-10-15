# Local development

Use Node.js `>=22.22.0` and the repository's pinned pnpm `10.33.0`. Corepack can select that version from `package.json`.

```bash
corepack pnpm install --frozen-lockfile
pnpm build
pnpm release:verify
```

`release:verify` builds the published packages and CLI, runs lint and type checks, executes the Node TAP suite and CLI/script tests, and checks package contents and the shared core dependency. `pnpm test` additionally runs the TAP suite across the configured runtimes; those runners need their own prerequisites. Application checks are separate: `pnpm typecheck:apps`, `pnpm test:apps`, and `pnpm build:apps`.

## Run the local federation

Install [mkcert](https://github.com/FiloSottile/mkcert#installation), then run:

```bash
pnpm build
pnpm setup:e2e
pnpm dev:federation
# Custom port:
pnpm dev:federation -- --port 9443
```

`setup:e2e` installs a local development CA and creates the certificate/key files in the ignored `.certs/` directory. It skips generation when both server files already exist. Keep the server certificate and `.certs/ca-path.txt` matched to the same CA.

The server starts six topologies on port `8443`. Its Node HTTP client resolves test hosts internally. Browser access also needs system DNS or hosts-file entries and trust in the local CA.

## Browser DNS

`/etc/hosts` does not support wildcards. For a small test, add only the hosts you need, for example:

```text
127.0.0.1 ta-sa.ofed.test op-sa.ofed.test rp-sa.ofed.test rp2-sa.ofed.test
```

For all topologies, use the hostnames in the tables below or configure a local DNS resolver to map `*.ofed.test` to `127.0.0.1`. On systems using dnsmasq alongside systemd-resolved, bind dnsmasq to an unused loopback address and route only `ofed.test` queries to it. The exact service configuration depends on the host's NetworkManager/resolver setup.

On Linux, verify the system resolver before opening the browser:

```bash
getent hosts ta-sa.ofed.test
```

It should return `127.0.0.1`. Investigate resolver timeouts or conflicting services rather than assuming a successful `dig` retry means the setup is healthy.

## TLS trust

`dev:federation` and `test:e2e` set `NODE_EXTRA_CA_CERTS` to the CA file recorded by setup:

```bash
NODE_EXTRA_CA_CERTS=$(cat .certs/ca-path.txt)/rootCA.pem
```

The variable must name the PEM file, not its directory. Browser trust is separate: `mkcert -install` installs the development CA into supported local trust stores. Restart the browser after installing it; Firefox may require its own certificate import.

If Node reports an issuer or certificate verification error, check the existing server certificate against the recorded CA:

```bash
openssl verify -CAfile "$(cat .certs/ca-path.txt)/rootCA.pem" .certs/ofed.pem
```

If they do not match, preserve any needed existing certificates, move the old `.certs/` directory aside, and rerun setup. Setup will not repair an existing pair automatically.

## Dev federation topologies

The dev server defines these topologies in [`scripts/dev-federation.ts`](../../scripts/dev-federation.ts). The [E2E tests](../test/e2e.md) use separate topology definitions with the same six names; their hostnames and fixtures differ.

Each topology has its own hostname prefix. The tables use the default port, `8443`.

### 1. single-anchor

Minimal topology: one TA, one OP, two RPs.

| Role | Entity ID |
|------|-----------|
| Trust anchor | `https://ta-sa.ofed.test:8443` |
| OP (leaf) | `https://op-sa.ofed.test:8443` |
| RP automatic (leaf) | `https://rp-sa.ofed.test:8443` |
| RP explicit (leaf) | `https://rp2-sa.ofed.test:8443` |

### 2. hierarchical

Two-level hierarchy: TA → 2 intermediate authorities (edu, health) → OPs + RPs.

| Role | Entity ID |
|------|-----------|
| Trust anchor | `https://ta-hi.ofed.test:8443` |
| Intermediate (edu) | `https://ia-edu-hi.ofed.test:8443` |
| Intermediate (health) | `https://ia-health-hi.ofed.test:8443` |
| OP (uni, via edu) | `https://op-uni-hi.ofed.test:8443` |
| OP (hospital, via health) | `https://op-hosp-hi.ofed.test:8443` |
| RP (via edu) | `https://rp1-hi.ofed.test:8443` |
| RP explicit (via health) | `https://rp2-hi.ofed.test:8443` |

### 3. multi-anchor

Two TAs (gov, industry) sharing one intermediate authority.

| Role | Entity ID |
|------|-----------|
| Trust anchor (gov) | `https://ta-gov-ma.ofed.test:8443` |
| Trust anchor (industry) | `https://ta-ind-ma.ofed.test:8443` |
| Intermediate (shared) | `https://ia-shared-ma.ofed.test:8443` |
| OP | `https://op-ma.ofed.test:8443` |
| RP automatic | `https://rp1-ma.ofed.test:8443` |
| RP explicit | `https://rp2-ma.ofed.test:8443` |

### 4. constrained

TA with `max_path_length=0`. `op-direct-co` resolves successfully; `op-deep-co` (via intermediate) intentionally fails.

| Role | Entity ID |
|------|-----------|
| Trust anchor | `https://ta-co.ofed.test:8443` |
| OP direct (valid chain) | `https://op-direct-co.ofed.test:8443` |
| Intermediate | `https://ia-deep-co.ofed.test:8443` |
| OP deep (invalid chain) | `https://op-deep-co.ofed.test:8443` |

### 5. cross-federation

Two separate federations (X and Y) linked by a bridge intermediate.

| Role | Entity ID |
|------|-----------|
| Trust anchor X | `https://ta-x-xf.ofed.test:8443` |
| Trust anchor Y | `https://ta-y-xf.ofed.test:8443` |
| Intermediate X | `https://ia-x-xf.ofed.test:8443` |
| Intermediate Y | `https://ia-y-xf.ofed.test:8443` |
| RP X | `https://rp-x-xf.ofed.test:8443` |
| RP Y | `https://rp-y-xf.ofed.test:8443` |
| Bridge (intermediate) | `https://bridge-xf.ofed.test:8443` |
| OP (fed X) | `https://op-x-xf.ofed.test:8443` |
| OP (fed Y) | `https://op-y-xf.ofed.test:8443` |

### 6. policy-operators

Demonstrates three §9.2 metadata policy operators: `subset_of`, `value`, and `add`. The policy is attached to the statement about `op-po`, issued by `ia-po`.

| Role | Entity ID |
|------|-----------|
| Trust anchor | `https://ta-po.ofed.test:8443` |
| Intermediate | `https://ia-po.ofed.test:8443` |
| OP | `https://op-po.ofed.test:8443` |
| RP | `https://rp-po.ofed.test:8443` |
