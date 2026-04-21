# Local Development

Setup guide for running the full federation stack locally, including wildcard DNS, TLS certificates, and the dev federation server.

## Wildcard DNS for `*.ofed.test` (Ubuntu 24)

`/etc/hosts` does not support wildcards. Use **dnsmasq** alongside `systemd-resolved`:

```bash
# 1. Ensure NetworkManager uses systemd-resolved (not its own dnsmasq)
sudo sed -i 's/dns=dnsmasq/dns=systemd-resolved/' /etc/NetworkManager/NetworkManager.conf

# 2. Install standalone dnsmasq
sudo apt install dnsmasq

# 3. Configure dnsmasq on 127.0.0.2 (avoids conflict with resolved on 127.0.0.53)
sudo tee /etc/dnsmasq.d/ofed.conf <<EOF
listen-address=127.0.0.2
bind-interfaces
address=/.ofed.test/127.0.0.1
EOF

# 4. Enable dnsmasq
sudo systemctl enable --now dnsmasq

# 5. Tell systemd-resolved to forward .ofed.test queries to dnsmasq
sudo mkdir -p /etc/systemd/resolved.conf.d
sudo tee /etc/systemd/resolved.conf.d/ofed.conf <<EOF
[Resolve]
DNS=127.0.0.2
Domains=~ofed.test
EOF

# 6. Restart everything
sudo systemctl restart dnsmasq systemd-resolved NetworkManager

# 7. Verify
getent hosts ta-sa.ofed.test   # → 127.0.0.1
```

> `dig` may show spurious `communications error` lines before returning `127.0.0.1` — this is harmless; the system resolver works correctly.

## TLS Certificates and Node.js Trust

`pnpm setup:e2e` generates TLS certs via mkcert. For Node.js to trust them (required for server-side trust chain resolution inside the dev server), `NODE_EXTRA_CA_CERTS` must point to the mkcert **root CA file** — not the directory. The `dev:federation` and `test:e2e` scripts handle this automatically:

```bash
# Already embedded in pnpm dev:federation — shown here for reference
NODE_EXTRA_CA_CERTS=$(cat .certs/ca-path.txt)/rootCA.pem
```

> **Common mistake:** setting `NODE_EXTRA_CA_CERTS` to the directory path (e.g. `~/.local/share/mkcert`) is silently ignored by Node.js. The path must end in `/rootCA.pem`.

To trust the cert in your browser (required for the explorer UI):

```bash
mkcert -install   # installs mkcert CA into the system/browser trust stores
```

## Starting the Dev Federation

```bash
pnpm build
pnpm setup:e2e               # generate TLS certs (once)
pnpm dev:federation          # starts all 6 topologies on port 8443
```

All `*.ofed.test` hostnames resolve automatically once the wildcard DNS is configured above.

## Dev Federation Topologies

These topologies are also used by the E2E test infrastructure — see [e2e.md](../test/e2e.md).

The dev server launches 6 topologies on port **8443**. Each topology is isolated by hostname prefix.

### 1. single-anchor — `ta-sa` / `op-sa` / `rp-sa` / `rp2-sa`

Minimal topology: one TA, one OP, two RPs.

| Role | Entity ID |
|------|-----------|
| Trust anchor | `https://ta-sa.ofed.test:8443` |
| OP (leaf) | `https://op-sa.ofed.test:8443` |
| RP automatic (leaf) | `https://rp-sa.ofed.test:8443` |
| RP explicit (leaf) | `https://rp2-sa.ofed.test:8443` |

### 2. hierarchical — `ta-hi` / `ia-edu-hi` / `ia-health-hi` / …

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

### 3. multi-anchor — `ta-gov-ma` / `ta-ind-ma` / `ia-shared-ma` / …

Two TAs (gov, industry) sharing one intermediate authority.

| Role | Entity ID |
|------|-----------|
| Trust anchor (gov) | `https://ta-gov-ma.ofed.test:8443` |
| Trust anchor (industry) | `https://ta-ind-ma.ofed.test:8443` |
| Intermediate (shared) | `https://ia-shared-ma.ofed.test:8443` |
| OP | `https://op-ma.ofed.test:8443` |
| RP automatic | `https://rp1-ma.ofed.test:8443` |
| RP explicit | `https://rp2-ma.ofed.test:8443` |

### 4. constrained — `ta-co` / `op-direct-co` / `ia-deep-co` / `op-deep-co`

TA with `max_path_length=0`. `op-direct-co` resolves successfully; `op-deep-co` (via intermediate) intentionally fails.

| Role | Entity ID |
|------|-----------|
| Trust anchor | `https://ta-co.ofed.test:8443` |
| OP direct (valid chain) | `https://op-direct-co.ofed.test:8443` |
| Intermediate | `https://ia-deep-co.ofed.test:8443` |
| OP deep (invalid chain) | `https://op-deep-co.ofed.test:8443` |

### 5. cross-federation — `ta-x-xf` / `ta-y-xf` / `bridge-xf` / …

Two separate federations (X and Y) linked by a bridge intermediate.

| Role | Entity ID |
|------|-----------|
| Trust anchor X | `https://ta-x-xf.ofed.test:8443` |
| Trust anchor Y | `https://ta-y-xf.ofed.test:8443` |
| Bridge (intermediate) | `https://bridge-xf.ofed.test:8443` |
| OP (fed X) | `https://op-x-xf.ofed.test:8443` |
| OP (fed Y) | `https://op-y-xf.ofed.test:8443` |

### 6. policy-operators — `ta-po` / `ia-po` / `op-po` / `rp-po`

Demonstrates all §9.2 metadata policy operators (`subset_of`, `value`, `add`).

| Role | Entity ID |
|------|-----------|
| Trust anchor | `https://ta-po.ofed.test:8443` |
| Intermediate | `https://ia-po.ofed.test:8443` |
| OP | `https://op-po.ofed.test:8443` |
| RP | `https://rp-po.ofed.test:8443` |
