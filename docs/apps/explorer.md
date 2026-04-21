# @oidfed/explorer

A visual tool for exploring live OpenID Federation deployments — inspect entity configurations, trace trust chains, browse metadata, and validate federation topology in real time.

## Role

Client-side SPA that connects directly from the browser to any federation endpoint — no backend required.

## Architecture

- **Framework**: React 19 + React Router (hash router for static deploy)
- **Build**: Vite → `dist/` (fully static, no SSR)
- **Runtime dependency**: `@oidfed/core` only

## Running Locally

```bash
# Dev server (hot reload)
pnpm --filter @oidfed/explorer dev
# → http://localhost:5173

# Type-check
pnpm --filter @oidfed/explorer typecheck

# Production build
pnpm --filter @oidfed/explorer build
# → apps/explorer/dist/  (static site)

# Preview production build locally
pnpm --filter @oidfed/explorer preview
```

To test against the local dev federation, start it first — see [`dev.md`](../guide/dev.md).

## Routes

| Path | Page |
|------|------|
| `/` | Home |
| `/entity[/:entityId]` | Entity Inspector |
| `/chain[/:entityId]` | Trust Chain Explorer |
| `/resolve` | Resolve Endpoint Proxy |
| `/topology` | Topology Graph |
| `/subordinates` | Subordinate Listing |
| `/expiry` | Expiration Dashboard |
| `/trust-marks` | Trust Mark Viewer |
| `/policy` | Policy Simulator |
| `/health` | Health Check |
| `/diff` | Metadata Diff |
| `/settings` | Settings |

## Configuration

Settings are persisted to `localStorage` under the key `oidfed_settings`. Managed via `/settings`:

| Setting | Description |
|---------|-------------|
| Trust anchors | List of TA entity IDs + optional JWKS (used by chain resolution and health checks) |
| HTTP timeout | Request timeout in milliseconds |
| Max chain depth | Maximum path length for trust chain resolution |
| Theme | `light`, `dark`, or `system` |
| Output format | `json` or `table` |
| Expiry thresholds | Warning/critical days before expiration (used by Expiration Dashboard) |

Settings can be exported to JSON and re-imported.

## Testing with the Dev Federation

Start the dev federation first — see [`dev.md`](../guide/dev.md) for setup.

### Settings — Trust Anchors

Add these TAs in **Settings → Trust Anchors** before testing chain-dependent features:

| Topology | Trust Anchor |
|----------|-------------|
| single-anchor | `https://ta-sa.ofed.test:8443` |
| hierarchical | `https://ta-hi.ofed.test:8443` |
| multi-anchor (gov) | `https://ta-gov-ma.ofed.test:8443` |
| multi-anchor (industry) | `https://ta-ind-ma.ofed.test:8443` |
| constrained | `https://ta-co.ofed.test:8443` |
| cross-federation (X) | `https://ta-x-xf.ofed.test:8443` |
| cross-federation (Y) | `https://ta-y-xf.ofed.test:8443` |
| policy-operators | `https://ta-po.ofed.test:8443` |

### Entity Inspector

- `https://ta-sa.ofed.test:8443` — all federation endpoints, trust marks, historical keys
- `https://op-sa.ofed.test:8443` — OP metadata with JWKS
- `https://ia-edu-hi.ofed.test:8443` — intermediate with metadata policy

### Trust Chain Explorer

Requires TAs in Settings.

- **Simple**: `https://op-sa.ofed.test:8443` → chain to `ta-sa`
- **Hierarchy**: `https://op-uni-hi.ofed.test:8443` → chain to `ta-hi` (3 levels)
- **Multi-chain**: `https://op-ma.ofed.test:8443` → chains to both `ta-gov-ma` and `ta-ind-ma`
- **Constraint violation**: `https://op-deep-co.ofed.test:8443` → invalid chain (see Constraints tab)
- **Policy diff**: `https://op-po.ofed.test:8443` → policy transformations (see Policy Diff tab)

### Resolve Endpoint Proxy

- Resolver: `https://ta-sa.ofed.test:8443`, Subject: `https://op-sa.ofed.test:8443`, TA: `https://ta-sa.ofed.test:8443`
- Multi-TA: Resolver: `https://ta-gov-ma.ofed.test:8443`, Subject: `https://op-ma.ofed.test:8443`, add both `ta-gov-ma` and `ta-ind-ma` as TAs

### Topology Graph

- **Simple**: `https://ta-sa.ofed.test:8443` (4 nodes)
- **Deep**: `https://ta-hi.ofed.test:8443` (7 nodes, 2 levels)
- **Multi-TA**: enter `https://ta-x-xf.ofed.test:8443`, add `https://ta-y-xf.ofed.test:8443` as additional TA

### Subordinate Listing

- `https://ta-sa.ofed.test:8443` — 3 subordinates (OP + 2 RPs)
- `https://ta-hi.ofed.test:8443` — 2 intermediates
- `https://ia-edu-hi.ofed.test:8443` — intermediate's own subordinates

### Expiration Dashboard

Requires TAs in Settings.

- `https://ta-hi.ofed.test:8443` — scans all subordinates' chain expiry

### Trust Mark Viewer

- **Fetch tab** — Issuer: `https://ta-sa.ofed.test:8443`, Type: `https://ta-sa.ofed.test:8443/trust-marks/certified`, Subject: `https://op-sa.ofed.test:8443`
- Also works with `ta-hi` topology

### Policy Simulator

- Standalone — no network needed
- Reference the policy-operators topology (`ia-po` policies) for realistic JSON

### Health Check

- **Single Entity**: `https://ta-sa.ofed.test:8443` — all endpoints pass
- **TA key comparison**: configure `ta-sa` in Settings with pinned JWKS, then probe it
- **Batch tab**: `https://ta-hi.ofed.test:8443` — fetches + health-checks all subordinates

### Metadata Diff

- Entity: `https://op-ma.ofed.test:8443`
- TA A: `https://ta-gov-ma.ofed.test:8443`
- TA B: `https://ta-ind-ma.ofed.test:8443`

## Known Issues

### Stale state after network errors

If the explorer shows an unexpected error, a blank result, or appears stuck after a network hiccup (e.g. dev server restart, DNS blip, or TLS handshake failure), **do a hard refresh** (`Ctrl+Shift+R` / `Cmd+Shift+R`) to clear any cached in-memory state.

This is the recommended first step whenever something looks wrong in the UI — most transient issues self-resolve after a refresh.
