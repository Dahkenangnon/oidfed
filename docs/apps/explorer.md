# @oidfed/explorer

Inspect Entity Configurations, trust chains, metadata policies, trust marks, and subordinate listings in the browser. The explorer is a static client-side app: requests go directly to federation endpoints, which must allow browser access through CORS. The browser must also trust their TLS certificates.

## Running locally

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

To test against the local dev federation, start it first; see [`dev.md`](../guide/dev.md).

## Routes

The app uses hash routing. The paths below follow `/#` in a browser URL, for example `https://explore.oidfed.com/#/entity`. Encode an Entity Identifier when placing it in a path segment.

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

Settings are stored in `localStorage` under `oidfed-explorer-settings`. Most fields are edited at `/#/settings`; expiry thresholds are edited on the dashboard:

| Setting | Description |
|---------|-------------|
| Trust anchors | List of TA entity IDs + optional JWKS (used by chain resolution and health checks) |
| HTTP timeout | Request timeout in milliseconds |
| Max chain depth | Maximum path length for trust chain resolution |
| Theme | `light`, `dark`, or `system` |
| JSON indentation | Number of spaces used in JSON output |
| Expiry thresholds | Critical, warning, and soon thresholds in days; edited in the Expiration Dashboard |

Settings can be exported to JSON and re-imported. Importing a settings file replaces the current settings. The settings URL import preview can add trust anchors without replacing the other fields.

## Testing with the dev federation

Start the dev federation first; see [`dev.md`](../guide/dev.md) for setup.

### Configure trust anchors

Add the anchors you need in Settings → Trust Anchors before using chain-dependent views. Pin each anchor's federation JWKS when you need to verify against a trusted key rather than learn keys from the endpoint.

| Topology | Trust Anchor |
|---|---|
| single-anchor | `https://ta-sa.ofed.test:8443` |
| hierarchical | `https://ta-hi.ofed.test:8443` |
| multi-anchor | `https://ta-gov-ma.ofed.test:8443`, `https://ta-ind-ma.ofed.test:8443` |
| constrained | `https://ta-co.ofed.test:8443` |
| cross-federation | `https://ta-x-xf.ofed.test:8443`, `https://ta-y-xf.ofed.test:8443` |
| policy-operators | `https://ta-po.ofed.test:8443` |

### Try each view

All identifiers below use `https://<host>.ofed.test:8443`.

| View | Input | What to inspect |
|---|---|---|
| Entity Inspector | `ta-sa`, `op-sa`, or `ia-edu-hi` | Advertised federation endpoints, OP protocol keys, or Intermediate metadata |
| Trust Chain Explorer | `op-sa` | Direct chain to `ta-sa` |
| Trust Chain Explorer | `op-uni-hi` | Path through the education Intermediate to `ta-hi` |
| Trust Chain Explorer | `op-ma` | Alternative paths to the government and industry TAs |
| Trust Chain Explorer | `op-deep-co` | Expected constraint failure under `max_path_length=0` |
| Trust Chain Explorer | `op-po` | Changes in the Policy Diff view |
| Resolve Endpoint Proxy | Resolver `ta-sa`, subject `op-sa`, anchor `ta-sa` | The authority's signed resolve response |
| Resolve Endpoint Proxy | Resolver `ta-gov-ma`, subject `op-ma`, both multi-anchor TAs | Resolution with multiple configured anchors |
| Topology Graph | `ta-sa` or `ta-hi` | Four-node or seven-node hierarchy |
| Topology Graph | `ta-x-xf` with `ta-y-xf` as an additional TA | The two federation structures and bridge |
| Subordinate Listing | `ta-sa` | Three immediate subordinates: one OP and two RPs |
| Subordinate Listing | `ta-hi` or `ia-edu-hi` | The TA's two Intermediates or an Intermediate's immediate subordinates |
| Expiration Dashboard | `ta-hi` | Candidate-chain expiry for its immediate subordinates; this is not a recursive federation scan or a full validation report |
| Health Check | `ta-sa` | Responses from its advertised endpoints; add pinned JWKS in Settings to compare TA keys |
| Health Check, Batch | `ta-hi` | Fetch and probe immediate subordinates |
| Metadata Diff | Entity `op-ma`, anchors `ta-gov-ma` and `ta-ind-ma` | Metadata resolved under each TA |

In Trust Mark Viewer, use issuer `https://ta-sa.ofed.test:8443`, type `https://ta-sa.ofed.test:8443/trust-marks/certified`, and subject `https://op-sa.ofed.test:8443`. The hierarchical topology also issues trust marks.

Policy Simulator accepts local JSON without network access. For an example, use the policy attached to `op-po` in the dev server, which is issued by `ia-po`.

## Troubleshooting

### Recovering after network errors

If the explorer shows an unexpected error, a blank result, or appears stuck after a network hiccup (e.g. dev server restart, DNS blip, or TLS handshake failure), reload the page (`Ctrl+Shift+R` / `Cmd+Shift+R`) to clear any cached in-memory state.

If the request still fails after reloading, check the endpoint URL, CORS response, DNS resolution, and TLS trust. Reloading does not repair those errors.
