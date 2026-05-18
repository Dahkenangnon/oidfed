# @oidfed/explorer

A visual tool for exploring live OpenID Federation deployments — inspect entity configurations, trace trust chains, browse metadata, and validate federation topology in real time.

> **Status:** prerelease — API may change before the upcoming stable `1.0.0` release.

## Run locally

```bash
pnpm --filter @oidfed/explorer dev
```

Live deployment: [explore.oidfed.com](https://explore.oidfed.com).

## TODO

- **Prefer `federation_extended_list_endpoint` when the authority advertises it.** Today the explorer's Subordinate Listing (`src/features/subordinates/page.tsx`), Batch Health from Authority (`src/features/health/components/batch-health-from-authority-panel.tsx`), Topology graph (`src/features/topology/hooks/use-topology-graph.ts`), and Expiry scan (`src/features/expiry/hooks/use-expiry-scan.ts`) all consume `federation_list_endpoint`. When an authority publishes `federation_extended_list_endpoint`, the explorer should use the extended endpoint via `fetchExtendedSubordinatesList` from `@oidfed/core` to: (a) paginate via `from_entity_id` / `next_entity_id`, (b) fetch signed `subordinate_statement` JWTs in the same round-trip (eliminates the N+1 fetch pattern for large federations), (c) surface `registered` / `updated` audit timestamps in the UI, (d) filter by `updated_after` / `updated_before` for ops dashboards. Fall back to the base list endpoint when only `federation_list_endpoint` is advertised.
- **Add an explicit "Extended Listing" inspector panel** that exposes the `claims` parameter to power users — let them request `metadata`, `metadata_policy`, `constraints`, `trust_marks`, `jwks`, etc. per entity in a single call and render the response payload alongside the per-entity JSON tree.
- **Update `src/lib/probe-endpoint.ts`** to probe the extended endpoint and label authorities that advertise it (badge: "Extended Listing supported").
- **Topology graph performance**: for authorities with 1000+ subordinates, the topology and batch-health features should chunk discovery via the extended endpoint's cursor pagination rather than relying on the all-at-once base list response. Document the maxPageSize behaviour expected from a well-configured authority.
