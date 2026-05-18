# @oidfed/learn

An interactive course on OpenID Federation 1.0 — 15 lessons from first principles to federation topology design, with hands-on exercises and spec-accurate references.

> **Status:** prerelease — content may change before the upcoming stable `1.0.0` release.

## Run locally

```bash
pnpm --filter @oidfed/learn dev
```

Live deployment: [learn.oidfed.com](https://learn.oidfed.com).

## TODO

- **Cover the Extended Subordinate Listing 1.0 (draft-02) endpoint.** Lesson 08 currently teaches only the base `federation_list_endpoint`. Add a section (or a sibling lesson) that explains `/federation_extended_list`: cursor pagination (`from_entity_id` / `next_entity_id`), `limit` / `defaultPageSize` / `maxPageSize`, time-window filtering (`updated_after` / `updated_before`), audit timestamps (`registered` / `updated`), and the bulk `claims` parameter (with all 13 supported top-level Subordinate Statement claims). The library implements this end-to-end on branch `feat/extended-listing-draft-02` — see `oidfed/docs/packages/authority.md#extended-subordinate-listing`.
- **Add a "What changed in the ecosystem" addendum** referencing the active Federation-family extensions tracked in the root `README.md` Related Specifications table: Entity Collection 1.0 (draft 00), Wallet Architectures 1.0 (draft 05), ACME-with-Federation (IETF Internet-Draft). Each gets a one-paragraph "what it adds to the base spec" pointer.
- **Add a hands-on exercise** that paginates through a (mock) authority with the Extended Listing endpoint and verifies a signed `subordinate_statement` JWT pulled in the same response — exercises both the cursor and the bulk-retrieval intent of §1.2 of the spec.
