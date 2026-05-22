# Changelog

All notable changes to `@oidfed/authority` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **BREAKING (install-tree).** `@oidfed/core` moved from `dependencies` to `peerDependencies`. Consumers MUST install `@oidfed/core` alongside `@oidfed/authority`. The peer range is `^0.4.0`. This guarantees a single resolved `@oidfed/core` when `@oidfed/authority` is installed beside its siblings; the previous model could install two side-by-side copies and silently break module identity.

## [0.4.0] - 2026-05-18

### Added

- New `/federation_extended_list` endpoint implementing the OpenID Federation Extended Subordinate Listing 1.0 (draft-02) specification: cursor pagination (`from_entity_id` / `next_entity_id`), `limit` with `defaultPageSize` / `maxPageSize` clamps, time-window filtering (`updated_after`, `updated_before`), audit timestamps (`registered`, `updated`), and bulk per-entity claim retrieval. Inherits all base `/federation_list` filters.
- Per-entity claim extractor coverage for the full top-level Subordinate Statement claim set: per-record extractors for `jwks`, `metadata`, `metadata_policy`, `constraints`, `crit`, `metadata_policy_crit`, `source_endpoint`, `trust_marks`; synthetic extractors for `iss`, `sub`, `iat`, `exp`, `subordinate_statement`. Synthetic `iat`/`exp` are snapshot once per request and aligned with the embedded JWT.
- Default substitution: when the client does NOT send the `claims` parameter at all, the configured `defaultClaims` (default `["subordinate_statement"]`) is used. If the client sends `claims=` (even with no value), no substitution happens — the user-supplied set wins and the `subordinate_statement` MUST-NOT rule is honoured.
- Wire-format flexibility for `claims`: handler accepts both comma-separated (`?claims=a,b`) and repeated-parameter (`?claims=a&claims=b`) forms.
- Auto-include of `registered`/`updated` when `updated_after`/`updated_before` is used without an explicit `audit_timestamps` value (explicit `false` still suppresses).
- New `SubordinateRecord` optional fields: `crit?: ReadonlyArray<string>`, `metadataPolicyCrit?: ReadonlyArray<string>`. `buildSubordinateStatement` emits them in the signed JWT when present.
- New `createExtendedListHandler(ctx, config?)` and `ExtendedListingConfig` (`enabled`, `defaultPageSize`, `maxPageSize`, `supportTimeFilters`, `supportAuditTimestamps`, `defaultClaims`, `maxStorePagesPerRequest`, `storeBatchSize`).
- New `EXTENDED_LIST_CLAIM_EXTRACTORS` map and `extractClaims(record, ctx, claims, now)` helper for plugging in custom per-claim extractors.
- New `AuthorityServer.listSubordinatesExtended(params?)` in-process API returning `Promise<Result<ExtendedListInProcessResult, FederationError>>`; types `ExtendedListInProcessParams` and `ExtendedListInProcessResult`.
- New OPTIONAL `TrustMarkStore.listForSubject(subject)` method used by `/federation_extended_list` when `claims=trust_marks` is requested. `MemoryTrustMarkStore` ships the implementation; deployments whose store cannot enumerate-by-subject receive `400 unsupported_parameter`.
- `AuthorityConfig.extendedListing?: ExtendedListingConfig` to configure the new endpoint.
- Page-fill loop: when post-filters reduce a store page below the requested limit, the handler continues fetching from the store (bounded by `maxStorePagesPerRequest`) until either the page is full or the store is exhausted. `next_entity_id` skips known non-matches in the current page so clients don't iterate through empty pages.
- `MemorySubordinateStore` now accepts an optional `clock` in its constructor; `update()` writes `updatedAt` as a NumericDate (seconds since the epoch).

### Changed

- **BREAKING:** `SubordinateStore.list(filter)` signature changed from `Promise<SubordinateRecord[]>` to `list(filter?, options?): Promise<ListPage>` where `ListPage = { items: SubordinateRecord[]; nextCursor?: EntityId }` and `ListPageOptions = { cursor?, limit?, updatedAfter?, updatedBefore? }`. Records MUST be returned in deterministic lexicographic order by `entityId`. The bundled `MemorySubordinateStore` is migrated. Custom store implementations need to adopt the new shape. Observable behaviour of the base `/federation_list` endpoint is unchanged — it still returns the same flat JSON array of entity IDs.
- **BREAKING (pre-release):** `AuthorityServer.listSubordinatesExtended` (introduced earlier on this branch, not yet released) now returns `Promise<Result<ExtendedListInProcessResult, FederationError>>` instead of throwing on errors — error codes (`entity_id_not_found`, `unsupported_parameter`, `invalid_request`) are preserved in the `Result.err` branch.
- `SubordinateRecord.createdAt` / `updatedAt` are now contractually NumericDates (seconds since the epoch). Custom store implementations and fixtures that previously wrote `Date.now()` (milliseconds) must use `Math.floor(Date.now() / 1000)` or `nowSeconds(clock)`.

### Fixed

- `MemorySubordinateStore.update()` previously wrote `Date.now()` (milliseconds) to `updatedAt`, breaking any downstream consumer that interpreted the field as NumericDate. Now writes seconds via `nowSeconds(this.clock)`.

## [0.3.0] - 2026-05-12

### Changed

- Align with OpenID Federation 1.1 Final and OpenID Connect for OpenID Federation 1.1 Final (published 2026-05-11).

## [0.2.0] - 2026-04-28

### Changed

- Relicensed from MIT to Apache License 2.0. Includes `NOTICE` file.

## [0.1.0] - 2026-04-21

Initial release.
