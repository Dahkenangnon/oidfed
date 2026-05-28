# Changelog

All notable changes to `@oidfed/authority` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Stripped lingering specification section / paragraph / figure references from internal comments, test descriptions, and prior CHANGELOG entries. No behaviour change; the package was already spec-conformant.

## [0.5.0] - 2026-05-23

### Removed

- **BREAKING.** `/federation_registration` handler removed from `@oidfed/authority`. The endpoint is an OpenID-Connect-specific concern and has moved to `@oidfed/oidc` as `createExplicitRegistrationHandler`. Authorities no longer expose `FederationEndpoint.Registration` in their route map.
- **BREAKING.** `RegistrationProtocolAdapter` type re-export removed from `@oidfed/authority`. Import it from `@oidfed/oidc` instead.
- `createRegistrationHandler` export removed.

### Changed

- **BREAKING.** `AuthorityConfig.registrationResponseTtlSeconds` and `AuthorityConfig.registrationConfig` removed. Callers configuring an explicit-registration endpoint should construct it via `createExplicitRegistrationHandler({ ... })` from `@oidfed/oidc` and mount it on their own server (e.g. alongside a leaf entity's `.well-known/openid-federation`).
- `HandlerContext` no longer carries `registrationResponseTtlSeconds`, `registrationConfig`, or `registrationProtocolAdapter`.

## [0.4.1] - 2026-05-23

### Added

- `sanitizeSubordinateMetadata(metadata)` exported helper that strips operational `federation_entity` claims from metadata destined for a Subordinate Statement.
- `FEDERATION_ENTITY_OPERATIONAL_FIELDS` and `isFederationEntityOperationalField(key)` for callers that need the same field list.
- `assertSubordinateStatementShape(payload)`, `assertMetadataValuesNotNull(metadata)`, `assertCritShape(payload)`, `assertMetadataPolicyCritShape(payload)`, and `assertMetadataPolicyShape(payload)` defensive helpers.
- `validateSubordinateRecord(record)` re-export for callers that want to pre-validate a record before insertion.
- New typed errors: `InvalidAuthorityConfig`, `InvalidSubordinateRecord`, `InvalidSubordinateStatementShape`, `InvalidMetadata`.

### Fixed

- Subordinate Statements no longer include the subordinate's own federation endpoint URLs (`federation_fetch_endpoint`, `federation_list_endpoint`, `federation_resolve_endpoint`, `federation_extended_list_endpoint`, `federation_trust_mark_endpoint`, `federation_trust_mark_status_endpoint`, `federation_trust_mark_list_endpoint`, `federation_historical_keys_endpoint`, every `_auth_methods` companion, and `endpoint_auth_signing_alg_values_supported`). Stripping happens at the wire layer inside `buildSubordinateStatement`.
- Subordinate Statements no longer accept the registration-only claims `aud` and `trust_anchor` in their top-level payload (those claims are reserved for Explicit Registration request/response). `assertSubordinateStatementShape` rejects them.
- `buildSubordinateStatement` now validates the shape of `crit`, `metadata_policy_crit`, and `metadata_policy` before signing — rejecting empty arrays, duplicates, references to spec-defined claims (in `crit`), references to standard policy operators (in `metadata_policy_crit`), and non-object `metadata_policy` values.

### Changed

- **BREAKING (install-tree).** `@oidfed/core` moved from `dependencies` to `peerDependencies`. Consumers MUST install `@oidfed/core` alongside `@oidfed/authority`. The peer range is `^0.4.0`. This guarantees a single resolved `@oidfed/core` when `@oidfed/authority` is installed beside its siblings; the previous model could install two side-by-side copies and silently break module identity.
- `MemorySubordinateStore.add(record)` now throws `InvalidSubordinateRecord` when the record's `metadata.federation_entity` carries operational claims (endpoint URLs, `_auth_methods` companions, or `endpoint_auth_signing_alg_values_supported`), or when any metadata leaf value is `null`. The previous behavior produced non-conformant Subordinate Statements. Callers that synthesize records from raw entity metadata should run their input through `sanitizeSubordinateMetadata` first.
- `createAuthorityServer(config)` now throws `InvalidAuthorityConfig` when the config is misconfigured: (a) `authorityHints` is an explicit empty array; (b) the config carries `trustMarkIssuers` or `trustMarkOwners` while not being a Trust Anchor (authorityHints non-empty); (c) `metadata.federation_entity` lacks `federation_fetch_endpoint` or `federation_list_endpoint`. Throws `InvalidMetadata` when any metadata leaf is `null`.
- EC emission gates `trust_mark_issuers` and `trust_mark_owners` on Trust Anchor identity (derived from empty/absent `authorityHints`).

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
