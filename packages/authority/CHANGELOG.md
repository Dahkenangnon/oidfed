# Changelog

All notable changes to `@oidfed/authority` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.0.0] - 2026-11-26

### Breaking Changes

* authorize federation requests and scope resolve reuse ([8a93565](https://github.com/Dahkenangnon/oidfed/commit/8a935655f5ca15c5f4fdc00b5b8c31be297f1978))
* enforce federation artifact signing policy ([888e2a8](https://github.com/Dahkenangnon/oidfed/commit/888e2a86308baad021346123c109549c3740a704))
* require federation POST selectors in the form ([7997498](https://github.com/Dahkenangnon/oidfed/commit/7997498008d5e674a8488827bca84e268c9bfb64))
* unify storage and federation host contracts ([2882619](https://github.com/Dahkenangnon/oidfed/commit/28826192c47f6eb898a0d1f590c87aa12b3a3d5d))
* require host-provided crypto ([d748f11](https://github.com/Dahkenangnon/oidfed/commit/d748f1168d8819ea5943433400b858e26f7030fb))
* integrate trust marks and enforce resolve policy ([fa26b16](https://github.com/Dahkenangnon/oidfed/commit/fa26b16d32a17f576a0ba57b99e0de2494ee390b))
* bind verification to caller context ([c138e09](https://github.com/Dahkenangnon/oidfed/commit/c138e09808827d95c83e0b4ea3cc90c5fce47ee4))
* separate Trust Mark results from chain validity ([921bd96](https://github.com/Dahkenangnon/oidfed/commit/921bd96a0b0391590b9c54ead9d0473f6065c6df))

### Features

* serve approved retained subordinate statements ([c1d7266](https://github.com/Dahkenangnon/oidfed/commit/c1d7266794b44b1a1e1edeaf9c2294971f429ca1))
* serve historical keys and validate endpoint metadata ([6497391](https://github.com/Dahkenangnon/oidfed/commit/64973910bc04840efb690972b1cd14846e780808))
* configure subordinate events response lifetime ([000d973](https://github.com/Dahkenangnon/oidfed/commit/000d973a78fa52fe245e3325e50a2281e0652ab9))
* support custom extended listing filters ([e1c30be](https://github.com/Dahkenangnon/oidfed/commit/e1c30be3f99b375c952c7be2f997cd13de878c45))
* project stored extended listing claims ([a888350](https://github.com/Dahkenangnon/oidfed/commit/a88835017bce503b12abb509d07841ff2dde6b8d))
* add standalone federation resolver hosting ([86ea2bc](https://github.com/Dahkenangnon/oidfed/commit/86ea2bc5c3fe850a1bb1ace9cc2aba9f51e7cedb))
* support critical extensions in Entity Statement publication ([a558bea](https://github.com/Dahkenangnon/oidfed/commit/a558bea6f091c8e0bdcf31b0d4853dabde5df28e))
* add trusted issuer evidence and trust mark verification ([caac696](https://github.com/Dahkenangnon/oidfed/commit/caac696d05ddc9f9f35bedfa526b404f7d2e38c5))
* annotate captured subordinate events ([6b9e779](https://github.com/Dahkenangnon/oidfed/commit/6b9e77959a9aaab8fd6397c10ff15d9a2d7c8be2))

### Bug Fixes

* harden Resolve caching and federation signing ([d2c42f6](https://github.com/Dahkenangnon/oidfed/commit/d2c42f646cab7d6f1ef6083495db32dc6829fccc))
* verify exact retained publication claims ([560b4e4](https://github.com/Dahkenangnon/oidfed/commit/560b4e4a4d90a18e9b56597dbd183e8033d99563))
* correct metadata, theming, links and docs scrolling ([c6053e4](https://github.com/Dahkenangnon/oidfed/commit/c6053e47549cfa8bce16d99105de940c7c810dd3))
* correct ESM and CommonJS declaration exports ([3475f0b](https://github.com/Dahkenangnon/oidfed/commit/3475f0bbc7cc7eea7c8501e02acb83edd0970375))
* harden metadata writes and HTTP body handling ([a91de89](https://github.com/Dahkenangnon/oidfed/commit/a91de89f9c68b07cd3d7138f463c3e515aea4026))
* honor nested trust mark lifetime defaults ([b8339eb](https://github.com/Dahkenangnon/oidfed/commit/b8339eb2f1cd8504386c8e4120b2d33f67f58764))
* validate configured TTLs before publication ([633fad1](https://github.com/Dahkenangnon/oidfed/commit/633fad1efaf507166dc8d44266f3cd60e7745fda))
* isolate and safely compose host metadata ([9ec838a](https://github.com/Dahkenangnon/oidfed/commit/9ec838a3bbb49dcf0973f0a7051a30feada1b7c6))
* snapshot storage inputs before queued writes ([5ea042e](https://github.com/Dahkenangnon/oidfed/commit/5ea042e7283c5a1dece50efc02a246fa95e91769))
* honor cancellation when serving subordinate events ([a23e60e](https://github.com/Dahkenangnon/oidfed/commit/a23e60e2c1abab40afa8908ba4a1746cc85a8101))
* snapshot subordinate events before queued writes ([dd96169](https://github.com/Dahkenangnon/oidfed/commit/dd96169fa3a9e35c3ef60040bc569f141f653952))
* contain extended listing storage errors and cancellation ([56ddfb5](https://github.com/Dahkenangnon/oidfed/commit/56ddfb5e8ca34546b4285d9b33238e4771e5de21))
* support trust anchors with superiors ([db62ca6](https://github.com/Dahkenangnon/oidfed/commit/db62ca6c5b06c100b532ed03856473e830a16847))
* reject conflicting hosted role routes ([fc1c3af](https://github.com/Dahkenangnon/oidfed/commit/fc1c3af088cbe5ca267c15e48c31fc72b81ad828))
* normalize published entity identifiers once ([9e825ae](https://github.com/Dahkenangnon/oidfed/commit/9e825ae30716c98d845e0146d6e1041715e1453f))
* validate Resolve candidates and evidence lifetimes ([790d186](https://github.com/Dahkenangnon/oidfed/commit/790d18644f9f0fd72169398ed80cb258a4ad8646))
* unify fixed endpoint selector matching ([d23a183](https://github.com/Dahkenangnon/oidfed/commit/d23a183e6f85950d27e2812f6830114fca517b8c))
* validate subordinate claims before publication ([d0c100c](https://github.com/Dahkenangnon/oidfed/commit/d0c100c25fcff716ae0dfda029603c00c06a2885))
* report lifecycle failures and publication guidance ([aa7ae6b](https://github.com/Dahkenangnon/oidfed/commit/aa7ae6b6a0eb32a5b05845f7c7525b8379ebefbd))
* scope metadata null checks and authenticate resolver ECs ([483fba1](https://github.com/Dahkenangnon/oidfed/commit/483fba10914c2d3b634ccd90e18bbfffca3541e3))
* enforce trust-chain authority hints and offline wallet guards ([b5b3f07](https://github.com/Dahkenangnon/oidfed/commit/b5b3f074873132a460c45cf3e3b777a92cb2bbc0))
* validate stored subordinate identifiers ([1863166](https://github.com/Dahkenangnon/oidfed/commit/1863166e97a50ce2e65b5a584ab108beee89d0e7))
* reject orphan endpoint authentication ([c844777](https://github.com/Dahkenangnon/oidfed/commit/c8447770f042a5563edbb1b4fa441ea864a25ca6))
* route endpoints by fixed query selectors ([d1be242](https://github.com/Dahkenangnon/oidfed/commit/d1be24264024f2ea108eccb56df0d2e083c55e52))
* allow open Trust Mark issuance ([dfd7ba2](https://github.com/Dahkenangnon/oidfed/commit/dfd7ba24daad47b473639df544dfb618384d1fd4))
* preserve authenticated endpoint queries ([bd15a3c](https://github.com/Dahkenangnon/oidfed/commit/bd15a3ca66d24907b172138d25d6412cb6db1cfc))
* align extended listing claims ([f6c5bc4](https://github.com/Dahkenangnon/oidfed/commit/f6c5bc465716b80959ebf65d004f8956b09d3378))
* tighten publication and trust checks ([66e88e2](https://github.com/Dahkenangnon/oidfed/commit/66e88e2d6e53880da0d757e4a4a8932b0dfcf27f))
* validate federation boundaries ([5207ec5](https://github.com/Dahkenangnon/oidfed/commit/5207ec5a797d3b58df14b2f147b59bef69f478c2))
* validate extended listing public keys ([b1627e9](https://github.com/Dahkenangnon/oidfed/commit/b1627e9e1da9158a929424faa9f00c44870565bf))
* preserve historical key lifetimes ([84c5dc5](https://github.com/Dahkenangnon/oidfed/commit/84c5dc5594112616cd0ed2c04ec4ecf2dc5cdc92))
* guard Trust Mark registry lookups ([a4f69b4](https://github.com/Dahkenangnon/oidfed/commit/a4f69b4f66353261a2fcf977147d816157ffb504))
* accept custom entity_type values in list filters ([32664f8](https://github.com/Dahkenangnon/oidfed/commit/32664f8b04cbd7bac4b32f49fbc350dad00fbfd3))

### Performance

* read event histories through snapshots ([d29ac21](https://github.com/Dahkenangnon/oidfed/commit/d29ac21e34036f3c07ba462ae675f7aab3d2a033))

### Refactor

* share protocol helpers and remove dead code ([f299374](https://github.com/Dahkenangnon/oidfed/commit/f299374faab2822cd06c543832e0d959e5210c39))
* centralize stored trust mark eligibility ([a3309f3](https://github.com/Dahkenangnon/oidfed/commit/a3309f37519109c35ac4bbdc76a97c02661f37d7))
* share extended listing request handling ([8b99cea](https://github.com/Dahkenangnon/oidfed/commit/8b99cea35a87c9bd59d8b38ff47920c5e7c0a3fd))


## [2.0.0] - 2026-10-26

### Breaking changes

- Extended Listing follows Draft 03: replace legacy cursor names with opaque `from` and `next` values. Unknown cursors return `page_not_found`. Both listing endpoints treat `trust_marked=false` as adding no restriction; supplied mark-type filters still apply. ([6c1c8a6](https://github.com/Dahkenangnon/oidfed/commit/6c1c8a60c234574109aedc062ead11094e99f82a))
- Endpoints configured for `private_key_jwt` require `storage.replay`. Assertions require `exp` and `jti`; `iat` is optional. Empty or unsupported authentication method lists fail construction. ([f51d9c6](https://github.com/Dahkenangnon/oidfed/commit/f51d9c64859a099d1720ee66675cd442554aedde))

### Added

- Subordinate Events Draft 01 endpoint and optional transactional event storage. Lifecycle methods record registration, attested metadata and policy changes, registered key changes, and explicit revocation. Retain history after removal and allow explicit suspension and custom events; recording an event alone does not enforce suspension. ([4c6398c](https://github.com/Dahkenangnon/oidfed/commit/4c6398cc568149ebeb01377e1df9cdee022ba44c))
- Optional Entity Collection hosting through core's shared service and an optional collection store. Support custom collectors and refresh-time filters. ([3d69d77](https://github.com/Dahkenangnon/oidfed/commit/3d69d778bd4ea074826e89872467f65e6b2073ab))
- Validate composed wallet role metadata before publishing Entity Configurations, including wallet claim-path wildcards. ([5863459](https://github.com/Dahkenangnon/oidfed/commit/58634591566fc500f3872b46b480d34d01a29a7b))

### Fixed

- Preserve anonymous Trust Mark Status POST requests when authentication is optional. Reject empty, duplicate, or invalid supplied credentials, bound request-body reads, and preserve repeated parameters when forwarding authenticated requests. ([f51d9c6](https://github.com/Dahkenangnon/oidfed/commit/f51d9c64859a099d1720ee66675cd442554aedde))
- Copy subordinate updates before queued transactions so caller mutations cannot change persisted records or event history. Document staged key rollover and production storage ownership. ([f51d9c6](https://github.com/Dahkenangnon/oidfed/commit/f51d9c64859a099d1720ee66675cd442554aedde))
- Support repeated Extended Listing Trust Mark filters, explicit empty claim selections, and finite NumericDates. ([6c1c8a6](https://github.com/Dahkenangnon/oidfed/commit/6c1c8a60c234574109aedc062ead11094e99f82a))
- Keep bundled TypeScript declaration generation working with TypeScript 6. ([a473ebb](https://github.com/Dahkenangnon/oidfed/commit/a473ebbb93d166ebcd69f9c8c52d376e48ff29fc))

## [1.0.0] - 2026-07-13

### Features

* add stable statement builders ([e726a5c](https://github.com/Dahkenangnon/oidfed/commit/e726a5ccbb24a816dba3356ba3b1607a3fbc3d6a))

### Bug Fixes

* enforce provider-owned federation key rollover ([776d123](https://github.com/Dahkenangnon/oidfed/commit/776d1236092366b007ed8a7d9882bd570a35f004))
* enforce federation endpoint validation ([ceae64b](https://github.com/Dahkenangnon/oidfed/commit/ceae64baf66980758db445ebc4bdb5343dff7f1d))
* align config docs and package claims ([ea093ac](https://github.com/Dahkenangnon/oidfed/commit/ea093acb7d3df03bbd43e90b30525681aedb7824))
* remove avoidable public any ([d0e754d](https://github.com/Dahkenangnon/oidfed/commit/d0e754d9a2f72fdf57b1bf584a131491a5ef4006))
* normalize endpoint routing and entity ids ([bdbf7f4](https://github.com/Dahkenangnon/oidfed/commit/bdbf7f4cadc29f7ac6b74b15a8d8e0c123d49363))
* abstract endpoint auth key lookup ([6c3f700](https://github.com/Dahkenangnon/oidfed/commit/6c3f7000b64b0db308c3eac1aafba324064fe701))
* align root docs with class api ([f8ae317](https://github.com/Dahkenangnon/oidfed/commit/f8ae317783708d5a89d107c93a1d6665f4ba0ca2))
* align public docs with class-only APIs ([eb6c359](https://github.com/Dahkenangnon/oidfed/commit/eb6c35953963b8dae0b9f700bfbe69ba92f223f4))
* harden resolve, explicit registration, and client auth validation ([f673908](https://github.com/Dahkenangnon/oidfed/commit/f673908aa7fc06422fefeef233bceca864f2e83d))

### Refactor

* clarify public role and key provider names ([1211280](https://github.com/Dahkenangnon/oidfed/commit/1211280b7cea233b6522830c149e8ac0abc7a352))


### Added

- `AuthorityConfig.trustAnchorHints` publishes preferred trust anchors as `trust_anchor_hints` for Intermediate Authority Entity Configurations.

### Changed

- Federation endpoint `private_key_jwt` authentication now resolves remote caller keys through `AuthorityConfig.clientKeyProvider`, defaulting to subordinate storage, instead of live trust-chain discovery.
- Authority HTTP routing now derives the Entity Configuration path from the normalized Entity Identifier and federation endpoint routes from advertised metadata endpoint URLs.
- **BREAKING.** Authority server and class facades no longer expose `rotateSigningKey()`. Federation key rollover is owned by the injected `FederationKeyLifecycleProvider`, so applications can plug in KMS-backed or database-backed key managers without authority-level lifecycle duplication.
- Extended subordinate listing in-process parameter and result types now use endpoint-oriented public names.

## [0.8.0] - 2026-06-25

### Refactor

* context propagation, type exports and request overrides ([d6e9174](https://github.com/Dahkenangnon/oidfed/commit/d6e91742f9e32818caf96d05673f86a01fc15364))
* migrate E2E scenarios and OP participant to new class-based facades ([1e6f5e5](https://github.com/Dahkenangnon/oidfed/commit/1e6f5e56cadb107f4a5d860a4ce39adf2455229c))


## [0.7.0] - 2026-06-24

### Refactor

* stabilize API exports and add strict metadata schemas ([f23c205](https://github.com/Dahkenangnon/oidfed/commit/f23c205d2634f963bca810db8cb0dc6ad2be459c))


## [0.6.1] - 2026-06-24

_No user-visible changes — released as part of the coordinated wave._


## [0.6.0] - 2026-06-24

### Features

* unify persistence behind storage adapter ([f622fca](https://github.com/Dahkenangnon/oidfed/commit/f622fca5955bfee03c90192308bd86bd3e1ec9ed))
* separate federation and OIDC signing keys ([0664c90](https://github.com/Dahkenangnon/oidfed/commit/0664c90641288f41b561588d954badd7f6ae5a4e))
* enhance the npm published keyworks ([a0e38c4](https://github.com/Dahkenangnon/oidfed/commit/a0e38c46c7fcafd75341a3aa306350e8f0f1df8d))

### Bug Fixes

* harden public API types and add trust anchor helper ([3283001](https://github.com/Dahkenangnon/oidfed/commit/3283001bbd291a42843c5e768d34405c0b064eac))
* review the public api of every pkg ([a95c473](https://github.com/Dahkenangnon/oidfed/commit/a95c473f1a92bdd55a248fcc1a8b319da2208295))
* add core dependency for package builds ([30d986d](https://github.com/Dahkenangnon/oidfed/commit/30d986df000c85c8e0320cc6b019c1c89d8015c7))

### Refactor

* implement new class-based developer experience and API design ([b2fe982](https://github.com/Dahkenangnon/oidfed/commit/b2fe98287f0c553feded3ec11b8b0059ebb41061))


### Added

- Unified `StorageAdapter` with subordinate, optional trust-mark, optional replay, optional cache, and serializable transaction capabilities.
- `MemoryStorageAdapter` for development and tests, including transaction rollback, detached records, replay, and cache capabilities.

### Changed

- **BREAKING.** `AuthorityConfig` now accepts one `storage` adapter instead of separate subordinate and trust-mark stores.
- Trust-mark persistence is expiry-aware, preserves exact issued JWT history, and supports complete deterministic pagination.
- Authority clocks now propagate to cache, client-assertion verification, trust-mark verification, and delegation signing.

### Removed

- **BREAKING.** Removed `SubordinateStore`, `TrustMarkStore`, `MemorySubordinateStore`, and `MemoryTrustMarkStore`.
- **BREAKING.** Generic core HTTP helpers are no longer re-exported; import them from `@oidfed/core`.

## [0.5.2] - 2026-05-28

_No user-visible changes — released as part of the coordinated wave._


## [0.5.1] - 2026-05-28

### Changed

- Stripped lingering specification section / paragraph / figure references from internal comments, test descriptions, and prior CHANGELOG entries. No behaviour change; the package was already spec-conformant.

## [0.5.0] - 2026-05-23

### Removed

- **BREAKING.** `/federation_registration` handler removed from `@oidfed/authority`. The endpoint is an OpenID-Connect-specific concern and is handled through `@oidfed/oidc` provider roles. Authorities no longer expose `FederationEndpoint.Registration` in their route map.
- **BREAKING.** `RegistrationProtocolAdapter` type re-export removed from `@oidfed/authority`. Import it from `@oidfed/oidc` instead.
- `createRegistrationHandler` export removed.

### Changed

- **BREAKING.** `AuthorityConfig.registrationResponseTtlSeconds` and `AuthorityConfig.registrationConfig` removed. Callers configuring an explicit-registration endpoint should compose an `OidcProviderRole` role from `@oidfed/oidc` and mount it on their own server (e.g. alongside a leaf entity's `.well-known/openid-federation`).
- `HandlerContext` no longer carries `registrationResponseTtlSeconds`, `registrationConfig`, or `registrationProtocolAdapter`.

## [0.4.1] - 2026-05-23

### Added

- `TrustAnchor.sanitizeSubordinateMetadata(metadata)` and `Intermediate.sanitizeSubordinateMetadata(metadata)` class helpers that strip operational `federation_entity` claims from metadata destined for a Subordinate Statement.
- Internal subordinate-statement shape validation now rejects operational fields and null metadata values before storage or statement issuance.
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
- New `AuthorityServer.listSubordinatesExtended(params?)` in-process API returning `Promise<Result<ExtendedSubordinateListingResult, FederationError>>`; types `ExtendedSubordinateListingParams` and `ExtendedSubordinateListingResult`.
- New OPTIONAL `TrustMarkStore.listForSubject(subject)` method used by `/federation_extended_list` when `claims=trust_marks` is requested. `MemoryTrustMarkStore` ships the implementation; deployments whose store cannot enumerate-by-subject receive `400 unsupported_parameter`.
- `AuthorityConfig.extendedListing?: ExtendedListingConfig` to configure the new endpoint.
- Page-fill loop: when post-filters reduce a store page below the requested limit, the handler continues fetching from the store (bounded by `maxStorePagesPerRequest`) until either the page is full or the store is exhausted. `next_entity_id` skips known non-matches in the current page so clients don't iterate through empty pages.
- `MemorySubordinateStore` now accepts an optional `clock` in its constructor; `update()` writes `updatedAt` as a NumericDate (seconds since the epoch).

### Changed

- **BREAKING:** `SubordinateStore.list(filter)` signature changed from `Promise<SubordinateRecord[]>` to `list(filter?, options?): Promise<ListPage>` where `ListPage = { items: SubordinateRecord[]; nextCursor?: EntityId }` and `ListPageOptions = { cursor?, limit?, updatedAfter?, updatedBefore? }`. Records MUST be returned in deterministic lexicographic order by `entityId`. The bundled `MemorySubordinateStore` is migrated. Custom store implementations need to adopt the new shape. Observable behaviour of the base `/federation_list` endpoint is unchanged — it still returns the same flat JSON array of entity IDs.
- **BREAKING:** `AuthorityServer.listSubordinatesExtended` now returns `Promise<Result<ExtendedSubordinateListingResult, FederationError>>` instead of throwing on errors — error codes (`entity_id_not_found`, `unsupported_parameter`, `invalid_request`) are preserved in the `Result.err` branch.
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
