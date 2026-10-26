# Changelog

All notable changes to `@oidfed/core` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2026-10-26

### Breaking changes

- Extended Listing replaces `fromEntityId` / `from_entity_id` and `next_entity_id` with opaque `from` and `next` cursors. Legacy cursor names are unsupported. ([6c1c8a6](https://github.com/Dahkenangnon/oidfed/commit/6c1c8a60c234574109aedc062ead11094e99f82a))
- Client assertions require `exp` and `jti`; `iat` is optional. `VerifiedClientAssertion.jti` is required and `issuedAt` is optional. Authentication integrations must supply replay storage for one-time use. ([f51d9c6](https://github.com/Dahkenangnon/oidfed/commit/f51d9c64859a099d1720ee66675cd442554aedde))

### Added

- Entity Collection Draft 01 service, schemas, storage contracts, and HTTP client. Support custom collectors, refresh-time filters, verified Trust Mark filtering, claim selection, language matching, and opaque pagination. Failed mandatory refresh work preserves the previous snapshot. ([3d69d77](https://github.com/Dahkenangnon/oidfed/commit/3d69d778bd4ea074826e89872467f65e6b2073ab))
- Subordinate Events Draft 01 schemas, media types, and a client that verifies signed histories against caller-supplied trusted authority keys. Requests reject redirects and enforce response byte and time limits. ([4c6398c](https://github.com/Dahkenangnon/oidfed/commit/4c6398cc568149ebeb01377e1df9cdee022ba44c))
- Staged trust-chain validation for request-dependent wallet policies, a composed-role metadata validation hook, and support for wallet claim-path wildcards without accepting null metadata fields elsewhere. ([5863459](https://github.com/Dahkenangnon/oidfed/commit/58634591566fc500f3872b46b480d34d01a29a7b))

### Fixed

- Make federation key transitions atomic and order activations independently of the clock. Copy key inputs and outputs, derive verification-capable public JWKs from WebCrypto signing keys, and preserve revocation timestamps at epoch zero. ([f51d9c6](https://github.com/Dahkenangnon/oidfed/commit/f51d9c64859a099d1720ee66675cd442554aedde))
- Support repeated Extended Listing Trust Mark types and explicit empty claim selections. Accept finite NumericDates and enforce response limits, cancelling unread rejected response bodies. ([6c1c8a6](https://github.com/Dahkenangnon/oidfed/commit/6c1c8a60c234574109aedc062ead11094e99f82a))
- Keep bundled TypeScript declaration generation working with TypeScript 6. ([a473ebb](https://github.com/Dahkenangnon/oidfed/commit/a473ebbb93d166ebcd69f9c8c52d376e48ff29fc))
- Update JOSE and schema-validation dependencies. ([d83b296](https://github.com/Dahkenangnon/oidfed/commit/d83b296634b86ae059cd71aa79b2a77d6fd05b89)) ([692ef7d](https://github.com/Dahkenangnon/oidfed/commit/692ef7de7218c2085983fd05a620051f35c5971e))

## [1.0.0] - 2026-07-13

### Features

* expose typed entity statement decoders ([c81bdf5](https://github.com/Dahkenangnon/oidfed/commit/c81bdf5005906e69fe5a977a4a18cb20ac0d3637))
* add stable statement builders ([e726a5c](https://github.com/Dahkenangnon/oidfed/commit/e726a5ccbb24a816dba3356ba3b1607a3fbc3d6a))

### Bug Fixes

* return public generated signing keys ([8c2a966](https://github.com/Dahkenangnon/oidfed/commit/8c2a966f1440de321db09a273052603977b2d475))
* enforce provider-owned federation key rollover ([776d123](https://github.com/Dahkenangnon/oidfed/commit/776d1236092366b007ed8a7d9882bd570a35f004))
* enforce federation endpoint validation ([ceae64b](https://github.com/Dahkenangnon/oidfed/commit/ceae64baf66980758db445ebc4bdb5343dff7f1d))
* enforce trust mark payload validation ([cd3af0c](https://github.com/Dahkenangnon/oidfed/commit/cd3af0cb31c99eabbcd9ebd4f4d2e783731a62ae))
* enforce federation policy validation ([54de0f0](https://github.com/Dahkenangnon/oidfed/commit/54de0f06b733258dfd4f0b94d627b469dff94fc5))
* tighten federation metadata validation ([a102e38](https://github.com/Dahkenangnon/oidfed/commit/a102e386736a8be57e191352dab7a4d6a165ef53))
* cover section 3 entity statement validation ([d098c56](https://github.com/Dahkenangnon/oidfed/commit/d098c56f2a3278ae5dcb520026bd25d2b529ff1d))
* enforce exact federation media types ([6c00afe](https://github.com/Dahkenangnon/oidfed/commit/6c00afeb3549ed06fde3fc077c039a561826db28))
* align config docs and package claims ([ea093ac](https://github.com/Dahkenangnon/oidfed/commit/ea093acb7d3df03bbd43e90b30525681aedb7824))
* remove avoidable public any ([d0e754d](https://github.com/Dahkenangnon/oidfed/commit/d0e754d9a2f72fdf57b1bf584a131491a5ef4006))
* harden raw trust-chain validation ([3d5f2c4](https://github.com/Dahkenangnon/oidfed/commit/3d5f2c4a185d9791fb551cf087415f601962bf13))
* validate supplied registration trust chains ([5c21f4f](https://github.com/Dahkenangnon/oidfed/commit/5c21f4f9d62b1d35a2802414e9391047b54f487f))
* require trust anchors for op registration ([36bd338](https://github.com/Dahkenangnon/oidfed/commit/36bd33813fdfced76f0930fa6da0b95e30297133))
* align root docs with class api ([f8ae317](https://github.com/Dahkenangnon/oidfed/commit/f8ae317783708d5a89d107c93a1d6665f4ba0ca2))
* align public docs with class-only APIs ([eb6c359](https://github.com/Dahkenangnon/oidfed/commit/eb6c35953963b8dae0b9f700bfbe69ba92f223f4))

### Refactor

* clarify public role and key provider names ([1211280](https://github.com/Dahkenangnon/oidfed/commit/1211280b7cea233b6522830c149e8ac0abc7a352))


### Added

- Stable Entity Configuration and Subordinate Statement payload builders, signing helpers, and claim-placement validation helpers for normal Entity Statements.
- Schema-backed `decodeEntityConfiguration()` and `decodeSubordinateStatement()` helpers for kind-safe unsigned Entity Statement inspection.

### Changed

- Federation HTTP fetch helpers now require exact parameter-free Content-Type values for spec-defined media types, including Entity Statements, Resolve Responses, Trust Marks, signed JWK Sets, and federation JSON list responses.
- `validateTrustChain()` now rejects malformed raw Entity Statements, invalid metadata policy critical operators, and invalid published Trust Marks during Trust Chain validation.
- `MemoryFederationKeyProvider` now requires an initial federation signing key or non-empty key array and rejects empty arrays during construction.
- **BREAKING.** `FederationKeyLifecycleProvider` is the public contract for provider-owned federation rollover through `publishKey()` and `switchActiveKey()` instead of the previous `addKey()` / `activateKey()` / `retireKey()` sequence. Published keys appear in the active Federation JWKS before signer switch, and expired retiring keys are excluded from the active Federation JWKS while remaining available through historical keys.
- Public federation signing-key construction and Trust Anchor key comparison result types now use explicit behavior-oriented names.
- `compareTrustAnchorKeys()` now compares public key material for matching `kid` values and reports missing or mismatched keys with behavior-focused field names.

## [0.8.0] - 2026-06-25

### Refactor

* context propagation, type exports and request overrides ([d6e9174](https://github.com/Dahkenangnon/oidfed/commit/d6e91742f9e32818caf96d05673f86a01fc15364))
* migrate E2E scenarios and OP participant to new class-based facades ([1e6f5e5](https://github.com/Dahkenangnon/oidfed/commit/1e6f5e56cadb107f4a5d860a4ce39adf2455229c))


## [0.7.0] - 2026-06-24

_No user-visible changes — released as part of the coordinated wave._


## [0.6.1] - 2026-06-24

_No user-visible changes — released as part of the coordinated wave._


## [0.6.0] - 2026-06-24

### Features

* relax entityId and authorityHints parameter type constraints ([07a3da5](https://github.com/Dahkenangnon/oidfed/commit/07a3da5618a740f6b7ed5547fb45c0b2bdf8ec08))
* unify runtime errors to monadic Result ([ba58a65](https://github.com/Dahkenangnon/oidfed/commit/ba58a656eec56ff34ef0ce1254b5747210219e17))
* export standard policy operators enum and re-export common core primitives ([92aeda6](https://github.com/Dahkenangnon/oidfed/commit/92aeda67ff5c8279b8211e089fc10374d7803433))
* unify persistence behind storage adapter ([f622fca](https://github.com/Dahkenangnon/oidfed/commit/f622fca5955bfee03c90192308bd86bd3e1ec9ed))
* separate federation and OIDC signing keys ([0664c90](https://github.com/Dahkenangnon/oidfed/commit/0664c90641288f41b561588d954badd7f6ae5a4e))
* enhance the npm published keyworks ([a0e38c4](https://github.com/Dahkenangnon/oidfed/commit/a0e38c46c7fcafd75341a3aa306350e8f0f1df8d))

### Bug Fixes

* harden public API types and add trust anchor helper ([3283001](https://github.com/Dahkenangnon/oidfed/commit/3283001bbd291a42843c5e768d34405c0b064eac))
* review the public api of every pkg ([a95c473](https://github.com/Dahkenangnon/oidfed/commit/a95c473f1a92bdd55a248fcc1a8b319da2208295))


### Added

- `ReplayStore`, structured `JtiReplayClaim`, and the runtime-neutral development `MemoryReplayStore`. Replay identity is scoped by issuer, audience, and JTI; capacity failures fail closed.
- Public `MemoryCacheOptions` and `MemoryFederationKeyProviderOptions`; key lifecycle time is explicitly exposed as `nowMs`.

### Changed

- **BREAKING.** `Clock.now()` is consistently Unix NumericDate seconds. Cache TTLs, JOSE verification, trust-chain validation, trust marks, and protocol assertions honor injected clocks.
- `validateTrustChain()` accepts readonly statement arrays.

### Removed

- **BREAKING.** Removed `JtiStore`, `InMemoryJtiStore`, and `hasSeenAndRecord()` in favor of atomic `ReplayStore.useJti()`.
- Internal federation key state and managed-entry types are no longer exported.

## [0.5.2] - 2026-05-28

_No user-visible changes — released as part of the coordinated wave._


## [0.5.1] - 2026-05-28

### Changed

- Refreshed runtime dependency ranges to pull in patch and minor updates: `jose` (^6.0.0 resolving to 6.2.3) and `zod` (^4.0.0 resolving to 4.4.3). No API change.

## [0.5.0] - 2026-05-23

### Removed

- **BREAKING.** OIDC explicit-registration payload schemas are no longer exported from `@oidfed/core`; use the type-only payload exports and role APIs from `@oidfed/oidc` instead.
- **BREAKING.** Typed OIDC metadata schemas (`OpenIDProviderMetadataSchema`, `OpenIDRelyingPartyMetadataSchema`) are no longer re-exported from `@oidfed/core`. The federation layer treats them as loose `z.record()`; OIDC-strict validation happens inside `@oidfed/oidc` role APIs.
- **BREAKING.** `RegistrationProtocolAdapter` and `RegistrationProtocolAdapterContext` interfaces moved to `@oidfed/oidc`.
- **BREAKING.** Client registration type definitions moved to `@oidfed/oidc`; runtime constants are implementation details.
- **BREAKING.** `JwtTyp.ExplicitRegistrationResponse` and `MediaType.ExplicitRegistrationResponse` removed. OIDC-specific response type and media-type constants are internal to `@oidfed/oidc`.
- **BREAKING.** `normalizeScope` and `denormalizeScope` are no longer part of the public API; they are internal implementation details of `applyMetadataPolicy` and remain in `packages/core/src/metadata-policy/apply.ts`.

### Changed

- `packages/core/src/schemas/metadata.ts` continues to define loose `OpenIDProviderMetadataSchema` / `OpenIDRelyingPartyMetadataSchema` (each `z.record()`) for internal use by `FederationMetadataSchema`. They are no longer publicly exported.

## [0.4.1] - 2026-05-23

### Added

- Public export `STANDARD_ENTITY_STATEMENT_CLAIMS` — the canonical set of claim names defined for Entity Statements. Used by callers that need to validate `crit` lists against the spec-defined claim set.

## [0.4.0] - 2026-05-18

### Added

- New `federation_extended_list_endpoint` claim and `federation_extended_list_endpoint_auth_methods` on `FederationEntityMetadataSchema`.
- New `FederationEndpoint.ExtendedList = "/federation_extended_list"`.
- New `FederationErrorCode.EntityIdNotFound = "entity_id_not_found"`.
- New Zod schemas for the Extended Subordinate Listing endpoint: `ExtendedListClaim`, `EXTENDED_LIST_SUPPORTED_CLAIMS` (13 claim names), `ExtendedListQuerySchema`, `ExtendedListEntitySchema`, `ExtendedListResponseSchema`, plus `ExtendedListQuery` / `ExtendedListEntity` / `ExtendedListResponse` / `ExtendedListRequestParams` types.
- `ExtendedListClaim` covers all top-level Subordinate Statement claims: `subordinate_statement`, `iss`, `sub`, `iat`, `exp`, `jwks`, `metadata`, `metadata_policy`, `constraints`, `crit`, `metadata_policy_crit`, `source_endpoint`, `trust_marks`.
- New `fetchExtendedSubordinatesList(endpoint, params?, options?)` client. HTTPS-only, content-type checked, surfaces spec-defined error codes (`entity_id_not_found`, `unsupported_parameter`) from `400 application/json` responses. Sends `claims` as a single comma-separated value on the wire.

## [0.3.0] - 2026-05-12

### Changed

- Align with OpenID Federation 1.1 Final and OpenID Connect for OpenID Federation 1.1 Final (published 2026-05-11).

## [0.2.0] - 2026-04-28

### Changed

- Relicensed from MIT to Apache License 2.0. Includes `NOTICE` file.

## [0.1.0] - 2026-04-21

Initial release.
