# Changelog

All notable changes to `@oidfed/core` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

- **BREAKING.** OIDC schemas moved to `@oidfed/oidc`. `ExplicitRegistrationRequestPayloadSchema` and `ExplicitRegistrationResponsePayloadSchema` are no longer exported from `@oidfed/core`; import them from `@oidfed/oidc` instead.
- **BREAKING.** Typed OIDC metadata schemas (`OpenIDProviderMetadataSchema`, `OpenIDRelyingPartyMetadataSchema`) are no longer re-exported from `@oidfed/core`. The federation layer treats them as loose `z.record()`; for OIDC-strict validation, import the schemas from `@oidfed/oidc`.
- **BREAKING.** `RegistrationProtocolAdapter` and `RegistrationProtocolAdapterContext` interfaces moved to `@oidfed/oidc`.
- **BREAKING.** `ClientRegistrationType` constant + type moved to `@oidfed/oidc`.
- **BREAKING.** `JwtTyp.ExplicitRegistrationResponse` and `MediaType.ExplicitRegistrationResponse` removed. The OIDC equivalents `OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE` and `OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE` live in `@oidfed/oidc`.
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
