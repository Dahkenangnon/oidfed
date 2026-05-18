# Changelog

All notable changes to `@oidfed/core` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
