# Changelog

All notable changes to `@oidfed/cli` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2026-10-26

### Breaking changes

- `list-extended --from` now takes the opaque `next` cursor from a Draft 03 response. Returned JSON uses `next` instead of `next_entity_id`; legacy cursor names are unsupported. ([6c1c8a6](https://github.com/Dahkenangnon/oidfed/commit/6c1c8a60c234574109aedc062ead11094e99f82a))

### Added

- `subordinate-events` retrieves and verifies signed authority histories using the required `--jwks-file` pinned keys. Optional client assertions select authenticated POST. ([4c6398c](https://github.com/Dahkenangnon/oidfed/commit/4c6398cc568149ebeb01377e1df9cdee022ba44c))
- `collection` retrieves unsigned Entity Collection Draft 01 results, with filters, claim selection, locales, opaque cursors, and optional authenticated POST. Validate selected entities separately before trusting them. ([3d69d77](https://github.com/Dahkenangnon/oidfed/commit/3d69d778bd4ea074826e89872467f65e6b2073ab))

### Fixed

- Accept repeated Trust Mark type filters and finite NumericDate time filters in `list-extended`, and preserve explicit empty claim selections. ([6c1c8a6](https://github.com/Dahkenangnon/oidfed/commit/6c1c8a60c234574109aedc062ead11094e99f82a))
- Clarify the CLI's Node.js requirement and the scope of library runtime coverage. ([f51d9c6](https://github.com/Dahkenangnon/oidfed/commit/f51d9c64859a099d1720ee66675cd442554aedde))
- Keep bundled TypeScript declaration generation working with TypeScript 6. ([a473ebb](https://github.com/Dahkenangnon/oidfed/commit/a473ebbb93d166ebcd69f9c8c52d376e48ff29fc))
- Update command-line and schema-validation dependencies. ([d83b296](https://github.com/Dahkenangnon/oidfed/commit/d83b296634b86ae059cd71aa79b2a77d6fd05b89))

## [1.0.0] - 2026-07-13

### Bug Fixes

* enforce provider-owned federation key rollover ([776d123](https://github.com/Dahkenangnon/oidfed/commit/776d1236092366b007ed8a7d9882bd570a35f004))


## [0.8.0] - 2026-06-25

_No user-visible changes — released as part of the coordinated wave._


## [0.7.0] - 2026-06-24

_No user-visible changes — released as part of the coordinated wave._


## [0.6.1] - 2026-06-24

_No user-visible changes — released as part of the coordinated wave._


## [0.6.0] - 2026-06-24

### Features

* separate federation and OIDC signing keys ([0664c90](https://github.com/Dahkenangnon/oidfed/commit/0664c90641288f41b561588d954badd7f6ae5a4e))
* enhance the npm published keyworks ([a0e38c4](https://github.com/Dahkenangnon/oidfed/commit/a0e38c46c7fcafd75341a3aa306350e8f0f1df8d))


## [0.5.2] - 2026-05-28

### Bug Fixes

* load version dynamically from package json ([2ac3e14](https://github.com/Dahkenangnon/oidfed/commit/2ac3e14d38a3e5d84c7d56dde4dc74163d3786bc))


## [0.5.1] - 2026-05-28

### Fixed

- Hardcoded `oidfed --version` literal in `src/index.ts` now matches the published `package.json` version (was drifting; bumped manually as part of this release).

### Changed

- Package README and reference doc updated to match the actual installed command surface.

## [0.5.0] - 2026-05-23

### Changed

- `@oidfed/core` dependency uses `workspace:^` (rewritten to `^<core-version>` on publish) so npm/pnpm/yarn can dedupe `@oidfed/core` across the install tree.

## [0.4.0] - 2026-05-18

### Added

- New `list-extended <authority-id>` command targeting the Extended Subordinate Listing endpoint with auto-discovery of `federation_extended_list_endpoint`. Flags: `--from`, `--limit`, `--updated-after`, `--updated-before`, `--audit-timestamps`, `--claims` (repeatable), `--entity-type`, `--trust-marked`, `--trust-mark-type`, `--intermediate`, `--extended-list-endpoint` (discovery override). Numeric option values are validated.

## [0.3.0] - 2026-05-12

### Changed

- Align with OpenID Federation 1.1 Final and OpenID Connect for OpenID Federation 1.1 Final (published 2026-05-11).

## [0.2.0] - 2026-04-28

### Changed

- Relicensed from MIT to Apache License 2.0. Includes `NOTICE` file.

## [0.1.0] - 2026-04-21

Initial release.
