# Changelog

All notable changes to `@oidfed/cli` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
