# Changelog

All notable changes to `@oidfed/cli` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
