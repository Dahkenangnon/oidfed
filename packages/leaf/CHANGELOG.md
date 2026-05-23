# Changelog

All notable changes to `@oidfed/leaf` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-05-23

### Changed

- **BREAKING (install-tree).** `@oidfed/core` moved from `dependencies` to `peerDependencies`. Consumers MUST install `@oidfed/core` alongside `@oidfed/leaf`. The peer range is `^0.4.0`. This guarantees a single resolved `@oidfed/core` when `@oidfed/leaf` is installed beside its siblings (`@oidfed/authority`, `@oidfed/oidc`); the previous model could install two side-by-side copies and silently break module identity.
- Realigned with the `0.4.x` line of `@oidfed/core` and sibling packages.

## [0.3.0] - 2026-05-12

### Changed

- Align with OpenID Federation 1.1 Final and OpenID Connect for OpenID Federation 1.1 Final (published 2026-05-11).

## [0.2.0] - 2026-04-28

### Changed

- Relicensed from MIT to Apache License 2.0. Includes `NOTICE` file.

## [0.1.0] - 2026-04-21

Initial release.
