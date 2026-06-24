# Changelog

All notable changes to `@oidfed/leaf` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-06-24

### Features

* unify runtime errors to monadic Result ([ba58a65](https://github.com/Dahkenangnon/oidfed/commit/ba58a656eec56ff34ef0ce1254b5747210219e17))
* separate federation and OIDC signing keys ([0664c90](https://github.com/Dahkenangnon/oidfed/commit/0664c90641288f41b561588d954badd7f6ae5a4e))
* enhance the npm published keyworks ([a0e38c4](https://github.com/Dahkenangnon/oidfed/commit/a0e38c46c7fcafd75341a3aa306350e8f0f1df8d))

### Bug Fixes

* harden public API types and add trust anchor helper ([3283001](https://github.com/Dahkenangnon/oidfed/commit/3283001bbd291a42843c5e768d34405c0b064eac))
* review the public api of every pkg ([a95c473](https://github.com/Dahkenangnon/oidfed/commit/a95c473f1a92bdd55a248fcc1a8b319da2208295))
* add core dependency for package builds ([30d986d](https://github.com/Dahkenangnon/oidfed/commit/30d986df000c85c8e0320cc6b019c1c89d8015c7))

### Refactor

* implement new class-based developer experience and API design ([b2fe982](https://github.com/Dahkenangnon/oidfed/commit/b2fe98287f0c553feded3ec11b8b0059ebb41061))


### Changed

- **BREAKING.** Removed the duplicate top-level `LeafConfig.clock`; configure the NumericDate-seconds clock through `LeafConfig.options.clock`.
- Trust-chain discovery accepts readonly statement arrays directly.

## [0.5.2] - 2026-05-28

_No user-visible changes — released as part of the coordinated wave._


## [0.5.1] - 2026-05-28

### Changed

- Released alongside the coordinated 0.5.1 patch wave. No source changes; this version exists to keep `@oidfed/*` versions aligned.

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
