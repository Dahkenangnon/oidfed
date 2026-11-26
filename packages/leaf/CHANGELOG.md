# Changelog

All notable changes to `@oidfed/leaf` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.0.0] - 2026-11-26

### Breaking Changes

* authorize federation requests and scope resolve reuse ([8a93565](https://github.com/Dahkenangnon/oidfed/commit/8a935655f5ca15c5f4fdc00b5b8c31be297f1978))
* enforce federation artifact signing policy ([888e2a8](https://github.com/Dahkenangnon/oidfed/commit/888e2a86308baad021346123c109549c3740a704))
* require federation POST selectors in the form ([7997498](https://github.com/Dahkenangnon/oidfed/commit/7997498008d5e674a8488827bca84e268c9bfb64))
* unify storage and federation host contracts ([2882619](https://github.com/Dahkenangnon/oidfed/commit/28826192c47f6eb898a0d1f590c87aa12b3a3d5d))
* require host-provided crypto ([d748f11](https://github.com/Dahkenangnon/oidfed/commit/d748f1168d8819ea5943433400b858e26f7030fb))

### Features

* serve historical keys and validate endpoint metadata ([6497391](https://github.com/Dahkenangnon/oidfed/commit/64973910bc04840efb690972b1cd14846e780808))
* add standalone federation resolver hosting ([86ea2bc](https://github.com/Dahkenangnon/oidfed/commit/86ea2bc5c3fe850a1bb1ace9cc2aba9f51e7cedb))
* support critical extensions in Entity Statement publication ([a558bea](https://github.com/Dahkenangnon/oidfed/commit/a558bea6f091c8e0bdcf31b0d4853dabde5df28e))
* host trust mark endpoints and manage publication ([df7e462](https://github.com/Dahkenangnon/oidfed/commit/df7e462a79768d0accbb1bd353222854f8a2555b))

### Bug Fixes

* correct metadata, theming, links and docs scrolling ([c6053e4](https://github.com/Dahkenangnon/oidfed/commit/c6053e47549cfa8bce16d99105de940c7c810dd3))
* correct ESM and CommonJS declaration exports ([3475f0b](https://github.com/Dahkenangnon/oidfed/commit/3475f0bbc7cc7eea7c8501e02acb83edd0970375))
* validate configured TTLs before publication ([633fad1](https://github.com/Dahkenangnon/oidfed/commit/633fad1efaf507166dc8d44266f3cd60e7745fda))
* isolate and safely compose host metadata ([9ec838a](https://github.com/Dahkenangnon/oidfed/commit/9ec838a3bbb49dcf0973f0a7051a30feada1b7c6))
* reject conflicting hosted role routes ([fc1c3af](https://github.com/Dahkenangnon/oidfed/commit/fc1c3af088cbe5ca267c15e48c31fc72b81ad828))
* normalize published entity identifiers once ([9e825ae](https://github.com/Dahkenangnon/oidfed/commit/9e825ae30716c98d845e0146d6e1041715e1453f))
* unify fixed endpoint selector matching ([d23a183](https://github.com/Dahkenangnon/oidfed/commit/d23a183e6f85950d27e2812f6830114fca517b8c))
* report configuration generation and serving failures ([162e0b9](https://github.com/Dahkenangnon/oidfed/commit/162e0b9bec3462d3fbed63bda6363056efb4e3c2))
* reject forbidden endpoint auth metadata ([9d39edd](https://github.com/Dahkenangnon/oidfed/commit/9d39edd4a44cb68c95e214ac990ef75c6a3329f2))

### Refactor

* share protocol helpers and remove dead code ([f299374](https://github.com/Dahkenangnon/oidfed/commit/f299374faab2822cd06c543832e0d959e5210c39))
* consolidate request handling ([34c96b2](https://github.com/Dahkenangnon/oidfed/commit/34c96b21c2ef4262557657d189ae139fa40257ac))


## [2.0.0] - 2026-10-26

### Added

- Optional Entity Collection Draft 01 endpoint hosting through core's shared service, including configured authentication and snapshot storage. ([3d69d77](https://github.com/Dahkenangnon/oidfed/commit/3d69d778bd4ea074826e89872467f65e6b2073ab))
- Validate composed wallet role metadata before publication and preserve permitted null claim-path wildcards. ([5863459](https://github.com/Dahkenangnon/oidfed/commit/58634591566fc500f3872b46b480d34d01a29a7b))

### Changed

- Reject authority-only Subordinate Events metadata on leaves. ([4c6398c](https://github.com/Dahkenangnon/oidfed/commit/4c6398cc568149ebeb01377e1df9cdee022ba44c))
- Reject authority-only Extended Listing metadata on leaves. ([6c1c8a6](https://github.com/Dahkenangnon/oidfed/commit/6c1c8a60c234574109aedc062ead11094e99f82a))

### Fixed

- Prevent older Entity Configuration builds from overwriting a refreshed cache. Reads during a refresh share the current build. Document when key publication, signer switching, and retirement require an explicit configuration refresh. ([f51d9c6](https://github.com/Dahkenangnon/oidfed/commit/f51d9c64859a099d1720ee66675cd442554aedde))
- Keep bundled TypeScript declaration generation working with TypeScript 6. ([a473ebb](https://github.com/Dahkenangnon/oidfed/commit/a473ebbb93d166ebcd69f9c8c52d376e48ff29fc))

## [1.0.0] - 2026-07-13

### Features

* add stable statement builders ([e726a5c](https://github.com/Dahkenangnon/oidfed/commit/e726a5ccbb24a816dba3356ba3b1607a3fbc3d6a))

### Bug Fixes

* align config docs and package claims ([ea093ac](https://github.com/Dahkenangnon/oidfed/commit/ea093acb7d3df03bbd43e90b30525681aedb7824))
* remove avoidable public any ([d0e754d](https://github.com/Dahkenangnon/oidfed/commit/d0e754d9a2f72fdf57b1bf584a131491a5ef4006))
* normalize endpoint routing and entity ids ([bdbf7f4](https://github.com/Dahkenangnon/oidfed/commit/bdbf7f4cadc29f7ac6b74b15a8d8e0c123d49363))
* require trust anchors for op registration ([36bd338](https://github.com/Dahkenangnon/oidfed/commit/36bd33813fdfced76f0930fa6da0b95e30297133))
* align public docs with class-only APIs ([eb6c359](https://github.com/Dahkenangnon/oidfed/commit/eb6c35953963b8dae0b9f700bfbe69ba92f223f4))

### Refactor

* clarify public role and key provider names ([1211280](https://github.com/Dahkenangnon/oidfed/commit/1211280b7cea233b6522830c149e8ac0abc7a352))


### Added

- `LeafConfig.trustAnchorHints` publishes preferred trust anchors as `trust_anchor_hints` in the Entity Configuration.

### Changed

- `LeafConfig.metadata` now uses core object-valued Entity Statement metadata typing, and role metadata composition no longer mutates the caller-provided metadata object.

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
