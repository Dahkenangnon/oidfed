# Changelog

Repository-wide changes (tooling, licensing, docs, release automation, cross-cutting spec updates) are tracked here. Per-package changes are tracked in each package's own `CHANGELOG.md`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0] - 2026-06-25

### Refactor

* context propagation, type exports and request overrides ([d6e9174](https://github.com/Dahkenangnon/oidfed/commit/d6e91742f9e32818caf96d05673f86a01fc15364))
* migrate E2E scenarios and OP participant to new class-based facades ([1e6f5e5](https://github.com/Dahkenangnon/oidfed/commit/1e6f5e56cadb107f4a5d860a4ce39adf2455229c))


## [0.7.0] - 2026-06-24

### Features

* export OIDCRegistrationAdapter class from public entrypoint ([de2c74c](https://github.com/Dahkenangnon/oidfed/commit/de2c74cf87a0fd9d0dc3fd260b5db761548ab064))

### Refactor

* stabilize API exports and add strict metadata schemas ([f23c205](https://github.com/Dahkenangnon/oidfed/commit/f23c205d2634f963bca810db8cb0dc6ad2be459c))


## [0.6.1] - 2026-06-24

_No user-visible changes — released as part of the coordinated wave._


## [0.6.0] - 2026-06-24

### Features

* relax entityId and authorityHints parameter type constraints ([07a3da5](https://github.com/Dahkenangnon/oidfed/commit/07a3da5618a740f6b7ed5547fb45c0b2bdf8ec08))
* unify runtime errors to monadic Result ([ba58a65](https://github.com/Dahkenangnon/oidfed/commit/ba58a656eec56ff34ef0ce1254b5747210219e17))
* export standard policy operators enum and re-export common core primitives ([92aeda6](https://github.com/Dahkenangnon/oidfed/commit/92aeda67ff5c8279b8211e089fc10374d7803433))
* unify persistence behind storage adapter ([f622fca](https://github.com/Dahkenangnon/oidfed/commit/f622fca5955bfee03c90192308bd86bd3e1ec9ed))
* consolidate sidebar links ([e23e712](https://github.com/Dahkenangnon/oidfed/commit/e23e7120598d1fc0ea35fe914c229e63d7f7d772))
* separate federation and OIDC signing keys ([0664c90](https://github.com/Dahkenangnon/oidfed/commit/0664c90641288f41b561588d954badd7f6ae5a4e))
* enhance the npm published keyworks ([a0e38c4](https://github.com/Dahkenangnon/oidfed/commit/a0e38c46c7fcafd75341a3aa306350e8f0f1df8d))
* migrate biome ([32cbaaf](https://github.com/Dahkenangnon/oidfed/commit/32cbaaf3f39ba7bb3616fbece93ab9b00f1300d9))
* share github icon across apps ([1faf78e](https://github.com/Dahkenangnon/oidfed/commit/1faf78e64cfc22fc5d56e8965c9efb755dfe865f))
* align navigation and simplify not found ([3e646bb](https://github.com/Dahkenangnon/oidfed/commit/3e646bb6622679f80c801bef0e7b8f5b321c1d65))
* polish layout navigation ([1b0ed2b](https://github.com/Dahkenangnon/oidfed/commit/1b0ed2b90c237b937b8a87edee13affca499c9ba))
* promote demo federation links ([108d507](https://github.com/Dahkenangnon/oidfed/commit/108d5072476907e5b8875f96bd261fda95b95feb))

### Bug Fixes

* harden public API types and add trust anchor helper ([ad06c9b](https://github.com/Dahkenangnon/oidfed/commit/ad06c9baaea806990f76b25371a4bd90563da9e4))
* harden public API types and add trust anchor helper ([3283001](https://github.com/Dahkenangnon/oidfed/commit/3283001bbd291a42843c5e768d34405c0b064eac))
* review the public api of every pkg ([a95c473](https://github.com/Dahkenangnon/oidfed/commit/a95c473f1a92bdd55a248fcc1a8b319da2208295))
* verify request objects with protocol keys ([c759b87](https://github.com/Dahkenangnon/oidfed/commit/c759b87f65fd04e9c35d695ba0ffbeb9917f21b2))
* bump esbuild to patched version ([4f7b42f](https://github.com/Dahkenangnon/oidfed/commit/4f7b42f6ed31ec8cde8d1ca4e9eb8df9d9c24080))
* add core dependency for package builds ([30d986d](https://github.com/Dahkenangnon/oidfed/commit/30d986df000c85c8e0320cc6b019c1c89d8015c7))
* upgrade vitest to ^4.1.0 to fix CVE-2026-47429 (GHSA-5xrq-8626-4rwp) ([98735bf](https://github.com/Dahkenangnon/oidfed/commit/98735bf40595d0c111273920855b5469bfa88396))

### Refactor

* implement new class-based developer experience and API design ([b2fe982](https://github.com/Dahkenangnon/oidfed/commit/b2fe98287f0c553feded3ec11b8b0059ebb41061))


### Changed

- Unified non-key authority persistence behind one transactional adapter while preserving separate federation key-provider custody.

## [0.5.2] - 2026-05-28

### Bug Fixes

* publish via npm trusted publishing for sigstore provenance ([6990c7d](https://github.com/Dahkenangnon/oidfed/commit/6990c7d7da4a27a7f752192a7f02fc56d2e1d5a8))
* load version dynamically from package json ([2ac3e14](https://github.com/Dahkenangnon/oidfed/commit/2ac3e14d38a3e5d84c7d56dde4dc74163d3786bc))


## [0.5.1] - 2026-05-28

### Added

- **Supply chain hardening:** Dependabot configuration (weekly, grouped minor/patch for npm + github-actions, `chore(deps)` scope for both production and development dependencies); npm publish provenance via GitHub OIDC (`id-token: write` + `npm publish --provenance` in `release.yml`); pnpm overrides for `qs` (≥6.15.2) and `postcss` (≥8.5.10) to consume CVE patches transitively; branch protection on `main` with 14 required status checks including default-setup CodeQL.
- **GitHub issue forms** replacing the old `.md` templates: `bug.yml`, `spec-compliance.yml`, `feature.yml`, plus a `config.yml` pointing security and discussion contacts to the right places.
- **Pull request template** extended with Spec impact / Compatibility impact / Breaking change sections.
- **Cross-OS hygiene files:** `.editorconfig` and `.gitattributes`.
- **Documentation entry-points:** root `docs/README.md` (task-oriented front door), root `examples/README.md` pointing to the `fed-oidfed-com` reference deployment, per-package README badges (CI, npm version, downloads, license, install size).
- **End-to-end coverage** of the OP→RP `request_uri` Request Object fetch path, gated by a topology-derived host allowlist to prevent SSRF.
- **Engines field** (`node: >=22`) on every Node-only workspace package (root, apps, internal/ui); protocol packages remain runtime-agnostic.

### Changed

- Root README refreshed with a sparse badge row, 30-second start, and a maturity box; the README banner image was removed and the orphaned banner assets deleted from `internal/assets/`.
- `SECURITY.md` rewritten to explicitly state that only the upcoming stable `1.x.y` line will receive security fixes; the current `0.x.y` prerelease line receives no backports.
- `apps/explorer` and `apps/learn` READMEs reduced to title + one descriptive paragraph; new `apps/home/README.md` added.
- Repository topic list pruned and reset; `trusted-execution-environment` removed; `openid-connect`, `oauth2`, and `trust-mark` added.
- Toolchain bumps via Dependabot: `turbo`, `biome`, `esbuild`, `tsx`, `ts-blank-space`, `undici`, `@playwright/test`, `@types/qunit` and others — see PR #7. GitHub Actions bumped: `actions/checkout`, `actions/setup-node`, `pnpm/action-setup` to v6.
- App-only dependency refresh: `react-day-picker` 9 → 10, `shiki` 3 → 4, `jsdom` 26 → 29, `@types/node` 22 → 25, `@base-ui/react` 1.3 → 1.5 (with a corresponding `internal/ui` source fix in `input.tsx` to bridge the changed `InputPrimitive.Props` shape to native `InputHTMLAttributes`).

### Fixed

- Stale `OpenID Federation 1.1 (draft)` label in `apps/learn` SEO metadata generator; 1.1 is now correctly marked final.
- Trust mark signature tampering test in the authority TAP suite is now deterministic (no longer flakes on Deno).
- The e2e OP harness's `request_uri` fetch no longer accepts arbitrary user-supplied URLs; it is gated by a topology-derived RP host allowlist.

### Removed

- Redundant advanced `CodeQL` workflow that conflicted with GitHub's default code-scanning setup.
- Orphaned banner assets under `internal/assets/`.

## [0.5.0] - 2026-05-23

## [0.3.0] - 2026-05-12

### Changed

- **Spec status:** OpenID Federation 1.1 and OpenID Connect for OpenID Federation 1.1 are now **Final** (published 2026-05-11). The ecosystem page, `llms.txt` files, and learn content have been updated accordingly.
- **Release automation:** replaced 18 manual `release:*:*` npm scripts with a single `pnpm release <package> <bump>` command backed by `scripts/release.mjs` and `.github/workflows/release.yml`. Tags follow the pattern `<scope>/v<X.Y.Z>` (e.g. `core/v0.2.1`, `all/v0.3.0`).

## [0.2.0] - 2026-04-28

### Changed

- Relicensed published libraries (`@oidfed/core`, `@oidfed/authority`, `@oidfed/leaf`, `@oidfed/oidc`, `@oidfed/cli`) and the repository root from MIT to **Apache License 2.0**. Apps (`@oidfed/home`, `@oidfed/explorer`, `@oidfed/learn`) and `internal/ui` remain **MIT**. Each Apache-2.0 package now ships a `NOTICE` file with copyright and third-party attribution.

## [0.1.0] - 2026-04-21

Initial release of the OpenID Federation TypeScript implementation.
