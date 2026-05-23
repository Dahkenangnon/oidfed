# Changelog

Repository-wide changes (tooling, licensing, docs, release automation, cross-cutting spec updates) are tracked here. Per-package changes are tracked in each package's own `CHANGELOG.md`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
