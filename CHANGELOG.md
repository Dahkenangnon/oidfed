# Changelog

Repository-wide changes (tooling, licensing, docs, release automation, cross-cutting spec updates) are tracked here. Per-package changes are tracked in each package's own `CHANGELOG.md`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
