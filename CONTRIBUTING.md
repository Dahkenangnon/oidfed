# Contributing to @oidfed

Thank you for your interest in contributing to the OpenID Federation TypeScript implementation.

## Prerequisites

- Node.js >= 22
- pnpm >= 10

## Setup

```bash
git clone https://github.com/Dahkenangnon/oidfed.git
cd oidfed
pnpm install
pnpm build
pnpm test
```

## Development Workflow

1. Create a feature branch from `main`: `git checkout -b feat/scope/my-feature` (e.g. `feat/core/trust-mark-validation`, `fix/oidc/registration-schema`)
2. Write tests first (TDD is the default workflow)
3. Implement your changes
4. Run the full verification loop:

```bash
pnpm typecheck
pnpm test
pnpm test:e2e
pnpm lint
pnpm build
pnpm typecheck:apps  # required when apps/* or internal/* changes
pnpm test:apps       # required when apps/* or internal/* changes
pnpm build:apps      # required when apps/* or internal/* changes
```

5. Commit using conventional commits (see below)
6. Open a pull request against `main`

## Commit Conventions

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(core): add trust mark delegation validation
fix(oidc): correct explicit registration response schema
docs: update architecture decision record for package split
test(authority): add subordinate statement edge cases
chore: update dependencies
```

Scope should be the package name without the `@oidfed/` prefix: `core`, `authority`, `leaf`, `oidc`, `cli`, `explorer`, `home`, `learn`, `ui`.

## Pull Request Process

1. Ensure the package/tool checks pass (`typecheck`, `test`, `lint`, `build`), plus the `*:apps` checks when changing apps or internal UI
2. Update relevant documentation if behavior changes
3. Add or update tests for any new functionality
4. Keep PRs focused — one logical change per PR
5. Fill out the PR template

## Code Style

Formatting and linting are handled by [Biome](https://biomejs.dev/). Run `pnpm lint:fix` to auto-fix issues.

## Testing

The verification commands are split by release scope. Unqualified commands validate the published packages and tools; `*:apps` commands validate the applications and their internal UI dependencies.

The test setup is split by purpose:

| Scope | Framework | Location |
|---|---|---|
| Unit (`core`, `authority`, `leaf`, `oidc`) | QUnit via TAP | `tests/tap/` |
| CLI (`tools/cli`) | Vitest | `tools/cli/test/` |
| Explorer (`apps/explorer`) | Vitest | `apps/explorer/test/` |
| E2E | Vitest | `tests/e2e/` (requires `pnpm setup:e2e` first) |

The 4 spec packages are framework-agnostic and run identically on Node, Bun, Deno, workerd, Electron, and browsers — the TAP suite is the sole unit-test gate.

Commands:

```bash
pnpm test                    # published surface: 6 TAP runtimes + tools
pnpm quick:test              # fast published-surface check: Node TAP + tools
pnpm test:apps               # application tests (currently Explorer)
pnpm test:tap                # all 6 TAP runtimes
pnpm test:tap:bun            # one runtime (debug aid) — same for deno/workerd/electron/browser
pnpm test:coverage           # c8 coverage with per-package thresholds
pnpm test:e2e                # e2e suite (Node only)
pnpm typecheck               # packages, tools, and TAP types
pnpm typecheck:apps          # apps and internal UI
pnpm build                   # packages and tools
pnpm build:apps              # apps and internal UI dependencies
```

## Releasing

Releases are fully automated via GitHub Actions. Maintainers only need to run one command from `main`:

```bash
# Single package (patch | minor | major)
pnpm release core patch
pnpm release authority minor
pnpm release oidc major

# All five packages at once (same version bump applied to all)
pnpm release all patch
```

Before running the release command, add your changes to the `## [Unreleased]` section in the relevant changelog:

- **Single package release** → edit `<package-dir>/CHANGELOG.md` (e.g. `packages/core/CHANGELOG.md`)
- **All-packages release** → edit the root `CHANGELOG.md` (repo-wide changes only)

The script handles the rest automatically.

The script (`scripts/release.mjs`):
1. Bumps the package version(s) in `package.json`
2. Renames `## [Unreleased]` → `## [<X.Y.Z>] - <today>` in `CHANGELOG.md` and inserts a fresh empty `## [Unreleased]` above it
3. Creates a conventional commit (`chore(<scope>): release v<X.Y.Z>`) that includes `CHANGELOG.md`
4. Pushes a scoped tag (`core/v0.2.1`, `all/v0.3.0`, …)

The tag push triggers `.github/workflows/release.yml`, which validates, builds, creates a GitHub Release with auto-generated notes, and publishes to npm.

## Questions?

Open a [discussion](https://github.com/Dahkenangnon/oidfed/discussions) or file an issue.
