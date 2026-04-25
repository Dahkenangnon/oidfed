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

1. Ensure all checks pass (`typecheck`, `test`, `lint`, `build`)
2. Update relevant documentation if behavior changes
3. Add or update tests for any new functionality
4. Keep PRs focused — one logical change per PR
5. Fill out the PR template

## Code Style

Formatting and linting are handled by [Biome](https://biomejs.dev/). Run `pnpm lint:fix` to auto-fix issues.

## Testing

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
pnpm test                    # full cross-runtime: 6 TAP runtimes + cli + explorer
pnpm quick:test              # fast local: Node TAP + cli + explorer
pnpm test:tap                # all 6 TAP runtimes
pnpm test:tap:bun            # one runtime (debug aid) — same for deno/workerd/electron/browser
pnpm test:coverage           # c8 coverage with per-package thresholds
pnpm test:e2e                # e2e suite (Node only)
```

## Questions?

Open a [discussion](https://github.com/Dahkenangnon/oidfed/discussions) or file an issue.
