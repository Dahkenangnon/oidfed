# Contributing to @oidfed

Thank you for your interest in contributing to the OpenID Federation TypeScript implementation.

## Prerequisites

- Node.js >= 20
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

- Formatting and linting are handled by [Biome](https://biomejs.dev/)
- Run `pnpm lint:fix` to auto-fix issues
- TypeScript strict mode is enabled across all packages
- Use explicit types; avoid `any`

## Monorepo Structure

```
packages/             — npm-publishable spec libraries
  @oidfed/core        — federation primitives
  @oidfed/authority   — trust anchor / intermediate authority
  @oidfed/leaf        — leaf entity
  @oidfed/oidc        — OpenID Connect / OAuth 2.0 layer

tools/                — npm-publishable tooling
  @oidfed/cli         — command-line tool

apps/                 — deployed sites (private, not published)
  @oidfed/explorer    — federation topology explorer (explore.oidfed.com)
  @oidfed/home        — project homepage (oidfed.com)
  @oidfed/learn       — interactive course (learn.oidfed.com)

internal/             — private shared packages (not published)
  @oidfed/ui          — shared UI component library
```

Dependencies flow inward: `authority`, `leaf`, `oidc`, and `cli` depend on `core`. No cross-dependencies between sibling packages. Apps depend on `core` and `ui`.

## Testing

- Framework: Vitest
- Write unit tests alongside implementation in each package
- E2E tests live in `tests/e2e/` (requires `pnpm setup:e2e` first)
- Aim for coverage parity with existing packages

## Questions?

Open a [discussion](https://github.com/Dahkenangnon/oidfed/discussions) or file an issue.
