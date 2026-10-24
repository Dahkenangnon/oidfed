# Contributing to @oidfed

## Prerequisites

Use the Node.js version in `.node-version`, or another version supported by the `engines.node` range in [package.json](package.json). The repository requires pnpm >= 10 and pins its package manager version through `packageManager`.

## Setup

```bash
git clone https://github.com/Dahkenangnon/oidfed.git
cd oidfed
pnpm install
pnpm build
pnpm test
```

## Development workflow

Create a feature branch from `main`: `git checkout -b feat/scope/my-feature`. For example, use `feat/core/trust-mark-validation` or `fix/oidc/registration-schema`.

Write tests before implementing a change. Before opening a pull request, run:

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

Run `pnpm setup:e2e` before your first E2E test run to prepare the local certificates. Commit your changes using the conventions below, then open a pull request against `main`.

## Commit conventions

Use [Conventional Commits](https://www.conventionalcommits.org/) with a required scope:

```text
feat(core): add trust mark delegation validation
fix(oidc): correct explicit registration response schema
docs(repo): update architecture decision record
test(authority): add subordinate statement edge cases
chore(deps): update dependencies
```

For package changes, use the package name without `@oidfed/`, such as `core`, `authority`, or `cli`. For repository changes, use a scope such as `repo`, `deps`, or `ci`. [commitlint.config.js](commitlint.config.js) lists the allowed types and scopes.

Keep the full subject at 72 characters or fewer, including the type, scope, spaces, and references. Aim for about 50 characters, including the trailing PR reference, so it is easier to see in GitHub's file list. GitHub truncates subjects to fit the available width; no repository setting can guarantee that the reference stays visible on every screen. Put supporting details in the body and wrap body lines at 120 characters.

The local commit hook and CI run commitlint to enforce syntax and length. These checks also apply to bot-authored commits. If a generated subject is too long, shorten that commit's subject; editing only the final squash title leaves the original commits unchanged for PR checks.

Development commits do not need a PR number. If a subject includes a numbered reference, commitlint allows exactly one at the end, in the form `(#116)`. Leading, embedded, and duplicate references are rejected. Keep other issue references in the body.

## Pull requests

Keep each PR focused on one change and fill out the [PR template](.github/pull_request_template.md). Include tests for new behavior and update the relevant documentation when behavior changes. Check that the package and tool verification commands pass, along with the application checks when changing `apps/*` or `internal/*`.

### Merging in GitHub

Keep the PR title conventional and omit its own PR number. Choose **Squash and merge**, then review the generated commit message before confirming the merge.

Use one trailing PR reference:

```text
feat(authority): add subordinate events (#116)
```

Keep GitHub's generated `(#116)` suffix and shorten the description if needed. Include the suffix when counting the subject length. Do not add the number after the conventional prefix or repeat it in the PR title.

For consistent squash subjects, use **Settings → General → Pull Requests → Allow squash merging → Default to pull request title**. GitHub uses the PR title and number as the final subject.

Use the commit body to explain the change and retain issue-closing references:

```text
Publish signed subordinate histories with transactional event storage.

Closes #115
```

Use the PR number in the subject and the issue number in the closing reference. Review both fields before confirming the merge.

GitHub UI merges do not run local hooks. PR CI checks the branch's commits; CI on `main` checks the final squash commit after it is merged. Commitlint enforces conventional syntax, length, and the position of numbered subject references. Maintainers must check that the final UI message includes the correct PR number before merging.

## Code style

[Biome](https://biomejs.dev/) handles formatting and linting. Run `pnpm lint:fix` to apply its fixes.

## Testing

`pnpm test` and `pnpm build` cover the published packages and tools. Their `:apps` variants cover the applications and their internal UI dependencies.

`pnpm typecheck` also checks TAP tests, E2E tests, and scripts. `pnpm lint` uses the root Biome configuration. `pnpm test:e2e` runs the HTTPS federation scenarios.

| Scope | Framework | Location |
|---|---|---|
| Unit (`core`, `authority`, `leaf`, `oidc`) | QUnit via TAP | `tests/tap/` |
| CLI (`tools/cli`) | Vitest | `tools/cli/test/` |
| Explorer (`apps/explorer`) | Vitest | `apps/explorer/test/` |
| E2E | Vitest | `tests/e2e/` (requires `pnpm setup:e2e` first) |

The four specification packages are framework-agnostic. Their unit tests use the same TAP suite across Node, Bun, Deno, workerd, Electron, and browsers.

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

GitHub Actions publishes releases from scoped tags. The maintainer workflow separates preparation from publishing so you can review the changelog before committing, tagging, or pushing.

Preview the files that would change:

```bash
pnpm release core patch --dry-run
pnpm release all minor --dry-run
```

Prepare the release files:

```bash
pnpm release core patch --prepare
pnpm release all minor --prepare
```

`--prepare` writes package versions and changelog sections. Review and edit each generated `## [<X.Y.Z>] - <date>` section before finalizing:

- For a single package, edit its `CHANGELOG.md`, such as `packages/core/CHANGELOG.md`.
- For an all-packages release, edit the package changelogs and the root `CHANGELOG.md`. The root section starts empty for you to write notes that cover changes across packages.

Preparation does not commit, tag, or push. After reviewing the diff and changelogs, finalize the release:

```bash
pnpm release core --finalize
pnpm release all --finalize
```

`--finalize` checks the prepared versions and changelog sections, refuses unexpected dirty files, then creates the release commit and tag and pushes them. Tags such as `core/v0.8.1` and `all/v0.9.0` trigger `.github/workflows/release.yml`, which validates, builds, creates the GitHub Release from the committed changelog, and publishes to npm.

The one-shot command prepares and publishes without a changelog review step:

```bash
pnpm release oidc patch
```

Use it only when the generated changelog is already acceptable without editing.

## Questions

Open a [discussion](https://github.com/Dahkenangnon/oidfed/discussions) or file an issue.
