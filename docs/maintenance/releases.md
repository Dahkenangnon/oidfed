# Releasing packages

Every package has its own version and release history. A release of `@oidfed/core`
uses a tag such as `core/v2.0.1` and a GitHub Release with that package's notes.
The same applies to Authority, Leaf, OIDC, Wallet, Crypto, and the CLI.

`all` is a command selector. It selects the seven publishable packages without giving
them a shared version or creating an aggregate tag or GitHub Release. For example,
a patch batch can release Core at `2.0.1` and Authority at `2.1.1` if they started at
different versions. Historical coordinated tags remain available as changelog baselines.

## Prepare and review

Use a supported Node version and the repository's pinned pnpm version. Fetch the
release tags before preparing changes so the changelog starts at the latest applicable
release. Then preview the version changes and generated changelogs:

```bash
git fetch origin --tags
pnpm release core patch --dry-run
pnpm release all minor --dry-run
```

Prepare the selected package files:

```bash
pnpm release core patch --prepare
pnpm release all minor --prepare
```

For the v3 batch, prepare a major release individually for core, authority, leaf, OIDC, wallet, and CLI. The batch also includes the first public Crypto release at `1.0.0`. Verify its trusted publisher before dispatch and confirm that the saved Core manifest resolves to the Crypto version in the batch.

Each selected package's own version is bumped. Its changelog is generated from its
nearest applicable release tag. The private root package and root changelog are not
versioned by these commands. Edit the generated notes so they explain changes a
consumer needs to understand, then commit and merge the reviewed files into `main`.
Preparation never commits, tags, pushes, or publishes.

## Start publication

Wait for the reviewed commit's package CI and security checks. From a clean checkout
of that commit in the upstream repository, run:

```bash
pnpm release core --publish
pnpm release all --publish
```

The helper fetches `origin/main`, checks that the local commit belongs to it, and
dispatches the Release workflow on `main`, passing the exact source SHA. It does not
push the local branch. Automatic one-shot release and `--finalize` commands are not
supported; prepare and review first, then publish the committed versions.

An individual scoped tag pushed for a reviewed main commit also triggers a single
package release. For a batch, use the helper: it dispatches one coordinated run and
lets that run create each package's tag and GitHub Release. Workflow-created tags do
not start another publishing run.

The workflow has three jobs:

1. **Verify and package** checks the source commit, package versions, notes, and CI
   results with read-only permissions. It builds and packs once, validates the saved
   archives, and uploads an immutable `release-bundle` artifact retained for 30 days.
2. **Publish verified archives** downloads that bundle, verifies its origin and
   integrity, and publishes its selected packages in dependency order. Only this job
   can request npm's short-lived OIDC credentials.
3. **Complete package releases** confirms npm's versions and integrity values, creates
   each missing annotated tag at the verified commit, and publishes the corresponding
   GitHub Release with its notes and checksum. Only this job has repository-write
   permission.

Package CI, including the memory and PostgreSQL storage job, and the security workflow must have passed for the exact source SHA in
this repository. Pending checks are allowed up to 20 minutes to complete. Missing,
failed, cancelled, or incomplete checks stop the release. Application-only checks
and OpenID conformance runs are not part of this package release gate.
Completed workflows missing a required job fail immediately with its workflow, run,
and job name. Timeouts list missing and pending jobs separately.
The required security jobs are the scoped source/dependency/artifact checks and
custom CodeQL. The scoped job runs the local rule fixtures and security lint.
Scheduled fuzzing and mutation checks remain separate.

## Archives, dependencies, and versions

The saved bundle contains the checked package archives, per-package release notes,
and a manifest recording package identities, versions, scoped tags, source and
workflow commits, the originating run, distribution tags, and integrity hashes.
The publisher does not rebuild or repack. The source, manifest, archive contents,
and npm integrity must agree.

A batch publishes Core before packages that require it. An internal dependency not
included in the selection must already have a published version satisfying the packed
range. If it does not, include it in the batch or publish it first.

Stable versions use npm's `latest` distribution tag. Prerelease versions use `next`;
the helper's preparation options remain `patch`, `minor`, and `major`. A missing stable
version older than npm's current `latest` is rejected so publication cannot move
`latest` backward. An already published, identical version can be recognized during
recovery without changing its distribution tag.

The publisher uses npm **11.21.2**, not a floating `latest` CLI. GitHub Actions are
pinned by commit. Publishing jobs share a queue so overlapping package releases do
not publish simultaneously; validation jobs can run independently.

## Trusted publishing setup

Create a GitHub environment named `npm`, permitting `main` and the seven package tag
patterns (`core/v*`, `authority/v*`, `leaf/v*`, `oidc/v*`, `wallet/v*`, `cli/v*`, and `crypto/v*`).
Starting publication is the authorization to release; the environment does not add
a separate review step by default.

For each npm package, configure its trusted publisher with:

- GitHub owner: `Dahkenangnon`.
- Repository: `oidfed`.
- Workflow filename: `release.yml`.
- Environment: `npm`.
- Permission to publish directly with `npm publish`.

Keep the npm and GitHub environment settings aligned. No long-lived npm token is
needed. Provenance is requested for each published archive. Keep the repository's
required CodeQL check aligned with `CodeQL security-extended (six packages)`.

See the [security checks](security-checks.md) for scanner setup. The workflow installs
the pinned scanners and runs the consumer checks against the six saved library archives. The dependency scan covers all published packages, including the CLI. Source checks cover the six libraries. The CLI also receives its release manifest and test checks.

## Recover an interrupted release

npm cannot overwrite an existing package version. A batch can therefore leave some
packages published if a later package fails. The workflow summary distinguishes
published, already-present, failed, and incomplete packages.

Resume a saved Release run with:

```bash
pnpm release --resume 123456789
```

Recovery verifies the original repository, workflow, successful verification job,
source commit, and saved archive hashes. It reuses the saved archives instead of
building again. A version already in npm is skipped only if its name, version, and
integrity match. A mismatch stops recovery. Registry authentication errors, outages,
and malformed responses are failures, not evidence that a version is absent.

An uncertain publish is checked against npm before it is reported as successful.
Registry propagation checks are bounded. If confirmation remains unavailable, the
run stops and retains the saved bundle for recovery.

If npm publication succeeded but GitHub Release completion failed, recovery can
finish the missing tags, checksum uploads, or draft releases. Existing tags must
identify the same source commit; they are never moved. A GitHub Release becomes public
only after its npm version has been confirmed and its checksum uploaded.

Download the saved bundle from the original workflow run if investigation is needed.
Once its retention period expires, recovery refuses to rebuild substitute archives.
Expired artifacts or conflicting registry contents require investigation before a new
release is prepared.
