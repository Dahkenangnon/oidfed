# Releasing packages

Run release commands with the supported Node and pinned pnpm versions.
Use a package name for one package or `all` for a batch. Each package has
its own version, changelog, and scoped tag, such as `core/v<version>`.

## Prepare and publish

```sh
git fetch origin --tags
pnpm release core patch --dry-run
pnpm release core patch --prepare
```

Review the generated changelog and manifest, then merge them into `main`.
From a clean checkout of the reviewed commit on upstream `main`, run:

```sh
pnpm release core --publish
```

The workflow requires package CI, PostgreSQL storage checks, and security
checks for the exact commit. It saves verified archives in a
`release-bundle` artifact for 30 days, publishes them in dependency order,
then creates the scoped GitHub Releases and tags. Include internal dependencies
in the batch when npm has no version that satisfies the packed range.

## Trusted publishing

In GitHub, allow `main` and the package tag patterns `core/v*`,
`authority/v*`, `leaf/v*`, `oidc/v*`, `wallet/v*`, `cli/v*`, and
`crypto/v*` in the `npm` environment.

For each package, configure npm to trust `Dahkenangnon/oidfed`,
`release.yml`, and the `npm` environment. Enable direct publication with
`npm publish`.

## Recover a release

Check the workflow summary, then resume using the saved Release run ID:

```sh
pnpm release --resume 123456789
```

Recovery reuses the saved bundle and skips versions whose npm integrity
matches. If the bundle expired or npm reports a mismatch, investigate before
preparing another release.
