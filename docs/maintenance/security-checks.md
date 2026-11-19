# Checking the protocol packages

The security checks cover `@oidfed/core`, `@oidfed/authority`, `@oidfed/leaf`, `@oidfed/oidc`, `@oidfed/wallet`, and `@oidfed/crypto`. They also check the workflows that validate and publish those packages. Applications, the CLI, and their own dependencies stay outside these checks.

Run the existing build, tests, lint, and type checks alongside them. Protocol tests establish the expected behavior; the additional tools help find unsafe data handling, missing assertions, packaging mistakes, and regressions in the tests themselves.

## Set up the tools

Use a Node version that satisfies the root `package.json` engine range and the pinned pnpm version. The repository's `.node-version` selects Node 22.22.2. With nvm, select it before installing dependencies:

```bash
nvm install "$(cat .node-version)"
nvm use "$(cat .node-version)"
pnpm install --frozen-lockfile
pnpm security:install
```

`security:install` supports Linux x64. It downloads pinned OSV-Scanner, Gitleaks, actionlint, ShellCheck, and zizmor releases from their maintainers and verifies their SHA-256 digests. The installer extracts only each tool's allowlisted executable into the workspace cache. The runner finds these tools automatically; no shell activation or PATH override is needed.

Source checks use the existing ESLint and TypeScript dependencies from the pnpm lockfile. Python is not required. None of these tools is shipped as a runtime dependency of the library.

Build the six packages, then run the checks:

```bash
pnpm --filter @oidfed/core --filter @oidfed/authority --filter @oidfed/leaf --filter @oidfed/oidc --filter @oidfed/wallet --filter @oidfed/crypto build
pnpm security:check
```

An `Unsupported engine` warning means the active Node version does not satisfy the repository's requirements. Switch Node versions before continuing. pnpm may name other workspaces in this warning; that does not extend the security scan to those applications.

The GitHub security workflow runs the same checks on pull requests and `main`, with a weekly full dependency scan. CodeQL uses advanced setup: its `security-extended` suite runs in the custom workflow with analysis paths limited to the six packages. Keep GitHub's default CodeQL setup disabled for this repository; enabling it blocks uploads from the custom workflow. To switch an existing repository, open **Settings → Advanced Security → CodeQL analysis → Switch to advanced**, disable default setup, and verify that the custom job uploads its results successfully.

## Choose a check

| Command | What it checks |
|---|---|
| `pnpm security:test` | Scanner scope, dependency extraction without an installation, directed-cycle matching, and detection and redaction of an unissued secret canary. Install the native tools first. |
| `pnpm security:lint` | TypeScript-backed promise handling, unsafe `any` propagation, exhaustive switches, risky regular expressions, JSDoc names, and local AST rules for dynamic execution, request-controlled dispatch, unsafe JSON copying, transport bypasses, and secret logging. Biome remains the formatter and general linter. |
| `pnpm security:architecture` | Package layering, private cross-package imports, Node built-ins in runtime source, and new runtime import cycles. |
| `pnpm security:secrets` | Redacted Gitleaks scans of the six package directories. Packed artifacts are scanned separately by `security:artifacts`. |
| `pnpm security:dependencies` | OSV advisories for exact production and optional dependency versions resolved from the six packages. Workspace links are traversed; app, tool, and development dependencies are excluded. |
| `pnpm security:artifacts` | Packed manifests and declarations with publint and Are the Types Wrong, secret scanning, isolated NodeNext ESM/CommonJS and bundler consumers, runtime imports, and public contract tests with tsd. Build first. |
| `pnpm security:workflows` | actionlint, with required ShellCheck analysis, and zizmor checks of every YAML file in `.github/workflows`, including CI, conformance, security, and release. Zizmor's regular reporting mode gates findings of low severity or higher; pedantic findings require a separate review. |
| `pnpm security:advisory` | Knip's unused-code report and jscpd's duplication report. These help reviewers choose useful cleanup work. They do not require deleting a public API or consolidating similar protocol rules. |

`security:check` runs the required local checks above, excluding the advisory, fuzz, and mutation commands. CodeQL runs in GitHub. The full runtime suite also includes generated properties for prototype safety, preservation of caller-owned metadata, selector semantics, and concurrent replay claims.

The workflow runner validates GitHub's queued-concurrency settings directly because actionlint 1.7.12 does not recognize `queue` yet. Only that unsupported-key diagnostic is exempted; invalid queue values, cancellation conflicts, shell issues, and other workflow errors still fail the check. During a release, `RELEASE_ARTIFACT_DIR` supplies the saved bundle to the artifact checks so they inspect the archives that will be published without packing again.

Dependency scanning builds a temporary CycloneDX input from pnpm's lockfile-backed production graph. Only package names and versions go to the advisory service. On a pull request, `SECURITY_BASE_SHA` selects a base commit so the check scans newly introduced versions. If that commit predates a scoped package or lacks another required input, the check explains the missing baseline and scans the complete current graph. Invalid commits and corrupt graphs fail. Scheduled and ordinary local runs also scan the full scoped graph. A failed scan fails the command.

## Maintain the source rules

`security:lint` analyzes source in all six library packages and fails if a package contributes no analyzed files. Parser errors, scanner configuration errors, findings, and warnings also fail the command. The local AST rules cover JavaScript and TypeScript; the typed checks use each TypeScript project's configuration. `security:test` exercises the rules with both unsafe and safe examples before the CI source scan runs.

The dispatch rule follows values obtained through `.get()` and `JSON.parse()` through local aliases, assignments, destructuring, and TypeScript casts. It accepts an applicable `Object.hasOwn()` branch or early-exit guard only while the checked registry and key remain unchanged. This is bounded, intraprocedural analysis: it does not prove the safety of arbitrary helper functions or track all mutations through aliases and calls. CodeQL's separate security analysis and human review remain necessary.

The logging rule recognizes `privateKey`, `clientSecret`, `clientAssertion`, `client_secret`, and `client_assertion` in any argument position of `debug`, `info`, `warn`, and `error` calls. Renamed values, interpolation, and nested data still need review.

Keep a negative and a nearby safe example for every rule change in `scripts/security/eslint-rules.test.mjs`. Verify the expected rule identifiers and source locations, then run `security:test` and `security:lint`. Update native scanner pins and checksums together in the installer; retain checksum verification and allowlisted extraction.

## Exercise the parsers and test guards

Run a short coverage-guided fuzzing session:

```bash
pnpm security:fuzz
# A longer session, up to 300 seconds:
FUZZ_SECONDS=120 pnpm security:fuzz
```

Jazzer.js instruments a bundle built from the current package source. The target exercises raw JWT payload processing and endpoint selectors. Seeds include duplicate policy members, JavaScript structural names, and deeply nested JSON. Inputs, corpora, and failure artifacts go to a temporary directory. A failed run prints its location for investigation.

Use mutation testing to check that the selector and credential-parameter tests reject broken guards:

```bash
pnpm security:mutation
```

Stryker currently mutates only `packages/core/src/endpoint-parameters.ts`, which the focused test imports directly. Its percentage measures that file's selector and credential-parameter tests, not mutation coverage across the library. The check requires a score of at least 95%. Review surviving mutations: changing an error message can be harmless, while accepting an extra selector value or allowing a credential override needs a test. The mutation report is written under the system temporary directory.

The weekly and manually triggered GitHub jobs run bounded fuzz and mutation checks. A timeout or interrupted run is incomplete verification.

## Review findings

Reproduce a finding against the affected source and its specification before changing behavior. Metadata extension names and values remain open where the protocol allows them, and publication-time metadata can still be completed by a Superior. Keep those cases in the tests.

The architecture check recognizes the exact existing cycles listed in `scripts/security/known-cycles.mjs`. A different directed cycle fails. Review any proposed exception as an architectural change. Knip protects the public entrypoints, and its reports can still include internal exports used only by tests or unused convenience barrels; check callers and package exports before removing anything.

Keep exceptions narrow and explain them beside the code or configuration. The authority context builder has one typed-lint exception because TypeScript's variadic `Object.assign` overload loses the types of its configuration fragments. Security-rule fixtures are strings analyzed by ESLint; their unsafe examples are never executed.
