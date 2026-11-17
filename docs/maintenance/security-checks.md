# Checking the protocol packages

The security checks cover `@oidfed/core`, `@oidfed/authority`, `@oidfed/leaf`, `@oidfed/oidc`, and `@oidfed/wallet`. They also check the workflows that validate and publish those packages. Applications, the CLI, and their own dependencies stay outside these checks.

Run the existing build, tests, lint, and type checks alongside them. Protocol tests establish the expected behavior; the additional tools help find unsafe data handling, missing assertions, packaging mistakes, and regressions in the tests themselves.

## Set up the tools

Use a Node version that satisfies the root `package.json` engine range and the pinned pnpm version. The repository's `.node-version` selects Node 22.22.2. With nvm, select it before installing dependencies:

```bash
nvm install "$(cat .node-version)"
nvm use "$(cat .node-version)"
pnpm install --frozen-lockfile
pnpm security:install
```

`security:install` supports Linux x64 and requires Python 3.12, 3.13, or 3.14 with `venv` and `pip`. It downloads pinned OSV-Scanner, Gitleaks, actionlint, ShellCheck, and zizmor releases from their maintainers and verifies their SHA-256 digests. Semgrep and every Python dependency are pinned by version and SHA-256 in an interpreter-specific lock. Only wheels are accepted; an unavailable wheel fails installation instead of starting a source build.

The installer recreates its generated Semgrep environment under `node_modules/.cache/spec-security/semgrep`, then checks dependency compatibility and the installed scanner version. This replaces packages from earlier installations without changing system Python. The runner finds the tools automatically; no shell activation or PATH override is needed. CI uses Python 3.12 for the main gate and tests fresh Semgrep installations on all three supported Python versions. The npm tools are pinned development dependencies. None of these tools is shipped as a runtime dependency of the library.

Build the five packages, then run the checks:

```bash
pnpm --filter @oidfed/core --filter @oidfed/authority --filter @oidfed/leaf --filter @oidfed/oidc --filter @oidfed/wallet build
pnpm security:check
```

An `Unsupported engine` warning means the active Node version does not satisfy the repository's requirements. Switch Node versions before continuing. pnpm may name other workspaces in this warning; that does not extend the security scan to those applications.

The GitHub security workflow runs the same checks on pull requests and `main`, with a weekly full dependency scan. CodeQL uses advanced setup: its `security-extended` suite runs in the custom workflow with analysis paths limited to the five packages. Keep GitHub's default CodeQL setup disabled for this repository; enabling it blocks uploads from the custom workflow. To switch an existing repository, open **Settings → Advanced Security → CodeQL analysis → Switch to advanced**, disable default setup, and verify that the custom job uploads its results successfully.

## Choose a check

| Command | What it checks |
|---|---|
| `pnpm security:test` | Scanner scope, dependency extraction without an installation, directed-cycle matching, and detection and redaction of an unissued secret canary. Install the native tools first. |
| `pnpm security:lint` | TypeScript-backed promise handling, unsafe `any` propagation, exhaustive switches, risky regular expressions, and JSDoc parameter and tag names. Biome remains the formatter and general linter. |
| `pnpm security:architecture` | Package layering, private cross-package imports, Node built-ins in runtime source, and new runtime import cycles. |
| `pnpm security:semgrep` | Tested local rules for dynamic execution, request-controlled registry dispatch, unsafe JSON copying, transport bypasses, and secret logging. The logging rule recognizes specific secret identifiers in any argument position; renamed values, interpolation, and nested data still need review. No Semgrep account is needed. |
| `pnpm security:secrets` | Redacted Gitleaks scans of the five package directories. Packed artifacts are scanned separately by `security:artifacts`. |
| `pnpm security:dependencies` | OSV advisories for exact production and optional dependency versions resolved from the five packages. Workspace links are traversed; app, tool, and development dependencies are excluded. |
| `pnpm security:artifacts` | Packed manifests and declarations with publint and Are the Types Wrong, secret scanning, isolated NodeNext ESM/CommonJS and bundler consumers, runtime imports, and public contract tests with tsd. Build first. |
| `pnpm security:workflows` | actionlint, with required ShellCheck analysis, and zizmor checks of every YAML file in `.github/workflows`, including CI, conformance, security, and release. Zizmor's regular reporting mode gates findings of low severity or higher; pedantic findings require a separate review. |
| `pnpm security:advisory` | Knip's unused-code report and jscpd's duplication report. These help reviewers choose useful cleanup work. They do not require deleting a public API or consolidating similar protocol rules. |

`security:check` runs the required local checks above, excluding the advisory, fuzz, and mutation commands. CodeQL runs in GitHub. The full runtime suite also includes generated properties for prototype safety, preservation of caller-owned metadata, selector semantics, and concurrent replay claims.

The workflow runner validates GitHub's queued-concurrency settings directly because actionlint 1.7.12 does not recognize `queue` yet. Only that unsupported-key diagnostic is exempted; invalid queue values, cancellation conflicts, shell issues, and other workflow errors still fail the check. During a release, `RELEASE_ARTIFACT_DIR` supplies the saved bundle to the artifact checks so they inspect the archives that will be published without packing again.

Dependency scanning builds a temporary CycloneDX input from pnpm's lockfile-backed production graph. Only package names and versions go to the advisory service. On a pull request, `SECURITY_BASE_SHA` selects a base commit so the check scans newly introduced versions. If that commit predates a scoped package or lacks another required input, the check explains the missing baseline and scans the complete current graph. Invalid commits and corrupt graphs fail. Scheduled and ordinary local runs also scan the full scoped graph. A failed scan fails the command.

## Update the Semgrep locks

Change the Semgrep version in `scripts/security/requirements/semgrep.in` and the installer's version check together. Regenerate each lock under its matching Python interpreter with pip-tools 7.7.0. For Python 3.12:

```bash
python3.12 -m venv /tmp/oidfed-lock-compiler-312
/tmp/oidfed-lock-compiler-312/bin/python -m pip install pip-tools==7.7.0
/tmp/oidfed-lock-compiler-312/bin/pip-compile \
  --upgrade --generate-hashes --strip-extras \
  --no-header --no-annotate --no-emit-index-url --no-emit-trusted-host \
  --pip-args='--only-binary=:all:' \
  --output-file scripts/security/requirements/semgrep-py312.txt \
  scripts/security/requirements/semgrep.in
```

Repeat with Python 3.13 and 3.14 and their respective lock filenames. Keep the compiler and interpreter versions in each lock's opening comment. Review every changed version and hash, then test fresh installations on all three interpreters. Commit the reviewed locks; CI consumes them without regenerating them or updating dependencies. A dependency without a compatible wheel needs a reviewed dependency change before the lock can be accepted.

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

Keep exceptions narrow and explain them beside the code or configuration. The authority context builder has one typed-lint exception because TypeScript's variadic `Object.assign` overload loses the types of its configuration fragments. The unexecuted Semgrep fixture allows `eval` only so the scanner's rejection can be tested. Neither exception relaxes runtime validation.
