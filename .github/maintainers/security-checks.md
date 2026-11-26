# Package security checks

## Set up the tools

Use the Node version in `.node-version` and install dependencies before running
the checks. The scanner installer supports Linux x64.

```sh
pnpm install --frozen-lockfile
pnpm security:install
pnpm build:publish
pnpm security:check
```

`security:check` covers source lint, architecture, secrets, dependencies, package
archives, and GitHub workflows. Source scans cover the six library packages.
Dependency scans include the published CLI. CodeQL runs in GitHub through the
custom [security workflow](../workflows/security.yml). Use advanced CodeQL setup
for that workflow.

## Targeted checks

| Command | Use it for |
|---|---|
| `pnpm security:lint` | Typed ESLint and local security rules |
| `pnpm security:test` | Changes to scanner or rule behavior |
| `pnpm security:architecture` | Package boundaries and runtime import cycles |
| `pnpm security:artifacts` | Packed declarations, consumer imports, and secrets in archives |
| `pnpm security:advisory` | Unused code and duplication reports |
| `pnpm security:fuzz` | JWT payload and endpoint selector parsing |
| `pnpm security:mutation` | Tests for endpoint selector and credential guards |

Keep scanner pins and checksums together. For a new lint rule or exception,
exercise an unsafe case and a safe case in the
[security rule tests](../../tests/scripts/security/eslint-rules.test.mjs).
