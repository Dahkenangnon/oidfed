# OpenID Federation conformance checks

Install repository dependencies, Docker with Compose, Git, and OpenSSL.
The harness builds and runs the suite in containers.

## Run a profile

```sh
pnpm test:conformance:unit   # Harness tests, without Docker
pnpm typecheck:conformance
pnpm test:conformance        # Trust Anchor, Intermediate, and Leaf
pnpm test:conformance:full   # Deployed entities plus OP and RP
```

Run the OP profile alone with the launcher. Use `--profile rp` for the RP.

```sh
pnpm exec tsx --tsconfig tests/conformance/tsconfig.json tests/conformance/run.ts --profile op
```

Use `--source <path>` to supply a clean suite checkout at the revision in
[`baseline.json`](../../../tests/conformance/baseline.json). To update the
revision, review the plan inventory and exclusions together, then run all
three profiles.

## Read the results

Read `.conformance/runs/<run-id>/results/summary.json` for failed conditions,
accepted capability skips, and exclusions. The
[pinned policy](../../../tests/conformance/policy.ts) lists the exact excluded
OP and RP cases. The OP exclusions require manual error-page review. The
RP exclusions depend on a fixture response that omits `access_token` and
`token_type`. A passing run covers the enabled cases.

Use `--keep-private` for local diagnosis only. The private directory can
contain test keys, assertions, cookies, and authorization codes. Keep it
local and remove it after diagnosis. If Docker cleanup fails, use the printed
Compose project name to identify the run’s resources.

See the [conformance workflow](../../workflows/conformance.yml) for CI profiles.
Use the Foundation’s [federation testing instructions](https://openid.net/certification/federation_testing/)
for hosted checks with a separate test deployment and disposable keys.
