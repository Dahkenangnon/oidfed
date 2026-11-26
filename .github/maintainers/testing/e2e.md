# End-to-end tests

Install [mkcert](https://github.com/FiloSottile/mkcert#installation) and the
repository dependencies, then run:

```sh
pnpm setup:e2e
pnpm test:e2e
```

The suite uses a disposable HTTPS server and resolves `*.ofed.test` to
loopback. For certificate errors, check [TLS trust](../development.md#tls-trust).

## Add a scenario

Use an existing [topology](../../../tests/e2e/topologies) with
[`useFederation()`](../../../tests/e2e/helpers/lifecycle.ts). It starts the test
bed and cleans it up after the suite. Use the test bed’s assigned port in the
request URL. The [federation API tests](../../../tests/e2e/scenarios/federation-api.test.ts)
show this pattern.

The [Vitest configuration](../../../tests/e2e/vitest.config.ts) maps library
imports to source. For manual browser testing, use the
[local federation server](../development.md#run-the-local-federation).
