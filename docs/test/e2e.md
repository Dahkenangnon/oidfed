# End-to-end tests

The E2E suite exercises federation packages together over HTTPS. Entity Identifiers use the `https` scheme, including in tests. Local certificates and an injected DNS lookup let the suite use `*.ofed.test` without external DNS.

## Setup and commands

Use a supported Node.js version (`^22.22.2 || ^24.15.0 || >=26.0.0`) and the repository's pinned pnpm version. Install [mkcert](https://github.com/FiloSottile/mkcert#installation); Linux browser trust may also need `libnss3-tools` or its platform equivalent.

```bash
pnpm setup:e2e
pnpm test:e2e
```

Setup installs a development CA and generates these ignored files:

```text
.certs/
├── ofed.pem         # *.ofed.test, localhost, and loopback addresses
├── ofed-key.pem     # TLS private key
└── ca-path.txt      # directory containing the signing CA's rootCA.pem
```

Each machine or CI runner generates its own certificates. Setup skips generation if both server files already exist; it does not verify that they match the CA recorded in `ca-path.txt`. See [TLS troubleshooting](../guide/dev.md#tls-trust) for a verification command.

`test:e2e` sets `NODE_EXTRA_CA_CERTS` to the recorded CA file and runs [`tests/e2e/vitest.config.ts`](../../tests/e2e/vitest.config.ts). The tests also inject that CA into undici's dispatcher. No hosts-file changes are needed for automated tests.

## How the test infrastructure fits together

| Layer | Source under `tests/e2e/` | Responsibility |
|---|---|---|
| DNS and TLS | [`helpers/setup-file.ts`](../../tests/e2e/helpers/setup-file.ts) | Install an undici dispatcher with the local CA and a loopback DNS lookup |
| HTTPS server | [`helpers/federation-server.ts`](../../tests/e2e/helpers/federation-server.ts) | Bind one ephemeral port on `127.0.0.1` and dispatch requests by hostname |
| HTTP applications | [`participants/`](../../tests/e2e/participants/) | Adapt Express to Web API handlers; connect OP registration to `node-oidc-provider` |
| Launcher | [`helpers/launcher.ts`](../../tests/e2e/helpers/launcher.ts) | Create keys, entities, stores, trust anchors, and subordinate records from a topology |
| Lifecycle | [`helpers/lifecycle.ts`](../../tests/e2e/helpers/lifecycle.ts) | Start and close a test bed through Vitest hooks |
| Scenarios | [`scenarios/`](../../tests/e2e/scenarios/) | Make HTTPS requests and assert protocol behavior |

The dispatcher setup runs through `setupFiles` in the test worker so `setGlobalDispatcher()` affects that worker's fetch calls. Its lookup redirects requests to loopback; keep external network requests out of these scenarios.

The server uses one port for all entities. The launcher adds that port to topology URLs, creates separate federation and protocol keys for each entity, and pins the generated TA keys in a `TrustAnchorSet`. Authorities get their own `MemoryStorageAdapter`; OP processing uses replay protection. RP test instances expose their OIDC role and request-object stores for registration scenarios.

Participant applications preserve the request body and forward the handler's HTTP status, headers, and response body. A leaf's own handler also supports composed role routes; the test leaf wrapper mounts the Entity Configuration route and optional Request Object retrieval. The OP participant adds explicit registration, authorization, token, and PAR integration used by the suite. The [wiring guide](../guide/wiring-guide.md) explains the application boundary.

## Add a scenario

Use a topology from [`tests/e2e/topologies/`](../../tests/e2e/topologies/) and the lifecycle helper:

```ts
import { expect, it } from "vitest";
import { useFederation } from "../helpers/lifecycle.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

const getTestBed = useFederation(singleAnchorTopology);

it("serves the Trust Anchor's Entity Configuration", async () => {
  const { server } = getTestBed();
  const response = await fetch(
    `https://ta.ofed.test:${server.port}/.well-known/openid-federation`,
  );
  expect(response.status).toBe(200);
  expect(response.headers.get("content-type")).toBe("application/entity-statement+jwt");
});
```

The lifecycle helper launches the federation in `beforeAll` and closes it in `afterAll`. The dispatcher is also closed by its setup-file hook. A single-anchor test bed has four entities: one TA, one OP, and two RPs. Each gets a federation key pair and a separate protocol key pair.

`FederationTestBed` exposes `server`, `entities`, `trustAnchors`, `requestObjectStores`, and `close()`. See the [launcher types](../../tests/e2e/helpers/launcher.ts) for the complete shape.

## Topologies

| Topology | Scenario |
|---|---|
| `single-anchor` | One TA, one OP, and two RPs for automatic and explicit registration |
| `hierarchical` | One TA with education and health Intermediates above OPs and RPs |
| `multi-anchor` | Two TAs above a shared Intermediate |
| `constrained` | `max_path_length=0`, with a valid direct path and a deliberately invalid deeper path |
| `cross-federation` | Two federations and a bridge Intermediate |
| `policy-operators` | `subset_of`, `value`, `add`, and `essential` metadata policies |

Add a `TopologyDefinition` in `topologies/` when a scenario needs a different trust structure, then pass it to `useFederation()` or `launchFederation()`.

## Test commands and isolation

| Command | Runs |
|---|---|
| `pnpm quick:test` | Node TAP suite and CLI tests |
| `pnpm test` | TAP suite across the configured runtimes, then CLI tests |
| `pnpm test:apps` | Application tests |
| `pnpm test:e2e` | HTTPS scenarios using the local test CA |

E2E has a standalone Vitest configuration. It maps the four federation libraries to `src/index.ts` through aliases. The other suites do not need E2E certificates.

## Browser testing

The long-running dev server defines its own six topologies in [`scripts/dev-federation.ts`](../../scripts/dev-federation.ts). It uses fixed port `8443` by default and imports built package output. Build and configure browser DNS/TLS through the [development guide](../guide/dev.md).

```bash
pnpm build
pnpm setup:e2e
pnpm dev:federation
```

Then inspect the single-anchor entities:

- `https://ta-sa.ofed.test:8443/.well-known/openid-federation`
- `https://op-sa.ofed.test:8443/.well-known/openid-federation`
- `https://rp-sa.ofed.test:8443/.well-known/openid-federation`

The `-sa` names belong to the dev server; automated single-anchor tests use names such as `ta.ofed.test` with an ephemeral port. Test DNS interception does not configure the browser's resolver.

## CI

The E2E job in [the CI workflow](../../.github/workflows/ci.yml) installs mkcert, generates certificates, and runs the suite. The relevant steps on Ubuntu are:

```yaml
- name: Set up E2E certificates
  run: |
    sudo apt-get install -y mkcert libnss3-tools
    pnpm setup:e2e

- name: Run E2E tests
  run: pnpm test:e2e
```
