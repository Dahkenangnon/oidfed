# E2E Test Infrastructure

End-to-end test infrastructure for `@oidfed/*`. Exercises all packages together over real HTTPS using spec-compliant entity identifiers (`*.ofed.test`).

## Why

The spec (Section 1.2) mandates that all Entity Identifiers use the `https` scheme — no exceptions for testing. Unit tests mock HTTP, but E2E tests need real TLS handshakes, real DNS resolution, and real cross-package wiring to verify the library works as developers will actually use it.

## Prerequisites

- **Node.js 22+**
- **mkcert** — generates locally-trusted TLS certificates

## Setup

One-time, per machine:

```bash
pnpm setup:e2e      # installs mkcert CA, generates *.ofed.test certs into .certs/
```

This creates:

```
.certs/
├── ofed.pem         # TLS certificate (wildcard *.ofed.test + localhost)
├── ofed-key.pem     # TLS private key
└── ca-path.txt      # path to mkcert's root CA (used at runtime)
```

`.certs/` is gitignored. Each developer/CI runner generates their own.

## Running

```bash
pnpm test:e2e       # runs E2E tests only (requires setup:e2e first)
pnpm test           # runs unit/integration tests only (no certs needed)
```

The `test:e2e` script sets `NODE_EXTRA_CA_CERTS` so Node's built-in TLS trusts the mkcert CA, then runs vitest with the E2E config.

## Architecture

Six layers, each building on the previous:

```
┌─────────────────────────────────────────────────┐
│  Layer 6: Test Scenarios (smoke.test.ts, ...)   │
├─────────────────────────────────────────────────┤
│  Layer 5: Lifecycle (useFederation)             │
├─────────────────────────────────────────────────┤
│  Layer 4: Launcher (topology → running infra)   │
├─────────────────────────────────────────────────┤
│  Layer 3: Participant Apps (Express wrappers)   │
├─────────────────────────────────────────────────┤
│  Layer 2: Vhost HTTPS Server (federation-server)│
├─────────────────────────────────────────────────┤
│  Layer 1: DNS + TLS (undici custom dispatcher)  │
└─────────────────────────────────────────────────┘
```

### Layer 1: DNS + TLS Interception

**File:** `helpers/setup-file.ts`

`*.ofed.test` domains don't exist in real DNS. We use undici's `Agent` with a custom `lookup` to resolve all hostnames to `127.0.0.1`, and inject mkcert's root CA so TLS handshakes succeed.

This runs as a vitest `setupFiles` entry (not `globalSetup`), because `setGlobalDispatcher` must execute in the same process as the test workers.

```
fetch("https://ta.ofed.test:PORT/...")
  → undici lookup → 127.0.0.1
  → undici TLS   → trusts mkcert root CA
  → connects to localhost:PORT with valid TLS
```

### Layer 2: Vhost HTTPS Server

**File:** `helpers/federation-server.ts`

A single `node:https` server binds to an ephemeral port on `127.0.0.1`. It reads the `Host` header and dispatches to the correct Express app:

```
                    https://ta.ofed.test:PORT
                              │
                    Host: ta.ofed.test
                              │
                    vhost map lookup
                              │
               ┌──────────────┼──────────────┐
               ▼              ▼              ▼
          TA Express     OP Express     RP Express
             app            app            app
```

One port serves all entities. This avoids port exhaustion and mirrors real reverse-proxy deployments.

**API:**

```typescript
const server = await createAndStartFederationTestServer();
server.addEntity("https://ta.ofed.test:PORT", taApp);
server.addEntity("https://op.ofed.test:PORT", opApp);
// ...
await server.close();
```

### Layer 3: Participant App Factories

**Files:** `participants/authority-app.ts`, `participants/leaf-app.ts`, `participants/openid-provider-app.ts`

Express app factories that bridge Express `(req, res)` to the library's Web API `(Request) => Promise<Response>`:

```typescript
// The bridge pattern (from docs/wiring-guide.md)
const url = new URL(req.originalUrl, entityId);
const request = new Request(url.toString(), { method, headers, body });
const response = await handler(request);
res.status(response.status);
for (const [key, value] of response.headers) res.setHeader(key, value);
res.send(await response.text());
```

| Factory | Wraps | Serves |
|---------|-------|--------|
| `createAuthorityApp` | `AuthorityServer.handler()` | All federation endpoints |
| `createLeafApp` | `LeafEntity.handler()` | `GET /.well-known/openid-federation` only |
| `createOpenIDProviderApp` | `AuthorityServer.handler()` + `oidc-provider` | Federation endpoints + OIDC (`/auth`, `/token`, etc.) |

The OP app also wires `processAutomaticRegistration` and `processExplicitRegistration` from `@oidfed/oidc` on the registration endpoints, and uses `oidc-provider` (panva/node-oidc-provider) for standard OIDC flows.

### Layer 4: Launcher

**File:** `helpers/launcher.ts`

`launchFederation(topology)` is the orchestrator. Given a declarative topology definition, it:

1. Starts the vhost server on an ephemeral port
2. Generates signing keys for every entity (`generateSigningKey("ES256")`)
3. Rewrites all URLs to include the ephemeral port (e.g., `https://ta.ofed.test` → `https://ta.ofed.test:54321`)
4. Builds the `TrustAnchorSet` from TA entities' public keys
5. Creates `AuthorityServer` instances (for TAs, intermediates, OPs) with `MemoryKeyStore(key)` and `MemorySubordinateStore`
6. Creates `LeafEntity` instances (for RPs)
7. Registers subordinates — walks each entity's `authorityHints` to find the parent authority and adds the entity to its `MemorySubordinateStore`
8. Creates Express apps via the participant factories
9. Registers all apps in the vhost server

Returns a `FederationTestBed`:

```typescript
interface FederationTestBed {
  server: FederationTestServer;        // port, addEntity, close
  entities: Map<string, EntityInstance>; // server + keys per entity
  trustAnchors: TrustAnchorSet;
  close(): Promise<void>;
}
```

### Layer 5: Lifecycle Helper

**File:** `helpers/lifecycle.ts`

Convenience wrapper for `beforeAll`/`afterAll`:

```typescript
const getTestBed = useFederation(singleAnchorTopology);

it("my test", async () => {
  const { server, entities, trustAnchors } = getTestBed();
  // server is running, all entities registered
});
```

### Layer 6: Test Scenarios

**Directory:** `scenarios/`

Each test file uses `useFederation(topology)` and makes real HTTPS requests:

```typescript
it("fetches TA entity configuration", async () => {
  const { server } = getTestBed();
  const response = await fetch(
    `https://ta.ofed.test:${server.port}/.well-known/openid-federation`
  );
  expect(response.status).toBe(200);
  expect(response.headers.get("content-type")).toContain("application/entity-statement+jwt");
});
```

## Topologies

Six topology definitions in `topologies/`. Each is a declarative `TopologyDefinition` that `launchFederation()` instantiates. See [dev.md](../guide/dev.md) for entity IDs and full topology diagrams.

| Topology | Description |
|----------|-------------|
| `single-anchor` | 1 TA, 1 OP, 2 RPs (one automatic, one explicit) |
| `hierarchical` | TA → 2 intermediates (edu, health) → OPs + RPs |
| `multi-anchor` | 2 TAs sharing one intermediate, OP, 2 RPs |
| `constrained` | TA with `max_path_length=0`; one valid chain, one deliberately failing |
| `cross-federation` | Two separate federations linked by a bridge intermediate |
| `policy-operators` | Demonstrates all §9.2 metadata policy operators |

Adding new topologies is just creating a new file that exports a `TopologyDefinition`.

## How a Test Runs

Complete flow for `smoke.test.ts`:

```
1. vitest loads tests/e2e/vitest.config.ts
      ↓
2. setupFiles: helpers/setup-file.ts
      → reads .certs/ca-path.txt → mkcert root CA
      → creates undici Agent (custom DNS lookup + CA)
      → setGlobalDispatcher(agent)
      ↓
3. beforeAll: useFederation(singleAnchorTopology)
      → generateSigningKey("ES256") × 3
      → createAuthorityServer (TA), createAuthorityServer (OP), createLeafEntity (RP)
      → register OP and RP as subordinates in TA's store
      → create Express apps (authority-app, openid-provider-app, leaf-app)
      → start HTTPS server on ephemeral port (e.g., 54321)
      → register all apps in vhost map
      ↓
4. test: fetch("https://ta.ofed.test:54321/.well-known/openid-federation")
      → undici resolves ta.ofed.test → 127.0.0.1
      → TLS handshake with .certs/ofed.pem (trusted via mkcert CA)
      → vhost server: Host=ta.ofed.test → TA Express app
      → Express bridge → AuthorityServer.handler() → signs JWT
      → 200 + application/entity-statement+jwt + valid 3-part JWT
      ↓
5. afterAll: close server + close undici agent
```

## Isolation from Unit Tests

The E2E vitest config is standalone (`tests/e2e/vitest.config.ts`), **not** in the root `vitest.config.ts` projects array. This means:

- `pnpm test` — runs only unit/integration tests (885 unit tests, no certs needed)
- `pnpm test:e2e` — runs only E2E tests (requires `pnpm setup:e2e` first)
- CI can run unit tests without mkcert, and add E2E as a separate step

The E2E config includes `resolve.alias` entries for all `@oidfed/*` packages, mapping them to their source `src/index.ts` files (same pattern the per-package vitest configs use).

## Browser / Manual Testing

The same federation can run as a long-lived server accessible from a browser.

### Prerequisites

1. **Build all packages** (the dev server imports from built `dist/`):

   ```bash
   pnpm build
   ```

2. **Generate TLS certificates** (if not done already):

   ```bash
   pnpm setup:e2e
   ```

3. **Add DNS entries** to `/etc/hosts`:

   ```
   127.0.0.1  ta.ofed.test op.ofed.test rp.ofed.test
   ```

   > Actual hostnames are topology-prefixed (e.g. `ta-sa.ofed.test`, `op-uni-hi.ofed.test`). The bare names above are illustrative only. See [dev.md](../guide/dev.md) for the full list.

4. **Trust the mkcert CA in your browser.** Running `mkcert -install` (done by `setup:e2e`) adds it to the system trust store. Most browsers pick this up automatically. Firefox users may need to import the CA manually via Settings > Certificates > Import (the CA path is in `.certs/ca-path.txt`).

### Running

```bash
pnpm dev:federation             # starts on port 8443
pnpm dev:federation -- --port 9443  # custom port
```

Then open in your browser:

- **Trust Anchor:** `https://ta.ofed.test:8443/.well-known/openid-federation`
- **OpenID Provider:** `https://op.ofed.test:8443/.well-known/openid-federation`
- **Relying Party:** `https://rp.ofed.test:8443/.well-known/openid-federation`

Each URL returns the entity's signed Entity Configuration JWT.

### How it differs from E2E tests

| | E2E tests (`pnpm test:e2e`) | Dev server (`pnpm dev:federation`) |
|---|---|---|
| Port | Ephemeral (random) | Fixed (default 8443) |
| DNS | undici in-process interception | System `/etc/hosts` |
| TLS trust | `NODE_EXTRA_CA_CERTS` env var | System/browser trust store |
| Lifecycle | Per-test (beforeAll/afterAll) | Long-running (Ctrl+C to stop) |
| Imports | Source (`src/index.ts` via vitest alias) | Built (`dist/` via workspace deps) |

### Script details

**File:** `scripts/dev-federation.ts`

The dev server reuses the same participant app pattern (Express bridge → library handlers) as the E2E infrastructure. It defines all 6 topologies inline and launches each in sequence on the same vhost HTTPS server with a fixed port — equivalent to calling `launchFederation()` for each topology, but without a test framework dependency.

## CI Setup

```yaml
- name: Setup E2E certificates
  run: |
    sudo apt-get install -y mkcert libnss3-tools
    pnpm setup:e2e

- name: Run E2E tests
  run: pnpm test:e2e
```

## Directory Structure

```
tests/e2e/
├── vitest.config.ts
├── helpers/
│   ├── setup-file.ts
│   ├── federation-server.ts
│   ├── launcher.ts
│   └── lifecycle.ts
├── participants/
│   ├── authority-app.ts
│   ├── leaf-app.ts
│   └── openid-provider-app.ts
├── topologies/
│   ├── types.ts
│   ├── single-anchor.ts
│   ├── hierarchical.ts
│   ├── multi-anchor.ts
│   ├── constrained.ts
│   ├── cross-federation.ts
│   └── policy-operators.ts
└── scenarios/
    ├── smoke.test.ts
    ├── automatic-registration.test.ts
    ├── explicit-registration.test.ts
    ├── cross-federation-registration.test.ts
    ├── cross-federation.test.ts
    ├── trust-chain-resolution.test.ts
    ├── constraints.test.ts
    ├── metadata-policy.test.ts
    ├── metadata-policy-operators.test.ts
    ├── federation-api.test.ts
    ├── failure-modes.test.ts
    ├── jti-replay.test.ts
    ├── key-rotation.test.ts
    ├── client-auth.test.ts
    ├── oidc-login-flow.test.ts
    ├── trust-mark-endpoints.test.ts
    ├── trust-mark-lifecycle.test.ts
    ├── trust-mark-delegation.test.ts
    ├── trust-mark-constraints.test.ts
    └── trust-mark-in-ec.test.ts
```
