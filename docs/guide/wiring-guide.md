# Wiring a federation into your application

This guide connects a Trust Anchor, Intermediate, OP, and RP. The TypeScript examples build on one another. They use temporary in-memory keys and stores for development; the [storage guide](storage-guide.md) describes production contracts.

For a working Express integration with [`node-oidc-provider`](https://github.com/panva/node-oidc-provider), read the [E2E OP participant](../../tests/e2e/participants/openid-provider-app.ts) and [launcher](../../tests/e2e/helpers/launcher.ts). Those are test applications with test accounts and interactions.

## Install

```bash
# Trust Anchor or Intermediate
pnpm add @oidfed/core @oidfed/authority

# Leaf OP or RP with OIDC federation roles
pnpm add @oidfed/core @oidfed/leaf @oidfed/oidc

# Express HTTP adapter used below
pnpm add express
pnpm add -D @types/express
```

The federation hierarchy in this example is:

```text
https://ta.example.org
└── https://ia.example.org
    ├── https://op.example.com
    └── https://rp.example.com
```

Each identifier needs its own HTTPS endpoint. An OP and RP share federation membership here; neither is the other's superior authority.

## 1. Create the Trust Anchor

```ts
import { Intermediate, MemoryStorageAdapter, TrustAnchor } from "@oidfed/authority";
import {
  createFederationSigningKey,
  createTrustAnchorSet,
  generateSigningKey,
  JwkSigner,
  MemoryFederationKeyProvider,
  MemoryReplayStore,
} from "@oidfed/core";

const taKeys = await generateSigningKey("ES256");
const ta = new TrustAnchor({
  entityId: "https://ta.example.org",
  keyProvider: new MemoryFederationKeyProvider(
    createFederationSigningKey(taKeys.privateKey),
  ),
  storage: new MemoryStorageAdapter(),
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: "https://ta.example.org/fetch",
      federation_list_endpoint: "https://ta.example.org/list",
    },
  },
});

const trustAnchors = createTrustAnchorSet([
  { entityId: ta.entityId, jwks: { keys: [taKeys.publicKey] } },
]);
```

A Trust Anchor omits `authorityHints`. Pin its public federation keys through your own trusted configuration process. Learning keys from the same untrusted endpoint you are evaluating does not establish that trust.

## 2. Create and enroll the Intermediate

```ts
const iaKeys = await generateSigningKey("ES256");
const intermediate = new Intermediate({
  entityId: "https://ia.example.org",
  authorityHints: [ta.entityId],
  trustAnchors,
  keyProvider: new MemoryFederationKeyProvider(
    createFederationSigningKey(iaKeys.privateKey),
  ),
  storage: new MemoryStorageAdapter(),
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: "https://ia.example.org/fetch",
      federation_list_endpoint: "https://ia.example.org/list",
    },
  },
});

await ta.registerSubordinate({
  entityId: intermediate.entityId,
  jwks: { keys: [iaKeys.publicKey] },
  entityTypes: ["federation_entity"],
  isIntermediate: true,
});
```

Authorities must advertise fetch and list endpoints. `registerSubordinate()` supplies timestamps and sanitizes subordinate metadata. If you write directly through `storage.subordinates`, supply timestamps and use `TrustAnchor.sanitizeSubordinateMetadata()` or `Intermediate.sanitizeSubordinateMetadata()` before storing metadata.

## 3. Add the OP's federation role

Use a `Leaf` when the OP does not issue Subordinate Statements. An OP that is also an authority can instead compose the role into an `Intermediate` with the required fetch and list metadata.

```ts
import { Leaf } from "@oidfed/leaf";
import {
  OIDCRegistrationAdapter,
  OidcProviderRole,
  OidcRelyingPartyRole,
  StaticProtocolSigningKeyProvider,
} from "@oidfed/oidc";

const opFederationKeys = await generateSigningKey("ES256");
const opProtocolKeys = await generateSigningKey("ES256");
const registeredClients = new Map<string, Record<string, unknown>>();

const opRole = new OidcProviderRole({
  trustAnchors,
  replayStore: new MemoryReplayStore(),
  registrationProtocolAdapter: new OIDCRegistrationAdapter(),
  metadata: {
    issuer: "https://op.example.com",
    authorization_endpoint: "https://op.example.com/auth",
    token_endpoint: "https://op.example.com/token",
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["ES256"],
    client_registration_types_supported: ["automatic", "explicit"],
    jwks: { keys: [opProtocolKeys.publicKey] },
  },
  onRegistration: async (clientId, metadata) => {
    registeredClients.set(clientId, metadata);
  },
});

const op = new Leaf({
  entityId: "https://op.example.com",
  authorityHints: [intermediate.entityId],
  trustAnchors,
  keyProvider: new MemoryFederationKeyProvider(
    createFederationSigningKey(opFederationKeys.privateKey),
  ),
  metadata: { federation_entity: { organization_name: "Example OP" } },
  roles: [opRole],
});

await intermediate.registerSubordinate({
  entityId: op.entityId,
  jwks: { keys: [opFederationKeys.publicKey] },
  entityTypes: ["openid_provider"],
});
```

`Leaf.handleRequest()` serves the Entity Configuration and dispatches explicit registration to the role's `/registration` handler. The role publishes that URL as `federation_registration_endpoint`.

Connect `onRegistration` to the client store your OP actually reads, including protocol-key metadata and registration expiry. The map above only demonstrates that handoff. Configure the OP to use the same protocol keys it publishes here; generating this metadata does not configure its token signer.

For automatic registration, your authorization endpoint calls `opRole.processAutomaticRegistration(requestObjectJwt, options)` before continuing the OIDC request. On success, use the returned `rpEntityId`, `resolvedRpMetadata`, and `trustChain` to provision the client and bound its lifetime. Reject a failed result. A shared atomic `ReplayStore` is required for this method in a multi-process deployment.

If the OP supports `request_uri` or PAR, integrate Request Object retrieval and PAR processing into those endpoints too. The [E2E OP participant](../../tests/e2e/participants/openid-provider-app.ts) shows the application wiring for the supported delivery modes.

## 4. Add the RP's federation role

```ts
const rpFederationKeys = await generateSigningKey("ES256");
const rpProtocolKeys = await generateSigningKey("ES256");
const rpRole = new OidcRelyingPartyRole({
  protocolKeyProvider: new StaticProtocolSigningKeyProvider({
    requestObjectSigner: new JwkSigner(rpProtocolKeys.privateKey),
  }),
  metadata: {
    redirect_uris: ["https://rp.example.com/callback"],
    response_types: ["code"],
    grant_types: ["authorization_code"],
    client_registration_types: ["automatic", "explicit"],
    token_endpoint_auth_method: "private_key_jwt",
    jwks: { keys: [rpProtocolKeys.publicKey] },
  },
});

const rp = new Leaf({
  entityId: "https://rp.example.com",
  authorityHints: [intermediate.entityId],
  trustAnchors,
  keyProvider: new MemoryFederationKeyProvider(
    createFederationSigningKey(rpFederationKeys.privateKey),
  ),
  metadata: { federation_entity: { organization_name: "Example RP" } },
  roles: [rpRole],
});

await intermediate.registerSubordinate({
  entityId: rp.entityId,
  jwks: { keys: [rpFederationKeys.publicKey] },
  entityTypes: ["openid_relying_party"],
});
```

At login, call `rpRole.automaticallyRegister()` with the OP Entity Identifier, registered redirect URI, scope, and fresh state/nonce bound to the browser session. Handle its `Result`, then narrow the returned `delivery` field before using mode-specific fields such as `authorizationUrl` or `formParams`. See [OIDC roles](../packages/oidc.md#automatic-registration-result).

For explicit registration, call `rpRole.explicitlyRegister(op.entityId, { trustAnchors })`. Persist a successful result's `clientId`, any `clientSecret`, and `trustChainExpiresAt`. Use your OIDC client to construct the authorization request and re-register before the chain expires.

During token exchange, the HTTP destination is the validated token endpoint. A `private_key_jwt` assertion's audience is the validated OP Entity Identifier:

```ts
const clientAssertion = await rpRole.createClientAssertion(op.entityId);
```

Your OIDC client must validate session state, use the applicable PKCE/nonce protections, handle token-endpoint errors, and validate the ID Token before creating a session. Federation registration supplies trusted metadata and client credentials; these OIDC responsibilities remain in the application.

## 5. Adapt the Web API handler to Express

This Express 5 adapter buffers the original request bytes with a 64 KiB limit. Mount it before other body parsers and only on federation routes. It builds URLs from the configured public Entity Identifier.

```ts
import express from "express";

function federationApp(
  publicEntityId: string,
  handler: (request: Request) => Promise<Response>,
  paths: string[],
) {
  const app = express();
  app.use(express.raw({ type: () => true, limit: "64kb" }));

  for (const path of paths) {
    app.all(path, async (req, res) => {
      const url = new URL(req.originalUrl, publicEntityId);
      if (url.origin !== new URL(publicEntityId).origin) {
        res.status(400).end();
        return;
      }
      const headers = new Headers();
      for (const [name, value] of Object.entries(req.headers)) {
        if (Array.isArray(value)) {
          for (const item of value) headers.append(name, item);
        } else if (value !== undefined) {
          headers.set(name, value);
        }
      }
      const body = req.method !== "GET" && req.method !== "HEAD" && Buffer.isBuffer(req.body)
        ? new Uint8Array(req.body).buffer
        : undefined;
      const response = await handler(new Request(url, {
        method: req.method,
        headers,
        ...(body !== undefined ? { body } : {}),
      }));
      res.status(response.status);
      response.headers.forEach((value, name) => res.setHeader(name, value));
      res.end(await response.text());
    });
  }
  return app;
}

const taApp = federationApp(ta.entityId, (request) => ta.handleRequest(request), [
  "/.well-known/openid-federation", "/fetch", "/list",
]);
const opFederationApp = federationApp(op.entityId, (request) => op.handleRequest(request), [
  "/.well-known/openid-federation", "/registration",
]);
```

Serve each app on its configured HTTPS origin, directly or through a TLS reverse proxy. Add the Intermediate and RP handlers the same way. In the OP application, mount the federation routes alongside the existing authorization/token routes. Forward exact JWT response content types, status codes, and bodies.

## Registration flow

1. The RP fetches the OP's Entity Configuration, follows authority hints, and obtains Subordinate Statements.
2. Discovery validates the chain against configured trust anchors, checks constraints, and applies metadata policies.
3. Automatic registration signs a protocol Request Object and delivers it through the selected mode. The OP validates it and the RP's chain, claims its replay identifier, and provisions the client.
4. Explicit registration instead posts a federation-signed Entity Configuration and receives a signed registration response. Supplied chains are validated before live discovery is attempted.
5. The existing OP and RP complete the authorization code flow using the trusted metadata and credentials. Registration lifetime is bounded by trust-chain validity.
