# End-to-End Wiring Guide

Integration guide for `@oidfed/*` with Express.js and [`panva/node-oidc-provider`](https://github.com/panva/node-oidc-provider). Demonstrates a complete OpenID Federation deployment.

## Installation

```bash
# Trust Anchor / Intermediate Authority
pnpm add @oidfed/core @oidfed/authority

# OpenID Provider (OP)
pnpm add @oidfed/core @oidfed/authority @oidfed/oidc

# Relying Party (RP)
pnpm add @oidfed/core @oidfed/leaf @oidfed/oidc

# CLI (global)
pnpm add -g @oidfed/cli
```

This guide follows the **eduGAIN topology** from the spec appendix:

```
Trust Anchor (edugain.geant.org)
       ┌────────┴────────┐
 SWAMID (swamid.se)   InCommon (incommon.org)
       │                      │
 umu.se (Org)                 │
       │                      │
 op.umu.se (OP)         wiki.ligo.org (RP)
```

## Table of Contents

1. [Trust Anchor Setup](#1-trust-anchor-setup)
2. [Intermediate Setup](#2-intermediate-setup)
3. [OP Setup (Express + node-oidc-provider)](#3-op-setup)
4. [RP Setup (Express + @oidfed/leaf + @oidfed/oidc)](#4-rp-setup)
5. [End-to-End Flow](#5-end-to-end-flow)

---

## 1. Trust Anchor Setup

A Trust Anchor using `@oidfed/authority` on Express.

```typescript
import express from "express";
import {
  TrustAnchor,
  MemoryStorageAdapter,
} from "@oidfed/authority";
import {
  entityId,
  generateSigningKey,
  JwkSigner,
  MemoryFederationKeyProvider,
} from "@oidfed/core";

const TA_ID = entityId("https://edugain.geant.org");
const federationKeyPair = await generateSigningKey("ES256");
const keyProvider = new MemoryFederationKeyProvider({
  signer: new JwkSigner(federationKeyPair.privateKey),
  publicJwk: federationKeyPair.publicKey,
});
const storage = new MemoryStorageAdapter();

const ta = new TrustAnchor({
  entityId: TA_ID,
  keyProvider,
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: "https://edugain.geant.org/federation_fetch",
      federation_list_endpoint: "https://edugain.geant.org/federation_list",
      federation_resolve_endpoint: "https://edugain.geant.org/federation_resolve",
    },
  },
  storage,
  // No authorityHints — this is a Trust Anchor
});

// Register subordinate Intermediates
const swamidKey = /* SWAMID's public signing key */;
await ta.listSubordinates(); // (just to show the API)

// Wire into Express
const app = express();

app.all("/*", async (req, res) => {
  const url = new URL(req.originalUrl, `https://${req.headers.host}`);
  const request = new Request(url.toString(), {
    method: req.method,
    headers: req.headers as Record<string, string>,
    body: req.method !== "GET" && req.method !== "HEAD" ? req.body : undefined,
  });

  const response = await ta.handleRequest(request);

  res.status(response.status);
  for (const [key, value] of response.headers) {
    res.setHeader(key, value);
  }
  res.send(await response.text());
});

app.listen(443);
```
```

### Adding Subordinates

```typescript
import { entityId } from "@oidfed/core";

// Register SWAMID as an Intermediate subordinate
await storage.subordinates.add({
  entityId: entityId("https://swamid.se"),
  jwks: { keys: [swamidPublicKey] },
  entityTypes: ["federation_entity"],
  isIntermediate: true,
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: "https://swamid.se/federation_fetch",
      federation_list_endpoint: "https://swamid.se/federation_list",
    },
  },
  createdAt: Date.now() / 1000,
  updatedAt: Date.now() / 1000,
});

// Register InCommon as an Intermediate subordinate
await storage.subordinates.add({
  entityId: entityId("https://incommon.org"),
  jwks: { keys: [incommonPublicKey] },
  entityTypes: ["federation_entity"],
  isIntermediate: true,
  createdAt: Date.now() / 1000,
  updatedAt: Date.now() / 1000,
});
```

---

## 2. Intermediate Setup

SWAMID as an Intermediate Authority — same pattern as the TA, but with `authorityHints`.

```typescript
import {
  Intermediate,
  MemoryStorageAdapter,
} from "@oidfed/authority";
import {
  entityId,
  generateSigningKey,
  JwkSigner,
  MemoryFederationKeyProvider,
} from "@oidfed/core";
import type { TrustAnchorSet } from "@oidfed/core";

const SWAMID_ID = entityId("https://swamid.se");
const federationKeyPair = await generateSigningKey("ES256");
const keyProvider = new MemoryFederationKeyProvider({
  signer: new JwkSigner(federationKeyPair.privateKey),
  publicJwk: federationKeyPair.publicKey,
});

// Trust Anchor keys for chain validation during registration
const trustAnchors: TrustAnchorSet = new Map([
  [entityId("https://edugain.geant.org"), { jwks: { keys: [taPublicKey] } }],
]);

const swamid = new Intermediate({
  entityId: SWAMID_ID,
  keyProvider,
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: "https://swamid.se/federation_fetch",
      federation_list_endpoint: "https://swamid.se/federation_list",
    },
  },
  authorityHints: [entityId("https://edugain.geant.org")], // ← Intermediate
  trustAnchors,
  storage: new MemoryStorageAdapter(),
});

// Register umu.se as a subordinate organization
// (umu.se itself may be an Intermediate with op.umu.se as its subordinate)
```

---

## 3. OP Setup

An OpenID Provider at `op.umu.se` using Express + `panva/node-oidc-provider` + `@oidfed/authority` + `@oidfed/oidc`.

The OP acts as an authority (issues its own Entity Configuration with `@oidfed/authority` and `Intermediate`) and processes incoming registrations (with the `FedOidcProvider` role from `@oidfed/oidc`).

```typescript
import express from "express";
import Provider from "oidc-provider";
import { Intermediate, MemoryStorageAdapter } from "@oidfed/authority";
import { FedOidcProvider, processAutomaticRegistration } from "@oidfed/oidc";
import {
  entityId,
  generateSigningKey,
  isOk,
  JwkSigner,
  MemoryFederationKeyProvider,
} from "@oidfed/core";
import type { TrustAnchorSet } from "@oidfed/core";

const OP_ID = entityId("https://op.umu.se");
const federationKeyPair = await generateSigningKey("ES256");
const keyProvider = new MemoryFederationKeyProvider({
  signer: new JwkSigner(federationKeyPair.privateKey),
  publicJwk: federationKeyPair.publicKey,
});
const storage = new MemoryStorageAdapter();

const trustAnchors: TrustAnchorSet = new Map([
  [entityId("https://edugain.geant.org"), { jwks: { keys: [taPublicKey] } }],
]);

// --- Federation server (Entity Configuration + role endpoints) ---

const opAuthority = new Intermediate({
  entityId: OP_ID,
  keyProvider,
  metadata: {
    federation_entity: {},
  },
  authorityHints: [entityId("https://umu.se")],
  trustAnchors,
  storage,
  roles: [
    new FedOidcProvider({
      registrationPath: "/registration",
      metadata: {
        issuer: "https://op.umu.se",
        authorization_endpoint: "https://op.umu.se/auth",
        token_endpoint: "https://op.umu.se/token",
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["ES256"],
        client_registration_types_supported: ["automatic", "explicit"],
      },
      // Optional: Pluggable hooks for client registration validation
      onRegisterClient: async (clientId, metadata, trustChain) => {
        // Custom check/storage logic for new clients. Returning true approves registration.
        return true;
      }
    })
  ]
});

// --- OIDC Provider (panva/node-oidc-provider) ---

const oidc = new Provider("https://op.umu.se", {
  // Standard OIDC provider configuration
  clients: [], // Clients registered dynamically via federation
  findAccount: async (ctx, id) => ({
    accountId: id,
    async claims() { return { sub: id }; },
  }),
  features: {
    registration: { enabled: false }, // Federation handles registration
  },
});

// --- Express wiring ---

const app = express();
app.use(express.raw({ type: "application/entity-statement+jwt", limit: "64kb" }));

// Route federation configuration requests
app.all("/.well-known/openid-federation", async (req, res) => {
  const request = new Request(`https://op.umu.se${req.originalUrl}`, { method: "GET" });
  const response = await opAuthority.handleRequest(request);
  res.status(response.status).type("application/entity-statement+jwt").send(await response.text());
});

// Route explicit registration requests to the FedOidcProvider role handler
app.post("/registration", async (req, res) => {
  const request = new Request(`https://op.umu.se${req.originalUrl}`, {
    method: "POST",
    headers: req.headers as Record<string, string>,
    body: req.body,
  });
  const response = await opAuthority.handleRequest(request);
  res.status(response.status).type("application/entity-statement+jwt").send(await response.text());
});

// Automatic registration: RP sends a Request Object in the authorization request
app.get("/auth", async (req, res, next) => {
  const requestJwt = req.query.request as string | undefined;

  if (requestJwt) {
    // Process the federation registration
    const result = await processAutomaticRegistration(requestJwt, trustAnchors, {
      opEntityId: OP_ID,
      replayStore: storage.replay,
      cache: storage.cache,
      httpClient: fetch,
    });

    if (isOk(result)) {
      const { rpEntityId, resolvedRpMetadata } = result.value;

      // Dynamically register the client in node-oidc-provider
      // (implementation depends on your adapter/storage)
      // Then forward to the OIDC provider's authorization endpoint
    } else {
      res.status(400).json({ error: result.error.code, error_description: result.error.description });
      return;
    }
  }

  // Forward to node-oidc-provider for standard OIDC flow
  return oidc.callback()(req, res, next);
});

// Standard OIDC endpoints
app.use("/", oidc.callback());

app.listen(443);
```

---

## 4. RP Setup

A Relying Party at `wiki.ligo.org` using Express + `@oidfed/leaf` + `@oidfed/oidc`.

```typescript
import express from "express";
import { Leaf, discoverEntity } from "@oidfed/leaf";
import {
  FedOidcClient,
  explicitRegistration,
  createClientAssertion,
  StaticOidcProtocolKeyProvider,
} from "@oidfed/oidc";
import {
  entityId,
  generateSigningKey,
  isOk,
  JwkSigner,
  MemoryFederationKeyProvider,
} from "@oidfed/core";
import type { TrustAnchorSet } from "@oidfed/core";

const RP_ID = entityId("https://wiki.ligo.org");
const federationKeyPair = await generateSigningKey("ES256");
const protocolKeyPair = await generateSigningKey("ES256");
const federationKeyProvider = new MemoryFederationKeyProvider({
  signer: new JwkSigner(federationKeyPair.privateKey),
  publicJwk: federationKeyPair.publicKey,
});

const trustAnchors: TrustAnchorSet = new Map([
  [entityId("https://edugain.geant.org"), { jwks: { keys: [taPublicKey] } }],
]);

// Federation keys sign the RP Entity Configuration. Protocol keys sign
// Request Objects and private_key_jwt client assertions.

// --- Leaf entity (serves Entity Configuration) ---

const rpRole = new FedOidcClient({
  protocolKeyProvider: new StaticOidcProtocolKeyProvider({
    requestObjectSigner: new JwkSigner(protocolKeyPair.privateKey),
  }),
  metadata: {
    redirect_uris: ["https://wiki.ligo.org/callback"],
    response_types: ["code"],
    grant_types: ["authorization_code"],
    client_registration_types: ["automatic"],
    token_endpoint_auth_method: "private_key_jwt",
    jwks: { keys: [protocolKeyPair.publicKey] },
  },
  requestDelivery: "query",
});

const leaf = new Leaf({
  entityId: RP_ID,
  authorityHints: [entityId("https://incommon.org")],
  keyProvider: federationKeyProvider,
  metadata: {
    federation_entity: {
      organization_name: "Wiki Ligo",
    },
  },
  roles: [rpRole],
});

// --- Express wiring ---

const app = express();

// Serve Entity Configuration
app.get("/.well-known/openid-federation", async (req, res) => {
  const request = new Request(`https://wiki.ligo.org${req.originalUrl}`, { method: "GET" });
  const response = await leaf.handleRequest(request);
  res.status(response.status).type("application/entity-statement+jwt").send(await response.text());
});

// Login: discover OP, register, redirect
app.get("/login", async (req, res) => {
  const opId = req.query.op as string;

  // 1. Discover the OP
  const opDiscoveryResult = await discoverEntity(entityId(opId), trustAnchors, {
    httpClient: fetch,
  });
  if (!isOk(opDiscoveryResult)) {
    res.status(400).send("Discovery failed: " + opDiscoveryResult.error.description);
    return;
  }
  const opDiscovery = opDiscoveryResult.value;

  // 2. Automatic registration — builds Request Object with trust chain using OIDC role instance.
  const resultVal = await rpRole.createAuthorizationRequest(
    opDiscovery,
    { scope: "openid profile", state: "random-state" },
    trustAnchors,
  );

  if (!isOk(resultVal)) {
    res.status(400).send("Registration failed: " + resultVal.error.description);
    return;
  }
  const result = resultVal.value;

  // 3. Redirect to OP
  if (result.delivery !== "query") throw new Error("expected query-mode result");
  res.redirect(result.authorizationUrl);
});

// Callback: exchange code for tokens
app.get("/callback", async (req, res) => {
  const { code, state } = req.query;

  // Create a client assertion for token endpoint authentication
  const assertion = await createClientAssertion(
    RP_ID,
    "https://op.umu.se/token",
    new JwkSigner(protocolKeyPair.privateKey),
  );

  // Exchange code for tokens using private_key_jwt
  const tokenResponse = await fetch("https://op.umu.se/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: code as string,
      redirect_uri: "https://wiki.ligo.org/callback",
      client_id: RP_ID,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: assertion,
    }),
  });

  const tokens = await tokenResponse.json();
  res.json(tokens);
});

app.listen(443);
```
```

### Explicit Registration Variant

```typescript
app.get("/login-explicit", async (req, res) => {
  const opId = req.query.op as string;
  const opDiscoveryResult = await discoverEntity(entityId(opId), trustAnchors);
  if (!isOk(opDiscoveryResult)) {
    res.status(400).send("Discovery failed");
    return;
  }
  const opDiscovery = opDiscoveryResult.value;

  // Explicit registration — sends EC to OP's registration endpoint
  const registrationResult = await explicitRegistration(
    opDiscovery,
    {
      entityId: RP_ID,
      keyProvider: federationKeyProvider,
      authorityHints: [entityId("https://incommon.org")],
      metadata: {
        openid_relying_party: {
          redirect_uris: ["https://wiki.ligo.org/callback"],
          response_types: ["code"],
          client_registration_types: ["explicit"],
          token_endpoint_auth_method: "private_key_jwt",
          jwks: { keys: [protocolKeyPair.publicKey] },
        },
      },
    },
    trustAnchors,
  );

  if (!isOk(registrationResult)) {
    res.status(400).send("Registration failed: " + registrationResult.error.description);
    return;
  }
  const registration = registrationResult.value;

  // registration.clientId — use for subsequent OIDC requests
  // registration.clientSecret — if provided
  // registration.trustChainExpiresAt — must re-register before this time
  // Now make a standard authorization request with the assigned client_id
});
```

---

## 5. End-to-End Flow

Sequence when a user at `wiki.ligo.org` authenticates via `op.umu.se`:

### Discovery Phase (bottom-up)

1. **RP discovers OP**: `wiki.ligo.org` fetches `https://op.umu.se/.well-known/openid-federation` → Entity Configuration JWT
2. **Resolve trust chains**: Follow `authority_hints` upward: `op.umu.se → umu.se → swamid.se → edugain.geant.org`
3. **Fetch Subordinate Statements**: At each level, fetch from the authority's `federation_fetch_endpoint`
4. **Validate**: Check signatures top-down from Trust Anchor, apply metadata policies, check constraints

### Registration Phase

5. **Automatic**: RP builds a signed Request Object containing its Entity Configuration + trust chain, sends it as the `request` parameter in the authorization URL
6. **OP processes**: Validates Request Object, resolves RP's trust chain (`wiki.ligo.org → incommon.org → edugain.geant.org`), verifies signature, validates RP metadata

### Authentication Phase

7. **Standard OIDC**: Authorization code flow proceeds normally — user authenticates, RP receives code
8. **Token exchange**: RP uses `private_key_jwt` (via `createClientAssertion`) to authenticate at the token endpoint
9. **ID Token**: RP receives and validates the ID Token

### Key Security Properties

- **Cross-OP replay prevention**: `opEntityId` is required in `processAutomaticRegistration` — the `aud` claim in the Request Object is validated against it
- **JTI replay detection**: The `replayStore` prevents Request Object reuse
- **Branded DiscoveryResult**: Only `discoverEntity()` can produce it — prevents unchecked data from flowing into registration
- **Trust chain expiry**: Explicit registration results include `trustChainExpiresAt` — the RP must re-register before this time
