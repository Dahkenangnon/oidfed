# `@oidfed/oidc`

OpenID Connect and OAuth 2.0 federation flows — automatic and explicit client registration, Request Object validation, and RP/OP metadata validation as defined in OpenID Federation 1.0.

## Overview

The `@oidfed/oidc` package bridges federation trust chains with OIDC/OAuth client registration. It provides role classes that declare provider/client metadata in parent entity contexts and class-owned methods to create or validate signed Request Objects.

---

## Capabilities & Usage Guide

### Composing Roles with Parent Entities
Roles represent OIDC and OAuth functions (such as Relying Parties or OpenID Providers). They are composed directly into a parent `Leaf`, `TrustAnchor`, or `Intermediates` entity. The parent entity merges the role's metadata and routes standard path requests to the role's handlers automatically.

```ts
import { Leaf } from "@oidfed/leaf";
import { FedOidcClient, StaticOidcProtocolKeyProvider } from "@oidfed/oidc";
import { generateSigningKey, JwkSigner, MemoryFederationKeyProvider } from "@oidfed/core";

// 1. Setup federation keys
const fedKeyPair = await generateSigningKey("ES256");
const keyProvider = new MemoryFederationKeyProvider({
  signer: new JwkSigner(fedKeyPair.privateKey),
  publicJwk: fedKeyPair.publicKey
});

// 2. Setup protocol key provider (used to sign Request Objects)
const protocolKeyPair = await generateSigningKey("ES256");
const protocolKeyProvider = new StaticOidcProtocolKeyProvider({
  requestObjectSigner: new JwkSigner(protocolKeyPair.privateKey)
});

// 3. Initialize parent Leaf with FedOidcClient role composed
const leaf = new Leaf({
  entityId: "https://rp.example.com",
  authorityHints: ["https://federation.example.org"],
  keyProvider,
  metadata: {
    federation_entity: { organization_name: "My Org" }
  },
  roles: [
    new FedOidcClient({
      protocolKeyProvider,
      metadata: {
        client_name: "My OIDC RP",
        redirect_uris: ["https://rp.example.com/callback"],
        response_types: ["code"],
        client_registration_types: ["automatic"],
        jwks: { keys: [protocolKeyPair.publicKey] }
      }
    })
  ]
});
```

---

### Client-Side Automatic Registration
For automatic registration, RPs sign authorization requests (Request Objects) that carry their metadata and trust chain in header parameters. The client role generates this JWT and prepares standard authorization parameters automatically.

```ts
import { Leaf } from "@oidfed/leaf";
import { createTrustAnchorSet, isOk } from "@oidfed/core";

// 1. Resolve and validate OP's metadata
const trustAnchors = createTrustAnchorSet([
  { entityId: "https://ta.example.org", jwks: { keys: [taKey] } }
]);
const opDiscoveryResult = await Leaf.discoverEntity(
  "https://op.example.com",
  trustAnchors,
  { httpClient: fetch }
);

if (isOk(opDiscoveryResult)) {
  // 2. Build authorization request
  const authzResult = await rpRole.createAuthorizationRequest(
    opDiscoveryResult.value,
    { scope: "openid profile", state: "xyz-state-abc" },
    trustAnchors
  );

  if (isOk(authzResult)) {
    const { authorizationUrl } = authzResult.value;
    console.log("Redirect user to:", authorizationUrl);
  }
}
```

---

### Provider-Side Explicit Registration
For explicit registration, OPs serve a `/registration` endpoint. RPs post their self-signed Entity Configuration or trust chains, and OPs reply with a signed explicit registration response whose `sub` is the RP Entity Identifier and whose registered client credentials are under `metadata.openid_relying_party`.

When an RP supplies a `trust_chain` header or an `application/trust-chain+json` request body, OP-side processing validates that supplied value as a full Trust Chain and uses it before attempting live Federation Entity Discovery. Invalid supplied chains fail registration.

RP-side explicit registration accepts only HTTP `200` responses with exact `Content-Type: application/explicit-registration-response+jwt`. It returns `clientId` from `metadata.openid_relying_party.client_id` and `clientSecret` from `metadata.openid_relying_party.client_secret` when the OP provisions one.

```ts
import { FedOidcProvider, OIDCRegistrationAdapter } from "@oidfed/oidc";

const trustAnchors = new Map([
  ["https://ta.example.org", { jwks: { keys: [taPublicKey] } }]
]);

const opRole = new FedOidcProvider({
  registrationPath: "/registration",
  trustAnchors,
  registrationResponseTtlSeconds: 3600,
  registrationProtocolAdapter: new OIDCRegistrationAdapter(),
  generateClientSecret: async (clientId) => {
    // Return a client secret to embed under metadata.openid_relying_party.client_secret,
    // or undefined if the RP is a public client.
    return "generated-secret-string";
  },
  metadata: {
    authorization_endpoint: "https://op.example.com/auth",
    token_endpoint: "https://op.example.com/token",
    client_registration_types_supported: ["automatic", "explicit"],
    jwks: { keys: [opProtocolPublicKey] }
  }
});
```

---

### Custom Protocol Registration Adapter
To customize how client metadata is validated or enriched during explicit registration requests, implement the `RegistrationProtocolAdapter` interface.

```ts
import type { RegistrationProtocolAdapter, RegistrationProtocolAdapterContext } from "@oidfed/oidc";
import { federationError, FederationErrorCode, ok, err } from "@oidfed/core";

class CustomAdapter implements RegistrationProtocolAdapter {
  validateClientMetadata(raw, context) {
    const oidcMeta = raw.openid_relying_party;
    if (oidcMeta && typeof oidcMeta === "object" && !oidcMeta.contacts) {
      return err(federationError(
        FederationErrorCode.InvalidMetadata,
        "contacts field is required by this federation profile"
      ));
    }
    return ok(raw);
  }

  enrichResponseMetadata(rpMeta, trustChain, context) {
    return {
      ...rpMeta,
      client_id: trustChain.entityId,
      custom_enriched_field: "enriched-value"
    };
  }
}
```

---

## Configuration API Reference

### `FedOidcClientConfig` & `FedOauthClientConfig`
Configuration parameters used to instantiate `FedOidcClient` and `FedOauthClient` facades.

| Configuration Field | Type | Required | Description |
|:---|:---|:---|:---|
| `protocolKeyProvider` | `OidcProtocolKeyProvider` | **Yes** | Provider managing active signing keys for OIDC/OAuth protocol assertions (e.g. Request Objects). |
| `metadata` | `Record<string, unknown>` | No | Role-specific metadata parameters (e.g. `redirect_uris`, `response_types`, `jwks`) merged under the corresponding entity type key. |
| `requestObjectTtlSeconds` | `number` | No | Lifespan in seconds for generated Request Objects. Defaults to 60. |
| `includePeerTrustChain` | `boolean` | No | Whether to include a Trust Chain for the peer entity (OP) in the `peer_trust_chain` JWS header, as defined in Section 4.4. Defaults to false. |
| `requestDelivery` | `RequestDelivery` | No | Request object transmission mode: `"form_post"` (default), `"query"`, `"request_uri"`, or `"par"`. |
| `requestUri` | `string` | No | Prefiled Request Object URI if using `"request_uri"` transmission delivery. |

### `AutomaticRegistrationResult`
The result of `FedOidcClient.createAuthorizationRequest(...)` is a discriminated union based on the selected `requestDelivery` mode:

- **`delivery: "query"`**:
  - `requestObjectJwt` (`string`): The signed Request Object JWT.
  - `trustChain` (`ValidatedTrustChain`): The validated OP trust chain.
  - `trustChainExpiresAt` (`number`): Expiration timestamp of the chain.
  - `authorizationUrl` (`string`): Full redirect URL containing `request` and `client_id` as query parameters.
- **`delivery: "form_post"`**:
  - `requestObjectJwt` (`string`): The signed Request Object JWT.
  - `trustChain` (`ValidatedTrustChain`): The validated OP trust chain.
  - `trustChainExpiresAt` (`number`): Expiration timestamp of the chain.
  - `authorizationEndpoint` (`string`): Endpoint to POST the request object to.
  - `formParams` (`Record<string, string>`): Form parameters to submit (contains `request` and `client_id`).
- **`delivery: "request_uri"`**:
  - `requestObjectJwt` (`string`): The signed Request Object JWT.
  - `trustChain` (`ValidatedTrustChain`): The validated OP trust chain.
  - `trustChainExpiresAt` (`number`): Expiration timestamp of the chain.
  - `requestUri` (`string`): The pre-configured URI where the caller must serve the Request Object.
  - `authorizationUrl` (`string`): Full redirect URL containing `request_uri` and `client_id` as query parameters.
- **`delivery: "par"`**:
  - `requestObjectJwt` (`string`): The signed Request Object JWT.
  - `trustChain` (`ValidatedTrustChain`): The validated OP trust chain.
  - `trustChainExpiresAt` (`number`): Expiration timestamp of the chain.
  - `pushedAuthorizationRequestEndpoint` (`string`): The PAR endpoint of the OP.
  - `authorizationUrl` (`string`): Full redirect URL containing the OP-issued `request_uri` and `client_id` as query parameters.
  - `parRequestUri` (`string`): The URN-style request URI returned by the OP's PAR endpoint.
  - `parExpiresAt` (`number`): Expiration timestamp of the PAR session.

### `FedOidcProviderConfig` & `FedOauthProviderConfig`
Configuration parameters used to instantiate `FedOidcProvider` and `FedOauthProvider` facades.

| Configuration Field | Type | Required | Description |
|:---|:---|:---|:---|
| `registrationPath` | `string` | No | Endpoint sub-path mapped for explicit client registration requests. Defaults to `"/registration"`. |
| `metadata` | `Record<string, unknown>` | No | Role-specific provider metadata properties (e.g. `authorization_endpoint`, `jwks`) merged under the matching entity type key. |
| `trustAnchors` | `TrustAnchorSet` | Yes, via role config or parent context | Non-empty trust anchors required for OP-side automatic and explicit registration processing. |
| `registrationResponseTtlSeconds`| `number` | No | TTL in seconds for signed explicit registration responses. Capped by RP trust chain validity. |
| `registrationProtocolAdapter` | `RegistrationProtocolAdapter`| No | Pluggable adapter to customize metadata schema validations and response enrichments. |
| `generateClientSecret` | `(sub: EntityId) => Promise<string>`| No | Hook called to issue a client secret for confidential Relying Parties. Returned values are embedded under `metadata.openid_relying_party.client_secret`. |
| `onRegistrationInvalidation` | `(sub: EntityId) => Promise<void>`| No | Late pre-commit hook called after validation and response preparation, immediately before `onRegistration`. |

### `FedOauthResourceConfig`
Configuration parameters used to instantiate `FedOauthResource` facades.

| Configuration Field | Type | Required | Description |
|:---|:---|:---|:---|
| `metadata` | `Record<string, unknown>` | No | Role-specific metadata properties merged under `oauth_resource` keys. |
| `jwks` | `{ keys: any[] }` | No | JWK Set representing resource server key validation material. |

---

## Frequently Asked Questions (FAQ)

### Q: Why must federation signing keys and OIDC/OAuth protocol keys remain separate?
**A:** Separating key scopes is an essential security requirement of the OpenID Federation specification. Federation keys are used solely to sign federation artifacts (Entity Configurations, subordinate statements, trust marks). OIDC/OAuth protocol keys are used for transaction-level operations (signing Request Objects, verifying authorization requests, client assertions). Mixing these roles weakens key isolation.

### Q: What is the `peer_trust_chain` JWS header parameter?
**A:** As defined in **Section 4.4** of the OpenID Federation specification, the `peer_trust_chain` parameter is a JOSE JWS header parameter containing a JSON array of Entity Statements representing the Trust Chain between the peer entity being interacted with (e.g. the OP, when sent by the RP in a Request Object) and the selected Trust Anchor. 

Crucially:
- It allows the RP to supply the OP's trust chain as resolved/chosen by the RP, ensuring both entities establish trust under a common selected Trust Anchor. This helps achieve **Federation Integrity** and **Metadata Integrity** properties.
- If both `trust_chain` (describing the RP's own chain) and `peer_trust_chain` are present, the Trust Anchor at the root of both chains **MUST** be the same.
- OP-side processing validates supplied `trust_chain` and `peer_trust_chain` values as full Trust Chains. Invalid supplied chains are rejected instead of being ignored in favor of live discovery.
- According to **Section 12.2.1**, the `peer_trust_chain` header parameter **MUST NOT** be used when the request body itself is a Trust Chain (`application/trust-chain+json`); it is only permitted when the request body is the Entity Configuration of the RP (`application/entity-statement+jwt`).
- It **MUST NOT** be included inside Entity Configurations or Subordinate Statements themselves.

### Q: How do OPs prevent Request Object replay attacks?
**A:** Every Request Object includes a unique identifier (`jti`) and expiration time (`exp`). The OP-side validator enforces that the request has not expired and queries a `ReplayStore` to verify that the `jti` has not been previously observed from the same issuer.
