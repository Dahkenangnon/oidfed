# `@oidfed/oidc`

<p align="center">
  <a href="https://www.npmjs.com/package/@oidfed/oidc"><img alt="npm" src="https://img.shields.io/npm/v/@oidfed/oidc.svg" /></a>
  <a href="https://www.npmjs.com/package/@oidfed/oidc"><img alt="downloads" src="https://img.shields.io/npm/dm/@oidfed/oidc.svg" /></a>
  <a href="https://github.com/Dahkenangnon/oidfed/blob/main/packages/oidc/LICENSE"><img alt="license" src="https://img.shields.io/npm/l/@oidfed/oidc.svg" /></a>
  <a href="https://packagephobia.com/result?p=@oidfed/oidc"><img alt="install size" src="https://packagephobia.com/badge?p=@oidfed/oidc" /></a>
</p>

`@oidfed/oidc` adds OpenID Connect and OAuth federation roles to a `Leaf`, `TrustAnchor`, or `Intermediate`. It creates and validates registration artifacts and supplies metadata for the parent Entity Configuration. Your existing OP and RP remain responsible for the OIDC protocol flow.

## Usage

### Composing roles with parent entities

Roles represent OIDC and OAuth functions (such as Relying Parties or OpenID Providers). They are composed directly into a parent `Leaf`, `TrustAnchor`, or `Intermediate` entity. The parent entity merges the role's metadata and routes standard path requests to the role's handlers automatically.

```ts
import { Leaf } from "@oidfed/leaf";
import { OidcRelyingPartyRole, StaticProtocolSigningKeyProvider } from "@oidfed/oidc";
import {
  createFederationSigningKey,
  generateSigningKey,
  JwkSigner,
  MemoryFederationKeyProvider,
} from "@oidfed/core";

// 1. Setup federation keys
const fedKeyPair = await generateSigningKey("ES256");
const keyProvider = new MemoryFederationKeyProvider(
  createFederationSigningKey(fedKeyPair.privateKey),
);

// 2. Setup protocol key provider (used to sign Request Objects)
const protocolKeyPair = await generateSigningKey("ES256");
const protocolKeyProvider = new StaticProtocolSigningKeyProvider({
  requestObjectSigner: new JwkSigner(protocolKeyPair.privateKey)
});

// 3. Initialize parent Leaf with OidcRelyingPartyRole role composed
const leaf = new Leaf({
  entityId: "https://rp.example.com",
  authorityHints: ["https://federation.example.org"],
  keyProvider,
  metadata: {
    federation_entity: { organization_name: "My Org" }
  },
  roles: [
    new OidcRelyingPartyRole({
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

### Client-side automatic registration

This fragment uses an `rpRole` already composed into a parent, a pinned `taKey`, and fresh `sessionState` / `sessionNonce` values bound to the login session.
For automatic registration, RPs sign authorization requests as Request Objects using protocol keys. The `trust_chain` JOSE header carries the RP's chain when available; metadata is resolved from its Entity Statements. Use `OidcRelyingPartyRole.automaticallyRegister(...)` for the normal RP flow: it discovers the OP, validates the selected trust chain, signs the Request Object, and returns the delivery-specific authorization parameters. Use `createAuthorizationRequest(...)` only when you already have a validated `DiscoveryResult`.

When `requestDelivery: "par"` is used, the role posts the signed Request Object with `private_key_jwt` client authentication. Both the Request Object signer and client-assertion signer must be published in the RP protocol metadata through `jwks`, `jwks_uri`, or `signed_jwks_uri`. The current API does not configure mutual-TLS/self-signed TLS client authentication for PAR.

When `requestDelivery: "request_uri"` is used, OP metadata that explicitly sets `request_uri_parameter_supported: false` blocks delivery before an authorization URL is produced.

```ts
import { createTrustAnchorSet, isOk } from "@oidfed/core";

const trustAnchors = createTrustAnchorSet([
  { entityId: "https://ta.example.org", jwks: { keys: [taKey] } }
]);

const authzResult = await rpRole.automaticallyRegister(
  {
    opEntityId: "https://op.example.com",
    redirect_uri: "https://rp.example.com/callback",
    scope: "openid profile",
    state: sessionState,
    nonce: sessionNonce,
    requestDelivery: "query"
  },
  { trustAnchors, httpClient: fetch }
);

if (isOk(authzResult) && authzResult.value.delivery === "query") {
  const { authorizationUrl } = authzResult.value;
  console.log("Redirect user to:", authorizationUrl);
}
```

### Provider-side explicit registration

The example assumes pinned `taPublicKey` and an `opProtocolPublicKey` used by the existing OP. Compose `opRole` into the parent entity to initialize and route it. If confidential clients need secrets, provide `generateClientSecret` backed by your credential store and a cryptographically secure generator.
For explicit registration, OPs serve a `/registration` endpoint. RPs post their self-signed Entity Configuration or trust chains, and OPs reply with a signed explicit registration response whose `sub` is the RP Entity Identifier and whose registered client credentials are under `metadata.openid_relying_party`.

When an RP supplies a `trust_chain` header or an exact `application/trust-chain+json` request body, OP-side processing validates that supplied value as a full Trust Chain and uses it before attempting live Federation Entity Discovery. Explicit registration request media types are parameter-free and matched exactly. Invalid supplied chains fail registration.

RP Entity Configuration metadata under `metadata.openid_relying_party` must not include registration-response-only credential fields such as `client_id`, `client_secret`, `client_id_issued_at`, or `client_secret_expires_at`.

RP-side explicit registration accepts only HTTP `200` responses with exact `Content-Type: application/explicit-registration-response+jwt`. The response must name the selected Trust Anchor, use the authority hint from the selected RP trust chain, and expire no later than that selected RP trust chain. It returns `clientId` from `metadata.openid_relying_party.client_id` and `clientSecret` from `metadata.openid_relying_party.client_secret` when the OP provisions one. If the OP also sends `client_secret_expires_at`, that value must not be earlier than the signed response expiry.

OP-side explicit registration does not publish registration-management tokens in the signed response metadata. Adapter-enriched `registration_access_token` and `registration_client_uri` values are removed before signing and before registration hooks are called.

```ts
import { OidcProviderRole, OIDCRegistrationAdapter } from "@oidfed/oidc";
import { createTrustAnchorSet } from "@oidfed/core";

const trustAnchors = createTrustAnchorSet([
  {
    entityId: "https://ta.example.org",
    jwks: { keys: [taPublicKey] }
  }
]);

const opRole = new OidcProviderRole({
  registrationPath: "/registration",
  trustAnchors,
  registrationResponseTtlSeconds: 3600,
  registrationProtocolAdapter: new OIDCRegistrationAdapter(),
  metadata: {
    issuer: "https://op.example.com",
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["ES256"],
    authorization_endpoint: "https://op.example.com/auth",
    token_endpoint: "https://op.example.com/token",
    client_registration_types_supported: ["automatic", "explicit"],
    jwks: { keys: [opProtocolPublicKey] }
  }
});
```

### Custom protocol registration adapter

Implement `RegistrationProtocolAdapter` to add profile checks or enrich explicit registration responses. This example adds one profile rule; compose it with `OIDCRegistrationAdapter` if you also need its OIDC schema checks. The optional `context` contains validated peer-chain metadata when supplied.

```ts
import type { RegistrationProtocolAdapter } from "@oidfed/oidc";
import { federationError, FederationErrorCode, ok, err } from "@oidfed/core";

const customAdapter: RegistrationProtocolAdapter = {
  validateClientMetadata(raw, context) {
    const metadata = raw.openid_relying_party;
    if (metadata && typeof metadata === "object" && !("contacts" in metadata)) {
      return err(federationError(
        FederationErrorCode.InvalidMetadata,
        "contacts field is required by this federation profile",
      ));
    }
    return ok(raw);
  },
  enrichResponseMetadata(rpMeta, trustChain, context) {
    return {
      ...rpMeta,
      client_id: trustChain.entityId,
      custom_enriched_field: "enriched-value",
    };
  },
};
```

## Configuration

### `OidcRelyingPartyRoleConfig` & `OAuthClientRoleConfig`

Configuration parameters used to instantiate `OidcRelyingPartyRole` and `OAuthClientRole`.

| Configuration Field | Type | Required | Description |
|:---|:---|:---|:---|
| `protocolKeyProvider` | `ProtocolSigningKeyProvider` | **Yes** | Provider managing active signing keys for OIDC/OAuth protocol assertions (e.g. Request Objects). |
| `metadata` | `Record<string, unknown>` | No | Role-specific metadata parameters (e.g. `redirect_uris`, `response_types`, `jwks`) merged under the corresponding entity type key. |
| `requestObjectTtlSeconds` | `number` | No | Lifespan in seconds for generated Request Objects. Defaults to 60. |
| `includePeerTrustChain` | `boolean` | No | Whether to include a Trust Chain for the peer entity (OP) in the `peer_trust_chain` JWS header. Defaults to false. |
| `requestDelivery` | `RequestDelivery` | No | Request object transmission mode: `"form_post"` (default), `"query"`, `"request_uri"`, or `"par"`. |
| `requestUri` | `string` | No | Preconfigured Request Object URI if using `"request_uri"` transmission delivery. |

`OidcRelyingPartyRoleConfig` also accepts `trustAnchors` and `authorityHints`. Its registration methods take trust anchors from call options, then role config, then the parent context. Authority hints come from the parent context when present.

### Automatic registration result

`automaticallyRegister()` and `createAuthorizationRequest()` return a `Result<AutomaticRegistrationResult>`. After checking `ok`, narrow `value.delivery` before accessing fields specific to a delivery mode.

Every successful result contains `requestObjectJwt` (`string`), `trustChain` (`ValidatedTrustChain`, for the OP), and `trustChainExpiresAt` (NumericDate seconds).

| `delivery` | Additional fields | Application action |
|---|---|---|
| `"query"` | `authorizationUrl: string` | Redirect to the URL carrying `request` and `client_id` |
| `"form_post"` | `authorizationEndpoint: string`, `formParams: Record<string, string>` | POST the returned form fields to the endpoint |
| `"request_uri"` | `requestUri: string`, `authorizationUrl: string` | Serve `requestObjectJwt` at `requestUri`, then redirect |
| `"par"` | `pushedAuthorizationRequestEndpoint: string`, `authorizationUrl: string`, `parRequestUri: string`, `parExpiresAt: number` | Redirect to the returned URL before PAR expiry |

### `OidcProviderRoleConfig` and `OAuthAuthorizationServerRoleConfig`

Configuration parameters used to instantiate `OidcProviderRole` and `OAuthAuthorizationServerRole`.

| Configuration Field | Type | Required | Description |
|:---|:---|:---|:---|
| `registrationPath` | `string` | No | Endpoint sub-path mapped for explicit client registration requests. Defaults to `"/registration"`. |
| `metadata` | `Record<string, unknown>` | No | Role-specific provider metadata properties (e.g. `authorization_endpoint`, `jwks`) merged under the matching entity type key. |
| `trustAnchors` | `TrustAnchorSet` | Yes, via role config or parent context | Non-empty trust anchors required for OP-side automatic and explicit registration processing. |
| `registrationResponseTtlSeconds`| `number` | No | TTL in seconds for signed explicit registration responses. Capped by RP trust chain validity. |
| `registrationProtocolAdapter` | `RegistrationProtocolAdapter`| No | Pluggable adapter to customize metadata schema validations and response enrichments. |
| `generateClientSecret` | `(sub: EntityId) => Promise<string \| undefined>`| No | Hook called to issue a client secret for confidential Relying Parties. Returned values are embedded under `metadata.openid_relying_party.client_secret`. |
| `onRegistrationInvalidation` | `(sub: EntityId) => Promise<void>`| No | Late pre-commit hook called after validation and response preparation, immediately before `onRegistration`. |

`OidcProviderRoleConfig` additionally accepts `replayStore` and `onRegistration`. `replayStore` is required when calling `processAutomaticRegistration()`; it is not inherited from the parent storage automatically. `onRegistration(sub, clientMetadata, clientSecret?)` lets you persist the accepted registration. The OAuth authorization-server role exposes the explicit-registration route and does not expose the OP's automatic-registration method or these two hooks.

### `OAuthResourceRoleConfig`

Configuration parameters used to instantiate `OAuthResourceRole`.

| Configuration Field | Type | Required | Description |
|:---|:---|:---|:---|
| `metadata` | `Record<string, unknown>` | No | Role-specific metadata properties merged under `oauth_resource` keys. |
| `jwks` | `JWKSet` | No | Core JWK Set representing resource server key validation material. |

## Common questions

### Why must federation signing keys and OIDC/OAuth protocol keys remain separate?

Separating key scopes is an essential security requirement of the OpenID Federation specification. Federation keys are used solely to sign federation artifacts (Entity Configurations, subordinate statements, trust marks). OIDC/OAuth protocol keys are used for transaction-level operations (signing Request Objects, verifying authorization requests, client assertions). Mixing these roles weakens key isolation.

### What is the `peer_trust_chain` JWS header parameter?

As defined in **Section 4.4** of the OpenID Federation specification, the `peer_trust_chain` parameter is a JOSE JWS header parameter containing a JSON array of Entity Statements representing the Trust Chain between the peer entity being interacted with (e.g. the OP, when sent by the RP in a Request Object) and the selected Trust Anchor.

The processing rules are:

- It allows the RP to supply the OP's trust chain as resolved/chosen by the RP, so both entities establish trust under a common selected Trust Anchor. This binds the two views to the same federation.
- If both `trust_chain` (describing the RP's own chain) and `peer_trust_chain` are present, the Trust Anchor at the root of both chains **MUST** be the same.
- OP-side processing validates supplied `trust_chain` and `peer_trust_chain` values as full Trust Chains. Invalid supplied chains are rejected instead of being ignored in favor of live discovery.
- According to **Section 12.2.1**, the `peer_trust_chain` header parameter **MUST NOT** be used when the request body itself is a Trust Chain (`application/trust-chain+json`); it is only permitted when the request body is the Entity Configuration of the RP (`application/entity-statement+jwt`).
- It **MUST NOT** be included inside Entity Configurations or Subordinate Statements themselves.

### How do OPs prevent Request Object replay attacks?

Every Request Object needs a `jti` and `exp`. OP-side processing checks expiry and claims the `(issuer, audience, jti)` tuple through the configured `ReplayStore`. Use a shared atomic implementation across instances; the OP role requires this store for automatic registration.
