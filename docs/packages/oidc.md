# @oidfed/oidc

OpenID Connect and OAuth 2.0 federation flows — automatic and explicit client registration, Request Object validation, and RP/OP metadata processing as defined in OpenID Federation 1.0.

## Role

This package bridges federation trust chains to OIDC/OAuth client registration and provides typed OP/RP metadata schemas, plus class-based role facades that plug directly into `Leaf`, `TrustAnchor`, or `Intermediate` instances.

## Install

```bash
pnpm add @oidfed/core @oidfed/oidc
```

## API

### OIDC & OAuth Roles

These roles are added to the `roles` array when initializing a `Leaf`, `TrustAnchor`, or `Intermediate`. They automatically merge their respective metadata into the parent entity configuration, handle incoming HTTP requests (like registration endpoints), and initialize with the parent entity's context.

All roles implement the `EntityRole` interface:

```ts
export interface EntityRole {
  type: string;
  metadata: Record<string, any>;
  routes: Map<string, (request: Request) => Promise<Response>>;
  initialize?(context: EntityContext): void;
}
```

---

### `FedOidcProvider`
Acts as an OpenID Connect Provider (OP). Registers the OIDC provider metadata and serves the federation registration endpoints.

```ts
import { FedOidcProvider } from "@oidfed/oidc";

const opRole = new FedOidcProvider({
  authorization_endpoint: "https://op.example.com/auth",
  token_endpoint: "https://op.example.com/token",
  jwks: { keys: [protocolKey] },
  // Optional endpoints:
  federation_registration_endpoint: "https://op.example.com/register",
  pushed_authorization_request_endpoint: "https://op.example.com/par",
  client_registration_types_supported: ["automatic", "explicit"],
  // Pluggable hooks for client registration validation:
  onRegisterClient: async (clientId, metadata, trustChain) => {
    // Custom check/storage logic for new clients. Returning true approves registration.
    return true;
  }
});
```

---

### `FedOidcClient`
Acts as an OpenID Connect Relying Party (RP). Registers OIDC Relying Party metadata.

```ts
import { FedOidcClient } from "@oidfed/oidc";

const rpRole = new FedOidcClient({
  protocolKeyProvider: oidcProtocolKeyProvider,
  metadata: {
    client_name: "My OIDC RP",
    redirect_uris: ["https://rp.example.com/callback"],
    response_types: ["code"],
    client_registration_types: ["automatic"],
    jwks: { keys: [protocolPublicKey] },
  },
  requestObjectTtlSeconds: 300,
  includePeerTrustChain: true,
  requestDelivery: "query", // "query" | "form_post" | "request_uri"
});
```

#### `createAuthorizationRequest(discovery, authzRequestParams, trustAnchors, options?)`
Creates a signed Request Object and builds authorization parameters/URLs for automatic registration.

- **`discovery`**: A `DiscoveryResult` (returned from `Leaf.discoverEntity()`).
- **`authzRequestParams`**: Standard authorization request parameters (e.g., `{ scope: "openid", state: "state" }`).
- **`trustAnchors`**: A `TrustAnchorSet` used to construct and validate trust chains.
- **`options`**: Optional `FederationOptions` to override clock/httpClient settings.

Returns a `Promise<Result<AutomaticRegistrationResult>>`:
```ts
interface AutomaticRegistrationResult {
  delivery: "query" | "form_post" | "request_uri";
  authorizationUrl?: string;
  formPostAction?: string;
  formPostFields?: Record<string, string>;
  requestObjectJwt?: string;
}
```

---

### `FedOauthProvider`
Acts as an OAuth 2.0 Authorization Server (AS).

```ts
import { FedOauthProvider } from "@oidfed/oidc";

const oauthAsRole = new FedOauthProvider({
  authorization_endpoint: "https://as.example.com/auth",
  token_endpoint: "https://as.example.com/token",
  jwks: { keys: [protocolKey] },
});
```

---

### `FedOauthClient`
Acts as an OAuth 2.0 Client.

```ts
import { FedOauthClient } from "@oidfed/oidc";

const oauthClientRole = new FedOauthClient({
  protocolKeyProvider: oidcProtocolKeyProvider,
  metadata: {
    client_name: "My OAuth Client",
    redirect_uris: ["https://client.example.com/callback"],
    response_types: ["code"],
    client_registration_types: ["automatic"],
    jwks: { keys: [protocolPublicKey] },
  },
  requestObjectTtlSeconds: 300,
  includePeerTrustChain: true,
  requestDelivery: "query", // "query" | "form_post" | "request_uri"
});
```

#### `createAuthorizationRequest(discovery, authzRequestParams, trustAnchors, options?)`
Has the same signature and return type as `FedOidcClient.createAuthorizationRequest()`.
```

---

### `FedOauthResource`
Acts as an OAuth 2.0 Resource Server (RS).

```ts
import { FedOauthResource } from "@oidfed/oidc";

const rsRole = new FedOauthResource({
  jwks: { keys: [protocolKey] },
});
```

---

### Composing Roles with Entities

To compose any role, pass it in the `roles` option of `Leaf`, `TrustAnchor`, or `Intermediate`:

```ts
import { Leaf } from "@oidfed/leaf";
import { FedOidcClient } from "@oidfed/oidc";
import { MemoryFederationKeyProvider, federationKey } from "@oidfed/core";

const rpEntity = new Leaf({
  entityId: "https://rp.example.com",
  authorityHints: ["https://federation.example.org"],
  keyProvider: new MemoryFederationKeyProvider(federationKey(federationSigningKey)),
  metadata: {
    federation_entity: {
      organization_name: "My Leaf Entity",
    },
  },
  roles: [
    new FedOidcClient({
      redirect_uris: ["https://rp.example.com/callback"],
      response_types: ["code"],
      client_registration_types: ["automatic"],
      jwks: { keys: [protocolPublicKey] },
    })
  ]
});
```

The resulting Entity Configuration JSON will automatically merge the role's metadata under the matching type key (e.g. `openid_relying_party`). Any incoming requests to the OIDC registration endpoints will be routed by `.handleRequest(request)`.

### Typed OIDC Metadata Types

```ts
import type {
  OpenIDRelyingPartyMetadata,
  OpenIDProviderMetadata,
  OIDCFederationMetadata,
} from "@oidfed/oidc";
```

### Key Separation

Two key domains must stay separate:

- **Federation entity keys**:
  top-level Entity Statement `jwks`, Entity Configurations, subordinate statements, trust marks, resolve responses, explicit-registration federation artifacts
- **OIDC/OAuth protocol keys**:
  `openid_relying_party.jwks`, `openid_provider.jwks`, Request Objects, PAR client assertions, and token-endpoint signatures.

The hosting application owns OIDC/OAuth protocol public-key publication through role metadata configurations. This package consumes that metadata and uses `OidcProtocolKeyProvider` for protocol signing.
