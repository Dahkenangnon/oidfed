# @oidfed/oidc

OpenID Connect and OAuth 2.0 federation flows — automatic and explicit client registration, Request Object validation, and RP/OP metadata processing as defined in OpenID Federation 1.0.

## Role

Use when building an RP alongside `@oidfed/leaf` or an OP alongside `@oidfed/authority`. This package bridges federation trust chains to OIDC client registration and provides typed OP/RP metadata schemas that replace the loose `z.record()` entity-type metadata in `@oidfed/core`.

## Install

```bash
pnpm add @oidfed/core @oidfed/oidc
```

## API

### Typed OIDC Metadata Schemas

```ts
import {
  OpenIDRelyingPartyMetadataSchema,
  OpenIDProviderMetadataSchema,
  OIDCFederationMetadataSchema,
  FederationEntityMetadataSchema,
  FederationMetadataSchema,
  validateOIDCMetadata,
} from "@oidfed/oidc";
import type {
  OpenIDRelyingPartyMetadata,
  OpenIDProviderMetadata,
  OIDCFederationMetadata,
} from "@oidfed/oidc";
```

### RP Automatic Registration

Automatic registration signs an OIDC Request Object. It uses OIDC protocol keys, not federation entity keys.

```ts
import { automaticRegistration, StaticOidcProtocolKeyProvider } from "@oidfed/oidc";
import { discoverEntity } from "@oidfed/leaf";
import { entityId, JwkSigner } from "@oidfed/core";

const opDiscovery = await discoverEntity(opEntityId, trustAnchors);

const result = await automaticRegistration(
  opDiscovery,
  {
    entityId: entityId("https://rp.example.com"),
    protocolKeyProvider: new StaticOidcProtocolKeyProvider({
      requestObjectSigner: new JwkSigner(rpProtocolSigningKey),
    }),
    authorityHints: [entityId("https://federation.example.org")],
    metadata: {
      openid_relying_party: {
        redirect_uris: ["https://rp.example.com/callback"],
        response_types: ["code"],
        client_registration_types: ["automatic"],
        jwks: { keys: [rpProtocolPublicKey] },
      },
    },
    requestDelivery: "form_post",
  },
  { scope: "openid profile", state: "xyz" },
  trustAnchors,
);
```

The result is a discriminated union on `delivery`:

```ts
type AutomaticRegistrationResult =
  | { delivery: "query"; requestObjectJwt; authorizationUrl; trustChain; trustChainExpiresAt }
  | { delivery: "form_post"; requestObjectJwt; authorizationEndpoint; formParams; trustChain; trustChainExpiresAt }
  | { delivery: "request_uri"; requestObjectJwt; requestUri; authorizationUrl; trustChain; trustChainExpiresAt }
  | { delivery: "par"; requestObjectJwt; pushedAuthorizationRequestEndpoint; authorizationUrl; parRequestUri; parExpiresAt; trustChain; trustChainExpiresAt };
```

### RP Explicit Registration

Explicit registration sends the RP federation Entity Configuration to the OP. It therefore uses federation keys, not OIDC protocol keys.

```ts
import { explicitRegistration } from "@oidfed/oidc";

const result = await explicitRegistration(
  opDiscovery,
  {
    entityId: entityId("https://rp.example.com"),
    keyProvider: rpFederationKeyProvider,
    authorityHints: [entityId("https://federation.example.org")],
    metadata: {
      openid_relying_party: {
        redirect_uris: ["https://rp.example.com/callback"],
        response_types: ["code"],
        client_registration_types: ["explicit"],
        jwks: { keys: [rpProtocolPublicKey] },
      },
    },
  },
  trustAnchors,
);
```

### OP Processing Automatic Registration

```ts
import { processAutomaticRegistration } from "@oidfed/oidc";
import type { ProcessAutomaticRegistrationOptions, ProcessedRegistration } from "@oidfed/oidc";

const result = await processAutomaticRegistration(requestObjectJwt, trustAnchors, {
  opEntityId: entityId("https://op.example.com"),
  replayStore: storage.replay,
  cache: storage.cache,
  httpClient: fetch,
});
```

Returns `Result<ProcessedRegistration, FederationError>` and never throws.
`replayStore` is required because automatic-registration Request Objects are single-use. The JTI is claimed only after claims, trust chains, metadata, protocol keys, and the Request Object signature have been validated.

### OP Processing Explicit Registration

```ts
import { processExplicitRegistration } from "@oidfed/oidc";
import type { ProcessExplicitRegistrationOptions } from "@oidfed/oidc";

const result = await processExplicitRegistration(
  requestBody,
  contentType,
  trustAnchors,
  { opEntityId: entityId("https://op.example.com") },
);
```

### Request Object Validation

```ts
import { validateAutomaticRegistrationRequest } from "@oidfed/oidc";
import type { ValidatedRequestObject, ValidatedRequestObjectResult } from "@oidfed/oidc";

const result = validateAutomaticRegistrationRequest(requestObjectJwt, {
  opEntityId: entityId("https://op.example.com"),
});
```

### Registration Adapter

```ts
import { OIDCRegistrationAdapter } from "@oidfed/oidc";
```

Implements `RegistrationProtocolAdapter` for plugging OIDC-aware registration validation into `@oidfed/authority`.

### Protocol Key Provider

```ts
import { StaticOidcProtocolKeyProvider } from "@oidfed/oidc";
import type { OidcProtocolKeyProvider } from "@oidfed/oidc";
```

```ts
interface OidcProtocolKeyProvider {
  getRequestObjectSigner(): Promise<JwtSigner>;
  getClientAssertionSigner?(): Promise<JwtSigner>;
}
```

This provider is only for OIDC/OAuth protocol signatures such as:

- automatic-registration Request Objects
- PAR `private_key_jwt` client assertions
- other RP-side protocol assertions the hosting application chooses to build with this package

It is not the source of truth for published federation keys.

### Client Assertions

```ts
import { createClientAssertion } from "@oidfed/oidc";
import { JwkSigner } from "@oidfed/core";

const assertion = await createClientAssertion(
  "https://rp.example.com",
  "https://op.example.com/token",
  new JwkSigner(rpProtocolSigningKey),
  { expiresInSeconds: 60 },
);
```

## Key Separation

For stable `v1.0.0`, two key domains must stay separate:

- Federation entity keys:
  top-level Entity Statement `jwks`, Entity Configurations, subordinate statements, trust marks, resolve responses, explicit-registration federation artifacts
- OIDC protocol keys:
  `openid_relying_party.jwks`, `jwks_uri`, `signed_jwks_uri`, Request Objects, PAR client assertions, and token-endpoint `private_key_jwt`

The hosting application owns OIDC protocol public-key publication through RP or OP metadata. This package only consumes that metadata and uses `OidcProtocolKeyProvider` for protocol signing.
