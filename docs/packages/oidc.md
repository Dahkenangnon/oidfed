# @oidfed/oidc

OpenID Connect and OAuth 2.0 federation flows — automatic and explicit client registration, Request Object validation, and RP/OP metadata processing as defined in OpenID Federation 1.0.

## Role

Use when building an **RP** (alongside `@oidfed/leaf`) or an **OP** (alongside `@oidfed/authority`). Bridges federation trust chains to OIDC client registration and provides strictly typed OP/RP metadata schemas that replace the loose `z.record()` types in `@oidfed/core` with field-level Zod validation.

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

### RP — Automatic Registration

For OPs that support `client_registration_types: ["automatic"]`. The RP embeds its trust chain in a signed Request Object and delivers it to the authorization endpoint via one of four `requestDelivery` modes (default: `"form_post"`).

```ts
import { automaticRegistration } from "@oidfed/oidc";
import type {
  AutomaticRegistrationConfig,
  AutomaticRegistrationResult,
  RequestDelivery,
} from "@oidfed/oidc";
```

The result is a discriminated union on `delivery`:

```ts
type AutomaticRegistrationResult =
  | { delivery: "query"; requestObjectJwt; authorizationUrl; trustChain; trustChainExpiresAt }
  | { delivery: "form_post"; requestObjectJwt; authorizationEndpoint; formParams; trustChain; trustChainExpiresAt }
  | { delivery: "request_uri"; requestObjectJwt; requestUri; authorizationUrl; trustChain; trustChainExpiresAt }
  | { delivery: "par"; requestObjectJwt; pushedAuthorizationRequestEndpoint; authorizationUrl; parRequestUri; parExpiresAt; trustChain; trustChainExpiresAt };
```

```ts
const result: AutomaticRegistrationResult = await automaticRegistration(
  opDiscovery,        // DiscoveryResult from discoverEntity()
  {
    entityId: entityId("https://rp.example.com"),
    signingKeys: [rpSigningKey],
    authorityHints: [entityId("https://federation.example.org")],
    metadata: {
      openid_relying_party: {
        redirect_uris: ["https://rp.example.com/callback"],
        response_types: ["code"],
        client_registration_types: ["automatic"],
      },
    },
    requestDelivery: "form_post", // default — also accepts "query", "request_uri", "par"
  },
  { scope: "openid profile", state: "xyz" },
  trustAnchors,
);

switch (result.delivery) {
  case "form_post":
    // render an auto-submit HTML form posting result.formParams to result.authorizationEndpoint
    break;
  case "query":
  case "request_uri":
  case "par":
    // 302 the user-agent to result.authorizationUrl
    break;
}
```

See the [package README](../../packages/oidc/README.md#request-object-delivery-modes) for per-mode rationale and code samples.

### RP — Explicit Registration

For OPs that support `client_registration_types: ["explicit"]`. The RP sends its Entity Configuration to the OP's registration endpoint.

```ts
import { explicitRegistration } from "@oidfed/oidc";
import type { ExplicitRegistrationConfig, ExplicitRegistrationResult } from "@oidfed/oidc";
```

```ts
const result: ExplicitRegistrationResult = await explicitRegistration(
  opDiscovery,
  {
    entityId: entityId("https://rp.example.com"),
    signingKeys: [rpSigningKey],
    authorityHints: [entityId("https://federation.example.org")],
    metadata: {
      openid_relying_party: {
        redirect_uris: ["https://rp.example.com/callback"],
        response_types: ["code"],
        client_registration_types: ["explicit"],
      },
    },
  },
  trustAnchors,
);
// result.clientId, result.clientSecret, result.expiresAt
// result.registeredMetadata, result.trustChainExpiresAt (§12.3)
```

### OP — Processing Automatic Registration

Validates an incoming Request Object, resolves the RP's trust chain, and verifies the signature. Returns `Result<ProcessedRegistration, FederationError>` — never throws.

```ts
import { processAutomaticRegistration } from "@oidfed/oidc";
import type { ProcessAutomaticRegistrationOptions, ProcessedRegistration } from "@oidfed/oidc";
```

```ts
const result = await processAutomaticRegistration(requestObjectJwt, trustAnchors, {
  opEntityId: entityId("https://op.example.com"), // REQUIRED — prevents cross-OP replay
  jtiStore,
  httpClient: fetch,
});

if (isOk(result)) {
  const { rpEntityId, resolvedRpMetadata, trustChain } = result.value;
}
```

### OP — Processing Explicit Registration

Validates an RP Entity Configuration submitted to the registration endpoint. Returns `Result<ProcessedRegistration, FederationError>` — never throws.

```ts
import { processExplicitRegistration } from "@oidfed/oidc";
import type { ProcessExplicitRegistrationOptions } from "@oidfed/oidc";
```

```ts
const result = await processExplicitRegistration(
  requestBody,
  contentType, // "application/entity-statement+jwt" or "application/trust-chain+json"
  trustAnchors,
  { opEntityId: entityId("https://op.example.com") },
);
```

### Request Object Validation

Lightweight synchronous pre-check before the heavier trust chain resolution.

```ts
import { validateAutomaticRegistrationRequest } from "@oidfed/oidc";
import type { ValidatedRequestObject, ValidatedRequestObjectResult } from "@oidfed/oidc";
```

```ts
const result = validateAutomaticRegistrationRequest(requestObjectJwt, {
  opEntityId: entityId("https://op.example.com"),
});
// result.value: { rpEntityId, opEntityId, exp, jti, claims, trustChainHeader? }
```

### Registration Adapter

```ts
import { OIDCRegistrationAdapter } from "@oidfed/oidc";
```

Implements the `RegistrationProtocolAdapter` interface (also exported from this package). Plug into `@oidfed/authority` for OIDC-aware registration processing: validates `openid_relying_party` against `OpenIDRelyingPartyMetadataSchema` and sets `client_id` to the trust chain entity ID.

### Client Assertions

```ts
import { createClientAssertion } from "@oidfed/oidc";
```

```ts
// private_key_jwt for OP token endpoint authentication
const assertion = await createClientAssertion(
  "https://rp.example.com",       // client_id
  "https://op.example.com/token", // audience
  rpSigningKey,
  { expiresInSeconds: 60 },
);
```
