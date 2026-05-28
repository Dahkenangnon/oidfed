# @oidfed/oidc

OpenID Connect and OAuth 2.0 federation flows — automatic and explicit client registration, Request Object validation, and RP/OP metadata processing as defined in [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html).

> **Status:** prerelease — API may change before the upcoming stable `1.0.0` release.

## Install

```bash
npm install @oidfed/core @oidfed/oidc
```

## Quick Start

### RP — Automatic Registration

```ts
import { automaticRegistration } from "@oidfed/oidc";
import { discoverEntity } from "@oidfed/leaf";

const opDiscovery = await discoverEntity(opEntityId, trustAnchors);

const result = await automaticRegistration(
  opDiscovery,
  rpConfig, // defaults to form_post delivery
  { scope: "openid profile", state: "xyz" },
  trustAnchors,
);

switch (result.delivery) {
  case "form_post":
    // Render an HTML form posting result.formParams to result.authorizationEndpoint
    break;
  case "query":
  case "request_uri":
  case "par":
    // 302 the user-agent to result.authorizationUrl
    break;
}
```

### OP — Processing Registration

```ts
import { processAutomaticRegistration } from "@oidfed/oidc";

const result = await processAutomaticRegistration(requestObjectJwt, trustAnchors, {
  opEntityId: entityId("https://op.example.com"),
  jtiStore,
});
// Result<ProcessedRegistration, FederationError> — never throws
```

## Request Object delivery modes

The Authorization Request can carry the signed Request Object in four ways. Select one via
`rpConfig.requestDelivery`. **The default is `"form_post"`** — the safest choice when the
Request Object embeds a `trust_chain` header (the JWT often exceeds 8 KB, hitting URL and
header-length ceilings in HTTP intermediaries).

### `form_post` (default)

Posts the Request Object as an `application/x-www-form-urlencoded` body. The RP renders an
auto-submit HTML form whose `action` is the OP authorization endpoint.

```ts
const result = await automaticRegistration(
  opDiscovery,
  { ...rpConfig, requestDelivery: "form_post" },
  authzParams,
  trustAnchors,
);
if (result.delivery === "form_post") {
  // Serve an HTML form to the user-agent:
  //   <form method="post" action={result.authorizationEndpoint}>
  //     <input type="hidden" name="request" value={result.formParams.request}>
  //     <input type="hidden" name="client_id" value={result.formParams.client_id}>
  //   </form>
}
```

### `query`

Places the Request Object value in a `?request=` query parameter of a GET to the OP
authorization endpoint. Compact but constrained by URL/header length limits when the
Request Object carries an embedded `trust_chain`.

```ts
const result = await automaticRegistration(
  opDiscovery,
  { ...rpConfig, requestDelivery: "query" },
  authzParams,
  trustAnchors,
);
if (result.delivery === "query") {
  // 302 the user-agent to result.authorizationUrl (contains ?request=&client_id=)
}
```

### `request_uri` (by reference)

The RP hosts the signed Request Object at a publicly-reachable URL it provides. The OP
fetches that URL when it receives `?request_uri=<URL>&client_id=<RP>`. The library does
NOT host the JWT — the caller must serve `result.requestObjectJwt` at the supplied
`requestUri` with `Content-Type: application/oauth-authz-req+jwt`, typically with a short
TTL and single-use semantics.

```ts
const result = await automaticRegistration(
  opDiscovery,
  {
    ...rpConfig,
    requestDelivery: "request_uri",
    requestUri: "https://rp.example.com/request-object/abc123",
  },
  authzParams,
  trustAnchors,
);
if (result.delivery === "request_uri") {
  // 1. Cache result.requestObjectJwt under the URL path you provided
  // 2. 302 the user-agent to result.authorizationUrl
}
```

### `par` (Pushed Authorization Request)

The library POSTs the Request Object directly to the OP's
`pushed_authorization_request_endpoint` (advertised in the OP `openid_provider` metadata),
receives a short-lived `urn:ietf:params:oauth:request_uri:<id>`, and returns an
authorization URL embedding that urn. The PAR request includes a `private_key_jwt`
client_assertion whose audience is the OP's Entity Identifier.

```ts
const result = await automaticRegistration(
  opDiscovery,
  { ...rpConfig, requestDelivery: "par" },
  authzParams,
  trustAnchors,
);
if (result.delivery === "par") {
  // 302 the user-agent to result.authorizationUrl (contains ?request_uri=urn:...)
  // result.parExpiresAt tells you when the urn becomes unusable
}
```

## Migration from 0.3.x

The 0.4.0 release introduces a breaking change to `automaticRegistration`'s return type
and default behavior:

- **`AutomaticRegistrationResult` is now a discriminated union on `result.delivery`.** Code
  that reads `result.authorizationUrl` must first narrow on the delivery mode, OR opt back
  into the historical shape by passing `requestDelivery: "query"`:

  ```ts
  // 0.3.x ergonomics, preserved in 0.4.0 with one extra config field:
  const result = await automaticRegistration(
    opDiscovery,
    { ...rpConfig, requestDelivery: "query" },
    authzParams,
    trustAnchors,
  );
  if (result.delivery === "query") {
    redirectTo(result.authorizationUrl);
  }
  ```

- **The default delivery mode is `"form_post"`.** Existing callers that did not specify a
  delivery mode previously received GET-query URLs; in 0.4.0 they now receive form-post
  result shapes (`result.authorizationEndpoint` + `result.formParams`) and must render an
  HTML form instead of issuing a 302.

## What's Included

- RP-side automatic registration (Request Object + trust chain embedding)
- RP-side explicit registration (Entity Configuration POST)
- OP-side processing for both registration types (returns `Result`, never throws)
- Typed OP/RP metadata schemas (replace core's loose `z.record()` with field-level validation)
- Request Object validation
- Client assertion creation (`private_key_jwt`)
- `OIDCRegistrationAdapter` for plugging into `@oidfed/authority`

## Documentation

Full API reference: [docs/packages/oidc.md](https://github.com/Dahkenangnon/oidfed/blob/main/docs/packages/oidc.md)

## Part of @oidfed

| Package | Role |
|---------|------|
| [@oidfed/core](https://www.npmjs.com/package/@oidfed/core) | Federation primitives |
| [@oidfed/authority](https://www.npmjs.com/package/@oidfed/authority) | Trust Anchor & Intermediate operations |
| [@oidfed/leaf](https://www.npmjs.com/package/@oidfed/leaf) | Leaf Entity toolkit |
| **@oidfed/oidc** | OIDC/OAuth 2.0 federation flows (this package) |
| [@oidfed/cli](https://www.npmjs.com/package/@oidfed/cli) | CLI for federation debugging |

## License

[Apache-2.0](./LICENSE) — see [`NOTICE`](./NOTICE) for attribution.
