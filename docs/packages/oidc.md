# `@oidfed/oidc`

<p align="center">
  <a href="https://www.npmjs.com/package/@oidfed/oidc"><img alt="npm" src="https://img.shields.io/npm/v/@oidfed/oidc.svg" /></a>
  <a href="https://www.npmjs.com/package/@oidfed/oidc"><img alt="downloads" src="https://img.shields.io/npm/dm/@oidfed/oidc.svg" /></a>
  <a href="https://github.com/Dahkenangnon/oidfed/blob/main/packages/oidc/LICENSE"><img alt="license" src="https://img.shields.io/npm/l/@oidfed/oidc.svg" /></a>
  <a href="https://packagephobia.com/result?p=@oidfed/oidc"><img alt="install size" src="https://packagephobia.com/badge?p=@oidfed/oidc" /></a>
</p>

`@oidfed/oidc` adds OpenID Connect and OAuth federation roles to a `Leaf`, `TrustAnchor`, or `Intermediate`. It creates and validates registration artifacts and supplies metadata for the parent Entity Configuration. Your existing OP and RP remain responsible for the OIDC protocol flow.

See [OIDC federation responsibilities](../guide/operator-responsibilities.md#oidc-federation) for registration lifetime enforcement, persistence, protocol keys, and replay storage.

OIDC federation registration validates chains independently of published Trust Mark acceptance. Applications that require an accreditation must check it before accepting the registration, using core's [`checkTrustMarkRequirements()`](core.md#trust-marks) with the validated chain supplied to their registration integration.

Supply `options.logger` for [host-supplied logging](core.md#host-supplied-logging). Registration messages name failures in `registrationProtocolAdapter`, `generateClientSecret`, `onRegistrationInvalidation`, or `onRegistration`. A callback rejecting metadata logs at warn; an unexpected callback failure logs at error. The handler retains its existing error response or exception, even if the logger throws. Client metadata, secrets, and callback errors are excluded from messages.

“Client Registration Request validated” means protocol validation succeeded. “Client Registration completed” follows the configured registration callbacks. Your application still owns persistence and registration expiry.

The federation option `customConstraintChecks` registers synchronous checks for additional constraints in authenticated Trust Chains. Failed checks reject the operation; unknown constraints remain ignored. See [custom constraints](core.md#custom-constraints) for the API and callback context.

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

Each stateful role instance belongs to one host. Create a separate instance for another Entity Identifier. Request construction uses the final composed local metadata, including fields supplied by the host. Per-call options override supplied fields while retaining the host’s other federation options, including its HTTP client and clock.

An `OidcProviderRole` or `OAuthAuthorizationServerRole` installs an explicit-registration handler. Its final composed metadata must include `"explicit"` in `client_registration_types_supported`, as required by [Federation §12.2](https://openid.net/specs/openid-federation-1_0.html#section-12.2). Supply that capability through the role or host metadata. Missing or incompatible configuration fails before publication. RP registration-method choices remain application configuration.

When publishing OP or AS metadata, a supplied `issuer` must exactly match the host’s Entity Identifier ([§5.1.3](https://openid.net/specs/openid-federation-1_0.html#section-5.1.3), [§5.1.4](https://openid.net/specs/openid-federation-1_0.html#section-5.1.4)). Before sending explicit registration, the RP also checks that the discovered registration endpoint uses HTTPS and has no fragment, including a bare trailing `#`. Invalid endpoints return `invalid_metadata` without a POST. Query strings and explicit ports remain supported.

`OIDCFederationPublicationMetadata` describes metadata published before superior completion under [Federation §5](https://openid.net/specs/openid-federation-1_0.html#section-5). Its protocol blocks may omit fields supplied by superiors. `OIDCFederationMetadata` and the protocol-specific metadata types describe effective metadata; protocol APIs validate the effective metadata before consuming it.

### Validate metadata independently

Each OIDC/OAuth role has two static parsers: `parseMetadata(raw)` for effective metadata and `parsePublicationMetadata(raw)` for a publication that Superiors may complete. Both return `{ success: true, data }` or `{ success: false, error }` without making network requests.

```ts
import {
  OidcProviderRole,
  type OpenIDProviderPublicationMetadata,
} from "@oidfed/oidc";

const draft: OpenIDProviderPublicationMetadata = {
  client_registration_types_supported: ["explicit"],
};
const publication = OidcProviderRole.parsePublicationMetadata(draft);
const effective = OidcProviderRole.parseMetadata(resolvedMetadata.openid_provider);
if (!effective.success) {
  // Inspect effective.error.issues before using any endpoints or capabilities.
}
```

The same methods exist on `OidcRelyingPartyRole`, `OAuthAuthorizationServerRole`, `OAuthClientRole`, and `OAuthResourceRole`. Each role also has a corresponding exported `*PublicationMetadata` type, inferred from its publication schema: `OpenIDRelyingPartyPublicationMetadata`, `OpenIDProviderPublicationMetadata`, `OAuthAuthorizationServerPublicationMetadata`, `OAuthClientPublicationMetadata`, and `OAuthResourcePublicationMetadata`. `OIDCFederationPublicationMetadata` uses these types for its blocks. The AS publication type matches the shared core definition. Resource metadata defaults to the federation profile, which permits common informational fields without a `resource` parameter. Use `OAuthResourceRole.parseMetadata(raw, { profile: "rfc9728" })` to require a complete RFC 9728 resource document.

Attaching a role to a Leaf or Authority checks its composed publication automatically. Missing protocol fields can be completed by a Superior; malformed supplied fields are rejected. Registration checks effective metadata after Superior overrides and policy application, before using endpoints or signing requests. Role-driven discovery can select another conformant path; malformed caller-supplied discovery results and invalid supplied chains are errors.

Unknown extension fields are preserved. Registered fields are checked against their protocol definitions, and federation registration-type arrays remain open to extension values. Explicit-registration responses use single-valued selections in place of RP Metadata Choices inputs; selections and protocol defaults must satisfy the RP's advertised choices.

These checks reject malformed metadata that earlier releases could accept. They establish metadata conformance, not issuer trust, endpoint availability, or the validity of embedded `signed_metadata` or `software_statement` JWTs. Continue to authenticate federation evidence before using parsed metadata. Bare Leaf/Authority hosts without a matching protocol role perform federation validation only; applications can call these parsers explicitly.

### Client-side automatic registration

This fragment uses an `rpRole` already composed into a parent, a pinned `taKey`, and fresh `sessionState` / `sessionNonce` values bound to the login session.
For automatic registration, RPs sign authorization requests as Request Objects using protocol keys. The `trust_chain` JOSE header carries the RP's chain when available; metadata is resolved from its Entity Statements. Use `OidcRelyingPartyRole.automaticallyRegister(...)` for the normal RP flow: it discovers the OP, validates the selected trust chain, signs the Request Object, and returns the delivery-specific authorization parameters. Use `createAuthorizationRequest(...)` only when you already have a validated `DiscoveryResult`.

RP and OP protocol metadata accept public keys with optional `kid` values, as defined by [Federation §5.2.1](https://openid.net/specs/openid-federation-1_0.html#section-5.2.1). During automatic registration, a Request Object can omit its header `kid` when the resolved protocol key set contains exactly one key. Multiple-key sets require the header identifier ([OIDC Core §10.1](https://openid.net/specs/openid-connect-core-1_0.html#Signing)); when supplied, it must identify a matching client key ([RFC 9101 §6.2](https://www.rfc-editor.org/rfc/rfc9101.html#section-6.2)). Explicit registration keeps the federation key requirements for the request Entity Configuration while accepting optional identifiers in its protocol metadata. The built-in signers include their key identifiers in generated JWTs.

With `requestDelivery: "par"`, the role posts the signed Request Object as proof under [Federation §12.1.1.2](https://openid.net/specs/openid-federation-1_0.html#section-12.1.1.2). It adds a `private_key_jwt` assertion when the selected chains' effective RP and OP metadata both advertise that method, as required by [§12.1.4](https://openid.net/specs/openid-federation-1_0.html#section-12.1.4). The RP can advertise a supported-method list or a single method. When both are supplied, the single value must belong to the list ([RP Metadata Choices §2](https://openid.net/specs/openid-connect-rp-metadata-choices-1_0.html#section-2)).

When mutual support for JWT authentication is absent, the request uses its signed Request Object alone. Contradictory method declarations return `invalid_metadata`. Each signer used must be published in the RP protocol metadata through `jwks`, `jwks_uri`, or `signed_jwks_uri`. The assertion audience is the OP Entity Identifier.

`OAuthClientRole` reads the client's authentication methods from `oauth_client` metadata. `RelyingPartyRole` reads them from `openid_relying_party`, including when the entity hosts both roles ([Federation §12.1.5](https://openid.net/specs/openid-federation-1_0.html#section-12.1.5)).

When `requestDelivery: "request_uri"` is used, OP metadata that explicitly sets `request_uri_parameter_supported: false` blocks delivery before an authorization URL is produced.

For OIDC query, form-post, and hosted Request Object delivery, the authorization
URL or form fields include the supplied `scope` and `response_type` alongside
`client_id`. These values match the signed claims, as required by
[OpenID Connect Core §§6.1 and 6.2](https://openid.net/specs/openid-connect-core-1_0.html#RequestObject)
and permitted by [JAR §5](https://www.rfc-editor.org/rfc/rfc9101.html#section-5).
OAuth-only delivery uses the existing JAR parameters. With PAR, authorization
parameters stay inside the JWT and client authentication stays outside it, per
[RFC 9126 §3](https://www.rfc-editor.org/rfc/rfc9126.html#section-3).

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

The example assumes pinned `taPublicKey` and an RSA `opProtocolPublicKey` used by the existing OP for RS256 signatures. Compose `opRole` into the parent entity to initialize and route it. If confidential clients need secrets, provide `generateClientSecret` backed by your credential store and a cryptographically secure generator.
For explicit registration, OPs serve a `/registration` endpoint. RPs post their self-signed Entity Configuration or trust chains, and OPs reply with a signed explicit registration response whose `sub` is the RP Entity Identifier and whose registered client credentials are under `metadata.openid_relying_party`.

The OP validates a supplied `trust_chain` header or `application/trust-chain+json` body. Without a supplied chain, it starts discovery from the submitted Entity Configuration and its authority hints. Each candidate must authenticate that request with the RP federation keys attested by its Immediate Superior before the OP selects a path. Invalid supplied chains fail registration. Request media types are parameter-free and matched exactly. See [Federation §12.2.2](https://openid.net/specs/openid-federation-1_0.html#section-12.2.2).

The submitted metadata is resolved through the selected chain's superior metadata, constraints, and metadata policy. The adapter receives that resolved metadata, and its final output must satisfy the same federation policy ([§12.2.2](https://openid.net/specs/openid-federation-1_0.html#section-12.2.2), [§6.1.4.2](https://openid.net/specs/openid-federation-1_0.html#section-6.1.4.2)). Registration hooks run after response preparation.

Unchanged resolved values retain their policy result. Adapters may change fields governed by standard operators or custom check operators when the result passes those policies. Fields governed by a custom modifying operator must retain their resolved value, including an omission. This is the library's registration contract: custom operators may transform values without being idempotent under [§6.1.3.2](https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.2). The RP applies the same rule when checking response metadata.

Optional response defaults are included when federation policy permits them; a `value: null` removal remains omitted. See [§12.2.3](https://openid.net/specs/openid-federation-1_0.html#section-12.2.3) and [§6.1.3.1.1](https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1.1).

The RP selects a shared-anchor path that attests its current signing key and sends that path's Immediate Superior as its authority hint, as allowed by [§12.2.1](https://openid.net/specs/openid-federation-1_0.html#section-12.2.1). Explicit registration needs an Immediate Superior because the response must name it under [§12.2.3](https://openid.net/specs/openid-federation-1_0.html#section-12.2.3). An entity that is also a configured anchor can register through an eligible upward path.

Both sides accept finite NumericDates and validate required statement times and payload `crit` claims. Fractional timestamps are preserved in registration and chain deadlines. Configure `understoodCriticalClaims` only for extensions your application understands and processes. Unknown critical claims fail validation under [§3.1.1](https://openid.net/specs/openid-federation-1_0.html#section-3.1.1).

RP Entity Configuration metadata under `metadata.openid_relying_party` must not include registration-response-only credential fields such as `client_id`, `client_secret`, `client_id_issued_at`, or `client_secret_expires_at`.

RP-side explicit registration accepts only HTTP `200` responses with exact `Content-Type: application/explicit-registration-response+jwt`. The RP rejects a response whose `iat` is later than its current time plus `clockSkewSeconds` (60 seconds by default), as required by [Federation §12.2.5](https://openid.net/specs/openid-federation-1_0.html#section-12.2.5) and [§3.2](https://openid.net/specs/openid-federation-1_0.html#section-3.2). The response must name the selected Trust Anchor, use the authority hint from the selected RP trust chain, and expire no later than that selected RP trust chain. It returns `clientId` from `metadata.openid_relying_party.client_id` and `clientSecret` from `metadata.openid_relying_party.client_secret` when the OP provisions one. If the OP also sends `client_secret_expires_at`, that value must not be earlier than the signed response expiry.

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
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
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
| `requestObjectTtlSeconds` | `number` | No | Lifespan in seconds for generated Request Objects. Defaults to 300. |
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

Automatic processing returns `ProcessedAutomaticRegistration`, including `protocolKeys: { keys, source }` from the Request Object verification. The `onRegistration` callback receives a detached metadata copy with those keys in `jwks`, including when they were resolved through `jwks_uri` or `signed_jwks_uri`. Resolution keeps the precedence in [Federation §5.2.1](https://openid.net/specs/openid-federation-1_0.html#section-5.2.1). Explicit registration retains its existing result and metadata handling.

Explicit-registration processing errors use the [§8.9](https://openid.net/specs/openid-federation-1_0.html#section-8.9) status mappings referenced by [§12.2.4](https://openid.net/specs/openid-federation-1_0.html#section-12.2.4): `invalid_trust_chain` returns 400, and `invalid_trust_anchor` returns 404. An invalid request signature returns 400 `invalid_request`; internal failures receive a sanitized server error.

### `OAuthResourceRoleConfig`

Configuration parameters used to instantiate `OAuthResourceRole`.

| Configuration Field | Type | Required | Description |
|:---|:---|:---|:---|
| `metadata` | `Record<string, unknown>` | No | Role-specific metadata properties merged under `oauth_resource` keys. |
| `jwks` | `JWKSet` | No | Core JWK Set representing resource server key validation material. |

## Common questions

### Federation and protocol signing keys

[OpenID Federation §3.1.1](https://openid.net/specs/openid-federation-1_0.html#section-3.1.1) says Federation Entity Keys **SHOULD NOT** be used for other protocols. oidfed provides separate federation and protocol key providers so applications can maintain that separation. Federation keys sign federation artifacts and federation endpoint client assertions; protocol keys sign OIDC/OAuth Request Objects and protocol client assertions.

The application manages protocol-key rotation and publishes the matching public keys in role metadata. `ProtocolSigningKeyProvider` selects signers; it has no federation-style publication or retirement lifecycle.

### Registration lifetime enforcement

[Federation §12.3](https://openid.net/specs/openid-federation-1_0.html#section-12.3) requires an OP registration to expire no later than the RP chain used to establish it. The RP must also stop using registration when its selected OP chain expires, then successfully reevaluate trust for automatic registration or renew explicit registration.

The explicit handler caps its signed response expiry to the RP chain, including the submitted Entity Configuration. OP automatic processing returns the validated RP `trustChain`. RP automatic and explicit registration return the selected OP chain's expiry as `trustChainExpiresAt`. An explicitly registered RP must renew before the earlier of `expiresAt` and `trustChainExpiresAt`.

Your application persists and enforces these deadlines in its client database and request processing. `onRegistration` receives client metadata and an optional secret; obtain the registration deadline from the signed response when storing the OP's client record. See [the integration responsibilities](../guide/operator-responsibilities.md#oidc-federation).

### What is the `peer_trust_chain` JWS header parameter?

As defined in **Section 4.4** of the OpenID Federation specification, the `peer_trust_chain` parameter is a JOSE JWS header parameter containing a JSON array of Entity Statements representing the Trust Chain between the peer entity being interacted with (e.g. the OP, when sent by the RP in a Request Object) and the selected Trust Anchor.

The processing rules are:

- It allows the RP to supply the OP's trust chain as resolved/chosen by the RP. Supplying both chains binds the two views to the same federation.
- If both `trust_chain` (describing the RP's own chain) and `peer_trust_chain` are present, the Trust Anchor at the root of both chains **MUST** be the same.
- In automatic registration, `peer_trust_chain` can be supplied independently. Without `trust_chain`, the OP discovers and validates the RP's chain normally; its selected Trust Anchor need not match the peer chain's anchor. The peer chain is still fully validated against configured Trust Anchors, and its resolved OP metadata is returned in `peerResolvedOpMetadata` for the integrator to use.
- OP-side processing validates supplied `trust_chain` and `peer_trust_chain` values as full Trust Chains. Each header must be a nonempty array of JWT strings. Malformed values, including empty arrays and `null`, are rejected before automatic-registration discovery or replay storage. Invalid supplied chains are rejected instead of being ignored in favor of live discovery.
- According to **Section 12.2.1**, the `peer_trust_chain` header parameter **MUST NOT** be used when the request body itself is a Trust Chain (`application/trust-chain+json`); it is only permitted when the request body is the Entity Configuration of the RP (`application/entity-statement+jwt`).
- It **MUST NOT** be included inside Entity Configurations or Subordinate Statements themselves.

### How do OPs prevent Request Object replay attacks?

Every Request Object needs a `jti` and `exp`. OP-side processing checks expiry and claims the `(issuer, audience, jti)` tuple through the configured `ReplayStore`. The claim is retained until `exp + clockSkewSeconds`, covering the full acceptance window required by [Federation §12.1.1.1](https://openid.net/specs/openid-federation-1_0.html#section-12.1.1.1). Use a shared atomic implementation across instances; the OP role requires this store for automatic registration.
