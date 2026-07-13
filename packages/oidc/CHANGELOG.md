# Changelog

All notable changes to `@oidfed/oidc` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- OIDC/OAuth role classes, role config types, and protocol signing-key providers now use explicit domain names across root exports and docs.
- Public documentation now treats the root `@oidfed/oidc` runtime surface as role/class-owned. Low-level registration helpers, constants, validators, and schemas are implementation details; use `OidcRelyingPartyRole`, `OidcProviderRole`, OAuth role classes, and type-only exports from the root package.
- OP-side automatic and explicit registration now require a non-empty Trust Anchor set. Provider roles fail during initialization when neither the role config nor parent entity context supplies trust anchors.
- OP-side registration now validates supplied `trust_chain`, `peer_trust_chain`, and exact parameter-free `application/trust-chain+json` inputs as full Trust Chains. Valid supplied RP chains are used before live Federation Entity Discovery; invalid supplied chains fail registration instead of falling back silently.
- Explicit-registration invalidation hooks now run only after validation and response preparation, immediately before registration commit hooks. Hook failures return sanitized `server_error` responses.
- RP-side explicit registration response processing now requires HTTP `200`, exact `application/explicit-registration-response+jwt`, a matching RP `sub`, and registered credentials under `metadata.openid_relying_party`.
- RP Entity Configuration metadata now rejects explicit-registration response-only credential fields; `client_id`, `client_secret`, `client_id_issued_at`, and `client_secret_expires_at` are valid only in explicit-registration response metadata.
- Provider role `registrationProtocolAdapter` config and OAuth resource `jwks` config now use typed public contracts instead of avoidable `any`.

## [0.8.0] - 2026-06-25

### Refactor

* context propagation, type exports and request overrides ([d6e9174](https://github.com/Dahkenangnon/oidfed/commit/d6e91742f9e32818caf96d05673f86a01fc15364))
* migrate E2E scenarios and OP participant to new class-based facades ([1e6f5e5](https://github.com/Dahkenangnon/oidfed/commit/1e6f5e56cadb107f4a5d860a4ce39adf2455229c))


## [0.7.0] - 2026-06-24

### Features

* export OIDCRegistrationAdapter class from public entrypoint ([de2c74c](https://github.com/Dahkenangnon/oidfed/commit/de2c74cf87a0fd9d0dc3fd260b5db761548ab064))

### Refactor

* stabilize API exports and add strict metadata schemas ([f23c205](https://github.com/Dahkenangnon/oidfed/commit/f23c205d2634f963bca810db8cb0dc6ad2be459c))


## [0.6.1] - 2026-06-24

_No user-visible changes — released as part of the coordinated wave._


## [0.6.0] - 2026-06-24

### Features

* unify runtime errors to monadic Result ([ba58a65](https://github.com/Dahkenangnon/oidfed/commit/ba58a656eec56ff34ef0ce1254b5747210219e17))
* export standard policy operators enum and re-export common core primitives ([92aeda6](https://github.com/Dahkenangnon/oidfed/commit/92aeda67ff5c8279b8211e089fc10374d7803433))
* unify persistence behind storage adapter ([f622fca](https://github.com/Dahkenangnon/oidfed/commit/f622fca5955bfee03c90192308bd86bd3e1ec9ed))
* separate federation and OIDC signing keys ([0664c90](https://github.com/Dahkenangnon/oidfed/commit/0664c90641288f41b561588d954badd7f6ae5a4e))
* enhance the npm published keyworks ([a0e38c4](https://github.com/Dahkenangnon/oidfed/commit/a0e38c46c7fcafd75341a3aa306350e8f0f1df8d))

### Bug Fixes

* harden public API types and add trust anchor helper ([3283001](https://github.com/Dahkenangnon/oidfed/commit/3283001bbd291a42843c5e768d34405c0b064eac))
* review the public api of every pkg ([a95c473](https://github.com/Dahkenangnon/oidfed/commit/a95c473f1a92bdd55a248fcc1a8b319da2208295))
* verify request objects with protocol keys ([c759b87](https://github.com/Dahkenangnon/oidfed/commit/c759b87f65fd04e9c35d695ba0ffbeb9917f21b2))
* add core dependency for package builds ([30d986d](https://github.com/Dahkenangnon/oidfed/commit/30d986df000c85c8e0320cc6b019c1c89d8015c7))

### Refactor

* implement new class-based developer experience and API design ([b2fe982](https://github.com/Dahkenangnon/oidfed/commit/b2fe98287f0c553feded3ec11b8b0059ebb41061))


### Changed

- **BREAKING.** OP automatic registration processing now requires `replayStore: ReplayStore`, namespaces claims by RP issuer and OP audience, and claims the JTI only after all cryptographic, metadata, and trust-chain validation succeeds.
- Added public `ClientAssertionOptions`; its clock and every registration clock use NumericDate seconds.
- Automatic and explicit registration now propagate injected clocks through Request Objects, Entity Configurations, PAR expiry, client assertions, and OP validation.

### Fixed

- Invalid Request Objects can no longer consume a legitimate JTI before signature validation. Replay backend failures now return `server_error`.

## [0.5.2] - 2026-05-28

_No user-visible changes — released as part of the coordinated wave._


## [0.5.1] - 2026-05-28

### Changed

- Refreshed `zod` runtime dependency (^4.0.0 resolving to 4.4.3, minor). No API change.
- Package README corrected — OP/RP schema description and `RegistrationProtocolAdapter` attribution updated to match the actual surface.

## [0.5.0] - 2026-05-23

### Added

- OP-side explicit registration handler support for the `/federation_registration` endpoint. It accepts `ExplicitRegistrationHandlerConfig` (opEntityId, signing-key resolver, trust anchors, optional protocol adapter, optional generateClientSecret and onRegistrationInvalidation hooks) and replaces the equivalent handler previously housed inside `@oidfed/authority`.
- `ExplicitRegistrationRequestPayload`, `ExplicitRegistrationResponsePayload` types now exported from `@oidfed/oidc`. The runtime schemas are implementation details.
- `RegistrationProtocolAdapter`, `RegistrationProtocolAdapterContext` interfaces now exported from `@oidfed/oidc`. Previously lived in `@oidfed/core`.
- Client registration type definitions now live in `@oidfed/oidc`. The runtime constants are implementation details.
- OIDC explicit registration response JWT and media-type constants are internal to `@oidfed/oidc`. They replace the previous `JwtTyp.ExplicitRegistrationResponse` / `MediaType.ExplicitRegistrationResponse` entries, which have been removed from `@oidfed/core`.

### Changed

- **BREAKING (install-tree).** `@oidfed/core` moved from `dependencies` to `peerDependencies`. Consumers MUST install `@oidfed/core` alongside `@oidfed/oidc`. The peer range is `^0.4.0`. This guarantees a single resolved `@oidfed/core` when `@oidfed/oidc` is installed beside its siblings; the previous model could install two side-by-side copies and silently break module identity.

## [0.4.0] - 2026-05-19

### Added

- RP automatic registration now supports four Request Object delivery modes via the new
  `requestDelivery` config field: `"query"`, `"form_post"`, `"request_uri"`, and `"par"`.
- New `RequestDelivery` type re-exported from `@oidfed/oidc`.
- `par` mode coordinates a Pushed Authorization Request internally and returns a
  ready-to-redirect authorization URL embedding the OP-issued `urn:`-style request_uri.

### Changed

- **BREAKING.** `AutomaticRegistrationResult` is now a discriminated union on a `delivery`
  field. Each variant carries the fields needed to dispatch the Request Object:
  - `query` — `authorizationUrl` (full URL with `?request=&client_id=`)
  - `form_post` — `authorizationEndpoint` + `formParams`
  - `request_uri` — `requestUri` + `authorizationUrl` (with `?request_uri=&client_id=`)
  - `par` — `pushedAuthorizationRequestEndpoint` + `authorizationUrl` (urn-style) +
    `parRequestUri` + `parExpiresAt`
- **BREAKING.** The default `requestDelivery` is `"form_post"`. Callers that rely on the
  historical `?request=` query-parameter behavior must pass `requestDelivery: "query"`.
  The new default sidesteps URL/header length ceilings in HTTP intermediaries when the
  Request Object embeds a `trust_chain`.

### Migration

Either narrow on `result.value.delivery`, or configure the RP role with `requestDelivery: "query"` to preserve the
0.3.x result shape:

```ts
const result = await rpRole.createAuthorizationRequest(
  opDiscovery,
  authzParams,
  trustAnchors,
  { requestDelivery: "query" },
);
if (result.ok && result.value.delivery === "query") {
  redirectTo(result.value.authorizationUrl);
}
```

## [0.3.0] - 2026-05-12

### Changed

- Align with OpenID Federation 1.1 Final and OpenID Connect for OpenID Federation 1.1 Final (published 2026-05-11).

## [0.2.0] - 2026-04-28

### Changed

- Relicensed from MIT to Apache License 2.0. Includes `NOTICE` file.

## [0.1.0] - 2026-04-21

Initial release.
