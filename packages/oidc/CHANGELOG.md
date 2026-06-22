# Changelog

All notable changes to `@oidfed/oidc` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **BREAKING.** `processAutomaticRegistration()` now requires `replayStore: ReplayStore`, namespaces claims by RP issuer and OP audience, and claims the JTI only after all cryptographic, metadata, and trust-chain validation succeeds.
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

- `createExplicitRegistrationHandler(config)` — self-contained OP-side handler for the `/federation_registration` endpoint. Accepts `ExplicitRegistrationHandlerConfig` (opEntityId, signing-key resolver, trust anchors, optional protocol adapter, optional generateClientSecret and onRegistrationInvalidation hooks). Replaces the equivalent handler previously housed inside `@oidfed/authority`.
- `ExplicitRegistrationRequestPayloadSchema`, `ExplicitRegistrationResponsePayloadSchema` (+ inferred types) now exported from `@oidfed/oidc`. Previously lived in `@oidfed/core`.
- `RegistrationProtocolAdapter`, `RegistrationProtocolAdapterContext` interfaces now exported from `@oidfed/oidc`. Previously lived in `@oidfed/core`.
- `ClientRegistrationType` constant + type now exported from `@oidfed/oidc`. Previously lived in `@oidfed/core`.
- `OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE` and `OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE` constants. They replace the previous `JwtTyp.ExplicitRegistrationResponse` / `MediaType.ExplicitRegistrationResponse` entries (which have been removed from `@oidfed/core`).

### Changed

- **BREAKING (install-tree).** `@oidfed/core` moved from `dependencies` to `peerDependencies`. Consumers MUST install `@oidfed/core` alongside `@oidfed/oidc`. The peer range is `^0.4.0`. This guarantees a single resolved `@oidfed/core` when `@oidfed/oidc` is installed beside its siblings; the previous model could install two side-by-side copies and silently break module identity.

## [0.4.0] - 2026-05-19

### Added

- `automaticRegistration` now supports four Request Object delivery modes via the new
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

Either narrow on `result.delivery`, or pass `requestDelivery: "query"` to preserve the
0.3.x result shape:

```ts
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

## [0.3.0] - 2026-05-12

### Changed

- Align with OpenID Federation 1.1 Final and OpenID Connect for OpenID Federation 1.1 Final (published 2026-05-11).

## [0.2.0] - 2026-04-28

### Changed

- Relicensed from MIT to Apache License 2.0. Includes `NOTICE` file.

## [0.1.0] - 2026-04-21

Initial release.
