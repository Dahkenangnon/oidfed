# Changelog

All notable changes to `@oidfed/oidc` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
