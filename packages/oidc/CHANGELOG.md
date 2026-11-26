# Changelog

All notable changes to `@oidfed/oidc` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.0.0] - 2026-11-26

### Breaking Changes

* enforce federation artifact signing policy ([888e2a8](https://github.com/Dahkenangnon/oidfed/commit/888e2a86308baad021346123c109549c3740a704))
* unify storage and federation host contracts ([2882619](https://github.com/Dahkenangnon/oidfed/commit/28826192c47f6eb898a0d1f590c87aa12b3a3d5d))
* require host-provided crypto ([d748f11](https://github.com/Dahkenangnon/oidfed/commit/d748f1168d8819ea5943433400b858e26f7030fb))
* bind verification to caller context ([c138e09](https://github.com/Dahkenangnon/oidfed/commit/c138e09808827d95c83e0b4ea3cc90c5fce47ee4))

### Features

* configure request object typing policies ([a7e7de2](https://github.com/Dahkenangnon/oidfed/commit/a7e7de2a8f46084db3285d8055c5683049f53ac2))
* add policy-aware pushed authorization requests ([1ef63bb](https://github.com/Dahkenangnon/oidfed/commit/1ef63bb5b7716c0a0262f7035fe8df8f56bc0b23))
* support OAuth-only federation registration ([427e6f8](https://github.com/Dahkenangnon/oidfed/commit/427e6f8ce79779528b44cba042c5cdb290be3d75))
* allow read-only registration management credentials ([fbc079d](https://github.com/Dahkenangnon/oidfed/commit/fbc079dcadd72d55c4076fb212619982a4708720))
* integrate configurable trust establishment ([e437b4d](https://github.com/Dahkenangnon/oidfed/commit/e437b4d0cd2e03b5bd2108d2fcb49ff76b3dcfb1))
* enforce trust mark policy before registration ([2a2cdc4](https://github.com/Dahkenangnon/oidfed/commit/2a2cdc4f5c278e677181f21e36c797838a90b0b3))
* type partial publication metadata ([ad4e430](https://github.com/Dahkenangnon/oidfed/commit/ad4e4303c98d5de0df41a73ce43bbac4137447e7))

### Bug Fixes

* bound explicit registration HTTP transport ([cde0a66](https://github.com/Dahkenangnon/oidfed/commit/cde0a66c3c42f3062873922d5850365f70943115))
* correct metadata, theming, links and docs scrolling ([c6053e4](https://github.com/Dahkenangnon/oidfed/commit/c6053e47549cfa8bce16d99105de940c7c810dd3))
* correct ESM and CommonJS declaration exports ([3475f0b](https://github.com/Dahkenangnon/oidfed/commit/3475f0bbc7cc7eea7c8501e02acb83edd0970375))
* isolate and safely compose host metadata ([9ec838a](https://github.com/Dahkenangnon/oidfed/commit/9ec838a3bbb49dcf0973f0a7051a30feada1b7c6))
* check registration signers against resolved metadata ([fb9c6cc](https://github.com/Dahkenangnon/oidfed/commit/fb9c6cc814b2c0d05e9910929b8d3d7b2d831024))
* accept non-expiring client secrets ([ab9a55a](https://github.com/Dahkenangnon/oidfed/commit/ab9a55a9e547036c87d44a82a57c224a4b7d9093))
* honor chain selection during explicit registration ([de1a9ba](https://github.com/Dahkenangnon/oidfed/commit/de1a9ba248cdf5f2e0eb67b9f3d7b81440eef286))
* harden policy dictionaries and callbacks ([34ed35d](https://github.com/Dahkenangnon/oidfed/commit/34ed35d07366f30f4ef7894dadca9f48e8e5ab89))
* enforce metadata conformance in roles and registration ([1e24251](https://github.com/Dahkenangnon/oidfed/commit/1e242518f2a840029edbf508d2207bf0ce141621))
* identify registration callback and validation failures ([b99a2fd](https://github.com/Dahkenangnon/oidfed/commit/b99a2fd371f593cf8b0607fd5fe4768ffc61c985))
* validate supplied trust chains and peer anchor matching ([87ad5bc](https://github.com/Dahkenangnon/oidfed/commit/87ad5bc9304249f46359a73494df177f677d20ec))
* scope metadata null checks and authenticate resolver ECs ([483fba1](https://github.com/Dahkenangnon/oidfed/commit/483fba10914c2d3b634ccd90e18bbfffca3541e3))
* enforce trust-chain authority hints and offline wallet guards ([b5b3f07](https://github.com/Dahkenangnon/oidfed/commit/b5b3f074873132a460c45cf3e3b777a92cb2bbc0))
* validate federation boundaries ([5207ec5](https://github.com/Dahkenangnon/oidfed/commit/5207ec5a797d3b58df14b2f147b59bef69f478c2))
* tighten key and registration handling ([40e8526](https://github.com/Dahkenangnon/oidfed/commit/40e8526d427336f3060ec2a5804230e34772bde8))
* separate protocol key identifier requirements ([34ba00e](https://github.com/Dahkenangnon/oidfed/commit/34ba00ec50007360ff7c599916909dcfb433e817))
* bind registration to federation trust ([a3bcbf7](https://github.com/Dahkenangnon/oidfed/commit/a3bcbf76b9088f091f39027e6460d518f42a39a1))
* reject future-issued registration responses ([b6e1763](https://github.com/Dahkenangnon/oidfed/commit/b6e1763b4729625476a787197f05c7794485f457))

### Refactor

* share protocol helpers and remove dead code ([f299374](https://github.com/Dahkenangnon/oidfed/commit/f299374faab2822cd06c543832e0d959e5210c39))


## [2.0.0] - 2026-10-26

### Breaking changes

- Stateful OIDC/OAuth role instances belong to one host. Create separate instances for separate hosts. ([f51d9c6](https://github.com/Dahkenangnon/oidfed/commit/f51d9c64859a099d1720ee66675cd442554aedde))

### Fixed

- Use final composed local metadata when constructing registration and authorization requests, including fields supplied by the host. ([f51d9c6](https://github.com/Dahkenangnon/oidfed/commit/f51d9c64859a099d1720ee66675cd442554aedde))
- Retain host federation options when applying per-call overrides, including the HTTP client and clock. Honor declared request delivery, URI, peer-chain, and Request Object lifetime overrides. ([f51d9c6](https://github.com/Dahkenangnon/oidfed/commit/f51d9c64859a099d1720ee66675cd442554aedde))
- Document registration lifetime enforcement, separate replay storage, and application-managed protocol-key rotation. Correct the documented Request Object lifetime default to 300 seconds. ([f51d9c6](https://github.com/Dahkenangnon/oidfed/commit/f51d9c64859a099d1720ee66675cd442554aedde))
- Keep bundled TypeScript declaration generation working with TypeScript 6. ([a473ebb](https://github.com/Dahkenangnon/oidfed/commit/a473ebbb93d166ebcd69f9c8c52d376e48ff29fc))
- Update the schema-validation dependency. ([d83b296](https://github.com/Dahkenangnon/oidfed/commit/d83b296634b86ae059cd71aa79b2a77d6fd05b89))

## [1.0.0] - 2026-07-13

### Bug Fixes

* respect request uri delivery metadata ([89e38a9](https://github.com/Dahkenangnon/oidfed/commit/89e38a9d36bea0cbd947c14c2d847e0338936623))
* enforce client registration trust checks ([4817cb4](https://github.com/Dahkenangnon/oidfed/commit/4817cb4652c7b74d72a9f21990b0541cb433ac14))
* tighten federation metadata validation ([a102e38](https://github.com/Dahkenangnon/oidfed/commit/a102e386736a8be57e191352dab7a4d6a165ef53))
* require shared trust anchor for registration ([aafa370](https://github.com/Dahkenangnon/oidfed/commit/aafa37016ac7ebfa9f9dbbf7ebc3e2d5a19c7589))
* split rp registration metadata schemas ([1584d0b](https://github.com/Dahkenangnon/oidfed/commit/1584d0b8d27384d651c7a51dde48588cfd5fe447))
* enforce exact federation media types ([6c00afe](https://github.com/Dahkenangnon/oidfed/commit/6c00afeb3549ed06fde3fc077c039a561826db28))
* align config docs and package claims ([ea093ac](https://github.com/Dahkenangnon/oidfed/commit/ea093acb7d3df03bbd43e90b30525681aedb7824))
* remove avoidable public any ([d0e754d](https://github.com/Dahkenangnon/oidfed/commit/d0e754d9a2f72fdf57b1bf584a131491a5ef4006))
* tighten explicit registration response validation ([20f0d32](https://github.com/Dahkenangnon/oidfed/commit/20f0d3281c20cb775a5006bcc3336ac70112bc6a))
* stabilize explicit registration hooks ([5a9ad92](https://github.com/Dahkenangnon/oidfed/commit/5a9ad9246ddb3ad56d146985a4f63897c10d29ca))
* validate supplied registration trust chains ([5c21f4f](https://github.com/Dahkenangnon/oidfed/commit/5c21f4f9d62b1d35a2802414e9391047b54f487f))
* require trust anchors for op registration ([36bd338](https://github.com/Dahkenangnon/oidfed/commit/36bd33813fdfced76f0930fa6da0b95e30297133))
* align root docs with class api ([f8ae317](https://github.com/Dahkenangnon/oidfed/commit/f8ae317783708d5a89d107c93a1d6665f4ba0ca2))
* align public docs with class-only APIs ([eb6c359](https://github.com/Dahkenangnon/oidfed/commit/eb6c35953963b8dae0b9f700bfbe69ba92f223f4))
* harden resolve, explicit registration, and client auth validation ([f673908](https://github.com/Dahkenangnon/oidfed/commit/f673908aa7fc06422fefeef233bceca864f2e83d))

### Refactor

* clarify public role and key provider names ([1211280](https://github.com/Dahkenangnon/oidfed/commit/1211280b7cea233b6522830c149e8ac0abc7a352))


### Changed

- OIDC/OAuth role classes, role config types, and protocol signing-key providers now use explicit domain names across root exports and docs.
- Public documentation now treats the root `@oidfed/oidc` runtime surface as role/class-owned. Low-level registration helpers, constants, validators, and schemas are implementation details; use `OidcRelyingPartyRole`, `OidcProviderRole`, OAuth role classes, and type-only exports from the root package.
- OP-side automatic and explicit registration now require a non-empty Trust Anchor set. Provider roles fail during initialization when neither the role config nor parent entity context supplies trust anchors.
- OP-side registration now validates supplied `trust_chain`, `peer_trust_chain`, and exact parameter-free `application/trust-chain+json` inputs as full Trust Chains. Valid supplied RP chains are used before live Federation Entity Discovery; invalid supplied chains fail registration instead of falling back silently.
- Explicit-registration invalidation hooks now run only after validation and response preparation, immediately before registration commit hooks. Hook failures return sanitized `server_error` responses.
- RP-side explicit registration response processing now requires HTTP `200`, exact `application/explicit-registration-response+jwt`, a matching RP `sub`, and registered credentials under `metadata.openid_relying_party`.
- RP-side explicit registration now verifies response `authority_hints`, response lifetime, and nested `client_secret_expires_at` against the selected RP registration trust chain.
- OP-side explicit registration removes registration-management token and URI fields from response metadata before signing and registration hooks.
- Automatic registration now rejects non-Entity-Identifier `client_id` values before trust-chain processing, and PAR delivery requires published protocol signing keys before the PAR POST is sent.
- Automatic registration `request_uri` delivery now respects OP metadata that disables the `request_uri` parameter.
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
