<div align="center">

# @oidfed/*: OpenID Federation 1.0

[![CI](https://github.com/Dahkenangnon/oidfed/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Dahkenangnon/oidfed/actions/workflows/ci.yml)
[![@oidfed/core](https://img.shields.io/npm/v/@oidfed/core?label=%40oidfed%2Fcore)](https://www.npmjs.com/package/@oidfed/core)
[![@oidfed/authority](https://img.shields.io/npm/v/@oidfed/authority?label=%40oidfed%2Fauthority)](https://www.npmjs.com/package/@oidfed/authority)
[![@oidfed/leaf](https://img.shields.io/npm/v/@oidfed/leaf?label=%40oidfed%2Fleaf)](https://www.npmjs.com/package/@oidfed/leaf)
[![@oidfed/oidc](https://img.shields.io/npm/v/@oidfed/oidc?label=%40oidfed%2Foidc)](https://www.npmjs.com/package/@oidfed/oidc)
[![@oidfed/cli](https://img.shields.io/npm/v/@oidfed/cli?label=%40oidfed%2Fcli)](https://www.npmjs.com/package/@oidfed/cli)
[![License](https://img.shields.io/badge/license-Apache--2.0%20(libs)%20%2F%20MIT%20(apps)-blue.svg)](#license)

JavaScript libraries for [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html): publish Entity Configurations, resolve and validate trust chains, apply metadata policies, manage trust marks, and add federation registration to an existing OP or RP.

The four libraries use Web APIs, including `Request`, `Response`, and Web Crypto. The test suite runs on Node.js, Deno, Bun, workerd, Electron, and browsers. Their external runtime dependencies are [`jose`](https://github.com/panva/jose) and [`zod`](https://github.com/colinhacks/zod). Storage and key-provider interfaces let applications supply their own database and signing service.

[Explorer](https://explore.oidfed.com) · [Project Home](https://oidfed.com) · [Learn OpenID Federation](https://learn.oidfed.com)

</div>

[Try the demo federation](https://fed.oidfed.com): six topologies covering single-anchor, hierarchical, multi-anchor, cross-federation, constrained, and metadata-policy setups. Inspect an entity in the [explorer](https://explore.oidfed.com); import the demo's trust anchors before using chain views. Deployment source: [Dahkenangnon/fed-oidfed-com](https://github.com/Dahkenangnon/fed-oidfed-com).

## Requirements

Repository development supports Node.js `^22.22.2 || ^24.15.0 || >=26.0.0`; CI uses `22.22.2`. Use the pinned pnpm version, `10.33.0`, through Corepack. The four library packages omit Node-specific `engines` metadata; the CLI separately declares Node.js `>=22.12.0`. JOSE signing and verification use `jose`.

## Choose a package

A federation hierarchy describes who attests to whom. OPs and RPs can both be leaf entities:

```text
Trust Anchor                         @oidfed/authority
└── Intermediate                     @oidfed/authority
    ├── OpenID Provider (leaf)       @oidfed/leaf + @oidfed/oidc
    └── Relying Party (leaf)          @oidfed/leaf + @oidfed/oidc

@oidfed/core supplies the shared federation primitives.
```

| Package | Role | Install when building a… | Docs |
|---------|------|--------------------------|------|
| `@oidfed/core` | Entity Statement builders, trust chain resolution and validation, metadata policy, and cryptographic verification | Any federation participant | [docs/packages/core.md](docs/packages/core.md) |
| `@oidfed/authority` | Subordinate management, statement issuance, and federation endpoints | Trust Anchor or Intermediate Authority | [docs/packages/authority.md](docs/packages/authority.md) |
| `@oidfed/leaf` | Entity Configuration serving and trust-chain discovery for leaf entities | OP, RP, resource server, or other leaf | [docs/packages/leaf.md](docs/packages/leaf.md) |
| `@oidfed/oidc` | OIDC and OAuth roles, automatic and explicit registration, Request Objects, and RP/OP metadata | OP or RP | [docs/packages/oidc.md](docs/packages/oidc.md) |

## Create a federated RP

```bash
pnpm add @oidfed/core @oidfed/leaf @oidfed/oidc
```

This example creates an RP's federation entity and OIDC role. It generates temporary keys in memory, suitable for development. Persist keys in your deployment, enroll the RP with its superior authority, and serve the returned Web API handler over HTTPS.

```ts
import {
  createFederationSigningKey,
  generateSigningKey,
  JwkSigner,
  MemoryFederationKeyProvider,
} from "@oidfed/core";
import { Leaf } from "@oidfed/leaf";
import { OidcRelyingPartyRole, StaticProtocolSigningKeyProvider } from "@oidfed/oidc";

const federationKeys = await generateSigningKey("ES256");
const protocolKeys = await generateSigningKey("ES256");

const rpRole = new OidcRelyingPartyRole({
  protocolKeyProvider: new StaticProtocolSigningKeyProvider({
    requestObjectSigner: new JwkSigner(protocolKeys.privateKey),
  }),
  metadata: {
    redirect_uris: ["https://rp.example.com/callback"],
    response_types: ["code"],
    client_registration_types: ["automatic", "explicit"],
    token_endpoint_auth_method: "private_key_jwt",
    jwks: { keys: [protocolKeys.publicKey] },
  },
});

const leaf = new Leaf({
  entityId: "https://rp.example.com",
  authorityHints: ["https://ta.example.org"],
  keyProvider: new MemoryFederationKeyProvider(
    createFederationSigningKey(federationKeys.privateKey),
  ),
  metadata: { federation_entity: { organization_name: "Example RP" } },
  roles: [rpRole],
});

export const handleRequest = (request: Request) => leaf.handleRequest(request);
```

Federation keys sign Entity Configurations; separate protocol keys sign Request Objects and client assertions. Your OIDC client still handles the login session, callback, token exchange, and token validation.

Start with the [documentation index](docs/README.md), then use the [wiring guide](docs/guide/wiring-guide.md) for HTTP and OP/RP integration or the [storage guide](docs/guide/storage-guide.md) for production adapter contracts. The [development guide](docs/guide/dev.md) and [E2E guide](docs/test/e2e.md) explain the local test federation.

The repository also includes the [CLI](docs/tools/cli.md), [browser explorer](docs/apps/explorer.md), [project website](https://oidfed.com), and [interactive course](https://learn.oidfed.com).

## Specification support

The implementation targets OpenID Federation 1.0. The two 1.1 specifications separate its protocol-independent and OIDC/OAuth functionality; both state that they introduce no new functionality. The table distinguishes that scope from extensions that need separate implementation work. Specification status checked on 2026-10-15.

| Specification | Spec status | This monorepo | Scope |
|---|---|---|---|
| [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) | Final (2026-02-17) | Implemented | Foundational protocol: Entity Statements, Trust Chains, Metadata, Policies, Trust Marks, Federation Endpoints, OpenID Connect client registration. |
| [OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html) | Final (2026-05-05) | Within the 1.0 implementation scope | Protocol-independent layer: Entity Statements, Trust Chains, metadata policies, trust marks, and endpoints. |
| [OpenID Federation for OpenID Connect 1.1](https://openid.net/specs/openid-federation-connect-1_1.html) | Final (2026-05-05) | Within the 1.0 implementation scope | Protocol-specific layer: OAuth 2.0 / OpenID Connect entity types, automatic + explicit client registration. |
| [OpenID Federation Extended Subordinate Listing 1.0](https://openid.net/specs/openid-federation-extended-listing-1_0.html) | *Draft 03* (2026-07-02) | Implemented | Paginated subordinate listing with audit timestamps and bulk per-entity claim retrieval for large-scale federations. See [docs/packages/authority.md](docs/packages/authority.md#extended-subordinate-listing). |
| [OpenID Federation Subordinate Events Endpoint 1.0](https://openid.net/specs/openid-federation-subordinate-events-1_0.html) | *Draft 01* | Not implemented | Optional Trust Anchor / Intermediate endpoint for publishing historical subordinate registration, revocation, metadata, policy, and Federation Entity Key update events. |
| [OpenID Federation Entity Collection 1.0](https://openid.net/specs/openid-federation-entity-collection-1_0.html) | *Draft 00* | Not implemented | Sub-federation entity discovery endpoint with hierarchical filtering, pagination, and UI-oriented metadata for login pickers and admin tools. |
| [OpenID Federation for Wallet Architectures 1.0](https://openid.net/specs/openid-federation-wallet-1_0.html) | *Draft 05* | Not implemented | Trust-establishment profile for digital-wallet ecosystems: Wallet Provider / Wallet Relying Party metadata, policy templates, trust mark guidance. |
| [Automatic Certificate Management Environment (ACME) with OpenID Federation 1.0](https://datatracker.ietf.org/doc/draft-ietf-acme-openid-federation/) | *Expired IETF ACME WG Internet-Draft (draft 00)* | Not implemented | Historical proposal for ACME Requestor / Issuer Federation Entity Types and automated X.509 issuance over federation discovery; monitor for a replacement revision. |

Extended Listing uses Draft 03's opaque `from` / `next` pagination and supports repeated `trust_mark_type` filters. When migrating from Draft 02, replace `fromEntityId` with `from` in helper calls and `next_entity_id` with `next` in responses. See [authority configuration](docs/packages/authority.md#extended-subordinate-listing).

### Companion and downstream specifications

These specifications are not part of the core Federation family, but they normatively invoke OpenID Federation processing or transport Federation artifacts.

| Specification | Status | Federation relationship |
|---|---|---|
| [OpenID Connect Relying Party Metadata Choices 1.0](https://openid.net/specs/openid-connect-rp-metadata-choices-1_0.html) | Final (2026-03-25) | Lets an RP express alternative supported metadata values, particularly when Federation Automatic Registration has no registration response for negotiation. |
| [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) | Final (2025-07-09) | Defines `openid_federation:` client identifiers, Federation-resolved Verifier metadata, and optional `trust_chain` transport. |
| [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) | Final (2025-09-16) | Defines an optional JOSE `trust_chain` header and normatively references OpenID Federation draft 43. |

Existing generic Trust Chain parsing and validation does not by itself constitute OpenID4VP or OpenID4VCI support.

### Implementation listing and conformance

`@oidfed` appears in the [OpenID Foundation implementation registry](https://openid.net/developers/openid-federation-implementations/). Registry inclusion is separate from certification; this repository does not claim an OIDF certification result. At the status check above, OIDF's [Federation testing guide](https://openid.net/certification/federation_testing/) describes the tests as early-stage and supports Automatic Registration for its registration-type setting.

## Operating a federation

Plan deployment controls using the specification’s operator guidance:

- [§18: Security Considerations](https://openid.net/specs/openid-federation-1_0.html#section-18): DoS prevention for the resolve, fetch, and registration endpoints; `authority_hints` depth limits; Trust Mark filtering; reverse-proxy end-to-end signing.
- [§19: Privacy Considerations](https://openid.net/specs/openid-federation-1_0.html#section-19): Entity Statements are org-level infrastructure: keep personal data minimal; mitigate Trust Mark Status and Fetch endpoint tracking via short-lived trust marks and static Trust Chains.
- [§17: Implementation Considerations](https://openid.net/specs/openid-federation-1_0.html#section-17): Multi-path topology ambiguity; Trust Mark policy design; resolver and Trust Anchor co-location.
- [`private_key_jwt` audience security](https://openid.net/notice-of-a-security-vulnerability/) ([CVE-2025-27370](https://www.cve.org/CVERecord?id=CVE-2025-27370), [CVE-2025-27371](https://www.cve.org/CVERecord?id=CVE-2025-27371)): For federation client authentication, a client assertion must contain exactly one audience value identifying the authorization server by its Federation Entity Identifier; token and PAR endpoint URLs are not substitutes. The federation endpoint and PAR assertion checks enforce an exact singleton match. Callers using low-level assertion-creation APIs must supply the validated AS/OP Entity Identifier.

This library provides the protocol mechanisms; policy, rate limiting, key management, HSM integration, and operational hardening are the operator's responsibility.

## Security

To report a vulnerability, email dah.kenangnon@gmail.com. See [SECURITY.md](SECURITY.md) for the full disclosure policy.

## License

- Libraries and CLI (`@oidfed/core`, `@oidfed/authority`, `@oidfed/leaf`, `@oidfed/oidc`, `@oidfed/cli`): [Apache 2.0](LICENSE).
- Apps and shared UI (`@oidfed/explorer`, `@oidfed/home`, `@oidfed/learn`, `@oidfed/ui`): MIT (see each component's own `LICENSE`).

Copyright © 2026-present [Yamonwan Justin Dah-kenangnon](https://github.com/Dahkenangnon).
