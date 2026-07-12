<div align="center">

# @oidfed/* — OpenID Federation 1.0

[![CI](https://github.com/Dahkenangnon/oidfed/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Dahkenangnon/oidfed/actions/workflows/ci.yml)
[![@oidfed/core](https://img.shields.io/npm/v/@oidfed/core?label=%40oidfed%2Fcore)](https://www.npmjs.com/package/@oidfed/core)
[![@oidfed/authority](https://img.shields.io/npm/v/@oidfed/authority?label=%40oidfed%2Fauthority)](https://www.npmjs.com/package/@oidfed/authority)
[![@oidfed/leaf](https://img.shields.io/npm/v/@oidfed/leaf?label=%40oidfed%2Fleaf)](https://www.npmjs.com/package/@oidfed/leaf)
[![@oidfed/oidc](https://img.shields.io/npm/v/@oidfed/oidc?label=%40oidfed%2Foidc)](https://www.npmjs.com/package/@oidfed/oidc)
[![@oidfed/cli](https://img.shields.io/npm/v/@oidfed/cli?label=%40oidfed%2Fcli)](https://www.npmjs.com/package/@oidfed/cli)
[![License](https://img.shields.io/badge/license-Apache--2.0%20(libs)%20%2F%20MIT%20(apps)-blue.svg)](#license)

The complete [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) implementation for JavaScript — runtime-agnostic, spec-compliant, built on Web API standards. Trust chain resolution and validation, metadata policy enforcement, trust marks, constraint checking, and automatic and explicit client registration — split across four focused packages built on Web API primitives (`Request → Response`), running anywhere JavaScript runs: Node.js, Deno, Bun, and beyond. All persistent state is behind pluggable storage interfaces, keeping database and HSM integrations entirely outside the core packages. The only runtime dependencies are [`jose`](https://github.com/panva/jose) and [`zod`](https://github.com/colinhacks/zod). Two operational utilities — a CLI and a browser-based explorer — complete the toolchain.

[Explorer](https://explore.oidfed.com) · [Project Home](https://oidfed.com) · [Learn OpenID Federation](https://learn.oidfed.com)

</div>

> [!TIP]
> **Try it live.** [`fed.oidfed.com`](https://fed.oidfed.com) is @oidfed's own reference deployment — OpenID Federation 1.0 topologies (single-anchor, hierarchical, multi-anchor, cross-federation, constrained, policy-operators) running on the packages in this repo. Open any trust chain in one click via [`explore.oidfed.com`](https://explore.oidfed.com) or hit it directly with [`@oidfed/cli`](https://www.npmjs.com/package/@oidfed/cli). Source: [`Dahkenangnon/fed-oidfed-com`](https://github.com/Dahkenangnon/fed-oidfed-com).

> [!IMPORTANT]
> **Spec:** Full [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) implementation · 
> 
> **Crypto:** All JOSE operations delegated to [`jose`](https://github.com/panva/jose) · 
> 
> **Status:** prerelease — API may change before the upcoming stable `1.0.0` release.

---

```
                    Trust Anchor                 ← @oidfed/authority
                   ╱             ╲
       Intermediate               Intermediate   ← @oidfed/authority
            │                          │
   OpenID Provider             OpenID Provider   ← @oidfed/authority + @oidfed/oidc
            │                          │
    Relying Party               Relying Party    ← @oidfed/leaf + @oidfed/oidc

    @oidfed/core underlies every node in the graph
```

---

## Packages

| Package | Role | Install when building a… | Docs |
|---------|------|--------------------------|------|
| `@oidfed/core` | Federation primitives — Entity Statement builders, trust chain resolution, metadata policy, and cryptographic verification. The foundational layer of the complete OpenID Federation 1.0 implementation | Any federation participant | [docs/packages/core.md](docs/packages/core.md) |
| `@oidfed/authority` | Trust Anchor and Intermediate Authority operations — subordinate management, statement issuance, federation endpoint serving, and policy enforcement | Trust Anchor or Intermediate Authority | [docs/packages/authority.md](docs/packages/authority.md) |
| `@oidfed/leaf` | Leaf Entity toolkit — Entity Configuration serving, authority discovery, and trust chain participation for any entity at the edge of an OpenID Federation | Relying Party | [docs/packages/leaf.md](docs/packages/leaf.md) |
| `@oidfed/oidc` | OpenID Connect and OAuth 2.0 federation flows — automatic and explicit client registration, Request Object validation, and RP/OP metadata processing as defined in OpenID Federation 1.0 | OP or RP | [docs/packages/oidc.md](docs/packages/oidc.md) |

## Usage Example

```ts
import { Leaf } from "@oidfed/leaf";
import { TrustAnchor, Intermediate, MemoryStorageAdapter } from "@oidfed/authority";
import { FedOidcClient, FedOidcProvider, StaticOidcProtocolKeyProvider } from "@oidfed/oidc";

// 1. Create a Leaf Entity composed with an OIDC Relying Party role
const leaf = new Leaf({
  entityId: "https://rp.example.com",
  authorityHints: ["https://ta.example.org"],
  keyProvider: myFederationKeyProvider,
  metadata: { federation_entity: { organization_name: "Leaf RP" } },
  roles: [
    new FedOidcClient({
      protocolKeyProvider: new StaticOidcProtocolKeyProvider({
        requestObjectSigner: protocolSigner
      }),
      metadata: {
        redirect_uris: ["https://rp.example.com/callback"],
        response_types: ["code"],
        client_registration_types: ["automatic"],
        jwks: { keys: [protocolPublicKey] }
      }
    })
  ]
});

// 2. Create a Trust Anchor (No authorityHints, storage required)
const ta = new TrustAnchor({
  entityId: "https://ta.example.org",
  keyProvider: myTAKeyProvider,
  storage: new MemoryStorageAdapter(),
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: "https://ta.example.org/federation_fetch",
      federation_list_endpoint: "https://ta.example.org/federation_list"
    }
  }
});

// 3. Create an Intermediate Authority composed with an OIDC Provider role
const trustAnchors = new Map([
  ["https://ta.example.org", { jwks: { keys: [taPublicKey] } }]
]);

const ia = new Intermediate({
  entityId: "https://ia.example.org",
  authorityHints: ["https://ta.example.org"],
  trustAnchors,
  keyProvider: myIAKeyProvider,
  storage: new MemoryStorageAdapter(),
  metadata: {
    federation_entity: {
      federation_fetch_endpoint: "https://ia.example.org/federation_fetch",
      federation_list_endpoint: "https://ia.example.org/federation_list"
    }
  },
  roles: [
    new FedOidcProvider({
      metadata: {
        issuer: "https://ia.example.org",
        authorization_endpoint: "https://ia.example.org/auth",
        token_endpoint: "https://ia.example.org/token",
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["ES256"],
        client_registration_types_supported: ["automatic", "explicit"],
        jwks: { keys: [protocolPublicKey] }
      }
    })
  ]
});
```

For integration examples, see the [Wiring Guide](docs/guide/wiring-guide.md). For production storage backends (PostgreSQL, MongoDB, Redis) and HSM key stores, see the [Storage Guide](docs/guide/storage-guide.md). To run a full multi-topology federation locally with wildcard DNS and TLS, see the [Dev Guide](docs/guide/dev.md) and [E2E Test infrastructure](docs/test/e2e.md).

The repository also ships a CLI ([`@oidfed/cli`](docs/tools/cli.md)), a live federation explorer at [explore.oidfed.com](https://explore.oidfed.com), an interactive course at [learn.oidfed.com](https://learn.oidfed.com), and a few internal packages that support the workspace — browse the source or the [docs/](docs/) directory to learn more.

## Related Specifications

[OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) has been factored into two final successor specifications (1.1 protocol-independent + 1.1 for OpenID Connect) that together cover exactly the same functionality as 1.0. Several active extensions build on top of 1.0/1.1 — wallets, large-federation discovery, ACME certificate issuance, and more. The table below tracks every Federation-family specification we are aware of, with this monorepo's implementation status alongside.

| Specification | Spec status | This monorepo | Scope |
|---|---|---|---|
| [**OpenID Federation 1.0**](https://openid.net/specs/openid-federation-1_0.html) | **Final** ✓ (2026-02-17) |  **Implemented** | Foundational protocol: Entity Statements, Trust Chains, Metadata, Policies, Trust Marks, Federation Endpoints, OpenID Connect client registration. |
| [**OpenID Federation 1.1**](https://openid.net/specs/openid-federation-1_1.html) | **Final** ✓ (2026-05-05) |  **Implemented** (by virtue of 1.0) | Protocol-independent layer — the 1.0 functionality factored apart with no behavioural changes. |
| [**OpenID Federation for OpenID Connect 1.1**](https://openid.net/specs/openid-federation-connect-1_1.html) | **Final** ✓ (2026-05-05) |  **Implemented** (by virtue of 1.0) | Protocol-specific layer — OAuth 2.0 / OpenID Connect entity types, automatic + explicit client registration. |
| [**OpenID Federation Extended Subordinate Listing 1.0**](https://openid.net/specs/openid-federation-extended-listing-1_0.html) | *Draft 02* |  **Implemented** (tracks draft-02) | Paginated subordinate listing with audit timestamps and bulk per-entity claim retrieval for large-scale federations. See [docs/packages/authority.md](docs/packages/authority.md#extended-subordinate-listing). |
| [**OpenID Federation Entity Collection 1.0**](https://openid.net/specs/openid-federation-entity-collection-1_0.html) | *Draft 00* |  **Not yet implemented** | Sub-federation entity discovery endpoint with hierarchical filtering, pagination, and UI-oriented metadata for login pickers and admin tools. |
| [**OpenID Federation for Wallet Architectures 1.0**](https://openid.net/specs/openid-federation-wallet-1_0.html) | *Draft 05* |  **Not yet implemented** | Trust-establishment profile for digital-wallet ecosystems — Wallet Provider / Wallet Relying Party metadata, policy templates, trust mark guidance. |
| [**Automatic Certificate Management Environment (ACME) with OpenID Federation 1.0**](https://datatracker.ietf.org/doc/draft-ietf-acme-openid-federation/) | *IETF Internet-Draft (draft-ietf-acme-openid-federation-00)* |  **Not yet implemented** | New Federation Entity Types for ACME Requestor / Issuer roles, enabling automated X.509 issuance over federation discovery. |


> [!NOTE]
> **OpenID Federation 1.1 + OpenID Federation for OpenID Connect 1.1** are a clean split of 1.0 — no functionality was added or removed, only factored apart. A complete 1.0 implementation is therefore a complete 1.1 implementation by definition. **Extended Subordinate Listing** is implemented end-to-end (server endpoint, federation-api client, CLI `list-extended` command) and tracks draft-02 verbatim — see [docs/packages/authority.md](docs/packages/authority.md#extended-subordinate-listing). **Entity Collection**, **Wallet Architectures**, and **ACME-with-Federation** are tracked but not yet implemented; contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

For real-world integration examples see the [Wiring Guide](docs/guide/wiring-guide.md), the [dev federation server](docs/guide/dev.md), and the [E2E test infrastructure](docs/test/e2e.md).

## Federation Operator Notes

Running a federation involves responsibilities beyond what this library enforces. Operators **MUST** read and address:

- [**§18 — Security Considerations**](https://openid.net/specs/openid-federation-1_0.html#section-18): DoS prevention for the resolve, fetch, and registration endpoints; `authority_hints` depth limits; Trust Mark filtering; reverse-proxy end-to-end signing.
- [**§19 — Privacy Considerations**](https://openid.net/specs/openid-federation-1_0.html#section-19): Entity Statements are org-level infrastructure — keep personal data minimal; mitigate Trust Mark Status and Fetch endpoint tracking via short-lived tokens and static Trust Chains.
- [**§17 — Implementation Considerations**](https://openid.net/specs/openid-federation-1_0.html#section-17): Multi-path topology ambiguity; Trust Mark policy design; resolver and Trust Anchor co-location.

This library provides the protocol mechanisms; policy, rate limiting, key management, HSM integration, and operational hardening are the operator's responsibility.

## Security

To report a vulnerability, email **dah.kenangnon@gmail.com** — see [SECURITY.md](SECURITY.md) for the full disclosure policy.

## License

- **Libraries** (`@oidfed/core`, `@oidfed/authority`, `@oidfed/leaf`, `@oidfed/oidc`, `@oidfed/cli`) — [Apache 2.0](LICENSE).
- **Apps & internal UI** (`@oidfed/explorer`, `@oidfed/home`, `@oidfed/learn`, `@oidfed/ui`) — MIT (see each component's own `LICENSE`).

Copyright © 2026-Present [Yamonwan Justin Dah-kenangnon](https://github.com/Dahkenangnon).
