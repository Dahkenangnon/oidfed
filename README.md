# oidfed

OpenID Federation's protocol-independent trust framework for JavaScript and TypeScript. Build Trust Anchors, Intermediate Authorities, and Leaf Entities that publish signed Entity Statements, discover and validate trust chains, apply metadata policies, and issue or verify Trust Marks.

The libraries use standard transport APIs such as `Request` and `Response`. Applications supply crypto operations and signing custody through explicit contracts, using Web Crypto or their chosen backend. The same package test suite runs on Node.js, Deno, Bun, workerd (the Cloudflare Workers runtime), Electron, and Chromium.

Protocol-specific roles add metadata and handlers to those entities. `@oidfed/oidc` supplies OpenID Connect and OAuth integrations; `@oidfed/wallet` supplies Wallet Provider, Credential Issuer, and Credential Verifier roles.

## Implemented specifications and features

| Specification | Implementation |
|---|---|
| [OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html) | Entity Configuration and Subordinate Statement signing and verification; trust-chain discovery and validation; metadata policies and constraints; Trust Mark issuance, validation, status, listing, and delegation; federation endpoints. |
| [OpenID Federation for OpenID Connect 1.1](https://openid.net/specs/openid-federation-connect-1_1.html) | OIDC and OAuth entity metadata, with automatic and explicit OIDC client registration. |
| [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) | The combined trust framework and OIDC/OAuth functionality from which the two 1.1 specifications were separated. |
| [Extended Subordinate Listing 1.0, Draft 03](https://openid.net/specs/openid-federation-extended-listing-1_0.html) | Opaque `from` / `next` pagination, repeated Trust Mark type filters, audit timestamps, and selected Subordinate Statement claims. |
| [Subordinate Events Endpoint 1.0, Draft 01](https://openid.net/specs/openid-federation-subordinate-events-1_0.html) | Signed subordinate event history, transactional lifecycle recording, and verified event retrieval. |
| [Entity Collection Endpoint 1.0, Draft 01](https://openid.net/specs/openid-federation-entity-collection-1_0-01.html) | Discovery of direct and indirect subordinates, with filters, informational metadata, language selection, and opaque pagination. Federation Entities and independent applications can serve the endpoint. |
| [Wallet Architectures 1.0, Draft 05](https://openid.net/specs/openid-federation-wallet-1_0-05.html) | Provider, issuer, and verifier roles, federation-backed request checks, Wallet Attestations, and credential-verification integrations. |

The two Federation 1.1 specifications separate the functionality defined in 1.0 and introduce no new functionality. Optional endpoints and registration features require the corresponding metadata and configuration; see the package documentation below.

See the [OpenID Federation ecosystem](https://oidfed.com/ecosystem/) for related specifications, implementations, and deployment examples.

## Packages

| Package | Use it for |
|---|---|
| [`@oidfed/crypto`](https://oidfed.com/docs/api/crypto) | Portable crypto engines, signing custody, keyring snapshots and compact JWS utilities; independent of existing host crypto APIs. |
| [`@oidfed/core`](https://oidfed.com/docs/api/core) | Entity Statements, trust-chain resolution and validation, metadata policy, Trust Marks, Entity Collection, and the shared storage contract. |
| [`@oidfed/authority`](https://oidfed.com/docs/api/authority) | Trust Anchors and Intermediates: subordinate management, statement issuance, and federation endpoint handlers. |
| [`@oidfed/leaf`](https://oidfed.com/docs/api/leaf) | Leaf Entity Configurations and trust-chain discovery. |
| [`@oidfed/oidc`](https://oidfed.com/docs/api/oidc) | OIDC and OAuth roles composed into an authority or leaf, with federation registration for OPs and RPs. |
| [`@oidfed/wallet`](https://oidfed.com/docs/api/wallet) | Wallet ecosystem roles, trust discovery, Wallet Attestations, presentation request policies, and credential-format integrations. |

Install the host and protocol packages your application uses. Add Core or Crypto directly when your code imports them.

## Usage

Create a Trust Anchor with your [crypto engine and federation keyring](https://oidfed.com/docs/api/crypto).

```sh
pnpm add @oidfed/authority @oidfed/core
```

```ts
import { TrustAnchor } from "@oidfed/authority";
import { MemoryFederationStorage, type CryptoContext } from "@oidfed/core";

export function createAnchor(crypto: CryptoContext) {
  const entityId = "https://anchor.example";
  return TrustAnchor.create({
    entityId,
    crypto,
    storage: new MemoryFederationStorage({ namespace: entityId }),
    metadata: {
      federation_entity: {
        federation_fetch_endpoint: `${entityId}/fetch`,
        federation_list_endpoint: `${entityId}/list`,
      },
    },
  });
}
```

Serve requests through `anchor.handleRequest(request)` over HTTPS and configure [durable storage](https://oidfed.com/docs/features/11.6.storage-adapters) for deployment.

## Resources

- [Documentation](https://oidfed.com/docs) and [v3 migration guide](https://oidfed.com/docs/api/migration-v3)
- [Demo federations](https://fed.oidfed.com) and [Explorer](https://explore.oidfed.com)
- [Learn OpenID Federation](https://learn.oidfed.com)
- [Security policy](https://github.com/Dahkenangnon/oidfed/blob/main/SECURITY.md) and [Contributing](https://github.com/Dahkenangnon/oidfed/blob/main/CONTRIBUTING.md)
