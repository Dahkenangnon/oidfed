# `@oidfed/leaf`

<p align="center">
  <a href="https://www.npmjs.com/package/@oidfed/leaf"><img alt="npm" src="https://img.shields.io/npm/v/@oidfed/leaf.svg" /></a>
  <a href="https://www.npmjs.com/package/@oidfed/leaf"><img alt="downloads" src="https://img.shields.io/npm/dm/@oidfed/leaf.svg" /></a>
  <a href="https://github.com/Dahkenangnon/oidfed/blob/main/packages/leaf/LICENSE"><img alt="license" src="https://img.shields.io/npm/l/@oidfed/leaf.svg" /></a>
  <a href="https://packagephobia.com/result?p=@oidfed/leaf"><img alt="install size" src="https://packagephobia.com/badge?p=@oidfed/leaf" /></a>
</p>

`@oidfed/leaf` publishes self-signed Entity Configurations for participants that do not issue Subordinate Statements, such as OPs, RPs, and resource servers. It signs and caches configurations and exposes validated discovery through `Leaf.discoverEntity()`.

See [operator and application responsibilities](../guide/operator-responsibilities.md) for key publication, configuration refresh, and the application state required by composed roles.

Supply `options.logger` for [host-supplied logging](core.md#host-supplied-logging), including publication and serving failures. If the composed metadata advertises a collection endpoint without a Resolve endpoint, the Leaf emits one info notice after successful Entity Configuration signing. The SHOULD recommendation does not prevent publication.

## Usage

### Creating a leaf entity

A Leaf entity publishes its own self-signed configuration but relies on superior authorities (authority hints) to attest to its status. Its `federation_entity` metadata must omit `federation_fetch_endpoint` and `federation_list_endpoint`.

```ts
import { Leaf } from "@oidfed/leaf";
import { OidcRelyingPartyRole, StaticProtocolSigningKeyProvider } from "@oidfed/oidc";
import {
  createFederationSigningKey,
  generateSigningKey,
  JwkSigner,
  MemoryFederationKeyProvider,
} from "@oidfed/core";

// 1. Generate keys and key providers
const keyPair = await generateSigningKey("ES256");
const keyProvider = new MemoryFederationKeyProvider(
  createFederationSigningKey(keyPair.privateKey),
);

// 2. Generate OIDC protocol keys and initialize the protocol key provider
const protocolKeyPair = await generateSigningKey("ES256");
const protocolKeyProvider = new StaticProtocolSigningKeyProvider({
  requestObjectSigner: new JwkSigner(protocolKeyPair.privateKey)
});

// 3. Initialize the Leaf Entity
const leaf = new Leaf({
  entityId: "https://rp.example.com",
  authorityHints: ["https://federation.example.org"],
  keyProvider,
  metadata: {
    federation_entity: {
      organization_name: "My Relying Party",
    },
  },
  roles: [
    new OidcRelyingPartyRole({
      protocolKeyProvider,
      metadata: {
        redirect_uris: ["https://rp.example.com/callback"],
        response_types: ["code"],
        client_registration_types: ["automatic"],
        jwks: { keys: [protocolKeyPair.publicKey] },
      }
    })
  ]
});
```

### Serving the Entity Configuration

`leaf.handleRequest(request)` serves `GET /.well-known/openid-federation` and dispatches any composed role routes. Built-in Entity Configuration discovery remains anonymous independently of Collection authentication; [Federation §9.1](https://openid.net/specs/openid-federation-1_0.html#section-9.1) defines its GET request without a client-assertion authentication flow. For an Entity Identifier with a path, the well-known suffix is appended to that path. Use the [Express adapter](../guide/wiring-guide.md#5-adapt-the-web-api-handler-to-express) to serve it in a Node application.

`getEntityConfiguration()` reuses the cached JWT until expiry. A Leaf removes one trailing `/` from its configured identifier once. Its `entityId`, role context, and EC `iss`/`sub` all use that published identifier. Discovery then follows §9's URL rule: remove one trailing `/` from the published identifier and append `/.well-known/openid-federation`. Use `leaf.entityId` when configuring another participant to discover it; repeated slashes and encoded path components are otherwise preserved.

Call `refreshEntityConfiguration()` after a key change when you need a new configuration before the cached token expires. A refresh supersedes earlier builds: their results cannot replace the refreshed cache, and concurrent reads reuse the current build.

### Discovering entities and trust chains

The following fragment assumes `taPublicKey` is the public federation key pinned for that Trust Anchor.
Leaf entities can discover other entities in the federation and validate their trust chains up to configured anchors using the static `Leaf.discoverEntity` method.

```ts
import { Leaf } from "@oidfed/leaf";
import { createTrustAnchorSet } from "@oidfed/core";

const trustAnchors = createTrustAnchorSet([
  {
    entityId: "https://ta.example.org",
    jwks: { keys: [taPublicKey] }
  }
]);

const result = await Leaf.discoverEntity(
  "https://op.example.com",
  trustAnchors,
  { httpClient: fetch }
);

if (result.ok) {
  const discovery = result.value;
  console.log("Metadata:", discovery.resolvedMetadata);
  console.log("Trust Chain Expires At:", new Date(discovery.trustChain.expiresAt * 1000));
} else {
  console.error("Discovery failed:", result.error.description);
}
```

## Configuration

When constructing a `Leaf` entity, you pass a `LeafConfig` configuration object.

| Configuration Field | Type | Required | Description & Constraints |
|:---|:---|:---|:---|
| `entityId` | `EntityId \| string` | **Yes** | The entity identifier URL for this leaf. Must be a valid HTTPS URL without query parameters or fragments. Removes one trailing slash from its own configured Entity Identifier. |
| `authorityHints` | `readonly (EntityId \| string)[]` | **Yes** | Non-empty list of superior authority entity IDs this leaf is registered with. Every entry must be a valid HTTPS URL. |
| `trustAnchorHints` | `readonly (EntityId \| string)[]` | No | Optional non-empty list of preferred trust anchors to publish as `trust_anchor_hints` in the Entity Configuration. Every entry must be a valid HTTPS URL. |
| `metadata` | `EntityStatementMetadata` | **Yes** | Object-valued metadata blocks to publish, keyed by Entity Type Identifier. Must contain at least one Entity Type Identifier. The `federation_entity` block must omit `federation_fetch_endpoint` and `federation_list_endpoint`. |
| `keyProvider` | `FederationKeyProvider` | **Yes** | Read-only provider for the current federation signer and published Federation JWKS. |
| `roles` | `EntityRole[]` | No | Composition roles (like OIDC Client/Provider roles) bound to this entity context. |
| `options` | `FederationOptions` | No | Core federation options (e.g. clock configurations). |
| `trustMarks` | `TrustMarkRef[]` | No | Trust marks this leaf claims about itself in its Entity Configuration. |
| `trustAnchors` | `TrustAnchorSet` | No | Configured trust anchors made available to composed roles. The static `Leaf.discoverEntity()` method takes its own trust-anchor argument. This field is not published in the Entity Configuration. |
| `entityConfigurationTtlSeconds`| `number` | No | TTL in seconds for the self-signed Entity Configuration JWT. Must be positive if defined. Defaults to 86400 (24 hours). |

## Common questions

### Why does the Leaf constructor throw when my metadata block contains endpoints?

Leaf entities are client or provider endpoints at the edge of the trust tree and do not issue subordinate statements or list subordinates. Therefore, they are forbidden from publishing `federation_fetch_endpoint` or `federation_list_endpoint` in their `federation_entity` metadata block.

### How does the Entity Configuration caching work?

A key provider can publish a new key while retaining the old signer, then switch signers and retire the previous key. The Leaf cache does not track those provider transitions automatically. Call `refreshEntityConfiguration()` after publication, signer switch, and retirement when the served configuration must reflect a change before expiry. The application chooses propagation and overlap intervals; see the [rollover stages](authority.md#federation-key-rotation).

The Leaf class signs and caches the Entity Configuration JWT internally. When `getEntityConfiguration()` is called, it returns the cached JWT if it has not expired yet. If it has expired or if `refreshEntityConfiguration()` is called, it re-queries the `keyProvider` for keys and generates a new signature.

During concurrent refreshes, only the newest generation updates the cache. A caller already waiting on an earlier build can still receive that JWT. The "Entity Configuration generated" message confirms that signing finished; it does not mean that result became the cached configuration.

### What is `DiscoveryResult` and how is it used?

`DiscoveryResult` is a branded value containing a selected validated trust chain, resolved metadata, and trust marks. `Leaf.discoverEntity()` returns it. The RP role's `automaticallyRegister()` and `explicitlyRegister()` methods perform discovery internally; `createAuthorizationRequest()` takes an existing `DiscoveryResult`.

## Entity Collection

A leaf can serve the optional Draft 01 collection endpoint while keeping its leaf role. Configure `collection` and publish `federation_collection_endpoint`. Requests through `Leaf.handleRequest` use the core service. Requests that omit `trust_anchor` receive an empty collection; an explicit supported anchor selects that collection. See the [Entity Collection guide](../guide/entity-collection.md).

Use `collection.collector` for an application-owned inventory or `collection.filter` for an additional restriction. These callbacks run during explicit refresh, through the same core service used by authorities and independent providers. See [collection policy](../guide/entity-collection.md#collection-policy).

The federation option `customConstraintChecks` registers synchronous checks for additional constraints in authenticated Trust Chains. Failed checks reject the operation; unknown constraints remain ignored. See [custom constraints](core.md#custom-constraints) for the API and callback context.

## Protocol metadata validation

Attached OIDC/OAuth and wallet roles validate their composed publication metadata through the existing role hook. Missing top-level fields may be supplied by a Superior; supplied fields must pass the role's publication checks. Without a matching role, the host applies federation checks only.

For independent checks, use the matching role's `parsePublicationMetadata()` before publication and `parseMetadata()` on completed effective metadata. The protocol packages also export named publication types. See the [OIDC/OAuth parser examples](oidc.md#validate-metadata-independently) and [wallet metadata guidance](wallet.md).

## Wallet roles

Attach `WalletProviderRole`, `CredentialIssuerRole`, or `CredentialVerifierRole` from `@oidfed/wallet` through `roles`. Hosts validate the final composed role metadata before publication. Wallet capabilities remain separate from the host's position in the federation. See the [wallet guide](wallet.md) for configuration and protocol integration.

## Hosting and publishing Trust Marks

A Leaf can issue Trust Marks without serving authority fetch/list endpoints. Configure `trustMarkIssuer` with a `TrustMarkStore`, and publish whichever Trust Mark endpoints the host serves:

```ts
import { Leaf } from "@oidfed/leaf";
import { MemoryTrustMarkStore } from "@oidfed/core";

const auditor = new Leaf({
  entityId: "https://auditor.example",
  authorityHints: ["https://market.example"],
  keyProvider,
  metadata: { federation_entity: {
    federation_trust_mark_endpoint: "https://auditor.example/marks",
    federation_trust_mark_status_endpoint: "https://auditor.example/mark-status",
    federation_trust_mark_list_endpoint: "https://auditor.example/mark-list",
  } },
  trustMarkIssuer: {
    storage: new MemoryTrustMarkStore(),
    trustMarkDefaults: { "https://market.example/marks/member-data": { ttlSeconds: 600 } },
    // Supply issuerEvidence and delegations when the framework declares an owner.
  },
});
const jwt = await auditor.issueTrustMark(subject, type);
await auditor.revokeTrustMark(type, subject);
```

`issueTrustMark`, `listTrustMarksForSubject`, `listTrustMarkedEntities`, `revokeTrustMark`, and `setTrustMarkDelegations` use the same lifecycle service as Authority. Nested configuration also supports signer selection, profiles through `options.trustMarkProfiles`, status policy, endpoint request extensions, and `authentication`. Production hosts need durable transactional storage; the memory store is process-local.

A Leaf that receives accreditation uses `attachTrustMark(jwt, { issuerEvidence, expectedTrustMarkType })`. It checks the mark for the Leaf's Entity Identifier before signing a replacement EC. Duplicate JWT attachment is idempotent; `replacement: "same-issuer-and-type"` removes the pair's other marks even when the replacement JWT is already attached. Unrelated marks stay published. `fetchAndAttachTrustMark({ issuer, trustMarkType, trustAnchors, options })` establishes trust, fetches, validates, and publishes in one operation. A failed signer leaves the previous publication/cache intact.

`getTrustMarks()` returns detached references. `removeTrustMark({ jwt })` can remove an expired or invalid publication without fetching anything. It does not revoke the issuer's stored accreditation.

For Leaf-hosted Trust Mark endpoints, `endpoint_auth_signing_alg_values_supported` limits the algorithms accepted for `private_key_jwt`. If `trustMarkIssuer.authentication.allowedAlgorithms` is also set, both restrictions apply. A configuration with no common algorithm fails at construction. Omitting the metadata field does not select an implicit algorithm.
