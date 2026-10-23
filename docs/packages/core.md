# `@oidfed/core`

<p align="center">
  <a href="https://www.npmjs.com/package/@oidfed/core"><img alt="npm" src="https://img.shields.io/npm/v/@oidfed/core.svg" /></a>
  <a href="https://www.npmjs.com/package/@oidfed/core"><img alt="downloads" src="https://img.shields.io/npm/dm/@oidfed/core.svg" /></a>
  <a href="https://github.com/Dahkenangnon/oidfed/blob/main/packages/core/LICENSE"><img alt="license" src="https://img.shields.io/npm/l/@oidfed/core.svg" /></a>
  <a href="https://packagephobia.com/result?p=@oidfed/core"><img alt="install size" src="https://packagephobia.com/badge?p=@oidfed/core" /></a>
</p>

`@oidfed/core` provides Entity Statement builders, signature verification, trust-chain discovery and validation, metadata policies, constraints, and trust marks for OpenID Federation 1.0. Authority, leaf, and OIDC packages use these primitives.

Use the functions here when you need direct control over federation processing. For an HTTP-serving entity, start with [authority](authority.md) or [leaf](leaf.md).

## Usage

Examples with names such as `taPublicKey`, `rawMetadata`, and `parsedStatements` assume application-supplied values of the corresponding public API types. They are integration fragments. `subordinateStatements` is a `ParsedEntityStatement[]` in leaf-to-TA order; use verified inputs when applying policy to a trust decision.

### Handling errors with `Result`

Many protocol operations return `Result<T, E>`. Check `ok` before reading `value` or `error`. Constructors, signing operations, and configuration validation can still throw; a `Result` return type does not make the whole API exception-free.

```ts
import { ok, err, federationError } from "@oidfed/core";
import type { Result, FederationError } from "@oidfed/core";

function parsePort(portStr: string): Result<number, FederationError> {
  const parsed = Number(portStr);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    return err(federationError("invalid_request", "Port must be an integer from 1 to 65535"));
  }
  return ok(parsed);
}

const res = parsePort("8080");
if (res.ok) {
  console.log("Success:", res.value); // 8080
} else {
  console.error("Failed:", res.error.description);
}
```

### Entity Identifiers (`EntityId`)

Validates that strings conform to OpenID Federation rules: must be valid URLs using the `https` scheme, without credentials, fragment, or query components, and at most 2048 characters. Per Section 3.1.2 of the OpenID Federation 1.0 specification, the `authority_hints` list of immediate superiors must not be empty `[]` and must not be present in the configurations of Trust Anchors with no superiors.

```ts
import { entityId, isValidEntityId } from "@oidfed/core";
import type { EntityId } from "@oidfed/core";

// Safely brand a string as an EntityId (throws TypeError on invalid formats)
const id: EntityId = entityId("https://op.example.com");

// Check validity without throwing exceptions
if (isValidEntityId("https://client.example.com?query=true")) {
  // Prohibited: contains a query component
}
```

### HTTP discovery and fetching

Fetch Entity Configurations and Subordinate Statements over HTTPS. The URL checks reject special-use IP literals and support host allowlists and additional blocked IPv4 ranges. DNS resolution and redirect policy belong to the HTTP transport: configure your injected `httpClient` and network access controls for the deployment. Federation response checks require the exact registered media type without parameters.

```ts
import { fetchEntityConfiguration, fetchSubordinateStatement, entityId } from "@oidfed/core";

const target = entityId("https://leaf.example.com");

// Fetch the self-signed Entity Configuration from its well-known endpoint
const ecResult = await fetchEntityConfiguration(target, {
  httpTimeoutMs: 5000,
  clockSkewSeconds: 60
});

if (ecResult.ok) {
  console.log("Entity Configuration JWT:", ecResult.value);
}
```

### Building and signing Entity Statements

Use the stable builders for normal Entity Configurations and Subordinate Statements. They validate Entity Identifier syntax, JWKS shape, time windows, metadata shape, and claim placement before signing. The lower-level `signEntityStatement` helper remains available for advanced extension payloads after callers perform their own validation.

```ts
import {
  decodeEntityConfiguration,
  decodeSubordinateStatement,
  generateSigningKey,
  signEntityConfiguration,
  signSubordinateStatement,
  verifyEntityStatement,
  JwkSigner
} from "@oidfed/core";

const keyPair = await generateSigningKey("ES256");
const signer = new JwkSigner(keyPair.privateKey);
const authorityKeyPair = await generateSigningKey("ES256");
const authoritySigner = new JwkSigner(authorityKeyPair.privateKey);

const entityConfigurationJwt = await signEntityConfiguration({
  entityId: "https://leaf.example.com",
  jwks: { keys: [keyPair.publicKey] },
  metadata: {
    federation_entity: {
      organization_name: "Example Leaf"
    }
  },
  authorityHints: ["https://ta.example.org"],
  signer,
  ttlSeconds: 3600
});

const subordinateStatementJwt = await signSubordinateStatement({
  issuer: "https://ta.example.org",
  subject: "https://leaf.example.com",
  jwks: { keys: [keyPair.publicKey] },
  metadata: {
    federation_entity: {
      organization_name: "Example Leaf"
    }
  },
  signer: authoritySigner,
  ttlSeconds: 3600
});

const decodedEc = decodeEntityConfiguration(entityConfigurationJwt);
const decodedSs = decodeSubordinateStatement(subordinateStatementJwt);

if (decodedEc.ok && decodedSs.ok) {
  console.log(decodedEc.value.payload.iss);
  console.log(decodedSs.value.payload.sub);
}

const result = await verifyEntityStatement(entityConfigurationJwt, {
  keys: [keyPair.publicKey]
});
```

`decodeEntityConfiguration` and `decodeSubordinateStatement` validate the JWT `typ` header and payload shape but do not verify signatures. Use them for local inspection and kind-safe parsing. Use `verifyEntityStatement`, trust-chain validation, or the higher-level verification helpers before trusting remote input.

### Trust-chain discovery and validation

`resolveTrustChains()` builds candidate paths. Pass each candidate to `validateTrustChain()` to check signatures, expiry, constraints, and metadata policy. Use `discoverEntity()` when you want a validated, selected chain in one call.

```ts
import { resolveTrustChains, validateTrustChain, createTrustAnchorSet, entityId } from "@oidfed/core";

const trustAnchors = createTrustAnchorSet([
  {
    entityId: "https://ta.example.org",
    jwks: { keys: [taPublicKey] }
  }
]);

// 1. Resolve trust chain candidates
const resolution = await resolveTrustChains(
  entityId("https://leaf.example.com"),
  trustAnchors
);

// 2. Validate chain signature continuity and resolve policy
for (const chain of resolution.chains) {
  const validation = await validateTrustChain(chain.statements, trustAnchors);
  if (validation.valid) {
    console.log("Validated Metadata:", validation.chain.resolvedMetadata);
    console.log("Chain Expiry:", new Date(validation.chain.expiresAt * 1000));
  }
}
```

### Metadata policy resolution

Resolve policies from the chain, then apply the combined policy to metadata. The standard operators in Section 9.2 are `value`, `default`, `one_of`, `subset_of`, `superset_of`, `add`, and `essential`.

```ts
import { resolveMetadataPolicy, applyMetadataPolicy } from "@oidfed/core";

// Parsed, verified Subordinate Statements in leaf-to-TA order.
// resolveMetadataPolicy reads each statement's payload.metadata_policy.
const policyResult = resolveMetadataPolicy(subordinateStatements);

if (policyResult.ok) {
  const finalMetadata = applyMetadataPolicy(rawMetadata, policyResult.value);
  if (finalMetadata.ok) console.log(finalMetadata.value);
}
```

### Checking constraints

Check maximum path length and permitted/excluded names against a parsed chain. `validateTrustChain()` runs the chain-level constraint checks and applies `allowed_entity_types` when resolving metadata.

```ts
import { checkConstraints } from "@oidfed/core";

const constraints = {
  max_path_length: 2,
  naming_constraints: {
    permitted: [".org", ".example.com"]
  }
};

// Depth level 1 check
const constraintsResult = checkConstraints(constraints, 1, parsedStatements);
if (constraintsResult.ok) {
  // Satisfies all path and domain restrictions
}
```

### Federation key providers

Federation signing keys are exposed through two contracts:

- `FederationKeyProvider` returns the current federation signer and the active published Federation JWKS. Leaf entities and OIDC/OAuth federation helpers use this read-only contract.
- `FederationKeyLifecycleProvider` extends `FederationKeyProvider` with key publication, active-key switching, revocation state, and historical federation keys for authorities and operator-owned rollover workflows.

OIDC/OAuth protocol keys remain separate from federation entity keys and are configured through protocol key providers in `@oidfed/oidc`.

```ts
import { createFederationSigningKey, MemoryFederationKeyProvider } from "@oidfed/core";

const keyProvider = new MemoryFederationKeyProvider(
  createFederationSigningKey(activePrivateKey),
);

// The in-memory provider implements FederationKeyLifecycleProvider
// and requires at least one initial active signing key.
const { signer, jwks } = await keyProvider.getFederationKeySet();
```

### Replay protection (`ReplayStore`)

A `ReplayStore` claims an `(issuer, audience, jti)` tuple until expiry. Claims must be atomic across the processes serving one tenant. The in-memory implementation is for development and tests.

```ts
import { MemoryReplayStore } from "@oidfed/core";

const store = new MemoryReplayStore({ maxEntries: 1000 });

const isNew = await store.useJti({
  issuer: "https://issuer.example.com",
  audience: "https://audience.example.com",
  jti: "jti-id-7890",
  expiresAt: Math.floor(Date.now() / 1000) + 600
});

if (!isNew) {
  console.warn("Replay detected");
}
```

### Memory cache

`MemoryCache` stores values with TTLs in seconds and evicts least recently used entries at capacity. Its data is process-local and lost on restart.

```ts
import { MemoryCache, ecCacheKey } from "@oidfed/core";
import { entityId } from "@oidfed/core";

const cache = new MemoryCache({ maxEntries: 100 });
const key = await ecCacheKey(entityId("https://example.com"));

await cache.set(key, "cached-statement-jwt", 3600);
const cached = await cache.get<string>(key);
```

### Trust marks

Validate the Trust Mark signature, issuer authorization, subject, expiry, and any delegation first. Status is a separate request to the issuer's advertised status endpoint. The example assumes `issuerJwks`, `trustMarkIssuers`, `trustMarkOwners`, and `statusEndpoint` came from trusted federation processing.

```ts
import { validateTrustMark, fetchTrustMarkStatus } from "@oidfed/core";

const validation = await validateTrustMark(rawTrustMarkJwt, trustMarkIssuers, issuerJwks, {
  expectedSubject: "https://leaf.example.com",
  trustMarkOwners // Optional dictionary mapping trust mark types to owners for delegation checks
});

if (validation.ok) {
  const status = await fetchTrustMarkStatus(
    statusEndpoint, rawTrustMarkJwt, issuerJwks, { httpClient: fetch },
  );
  console.log("Trust Mark Status:", status);
}
```

## Subordinate Events Endpoint

[Draft 01](https://openid.net/specs/openid-federation-subordinate-events-1_0.html) defines signed histories published by authorities about their Immediate Subordinates. `fetchSubordinateEvents` fetches and verifies a response using independently trusted issuer keys:

```ts
import { entityId, fetchSubordinateEvents } from "@oidfed/core";

const result = await fetchSubordinateEvents(
  "https://ta.example.org/history",
  entityId("https://client.example.org"),
  {
    issuer: entityId("https://ta.example.org"),
    issuerJwks: trustedAuthorityJwks,
  },
);
if (!result.ok) throw new Error(result.error.description);
console.log(result.value.federation_registration_events);
```

`trustedAuthorityJwks` must come from a trusted source. The client checks the signature, JWT type, payload schema, expected issuer, requested subject, and applicable dates. The endpoint origin is not a substitute for the issuer Entity Identifier. A supplied `clientAssertion` switches the request to authenticated form POST; create the assertion with the authority's Entity Identifier as its audience. Existing timeout, response-size, cancellation, and fetch-URL protections apply. Both request modes reject redirects to prevent assertion forwarding and requests to unvalidated destinations. Use the final advertised endpoint URL; it must have no fragment, including an empty trailing `#`. Encoded `%23` characters in paths or query parameters remain valid.

Use `verifySubordinateEventsResponse(jwt, trustedAuthorityJwks, { issuer, subject })` for a JWT obtained separately. Both helpers accept the existing clock and clock-skew options. Required response claims are `iss`, `sub`, `iat`, and `federation_registration_events`; `exp` is optional. Response issuance and event occurrence times are separate. Numeric timestamps may be fractional or negative and must be finite.

Core exports `SubordinateEventSchema`, `SubordinateEventsResponseSchema`, their inferred types, and standard `SubordinateEventType` constants. The `event` field also accepts operator-defined strings. The standard key-change name is `jwks_update`, as defined in §2.3.3; names in received history are preserved. The registration exclusion in that section is applied by authority capture to its initial registration operation, without rejecting separate events merely for equal timestamps.

`information_uri` is optional and recommends HTTPS; HTTP URLs and fragments remain valid. The client does not dereference it. The shared `MediaType.EntityEventsStatement` and `JwtTyp.EntityEventsStatement` constants identify the response. Decoding alone does not verify history, and signed history does not establish past trust-chain validity.
