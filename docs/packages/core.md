# `@oidfed/core`

Federation primitives for JavaScript — entity statements, trust chain resolution, metadata policy, cryptographic verification, and federation signing abstractions. This is the foundational layer of the OpenID Federation 1.0/1.1 implementation.

## Overview

The `@oidfed/core` package provides the low-level building blocks required to interact with an OpenID Federation. It encapsulates key parsing, signature verification, HTTP discovery workflows, constraint enforcement, and hierarchical metadata policy merges. It maintains zero dependencies on OIDC-specific presentation logic, making it suitable for any federation client, authority server, or intermediate node.

---

## Capabilities & Usage Guide

### 1. Functional Error Management (`Result`)
To avoid side-effects from uncaught exceptions, the library encapsulates operations in a serializable, structurally typed `Result<T, E>` wrapper. 

```ts
import { ok, err, isOk, federationError } from "@oidfed/core";
import type { Result, FederationError } from "@oidfed/core";

function parsePort(portStr: string): Result<number, FederationError> {
  const parsed = Number.parseInt(portStr, 10);
  if (Number.isNaN(parsed)) {
    return err(federationError("invalid_request", "Port must be a valid number"));
  }
  return ok(parsed);
}

const res = parsePort("8080");
if (isOk(res)) {
  console.log("Success:", res.value); // 8080
} else {
  console.error("Failed:", res.error.description);
}
```

---

### 2. Entity Identifiers (`EntityId`)
Validates that strings conform to OpenID Federation rules: must be valid URLs using the `https` scheme, without fragment or query components, and under 2048 characters. Per Section 3.1.2 of the OpenID Federation 1.0 specification, the `authority_hints` list of immediate superiors must not be empty `[]` and must not be present in the configurations of Trust Anchors with no superiors.

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

---

### 3. HTTP Discovery and Fetching
Provides HTTP fetching primitives equipped with SSRF protection (IP address validation blocking special-use ranges like loopback and private networks) to retrieve configurations and statements.

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

---

### 4. JOSE & Cryptographic Signing
Implements signing, decoding, and signature verification on entity statements using cryptographic key adapters.

```ts
import { generateSigningKey, signEntityStatement, verifyEntityStatement, JwkSigner } from "@oidfed/core";
import type { JwtSigner } from "@oidfed/core";

const keyPair = await generateSigningKey("ES256");
const signer: JwtSigner = new JwkSigner(keyPair.privateKey);

const payload = {
  iss: "https://leaf.example.com",
  sub: "https://leaf.example.com",
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  metadata: {}
};

// Sign statement
const signedJwt = await signEntityStatement(payload, signer);

// Verify statement
const result = await verifyEntityStatement(signedJwt, {
  keys: [keyPair.publicKey]
});
```

---

### 5. Trust Chain Discovery & Validation
Finds trust paths from a leaf entity to configured Trust Anchors, validates each link's signature/expiration, and resolves the final metadata.

```ts
import { resolveTrustChains, validateTrustChain, createTrustAnchorSet, entityId } from "@oidfed/core";

const trustAnchors = createTrustAnchorSet([
  {
    entityId: entityId("https://ta.example.org"),
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

---

### 6. Metadata Policy Resolution
Merges policy trees resolved from intermediate subordinates in a chain and applies them to metadata properties. It fully supports standard operators defined in Section 6.1.3.1 of the specification: `value`, `default`, `one_of`, `subset_of`, `superset_of`, `add`, and `essential`.

```ts
import { resolveMetadataPolicy, applyMetadataPolicy } from "@oidfed/core";

const anchorPolicy = {
  openid_relying_party: {
    contacts: { essential: true }
  }
};

const subordinatePolicy = {
  openid_relying_party: {
    contacts: { add: ["admin@intermediate.org"] }
  }
};

// Resolve the policy chain
const policyResult = resolveMetadataPolicy([anchorPolicy, subordinatePolicy]);

if (policyResult.ok) {
  // Apply the resolved policy to raw metadata
  const finalMetadata = applyMetadataPolicy(rawMetadata, policyResult.value);
}
```

---

### 7. Entity Constraints Enforcer
Enforces path length limitations and naming constraints (permitted and excluded domains) along the trust chain.

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

---

### 8. Federation Key Providers
Manages signing configurations and public JWKS publications for federation entities, supporting rotation schedules.

```ts
import { MemoryFederationKeyProvider, JwkSigner } from "@oidfed/core";

const keyProvider = new MemoryFederationKeyProvider({
  signer: new JwkSigner(activePrivateKey),
  publicJwk: activePublicKey
});

// Retrieve current signing configuration and published keys
const { signer, jwks } = await keyProvider.getFederationKeySet();
```

---

### 9. Replay Protection (`ReplayStore`)
Enforces message uniqueness by checking transaction identifiers (`jti`) within token validation loops.

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

---

### 10. Memory Cache
Implements in-memory cache helpers using standard TTL parameters (seconds) to cache entity configurations and trust chains.

```ts
import { MemoryCache, ecCacheKey } from "@oidfed/core";
import { entityId } from "@oidfed/core";

const cache = new MemoryCache({ maxEntries: 100 });
const key = await ecCacheKey(entityId("https://example.com"));

await cache.set(key, "cached-statement-jwt", 3600);
const cached = await cache.get<string>(key);
```

---

### 11. Trust Marks
Provides verification of trust mark assertions, checking signatures and validating their active status.

```ts
import { validateTrustMark, fetchTrustMarkStatus } from "@oidfed/core";

const validation = await validateTrustMark(rawTrustMarkJwt, trustMarkIssuers, issuerJwks, {
  expectedSubject: "https://leaf.example.com",
  trustMarkOwners // Optional dictionary mapping trust mark types to owners for delegation checks
});

if (validation.ok) {
  const status = await fetchTrustMarkStatus(validation.value, { httpClient: fetch });
  console.log("Trust Mark Status:", status);
}
```
