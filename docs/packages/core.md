# `@oidfed/core`

<p align="center">
  <a href="https://www.npmjs.com/package/@oidfed/core"><img alt="npm" src="https://img.shields.io/npm/v/@oidfed/core.svg" /></a>
  <a href="https://www.npmjs.com/package/@oidfed/core"><img alt="downloads" src="https://img.shields.io/npm/dm/@oidfed/core.svg" /></a>
  <a href="https://github.com/Dahkenangnon/oidfed/blob/main/packages/core/LICENSE"><img alt="license" src="https://img.shields.io/npm/l/@oidfed/core.svg" /></a>
  <a href="https://packagephobia.com/result?p=@oidfed/core"><img alt="install size" src="https://packagephobia.com/badge?p=@oidfed/core" /></a>
  <a href="https://github.com/Dahkenangnon/oidfed/blob/main/scripts/coverage-check.sh"><img alt="coverage" src="https://img.shields.io/badge/coverage-%E2%89%A590%25-brightgreen" /></a>
</p>

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
Provides HTTP fetching primitives equipped with SSRF protection (IP address validation blocking special-use ranges like loopback and private networks) to retrieve configurations and statements. Successful federation responses must carry the exact registered media type with no parameters.

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

### 4. Entity Statement Builders & Signing
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
  signer,
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

---

### 5. Trust Chain Discovery & Validation
Finds trust paths from a leaf entity to configured Trust Anchors, validates each link's signature/expiration, and resolves the final metadata.

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
