# `@oidfed/core`

<p align="center">
  <a href="https://www.npmjs.com/package/@oidfed/core"><img alt="npm" src="https://img.shields.io/npm/v/@oidfed/core.svg" /></a>
  <a href="https://www.npmjs.com/package/@oidfed/core"><img alt="downloads" src="https://img.shields.io/npm/dm/@oidfed/core.svg" /></a>
  <a href="https://github.com/Dahkenangnon/oidfed/blob/main/packages/core/LICENSE"><img alt="license" src="https://img.shields.io/npm/l/@oidfed/core.svg" /></a>
  <a href="https://packagephobia.com/result?p=@oidfed/core"><img alt="install size" src="https://packagephobia.com/badge?p=@oidfed/core" /></a>
</p>

`@oidfed/core` provides Entity Statement builders, signature verification, trust-chain discovery and validation, metadata policies, constraints, and trust marks for OpenID Federation 1.0. Authority, leaf, and OIDC packages use these primitives.

Use the functions here when you need direct control over federation processing. For an HTTP-serving entity, start with [authority](authority.md) or [leaf](leaf.md).

See [operator and application responsibilities](../guide/operator-responsibilities.md#openid-federation) for anchor provisioning, independent key comparisons, trust reevaluation, and production key and storage contracts.

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

Fetch Entity Configurations and Subordinate Statements over HTTPS. The URL checks reject special-use IP literals and support host allowlists and additional blocked IPv4 ranges. DNS resolution and redirect policy belong to the HTTP transport: configure your injected `httpClient` and network access controls for the deployment. Federation response checks require the exact registered media type without parameters. Entity Configuration discovery uses GET under [§9.1](https://openid.net/specs/openid-federation-1_0.html#section-9.1), without a Federation client assertion. The advertised `*_auth_methods` settings cover other federation endpoints. Profile-specific discovery access controls require a suitably configured HTTP transport.

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

### Verifying Resolve Responses

Use `verifyResolveResponse` with the resolver's trusted public keys. For an authenticated request, supply your application's Entity Identifier as `expectedAudience`:

```ts
import { verifyResolveResponse } from "@oidfed/core";

const result = await verifyResolveResponse(responseJwt, resolverJwks, {
  expectedAudience: "https://client.example.com",
});
```

Under [Federation §8.3.2](https://openid.net/specs/openid-federation-1_0.html#section-8.3.2), `aud` is optional and identifies only the requesting party when present. The helper accepts a string or a nonempty array containing only that same identifier, following [RFC 7519 §4.1.3](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3). Each value must match `expectedAudience` exactly. A response containing `aud` fails verification if the caller omits `expectedAudience`. Responses without `aud` remain valid with or without a configured audience; any supplied `expectedAudience` must be a valid Entity Identifier.

The helper checks the JWT signature, type, time claims, payload shape, and audience. The application chooses the trusted resolver keys and checks that the returned subject and trust chain satisfy its request and trust policy.

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

Validation rejects a path that visits an Entity more than once, as required by [Federation §17.1](https://openid.net/specs/openid-federation-1_0.html#section-17.1) and [§10.1](https://openid.net/specs/openid-federation-1_0.html#section-10.1). The optional closing Trust Anchor Entity Configuration describes the final Entity in that path. Separate candidate paths may share Entities.

When the chain includes the Trust Anchor's Entity Configuration, its signature must verify against both the configured anchor keys and its own `jwks` ([Federation §3.2](https://openid.net/specs/openid-federation-1_0.html#section-3.2), [§4](https://openid.net/specs/openid-federation-1_0.html#section-4)). The configured keys establish trust; the self-signature check confirms that the EC's published key matches its signature. During rollover, the EC can publish additional keys while retaining the key that signs it, following [§11.2](https://openid.net/specs/openid-federation-1_0.html#section-11.2).

To start discovery from a supplied signed Entity Configuration, pass `entityConfigurationJwt` in `ResolveTrustChainsOptions`. The resolver checks its identity and follows its authority hints using the configured traversal and HTTP limits. It leaves the cached published EC unchanged. Discovery produces candidates; it does not authenticate the supplied JWT.

During each `resolveTrustChains()` call, candidate paths share pending and completed statement retrievals, following [Federation §10.1](https://openid.net/specs/openid-federation-1_0.html#section-10.1). Entity Configurations are identified by their exact Entity Identifier; Subordinate Statements by their issuer and subject. A failed retrieval is shared for that call and can be retried by a later call. Repeated values in each authority-hint list are collapsed after the raw hint-count limit is applied. Each path keeps its own loop checks, so converging paths remain available.

`maxTotalFetches` limits calls to the HTTP client, including failed requests. Cached, supplied, and shared statements consume no HTTP budget; a fully cached resolution can run with `maxTotalFetches: 0`. `maxResolutionSteps` separately bounds branch expansion, including paths that reuse statements. It accepts a positive safe integer and defaults to `DEFAULT_MAX_RESOLUTION_STEPS` (1000). Each admitted hint counts as one step after filtering and loop checks. When a limit prevents further work, the result includes `incomplete: true`, an error, and any candidates already found. These local safeguards bound discovery work; each returned candidate still needs validation.

For explicit registration, `validateTrustChain()` accepts `explicitRegistrationRequest: { jwt, audience }`. It authenticates the supplied path and the registration JWT against that path's attested federation keys. The supplied path's EC provides evidence of the relationship; its metadata does not determine whether the tailored registration metadata is acceptable. Metadata resolution then uses the actual request and the path's superior statements, as required by [Federation §12.2.2](https://openid.net/specs/openid-federation-1_0.html#section-12.2.2). The returned chain contains the submitted request as its first statement. The OIDC role handles registration transport, peer-chain checks, candidate selection, and response processing.

`validateCriticalClaims(payload, understoodClaims?)` checks the payload `crit` rules in [§3.1.1](https://openid.net/specs/openid-federation-1_0.html#section-3.1.1). `validateEntityStatementTimeClaims(payload, options?)` checks required statement timestamps against the configured clock and skew. Both helpers return a `Result`; use them alongside signature and profile validation.

Entity Statement and explicit-registration timestamps accept finite NumericDates, including fractions and dates at or before the Unix epoch, as defined in [RFC 7519 §2](https://www.rfc-editor.org/rfc/rfc7519#section-2). Time validation still enforces issuance and expiry against the configured clock. Entity Statement builders preserve the supplied `issuedAt` and require a positive integer `ttlSeconds`.

A configured Trust Anchor can also have superiors, as described in [Federation §4.1](https://openid.net/specs/openid-federation-1_0.html#section-4.1). Its signed `authority_hints` declares those relationships; the configured anchor keys establish trust for your application. An anchor with superiors may also publish `trust_anchor_hints`. An anchor without superiors must omit both claims, and either array must be nonempty when present ([§3.1.2](https://openid.net/specs/openid-federation-1_0.html#section-3.1.2)).

When the requested entity is a configured anchor, `resolveTrustChains()` includes its own Entity Configuration as a direct candidate and follows any authority hints for additional paths. Each candidate still needs validation against the configured keys. Errors or work limits on a superior path remain visible in `errors` and, when applicable, `incomplete`, even when a direct candidate is available.

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

Resolve policies from the chain, then apply the combined policy to metadata. The standard operators in [Federation §6.1.3](https://openid.net/specs/openid-federation-1_0.html#section-6.1.3) are `value`, `default`, `one_of`, `subset_of`, `superset_of`, `add`, and `essential`.

Overrides and policies apply only to entity types present in the input metadata, following [§3.1.1](https://openid.net/specs/openid-federation-1_0.html#section-3.1.1) and [§6.1.1](https://openid.net/specs/openid-federation-1_0.html#section-6.1.1). When calling `applyMetadataPolicy()` directly, include an object for each intended type; `{}` allows its parameters to be supplied by overrides or policies. Types removed by `allowed_entity_types` remain absent. Policy syntax, critical operators, and merge conflicts are still checked during resolution under [§6.1.4.1](https://openid.net/specs/openid-federation-1_0.html#section-6.1.4.1).

Core validates known `federation_entity` fields in Entity Configurations and Subordinate Statements under [§3.2](https://openid.net/specs/openid-federation-1_0.html#section-3.2) and [§5.1.1](https://openid.net/specs/openid-federation-1_0.html#section-5.1.1). `applyMetadataPolicy()` checks these fields after all operators finish; `validateTrustChain()` also checks the final metadata when no policy applies. Invalid results return validation errors, as required by [§6.1.4.2](https://openid.net/specs/openid-federation-1_0.html#section-6.1.4.2). Custom entity types and extension parameters are preserved. Protocol packages and applications validate their protocol-specific fields.

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

`naming_constraints` applies to the subject of the Subordinate Statement carrying it and to that subject's subordinates, as specified in [Federation §3.1.3](https://openid.net/specs/openid-federation-1_0.html#section-3.1.3). The issuer is outside its own constraint. Hostname matching follows [§6.2.2](https://openid.net/specs/openid-federation-1_0.html#section-6.2.2), with excluded names taking precedence over permitted names. A violation invalidates the chain under [§6.2](https://openid.net/specs/openid-federation-1_0.html#section-6.2).

`max_path_length` sets the maximum number of Intermediate Entities between the issuer of the constraint and the Trust Chain subject. [Federation §6.2.1](https://openid.net/specs/openid-federation-1_0.html#section-6.2.1) requires a non-negative integer and specifies no upper bound. The schema accepts non-negative JavaScript safe integers. Local discovery work is bounded separately by `maxChainDepth`, `maxAuthorityHints`, `maxResolutionSteps`, and `maxTotalFetches`; a large constraint value does not increase those budgets.

`allowed_entity_types` accepts non-empty Entity Type identifiers, including custom types permitted by [Federation §5.1](https://openid.net/specs/openid-federation-1_0.html#section-5.1). Omit the constraint to allow all types, or use `[]` to retain only `federation_entity`. That type is always retained and must not appear in the array. Filtering follows [§6.2.3](https://openid.net/specs/openid-federation-1_0.html#section-6.2.3); applications validate the protocol-specific metadata they use.

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

The bundled key providers copy supplied and returned public JWK data; `JwkSigner` copies its software key on construction. Opaque signers retain custody of their own key material. When creating federation signing keys from private JWKs, the derived public key permits verification rather than signing.

The bundled federation key providers and Entity Statement builders check the public parameters of every key before accepting a set for publication. `validatePublicJwkSet(value)` exposes the same check as a `Result<void, FederationError>`, including the federation requirement for unique, nonempty `kid` values. Key-material errors identify the key index and parameter without including key values.

Publication uses a detached JSON snapshot of the supplied set. Validation checks that snapshot, including any `toJSON()` output, and providers and builders retain it for later use. Required parameters must appear in the serialized data. Serialization failures return a validation error without exposing the underlying exception.

`preparePublicJwkSet(value)` returns that validated snapshot as a `Result<JWKSet, FederationError>`. Use its returned value when publishing or retaining a set: subsequent changes to the input leave the snapshot unchanged. The helper preserves JSON extension members and rejects private key fields, consistent with the public-key claim defined in [Federation §3.1.1](https://openid.net/specs/openid-federation-1_0.html#section-3.1.1). It is exported from `@oidfed/core` alongside `validatePublicJwkSet`.

The check covers required RSA, EC and OKP parameters, base64url encoding, minimal RSA integer encoding, and public-parameter lengths for P-256, P-384, P-521, Ed25519, Ed448, X25519 and X448. These representations are defined by [RFC 7518 §6](https://www.rfc-editor.org/rfc/rfc7518.html#section-6) and [RFC 8037 §2](https://www.rfc-editor.org/rfc/rfc8037.html#section-2). Other curve identifiers receive the generic parameter and encoding checks; their curve-specific representation and cryptographic usability remain the responsibility of the backend.

`JWKSchema` and `JWKSetSchema` provide structural parsing. Received sets retain their keys, and verification checks the selected key. An incomplete, unselected key can coexist with a valid signing key, consistent with [RFC 7517 §5](https://www.rfc-editor.org/rfc/rfc7517.html#section-5). The publication check applies to the top-level federation `jwks`; protocol metadata and generic JWT signing keep their separate validation contracts.

`MetadataJWKSetSchema` parses public protocol keys under [Federation §5.2.1](https://openid.net/specs/openid-federation-1_0.html#section-5.2.1). A key can omit `kid`, and different keys can share an identifier where the protocol permits it ([RFC 7517 §4.5](https://www.rfc-editor.org/rfc/rfc7517.html#section-4.5)). `resolveEntityKeys()` applies this schema to inline `jwks` and HTTPS `jwks_uri` responses; signed JWK Set payloads use the same key schema. The signed envelope uses federation keys and requires its own header `kid`.

`verifyProtocolJwt(jwt, jwks, options)` verifies protocol JWTs against authenticated metadata keys. Set `expectedTyp` to the protocol's required type. The default `keyIdPolicy: "required"` requires a header `kid`; `"single-key"` permits omission when the supplied set contains exactly one key, following [OIDC Core §10.1](https://openid.net/specs/openid-connect-core-1_0.html#Signing). A supplied identifier must match. Candidate selection checks the signing algorithm, key type, curve and usage before signature verification. The helper checks JWT time claims using `clock` and `clockSkewSeconds`; callers bind the keys to the expected entity and validate protocol claims, including issuer and audience. `verifyEntityStatement()` retains the federation header requirements.

`MemoryFederationKeyProvider` orders activations independently of the clock and applies each lifecycle transition atomically. Publishing does not change the signer. Switching selects the requested published key and schedules the previous signer for retirement. Retirement removes a key from subsequent published JWKS results without deleting its historical record.

The memory provider's `getHistoricalFederationKeys()` returns retired and revoked keys. A retiring key enters history at its recorded expiry; active keys, prepublished keys and keys still in overlap remain in the current JWKS. An empty history returns `[]`. Per-key `exp` records the lifetime required by [Federation §8.7.2](https://openid.net/specs/openid-federation-1_0.html#section-8.7.2); reads preserve that value. NumericDate values retain fractional seconds to match the provider's millisecond deadlines.

Rollover follows [Federation §11.2](https://openid.net/specs/openid-federation-1_0.html#section-11.2). The application publishes a key, allows a propagation interval, then switches signers. `retirePreviousAfterMs` controls the separate post-switch overlap; the memory provider defaults to seven days. The provider does not decide when participants have obtained a new key. See the [staged authority example](authority.md#federation-key-rotation).

The retirement interval must be finite and nonnegative, and the resulting deadline must be finite. Zero retires the previous signer immediately. Invalid intervals leave the key state unchanged.

Revocation is a local provider operation, with historical key status defined by [§8.7.2](https://openid.net/specs/openid-federation-1_0.html#section-8.7.2). It does not notify other participants or invalidate their cached statements; [§11.4](https://openid.net/specs/openid-federation-1_0.html#section-11.4) leaves that process to the federation. Occurrence timestamps remain stable on later history reads, including epoch zero.

The memory provider preserves a key's recorded expiry when revoking it. For a key with no recorded expiry, the first revocation sets its validity cutoff. Repeating `revokeKey()` updates the reason while preserving both expiry and the first `revoked_at`. This also preserves the original expiry when a compromise is discovered after retirement, as described in [§8.7](https://openid.net/specs/openid-federation-1_0.html#section-8.7).

### Replay protection (`ReplayStore`)

`verifyClientAssertion()` requires `exp` and a non-empty `jti`; `iat` is optional. It checks the signature, issuer/subject equality, exact audience, expiry, and any supplied issuance time. Pass `replayStore` to atomically claim a verified assertion. Without it, the function verifies the JWT without recording its use. Authentication handlers must provide replay storage. These claims follow [OIDC Core §9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication), referenced by [Federation §8.8](https://openid.net/specs/openid-federation-1_0.html#section-8.8).

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

`validateTrustChain()` reports chain validity separately from Trust Mark trust, following [Federation §3.2](https://openid.net/specs/openid-federation-1_0.html#section-3.2) and [§17.5](https://openid.net/specs/openid-federation-1_0.html#section-17.5). Mandatory reference syntax checks, including matching the reference's type to the JWT's type, remain part of chain validation. An expired mark or unavailable issuer evidence appears in the mark results while an otherwise valid chain remains valid.

For a valid chain, `trustMarkEvaluations` contains one result per published subject mark, in reference order. Each result identifies its `referenceIndex` and `trustMarkType`:

- `verified` includes the validated `mark`.
- `invalid` includes the validation `error`.
- `unevaluated` includes a `reason` and `description`: issuer policy or trusted keys were unavailable, or evaluation was reserved for a separate step.

`chain.trustMarks` contains only verified marks. Verification describes the evidence at validation time; active status is checked separately. Chain expiry remains the earliest Entity Statement expiry under [§10.4](https://openid.net/specs/openid-federation-1_0.html#section-10.4).

Use `checkTrustMarkRequirements()` to apply your application's accreditation requirements:

```ts
import { checkTrustMarkRequirements, validateTrustChain } from "@oidfed/core";

const result = await validateTrustChain(statements, trustAnchors);
if (!result.valid) throw new Error("Invalid federation chain");

const accreditation = checkTrustMarkRequirements(result.chain, {
  requiredTypes: ["https://accreditation.example/university"],
});
if (!accreditation.ok) throw new Error(accreditation.error.description);
```

Each required type needs at least one verified mark whose dates remain valid. Set `requireAllPublished: true` to require every published mark to pass as an additional application policy; an empty publication satisfies that option, so use `requiredTypes` when a mark must exist. Both checks apply when combined. The helper rejects expired chain evidence and rechecks mark and delegation dates using the supplied clock and clock skew. The helper uses the supplied evidence. Obtain fresh issuer evidence and check active status when your policy requires it.

Chain validation uses the included anchor Entity Configuration's issuer and owner declarations. An omitted anchor configuration or undeclared type leaves the mark unevaluated. For issuers outside the supplied chain, `trustMarkIssuerKeys` accepts keys whose federation trust the caller has independently established under [§7.3](https://openid.net/specs/openid-federation-1_0.html#section-7.3). Supply the necessary anchor configuration when evaluating its mark policy. Fetching an issuer's self-published keys alone does not establish that trust.


Validate the Trust Mark signature, issuer authorization, subject, expiry, and any delegation first. Status is a separate request to the issuer's advertised status endpoint. The example assumes `issuerJwks`, `trustMarkIssuers`, `trustMarkOwners`, and `statusEndpoint` came from trusted federation processing.

Issuer and owner registries use explicitly declared JSON members. In `validateTrustMark()`, an explicit empty issuer array permits any issuer for that type; a nonempty array restricts issuance to its listed Entity Identifiers ([Federation §3.1.2](https://openid.net/specs/openid-federation-1_0.html#section-3.1.2)). An explicit owner entry requires a valid delegation under [§7.3](https://openid.net/specs/openid-federation-1_0.html#section-7.3). Malformed entries return validation errors.

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

## Entity Collection

Use `EntityCollectionService` to refresh Draft 01 collections, query them in process, and handle Web-standard HTTP requests. It uses `MemoryEntityCollectionStore` by default; implement `EntityCollectionStore` for durable storage. The `fetchEntityCollection` client retrieves unsigned informational JSON from collection providers, including independent applications. See the [Entity Collection guide](../guide/entity-collection.md) for the APIs, filters, authentication, storage, and defaults.

When cancellation or a work limit stops resolution, `resolveTrustChains` reports `incomplete: true` alongside its `chains` and `errors`. Collection refresh rejects these incomplete results. Pass a signal to `createConcurrencyLimiter(maxConcurrent, signal?)` to cancel queued work. When caching calls to `fetchSubordinateStatement`, supply the actual Entity Identifier as `issuer` in the options to distinguish authorities hosted on the same origin.

Collection configuration accepts an optional `collector` for application inventories and a `filter` for additional restrictions. Core validates collector output and verifies the marks used for filtering. `EntityCollectionCandidate` contains informational entity data and an eligibility deadline; `CollectionEntry` adds optional chain evidence and core-verified mark evidence. The [collection policy examples](../guide/entity-collection.md#collection-policy) cover independent sources and snapshot-time filters. Chain validation and Trust Mark evaluation have separate results, as described [above](#trust-marks).

## Contextual metadata validation

`prepareTrustChainValidation(statements, trustAnchors, options)` authenticates chain evidence while reserving explicitly named policy inputs that are absent from published metadata. Specify them through `deferredClaims`, an array of `{ entityType, parameter }` pairs. Unrelated policies and policies for published values must pass during preparation.

The returned `PreparedTrustChain` is an opaque handle with pending claims and preliminary effective metadata. It is distinct from `ValidatedTrustChain` and `DiscoveryResult`. Call `completeTrustChainValidation(prepared, contextualMetadata)` to finish the policies against the original evidence. Only reserved fields can receive contextual values. Completion revalidates the chain, expiry, and cancellation; request-derived metadata stays outside signed statement payloads and shared discovery caches.

`validateTrustChain` keeps its existing strict behavior and never defers required inputs. Wallet roles use the staged APIs for request-dependent DCQL checks; see the [wallet guide](wallet.md).

`EntityRole.validateMetadata(metadata, context)` is an optional synchronous hook. Hosts invoke it on detached composed role metadata before publication. Existing roles can omit it.

`findInvalidMetadataNullPaths(metadata)` returns the paths of forbidden null values. Statement builders, chain validation, and authority publication share this check. It permits null wildcard components only in the wallet specifications' issuer claim-description and verifier DCQL path arrays; other null metadata values remain invalid. Wallet roles validate the paths' format-specific syntax.
