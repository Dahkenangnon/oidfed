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

### Host-supplied logging

Pass your logger in `FederationOptions.logger` to receive messages from core, authority, leaf, OIDC, and wallet operations. Logging is silent until you supply one. Each call passes a single message. Messages exclude JWTs, credentials, private keys, callback inputs, and raw exceptions. Synchronous exceptions and rejected promises from the logger are contained, leaving the operation's result, exception, or HTTP response unchanged.

Synchronous and asynchronous loggers are supported. The library handles returned promises without awaiting them, so a pending remote sink does not hold up protocol processing. Synchronous work inside your logger still runs inline.

Messages omit entity identifiers and structured context. In a collection traversal, a warning therefore does not identify the individual entity that triggered it. Use your application's operation correlation where needed.

The levels have these meanings:

- `debug`: processing steps, cache decisions, candidate paths, and cancellation.
- `info`: completed operations and observable departures from applicable SHOULD or RECOMMENDED guidance.
- `warn`: rejected input or configuration that needs attention. Applicable MUST violations still cause normal rejection.
- `error`: unexpected service, storage, or application-callback failures, including verification timeouts.

Messages use the specification's terms where they apply. For example, a collection publisher without a Resolve endpoint receives one info notice after successful Entity Configuration signing: “Federation Entities publishing a federation_collection_endpoint SHOULD also publish a federation_resolve_endpoint.” Non-HTTPS Subordinate Event documentation produces a recommendation notice after its transaction commits. Omitting a MAY/OPTIONAL feature stays quiet.

Callback failures name the application integration, such as `onRegistration` or Wallet acceptance. Cache errors identify whether the read, write, or expired-entry deletion failed. Authority lifecycle completion messages follow successful commit. Continue handling returned errors and exceptions; a log message does not replace rejection or confirm that your callback performed every required check.

The specification determines which requirements apply; oidfed chooses these log levels, following node-oidc-provider's distinction between SHOULD notices and MUST warnings. Configure filtering and output in your host logger.

Logging cannot check application duties such as obtaining consent or scheduling trust refreshes. See [operator and application responsibilities](../guide/operator-responsibilities.md).

Core validation rejects a known Intermediate Entity or Trust Anchor whose checked Entity Configuration lacks `federation_fetch_endpoint` or `federation_list_endpoint`, following Federation §5.1.1. This is validation behavior even when no logger is supplied. Endpoint checks use the Entity Configurations available for validation; they do not require a trailing Trust Anchor Entity Configuration in a chain that otherwise permits its omission. Repeated paths to the same invalid authority produce one endpoint warning per resolution operation while retaining their individual errors. A later operation can report the problem again.

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

Fetch Entity Configurations and Subordinate Statements over HTTPS. The URL checks reject special-use IP literals and support host allowlists and additional blocked IPv4 ranges. DNS resolution and redirect policy belong to the HTTP transport: configure your injected `httpClient` and network access controls for the deployment. HTTP media-type names are compared case-insensitively. JSON responses accept parameters such as `charset=utf-8` ([RFC 8259 §11](https://www.rfc-editor.org/rfc/rfc8259.html#section-11)); registered Federation types, including `application/trust-chain+json`, require no parameters under [§15](https://openid.net/specs/openid-federation-1_0.html#section-15). Entity Configuration discovery uses GET under [§9.1](https://openid.net/specs/openid-federation-1_0.html#section-9.1), without a Federation client assertion. The advertised `*_auth_methods` settings cover other federation endpoints. Profile-specific discovery access controls require a suitably configured HTTP transport.

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

EC and Subordinate Statement caches expire at the earlier of the statement's `exp` and `cacheMaxTtlSeconds` (3600 seconds by default). Fetchers discard stale cache entries and refetch, following [Federation §10.2](https://openid.net/specs/openid-federation-1_0.html#section-10.2). Decoding `exp` determines cache lifetime only; callers still verify the returned JWT. A fetched statement without a usable future expiry is returned for validation and left uncached. Malformed fetch endpoint URLs return an error `Result`.

The HTTP method helpers return 405 with `Allow` and the `method_not_allowed` extension code. Their JSON body includes `error_description`, following the error format in [§8.9](https://openid.net/specs/openid-federation-1_0.html#section-8.9).

`maxTotalFetches` counts calls to the configured HTTP client. Redirects followed inside that client can make additional network exchanges. Deployments needing a limit on every exchange should enforce it in their HTTP client; endpoints that reject redirects retain that restriction.

### Verifying Resolve Responses

Use `verifyResolveResponse` with the resolver's trusted public keys, its Entity Identifier, and the requested subject. For an authenticated request, supply your application's Entity Identifier as `expectedAudience`:

```ts
import { verifyResolveResponse } from "@oidfed/core";

const result = await verifyResolveResponse(responseJwt, resolverJwks, {
  expectedIssuer: "https://resolver.example.com",
  expectedSubject: "https://leaf.example.com",
  expectedAudience: "https://client.example.com",
});
```

Under [Federation §8.3.2](https://openid.net/specs/openid-federation-1_0.html#section-8.3.2), `aud` is optional and identifies only the requesting party when present. The helper accepts a string or a nonempty array containing only that same identifier, following [RFC 7519 §4.1.3](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3). Each value must match `expectedAudience` exactly. A response containing `aud` fails verification if the caller omits `expectedAudience`. Responses without `aud` remain valid with or without a configured audience; any supplied `expectedAudience` must be a valid Entity Identifier.

The helper checks the JWT signature, type, time claims, payload shape, issuer, subject, and audience. Supply expected identities from your request or trusted configuration, as required for contextual JWT validation by [RFC 8725 §3.8](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.8). The application chooses trusted resolver keys and assesses the returned chain against its trust policy.

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

Every Subordinate Statement must name an issuer listed in its subject's Entity Configuration `authority_hints` ([§3.2(6)](https://openid.net/specs/openid-federation-1_0.html#section-3.2)). Validation reuses the chain's subject EC and looks up the intermediate ECs by exact Entity Identifier. Each resolved candidate exposes `entityConfigurations`; pass this map in the validation options to reuse discovery's ECs. These are auxiliary inputs and do not change the serialized `statements` array.

For independently supplied chains, provide signed intermediate EC JWTs through `entityConfigurations: ReadonlyMap<string, string>`, or allow validation to retrieve missing ECs using the configured HTTP client and cache. Each EC's identity, claims, time limits, self-signature, and signature against the subject keys attested in the chain are checked before its hints are used. Missing, invalid, or unavailable evidence fails validation. A fully local validation can use `maxTotalFetches: 0`; missing evidence then fails without network access. Additional retrievals are serial, cancellable, and bounded by `maxTotalFetches`, including failed HTTP calls. Invalid chain signatures are rejected before additional EC retrievals.

The returned validated chain's `expiresAt` is capped by the ECs supporting these relationship checks, so consumers refresh before any supporting evidence expires. Prepared validation retains the supporting signed ECs for completion and rechecks their validity.

To start discovery from a supplied signed Entity Configuration, pass `entityConfigurationJwt` in `ResolveTrustChainsOptions`. The resolver validates the identity, structure, time claims, and self-signature of the supplied EC and every fetched EC before following its authority hints or endpoints. It leaves the cached published EC unchanged. For a supplied explicit-registration request, also pass `explicitRegistrationAudience` with the expected OP Entity Identifier; its `aud` must match. This context applies only to the supplied JWT; fetched ECs follow ordinary publication rules. An audience without a supplied JWT is rejected. Discovery still produces candidate paths that require final validation against configured Trust Anchors.

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
  const validation = await validateTrustChain(chain.statements, trustAnchors, {
    entityConfigurations: chain.entityConfigurations
  });
  if (validation.valid) {
    console.log("Validated Metadata:", validation.chain.resolvedMetadata);
    console.log("Chain Expiry:", new Date(validation.chain.expiresAt * 1000));
  }
}
```

Supplied chains are limited to 100 statements by default, including their Entity Configurations. Set `maxChainLength` to a positive safe integer for deployments requiring longer chains. This resource budget follows [Federation §18.1](https://openid.net/specs/openid-federation-1_0.html#section-18.1); `maxChainDepth` separately limits discovery traversal.

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

Metadata policy `value` and `default` operators support JSON objects under [Federation §6.1.3.1.8](https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1.8). Merging compares complete values structurally: object member order is immaterial, array order is significant, and conflicting values fail. Nested objects are not recursively combined. Resolved values are detached from the supplied policy.

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

`JWKSchema` and `JWKSetSchema` provide structural parsing. Received sets retain unknown `kty` values; verification skips unsupported key types. Mandatory key-set rules still apply, and protocol `kid` omission depends on the original published key count. An incomplete, unselected key can coexist with a valid signing key, consistent with [RFC 7517 §5](https://www.rfc-editor.org/rfc/rfc7517.html#section-5). Federation publication checks apply to the top-level `jwks`. Composed hosts and statement builders also require supported public key types in inline protocol metadata. Generic JWT signing remains a lower-level operation.

`MetadataJWKSetSchema` parses public protocol keys under [Federation §5.2.1](https://openid.net/specs/openid-federation-1_0.html#section-5.2.1). A key can omit `kid`, and different keys can share an identifier where the protocol permits it ([RFC 7517 §4.5](https://www.rfc-editor.org/rfc/rfc7517.html#section-4.5)). `resolveEntityKeys()` applies this schema to inline `jwks` and HTTPS `jwks_uri` responses; signed JWK Set payloads use the same key schema. The signed envelope uses federation keys and requires its own header `kid`.

`resolveEntityKeys()`, `fetchSignedJwkSet()`, and `verifySignedJwkSet()` require `expectedIssuer` and `expectedOwner`. Supply both from authenticated entity context. [§5.2.1](https://openid.net/specs/openid-federation-1_0.html#section-5.2.1) recommends that issuer and owner match; explicitly expected distinct identities are accepted. Historical-key fetch and verification helpers require `expectedIssuer`.

`verifyProtocolJwt(jwt, jwks, options)` verifies protocol JWTs against authenticated metadata keys. Set `expectedTyp` to the protocol's required type. The default `keyIdPolicy: "required"` requires a header `kid`; `"single-key"` permits omission when the supplied set contains exactly one key, following [OIDC Core §10.1](https://openid.net/specs/openid-connect-core-1_0.html#Signing). A supplied identifier must match. Candidate selection checks the signing algorithm, key type, curve and usage before signature verification. The helper checks JWT time claims using `clock` and `clockSkewSeconds`; callers bind the keys to the expected entity and validate protocol claims, including issuer and audience. `verifyEntityStatement()` retains the federation header requirements.

`MemoryFederationKeyProvider` orders activations independently of the clock and applies each lifecycle transition atomically. Publishing does not change the signer. Switching selects the requested published key and schedules the previous signer for retirement. Retirement removes a key from subsequent published JWKS results without deleting its historical record.

The memory provider's `getHistoricalFederationKeys()` returns retired and revoked keys. A retiring key enters history at its recorded expiry; active keys, prepublished keys and keys still in overlap remain in the current JWKS. An empty history returns `[]`. Per-key `exp` records the lifetime required by [Federation §8.7.2](https://openid.net/specs/openid-federation-1_0.html#section-8.7.2); reads preserve that value. NumericDate values retain fractional seconds to match the provider's millisecond deadlines.

Rollover follows [Federation §11.2](https://openid.net/specs/openid-federation-1_0.html#section-11.2). The application publishes a key, allows a propagation interval, then switches signers. `retirePreviousAfterMs` controls the separate post-switch overlap; the memory provider defaults to seven days. The provider does not decide when participants have obtained a new key. See the [staged authority example](authority.md#federation-key-rotation).

The retirement interval must be finite and nonnegative, and the resulting deadline must be finite. Zero retires the previous signer immediately. Invalid intervals leave the key state unchanged.

Revocation is a local provider operation, with historical key status defined by [§8.7.2](https://openid.net/specs/openid-federation-1_0.html#section-8.7.2). It does not notify other participants or invalidate their cached statements; [§11.4](https://openid.net/specs/openid-federation-1_0.html#section-11.4) leaves that process to the federation. Occurrence timestamps remain stable on later history reads, including epoch zero.

The memory provider preserves a key's recorded expiry when revoking it. For a key with no recorded expiry, the first revocation sets its validity cutoff. Repeating `revokeKey()` updates the reason while preserving both expiry and the first `revoked_at`. This also preserves the original expiry when a compromise is discovered after retirement, as described in [§8.7](https://openid.net/specs/openid-federation-1_0.html#section-8.7).

After the last active key is revoked, signing stops until the application publishes a replacement and explicitly activates it with `switchActiveKey(kid)`. A replacement published before revocation can also be selected. Historical revocation records remain intact. The application manages trusted distribution of the replacement according to its [§11.4 revocation policy](https://openid.net/specs/openid-federation-1_0.html#section-11.4).

`selectHistoricalVerificationKey(keys, { kid, validAt, securityRevocationReasons })` accepts additional security-revocation reasons defined by the federation under [§8.7.3](https://openid.net/specs/openid-federation-1_0.html#section-8.7.3). These strings are matched exactly and extend the built-in reasons `compromised`, `keyCompromise`, and `key_compromise`. Security-revoked keys are rejected even for signatures predating revocation. Other reasons retain the normal validity and revocation-time checks; configure any custom security reasons used by your federation.

`compareTrustAnchorKeys(ecJwks, independentJwks, entityId)` compares identifiers and public-key thumbprints for [§11.3](https://openid.net/specs/openid-federation-1_0.html#section-11.3). Both sets must be nonempty and contain public keys with distinct, nonempty identifiers. Invalid or uncomparable sets produce `match: false` with `inputErrors` identifying the affected source and reason. Valid sets retain the missing-key and mismatched-material diagnostics. An unsupported key type makes the comparison inconclusive; ordinary verification keeps its separate key-selection rules.

### Replay protection (`ReplayStore`)

`verifyClientAssertion()` requires `exp` and a non-empty `jti`; `iat` is optional. It checks the signature, issuer/subject equality, exact audience, expiry, and any supplied issuance time. Pass `replayStore` to atomically claim a verified assertion. Expiry is checked again after replay storage completes. Without it, the function verifies the JWT without recording its use. Authentication handlers must provide replay storage. These claims follow [OIDC Core §9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication), referenced by [Federation §8.8](https://openid.net/specs/openid-federation-1_0.html#section-8.8).

A `ReplayStore` claims an `(issuer, audience, jti)` tuple until expiry. Claims must be atomic across the processes serving one tenant. The in-memory implementation is for development and tests.

`MemoryReplayStore` retains the full SHA-256 digest of the JSON tuple `[issuer, audience, jti]`. Stored keys have a fixed size even when valid identifiers are long. Claims that expire during hashing are rejected. It retains the existing entry-count limit and expires records through the accepted validity window.

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
    statusEndpoint, rawTrustMarkJwt, issuerJwks, {
      expectedIssuer: validation.value.issuer,
      httpClient: fetch,
    },
  );
  console.log("Trust Mark Status:", status);
}
```

`validateTrustMark()` requires `expectedSubject`, the entity whose configuration contains the mark ([§7.3](https://openid.net/specs/openid-federation-1_0.html#section-7.3)). Establish trust in the issuer and its keys before calling it.

`fetchTrustMarkStatus()` binds the signed response to `expectedIssuer` and the exact submitted JWT. It applies the shared URL, cancellation, timeout, and response-size limits and rejects redirects. Direct `verifyTrustMarkStatusResponse()` calls require `expectedIssuer` and `expectedTrustMark`. Additional status strings are preserved under [§8.4.2](https://openid.net/specs/openid-federation-1_0.html#section-8.4.2); only `active` denotes an active mark. Response `iat` accepts finite NumericDates.

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

Composed hosts and Entity Statement builders check supplied OP/AS `issuer` values against the statement subject and prohibit `jwks`, `jwks_uri`, and `signed_jwks_uri` inside `federation_entity` metadata ([Federation §§5.1.3–5.2.1](https://openid.net/specs/openid-federation-1_0.html#section-5.1.3)). These checks allow partial metadata for superiors to complete. Federation Entity Keys belong in the statement’s top-level `jwks`.

Entity Identifiers reject query and fragment delimiters, including empty trailing `?` and `#`, under [Federation §1.2](https://openid.net/specs/openid-federation-1_0.html#section-1.2). Percent-encoded characters remain part of the identifier. Key URL helpers also enforce their fragment-free URL contract, including an empty `#`; that URL policy is separate from the Entity Identifier rules.

`EntityRole.validateMetadata(metadata, context)` is an optional synchronous hook. Hosts invoke it on detached composed role metadata before publication. Existing roles can omit it.

`findInvalidMetadataNullPaths(metadata)` returns the paths of forbidden null values. Statement builders, chain validation, and authority publication share this check. It rejects null entity-type blocks and direct metadata parameter values, following Federation §5. Nested objects and arrays may contain null; protocol-specific schemas, including wallet claim-path syntax, can impose additional restrictions.

### Remote protocol errors

Federation clients preserve recognized error codes. An unfamiliar syntactically valid OAuth error produces `ERR_REMOTE_RESPONSE`, with the responder's explanation in `description` and its code and HTTP status in `remoteError`. Treat those fields as remote input. Server-side public-error conversion maps this internal classification to a generic server error. [Entity Collection §3.4.2](https://openid.net/specs/openid-federation-entity-collection-1_0-01.html#section-3.4.2) permits OAuth registry errors beyond the draft's named codes.
