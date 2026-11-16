# Discovery, chain validation, and assessments

[`@oidfed/core`](README.md)

Discovery obtains candidate evidence. Validation checks a chain against configured anchors and applies constraints and policy. An assessment can use local validation or an explicitly trusted resolver; the selected mode determines the trust boundary.

## `assessEntity`

[Source](../../../packages/core/src/trust-chain/assessment.ts#L292)

Assess a subject using local chain validation or an explicitly authorized resolver. The returned kind records which trust boundary was used; resolver-reported metadata is not relabeled as a locally validated chain.

```typescript signature
assessEntity(subject: EntityId, anchors: TrustAnchorSet, options?: EntityAssessmentOptions): Promise<Result<EntityAssessment>>;
```

## `calculateChainExpiration`

[Source](../../../packages/core/src/trust-chain/validate.ts#L60)

Calculate the earliest expiration across all statements in a chain.

```typescript signature
calculateChainExpiration(chain: readonly ParsedEntityStatement[]): number;
```

## `chainRemainingTtl`

[Source](../../../packages/core/src/trust-chain/validate.ts#L1719)

Get remaining TTL in seconds, returning 0 if expired.

```typescript signature
chainRemainingTtl(chain: ValidatedTrustChain, clock?: Clock): number;
```

### Usage example

Use these helpers for a status display or refresh schedule after chain validation. The earliest statement expiration is a chain bound; accreditation or other operation evidence can impose a shorter usable lifetime.

```ts
import {
  calculateChainExpiration, chainRemainingTtl, describeTrustChain, isChainExpired,
  type Clock, type ValidatedTrustChain,
} from "@oidfed/core";

export function evidenceSummary(chain: ValidatedTrustChain, clock: Clock) {
  return {
    path: describeTrustChain(chain),
    statementDeadline: calculateChainExpiration(chain.statements),
    remainingSeconds: chainRemainingTtl(chain, clock),
    needsRefresh: isChainExpired(chain, clock),
  };
}
```

## `compareTrustAnchorKeys`

[Source](../../../packages/core/src/trust-chain/anchor-keys.ts#L24)

Compare Trust Anchor public keys retrieved from the Entity Configuration
against keys retrieved via an independent mechanism.

```typescript signature
compareTrustAnchorKeys(ecJwks: Pick<JWKSet, "keys">, independentJwks: Pick<JWKSet, "keys">, entityId: EntityId): Promise<TrustAnchorKeyComparisonResult>;
```

## `completeTrustChainValidation`

[Source](../../../packages/core/src/trust-chain/validate.ts#L686)

Complete the original prepared evidence with permitted contextual inputs. Context cannot replace published metadata, only fill the explicitly pending absent values. Completion rejects copied or fabricated prepared objects, rechecks evidence lifetime and constraints, and returns a completed validated chain or a failing Result.

```typescript signature
completeTrustChainValidation(prepared: PreparedTrustChain, context?: Readonly<Record<string, Record<string, unknown>>>): Promise<Result<ValidatedTrustChain>>;
```

## `ContextualMetadataClaim`

[Source](../../../packages/core/src/trust-chain/validate.ts#L474)

A metadata claim whose final validation depends on protocol context supplied later.

```typescript signature
interface ContextualMetadataClaim {
	readonly entityType: string;
	readonly parameter: string;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entityType` | `string` | Entity Type Identifier used to select a metadata block or filter entries. |
| `parameter` | `string` | Metadata parameter whose value needs contextual validation. |

## `createConcurrencyLimiter`

[Source](../../../packages/core/src/trust-chain/resolve.ts#L25)

Create a concurrency limiter that allows at most `maxConcurrent` parallel executions.

```typescript signature
createConcurrencyLimiter(maxConcurrent: number, signal?: AbortSignal): <T>(fn: () => Promise<T>) => Promise<T>;
```

## `createTrustChainOperation`

[Source](../../../packages/core/src/trust-chain/operation.ts#L6)

Create operation options that share one HTTP-call allowance across discovery, issuer resolution, and candidate validation. Cache hits and supplied statements consume no allowance. The default is 50 calls; zero permits cache/supplied-evidence use. The allowance must be a nonnegative safe integer. `exhausted()` reports an exceeded allowance or caller cancellation, not merely whether the last permitted call used it up.

```typescript signature
createTrustChainOperation(options?: FederationOptions): Result<{
	options: FederationOptions;
	exhausted: () => boolean;
}>;
```

## `describeTrustChain`

[Source](../../../packages/core/src/trust-chain/validate.ts#L1725)

Human-readable chain description: hostnames joined with arrows.

```typescript signature
describeTrustChain(chain: ValidatedTrustChain): string;
```

## `discoverEntity`

[Source](../../../packages/core/src/trust-chain/discovery.ts#L23)

Discover and validate candidate chains for the target, then select with `options.chainSelection`, or `shortestChain` when no selector is supplied. Discovery and candidate validation share one fetch allowance. Exhaustion, or incomplete discovery with a custom selector, returns an error rather than selecting from an incomplete set. Refresh the assessment when its evidence expires.

```typescript signature
discoverEntity(entityId: EntityId, trustAnchors: TrustAnchorSet, options?: FederationOptions): Promise<Result<DiscoveryResult>>;
```

## `discoverEntityFromChain`

[Source](../../../packages/core/src/trust-chain/discovery.ts#L90)

Validate supplied statements before exposing them to protocol operations.

```typescript signature
discoverEntityFromChain(entityId: EntityId, statements: readonly string[], trustAnchors: TrustAnchorSet, options?: FederationOptions): Promise<Result<DiscoveryResult>>;
```

## `EntityAssessment`

[Source](../../../packages/core/src/trust-chain/assessment.ts#L54)

The result of assessing an entity through a locally validated chain or a trusted resolver.

```typescript signature
type EntityAssessment = {
	readonly kind: "local";
	readonly entityId: EntityId;
	readonly expiresAt: number;
	readonly discovery: DiscoveryResult;
	readonly resolvedMetadata: DiscoveryResult["resolvedMetadata"];
} | {
	readonly kind: "resolver";
	readonly entityId: EntityId;
	readonly resolver: EntityId;
	readonly trustAnchorId: EntityId;
	readonly expiresAt: number;
	readonly responseJwt: string;
	readonly statements: readonly string[];
	readonly resolvedMetadata: ResolveResponsePayload["metadata"];
	readonly reportedTrustMarks: NonNullable<ResolveResponsePayload["trust_marks"]>;
};
```

## `EntityAssessmentOptions`

[Source](../../../packages/core/src/trust-chain/assessment.ts#L48)

The trust-resolution mode and inputs used to assess an entity.

```typescript signature
interface EntityAssessmentOptions extends FederationOptions {
	/** Delegation is explicit. The default locally validates the subject chain. */
	mode?: "local" | "resolver";
	/** Explicit subject evidence for local assessment, including offline use. */
	trustChain?: readonly string[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `mode?` | `"local" \| "resolver"` | Discriminator selecting the configured policy or acquisition behavior. |
| `trustChain?` | `readonly string[]` | Supplied or validated Trust Chain, in the representation declared by this contract. |
| `trustResolution?` | `import("./trust-chain/assessment.js").TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Independently supplied issuer keys for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
| `offline?` | `boolean` | Disallow network access when only supplied evidence is permitted. |
| `httpClient?` | `HttpClient` | Host HTTP transport; defaults to the runtime's fetch implementation. |
| `entityConfigurations?` | `ReadonlyMap<string, string> \| undefined` | Subject Entity Configuration JWTs used during chain validation; signatures and identity bindings still need validation. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `cache?` | `CacheProvider` | Host cache for signed statements or operation results; cache hits do not establish trust. |
| `logger?` | `Logger` | Optional host logger. Library calls are message-only, nonblocking, and protected from sink failures. |
| `httpTimeoutMs?` | `number` | Timeout in milliseconds for bounded transport or host callbacks; defaults to 10000. |
| `clockSkewSeconds?` | `number` | Allowed time-claim leeway in seconds; the default verifier allowance is 60 seconds. |
| `maxChainDepth?` | `number` | Maximum recursive discovery depth; defaults to 8. |
| `maxChainLength?` | `number` | Maximum statements in a validated chain, including both ECs. Default: 100; resource policy, not a protocol limit. |
| `maxResolutionSteps?` | `number` | Maximum eligible branch expansions per resolution, including reused statements. Default: 1000. |
| `maxAuthorityHints?` | `number` | Maximum authority hints examined for an entity; defaults to 10. |
| `maxConcurrentFetches?` | `number` | Maximum concurrent fetches during chain traversal and collection refresh; defaults to 6. |
| `cacheMaxTtlSeconds?` | `number` | Fetched EC and Subordinate Statement cache retention cap in seconds; defaults to 3600 and is bounded by the statement's `exp`. Applies to statement fetchers using a cache. |
| `signal?` | `AbortSignal` | Cancellation signal for the waiting caller and cooperative work started by this operation. |
| `maxResponseBytes?` | `number` | Maximum response or decoded token size in bytes for APIs applying this limit; the shared default is 524288. |
| `blockedCIDRs?` | `string[]` | Additional blocked IP ranges applied by URL fetch validation. |
| `allowedHosts?` | `string[]` | Optional exact hostname allowlist applied before outbound fetching. |
| `authorityHintFilter?` | `(hint: URL, subject: EntityId) => boolean` | Host predicate for accepting an authority hint before traversal. |
| `understoodCriticalClaims?` | `ReadonlySet<string>` | Extension claim names the application actually understands and processes; unknown critical claims are rejected. |
| `maxTotalFetches?` | `number` | Maximum HTTP client calls; discovery helpers share the allowance across discovery and candidate validation. Cached and supplied statements use no allowance. Core accepts zero. Default: 50. |
| `customPolicyOperators?` | `readonly PolicyOperatorDefinition[]` | Federation-defined policy operators in addition to the seven standard ones. Forwarded to `resolveMetadataPolicy` and `applyMetadataPolicy` during trust-chain validation. |
| `customConstraintChecks?` | `readonly ConstraintCheckDefinition[]` | Federation-defined constraints checked against authenticated chains. Unknown names are ignored. |

## `FederationResolverConfig`

[Source](../../../packages/core/src/resolver/service.ts#L50)

Identity, signing, trust, caching, and authentication settings for a hosted Resolve service.

```typescript signature
interface FederationResolverConfig {
	readonly entityId: EntityId | string;
	readonly keyProvider: FederationKeyProvider;
	readonly trustAnchors?: TrustAnchorSet;
	readonly cache?: CacheProvider;
	readonly options?: FederationOptions;
	readonly requireAuthForFreshResolution?: boolean;
	readonly authentication?: Omit<EndpointAuthenticationConfig, "receiverEntityId">;
	readonly assessLocalTrustMarkStatus?: (
		jwt: string,
	) => Promise<TrustMarkStatusAssessment | undefined>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entityId` | `EntityId \| string` | Exact Entity Identifier bound to this object or operation. |
| `keyProvider` | `FederationKeyProvider` | Provider of current Federation Entity Keys and the active signer. |
| `trustAnchors?` | `TrustAnchorSet` | Independently trusted anchor identities and their public Federation Entity Keys. |
| `cache?` | `CacheProvider` | Host cache for signed statements or operation results; cache hits do not establish trust. |
| `options?` | `FederationOptions` | Shared federation transport and validation settings for this operation. |
| `requireAuthForFreshResolution?` | `boolean` | Require authenticated HTTP access for live discovery; true by default. Local calls can populate the cache. |
| `authentication?` | `Omit<EndpointAuthenticationConfig, "receiverEntityId">` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `assessLocalTrustMarkStatus?` | `( jwt: string, ) => Promise<TrustMarkStatusAssessment \| undefined>` | Read authoritative local status and its evidence deadline when the resolver encounters a locally issued mark. |

## `FederationResolverIntegration`

[Source](../../../packages/core/src/resolver/service.ts#L62)

Configuration for composing a Resolve service into an entity host.

```typescript signature
type FederationResolverIntegration = Omit<
	FederationResolverConfig,
	"entityId" | "keyProvider"
>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `options?` | `FederationOptions` | Shared federation transport and validation settings for this operation. |
| `authentication?` | `Omit<EndpointAuthenticationConfig, "receiverEntityId">` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `cache?` | `CacheProvider` | Host cache for signed statements or operation results; cache hits do not establish trust. |
| `trustAnchors?` | `TrustAnchorSet` | Independently trusted anchor identities and their public Federation Entity Keys. |
| `requireAuthForFreshResolution?` | `boolean` | Require authenticated HTTP access for live discovery; true by default. Local calls can populate the cache. |
| `assessLocalTrustMarkStatus?` | `( jwt: string, ) => Promise<TrustMarkStatusAssessment \| undefined>` | Read authoritative local status and its evidence deadline when the resolver encounters a locally issued mark. |

## `FederationResolverService`

[Source](../../../packages/core/src/resolver/service.ts#L69)

Resolve hosting independent of subordinate storage and Authority endpoints.

```typescript signature
new FederationResolverService(config: FederationResolverConfig): FederationResolverService;
```

### `FederationResolverService#handleRequest`

Handle a Web API Request and return the protocol Response. The application supplies external HTTPS routing.

[Source](../../../packages/core/src/resolver/service.ts#L89)

```typescript signature
handleRequest(request: Request): Promise<Response>;
```

### `FederationResolverService#resolve`

In-process callers may populate the cache without endpoint authentication.

[Source](../../../packages/core/src/resolver/service.ts#L93)

```typescript signature
resolve(request: Request, options?: FederationOptions): Promise<Response>;
```

### `FederationResolverService#handleAuthenticatedRequest`

For hosts which have already applied the shared authentication wrapper.

[Source](../../../packages/core/src/resolver/service.ts#L103)

```typescript signature
handleAuthenticatedRequest(request: Request): Promise<Response>;
```

## `fetchEntityConfiguration`

[Source](../../../packages/core/src/trust-chain/fetch.ts#L507)

Retrieve the target's compact Entity Configuration JWT using well-known HTTPS GET discovery, without a Federation client assertion. Network responses require HTTP 200; cached statements are reused only while their cache lifetime remains positive. This fetch does not authenticate the returned statement. Cache adapter failures can reject the promise rather than return a protocol Result.

```typescript signature
fetchEntityConfiguration(entityId: EntityId, options?: FederationOptions): Promise<Result<string, FederationError>>;
```

## `fetchSubordinateStatement`

[Source](../../../packages/core/src/trust-chain/fetch.ts#L565)

Retrieve a compact Subordinate Statement JWT about the subject, using anonymous GET or configured authenticated POST. Network responses require HTTP 200; signature, subject, and chain checks remain the caller's responsibility. When the issuer identity is known, pass `options.issuer` for cache isolation and the independent authentication-audience check. Cache adapter failures can reject the promise.

```typescript signature
fetchSubordinateStatement(fetchEndpoint: string, subject: EntityId, options?: FetchSubordinateStatementOptions): Promise<Result<string, FederationError>>;
```

## `FetchSubordinateStatementOptions`

[Source](../../../packages/core/src/trust-chain/fetch.ts#L559)

Transport, authentication, and caching settings for fetching a Subordinate Statement.

```typescript signature
interface FetchSubordinateStatementOptions extends FederationOptions {
	/** Actual issuer identifier for isolating cached attestations when it is known. */
	issuer?: EntityId;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuer?` | `EntityId` | Issuer identity for the signed artifact or configured service. |
| `trustResolution?` | `import("./trust-chain/assessment.js").TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Independently supplied issuer keys for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
| `offline?` | `boolean` | Disallow network access when only supplied evidence is permitted. |
| `httpClient?` | `HttpClient` | Host HTTP transport; defaults to the runtime's fetch implementation. |
| `entityConfigurations?` | `ReadonlyMap<string, string> \| undefined` | Subject Entity Configuration JWTs used during chain validation; signatures and identity bindings still need validation. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `cache?` | `CacheProvider` | Host cache for signed statements or operation results; cache hits do not establish trust. |
| `logger?` | `Logger` | Optional host logger. Library calls are message-only, nonblocking, and protected from sink failures. |
| `httpTimeoutMs?` | `number` | Timeout in milliseconds for bounded transport or host callbacks; defaults to 10000. |
| `clockSkewSeconds?` | `number` | Allowed time-claim leeway in seconds; the default verifier allowance is 60 seconds. |
| `maxChainDepth?` | `number` | Maximum recursive discovery depth; defaults to 8. |
| `maxChainLength?` | `number` | Maximum statements in a validated chain, including both ECs. Default: 100; resource policy, not a protocol limit. |
| `maxResolutionSteps?` | `number` | Maximum eligible branch expansions per resolution, including reused statements. Default: 1000. |
| `maxAuthorityHints?` | `number` | Maximum authority hints examined for an entity; defaults to 10. |
| `maxConcurrentFetches?` | `number` | Maximum concurrent fetches during chain traversal and collection refresh; defaults to 6. |
| `cacheMaxTtlSeconds?` | `number` | Fetched EC and Subordinate Statement cache retention cap in seconds; defaults to 3600 and is bounded by the statement's `exp`. Applies to statement fetchers using a cache. |
| `signal?` | `AbortSignal` | Cancellation signal for the waiting caller and cooperative work started by this operation. |
| `maxResponseBytes?` | `number` | Maximum response or decoded token size in bytes for APIs applying this limit; the shared default is 524288. |
| `blockedCIDRs?` | `string[]` | Additional blocked IP ranges applied by URL fetch validation. |
| `allowedHosts?` | `string[]` | Optional exact hostname allowlist applied before outbound fetching. |
| `authorityHintFilter?` | `(hint: URL, subject: EntityId) => boolean` | Host predicate for accepting an authority hint before traversal. |
| `understoodCriticalClaims?` | `ReadonlySet<string>` | Extension claim names the application actually understands and processes; unknown critical claims are rejected. |
| `maxTotalFetches?` | `number` | Maximum HTTP client calls; discovery helpers share the allowance across discovery and candidate validation. Cached and supplied statements use no allowance. Core accepts zero. Default: 50. |
| `customPolicyOperators?` | `readonly PolicyOperatorDefinition[]` | Federation-defined policy operators in addition to the seven standard ones. Forwarded to `resolveMetadataPolicy` and `applyMetadataPolicy` during trust-chain validation. |
| `customConstraintChecks?` | `readonly ConstraintCheckDefinition[]` | Federation-defined constraints checked against authenticated chains. Unknown names are ignored. |

## `isChainExpired`

[Source](../../../packages/core/src/trust-chain/validate.ts#L1713)

Check if a validated trust chain has expired.

```typescript signature
isChainExpired(chain: ValidatedTrustChain, clock?: Clock): boolean;
```

## `isEntityAssessment`

[Source](../../../packages/core/src/trust-chain/assessment.ts#L75)

Recognize an assessment created by this library instance. Copying or deserializing the object's fields does not retain its provenance.

```typescript signature
isEntityAssessment(value: unknown): value is EntityAssessment;
```

## `longestExpiry`

[Source](../../../packages/core/src/trust-chain/validate.ts#L1747)

Select the chain that expires last.

```typescript signature
const longestExpiry: ChainSelectionStrategy;
```

## `preferTrustAnchor`

[Source](../../../packages/core/src/trust-chain/validate.ts#L1754)

Create a strategy that prefers chains terminating at the given trust anchor.

```typescript signature
preferTrustAnchor(taId: string): ChainSelectionStrategy;
```

## `PreparedTrustChain`

[Source](../../../packages/core/src/trust-chain/validate.ts#L488)

Authenticated chain evidence with explicitly unfinished metadata policy checks.

```typescript signature
interface PreparedTrustChain {
	readonly [preparedBrand]: true;
	readonly entityId: EntityId;
	readonly trustAnchorId: EntityId;
	readonly expiresAt: number;
	readonly resolvedMetadata: Readonly<Record<string, Record<string, unknown>>>;
	readonly statements: ReadonlyArray<ParsedEntityStatement>;
	readonly pendingClaims: readonly ContextualMetadataClaim[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entityId` | `EntityId` | Exact Entity Identifier bound to this object or operation. |
| `trustAnchorId` | `EntityId` | Trust Anchor at which the chain or evidence terminates. |
| `expiresAt` | `number` | Expiration or eligibility deadline as a NumericDate in seconds; the owning API defines the evidence it bounds. |
| `resolvedMetadata` | `Readonly<Record<string, Record<string, unknown>>>` | Metadata produced after superior overrides, constraints, and policy application. |
| `statements` | `ReadonlyArray<ParsedEntityStatement>` | Leaf-first statements. The owning contract specifies compact JWTs or parsed statements. |
| `pendingClaims` | `readonly ContextualMetadataClaim[]` | Declared absent metadata parameters awaiting protocol context before completion. |
| `[preparedBrand]` | `true` | Opaque type brand supplied by preparation. Completion also checks process-local evidence provenance. |

## `PrepareTrustChainOptions`

[Source](../../../packages/core/src/trust-chain/validate.ts#L479)

Inputs for validating a chain while deferring metadata checks that need additional context.

```typescript signature
interface PrepareTrustChainOptions
	extends Omit<TrustChainValidationOptions, "explicitRegistrationRequest"> {
	/** Only policies for absent values in these fields may remain pending. */
	readonly deferredClaims: readonly ContextualMetadataClaim[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `deferredClaims` | `readonly ContextualMetadataClaim[]` | Only policies for absent values in these fields may remain pending. |
| `signal?` | `AbortSignal` | Cancellation signal for the waiting caller and cooperative work started by this operation. |
| `httpTimeoutMs?` | `number` | Timeout in milliseconds for bounded transport or host callbacks; defaults to 10000. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `trustResolution?` | `import("./trust-chain/assessment.js").TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Independently supplied issuer keys for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
| `offline?` | `boolean` | Disallow network access when only supplied evidence is permitted. |
| `httpClient?` | `HttpClient` | Host HTTP transport; defaults to the runtime's fetch implementation. |
| `entityConfigurations?` | `ReadonlyMap<string, string> \| undefined` | Subject Entity Configuration JWTs used during chain validation; signatures and identity bindings still need validation. |
| `cache?` | `CacheProvider` | Host cache for signed statements or operation results; cache hits do not establish trust. |
| `logger?` | `Logger` | Optional host logger. Library calls are message-only, nonblocking, and protected from sink failures. |
| `clockSkewSeconds?` | `number` | Allowed time-claim leeway in seconds; the default verifier allowance is 60 seconds. |
| `maxChainDepth?` | `number` | Maximum recursive discovery depth; defaults to 8. |
| `maxChainLength?` | `number` | Maximum statements in a validated chain, including both ECs. Default: 100; resource policy, not a protocol limit. |
| `maxResolutionSteps?` | `number` | Maximum eligible branch expansions per resolution, including reused statements. Default: 1000. |
| `maxAuthorityHints?` | `number` | Maximum authority hints examined for an entity; defaults to 10. |
| `maxConcurrentFetches?` | `number` | Maximum concurrent fetches during chain traversal and collection refresh; defaults to 6. |
| `cacheMaxTtlSeconds?` | `number` | Fetched EC and Subordinate Statement cache retention cap in seconds; defaults to 3600 and is bounded by the statement's `exp`. Applies to statement fetchers using a cache. |
| `maxResponseBytes?` | `number` | Maximum response or decoded token size in bytes for APIs applying this limit; the shared default is 524288. |
| `blockedCIDRs?` | `string[]` | Additional blocked IP ranges applied by URL fetch validation. |
| `allowedHosts?` | `string[]` | Optional exact hostname allowlist applied before outbound fetching. |
| `authorityHintFilter?` | `(hint: URL, subject: EntityId) => boolean` | Host predicate for accepting an authority hint before traversal. |
| `understoodCriticalClaims?` | `ReadonlySet<string>` | Extension claim names the application actually understands and processes; unknown critical claims are rejected. |
| `maxTotalFetches?` | `number` | Maximum HTTP client calls; discovery helpers share the allowance across discovery and candidate validation. Cached and supplied statements use no allowance. Core accepts zero. Default: 50. |
| `customPolicyOperators?` | `readonly PolicyOperatorDefinition[]` | Federation-defined policy operators in addition to the seven standard ones. Forwarded to `resolveMetadataPolicy` and `applyMetadataPolicy` during trust-chain validation. |
| `customConstraintChecks?` | `readonly ConstraintCheckDefinition[]` | Federation-defined constraints checked against authenticated chains. Unknown names are ignored. |
| `verboseErrors?` | `boolean` | Retained option for caller compatibility; current trust-chain validation does not branch on it. |
| `explicitRegistrationAudience?` | `EntityId \| string` | Expected OP Entity Identifier when authenticating an Explicit Registration request's supplied EC. |

## `prepareTrustChainValidation`

[Source](../../../packages/core/src/trust-chain/validate.ts#L600)

Authenticate chain evidence and resolve policy while allowing explicitly named, absent context-dependent metadata inputs to remain pending. The result carries process-local provenance for completion and is not a fully completed discovery result. Use `completeTrustChainValidation` with that original prepared object before accepting its final effective metadata.

```typescript signature
prepareTrustChainValidation(chain: readonly string[], anchors: TrustAnchorSet, options: PrepareTrustChainOptions): Promise<Result<PreparedTrustChain>>;
```

## `RefreshOptions`

[Source](../../../packages/core/src/trust-chain/refresh.ts#L18)

Controls for refreshing a previously validated trust chain.

```typescript signature
interface RefreshOptions extends FederationOptions {
	/** Retrieve fresh ECs and Subordinate Statements, bypassing pre-existing statement cache entries. */
	forceRefresh?: boolean;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `forceRefresh?` | `boolean` | Retrieve fresh ECs and Subordinate Statements, bypassing pre-existing statement cache entries. |
| `trustResolution?` | `import("./trust-chain/assessment.js").TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Independently supplied issuer keys for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
| `offline?` | `boolean` | Disallow network access when only supplied evidence is permitted. |
| `httpClient?` | `HttpClient` | Host HTTP transport; defaults to the runtime's fetch implementation. |
| `entityConfigurations?` | `ReadonlyMap<string, string> \| undefined` | Subject Entity Configuration JWTs used during chain validation; signatures and identity bindings still need validation. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `cache?` | `CacheProvider` | Host cache for signed statements or operation results; cache hits do not establish trust. |
| `logger?` | `Logger` | Optional host logger. Library calls are message-only, nonblocking, and protected from sink failures. |
| `httpTimeoutMs?` | `number` | Timeout in milliseconds for bounded transport or host callbacks; defaults to 10000. |
| `clockSkewSeconds?` | `number` | Allowed time-claim leeway in seconds; the default verifier allowance is 60 seconds. |
| `maxChainDepth?` | `number` | Maximum recursive discovery depth; defaults to 8. |
| `maxChainLength?` | `number` | Maximum statements in a validated chain, including both ECs. Default: 100; resource policy, not a protocol limit. |
| `maxResolutionSteps?` | `number` | Maximum eligible branch expansions per resolution, including reused statements. Default: 1000. |
| `maxAuthorityHints?` | `number` | Maximum authority hints examined for an entity; defaults to 10. |
| `maxConcurrentFetches?` | `number` | Maximum concurrent fetches during chain traversal and collection refresh; defaults to 6. |
| `cacheMaxTtlSeconds?` | `number` | Fetched EC and Subordinate Statement cache retention cap in seconds; defaults to 3600 and is bounded by the statement's `exp`. Applies to statement fetchers using a cache. |
| `signal?` | `AbortSignal` | Cancellation signal for the waiting caller and cooperative work started by this operation. |
| `maxResponseBytes?` | `number` | Maximum response or decoded token size in bytes for APIs applying this limit; the shared default is 524288. |
| `blockedCIDRs?` | `string[]` | Additional blocked IP ranges applied by URL fetch validation. |
| `allowedHosts?` | `string[]` | Optional exact hostname allowlist applied before outbound fetching. |
| `authorityHintFilter?` | `(hint: URL, subject: EntityId) => boolean` | Host predicate for accepting an authority hint before traversal. |
| `understoodCriticalClaims?` | `ReadonlySet<string>` | Extension claim names the application actually understands and processes; unknown critical claims are rejected. |
| `maxTotalFetches?` | `number` | Maximum HTTP client calls; discovery helpers share the allowance across discovery and candidate validation. Cached and supplied statements use no allowance. Core accepts zero. Default: 50. |
| `customPolicyOperators?` | `readonly PolicyOperatorDefinition[]` | Federation-defined policy operators in addition to the seven standard ones. Forwarded to `resolveMetadataPolicy` and `applyMetadataPolicy` during trust-chain validation. |
| `customConstraintChecks?` | `readonly ConstraintCheckDefinition[]` | Federation-defined constraints checked against authenticated chains. Unknown names are ignored. |

## `refreshTrustChain`

[Source](../../../packages/core/src/trust-chain/refresh.ts#L49)

Refreshes a trust chain if it has expired (or if forceRefresh is set).
Participants must support refreshing expired trust chains.
The explicit clock argument takes precedence over options.clock throughout the operation.
Forced refresh bypasses existing statement cache entries, writes fetched statements back,
and never falls back to the previous chain on failure. Transport/upstream caches remain host-owned.

```typescript signature
refreshTrustChain(chain: ValidatedTrustChain, trustAnchors: TrustAnchorSet, options?: RefreshOptions, clock?: Clock): Promise<Result<ValidatedTrustChain>>;
```

## `resolveTrustChainForAnchor`

[Source](../../../packages/core/src/trust-chain/peer.ts#L18)

Build a Trust Chain for `subject` that ends at the given `trustAnchorId`.

Returns the array of Entity Statement JWTs ready to attach as a
`trust_chain` or `peer_trust_chain` JWS header value, or an error if no
valid chain to that anchor exists from this resolver's vantage point.

```typescript signature
resolveTrustChainForAnchor(subject: EntityId, trustAnchorId: EntityId, trustAnchors: TrustAnchorSet, options?: FederationOptions): Promise<Result<readonly string[], FederationError>>;
```

## `resolveTrustChains`

[Source](../../../packages/core/src/trust-chain/resolve.ts#L74)

Discover candidate compact-JWT chains ending at the configured anchors, within the supplied traversal limits. Candidates are not fully validated chains. Inspect both `errors` and `incomplete`: hitting a limit or cancellation can leave a partial set. Pass each candidate's `entityConfigurations` into validation to reuse retrieved subject ECs.

```typescript signature
resolveTrustChains(entityId: EntityId, trustAnchors: TrustAnchorSet, options?: ResolveTrustChainsOptions): Promise<TrustChainResult>;
```

## `ResolveTrustChainsOptions`

[Source](../../../packages/core/src/trust-chain/resolve.ts#L66)

Inputs and limits for discovering candidate trust chains.

```typescript signature
interface ResolveTrustChainsOptions extends FederationOptions {
	/** Start with this signed EC; its hints are traversed without fetching or caching a replacement. */
	readonly entityConfigurationJwt?: string;
	/** Expected OP audience for a supplied explicit-registration request. */
	readonly explicitRegistrationAudience?: EntityId;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entityConfigurationJwt?` | `string` | Start with this signed EC; its hints are traversed without fetching or caching a replacement. |
| `explicitRegistrationAudience?` | `EntityId` | Expected OP Entity Identifier when authenticating an Explicit Registration request's supplied EC. |
| `trustResolution?` | `import("./trust-chain/assessment.js").TrustResolutionSource` | Acquisition source; protocol consumers still validate the returned subject chain. |
| `chainSelection?` | `ChainSelectionStrategy` | Select among validated candidates eligible for the current operation. |
| `authentication?` | `EndpointClientAuthentication` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `getEndpointAuthentication?` | `EndpointAuthenticationProvider` | Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. |
| `additionalParameters?` | `EndpointAdditionalParameters` | Extension selectors for outgoing requests; reserved names and conflicting fixed selectors are rejected. |
| `trustMarkVerification?` | `TrustMarkVerificationOptions` | Issuer-evidence and accreditation-resolution options for evaluating published Trust Marks. |
| `trustMarkIssuerKeys?` | `ReadonlyMap<string, JWKSet>` | Independently supplied issuer keys for evaluating published Trust Marks. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
| `offline?` | `boolean` | Disallow network access when only supplied evidence is permitted. |
| `httpClient?` | `HttpClient` | Host HTTP transport; defaults to the runtime's fetch implementation. |
| `entityConfigurations?` | `ReadonlyMap<string, string> \| undefined` | Subject Entity Configuration JWTs used during chain validation; signatures and identity bindings still need validation. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `cache?` | `CacheProvider` | Host cache for signed statements or operation results; cache hits do not establish trust. |
| `logger?` | `Logger` | Optional host logger. Library calls are message-only, nonblocking, and protected from sink failures. |
| `httpTimeoutMs?` | `number` | Timeout in milliseconds for bounded transport or host callbacks; defaults to 10000. |
| `clockSkewSeconds?` | `number` | Allowed time-claim leeway in seconds; the default verifier allowance is 60 seconds. |
| `maxChainDepth?` | `number` | Maximum recursive discovery depth; defaults to 8. |
| `maxChainLength?` | `number` | Maximum statements in a validated chain, including both ECs. Default: 100; resource policy, not a protocol limit. |
| `maxResolutionSteps?` | `number` | Maximum eligible branch expansions per resolution, including reused statements. Default: 1000. |
| `maxAuthorityHints?` | `number` | Maximum authority hints examined for an entity; defaults to 10. |
| `maxConcurrentFetches?` | `number` | Maximum concurrent fetches during chain traversal and collection refresh; defaults to 6. |
| `cacheMaxTtlSeconds?` | `number` | Fetched EC and Subordinate Statement cache retention cap in seconds; defaults to 3600 and is bounded by the statement's `exp`. Applies to statement fetchers using a cache. |
| `signal?` | `AbortSignal` | Cancellation signal for the waiting caller and cooperative work started by this operation. |
| `maxResponseBytes?` | `number` | Maximum response or decoded token size in bytes for APIs applying this limit; the shared default is 524288. |
| `blockedCIDRs?` | `string[]` | Additional blocked IP ranges applied by URL fetch validation. |
| `allowedHosts?` | `string[]` | Optional exact hostname allowlist applied before outbound fetching. |
| `authorityHintFilter?` | `(hint: URL, subject: EntityId) => boolean` | Host predicate for accepting an authority hint before traversal. |
| `understoodCriticalClaims?` | `ReadonlySet<string>` | Extension claim names the application actually understands and processes; unknown critical claims are rejected. |
| `maxTotalFetches?` | `number` | Maximum HTTP client calls; discovery helpers share the allowance across discovery and candidate validation. Cached and supplied statements use no allowance. Core accepts zero. Default: 50. |
| `customPolicyOperators?` | `readonly PolicyOperatorDefinition[]` | Federation-defined policy operators in addition to the seven standard ones. Forwarded to `resolveMetadataPolicy` and `applyMetadataPolicy` during trust-chain validation. |
| `customConstraintChecks?` | `readonly ConstraintCheckDefinition[]` | Federation-defined constraints checked against authenticated chains. Unknown names are ignored. |

## `selectTrustChain`

[Source](../../../packages/core/src/trust-chain/selection.ts#L12)

Invoke the configured synchronous selector, or the supplied fallback, on detached frozen candidates. A selector must return one of those candidate objects; thrown errors, promises, and fabricated or copied selections are rejected. The callback cannot modify the frozen snapshots. The successful Result contains the corresponding original validated chain. Without a configured selector or fallback, the first candidate is used.

```typescript signature
selectTrustChain(chains: readonly ValidatedTrustChain[], options?: FederationOptions, fallback?: ChainSelectionStrategy): Result<ValidatedTrustChain>;
```

## `shortestChain`

[Source](../../../packages/core/src/trust-chain/validate.ts#L1738)

Select the chain with the fewest statements.

```typescript signature
const shortestChain: ChainSelectionStrategy;
```

## `TrustAnchorKeyComparisonResult`

[Source](../../../packages/core/src/trust-chain/anchor-keys.ts#L7)

Result of comparing Trust Anchor keys from two sources.

```typescript signature
interface TrustAnchorKeyComparisonResult {
	match: boolean;
	entityId: EntityId;
	missingInEntityConfiguration: string[];
	missingInIndependentSource: string[];
	mismatchedKeyMaterial: string[];
	/** Sources whose complete public key sets could not be compared. */
	inputErrors?: readonly {
		source: "entity_configuration" | "independent_source";
		reason: string;
	}[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `match` | `boolean` | Whether both sources contain the same public-key set. |
| `entityId` | `EntityId` | Exact Entity Identifier bound to this object or operation. |
| `missingInEntityConfiguration` | `string[]` | Key identifiers found only in the independent source. |
| `missingInIndependentSource` | `string[]` | Key identifiers found only in the Entity Configuration. |
| `mismatchedKeyMaterial` | `string[]` | Key identifiers present in both sources but bound to different public material. |
| `inputErrors?` | `readonly { source: "entity_configuration" \| "independent_source"; reason: string; }[]` | Sources whose complete public key sets could not be compared. |

## `TrustedResolverConfig`

[Source](../../../packages/core/src/trust-chain/assessment.ts#L35)

The resolver identity, verification policy, and trust configuration accepted by the host.

```typescript signature
interface TrustedResolverConfig {
	readonly entityId: EntityId | string;
	readonly endpoint: string;
	/** Explicit authorization of this resolver, separately from the subject's anchors. */
	readonly trust: {
		readonly kind: "pinned";
		readonly jwks: JWKSet;
	} | {
		readonly kind: "federation";
		readonly trustAnchors: TrustAnchorSet;
	};
	/** Recipient identity for custom endpoint authentication; private_key_jwt infers its clientId. */
	readonly requester?: EntityId | string;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entityId` | `EntityId \| string` | Exact Entity Identifier bound to this object or operation. |
| `endpoint` | `string` | Serving or remote endpoint URL; request extension contexts use status, list, or retrieval instead. |
| `trust` | `\| { readonly kind: "pinned"; readonly jwks: JWKSet } \| { readonly kind: "federation"; readonly trustAnchors: TrustAnchorSet }` | Explicit authorization of this resolver, separately from the subject's anchors. |
| `requester?` | `EntityId \| string` | Recipient identity for custom endpoint authentication; private_key_jwt infers its clientId. |

## `TrustResolutionSource`

[Source](../../../packages/core/src/trust-chain/assessment.ts#L45)

Identifies how an entity's trust assessment was obtained.

```typescript signature
type TrustResolutionSource = {
	readonly kind: "bottom-up";
} | {
	readonly kind: "resolver";
	readonly resolver: TrustedResolverConfig;
};
```

## `validateEntityId`

[Source](../../../packages/core/src/trust-chain/fetch.ts#L258)

Validate an Entity Identifier and return the result through the error model shown in the signature.

```typescript signature
validateEntityId(value: string): Result<EntityId, FederationError>;
```

## `validateFetchUrl`

[Source](../../../packages/core/src/trust-chain/fetch.ts#L195)

Check HTTPS syntax, the 2048-character limit, absence of URL credentials, an optional exact hostname allowlist, special-use IP literals, and additional blocked IPv4 CIDRs. This URL check does not resolve DNS or pin a connection's destination; the host transport owns that enforcement. Endpoint-specific fragment rules are checked by their callers.

```typescript signature
validateFetchUrl(url: string, options?: Pick<FederationOptions, "blockedCIDRs" | "allowedHosts">): Result<URL, FederationError>;
```

## `validateTrustChain`

[Source](../../../packages/core/src/trust-chain/validate.ts#L414)

Validate a chain and report its published Trust Marks independently (Federation §§3.2, 7.3).

```typescript signature
validateTrustChain(chain: ReadonlyArray<string>, trustAnchors: TrustAnchorSet, options?: TrustChainValidationOptions): Promise<ValidationResult>;
```

`TrustChainValidationOptions` is the local name used by the declaration, rather than a root export. It extends [`FederationOptions`](contracts.md#federationoptions) with these call-specific fields:

| Option | Declared type | Description |
|---|---|---|
| `verboseErrors?` | `boolean` | Return detailed failures where supported instead of a generic validation error. |
| `explicitRegistrationAudience?` | `EntityId \| string` | Expected OP identity when validating a supplied Explicit Registration EC. |
| `explicitRegistrationRequest?` | `{ readonly jwt: string; readonly audience: EntityId \| string }` | Authenticate the signed registration EC against the candidate before resolving its metadata. |

The signature remains usable without importing that local type:

```typescript
import { validateTrustChain } from "@oidfed/core";

type ValidationOptions = NonNullable<Parameters<typeof validateTrustChain>[2]>;
const options: ValidationOptions = {
  verboseErrors: true,
  offline: true,
  maxTotalFetches: 0,
};
```
