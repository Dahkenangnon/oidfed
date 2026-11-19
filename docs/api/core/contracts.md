# Identifiers, results, and host contracts

[`@oidfed/core`](README.md)

Use these contracts to connect your clock, cache, logger, HTTP transport, and protocol roles. An Entity Identifier retains its exact spelling after validation; URL equivalence does not establish federation identity.

## `assertPositiveTtlSeconds`

[Source](../../../packages/core/src/ttl.ts#L9)

Validate a configured lifetime before publication. Entity Statement builders
use safe-integer durations; Trust Marks and event responses allow fractions.
This does not check the resulting expiration against a particular clock.

- `throws`: TypeError when the duration does not satisfy the selected rule.

```typescript signature
assertPositiveTtlSeconds(value: number, field: string, mode: "safe-integer" | "finite"): void;
```

## `CacheProvider`

[Source](../../../packages/core/src/types.ts#L70)

The cache interface a host implements to store values with a lifetime.

```typescript signature
interface CacheProvider {
	get<T>(key: string): Promise<T | undefined>;
	set<T>(key: string, value: T, ttlSeconds: number): Promise<void>;
	delete(key: string): Promise<void>;
	clear(): Promise<void>;
	[Symbol.asyncDispose](): Promise<void>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `get` | `<T>(key: string) => Promise<T \| undefined>` | Read a cached value by key, returning undefined when absent or expired. |
| `set` | `<T>(key: string, value: T, ttlSeconds: number) => Promise<void>` | Store a value with its TTL in seconds. |
| `delete` | `(key: string) => Promise<void>` | Remove a cached entry by key. |
| `clear` | `() => Promise<void>` | Clear the entries owned by this cache. |
| `[Symbol.asyncDispose]` | `() => Promise<void>` | Release this cache's resources; MemoryCache clears its process-local entries. |

## `chainCacheKey`

[Source](../../../packages/core/src/cache/index.ts#L107)

Build the cache key for a subject's trust-chain operation under the supplied anchor context.

```typescript signature
chainCacheKey(entityId: EntityId, trustAnchorId: EntityId, engine: CryptoEngine): Promise<string>;
```

## `ChainSelectionStrategy`

[Source](../../../packages/core/src/types.ts#L278)

A synchronous callback that chooses one of the validated candidate chains.

```typescript signature
type ChainSelectionStrategy = (chains: ValidatedTrustChain[]) => ValidatedTrustChain;
```

## `Clock`

[Source](../../../packages/core/src/types.ts#L60)

The time source used by operations that evaluate timestamps and expiry.

```typescript signature
interface Clock {
	/** Current Unix time as a NumericDate in seconds. */
	now(): number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `now` | `() => number` | Current Unix time as a NumericDate in seconds. |

## `composeEntityMetadata`

[Source](../../../packages/core/src/roles.ts#L14)

Compose detached metadata from own enumerable properties, in source order.
Later sources replace whole parameter values, including arrays and objects.
Entity type and parameter names remain open, including JavaScript property names.
This copies data; it neither initializes roles nor establishes protocol conformance.

- `throws`: TypeError for non-object entity type blocks; cloning errors also propagate.

```typescript signature
composeEntityMetadata(...sources: readonly Readonly<Record<string, unknown>>[]): Record<string, Record<string, unknown>>;
```

## `ConstraintCheckContext`

[Source](../../../packages/core/src/types.ts#L246)

Detached, recursively frozen evidence. Position uses leaf-first chain indexing.

```typescript signature
interface ConstraintCheckContext {
	readonly issuerId: EntityId;
	readonly subjectId: EntityId;
	readonly trustChainSubjectId: EntityId;
	readonly trustAnchorId: EntityId;
	readonly position: number;
	readonly statements: ConstraintReadonly<readonly ParsedEntityStatement[]>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuerId` | `EntityId` | Entity Identifier of the issuer named by this context. |
| `subjectId` | `EntityId` | Entity Identifier of the subject named by this context. |
| `trustChainSubjectId` | `EntityId` | Entity Identifier at the beginning of the chain. |
| `trustAnchorId` | `EntityId` | Trust Anchor at which the chain or evidence terminates. |
| `position` | `number` | Leaf-first statement index of the statement carrying the constraint. |
| `statements` | `ConstraintReadonly<readonly ParsedEntityStatement[]>` | Leaf-first statements. The owning contract specifies compact JWTs or parsed statements. |

## `ConstraintCheckDefinition`

[Source](../../../packages/core/src/types.ts#L256)

Synchronous checks may run again when prepared validation is completed.

```typescript signature
interface ConstraintCheckDefinition {
	readonly name: string;
	check(value: unknown, context: ConstraintCheckContext): Result<void, FederationError>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `name` | `string` | Federation-defined operator or constraint name; standard names cannot be replaced. |
| `check` | `(value: unknown, context: ConstraintCheckContext) => Result<void, FederationError>` | Evaluate a custom constraint against detached authenticated evidence and return a Result synchronously. |

## `createTrustAnchorSet`

[Source](../../../packages/core/src/types.ts#L138)

Build a read-only-typed map from exact validated Entity Identifiers to the supplied key sets. Duplicate identifiers use the last entry. This helper validates the identifiers, but does not validate or clone their JWK Sets. Treat the configuration as owned trust data; the read-only type does not freeze the runtime Map or nested keys.

```typescript signature
createTrustAnchorSet(anchors: ReadonlyArray<{
	readonly entityId: string;
	readonly jwks: JWKSet;
}>): TrustAnchorSet;
```

## `DiscoveryResult`

[Source](../../../packages/core/src/types.ts#L286)

Result of entity discovery through the federation.

Branded to prevent callers from constructing unchecked inputs —
`discoverEntity()` and `discoverEntityFromChain()` in core produce this type after validation.

```typescript signature
type DiscoveryResult = {
	readonly [_discoveryBrand]: true;
	readonly entityId: EntityId;
	readonly resolvedMetadata: Readonly<Record<string, Record<string, unknown>>>;
	readonly trustChain: ValidatedTrustChain;
	readonly trustMarks: ReadonlyArray<ValidatedTrustMark>;
};
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entityId` | `EntityId` | Exact Entity Identifier bound to this object or operation. |
| `resolvedMetadata` | `Readonly<Record<string, Record<string, unknown>>>` | Metadata produced after superior overrides, constraints, and policy application. |
| `trustChain` | `ValidatedTrustChain` | Supplied or validated Trust Chain, in the representation declared by this contract. |
| `trustMarks` | `ReadonlyArray<ValidatedTrustMark>` | Trust Mark references, verified marks, or evaluations supplied by the owning contract. |
| `[_discoveryBrand]` | `true` | Opaque type brand supplied by core discovery. It is not an application-provided field. |

## `ecCacheKey`

[Source](../../../packages/core/src/cache/index.ts#L95)

Build the cache key for an Entity Configuration identified by its exact Entity Identifier.

```typescript signature
ecCacheKey(entityId: EntityId, engine: CryptoEngine): Promise<string>;
```

## `EntityContext`

[Source](../../../packages/core/src/types.ts#L294)

The parent entity's identity, keys, and shared settings made available to a composed role.

```typescript signature
interface EntityContext {
	readonly entityId: string;
	readonly crypto: CryptoContext;
	readonly options: FederationOptions;
	readonly trustAnchors?: TrustAnchorSet;
	readonly authorityHints?: readonly EntityId[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entityId` | `string` | Exact Entity Identifier bound to this object or operation. |
| `crypto` | `CryptoContext` | Host crypto engine, signing keyring and optional key history. |
| `options?` | `FederationOptions \| undefined` | Shared federation transport and validation settings for this operation. |
| `trustAnchors?` | `TrustAnchorSet` | Independently trusted anchor identities and their public Federation Entity Keys. |
| `authorityHints?` | `readonly EntityId[]` | Immediate Superior Entity Identifiers published as authority_hints. |

## `entityId`

[Source](../../../packages/core/src/types.ts#L21)

Validate an HTTPS Entity Identifier with at most 2048 characters, no credentials, query, or fragment, and return the original string with a TypeScript brand. Invalid input throws. The returned identifier is not URL-reserialized or normalized for comparisons.

```typescript signature
entityId(value: string): EntityId;
```

## `EntityId`

[Source](../../../packages/core/src/types.ts#L18)

An Entity Identifier validated by the library and represented as a branded string.

```typescript signature
type EntityId = string & { readonly [EntityIdBrand]: true };
```

## `EntityRole`

[Source](../../../packages/core/src/types.ts#L302)

The contract for adding protocol metadata, validation, and routes to an entity host.

```typescript signature
interface EntityRole {
	readonly type: string;
	readonly metadata: Record<string, unknown>;
	readonly routes?: ReadonlyMap<string, (request: Request) => Promise<Response>>;
	initialize?(context: EntityContext): void | Promise<void>;
	/** Rebuild managed public keys for each EC publication; captured entries can pin an operation. */
	publicationMetadata?(
		context: EntityContext,
		entries?: ReadonlyMap<string, import("@oidfed/crypto").KeyringEntry>,
	): Promise<Record<string, unknown>>;
	/** Validate the final composed role block before its host publishes metadata. */
	validateMetadata?(metadata: Readonly<Record<string, unknown>>, context: EntityContext): void;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `type` | `string` | Entity Type Identifier of the role's metadata block. |
| `metadata` | `Record<string, unknown>` | Protocol metadata contributed by this role to its entity host. |
| `routes?` | `ReadonlyMap<string, (request: Request) => Promise<Response>>` | Role-owned request handlers keyed by endpoint path. |
| `initialize?` | `(context: EntityContext) => void` | Initialize the role with its host entity context. |
| `validateMetadata?` | `(metadata: Readonly<Record<string, unknown>>, context: EntityContext) => void` | Validate the final composed role block before its host publishes metadata. |

## `err`

[Source](../../../packages/core/src/errors.ts#L34)

Wrap an error in a Result.

```typescript signature
err<E>(error: E): Result<never, E>;
```

## `esCacheKey`

[Source](../../../packages/core/src/cache/index.ts#L101)

Build the cache key for a statement issued by one entity about another.

```typescript signature
esCacheKey(issuer: EntityId, subject: EntityId, engine: CryptoEngine): Promise<string>;
```

## `federationError`

[Source](../../../packages/core/src/errors.ts#L15)

Construct a FederationError value.

```typescript signature
federationError(code: FederationErrorCode | InternalErrorCode, description: string, cause?: unknown): FederationError;
```

## `FederationError`

[Source](../../../packages/core/src/errors.ts#L6)

Plain, structurally typed error data containing a code, description, and optional cause. A function's return type determines whether this is carried in a `Result`; other APIs can throw or reject. An arbitrary cause need not be JSON-serializable, and copying an error does not preserve private fetch-failure classification.

```typescript signature
type FederationError = {
	readonly code: FederationErrorCode | InternalErrorCode;
	readonly description: string;
	readonly cause?: unknown;
	/** Untrusted responder details; code remains a typed local classification. */
	readonly remoteError?: { readonly code: string; readonly status: number };
};
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `code` | `FederationErrorCode \| InternalErrorCode` | Error code for the failure; use the declared union for the allowed values. |
| `description` | `string` | Human-readable explanation or informational description, according to the owning contract. |
| `cause?` | `unknown` | Original diagnostic cause, when retained. Do not expose it directly in an HTTP error response. |
| `remoteError?` | `{ readonly code: string; readonly status: number }` | Untrusted responder details; code remains a typed local classification. |

## `FederationOptions`

[Source](../../../packages/core/src/types.ts#L86)

Shared transport, trust-validation, caching, logging, and resource-limit settings.

```typescript signature
interface FederationOptions {
	/** Explicit cryptographic backend. No global backend is selected by the library. */
	readonly engine: CryptoEngine;
	/** Public key and algorithm definitions for standalone operations. */
	readonly algorithmRegistry?: JwsAlgorithmRegistry | undefined;
	/** Algorithms permitted for signing and verification with Federation Entity Keys. */
	readonly allowedFederationAlgorithms?: readonly string[] | undefined;
	/** Local policy for protocol-key operations. */
	readonly allowedAlgorithms?: readonly string[];
	/** Maximum matching keys tried for one JWT. Defaults to 16. */
	readonly maxVerificationCandidates?: number;
	/** Maximum encoded compact JWT bytes. Defaults to the crypto package limit. */
	readonly maxCompactBytes?: number;
	/** How to acquire evidence. Protocol consumers validate the returned subject chain. */
	trustResolution?: import("./trust-chain/assessment.js").TrustResolutionSource;
	/** Select among validated candidates eligible for the current operation. */
	chainSelection?: ChainSelectionStrategy;
	authentication?: EndpointClientAuthentication;
	/** Select authentication for each outgoing federation endpoint request. Mutually exclusive with authentication. */
	getEndpointAuthentication?: EndpointAuthenticationProvider;
	additionalParameters?: EndpointAdditionalParameters;
	trustMarkVerification?: TrustMarkVerificationOptions;
	trustMarkIssuerKeys?: ReadonlyMap<string, JWKSet>;
	trustMarkProfiles?: readonly TrustMarkProfile[];
	/** Disallow network access when only supplied evidence is permitted. */
	offline?: boolean;
	httpClient?: HttpClient;
	/** Signed subject ECs keyed by exact Entity Identifier. Each is validated against the chain. */
	entityConfigurations?: ReadonlyMap<string, string> | undefined;
	clock?: Clock;
	cache?: CacheProvider;
	logger?: Logger;
	httpTimeoutMs?: number;
	clockSkewSeconds?: number;
	maxChainDepth?: number;
	/** Maximum statements in a validated chain, including both ECs. Default: 100; resource policy, not a protocol limit. */
	maxChainLength?: number;
	/** Maximum eligible branch expansions per resolution, including reused statements. Default: 1000. */
	maxResolutionSteps?: number;
	maxAuthorityHints?: number;
	maxConcurrentFetches?: number;
	/** Fetched statement cache retention cap in seconds. Defaults to 3600, bounded by the statement's exp. */
	cacheMaxTtlSeconds?: number;
	signal?: AbortSignal;
	maxResponseBytes?: number;
	blockedCIDRs?: string[];
	allowedHosts?: string[];
	authorityHintFilter?: (hint: URL, subject: EntityId) => boolean;
	understoodCriticalClaims?: ReadonlySet<string>;
	/** Maximum HTTP client calls; discovery helpers share the allowance across discovery and candidate validation. Cached and supplied statements use no allowance. Core accepts zero. Default: 50. */
	maxTotalFetches?: number;
	/**
	 * Federation-defined policy operators in addition to the seven standard ones.
	 * Forwarded to `resolveMetadataPolicy` and `applyMetadataPolicy` during
	 * trust-chain validation.
	 */
	customPolicyOperators?: readonly PolicyOperatorDefinition[];
	/** Federation-defined constraints checked against authenticated chains. Unknown names are ignored. */
	customConstraintChecks?: readonly ConstraintCheckDefinition[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
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

## `findInvalidMetadataNullPaths`

[Source](../../../packages/core/src/metadata-values.ts#L6)

Return paths to a null metadata root, null Entity Type blocks, and null direct metadata parameter values. This helper does not reject null values nested inside a parameter object or array, and it is not a complete metadata-shape validator.

```typescript signature
findInvalidMetadataNullPaths(metadata: unknown): readonly (readonly (string | number)[])[];
```

## `flatMap`

[Source](../../../packages/core/src/errors.ts#L60)

Continue a successful Result with another Result-returning operation; preserve an existing error.

```typescript signature
flatMap<T, U, E>(result: Result<T, E>, fn: (value: T) => Result<U, E>): Result<U, E>;
```

### Usage example

Use `map` for a successful value and `flatMap` for another fallible step. `mapErr` adapts the failure for a caller. A fallback belongs only where the application can safely proceed without the value; it must not convert a failed trust check into acceptance.

```ts
import { ok, err, map, flatMap, mapErr, isErr, unwrapOr, type Result } from "@oidfed/core";

export function readPageSize(value: string): Result<number, string> {
  const parsed: Result<number, string> = /^\d+$/.test(value)
    ? ok(Number(value)) : err("Page size must contain digits");
  const bounded = flatMap(parsed, size =>
    Number.isSafeInteger(size) && size > 0 && size <= 100
      ? ok(size) : err("Page size must be between 1 and 100"));
  return map(bounded, size => size);
}

const invalid = mapErr(readPageSize("bad"), message => ({ field: "limit", message }));
if (isErr(invalid)) {
  // An editor can display invalid.error.message beside its limit field.
}
const optionalDisplayLimit = unwrapOr(readPageSize("25"), 25);
```

## `freezeSnapshot`

[Source](../../../packages/core/src/callbacks.ts#L45)

Freeze the supplied object and its enumerable nested object values in place, returning the same value. It does not clone the input. Clone evidence first when the caller must retain a mutable copy; freezing an object also does not prevent a Map or Set's own mutation methods.

```typescript signature
freezeSnapshot<T>(value: T): T;
```

## `HttpClient`

[Source](../../../packages/core/src/types.ts#L58)

The host-supplied HTTP transport used by federation clients.

```typescript signature
type HttpClient = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
```

## `isErr`

[Source](../../../packages/core/src/errors.ts#L44)

Type guard narrowing a Result to its error variant.

```typescript signature
isErr<T, E>(result: Result<T, E>): result is { ok: false; error: E };
```

## `isJsonData`

[Source](../../../packages/core/src/callbacks.ts#L59)

Check for finite-number JSON data made from primitives, arrays, and plain or null-prototype objects. Cycles and unsupported values are rejected; shared references without cycles are allowed. This is a data-shape predicate, not a serializer or a trust check.

```typescript signature
isJsonData(value: unknown): boolean;
```

## `isLanguageTag`

[Source](../../../packages/core/src/language-tags.ts#L35)

Check a language tag's accepted BCP 47 syntax for localized metadata and request selectors.

```typescript signature
isLanguageTag(tag: string): boolean;
```

## `isOk`

[Source](../../../packages/core/src/errors.ts#L39)

Type guard narrowing a Result to its success variant.

```typescript signature
isOk<T, E>(result: Result<T, E>): result is { ok: true; value: T };
```

## `isValidEntityId`

[Source](../../../packages/core/src/types.ts#L32)

Test the same identifier rules as `entityId`, returning `false` on invalid input without throwing or changing the string.

```typescript signature
isValidEntityId(value: string): value is EntityId;
```

## `JtiReplayClaim`

[Source](../../../packages/core/src/replay-store.ts#L4)

A replay-protected JWT identifier scoped to its issuer and audience.

```typescript signature
interface JtiReplayClaim {
	readonly issuer: string;
	readonly audience: string;
	readonly jti: string;
	/** JWT expiration as a NumericDate. */
	readonly expiresAt: number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuer` | `string` | Issuer identity for the signed artifact or configured service. |
| `audience` | `string` | Expected recipient identity. Federation endpoint assertions use the responder's Entity Identifier, not its URL origin. |
| `jti` | `string` | JWT identifier used for replay protection, scoped to issuer and audience. |
| `expiresAt` | `number` | Expiration or eligibility deadline as a NumericDate in seconds; the owning API defines the evidence it bounds. |

## `Logger`

[Source](../../../packages/core/src/types.ts#L79)

Host logger. Returned promises are handled without awaiting them; sink failures are ignored.

```typescript signature
interface Logger {
	debug(msg: string, context?: Record<string, unknown>): void;
	info(msg: string, context?: Record<string, unknown>): void;
	warn(msg: string, context?: Record<string, unknown>): void;
	error(msg: string, context?: Record<string, unknown>): void;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `debug` | `(msg: string, context?: Record<string, unknown>) => void` | Emit a diagnostic message for developers. |
| `info` | `(msg: string, context?: Record<string, unknown>) => void` | Emit an informational lifecycle or recommended-behavior message. |
| `warn` | `(msg: string, context?: Record<string, unknown>) => void` | Emit a warning about a condition requiring operator attention. |
| `error` | `(msg: string, context?: Record<string, unknown>) => void` | Emit an operational failure message. |

## `map`

[Source](../../../packages/core/src/errors.ts#L49)

Transform a Result's successful value while preserving its error branch.

```typescript signature
map<T, U, E>(result: Result<T, E>, fn: (value: T) => U): Result<U, E>;
```

## `mapErr`

[Source](../../../packages/core/src/errors.ts#L71)

Transform a Result's error while preserving its successful value.

```typescript signature
mapErr<T, E, F>(result: Result<T, E>, fn: (error: E) => F): Result<T, F>;
```

## `MemoryCache`

[Source](../../../packages/core/src/cache/index.ts#L24)

LRU in-memory cache with TTL-based expiry and configurable max entries.

**WARNING: Development and testing only.** Cache is not shared across processes
and is lost on restart. For production with multiple processes or containers,
implement `CacheProvider` with Redis or similar.

```typescript signature
new MemoryCache(options?: MemoryCacheOptions): MemoryCache;
```

Defaults to 1000 entries. Reads update LRU order and remove expired entries; inserting a new key at capacity evicts the least recently used entry. Values are retained and returned by reference, so this cache does not provide snapshot isolation. TTLs are measured in seconds using the configured clock.

### `MemoryCache#get`

Read the requested key or record through this store's contract.

[Source](../../../packages/core/src/cache/index.ts#L36)

```typescript signature
get<T>(key: string): Promise<T | undefined>;
```

### `MemoryCache#set`

Store a value under the supplied key and retention options.

[Source](../../../packages/core/src/cache/index.ts#L56)

```typescript signature
set<T>(key: string, value: T, ttlSeconds: number): Promise<void>;
```

### `MemoryCache#delete`

Remove the requested stored value.

[Source](../../../packages/core/src/cache/index.ts#L70)

```typescript signature
delete(key: string): Promise<void>;
```

### `MemoryCache#clear`

Clear the values owned by this store.

[Source](../../../packages/core/src/cache/index.ts#L75)

```typescript signature
clear(): Promise<void>;
```

### `MemoryCache#[Symbol.asyncDispose]`

Clear this in-memory cache during asynchronous disposal. This does not clear another process's cache or revoke signed evidence.

[Source](../../../packages/core/src/cache/index.ts#L80)

```typescript signature
[Symbol.asyncDispose](): Promise<void>;
```

## `MemoryCacheOptions`

[Source](../../../packages/core/src/cache/index.ts#L11)

Capacity and time settings for the in-memory cache.

```typescript signature
interface MemoryCacheOptions {
	readonly maxEntries?: number;
	/** NumericDate clock in seconds. */
	readonly clock?: Clock;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `maxEntries?` | `number` | Maximum in-memory cache entries; defaults to 1000 for MemoryCache. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |

## `MemoryReplayStore`

[Source](../../../packages/core/src/memory-replay-store.ts#L20)

Development-only in-memory replay store with fail-closed capacity handling.

```typescript signature
new MemoryReplayStore(options: MemoryReplayStoreOptions): MemoryReplayStore;
```

Defaults to 10000 live claims and requires a positive safe-integer capacity. The `(issuer, audience, jti)` tuple is hashed before the atomic lookup and insert. Expired or already-used claims return `false`; malformed claims throw and a full store rejects with `ReplayStoreCapacityError`. Records are process-local and disappear on restart.

### `MemoryReplayStore#useJti`

Returns true when claimed, or false when the claim was already used or has expired.

[Source](../../../packages/core/src/memory-replay-store.ts#L42)

```typescript signature
useJti(claim: JtiReplayClaim): Promise<boolean>;
```

## `MemoryReplayStoreOptions`

[Source](../../../packages/core/src/memory-replay-store.ts#L6)

Settings for the in-memory replay store.

```typescript signature
interface MemoryReplayStoreOptions {
	readonly engine: CryptoEngine;
	readonly clock?: Clock;
	readonly maxEntries?: number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `maxEntries?` | `number` | Maximum live replay claims; defaults to 10000. Must be a positive safe integer; live entries are never evicted to admit a new claim. |

## `nowSeconds`

[Source](../../../packages/core/src/types.ts#L66)

Returns the current time as seconds since the epoch.

```typescript signature
nowSeconds(clock?: Clock): number;
```

## `ok`

[Source](../../../packages/core/src/errors.ts#L29)

Wrap a success value in a Result.

```typescript signature
ok<T>(value: T): Result<T, never>;
```

## `ParsedEntityStatement`

[Source](../../../packages/core/src/types.ts#L49)

Decoded JWT header and payload. This structure does not contain the original compact JWT and does not itself establish signature or chain validity; its verification state comes from the operation returning it.

```typescript signature
type ParsedEntityStatement<Payload = DecodedFederationJwtPayload> = {
	readonly header: Record<string, unknown>;
	readonly payload: Payload;
};
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `header` | `Record<string, unknown>` | Decoded JWT header. Decoding alone does not authenticate it. |
| `payload` | `Payload` | Decoded claims; their verification state is determined by the enclosing result. |

## `PolicyMergeResult`

[Source](../../../packages/core/src/types.ts#L274)

Success or failure from combining two values of a metadata-policy operator.

```typescript signature
type PolicyMergeResult = { ok: true; value: unknown } | { ok: false; error: string };
```

## `PolicyOperatorDefinition`

[Source](../../../packages/core/src/types.ts#L261)

A custom operator's name, ordering, combination rules, and merge/application callbacks.

```typescript signature
interface PolicyOperatorDefinition {
	name: string;
	order: number;
	action: "check" | "modify" | "both";
	apply(parameterValue: unknown, operatorValue: unknown): PolicyOperatorResult;
	merge(existingValue: unknown, newValue: unknown): PolicyMergeResult;
	canCombineWith(otherOperator: string, thisValue: unknown, otherValue: unknown): boolean;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `name` | `string` | Federation-defined operator or constraint name; standard names cannot be replaced. |
| `order` | `number` | Finite operator application order, respecting the value and essential boundaries. |
| `action` | `"check" \| "modify" \| "both"` | Whether the policy operator checks, modifies, or both checks and modifies the parameter. |
| `apply` | `(parameterValue: unknown, operatorValue: unknown) => PolicyOperatorResult` | Apply an operator to the parameter value and return its result synchronously. |
| `merge` | `(existingValue: unknown, newValue: unknown) => PolicyMergeResult` | Combine superior and subordinate values of this policy operator synchronously. |
| `canCombineWith` | `(otherOperator: string, thisValue: unknown, otherValue: unknown) => boolean` | Return whether this operator can coexist with another operator on the same parameter. |

## `PolicyOperatorResult`

[Source](../../../packages/core/src/types.ts#L270)

Success or failure from applying a metadata-policy operator to a parameter value.

```typescript signature
type PolicyOperatorResult = {
	ok: true;
	value: unknown;
	removed?: boolean;
} | {
	ok: false;
	error: string;
};
```

## `ReplayStore`

[Source](../../../packages/core/src/replay-store.ts#L13)

Atomic replay protection for one-time JWT processing.

```typescript signature
interface ReplayStore {
	/** Returns true when claimed, or false when the claim was already used or has expired. */
	useJti(claim: JtiReplayClaim): Promise<boolean>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `useJti` | `(claim: JtiReplayClaim) => Promise<boolean>` | Returns true when claimed, or false when the claim was already used or has expired. |

## `ReplayStoreCapacityError`

[Source](../../../packages/core/src/memory-replay-store.ts#L12)

Raised when accepting another claim would require evicting a live replay record.

```typescript signature
new ReplayStoreCapacityError(maxEntries: number): ReplayStoreCapacityError;
```

Extends the standard `Error` class, including its `name` and `message`. Runtime-specific Error additions are not separate library APIs.

## `ResolvedMetadataPolicy`

[Source](../../../packages/core/src/types.ts#L276)

The metadata policy produced by combining the applicable declarations.

```typescript signature
type ResolvedMetadataPolicy = Record<string, Record<string, Record<string, unknown>>>;
```

## `Result`

[Source](../../../packages/core/src/errors.ts#L24)

Success and failure branches discriminated by `ok`. Read `value` only after success and `error` only after failure. The type does not catch exceptions from callbacks passed to helpers such as `map` or `flatMap`.

```typescript signature
type Result<T, E = FederationError> = {
	readonly ok: true;
	readonly value: T;
} | {
	readonly ok: false;
	readonly error: E;
};
```

## `runAsyncOperation`

[Source](../../../packages/core/src/async-operation.ts#L28)

Run host-controlled work with a cooperative AbortSignal and a timeout, defaulting to 10000 milliseconds. Cancellation and timeout reject with `AbortError` or `TimeoutError`; callback exceptions and rejections propagate. A callback that ignores its signal can still finish later, so this helper does not roll back its side effects.

```typescript signature
runAsyncOperation<T>(operation: (signal: AbortSignal) => T | Promise<T>, options: Pick<FederationOptions, "signal" | "httpTimeoutMs">): Promise<T>;
```

### Usage example

`waitForOperation` releases a cancelled caller without cancelling the pending operation. `runAsyncOperation` also supplies a bounded signal to the host callback. Use the latter when the callback can cooperate with cancellation; neither helper rolls back a committed storage transaction.

```ts
import { runAsyncOperation, waitForOperation, type FederationOptions } from "@oidfed/core";

export async function awaitStoredSnapshot<T>(pending: Promise<T>, signal: AbortSignal) {
  return waitForOperation(pending, [signal]);
}

export async function queryHostPolicy<T>(
  check: (signal: AbortSignal) => Promise<T>, options: FederationOptions,
) {
  return runAsyncOperation(check, options);
}
```

## `safeLogger`

[Source](../../../packages/core/src/logging.ts#L8)

Return a message-only wrapper around the host logger, or `undefined` when no logger is supplied. It preserves the sink's receiver, catches synchronous throws, consumes rejected promises, and never waits for an async sink. Although `Logger` accepts optional context for host compatibility, the protected wrapper forwards only the message.

```typescript signature
safeLogger(logger: Logger | undefined): Logger | undefined;
```

## `setOwn`

[Source](../../../packages/core/src/callbacks.ts#L32)

Write JSON member names without invoking Object.prototype setters.

```typescript signature
setOwn(object: object, name: string, value: unknown): void;
```

### Usage example

Use an owned snapshot when another component must not mutate evidence. `setOwn` creates a data property even for a key such as `__proto__`; it does not interpret the key as a prototype setter.

```ts
import { freezeSnapshot, isJsonData, setOwn } from "@oidfed/core";

export function extensionSnapshot(name: string, value: unknown) {
  if (!isJsonData(value)) throw new TypeError("Extension must be JSON data");
  const payload: Record<string, unknown> = {};
  setOwn(payload, name, structuredClone(value));
  return freezeSnapshot(payload);
}
```

## `TrustAnchorSet`

[Source](../../../packages/core/src/types.ts#L135)

Read-only-typed mapping of independently trusted Entity Identifiers to their public Federation Entity Keys. The type alone does not freeze a supplied Map or clone its values.

```typescript signature
type TrustAnchorSet = ReadonlyMap<string, Readonly<{ jwks: JWKSet }>>;
```

## `TrustChain`

[Source](../../../packages/core/src/types.ts#L144)

A discovered candidate containing leaf-first compact Entity Statement JWTs and its proposed anchor and expiration. It is distinct from `ValidatedTrustChain`; discovery alone does not establish complete trust or effective protocol metadata.

```typescript signature
interface TrustChain {
	readonly statements: ReadonlyArray<string>;
	/** ECs retrieved while resolving this candidate; pass as validation options to avoid refetching. */
	readonly entityConfigurations?: ReadonlyMap<string, string>;
	readonly entityId: EntityId;
	readonly trustAnchorId: EntityId;
	readonly expiresAt: number;
	readonly resolvedMetadata?: Readonly<Record<string, unknown>>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `statements` | `ReadonlyArray<string>` | Leaf-first statements. The owning contract specifies compact JWTs or parsed statements. |
| `entityConfigurations?` | `ReadonlyMap<string, string>` | Subject Entity Configuration JWTs used during chain validation; signatures and identity bindings still need validation. |
| `entityId` | `EntityId` | Exact Entity Identifier bound to this object or operation. |
| `trustAnchorId` | `EntityId` | Trust Anchor at which the chain or evidence terminates. |
| `expiresAt` | `number` | Expiration or eligibility deadline as a NumericDate in seconds; the owning API defines the evidence it bounds. |
| `resolvedMetadata?` | `Readonly<Record<string, unknown>>` | Metadata produced after superior overrides, constraints, and policy application. |

## `TrustChainResult`

[Source](../../../packages/core/src/types.ts#L154)

The candidates and discovery information returned by trust-chain resolution.

```typescript signature
interface TrustChainResult {
	readonly chains: ReadonlyArray<TrustChain>;
	readonly errors: ReadonlyArray<FederationError>;
	/** Resolution stopped before examining its configured scope because of a limit or cancellation. */
	readonly incomplete?: true;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `chains` | `ReadonlyArray<TrustChain>` | Candidate chains discovered so far; each still needs validation. |
| `errors` | `ReadonlyArray<FederationError>` | Validation or discovery failures recorded by the operation. |
| `incomplete?` | `true` | Resolution stopped before examining its configured scope because of a limit or cancellation. |

## `TrustMarkEvaluation`

[Source](../../../packages/core/src/types.ts#L193)

Evaluation of a Trust Mark, independent of the enclosing chain's validity.

```typescript signature
type TrustMarkEvaluation = Readonly<{
	referenceIndex: number;
	trustMarkType: string;
}> & (Readonly<{
	status: "verified";
	mark: ValidatedTrustMark;
}> | Readonly<{
	status: "invalid";
	error: FederationError;
}> | Readonly<{
	status: "unevaluated";
	reason: "not_evaluated" | "issuer_policy_unavailable" | "issuer_keys_unavailable";
	description: string;
}>);
```

## `TrustMarkEvidence`

[Source](../../../packages/core/src/types.ts#L207)

Verified Trust Mark evidence with a required original JWT, verified claims, and the key's current or historical source. It also retains the supporting issuer context and evidence deadline when available.

```typescript signature
interface TrustMarkEvidence extends ValidatedTrustMark {
	readonly jwt: string;
	readonly claims: Readonly<Record<string, unknown>>;
	readonly verificationKey: Readonly<{
		source: "current" | "historical";
		kid: string;
		responseJwt?: string;
	}>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `jwt` | `string` | Verified compact Trust Mark JWT, required in this richer evidence record. |
| `claims` | `Readonly<Record<string, unknown>>` | Verified Trust Mark claims, required in this evidence record. |
| `verificationKey` | `Readonly<{ source: "current" \| "historical"; kid: string; responseJwt?: string; }>` | Verification key identifier, its current/historical source, and any retained historical response JWT. |
| `issuerEvidence?` | `import("./trust-marks/evidence.js").TrustMarkIssuerContext` | Previously established federation issuer evidence or explicit host out-of-band trust. |
| `verificationExpiresAt?` | `number` | Deadline of the evidence supporting verification, which can precede the signed token's exp. |
| `trustMarkType` | `string` | Trust Mark type identifier used for issuance, verification, or filtering. |
| `issuer` | `string` | Issuer identity for the signed artifact or configured service. |
| `subject` | `string` | Subject identity for the statement, mark, or authentication being processed. |
| `issuedAt` | `number` | Issuance time as a NumericDate in seconds. |
| `expiresAt?` | `number` | Expiration or eligibility deadline as a NumericDate in seconds; the owning API defines the evidence it bounds. |
| `delegation?` | `Readonly<ValidatedTrustMarkDelegation>` | Owner-signed delegation JWT authorizing the Trust Mark Issuer. |

## `UnverifiedEntityStatement`

[Source](../../../packages/core/src/types.ts#L53)

A decoded Entity Statement whose claims and signature have not established trust.

```typescript signature
type UnverifiedEntityStatement<Payload = DecodedFederationJwtPayload> =
	ParsedEntityStatement<Payload> & {
		readonly [Unverified]: true;
	};
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `header` | `Record<string, unknown>` | Decoded JWT header. Decoding alone does not authenticate it. |
| `payload` | `Payload` | Decoded claims; their verification state is determined by the enclosing result. |
| `[Unverified]` | `true` | Opaque compile-time marker for a decoded statement that has not established trust. |

## `unwrapOr`

[Source](../../../packages/core/src/errors.ts#L79)

Read a successful Result value or use the supplied fallback. Use an explicit branch when an error must stop the operation.

```typescript signature
unwrapOr<T, E>(result: Result<T, E>, fallback: T): T;
```

## `ValidatedTrustChain`

[Source](../../../packages/core/src/types.ts#L161)

A validated chain, its resolved metadata, selected anchor, and evidence lifetime.

```typescript signature
interface ValidatedTrustChain {
	readonly statements: ReadonlyArray<ParsedEntityStatement>;
	readonly entityId: EntityId;
	readonly trustAnchorId: EntityId;
	readonly expiresAt: number;
	readonly resolvedMetadata: Readonly<Record<string, Record<string, unknown>>>;
	readonly trustMarks: ReadonlyArray<ValidatedTrustMark>;
	/** Evaluation of each published subject mark, in reference order. */
	readonly trustMarkEvaluations: ReadonlyArray<TrustMarkEvaluation>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `statements` | `ReadonlyArray<ParsedEntityStatement>` | Leaf-first statements. The owning contract specifies compact JWTs or parsed statements. |
| `entityId` | `EntityId` | Exact Entity Identifier bound to this object or operation. |
| `trustAnchorId` | `EntityId` | Trust Anchor at which the chain or evidence terminates. |
| `expiresAt` | `number` | Expiration or eligibility deadline as a NumericDate in seconds; the owning API defines the evidence it bounds. |
| `resolvedMetadata` | `Readonly<Record<string, Record<string, unknown>>>` | Metadata produced after superior overrides, constraints, and policy application. |
| `trustMarks` | `ReadonlyArray<ValidatedTrustMark>` | Trust Mark references, verified marks, or evaluations supplied by the owning contract. |
| `trustMarkEvaluations` | `ReadonlyArray<TrustMarkEvaluation>` | Evaluation of each published subject mark, in reference order. |

## `ValidatedTrustMark`

[Source](../../../packages/core/src/types.ts#L217)

A verified Trust Mark and the evidence associated with its validation.

```typescript signature
interface ValidatedTrustMark {
	/** Authenticated issuer context retained for subsequent status checks; federation provenance is runtime-bound. */
	readonly issuerEvidence?: import("./trust-marks/evidence.js").TrustMarkIssuerContext;
	/** Present on marks validated by current core APIs; optional for older host-created records. */
	readonly jwt?: string;
	readonly claims?: Readonly<Record<string, unknown>>;
	/** Expiry of the evidence supporting this assessment; distinct from the token expiry. */
	readonly verificationExpiresAt?: number;
	readonly trustMarkType: string;
	readonly issuer: string;
	readonly subject: string;
	readonly issuedAt: number;
	readonly expiresAt?: number;
	readonly delegation?: Readonly<ValidatedTrustMarkDelegation>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuerEvidence?` | `import("./trust-marks/evidence.js").TrustMarkIssuerContext` | Previously established federation issuer evidence or explicit host out-of-band trust. |
| `jwt?` | `string` | Compact JWT string retained or supplied for this operation. |
| `claims?` | `Readonly<Record<string, unknown>>` | Claims associated with the artifact or selected for this operation. |
| `verificationExpiresAt?` | `number` | Deadline of the evidence supporting verification, which can precede the signed token's exp. |
| `trustMarkType` | `string` | Trust Mark type identifier used for issuance, verification, or filtering. |
| `issuer` | `string` | Issuer identity for the signed artifact or configured service. |
| `subject` | `string` | Subject identity for the statement, mark, or authentication being processed. |
| `issuedAt` | `number` | Issuance time as a NumericDate in seconds. |
| `expiresAt?` | `number` | Expiration or eligibility deadline as a NumericDate in seconds; the owning API defines the evidence it bounds. |
| `delegation?` | `Readonly<ValidatedTrustMarkDelegation>` | Owner-signed delegation JWT authorizing the Trust Mark Issuer. |

## `ValidatedTrustMarkDelegation`

[Source](../../../packages/core/src/types.ts#L233)

A verified owner's delegation to a Trust Mark Issuer.

```typescript signature
interface ValidatedTrustMarkDelegation {
	readonly issuer: string;
	readonly subject: string;
	readonly trustMarkType: string;
	readonly issuedAt: number;
	readonly expiresAt?: number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuer` | `string` | Issuer identity for the signed artifact or configured service. |
| `subject` | `string` | Subject identity for the statement, mark, or authentication being processed. |
| `trustMarkType` | `string` | Trust Mark type identifier used for issuance, verification, or filtering. |
| `issuedAt` | `number` | Issuance time as a NumericDate in seconds. |
| `expiresAt?` | `number` | Expiration or eligibility deadline as a NumericDate in seconds; the owning API defines the evidence it bounds. |

## `validateRoleMetadata`

[Source](../../../packages/core/src/roles.ts#L32)

Run shared publication checks for composed inline public keys and protocol issuer binding, then invoke each attached role's `validateMetadata` hook on a detached, shallow-frozen metadata block. The host must compose metadata and initialize roles separately. Invalid publication data and role errors throw; missing effective fields may still be supplied by a Superior.

```typescript signature
validateRoleMetadata(roles: readonly EntityRole[] | undefined, metadata: Readonly<Record<string, unknown>>, context: EntityContext): void;
```

## `ValidationError`

[Source](../../../packages/core/src/types.ts#L184)

The location and reason for a validation failure.

```typescript signature
interface ValidationError {
	readonly code: InternalErrorCode;
	readonly message: string;
	readonly statementIndex?: number;
	readonly field?: string;
	readonly checkNumber?: number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `code` | `InternalErrorCode` | Error code for the failure; use the declared union for the allowed values. |
| `message` | `string` | Explanation of the validation failure. |
| `statementIndex?` | `number` | Zero-based index of the affected statement in the leaf-first chain. |
| `field?` | `string` | Field path associated with a validation failure. |
| `checkNumber?` | `number` | Validation-check number associated with the failure, when supplied. |

## `ValidationResult`

[Source](../../../packages/core/src/types.ts#L172)

A validation outcome and any errors explaining rejection.

```typescript signature
type ValidationResult = {
	readonly valid: true;
	readonly chain: ValidatedTrustChain;
	readonly errors: ReadonlyArray<ValidationError>;
} | {
	readonly valid: false;
	readonly chain?: undefined;
	readonly errors: ReadonlyArray<ValidationError>;
};
```

## `waitForOperation`

[Source](../../../packages/core/src/async-operation.ts#L7)

Wait for an existing promise while observing the supplied cancellation signals. Cancellation rejects with an `AbortError` and removes the waiting caller's listeners; the pending operation is allowed to finish. There is no timeout or rollback in this helper.

```typescript signature
waitForOperation<T>(pending: Promise<T>, signals: readonly (AbortSignal | undefined)[]): Promise<T>;
```


## Crypto dependencies

`CryptoContext` contains `engine`, `keyring`, optional `federationPurpose`, and an optional `history` source. `BoundFederationOptions<Options>` omits the engine from options on an initialized host or role. The instance uses its host engine; standalone operations require `FederationOptions.engine`. See the [migration guide](../crypto/migration.md).
