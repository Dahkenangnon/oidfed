# Trust Marks

[`@oidfed/core`](README.md)

Establish issuer trust before relying on a mark. Signing, delegation, holding a JWT, accreditation policy, and live status are separate operations. Evidence objects preserve provenance in the current process and cannot be recreated by copying their fields.

## `AttachTrustMarkOptions`

[Source](../../../packages/core/src/trust-marks/holder.ts#L14)

Issuer evidence and replacement policy for attaching a mark to its holder.

```typescript signature
interface AttachTrustMarkOptions
	extends Omit<ValidateTrustMarkWithIssuerOptions, "expectedSubject"> {
	readonly issuerEvidence: TrustMarkIssuerContext;
	readonly replacement?: "same-issuer-and-type";
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuerEvidence` | `TrustMarkIssuerContext` | Previously established federation issuer evidence or explicit host out-of-band trust. |
| `replacement?` | `"same-issuer-and-type"` | When set to same-issuer-and-type, replace published references from the same issuer for this type. Omitted mode appends and ignores duplicate JWTs. |
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
| `expectedTrustMarkType` | `string` | Trust Mark type that must match the verified payload. |
| `trustMarkOwners?` | `Record<string, TrustMarkOwner>` | Trusted owner identity and keys indexed by Trust Mark type. |
| `historicalKeys?` | `HistoricalTrustMarkOptions` | Historical-key source and freshness policy; signature failures do not trigger a historical-key retry. |

## `checkTrustMarkRequirements`

[Source](../../../packages/core/src/trust-marks/requirements.ts#L21)

Check required Trust Mark types and, optionally, every published mark against already validated evidence. Chain, mark, delegation, and verification-evidence deadlines are checked again. This synchronous function does not fetch fresh issuer evidence or query Status/Listing endpoints; the host chooses those additional checks.

```typescript signature
checkTrustMarkRequirements(chain: ValidatedTrustChain, requirements: TrustMarkRequirements, options?: Pick<FederationOptions, "clock" | "clockSkewSeconds">): Result<void, FederationError>;
```

## `EstablishTrustMarkIssuerOptions`

[Source](../../../packages/core/src/trust-marks/evidence.ts#L76)

Issuer identity, accreditation policy, and trust inputs for establishing issuer evidence.

```typescript signature
interface EstablishTrustMarkIssuerOptions {
	readonly issuer: string;
	readonly trustMarkType: string;
	readonly trustAnchors: TrustAnchorSet;
	readonly trustChain?: readonly string[];
	readonly entityConfigurations?: ReadonlyMap<string, string>;
	readonly options?: FederationOptions;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuer` | `string` | Issuer identity for the signed artifact or configured service. |
| `trustMarkType` | `string` | Trust Mark type identifier used for issuance, verification, or filtering. |
| `trustAnchors` | `TrustAnchorSet` | Independently trusted anchor identities and their public Federation Entity Keys. |
| `trustChain?` | `readonly string[]` | Supplied or validated Trust Chain, in the representation declared by this contract. |
| `entityConfigurations?` | `ReadonlyMap<string, string>` | Subject Entity Configuration JWTs used during chain validation; signatures and identity bindings still need validation. |
| `options?` | `FederationOptions` | Shared federation transport and validation settings for this operation. |

## `establishTrustMarkIssuerTrust`

[Source](../../../packages/core/src/trust-marks/evidence.ts#L96)

Validate supplied proofs or discover an eligible issuer chain without recursive mark evaluation.

```typescript signature
establishTrustMarkIssuerTrust(input: EstablishTrustMarkIssuerOptions): Promise<Result<FederationTrustMarkIssuerEvidence>>;
```

## `FederationTrustMarkIssuerEvidence`

[Source](../../../packages/core/src/trust-marks/evidence.ts#L39)

Evidence issued by establishTrustMarkIssuerTrust after federation validation.
Consumers check its process-local object identity as well as expiry. A spread,
structured clone, or JSON round trip does not retain that provenance; establish
fresh evidence from signed statements when crossing a process boundary.

```typescript signature
interface FederationTrustMarkIssuerEvidence {
	readonly kind: "federation";
	readonly issuer: string;
	readonly trustMarkType: string;
	readonly trustAnchorId: string;
	readonly statements: readonly string[];
	readonly entityConfigurations: Readonly<Record<string, string>>;
	readonly keys: JWKSet;
	readonly expiresAt: number;
	readonly metadata?: FederationEntityMetadata;
	readonly trustMarkIssuers: Readonly<Record<string, readonly string[]>>;
	readonly trustMarkOwners: Readonly<Record<string, TrustMarkOwner>>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `kind` | `"federation"` | Discriminator selecting the evidence or acquisition mode. |
| `issuer` | `string` | Issuer identity for the signed artifact or configured service. |
| `trustMarkType` | `string` | Trust Mark type identifier used for issuance, verification, or filtering. |
| `trustAnchorId` | `string` | Trust Anchor at which the chain or evidence terminates. |
| `statements` | `readonly string[]` | Leaf-first statements. The owning contract specifies compact JWTs or parsed statements. |
| `entityConfigurations` | `Readonly<Record<string, string>>` | Subject Entity Configuration JWTs used during chain validation; signatures and identity bindings still need validation. |
| `keys` | `JWKSet` | Public keys in the set; metadata sets may be empty, while Federation signing-key sets require at least one key. |
| `expiresAt` | `number` | Expiration or eligibility deadline as a NumericDate in seconds; the owning API defines the evidence it bounds. |
| `metadata?` | `FederationEntityMetadata` | Validated issuer federation metadata, including any authenticated Trust Mark endpoints. |
| `trustMarkIssuers` | `Readonly<Record<string, readonly string[]>>` | Permitted issuer identities indexed by Trust Mark type; an empty array allows any issuer under the applicable policy. |
| `trustMarkOwners` | `Readonly<Record<string, TrustMarkOwner>>` | Trusted owner identity and keys indexed by Trust Mark type. |

## `FetchAndAttachTrustMarkOptions`

[Source](../../../packages/core/src/trust-marks/holder.ts#L22)

Retrieval and validation settings for obtaining a mark and publishing it on its holder.

```typescript signature
interface FetchAndAttachTrustMarkOptions {
	readonly issuer: string;
	readonly trustMarkType: string;
	readonly trustAnchors: TrustAnchorSet;
	readonly replacement?: "same-issuer-and-type";
	readonly options?: FederationOptions;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuer` | `string` | Issuer identity for the signed artifact or configured service. |
| `trustMarkType` | `string` | Trust Mark type identifier used for issuance, verification, or filtering. |
| `trustAnchors` | `TrustAnchorSet` | Independently trusted anchor identities and their public Federation Entity Keys. |
| `replacement?` | `"same-issuer-and-type"` | When set to same-issuer-and-type, replace published references from the same issuer for this type. Omitted mode appends and ignores duplicate JWTs. |
| `options?` | `FederationOptions` | Shared federation transport and validation settings for this operation. |

## `fetchTrustMark`

[Source](../../../packages/core/src/trust-marks/fetch.ts#L34)

Fetch a Trust Mark JWT; validate it before relying on it.
Configure the endpoint and authentication together from trusted configuration or validated metadata.
This standalone client uses authentication.audience without an independent responder identity;
getEndpointAuthentication receives no responder. Authenticated requests use POST and never retry anonymously.
TrustMarkHolder.fetchAndAttachTrustMark supplies its verified issuer identity for an additional audience check.

```typescript signature
fetchTrustMark(endpoint: string, params: FetchTrustMarkParams, options?: FederationOptions): Promise<Result<string, FederationError>>;
```

## `FetchTrustMarkParams`

[Source](../../../packages/core/src/trust-marks/fetch.ts#L22)

Subject and Trust Mark type selectors sent to the issuance endpoint.

```typescript signature
interface FetchTrustMarkParams {
	trustMarkType: string;
	sub: EntityId;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `trustMarkType` | `string` | Trust Mark type identifier used for issuance, verification, or filtering. |
| `sub` | `EntityId` | Subject of the signed artifact. An Entity Configuration is self-issued; other artifacts name their own subject. |

## `fetchTrustMarkStatus`

[Source](../../../packages/core/src/trust-marks/fetch.ts#L133)

POST a Trust Mark JWT to a Trust Mark Status endpoint and verify the response.

```typescript signature
fetchTrustMarkStatus(input: FetchTrustMarkStatusInput): Promise<Result<TrustMarkStatusResult, FederationError>>;
fetchTrustMarkStatus(endpoint: string, trustMarkJwt: string, signerJwks: JWKSet, options: FetchTrustMarkStatusOptions): Promise<Result<TrustMarkStatusResult, FederationError>>;
```

The evidence-aware overload takes its endpoint and current keys from the issuer context, binds the submitted mark to the expected subject and type, and rejects response `iat` values beyond the allowed clock skew. An age limit is enforced only when `freshness.maxAgeSeconds` is supplied; there is no default maximum age. The endpoint/key overload requires independent issuer trust and does not enable that extra issued-at check by itself. Both overloads verify that the signed response refers to the exact submitted JWT; neither substitutes for validating the Trust Mark itself.

## `FetchTrustMarkStatusInput`

[Source](../../../packages/core/src/trust-marks/fetch.ts#L114)

The mark JWT and issuer evidence used for an evidence-aware Status request.

```typescript signature
interface FetchTrustMarkStatusInput extends FederationOptions {
	jwt: string;
	issuerEvidence: TrustMarkIssuerContext;
	expectedSubject: string;
	expectedTrustMarkType: string;
	freshness?: { maxAgeSeconds: number };
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `jwt` | `string` | Compact JWT string retained or supplied for this operation. |
| `issuerEvidence` | `TrustMarkIssuerContext` | Previously established federation issuer evidence or explicit host out-of-band trust. |
| `expectedSubject` | `string` | Subject identity that must match the verified payload. |
| `expectedTrustMarkType` | `string` | Trust Mark type that must match the verified payload. |
| `freshness?` | `{ maxAgeSeconds: number }` | Optional maximum age for signed Status responses. Evidence-aware calls check iat against the allowed clock skew even when this age limit is omitted. |
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

## `FetchTrustMarkStatusOptions`

[Source](../../../packages/core/src/trust-marks/fetch.ts#L108)

Verification and transport settings for a Trust Mark Status request.

```typescript signature
interface FetchTrustMarkStatusOptions extends FederationOptions {
	expectedIssuer: string;
	clockSkewSeconds?: number;
	clock?: Clock;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `expectedIssuer` | `string` | Issuer identity that must match the verified payload. |
| `clockSkewSeconds?` | `number` | Allowed time-claim leeway in seconds; the default verifier allowance is 60 seconds. |
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
| `httpTimeoutMs?` | `number` | Timeout in milliseconds for bounded transport or host callbacks; defaults to 10000. |
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

## `HistoricalTrustMarkOptions`

[Source](../../../packages/core/src/trust-marks/evidence.ts#L63)

Historical-key sources and policy for checking marks signed with retired keys.

```typescript signature
interface HistoricalTrustMarkOptions {
	readonly mode: "on-missing-kid" | "supplied-only";
	readonly responses?: readonly string[];
	readonly maxAgeSeconds: number;
	readonly allowedRevocationReasons?: readonly string[];
	readonly securityRevocationReasons?: readonly string[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `mode` | `"on-missing-kid" \| "supplied-only"` | Discriminator selecting the configured policy or acquisition behavior. |
| `responses?` | `readonly string[]` | Previously obtained signed Historical Keys responses; they still need verification. |
| `maxAgeSeconds` | `number` | Maximum accepted evidence age in seconds, interpreted by the owning freshness policy. |
| `allowedRevocationReasons?` | `readonly string[]` | Nonsecurity revocation reasons the historical-key policy permits. |
| `securityRevocationReasons?` | `readonly string[]` | Revocation reasons that must not be bypassed when selecting a historical key. |

## `isStoredTrustMarkEligible`

[Source](../../../packages/core/src/trust-marks/eligibility.ts#L10)

Filter previously verified stored marks by active state and mark/delegation time.
Apply before choosing the newest record, using exact issuer time without leeway.
Ingestion must establish signature, issuer trust, and matching record fields;
this predicate does not perform cryptographic or profile verification.

```typescript signature
isStoredTrustMarkEligible(record: TrustMarkRecord, validAt: number): boolean;
```

## `MemoryTrustMarkStorage`

[Source](../../../packages/core/src/trust-marks/memory.ts#L34)

Keep managed Trust Mark records in memory. Use durable transactional storage for deployments that must survive restart or coordinate workers.

```typescript signature
new MemoryTrustMarkStorage(read: () => Map<string, TrustMarkRecord>, mutate: <T>(
			operation: (records: Map<string, TrustMarkRecord>) => T | Promise<T>,
		) => Promise<T>): MemoryTrustMarkStorage;
```

### `MemoryTrustMarkStorage#listCandidates`

Return every candidate, including revoked records, before service-level eligibility and newest-record selection. Return detached records from one consistent view.

[Source](../../../packages/core/src/trust-marks/memory.ts#L48)

```typescript signature
listCandidates(filter: {
		issuer: string;
		trustMarkType?: string;
		subject?: EntityId;
	}): Promise<TrustMarkRecord[]>;
```

### `MemoryTrustMarkStorage#getValid`

Read an eligible stored mark matching the supplied selectors.

[Source](../../../packages/core/src/trust-marks/memory.ts#L66)

```typescript signature
getValid(trustMarkType: string, subject: EntityId, validAt: number): Promise<TrustMarkRecord | undefined>;
```

### `MemoryTrustMarkStorage#getByJwt`

Return a detached record, including revoked or expired records when present.

[Source](../../../packages/core/src/trust-marks/memory.ts#L84)

```typescript signature
getByJwt(jwt: string): Promise<TrustMarkRecord | undefined>;
```

### `MemoryTrustMarkStorage#listValid`

List eligible records under the requested issuer and type selectors.

[Source](../../../packages/core/src/trust-marks/memory.ts#L89)

```typescript signature
listValid(trustMarkType: string, validAt: number, options: TrustMarkListOptions): Promise<TrustMarkListPage>;
```

### `MemoryTrustMarkStorage#listValidForSubject`

List eligible records for a subject.

[Source](../../../packages/core/src/trust-marks/memory.ts#L117)

```typescript signature
listValidForSubject(subject: EntityId, validAt: number): Promise<TrustMarkRecord[]>;
```

### `MemoryTrustMarkStorage#hasAnyValid`

Check whether any matching eligible record exists.

[Source](../../../packages/core/src/trust-marks/memory.ts#L133)

```typescript signature
hasAnyValid(subject: EntityId, validAt: number): Promise<boolean>;
```

### `MemoryTrustMarkStorage#issue`

Capture input before asynchronous work. Reissuing the same JWT must not replace its record.

[Source](../../../packages/core/src/trust-marks/memory.ts#L139)

```typescript signature
issue(record: TrustMarkRecord): Promise<void>;
```

### `MemoryTrustMarkStorage#revoke`

Apply the repository's revocation update to matching records.

[Source](../../../packages/core/src/trust-marks/memory.ts#L148)

```typescript signature
revoke(trustMarkType: string, subject: EntityId, revokedAt: number, issuer?: string): Promise<void>;
```

## `MemoryTrustMarkStore`

[Source](../../../packages/core/src/trust-marks/memory.ts#L171)

In-memory, process-local transaction adapter. Production hosts supply durable storage.

```typescript signature
new MemoryTrustMarkStore(): MemoryTrustMarkStore;
```

### `MemoryTrustMarkStore#trustMarks`

The adapter's Trust Mark record repository.

[Source](../../../packages/core/src/trust-marks/memory.ts#L174)

```typescript signature
readonly trustMarks: MemoryTrustMarkStorage;
```

### `MemoryTrustMarkStore#transaction`

Commit all callback writes together, or roll them back on failure. Use tx repositories only; awaiting parent queued writes inside the callback can deadlock.

[Source](../../../packages/core/src/trust-marks/memory.ts#L191)

```typescript signature
transaction<T>(operation: (tx: { trustMarks: TrustMarkStorage }) => Promise<T>): Promise<T>;
```

### `MemoryTrustMarkStore#readSnapshot`

Run reads against a consistent storage snapshot.

[Source](../../../packages/core/src/trust-marks/memory.ts#L206)

```typescript signature
readSnapshot<T>(operation: (snapshot: {
			trustMarks: Pick<TrustMarkStorage, "listCandidates" | "getByJwt">;
		}) => Promise<T>): Promise<T>;
```

## `OutOfBandTrustMarkIssuer`

[Source](../../../packages/core/src/trust-marks/evidence.ts#L53)

Independently trusted issuer configuration supplied by the host, not discovered from an unverified mark.

```typescript signature
interface OutOfBandTrustMarkIssuer {
	readonly kind: "out-of-band";
	readonly issuer: string;
	readonly allowedTrustMarkTypes: readonly string[];
	readonly keys: JWKSet;
	readonly trustMarkOwners?: Readonly<Record<string, TrustMarkOwner>>;
	/** Independently trusted endpoint metadata, never taken from the submitted token. */
	readonly metadata?: FederationEntityMetadata;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `kind` | `"out-of-band"` | Discriminator selecting the evidence or acquisition mode. |
| `issuer` | `string` | Issuer identity for the signed artifact or configured service. |
| `allowedTrustMarkTypes` | `readonly string[]` | Trust Mark types explicitly allowed for this out-of-band issuer. |
| `keys` | `JWKSet` | Public keys in the set; metadata sets may be empty, while Federation signing-key sets require at least one key. |
| `trustMarkOwners?` | `Readonly<Record<string, TrustMarkOwner>>` | Trusted owner identity and keys indexed by Trust Mark type. |
| `metadata?` | `FederationEntityMetadata` | Entity metadata indexed by Entity Type Identifier. Publication may be partial; effective metadata is checked after policy. |

## `RemoveTrustMarkSelector`

[Source](../../../packages/core/src/trust-marks/holder.ts#L19)

Selects published Trust Mark references to remove from a holder.

```typescript signature
type RemoveTrustMarkSelector = {
	readonly jwt: string;
} | {
	readonly issuer: string;
	readonly trustMarkType: string;
};
```

## `signTrustMark`

[Source](../../../packages/core/src/trust-marks/sign.ts#L72)

Sign a Trust Mark without starting an issuer server. Accreditation is host policy.

```typescript signature
signTrustMark(options: SignTrustMarkOptions): Promise<string>;
```

## `signTrustMarkDelegation`

[Source](../../../packages/core/src/trust-marks/sign.ts#L84)

Owner-signed issuance authorization. The base delegation typ cannot be overridden.

```typescript signature
signTrustMarkDelegation(options: SignTrustMarkDelegationOptions): Promise<string>;
```

## `SignTrustMarkDelegationOptions`

[Source](../../../packages/core/src/trust-marks/sign.ts#L14)

Signing and extension settings for an owner's delegation JWT.

```typescript signature
interface SignTrustMarkDelegationOptions extends TrustMarkLifetime {
	readonly issuer: string;
	readonly subject: string;
	readonly trustMarkType: string;
	readonly signer: JwtSigner;
	readonly clock?: Clock;
	readonly ref?: string;
	readonly additionalClaims?: Readonly<Record<string, unknown>>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuer` | `string` | Issuer identity for the signed artifact or configured service. |
| `subject` | `string` | Subject identity for the statement, mark, or authentication being processed. |
| `trustMarkType` | `string` | Trust Mark type identifier used for issuance, verification, or filtering. |
| `signer` | `JwtSigner` | Signing capability and its public algorithm/key identifier. Private-key custody stays with the implementation. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `ref?` | `string` | Reference URL for the Trust Mark or its delegation. |
| `additionalClaims?` | `Readonly<Record<string, unknown>>` | Additional JSON claims. The owning builder rejects collisions with its reserved claims. |
| `ttlSeconds?` | `number` | Lifetime in seconds; the owning builder defines the default and whether fractions are accepted. |
| `noExpiry?` | `boolean` | Omit exp when true; cannot be combined with ttlSeconds. |

## `SignTrustMarkOptions`

[Source](../../../packages/core/src/trust-marks/sign.ts#L23)

Signing and extension settings for a Trust Mark JWT.

```typescript signature
interface SignTrustMarkOptions extends SignTrustMarkDelegationOptions {
	readonly logoUri?: string;
	readonly delegation?: string;
	readonly typ?: string;
	readonly trustMarkProfiles?: readonly TrustMarkProfile[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `logoUri?` | `string` | Optional logo URL written as logo_uri in the Trust Mark. |
| `delegation?` | `string` | Owner-signed delegation JWT authorizing the Trust Mark Issuer. |
| `typ?` | `string` | JWT type; the owning signer or verifier determines which profile types are allowed. |
| `trustMarkProfiles?` | `readonly TrustMarkProfile[]` | Explicitly recognized framework JWT types and their optional claim-validation policies. |
| `issuer` | `string` | Issuer identity for the signed artifact or configured service. |
| `subject` | `string` | Subject identity for the statement, mark, or authentication being processed. |
| `trustMarkType` | `string` | Trust Mark type identifier used for issuance, verification, or filtering. |
| `signer` | `JwtSigner` | Signing capability and its public algorithm/key identifier. Private-key custody stays with the implementation. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `ref?` | `string` | Reference URL for the Trust Mark or its delegation. |
| `additionalClaims?` | `Readonly<Record<string, unknown>>` | Additional JSON claims. The owning builder rejects collisions with its reserved claims. |
| `ttlSeconds?` | `number` | Lifetime in seconds; the owning builder defines the default and whether fractions are accepted. |
| `noExpiry?` | `boolean` | Omit exp when true; cannot be combined with ttlSeconds. |

## `TrustMarkDelegationIssuanceOptions`

[Source](../../../packages/core/src/trust-marks/sign.ts#L92)

Lifetime and extension claims used when issuing an owner delegation.

```typescript signature
type TrustMarkDelegationIssuanceOptions = Omit<
	SignTrustMarkDelegationOptions,
	"issuer" | "subject" | "trustMarkType" | "signer" | "clock"
>;
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `ref?` | `string` | Reference URL for the Trust Mark or its delegation. |
| `additionalClaims?` | `Readonly<Record<string, unknown>>` | Additional JSON claims. The owning builder rejects collisions with its reserved claims. |
| `ttlSeconds?` | `number` | Lifetime in seconds; the owning builder defines the default and whether fractions are accepted. |
| `noExpiry?` | `boolean` | Omit exp when true; cannot be combined with ttlSeconds. |

## `TrustMarkHolder`

[Source](../../../packages/core/src/trust-marks/holder.ts#L30)

Serializes publication mutations; a failed publisher leaves the prior references intact.

```typescript signature
new TrustMarkHolder(subject: string, refs: readonly TrustMarkRef[], publish: (references: readonly TrustMarkRef[]) => Promise<void>): TrustMarkHolder;
```

### `TrustMarkHolder#getTrustMarks`

Read the holder's currently published Trust Mark references as an independent snapshot.

[Source](../../../packages/core/src/trust-marks/holder.ts#L41)

```typescript signature
getTrustMarks(): TrustMarkRef[];
```

### `TrustMarkHolder#updatePublication`

Notify the owning host that Trust Mark publication changed.

[Source](../../../packages/core/src/trust-marks/holder.ts#L44)

```typescript signature
updatePublication<T>(operation: () => Promise<T>): Promise<T>;
```

### `TrustMarkHolder#attachTrustMark`

Validate a received mark for this holder before updating its publication.

[Source](../../../packages/core/src/trust-marks/holder.ts#L57)

```typescript signature
attachTrustMark(jwt: string, options: AttachTrustMarkOptions): Promise<void>;
```

### `TrustMarkHolder#fetchAndAttachTrustMark`

Retrieve a mark using verified issuer context, validate it, and attach it to the holder on success.

[Source](../../../packages/core/src/trust-marks/holder.ts#L91)

```typescript signature
fetchAndAttachTrustMark(input: FetchAndAttachTrustMarkOptions): Promise<void>;
```

### `TrustMarkHolder#removeTrustMark`

Remove a matching reference from future holder publication. This does not revoke the issuer's accreditation record.

[Source](../../../packages/core/src/trust-marks/holder.ts#L118)

```typescript signature
removeTrustMark(selector: RemoveTrustMarkSelector): Promise<void>;
```

## `TrustMarkIssuanceOptions`

[Source](../../../packages/core/src/trust-marks/issuer.ts#L34)

Claims, lifetime, and renewal choices for issuing a Trust Mark.

```typescript signature
interface TrustMarkIssuanceOptions extends TrustMarkLifetime {
	readonly renewal?: "reuse" | "renew";
	readonly logoUri?: string;
	readonly ref?: string;
	readonly additionalClaims?: Readonly<Record<string, unknown>>;
	readonly typ?: string;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `renewal?` | `"reuse" \| "renew"` | reuse returns an eligible matching stored mark when possible; renew creates a new issuance. |
| `logoUri?` | `string` | Optional logo URL written as logo_uri in the Trust Mark. |
| `ref?` | `string` | Reference URL for the Trust Mark or its delegation. |
| `additionalClaims?` | `Readonly<Record<string, unknown>>` | Additional JSON claims. The owning builder rejects collisions with its reserved claims. |
| `typ?` | `string` | JWT type; the owning signer or verifier determines which profile types are allowed. |
| `ttlSeconds?` | `number` | Lifetime in seconds; the owning builder defines the default and whether fractions are accepted. |
| `noExpiry?` | `boolean` | Omit exp when true; cannot be combined with ttlSeconds. |

## `TrustMarkIssuerConfig`

[Source](../../../packages/core/src/trust-marks/issuer.ts#L65)

Keys, storage, lifetime defaults, delegations, and policies for a Trust Mark Issuer.

```typescript signature
interface TrustMarkIssuerConfig {
	readonly trustMarkRequestExtensions?: Readonly<Record<string, TrustMarkRequestExtension>>;
	readonly storage: TrustMarkStore;
	readonly authentication?: Omit<EndpointAuthenticationConfig, "receiverEntityId" | "methods">;
	readonly defaults?: TrustMarkIssuanceOptions;
	readonly trustMarkSigner?: (
		context: Readonly<{ issuer: string; subject: string; trustMarkType: string }>,
	) => JwtSigner | Promise<JwtSigner>;
	readonly trustMarkDefaults?: Readonly<Record<string, TrustMarkIssuanceOptions>>;
	readonly delegations?: Readonly<Record<string, string>>;
	/** Independent issuer trust supplies owner keys for delegated issuance. */
	readonly issuerEvidence?: readonly TrustMarkIssuerContext[];
	readonly trustMarkStatusPolicy?: TrustMarkStatusPolicy;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `trustMarkRequestExtensions?` | `Readonly<Record<string, TrustMarkRequestExtension>>` | Host validators for additional request parameters; unknown extension parameters are ignored. |
| `storage` | `TrustMarkStore` | Transactional Trust Mark storage adapter. |
| `authentication?` | `Omit<EndpointAuthenticationConfig, "receiverEntityId" \| "methods">` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `defaults?` | `TrustMarkIssuanceOptions` | Issuer-wide issuance defaults, overridden by per-type settings and then per-call options. |
| `trustMarkSigner?` | `( context: Readonly<{ issuer: string; subject: string; trustMarkType: string }>, ) => JwtSigner \| Promise<JwtSigner>` | Host callback selecting the signing capability for one Trust Mark issuance. |
| `trustMarkDefaults?` | `Readonly<Record<string, TrustMarkIssuanceOptions>>` | Per-type issuance defaults, overriding issuer-wide defaults. |
| `delegations?` | `Readonly<Record<string, string>>` | Delegation JWTs indexed by Trust Mark type; setting them alone does not authenticate owner trust. |
| `issuerEvidence?` | `readonly TrustMarkIssuerContext[]` | Previously established federation issuer evidence or explicit host out-of-band trust. |
| `trustMarkStatusPolicy?` | `TrustMarkStatusPolicy` | Optional host status policy; it cannot reactivate an ineligible or revoked record. |

## `trustMarkIssuerContext`

[Source](../../../packages/core/src/trust-marks/evidence.ts#L216)

Check evidence each time it is used; plain JSON cannot impersonate a validated issuer chain.

```typescript signature
trustMarkIssuerContext(context: TrustMarkIssuerContext, type: string, options?: FederationOptions): Result<{
	issuer: string;
	keys: JWKSet;
	owners: Record<string, TrustMarkOwner>;
	metadata?: FederationEntityMetadata;
	expiresAt?: number;
}>;
```

## `TrustMarkIssuerContext`

[Source](../../../packages/core/src/trust-marks/evidence.ts#L62)

Issuer identity and authenticated evidence used to verify its marks.

```typescript signature
type TrustMarkIssuerContext = FederationTrustMarkIssuerEvidence | OutOfBandTrustMarkIssuer;
```

## `TrustMarkIssuerService`

[Source](../../../packages/core/src/trust-marks/issuer.ts#L128)

Shared managed issuance and eligibility for Leaf and Authority hosts.

```typescript signature
new TrustMarkIssuerService(config: TrustMarkIssuerServiceOptions): TrustMarkIssuerService;
```

### `TrustMarkIssuerService#issuer`

The issuer identifier bound to this service.

[Source](../../../packages/core/src/trust-marks/issuer.ts#L129)

```typescript signature
readonly issuer: EntityId;
```

### `TrustMarkIssuerService#updatePolicy`

Update the issuer service's policy through its validated configuration boundary.

[Source](../../../packages/core/src/trust-marks/issuer.ts#L221)

```typescript signature
updatePolicy(owners: Readonly<Record<string, TrustMarkOwner>>, issuers?: Readonly<Record<string, readonly string[]>>): void;
```

### `TrustMarkIssuerService#setDelegations`

Replace this issuer service's delegation map after configuration-shape checks. Setting the map alone does not verify its JWT signatures or establish owner trust.

[Source](../../../packages/core/src/trust-marks/issuer.ts#L229)

```typescript signature
setDelegations(delegations: Readonly<Record<string, string>>): Promise<void>;
```

### `TrustMarkIssuerService#eligibility`

Evaluate stored-mark eligibility against lifetime, delegation, and issuer state.

[Source](../../../packages/core/src/trust-marks/issuer.ts#L239)

```typescript signature
eligibility(record: TrustMarkRecord, at?: number): Promise<string>;
```

### `TrustMarkIssuerService#listTrustMarksForSubject`

List eligible marks issued for the subject under this issuer's state.

[Source](../../../packages/core/src/trust-marks/issuer.ts#L304)

```typescript signature
listTrustMarksForSubject(subject: string): Promise<TrustMarkRecord[]>;
```

### `TrustMarkIssuerService#getTrustMark`

Retrieve an eligible, already-issued mark for the requested subject and type.

[Source](../../../packages/core/src/trust-marks/issuer.ts#L311)

```typescript signature
getTrustMark(subject: string, type: string): Promise<string | undefined>;
```

### `TrustMarkIssuerService#listTrustMarkedEntities`

List subjects currently eligible for the requested mark type.

[Source](../../../packages/core/src/trust-marks/issuer.ts#L316)

```typescript signature
listTrustMarkedEntities(type: string, subject?: string): Promise<string[]>;
```

### `TrustMarkIssuerService#revokeTrustMark`

Revoke matching active issuer records for the type and subject.

[Source](../../../packages/core/src/trust-marks/issuer.ts#L328)

```typescript signature
revokeTrustMark(type: string, subject: string): Promise<void>;
```

### `TrustMarkIssuerService#issueTrustMark`

Issue or reuse a stored mark according to the issuer's policy and requested renewal/lifetime options.

[Source](../../../packages/core/src/trust-marks/issuer.ts#L357)

```typescript signature
issueTrustMark(subject: string, type: string, requested?: TrustMarkIssuanceOptions): Promise<string>;
```

### `TrustMarkIssuerService#handleRequest`

Handle a Web API Request and return the protocol Response. The application supplies external HTTPS routing.

[Source](../../../packages/core/src/trust-marks/issuer.ts#L489)

```typescript signature
handleRequest(kind: "status" | "list" | "retrieval", request: Request): Promise<Response>;
```

### `TrustMarkIssuerService#assessTrustMarkStatus`

Assess current status without signing; unknown instances have no assessment.

[Source](../../../packages/core/src/trust-marks/issuer.ts#L542)

```typescript signature
assessTrustMarkStatus(jwt: string): Promise<TrustMarkStatusAssessment | undefined>;
```

### `TrustMarkIssuerService#statusResponse`

Build the issuer's signed status response from authoritative mark eligibility and any configured status policy.

[Source](../../../packages/core/src/trust-marks/issuer.ts#L631)

```typescript signature
statusResponse(jwt: string): Promise<string | undefined>;
```

## `TrustMarkIssuerServiceOptions`

[Source](../../../packages/core/src/trust-marks/issuer.ts#L79)

HTTP endpoint and authentication settings for a hosted Trust Mark Issuer service.

```typescript signature
interface TrustMarkIssuerServiceOptions extends TrustMarkIssuerConfig {
	readonly issuer: string;
	readonly statusEndpointPublished?: boolean;
	readonly keyProvider: FederationKeyProvider;
	readonly options?: FederationOptions;
	/** Local Trust Anchor policy; do not populate from unverified token claims. */
	readonly trustMarkOwners?: Readonly<Record<string, TrustMarkOwner>>;
	readonly trustMarkIssuers?: Readonly<Record<string, readonly string[]>>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuer` | `string` | Issuer identity for the signed artifact or configured service. |
| `statusEndpointPublished?` | `boolean` | Whether the issuer advertises a Status endpoint, used for non-expiring-mark guidance. |
| `keyProvider` | `FederationKeyProvider` | Provider of current Federation Entity Keys and the active signer. |
| `options?` | `FederationOptions` | Shared federation transport and validation settings for this operation. |
| `trustMarkOwners?` | `Readonly<Record<string, TrustMarkOwner>>` | Trusted owner identity and keys indexed by Trust Mark type. |
| `trustMarkIssuers?` | `Readonly<Record<string, readonly string[]>>` | Permitted issuer identities indexed by Trust Mark type; an empty array allows any issuer under the applicable policy. |
| `trustMarkRequestExtensions?` | `Readonly<Record<string, TrustMarkRequestExtension>>` | Host validators for additional request parameters; unknown extension parameters are ignored. |
| `storage` | `TrustMarkStore` | Transactional Trust Mark storage adapter. |
| `authentication?` | `Omit<EndpointAuthenticationConfig, "receiverEntityId" \| "methods">` | Authentication settings for the endpoint or outgoing request described by this contract. |
| `defaults?` | `TrustMarkIssuanceOptions` | Issuer-wide issuance defaults, overridden by per-type settings and then per-call options. |
| `trustMarkSigner?` | `( context: Readonly<{ issuer: string; subject: string; trustMarkType: string }>, ) => JwtSigner \| Promise<JwtSigner>` | Host callback selecting the signing capability for one Trust Mark issuance. |
| `trustMarkDefaults?` | `Readonly<Record<string, TrustMarkIssuanceOptions>>` | Per-type issuance defaults, overriding issuer-wide defaults. |
| `delegations?` | `Readonly<Record<string, string>>` | Delegation JWTs indexed by Trust Mark type; setting them alone does not authenticate owner trust. |
| `issuerEvidence?` | `readonly TrustMarkIssuerContext[]` | Previously established federation issuer evidence or explicit host out-of-band trust. |
| `trustMarkStatusPolicy?` | `TrustMarkStatusPolicy` | Optional host status policy; it cannot reactivate an ineligible or revoked record. |

## `TrustMarkLifetime`

[Source](../../../packages/core/src/trust-marks/sign.ts#L10)

The choice between an expiring Trust Mark and one without an `exp` claim.

```typescript signature
interface TrustMarkLifetime {
	readonly ttlSeconds?: number;
	readonly noExpiry?: boolean;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `ttlSeconds?` | `number` | Lifetime in seconds; the owning builder defines the default and whether fractions are accepted. |
| `noExpiry?` | `boolean` | Omit exp when true; cannot be combined with ttlSeconds. |

## `TrustMarkListOptions`

[Source](../../../packages/core/src/trust-marks/storage.ts#L3)

Selectors and paging settings for reading an issuer's stored marks.

```typescript signature
interface TrustMarkListOptions {
	readonly subject?: EntityId;
	/** Subject of the first unreturned record; inclusive. */
	readonly cursor?: EntityId;
	readonly limit: number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `subject?` | `EntityId` | Subject identity for the statement, mark, or authentication being processed. |
| `cursor?` | `EntityId` | Subject of the first unreturned record; inclusive. |
| `limit` | `number` | Requested maximum number of entries on a page. |

## `TrustMarkListPage`

[Source](../../../packages/core/src/trust-marks/storage.ts#L10)

One page of stored Trust Mark records and its continuation information.

```typescript signature
interface TrustMarkListPage {
	readonly items: TrustMarkRecord[];
	readonly nextCursor?: EntityId;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `items` | `TrustMarkRecord[]` | Stored Trust Mark records returned on this page. |
| `nextCursor?` | `EntityId` | Continuation cursor for the next stored-record page, when one exists. |

## `TrustMarkProfile`

[Source](../../../packages/core/src/trust-marks/profiles.ts#L6)

An explicitly recognized framework JWT type, scoped to its Trust Mark types.

```typescript signature
interface TrustMarkProfile {
	readonly typ: string;
	readonly trustMarkTypes: readonly string[];
	readonly validateClaims?: (
		claims: Readonly<Record<string, unknown>>,
	) => Result<void> | Promise<Result<void>>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `typ` | `string` | Recognized framework Trust Mark JWT typ; delegation JWT types cannot be registered here. |
| `trustMarkTypes` | `readonly string[]` | Trust Mark type identifiers explicitly covered by this framework profile. |
| `validateClaims?` | `( claims: Readonly<Record<string, unknown>>, ) => Result<void> \| Promise<Result<void>>` | Host framework claim validation after base Trust Mark checks; return false or a failing Result to reject. |

## `TrustMarkRecord`

[Source](../../../packages/core/src/trust-marks/storage.ts#L58)

Stored fields mirror the signed JWT's type, subject, iat, and optional exp.
Ingestion establishes the JWT's signature and issuer trust before storing it.

```typescript signature
interface TrustMarkRecord {
	readonly trustMarkType: string;
	readonly subject: EntityId;
	readonly jwt: string;
	readonly issuedAt: number;
	readonly expiresAt?: number;
	readonly active: boolean;
	readonly revokedAt?: number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `trustMarkType` | `string` | Trust Mark type identifier used for issuance, verification, or filtering. |
| `subject` | `EntityId` | Subject identity for the statement, mark, or authentication being processed. |
| `jwt` | `string` | Compact JWT string retained or supplied for this operation. |
| `issuedAt` | `number` | Issuance time as a NumericDate in seconds. |
| `expiresAt?` | `number` | Expiration or eligibility deadline as a NumericDate in seconds; the owning API defines the evidence it bounds. |
| `active` | `boolean` | Whether the issuer's local record remains active. |
| `revokedAt?` | `number` | NumericDate when the issuer recorded revocation. |

## `TrustMarkRequestContext`

[Source](../../../packages/core/src/trust-marks/issuer.ts#L55)

Request and authentication information supplied to a Trust Mark endpoint extension.

```typescript signature
interface TrustMarkRequestContext {
	readonly endpoint: "status" | "list" | "retrieval";
	readonly issuer: string;
	readonly caller?: string;
	readonly parameters: Readonly<Record<string, readonly string[]>>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `endpoint` | `"status" \| "list" \| "retrieval"` | Serving or remote endpoint URL; request extension contexts use status, list, or retrieval instead. |
| `issuer` | `string` | Issuer identity for the signed artifact or configured service. |
| `caller?` | `string` | Authenticated caller Entity Identifier, when authentication succeeded. |
| `parameters` | `Readonly<Record<string, readonly string[]>>` | Form parameter names or values supplied to this authentication or extension contract. |

## `TrustMarkRequestExtension`

[Source](../../../packages/core/src/trust-marks/issuer.ts#L61)

A host-defined extension for a Trust Mark request parameter.

```typescript signature
type TrustMarkRequestExtension = (
	values: readonly string[],
	context: Readonly<TrustMarkRequestContext>,
) => Result<void> | Promise<Result<void>>;
```

## `TrustMarkRequirements`

[Source](../../../packages/core/src/trust-marks/requirements.ts#L11)

Application accreditation requirements, applied after Federation chain validation.

```typescript signature
interface TrustMarkRequirements {
	readonly requiredTypes?: readonly string[];
	readonly requireAllPublished?: boolean;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `requiredTypes?` | `readonly string[]` | Trust Mark types for which the caller requires currently usable verified evidence. |
| `requireAllPublished?` | `boolean` | Require every published Trust Mark to be verified, in addition to any required type list. |

## `TrustMarkStatusAssessment`

[Source](../../../packages/core/src/trust-marks/issuer.ts#L41)

A Trust Mark Status response payload and its verification deadline.

```typescript signature
interface TrustMarkStatusAssessment {
	readonly payload: Readonly<TrustMarkStatusResponsePayload>;
	readonly verificationExpiresAt?: number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `payload` | `Readonly<TrustMarkStatusResponsePayload>` | Decoded claims; their verification state is determined by the enclosing result. |
| `verificationExpiresAt?` | `number` | Deadline of the evidence supporting verification, which can precede the signed token's exp. |

## `TrustMarkStatusPolicy`

[Source](../../../packages/core/src/trust-marks/issuer.ts#L49)

A callback through which the issuer applies its own status policy.

```typescript signature
type TrustMarkStatusPolicy = (context: TrustMarkStatusPolicyContext) => {
	readonly status: string;
	readonly additionalClaims?: Readonly<Record<string, unknown>>;
} | Promise<{
	readonly status: string;
	readonly additionalClaims?: Readonly<Record<string, unknown>>;
}>;
```

## `TrustMarkStatusPolicyContext`

[Source](../../../packages/core/src/trust-marks/issuer.ts#L45)

The mark and base status supplied to the issuer's status policy.

```typescript signature
interface TrustMarkStatusPolicyContext {
	readonly baseStatus: string;
	readonly record: Readonly<TrustMarkRecord>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `baseStatus` | `string` | Status determined from authoritative issuer records before applying the optional host policy. |
| `record` | `Readonly<TrustMarkRecord>` | Stored issuance record supplied to the status policy as detached read-only evidence. |

## `TrustMarkStatusResult`

[Source](../../../packages/core/src/trust-marks/fetch.ts#L122)

A mark's status together with the information returned by the status operation.

```typescript signature
interface TrustMarkStatusResult {
	jwt: string;
	claims: Readonly<Record<string, unknown>>;
	verificationExpiresAt?: number;
	/** Additional status strings are permitted by Federation §8.4.2. */
	status: string;
	issuer: EntityId;
	issuedAt: number;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `jwt` | `string` | Compact JWT string retained or supplied for this operation. |
| `claims` | `Readonly<Record<string, unknown>>` | Claims associated with the artifact or selected for this operation. |
| `verificationExpiresAt?` | `number` | Deadline of the evidence supporting verification, which can precede the signed token's exp. |
| `status` | `string` | Reported mark status; active is the interoperable positive value, while other strings may be profile-defined. |
| `issuer` | `EntityId` | Issuer identity for the signed artifact or configured service. |
| `issuedAt` | `number` | Issuance time as a NumericDate in seconds. |

## `TrustMarkStorage`

[Source](../../../packages/core/src/trust-marks/storage.ts#L23)

Current-validity queries require active marks with finite issuedAt <= validAt
and either no expiration or expiresAt > validAt. An embedded delegation must
also be decodable, have finite iat <= validAt, and have no exp or exp > validAt.
Apply this eligibility before selecting the newest mark, using exact issuer time
without added clock leeway. See isStoredTrustMarkEligible for the shared predicate.
Ingestion, not this time filter, establishes signature and issuer trust.

```typescript signature
interface TrustMarkStorage {
	/** Return every candidate, including revoked records, before service-level eligibility and newest-record selection. Return detached records from one consistent view. */
	listCandidates(filter: {
		readonly issuer: string;
		readonly trustMarkType?: string;
		readonly subject?: EntityId;
	}): Promise<TrustMarkRecord[]>;
	getValid(
		trustMarkType: string,
		subject: EntityId,
		validAt: number,
	): Promise<TrustMarkRecord | undefined>;
	/** Return a detached record, including revoked or expired records when present. */
	getByJwt(jwt: string): Promise<TrustMarkRecord | undefined>;
	listValid(
		trustMarkType: string,
		validAt: number,
		options: TrustMarkListOptions,
	): Promise<TrustMarkListPage>;
	listValidForSubject(subject: EntityId, validAt: number): Promise<TrustMarkRecord[]>;
	hasAnyValid(subject: EntityId, validAt: number): Promise<boolean>;
	/** Capture input before asynchronous work. Reissuing the same JWT must not replace its record. */
	issue(record: TrustMarkRecord): Promise<void>;
	revoke(
		trustMarkType: string,
		subject: EntityId,
		revokedAt: number,
		issuer?: string,
	): Promise<void>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `listCandidates` | `(filter: { readonly issuer: string; readonly trustMarkType?: string; readonly subject?: EntityId; }) => Promise<TrustMarkRecord[]>` | Return every candidate, including revoked records, before service-level eligibility and newest-record selection. Return detached records from one consistent view. |
| `getValid` | `(trustMarkType: string, subject: EntityId, validAt: number) => Promise<TrustMarkRecord \| undefined>` | Return the newest eligible record for this type and subject at validAt. |
| `getByJwt` | `(jwt: string) => Promise<TrustMarkRecord \| undefined>` | Return a detached record, including revoked or expired records when present. |
| `listValid` | `(trustMarkType: string, validAt: number, options: TrustMarkListOptions) => Promise<TrustMarkListPage>` | Page through eligible records for the type at validAt. |
| `listValidForSubject` | `(subject: EntityId, validAt: number) => Promise<TrustMarkRecord[]>` | Return eligible records for the subject at validAt. |
| `hasAnyValid` | `(subject: EntityId, validAt: number) => Promise<boolean>` | Report whether any record for the subject is eligible at validAt. |
| `issue` | `(record: TrustMarkRecord) => Promise<void>` | Capture input before asynchronous work. Reissuing the same JWT must not replace its record. |
| `revoke` | `(trustMarkType: string, subject: EntityId, revokedAt: number, issuer?: string) => Promise<void>` | Revoke matching active issuer records; retain history for status responses. |

## `TrustMarkStore`

[Source](../../../packages/core/src/trust-marks/storage.ts#L69)

Atomic write and consistent read boundary shared by Leaf and Authority issuers.

```typescript signature
interface TrustMarkStore {
	readonly trustMarks: TrustMarkStorage;
	/** Commit all callback writes together, or roll them back on failure. Use tx repositories only; awaiting parent queued writes inside the callback can deadlock. */
	transaction<T>(
		operation: (tx: { readonly trustMarks: TrustMarkStorage }) => Promise<T>,
	): Promise<T>;
	readSnapshot<T>(
		operation: (snapshot: {
			readonly trustMarks: Pick<TrustMarkStorage, "listCandidates" | "getByJwt">;
		}) => Promise<T>,
	): Promise<T>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `trustMarks` | `TrustMarkStorage` | Trust Mark references, verified marks, or evaluations supplied by the owning contract. |
| `transaction` | `<T>(operation: (tx: { readonly trustMarks: TrustMarkStorage; }) => Promise<T>) => Promise<T>` | Commit all callback writes together, or roll them back on failure. Use tx repositories only; awaiting parent queued writes inside the callback can deadlock. |
| `readSnapshot` | `<T>(operation: (snapshot: { readonly trustMarks: Pick<TrustMarkStorage, "listCandidates" \| "getByJwt">; }) => Promise<T>) => Promise<T>` | Run reads against one consistent view without accepting writes. |

## `TrustMarkValidationOptions`

[Source](../../../packages/core/src/trust-marks/index.ts#L24)

Expected identities, time policy, and delegation settings for validating a mark.

```typescript signature
interface TrustMarkValidationOptions extends FederationOptions {
	trustMarkOwners?: Record<string, TrustMarkOwner>;
	/** Entity whose configuration contains this mark; supply independently of the JWT (§7.3). */
	expectedSubject: string;
	expectedTrustMarkType?: string;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `trustMarkOwners?` | `Record<string, TrustMarkOwner>` | Trusted owner identity and keys indexed by Trust Mark type. |
| `expectedSubject` | `string` | Subject identity that must match the verified payload. |
| `expectedTrustMarkType?` | `string` | Trust Mark type that must match the verified payload. |
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

## `TrustMarkVerificationOptions`

[Source](../../../packages/core/src/trust-marks/evidence.ts#L70)

Issuer evidence, accreditation anchors, resolution mode, and historical-key settings for published marks.

```typescript signature
interface TrustMarkVerificationOptions {
	readonly mode?: "provided" | "resolve";
	readonly issuerEvidence?: readonly TrustMarkIssuerContext[];
	readonly trustAnchors?: TrustAnchorSet;
	readonly historicalKeys?: HistoricalTrustMarkOptions;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `mode?` | `"provided" \| "resolve"` | Discriminator selecting the configured policy or acquisition behavior. |
| `issuerEvidence?` | `readonly TrustMarkIssuerContext[]` | Previously established federation issuer evidence or explicit host out-of-band trust. |
| `trustAnchors?` | `TrustAnchorSet` | Independently trusted anchor identities and their public Federation Entity Keys. |
| `historicalKeys?` | `HistoricalTrustMarkOptions` | Historical-key source and freshness policy; signature failures do not trigger a historical-key retry. |

## `validateTrustMark`

[Source](../../../packages/core/src/trust-marks/index.ts#L46)

Validate a Trust Mark using the supplied issuer keys and owner/issuer policy. This low-level call does not discover accreditation trust for you.

```typescript signature
validateTrustMark(trustMarkJwt: string, trustMarkIssuers: Record<string, string[]>, issuerJwks: JWKSet, options: TrustMarkValidationOptions): Promise<Result<TrustMarkEvidence, FederationError>>;
```

## `validateTrustMarkLogo`

[Source](../../../packages/core/src/trust-marks/logo.ts#L20)

Fetch an HTTPS logo URL and check for a successful HTTP response whose media type begins with `image/`. This helper does not decode image bytes, enforce a body-size limit, or establish accreditation. Non-HTTPS URLs and fragments are rejected by this helper even though the Trust Mark claim's URL syntax is broader.

```typescript signature
validateTrustMarkLogo(url: string, options?: ValidateTrustMarkLogoOptions): Promise<Result<{ contentType: string }, FederationError>>;
```

## `ValidateTrustMarkLogoOptions`

[Source](../../../packages/core/src/trust-marks/logo.ts#L18)

Controls for validating a Trust Mark's logo URI.

```typescript signature
interface ValidateTrustMarkLogoOptions extends FederationOptions {}
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

## `validateTrustMarkWithIssuer`

[Source](../../../packages/core/src/trust-marks/evidence.ts#L263)

Validate a mark with established federation issuer evidence or explicit out-of-band issuer trust, including applicable delegation and historical-key rules.

```typescript signature
validateTrustMarkWithIssuer(jwt: string, context: TrustMarkIssuerContext, input: ValidateTrustMarkWithIssuerOptions): Promise<Result<TrustMarkEvidence>>;
```

## `ValidateTrustMarkWithIssuerOptions`

[Source](../../../packages/core/src/trust-marks/evidence.ts#L259)

Expected mark type, holder, time, and historical-key settings used with issuer evidence.

```typescript signature
interface ValidateTrustMarkWithIssuerOptions extends TrustMarkValidationOptions {
	readonly expectedTrustMarkType: string;
	readonly historicalKeys?: HistoricalTrustMarkOptions;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `expectedTrustMarkType` | `string` | Trust Mark type that must match the verified payload. |
| `historicalKeys?` | `HistoricalTrustMarkOptions` | Historical-key source and freshness policy; signature failures do not trigger a historical-key retry. |
| `trustMarkOwners?` | `Record<string, TrustMarkOwner>` | Trusted owner identity and keys indexed by Trust Mark type. |
| `expectedSubject` | `string` | Subject identity that must match the verified payload. |
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

