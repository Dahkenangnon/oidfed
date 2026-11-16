# Federation hosts

[`@oidfed/leaf`](README.md)

Construct one host for an Entity Identifier and compose fresh protocol-role instances into it. Hosts accept Web API requests; the application supplies HTTPS routing and durable infrastructure. Constructor validation can throw before a handler is available.

## `Leaf`

[Source](../../../packages/leaf/src/entity-configuration.ts#L80)

Host a non-authority Federation participant: publish its Entity Configuration, compose protocol roles, and optionally serve Resolve, Entity Collection, or Trust Mark endpoints. A Leaf never issues Subordinate Statements.

Construction validates local configuration and composes detached publication metadata; it does not establish trust in a Superior or generate an EC. Requesting an uncached EC, refreshing it, or changing holder publication triggers signing. Constructor errors throw. Discovery and assessment return `Result` values; EC generation, holder mutations, and issuer operations can reject their promises.

A public property marked `readonly` cannot be reassigned through TypeScript; the referenced service may still expose its own operations. Types other than `Leaf` and `LeafConfig` in the signatures below belong to `@oidfed/core`.

```typescript signature
new Leaf(config: LeafConfig): Leaf;
```

### `Leaf#resolver`

The hosted [`FederationResolverService`](../core/chains.md#federationresolverservice), present only when `LeafConfig.resolver` is configured. It remains available for local calls even without a published Resolve endpoint; publishing that endpoint also installs its HTTP route.

[Source](../../../packages/leaf/src/entity-configuration.ts#L81)

```typescript signature
readonly resolver?: FederationResolverService;
```

### `Leaf#assessEntity`

Assess the target through local chain validation or an explicitly trusted resolver, using the core [`assessEntity`](../core/chains.md#assessentity) contract. Per-call options override host options. Anchors come from the call's `trustAnchors`, then `LeafConfig.trustAnchors`, then an empty set. A successful assessment is evidence, not application authorization.

[Source](../../../packages/leaf/src/entity-configuration.ts#L87)

```typescript signature
assessEntity(target: EntityId, options?: EntityAssessmentOptions & {
	trustAnchors?: TrustAnchorSet;
}): Promise<import("@oidfed/core").Result<import("@oidfed/core").EntityAssessment>>;
```

### `Leaf#discoverEntity`

Discover and validate candidate chains for the target, then apply the configured chain selector or the default shortest-chain selection. Per-call options override host options. Anchors come from the call, then the host configuration, then an empty set. Handle the returned `Result` before using its discovery evidence. This method performs local chain discovery; use `assessEntity` to choose a trusted-resolver mode.

[Source](../../../packages/leaf/src/entity-configuration.ts#L99)

```typescript signature
discoverEntity(target: EntityId, options?: FederationOptions & {
	trustAnchors?: TrustAnchorSet;
}): Promise<import("@oidfed/core").Result<import("@oidfed/core").DiscoveryResult>>;
```

### `Leaf#discoverEntityFromChain`

Validate supplied leaf-first compact Entity Statements for the exact target and return a branded discovery result on success. Read-only chain arrays are accepted. Options and anchors follow the same per-call-over-host precedence as `discoverEntity`. Supplied statements do not imply offline operation: validation can retrieve required subject ECs or issuer evidence unless configured otherwise.

[Source](../../../packages/leaf/src/entity-configuration.ts#L110)

```typescript signature
discoverEntityFromChain(target: EntityId, statements: readonly string[], options?: FederationOptions & {
	trustAnchors?: TrustAnchorSet;
}): Promise<import("@oidfed/core").Result<import("@oidfed/core").DiscoveryResult>>;
```

### `Leaf#collection`

The hosted [`EntityCollectionService`](../core/collection.md#entitycollectionservice), present only when `LeafConfig.collection` is configured. Refresh and query it explicitly. An advertised collection endpoint installs its HTTP route; construction does not automatically collect or publish a snapshot.

[Source](../../../packages/leaf/src/entity-configuration.ts#L122)

```typescript signature
readonly collection?: EntityCollectionService;
```

### `Leaf#entityId`

Entity Identifier bound to this host after removing one trailing slash from the configured value. The remaining string is validated as an HTTPS Entity Identifier; it is the identity used in newly signed ECs and the host's services.

[Source](../../../packages/leaf/src/entity-configuration.ts#L134)

```typescript signature
readonly entityId: EntityId;
```

### `Leaf#getEntityConfiguration`

Return the cached EC while it is unexpired. Otherwise, generate and sign one with the current key provider, host clock, stored publication metadata, and current holder references. Concurrent calls share the in-flight build. Key-provider, validation, or signing errors reject the promise. An unchanged cached EC can remain in use after a provider key change; call `refreshEntityConfiguration` when immediate regeneration is required.

[Source](../../../packages/leaf/src/entity-configuration.ts#L501)

```typescript signature
getEntityConfiguration(): Promise<string>;
```

### `Leaf#isEntityConfigurationExpired`

Return `true` before any EC is cached, or when the host clock reaches its cached `exp`. This checks local cache lifetime only; it does not evaluate remote revocation, fetch a new chain, or check whether the key provider changed.

[Source](../../../packages/leaf/src/entity-configuration.ts#L516)

```typescript signature
isEntityConfigurationExpired(): boolean;
```

### `Leaf#refreshEntityConfiguration`

Invalidate the cached EC and start a new build using current keys and the host's stored metadata. An older concurrent build cannot overwrite this generation's cache. The method returns a compact JWT or rejects; it does not reload metadata from the original configuration object. A failed refresh leaves the old cache invalidated.

[Source](../../../packages/leaf/src/entity-configuration.ts#L526)

```typescript signature
refreshEntityConfiguration(): Promise<string>;
```

### `Leaf#getTrustMarks`

Return a detached snapshot of the holder's currently published Trust Mark references. Initial references are included before an EC has been generated. Reading the array does not verify the JWTs or check their current status.

[Source](../../../packages/leaf/src/entity-configuration.ts#L539)

```typescript signature
getTrustMarks(): { trust_mark_type: string; trust_mark: string; }[];
```

### `Leaf#attachTrustMark`

Validate a mark for this Leaf using the explicitly supplied issuer evidence and verification options, then sign and cache an EC containing the updated holder references. Optional `same-issuer-and-type` replacement replaces prior references for that issuer/type; otherwise a distinct JWT is appended and an identical JWT is ignored. Failed validation or publication rejects and preserves the prior references. Verification options are not automatically merged with `LeafConfig.options`; EC generation still uses the host's configured keys and clock.

[Source](../../../packages/leaf/src/entity-configuration.ts#L545)

```typescript signature
attachTrustMark(jwt: string, options: AttachTrustMarkOptions): Promise<void>;
```

### `Leaf#fetchAndAttachTrustMark`

Establish issuer trust using the explicitly supplied `trustAnchors` and `options`, fetch a mark from the verified issuer's endpoint, validate it for this holder, and attach it. This method does not inherit the host's discovery anchors or transport options. EC publication uses the host configuration. A failure rejects without attaching an unverified mark.

[Source](../../../packages/leaf/src/entity-configuration.ts#L549)

```typescript signature
fetchAndAttachTrustMark(options: FetchAndAttachTrustMarkOptions): Promise<void>;
```

### `Leaf#removeTrustMark`

Remove references matching the exact JWT or issuer/type selector, then regenerate the holder's EC when publication changes. Failure to publish rejects and preserves the prior references. This changes future publication; it does not revoke the issuer's records or invalidate ECs already held by other parties.

[Source](../../../packages/leaf/src/entity-configuration.ts#L553)

```typescript signature
removeTrustMark(selector: RemoveTrustMarkSelector): Promise<void>;
```

### `Leaf#issueTrustMark`

Issue a mark for the subject, or reuse an eligible stored mark according to the requested renewal mode and issuer defaults. Requires `LeafConfig.trustMarkIssuer`; otherwise the promise rejects. The core issuer service handles signing, storage, profile, delegation, and lifetime checks. Issuing a mark does not attach it to the subject's EC.

[Source](../../../packages/leaf/src/entity-configuration.ts#L565)

```typescript signature
issueTrustMark(subject: string, type: string, options?: TrustMarkIssuanceOptions): Promise<string>;
```

### `Leaf#revokeTrustMark`

Revoke all matching active records held by this issuer for the type and subject. Requires `LeafConfig.trustMarkIssuer`. This records local issuer revocation; it does not remove the holder's published reference or erase signed JWTs already distributed.

[Source](../../../packages/leaf/src/entity-configuration.ts#L576)

```typescript signature
revokeTrustMark(type: string, subject: string): Promise<void>;
```

### `Leaf#listTrustMarksForSubject`

Return detached eligible records issued by this Leaf for the subject, evaluated using the issuer service's current state and clock. Requires `LeafConfig.trustMarkIssuer`; it does not list marks obtained by this Leaf as a holder.

[Source](../../../packages/leaf/src/entity-configuration.ts#L583)

```typescript signature
listTrustMarksForSubject(subject: string): Promise<import("@oidfed/core").TrustMarkRecord[]>;
```

### `Leaf#listTrustMarkedEntities`

Return sorted, distinct subject identifiers with eligible locally issued marks of the given type. An optional subject restricts the result. Requires `LeafConfig.trustMarkIssuer`.

[Source](../../../packages/leaf/src/entity-configuration.ts#L587)

```typescript signature
listTrustMarkedEntities(type: string, subject?: string): Promise<string[]>;
```

### `Leaf#setTrustMarkDelegations`

Replace this issuer's delegation map with a detached, frozen copy after checking that it is JSON object data containing string values. Requires `LeafConfig.trustMarkIssuer`. Setting the map does not itself authenticate the owner's JWTs; issuance and eligibility checks apply the cryptographic and lifetime rules. It does not change holder references or automatically regenerate the EC.

[Source](../../../packages/leaf/src/entity-configuration.ts#L594)

```typescript signature
setTrustMarkDelegations(delegations: Readonly<Record<string, string>>): Promise<void>;
```

### `Leaf#handleRequest`

Dispatch by URL path to a composed role or configured service route, then to this Leaf's well-known EC path. EC discovery accepts GET, returns HTTP 200 with `application/entity-statement+jwt`, and converts EC generation failures to a generic HTTP 500 response. Unsupported methods receive 405 and unknown paths receive 404. Composed handlers retain their own error behavior and can reject. The application supplies external HTTPS routing.

[Source](../../../packages/leaf/src/entity-configuration.ts#L599)

```typescript signature
handleRequest(request: Request): Promise<Response>;
```

### `Leaf.assessEntity`

Static alias of core [`assessEntity`](../core/chains.md#assessentity). Supply anchors and options explicitly; no Leaf instance or host configuration is consulted. The first declaration below describes the callable property, followed by its call signature.

[Source](../../../packages/leaf/src/entity-configuration.ts#L83)

```typescript signature
static assessEntity: typeof assessEntity;
```

Callable signature:

```typescript signature
Leaf.assessEntity(subject: EntityId, anchors: TrustAnchorSet, options?: EntityAssessmentOptions): Promise<Result<EntityAssessment>>;
```

### `Leaf.discoverEntityFromChain`

Static alias of core [`discoverEntityFromChain`](../core/chains.md#discoverentityfromchain). It accepts a read-only chain array and explicit trust inputs, without constructing a Leaf or inheriting host options. The property declaration and call signature are both shown.

[Source](../../../packages/leaf/src/entity-configuration.ts#L85)

```typescript signature
static discoverEntityFromChain: typeof discoverEntityFromChain;
```

Callable signature:

```typescript signature
Leaf.discoverEntityFromChain(entityId: EntityId, statements: readonly string[], trustAnchors: TrustAnchorSet, options?: FederationOptions): Promise<Result<DiscoveryResult>>;
```

### `Leaf.discoverEntity`

Static convenience wrapper around core discovery. It accepts a string or branded Entity Identifier, validates the target through `entityId`, and uses only the explicitly supplied anchors and options. Invalid target identifiers throw synchronously before discovery starts; discovery outcomes otherwise use the returned `Result`.

[Source](../../../packages/leaf/src/entity-configuration.ts#L126)

```typescript signature
static discoverEntity(targetEntityId: EntityId | string, trustAnchors: TrustAnchorSet, options?: FederationOptions): Promise<import("@oidfed/core").Result<import("@oidfed/core").DiscoveryResult>>;
```

## `LeafConfig`

[Source](../../../packages/leaf/src/entity-configuration.ts#L58)

Construction settings for one Leaf. Host metadata is cloned, roles are initialized in order, and their metadata replaces matching host parameters in that order. The resulting publication metadata must be nonempty; an initially empty `metadata` object is permitted when a role contributes a block.

Changing the original metadata object does not change the host. Re-create the Leaf to change general publication metadata; EC refresh re-reads keys and the existing stored metadata. Key providers, role instances, options, and storage are not universally cloned or frozen. Treat construction settings as immutable, including `trustAnchorHints`, whose array remains referenced.

Instance discovery and assessment calls merge host options with call options. Holder attachment and fetching use their explicit verification/fetch options, while managed issuance uses its issuer service configuration. Static calls have no host defaults.

```typescript signature
interface LeafConfig extends EntityStatementExtensions {
	resolver?: FederationResolverIntegration;
	trustMarkIssuer?: TrustMarkIssuerConfig;
	collection?: EntityCollectionIntegration;
	entityId: EntityId | string;
	authorityHints: readonly (EntityId | string)[];
	metadata: EntityStatementMetadata;
	keyProvider: FederationKeyProvider;
	roles?: EntityRole[];
	options?: FederationOptions;
	trustMarks?: TrustMarkRef[];
	trustAnchorHints?: readonly (EntityId | string)[];
	/** Positive safe-integer EC lifetime in seconds; omission uses the core default. */
	entityConfigurationTtlSeconds?: number;
	trustAnchors?: TrustAnchorSet;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `resolver?` | `FederationResolverIntegration` | Optional Resolve service configuration. Identity and keys come from this Leaf; resolver options override host options, and resolver anchors override host anchors. See [`FederationResolverIntegration`](../core/chains.md#federationresolverintegration). |
| `trustMarkIssuer?` | `TrustMarkIssuerConfig` | [`TrustMarkIssuerConfig`](../core/marks.md#trustmarkissuerconfig) supplies transactional storage, issuance defaults, delegation evidence, and endpoint authentication. Required for the issuer methods and any advertised Trust Mark endpoints. Holder methods work independently. |
| `collection?` | `EntityCollectionIntegration` | Optional Entity Collection service configuration. Its anchors are supplied through this integration; its options override host options. A published collection endpoint requires this configuration. See [`EntityCollectionIntegration`](../core/collection.md#entitycollectionintegration). |
| `entityId` | `EntityId \| string` | Own HTTPS Entity Identifier without credentials, query, or fragment. Construction removes one trailing slash and validates the result. |
| `authorityHints` | `readonly (EntityId \| string)[]` | Required nonempty Immediate Superior identifiers. Each must be a valid Entity Identifier; construction copies the array without checking remote registration or trust. |
| `metadata` | `EntityStatementMetadata` | Host metadata indexed by Entity Type. Final composed metadata must be nonempty. Leaves reject Fetch, List, Extended Listing, and Subordinate Events endpoints and their auth-method fields in federation_entity. |
| `keyProvider` | `FederationKeyProvider` | [`FederationKeyProvider`](../core/keys.md#federationkeyprovider) supplies current Federation Entity Keys and a signer when generating an EC. A lifecycle provider can also satisfy this narrower read interface. |
| `roles?` | `EntityRole[]` | [`EntityRole`](../core/contracts.md#entityrole) instances are initialized and composed in array order. Create fresh stateful role instances for this host. Duplicate route paths and collisions with EC or service routes are rejected. |
| `options?` | `FederationOptions` | [`FederationOptions`](../core/contracts.md#federationoptions) supplies the shared host clock, transport, validation, caching, and logging settings. They are inherited by instance discovery/assessment and service integrations as described above. |
| `trustMarks?` | `TrustMarkRef[]` | Initial holder references, copied at construction and included in subsequent EC publication. Copying or publishing them does not cryptographically validate their JWTs; attachTrustMark performs evidence-aware validation. |
| `trustAnchorHints?` | `readonly (EntityId \| string)[]` | Optional nonempty reachable-anchor hints published in the EC. These hints do not establish trust or replace trustAnchors. Every value must be a valid Entity Identifier; do not mutate the array after construction. |
| `entityConfigurationTtlSeconds?` | `number` | EC lifetime in seconds. Must be a positive safe integer; defaults to 86400. The expiration is computed from the host clock when a new EC is generated. |
| `trustAnchors?` | `TrustAnchorSet` | Default independently trusted anchors for instance discovery/assessment and composed roles. The resolver can override them. They are not published in the EC or automatically used by fetchAndAttachTrustMark. |
| `additionalClaims?` | `Readonly<Record<string, unknown>> \| undefined` | Detached custom top-level EC claims. Reserved Entity Statement claims cannot be overridden; invalid publication extensions throw before signing. |
| `crit?` | `readonly string[] \| undefined` | Extension claim names recipients must understand and process. Each must be present in additionalClaims; standard Entity Statement claim names cannot be listed. |

