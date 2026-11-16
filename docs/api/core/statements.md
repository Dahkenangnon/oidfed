# Entity Statements and signatures

[`@oidfed/core`](README.md)

Builders construct claims; signers produce JWTs; verification checks authenticated evidence. Decoding alone does not establish trust. Keep federation signing keys separate from application protocol keys.

## `assertTypHeader`

[Source](../../../packages/core/src/jose/verify.ts#L180)

Assert that a JWT header has the expected `typ` value, throwing on mismatch.

```typescript signature
assertTypHeader(header: Record<string, unknown>, expectedTyp: string): asserts header is Record<string, unknown> & { typ: string };
```

## `buildEntityConfigurationPayload`

[Source](../../../packages/core/src/statement-builders.ts#L140)

Build a self-issued Entity Configuration payload from the entity's public keys, metadata, lifetime, and extensions. Configuration errors throw before signing.

```typescript signature
buildEntityConfigurationPayload(options: BuildEntityConfigurationPayloadOptions): EntityConfigurationPayload;
```

## `BuildEntityConfigurationPayloadOptions`

[Source](../../../packages/core/src/statement-builders.ts#L79)

Identity, keys, metadata, and timing inputs for building an Entity Configuration payload.

```typescript signature
interface BuildEntityConfigurationPayloadOptions
	extends StatementTimeOptions,
		EntityStatementExtensions {
	readonly entityId: EntityId | string;
	readonly jwks: JWKSet;
	readonly metadata: EntityStatementMetadata;
	readonly authorityHints?: readonly (EntityId | string)[];
	readonly trustAnchorHints?: readonly (EntityId | string)[];
	readonly trustMarks?: readonly TrustMarkRef[];
	readonly trustMarkIssuers?: Readonly<Record<string, readonly (EntityId | string)[]>>;
	readonly trustMarkOwners?: Readonly<Record<string, TrustMarkOwner>>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `entityId` | `EntityId \| string` | Exact Entity Identifier bound to this object or operation. |
| `jwks` | `JWKSet` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `metadata` | `EntityStatementMetadata` | Composed publication metadata. Superiors may supply missing protocol fields later. |
| `authorityHints?` | `readonly (EntityId \| string)[]` | Immediate Superior Entity Identifiers published as authority_hints. |
| `trustAnchorHints?` | `readonly (EntityId \| string)[]` | Reachable Trust Anchor identifiers published as trust_anchor_hints when the entity has Superiors. |
| `trustMarks?` | `readonly TrustMarkRef[]` | Trust Mark references, verified marks, or evaluations supplied by the owning contract. |
| `trustMarkIssuers?` | `Readonly<Record<string, readonly (EntityId \| string)[]>>` | Permitted issuer identities indexed by Trust Mark type; an empty array allows any issuer under the applicable policy. |
| `trustMarkOwners?` | `Readonly<Record<string, TrustMarkOwner>>` | Trusted owner identity and keys indexed by Trust Mark type. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `issuedAt?` | `number` | Issuance time as a NumericDate in seconds. |
| `ttlSeconds?` | `number` | Lifetime in seconds; the owning builder defines the default and whether fractions are accepted. |
| `additionalClaims?` | `Readonly<Record<string, unknown>> \| undefined` | Additional JSON claims. The owning builder rejects collisions with its reserved claims. |
| `crit?` | `readonly string[] \| undefined` | Extension claim names recipients must understand and process; each named claim must be present. |

## `buildSubordinateStatementPayload`

[Source](../../../packages/core/src/statement-builders.ts#L189)

Build a Superior's statement about a subordinate, including its public federation keys, metadata, policy, and constraints. Invalid publication claims throw before signing.

```typescript signature
buildSubordinateStatementPayload(options: BuildSubordinateStatementPayloadOptions): SubordinateStatementPayload;
```

## `BuildSubordinateStatementPayloadOptions`

[Source](../../../packages/core/src/statement-builders.ts#L92)

Superior and subordinate identities, keys, policy, and timing inputs for a Subordinate Statement payload.

```typescript signature
interface BuildSubordinateStatementPayloadOptions
	extends StatementTimeOptions,
		EntityStatementExtensions {
	readonly issuer: EntityId | string;
	readonly subject: EntityId | string;
	readonly jwks: JWKSet;
	readonly metadata?: EntityStatementMetadata;
	readonly metadataPolicy?: FederationMetadataPolicy | Readonly<Record<string, unknown>>;
	readonly constraints?: TrustChainConstraints;
	readonly sourceEndpoint?: string;
	readonly metadataPolicyCrit?: readonly string[];
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `issuer` | `EntityId \| string` | Issuer identity for the signed artifact or configured service. |
| `subject` | `EntityId \| string` | Subject identity for the statement, mark, or authentication being processed. |
| `jwks` | `JWKSet` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `metadata?` | `EntityStatementMetadata` | Entity metadata indexed by Entity Type Identifier. Publication may be partial; effective metadata is checked after policy. |
| `metadataPolicy?` | `FederationMetadataPolicy \| Readonly<Record<string, unknown>>` | Metadata policy supplied for this statement, indexed by Entity Type and metadata parameter. |
| `constraints?` | `TrustChainConstraints` | Path, naming, Entity Type, or federation-defined constraints carried by the statement. |
| `sourceEndpoint?` | `string` | Fetch endpoint published in the statement's source_endpoint claim. |
| `metadataPolicyCrit?` | `readonly string[]` | Nonstandard metadata-policy operators that recipients must understand. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `issuedAt?` | `number` | Issuance time as a NumericDate in seconds. |
| `ttlSeconds?` | `number` | Lifetime in seconds; the owning builder defines the default and whether fractions are accepted. |
| `additionalClaims?` | `Readonly<Record<string, unknown>> \| undefined` | Additional JSON claims. The owning builder rejects collisions with its reserved claims. |
| `crit?` | `readonly string[] \| undefined` | Extension claim names recipients must understand and process; each named claim must be present. |

## `checkApplicationJwtHeader`

[Source](../../../packages/core/src/jose/application-jwt.ts#L49)

ACA §9 allows applications to narrow the backend's supported algorithms.

```typescript signature
checkApplicationJwtHeader(header: jose.ProtectedHeaderParameters, typ: string, allowed?: readonly string[]): Result<string>;
```

## `decodeApplicationJwt`

[Source](../../../packages/core/src/jose/application-jwt.ts#L22)

Decode an application JWT into its header and payload under the configured limits. Decoding does not authenticate either object.

```typescript signature
decodeApplicationJwt(jwt: string, options: FederationOptions): Result<{ header: jose.ProtectedHeaderParameters; payload: jose.JWTPayload }>;
```

## `decodeEntityConfiguration`

[Source](../../../packages/core/src/jose/verify.ts#L104)

Decode and schema-validate an Entity Configuration JWT without signature verification.

```typescript signature
decodeEntityConfiguration(jwt: string): Result<UnverifiedEntityStatement<EntityConfigurationPayload>, FederationError>;
```

## `decodeEntityStatement`

[Source](../../../packages/core/src/jose/verify.ts#L83)

Decode a JWT entity statement without signature verification.

```typescript signature
decodeEntityStatement(jwt: string): Result<UnverifiedEntityStatement, FederationError>;
```

## `decodeSubordinateStatement`

[Source](../../../packages/core/src/jose/verify.ts#L129)

Decode and schema-validate a Subordinate Statement JWT without signature verification.

```typescript signature
decodeSubordinateStatement(jwt: string): Result<UnverifiedEntityStatement<SubordinateStatementPayload>, FederationError>;
```

## `EntityStatementExtensions`

[Source](../../../packages/core/src/statement-builders.ts#L46)

Additional Entity Statement claims and critical-claim declarations.

```typescript signature
interface EntityStatementExtensions {
	/** Custom top-level claims; standard Entity Statement claims cannot be overridden. */
	readonly additionalClaims?: Readonly<Record<string, unknown>> | undefined;
	/** Extension claims recipients MUST understand and process (Federation §13.4). */
	readonly crit?: readonly string[] | undefined;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `additionalClaims?` | `Readonly<Record<string, unknown>> \| undefined` | Additional JSON claims. The owning builder rejects collisions with its reserved claims. |
| `crit?` | `readonly string[] \| undefined` | Extension claim names recipients must understand and process; each named claim must be present. |

## `EntityStatementKind`

[Source](../../../packages/core/src/statement-builders.ts#L32)

Distinguishes a self-issued Entity Configuration from a Subordinate Statement.

```typescript signature
type EntityStatementKind = "entity-configuration" | "subordinate-statement";
```

## `EntityStatementMetadata`

[Source](../../../packages/core/src/statement-builders.ts#L38)

Metadata claims supplied when building an Entity Statement.

```typescript signature
type EntityStatementMetadata = Readonly<Record<string, Readonly<Record<string, unknown>>>>;
```

## `JwkSigner`

[Source](../../../packages/core/src/jose/signer.ts#L24)

Software-key signer backed by `jose`. Construction validates and snapshots the private asymmetric JWK, including its `kid` and signing algorithm. Key import is deferred until signing; invalid input or backend failures throw or reject. `JwkSignerOptions` has an optional algorithm override, not a key-header override.

```typescript signature
new JwkSigner(key: JWK, options?: JwkSignerOptions): JwkSigner;
```

### `JwkSigner#kid`

Key identifier used to select this signer's public key.

[Source](../../../packages/core/src/jose/signer.ts#L25)

```typescript signature
readonly kid: string;
```

### `JwkSigner#alg`

Signing algorithm advertised by this signer.

[Source](../../../packages/core/src/jose/signer.ts#L26)

```typescript signature
readonly alg: SupportedAlgorithm;
```

### `JwkSigner#signJwt`

Sign the supplied JWT data through this signer's configured key or signing backend.

[Source](../../../packages/core/src/jose/signer.ts#L39)

```typescript signature
signJwt(payload: Uint8Array, protectedHeader: Readonly<Record<string, unknown>>): Promise<string>;
```

## `JwkSignerOptions`

[Source](../../../packages/core/src/jose/signer.ts#L19)

Optional signing algorithm for `JwkSigner`. If omitted, the signer uses the JWK's `alg`; the key must also contain a nonempty `kid` and private material.

```typescript signature
interface JwkSignerOptions {
	readonly alg?: SupportedAlgorithm;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `alg?` | `SupportedAlgorithm` | Algorithm associated with the signer or JWK. |

## `JwtSigner`

[Source](../../../packages/core/src/jose/signer.ts#L13)

Signing interface for a software key, remote signing service, or another host-controlled backend. Implementations own key custody. The bundled `JwkSigner` imports its private JWK through `jose`; callers using the interface do not need to expose private material to protocol code.

```typescript signature
interface JwtSigner {
	readonly kid: string;
	readonly alg: SupportedAlgorithm;
	signJwt(payload: Uint8Array, protectedHeader: Readonly<Record<string, unknown>>): Promise<string>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `kid` | `string` | Key identifier used to select a public verification key. |
| `alg` | `SupportedAlgorithm` | Algorithm associated with the signer or JWK. |
| `signJwt` | `(payload: Uint8Array, protectedHeader: Readonly<Record<string, unknown>>) => Promise<string>` | Sign the supplied payload bytes and protected header using this signer's key custody. |

## `matchesJwtType`

[Source](../../../packages/core/src/jose/application-jwt.ts#L39)

RFC 7515 §4.1.9 treats typ as a media type, with an optional application/ prefix.

```typescript signature
matchesJwtType(actual: unknown, expected: string): boolean;
```

## `prepareEntityStatementExtensions`

[Source](../../../packages/core/src/statement-builders.ts#L54)

Validate and detach publication extensions. Throws before retaining or signing invalid data.

```typescript signature
prepareEntityStatementExtensions(options: EntityStatementExtensions): EntityStatementExtensions;
```

## `signApplicationJwt`

[Source](../../../packages/core/src/jose/application-jwt.ts#L130)

Sign an application payload with the supplied signer, JWT type, and optional Trust Chain header. The caller supplies the protocol claims.

```typescript signature
signApplicationJwt(payload: Record<string, unknown>, typ: string, signer: JwtSigner, options: FederationOptions, chain?: readonly string[]): Promise<Result<string>>;
```

## `signEntityConfiguration`

[Source](../../../packages/core/src/statement-builders.ts#L178)

Build and sign a self-issued Entity Configuration using the supplied federation signer.

```typescript signature
signEntityConfiguration(options: SignEntityConfigurationOptions): Promise<string>;
```

## `SignEntityConfigurationOptions`

[Source](../../../packages/core/src/statement-builders.ts#L105)

Payload and signing options for a self-issued Entity Configuration.

```typescript signature
interface SignEntityConfigurationOptions extends BuildEntityConfigurationPayloadOptions {
	readonly signer: JwtSigner;
	readonly alg?: SupportedAlgorithm;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `signer` | `JwtSigner` | Signing capability and its public algorithm/key identifier. Private-key custody stays with the implementation. |
| `alg?` | `SupportedAlgorithm` | Algorithm associated with the signer or JWK. |
| `entityId` | `EntityId \| string` | Exact Entity Identifier bound to this object or operation. |
| `jwks` | `JWKSet` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `metadata` | `EntityStatementMetadata` | Entity metadata indexed by Entity Type Identifier. Publication may be partial; effective metadata is checked after policy. |
| `authorityHints?` | `readonly (EntityId \| string)[]` | Immediate Superior Entity Identifiers published as authority_hints. |
| `trustAnchorHints?` | `readonly (EntityId \| string)[]` | Reachable Trust Anchor identifiers published as trust_anchor_hints when the entity has Superiors. |
| `trustMarks?` | `readonly TrustMarkRef[]` | Trust Mark references, verified marks, or evaluations supplied by the owning contract. |
| `trustMarkIssuers?` | `Readonly<Record<string, readonly (EntityId \| string)[]>>` | Permitted issuer identities indexed by Trust Mark type; an empty array allows any issuer under the applicable policy. |
| `trustMarkOwners?` | `Readonly<Record<string, TrustMarkOwner>>` | Trusted owner identity and keys indexed by Trust Mark type. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `issuedAt?` | `number` | Issuance time as a NumericDate in seconds. |
| `ttlSeconds?` | `number` | Lifetime in seconds; the owning builder defines the default and whether fractions are accepted. |
| `additionalClaims?` | `Readonly<Record<string, unknown>> \| undefined` | Additional JSON claims. The owning builder rejects collisions with its reserved claims. |
| `crit?` | `readonly string[] \| undefined` | Extension claim names recipients must understand and process; each named claim must be present. |

## `signEntityStatement`

[Source](../../../packages/core/src/jose/sign.ts#L15)

Serialize and sign a payload as a compact JWT. The default `typ` is `entity-statement+jwt`; the algorithm must match the signer. `extraHeaders` cannot override `alg`, `kid`, or `typ`. This generic signer does not validate the payload as an Entity Configuration or Subordinate Statement; use their builders when those publication checks are required. Errors reject the returned promise.

```typescript signature
signEntityStatement(payload: Record<string, unknown>, signer: JwtSigner, options?: SignEntityStatementOptions): Promise<string>;
```

## `SignEntityStatementOptions`

[Source](../../../packages/core/src/jose/sign.ts#L6)

Header and signing options for an Entity Statement JWT.

```typescript signature
interface SignEntityStatementOptions {
	readonly alg?: SupportedAlgorithm;
	readonly typ?: string;
	readonly extraHeaders?: Record<string, unknown>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `alg?` | `SupportedAlgorithm` | Defaults to `signer.alg`; an explicit value must match the signer. |
| `typ?` | `string` | Protected JWT type; defaults to `entity-statement+jwt`. |
| `extraHeaders?` | `Record<string, unknown>` | Additional protected JWS headers, subject to the signer's reserved-header checks. |

## `signSubordinateStatement`

[Source](../../../packages/core/src/statement-builders.ts#L219)

Build and sign a Subordinate Statement with the Superior's federation signer.

```typescript signature
signSubordinateStatement(options: SignSubordinateStatementOptions): Promise<string>;
```

## `SignSubordinateStatementOptions`

[Source](../../../packages/core/src/statement-builders.ts#L110)

Payload and signing options for a Superior's Subordinate Statement.

```typescript signature
interface SignSubordinateStatementOptions extends BuildSubordinateStatementPayloadOptions {
	readonly signer: JwtSigner;
	readonly alg?: SupportedAlgorithm;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `signer` | `JwtSigner` | Signing capability and its public algorithm/key identifier. Private-key custody stays with the implementation. |
| `alg?` | `SupportedAlgorithm` | Algorithm associated with the signer or JWK. |
| `issuer` | `EntityId \| string` | Issuer identity for the signed artifact or configured service. |
| `subject` | `EntityId \| string` | Subject identity for the statement, mark, or authentication being processed. |
| `jwks` | `JWKSet` | JSON Web Key Set. The owning API determines whether these are Federation Entity Keys or protocol keys. |
| `metadata?` | `EntityStatementMetadata` | Entity metadata indexed by Entity Type Identifier. Publication may be partial; effective metadata is checked after policy. |
| `metadataPolicy?` | `FederationMetadataPolicy \| Readonly<Record<string, unknown>>` | Metadata policy supplied for this statement, indexed by Entity Type and metadata parameter. |
| `constraints?` | `TrustChainConstraints` | Path, naming, Entity Type, or federation-defined constraints carried by the statement. |
| `sourceEndpoint?` | `string` | Fetch endpoint published in the statement's source_endpoint claim. |
| `metadataPolicyCrit?` | `readonly string[]` | Nonstandard metadata-policy operators that recipients must understand. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |
| `issuedAt?` | `number` | Issuance time as a NumericDate in seconds. |
| `ttlSeconds?` | `number` | Lifetime in seconds; the owning builder defines the default and whether fractions are accepted. |
| `additionalClaims?` | `Readonly<Record<string, unknown>> \| undefined` | Additional JSON claims. The owning builder rejects collisions with its reserved claims. |
| `crit?` | `readonly string[] \| undefined` | Extension claim names recipients must understand and process; each named claim must be present. |

## `validateCriticalClaims`

[Source](../../../packages/core/src/statement-validation.ts#L12)

Enforce payload critical claims under Federation §3.1.1. Callers process the extensions they declare understood.

```typescript signature
validateCriticalClaims(payload: Readonly<Record<string, unknown>>, understood?: ReadonlySet<string>): Result<void, FederationError>;
```

### Usage example

A host implementing an extension must process the names it declares understood. These helpers check declaration and time rules; use them on authenticated payloads or as preliminary checks without confusing them with signature verification.

```ts
import { validateCriticalClaims, validateEntityStatementTimeClaims, type Clock } from "@oidfed/core";

export function inspectStatementClaims(payload: Record<string, unknown>, clock: Clock) {
  const critical = validateCriticalClaims(payload,
    new Set(["https://campus.example/claims/access-profile"]));
  if (!critical.ok) return critical;
  return validateEntityStatementTimeClaims(payload, { clock, clockSkewSeconds: 0 });
}
```

## `validateEntityStatementClaims`

[Source](../../../packages/core/src/statement-builders.ts#L233)

Check statement claims for the requested statement kind, including identity relationships and permitted claim placement.

```typescript signature
validateEntityStatementClaims(payload: Readonly<Record<string, unknown>>, options: ValidateEntityStatementClaimsOptions): Result<void, FederationError>;
```

## `ValidateEntityStatementClaimsOptions`

[Source](../../../packages/core/src/statement-builders.ts#L34)

Statement kind, identity, time, and understood-critical-claim settings for claim validation.

```typescript signature
interface ValidateEntityStatementClaimsOptions {
	readonly kind: EntityStatementKind;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `kind` | `EntityStatementKind` | Discriminator selecting the evidence or acquisition mode. |

## `validateEntityStatementTimeClaims`

[Source](../../../packages/core/src/statement-validation.ts#L43)

Check required Entity Statement times using the verifier's clock and allowed skew (§3.2).

```typescript signature
validateEntityStatementTimeClaims(payload: Readonly<Record<string, unknown>>, options?: Pick<FederationOptions, "clock" | "clockSkewSeconds">): Result<void, FederationError & { readonly field: "iat" | "exp" }>;
```

## `validateSigner`

[Source](../../../packages/core/src/jose/signer.ts#L51)

Check that a signer has the algorithm and key identifier required for publication.

```typescript signature
validateSigner(signer: JwtSigner): void;
```

## `validateSubordinateStatementPublicationClaims`

[Source](../../../packages/core/src/statement-builders.ts#L276)

Validate supplied publication claims without inventing required issuer, key, or time claims.

```typescript signature
validateSubordinateStatementPublicationClaims(payload: Readonly<Record<string, unknown>>, options?: MetadataPolicyOptions): Result<void, FederationError>;
```

## `VerifiedProtocolJwt`

[Source](../../../packages/core/src/jose/verify-protocol.ts#L20)

A protocol JWT's header and payload returned after verification.

```typescript signature
interface VerifiedProtocolJwt {
	header: Record<string, unknown>;
	payload: Record<string, unknown>;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `header` | `Record<string, unknown>` | Decoded JWT header. Decoding alone does not authenticate it. |
| `payload` | `Record<string, unknown>` | Decoded claims; their verification state is determined by the enclosing result. |

## `verifyApplicationJwt`

[Source](../../../packages/core/src/jose/application-jwt.ts#L72)

Verify the signature, type, supported algorithms, and any supplied audience against the provided public keys. Present `exp` and `nbf` claims are checked with clock tolerance; `iat` is checked for finite numeric syntax, without imposing an age limit. Required claims, freshness policy, and issuer trust belong to the calling protocol workflow.

```typescript signature
verifyApplicationJwt(jwt: string, keys: JWKSet, typ: string, options: FederationOptions, audience?: string, confirmationKey?: boolean, allowedAlgorithms?: readonly string[]): Promise<Result<jose.JWTPayload>>;
```

## `verifyEntityStatement`

[Source](../../../packages/core/src/jose/verify.ts#L17)

Verify the JWT's exact type, supported signing algorithm, nonempty `kid`, signature, and present JWT time claims against the supplied public keys. The default type is `entity-statement+jwt` and default clock tolerance is 60 seconds. This low-level call does not perform complete claim-shape, chain-link, policy, or Trust Anchor validation.

```typescript signature
verifyEntityStatement(jwt: string, jwks: JWKSet, options?: { clockSkewSeconds?: number; clock?: Clock; expectedTyp?: string }): Promise<Result<ParsedEntityStatement, FederationError>>;
```

## `verifyProtocolJwt`

[Source](../../../packages/core/src/jose/verify-protocol.ts#L30)

Verify a protocol JWT against authenticated public metadata keys.
Checks signature, type and JWT time claims. The caller validates protocol claims
such as issuer and audience and supplies keys bound to the expected entity.

```typescript signature
verifyProtocolJwt(jwt: string, jwks: JWKSet, options: VerifyProtocolJwtOptions): Promise<Result<VerifiedProtocolJwt, FederationError>>;
```

## `VerifyProtocolJwtOptions`

[Source](../../../packages/core/src/jose/verify-protocol.ts#L10)

Expected type, identity, algorithms, and claim checks for a protocol JWT.

```typescript signature
interface VerifyProtocolJwtOptions {
	expectedTyp: string;
	/** Application policy, in addition to supported asymmetric algorithms. */
	allowedAlgorithms?: readonly string[];
	/** Require kid by default; single-key permits omission for a set containing one key. */
	keyIdPolicy?: "required" | "single-key";
	clockSkewSeconds?: number;
	clock?: Clock;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `expectedTyp` | `string` | Exact JWT typ required by this verifier. |
| `allowedAlgorithms?` | `readonly string[]` | Optional algorithm allowlist, applied in addition to the library's supported algorithms. |
| `keyIdPolicy?` | `"required" \| "single-key"` | Require kid by default; single-key permits omission for a set containing one key. |
| `clockSkewSeconds?` | `number` | Allowed time-claim leeway in seconds; the default verifier allowance is 60 seconds. |
| `clock?` | `Clock` | NumericDate time source; omitted clocks use the runtime's current time. |

