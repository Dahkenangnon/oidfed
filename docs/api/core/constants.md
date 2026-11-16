# Protocol constants and defaults

[`@oidfed/core`](README.md)

Use these exported values when constructing protocol messages or configuring limits. Defaults are library policy unless the associated specification requires the value. A host may tighten operational limits through the documented options.

## `CachePrefix`

[Source](../../../packages/core/src/constants.ts#L124)

Prefixes used to namespace Entity Configuration, Entity Statement, and Trust Chain cache keys.

```typescript signature
const CachePrefix: {
	readonly EntityConfiguration: "ec:";
	readonly EntityStatement: "es:";
	readonly TrustChain: "chain:";
};
```

## `DEFAULT_CACHE_MAX_TTL_SECONDS`

[Source](../../../packages/core/src/constants.ts#L169)

Maximum default cache retention, in seconds. Check the calling API for overrides and operation-specific defaults.

```typescript signature
const DEFAULT_CACHE_MAX_TTL_SECONDS = 86400;
```

## `DEFAULT_CACHE_TTL_SECONDS`

[Source](../../../packages/core/src/constants.ts#L168)

Default cache-entry lifetime, in seconds. Check the calling API for overrides and operation-specific defaults.

```typescript signature
const DEFAULT_CACHE_TTL_SECONDS = 3600;
```

## `DEFAULT_CLIENT_ASSERTION_TTL_SECONDS`

[Source](../../../packages/core/src/constants.ts#L174)

Default private-key JWT client-assertion lifetime, in seconds. Check the calling API for overrides and operation-specific defaults.

```typescript signature
const DEFAULT_CLIENT_ASSERTION_TTL_SECONDS = 60;
```

## `DEFAULT_CLOCK_SKEW_SECONDS`

[Source](../../../packages/core/src/constants.ts#L163)

Default leeway for supported time-claim checks, in seconds. Check the calling API for overrides and operation-specific defaults.

```typescript signature
const DEFAULT_CLOCK_SKEW_SECONDS = 60;
```

## `DEFAULT_DELEGATION_TTL_SECONDS`

[Source](../../../packages/core/src/constants.ts#L172)

Default Trust Mark delegation lifetime, in seconds. Check the calling API for overrides and operation-specific defaults.

```typescript signature
const DEFAULT_DELEGATION_TTL_SECONDS = 86400;
```

## `DEFAULT_ENTITY_STATEMENT_TTL_SECONDS`

[Source](../../../packages/core/src/constants.ts#L171)

Default Entity Statement lifetime, in seconds. Check the calling API for overrides and operation-specific defaults.

```typescript signature
const DEFAULT_ENTITY_STATEMENT_TTL_SECONDS = 86400;
```

## `DEFAULT_HTTP_TIMEOUT_MS`

[Source](../../../packages/core/src/constants.ts#L162)

Default HTTP operation timeout, in milliseconds. Check the calling API for overrides and operation-specific defaults.

```typescript signature
const DEFAULT_HTTP_TIMEOUT_MS = 10000;
```

Runtime default: 10000 milliseconds.

## `DEFAULT_KEY_RETIRE_AFTER_MS`

[Source](../../../packages/core/src/constants.ts#L175)

Default overlap after switching the active federation signing key, in milliseconds. This does not schedule the earlier wait between publishing a replacement and activating it. Check the calling API for overrides and operation-specific defaults.

```typescript signature
const DEFAULT_KEY_RETIRE_AFTER_MS: number;
```

Runtime default: 604800000 milliseconds (seven days).

## `DEFAULT_MAX_AUTHORITY_HINTS`

[Source](../../../packages/core/src/constants.ts#L167)

Default limit on authority hints examined for an entity. Check the calling API for overrides and operation-specific defaults.

```typescript signature
const DEFAULT_MAX_AUTHORITY_HINTS = 10;
```

## `DEFAULT_MAX_CHAIN_DEPTH`

[Source](../../../packages/core/src/constants.ts#L165)

Default discovery depth limit. Check the calling API for overrides and operation-specific defaults.

```typescript signature
const DEFAULT_MAX_CHAIN_DEPTH = 8;
```

## `DEFAULT_MAX_CHAIN_LENGTH`

[Source](../../../packages/core/src/constants.ts#L164)

Default maximum statement count in a validated chain. Check the calling API for overrides and operation-specific defaults.

```typescript signature
const DEFAULT_MAX_CHAIN_LENGTH = 100;
```

## `DEFAULT_MAX_REQUEST_BODY_BYTES`

[Source](../../../packages/core/src/constants.ts#L161)

Default maximum accepted request-body size, in bytes. Check the calling API for overrides and operation-specific defaults.

```typescript signature
const DEFAULT_MAX_REQUEST_BODY_BYTES: number;
```

Runtime default: 65536 bytes.

## `DEFAULT_MAX_RESOLUTION_STEPS`

[Source](../../../packages/core/src/constants.ts#L166)

Default upper bound on branch expansion during chain resolution. Check the calling API for overrides and operation-specific defaults.

```typescript signature
const DEFAULT_MAX_RESOLUTION_STEPS = 1000;
```

## `DEFAULT_MAX_RESPONSE_BYTES`

[Source](../../../packages/core/src/constants.ts#L160)

Default maximum fetched response size, in bytes. Check the calling API for overrides and operation-specific defaults.

```typescript signature
const DEFAULT_MAX_RESPONSE_BYTES: number;
```

Runtime default: 524288 bytes.

## `DEFAULT_REQUEST_OBJECT_TTL_SECONDS`

[Source](../../../packages/core/src/constants.ts#L173)

Default signed Request Object lifetime, in seconds. Check the calling API for overrides and operation-specific defaults.

```typescript signature
const DEFAULT_REQUEST_OBJECT_TTL_SECONDS = 300;
```

## `EntityType`

[Source](../../../packages/core/src/constants.ts#L45)

An Entity Type Identifier supported by the library.

```typescript signature
const EntityType: {
	readonly FederationEntity: "federation_entity";
	readonly OpenIDRelyingParty: "openid_relying_party";
	readonly OpenIDProvider: "openid_provider";
	readonly OAuthAuthorizationServer: "oauth_authorization_server";
	readonly OAuthClient: "oauth_client";
	readonly OAuthResource: "oauth_resource";
	readonly OpenIDWalletProvider: "openid_wallet_provider";
	readonly OpenIDCredentialIssuer: "openid_credential_issuer";
	readonly OpenIDCredentialVerifier: "openid_credential_verifier";
};
type EntityType = (typeof EntityType)[keyof typeof EntityType];
```

## `EntityTypeIdentifier`

[Source](../../../packages/core/src/constants.ts#L65)

Any Entity Type Identifier, including extension identifiers.

Federation 1.0 §1.2 defines the value space as an open string ("String
identifier for an Entity Type"), §5.1 permits identifiers beyond the
published set ("Additional Entity Type Identifiers MAY be defined to support
use cases for other protocols"), and §20 establishes no registry — so no
closed validation set exists. `EntityType` enumerates the identifiers
published by Federation 1.0 §5.1 and Wallet Architectures Draft 05 §6; this
type additionally admits any other identifier while keeping editor
completion for the known constants.

```typescript signature
type EntityTypeIdentifier = EntityType | (string & Record<never, never>);
```

## `FederationEndpoint`

[Source](../../../packages/core/src/constants.ts#L5)

Conventional endpoint path values, with a type union of those values. These constants do not discover an entity's endpoints; use its validated `federation_entity` metadata for remote calls.

```typescript signature
const FederationEndpoint: {
	readonly Fetch: "/federation_fetch";
	readonly List: "/federation_list";
	readonly ExtendedList: "/federation_extended_list";
	readonly Collection: "/federation_collection";
	readonly Resolve: "/federation_resolve";
	readonly Registration: "/federation_registration";
	readonly TrustMarkStatus: "/federation_trust_mark_status";
	readonly TrustMarkList: "/federation_trust_mark_list";
	readonly TrustMark: "/federation_trust_mark";
	readonly HistoricalKeys: "/federation_historical_keys";
};
type FederationEndpoint = (typeof FederationEndpoint)[keyof typeof FederationEndpoint];
```

## `FederationErrorCode`

[Source](../../../packages/core/src/constants.ts#L88)

A protocol error code used in federation error responses.

```typescript signature
const FederationErrorCode: {
	readonly InvalidRequest: "invalid_request";
	readonly InvalidClient: "invalid_client";
	readonly InvalidIssuer: "invalid_issuer";
	readonly InvalidSubject: "invalid_subject";
	readonly InvalidTrustAnchor: "invalid_trust_anchor";
	readonly InvalidTrustChain: "invalid_trust_chain";
	readonly InvalidMetadata: "invalid_metadata";
	readonly NotFound: "not_found";
	readonly ServerError: "server_error";
	readonly TemporarilyUnavailable: "temporarily_unavailable";
	readonly UnsupportedParameter: "unsupported_parameter";
	readonly UnsupportedClaim: "unsupported_claim";
	readonly EntityIdNotFound: "entity_id_not_found";
	readonly PageNotFound: "page_not_found";
};
type FederationErrorCode = (typeof FederationErrorCode)[keyof typeof FederationErrorCode];
```

## `InternalErrorCode`

[Source](../../../packages/core/src/constants.ts#L106)

An error code used within library operations.

```typescript signature
const InternalErrorCode: {
	readonly TrustChainInvalid: "ERR_TRUST_CHAIN_INVALID";
	readonly SignatureInvalid: "ERR_SIGNATURE_INVALID";
	readonly MetadataPolicyError: "ERR_METADATA_POLICY_ERROR";
	readonly MetadataPolicyViolation: "ERR_METADATA_POLICY_VIOLATION";
	readonly ConstraintViolation: "ERR_CONSTRAINT_VIOLATION";
	readonly Network: "ERR_NETWORK";
	readonly RemoteResponse: "ERR_REMOTE_RESPONSE";
	readonly InvalidResponse: "ERR_INVALID_RESPONSE";
	readonly TrustAnchorUnknown: "ERR_TRUST_ANCHOR_UNKNOWN";
	readonly Timeout: "ERR_TIMEOUT";
	readonly UnsupportedAlg: "ERR_UNSUPPORTED_ALG";
	readonly TrustMarkInvalid: "ERR_TRUST_MARK_INVALID";
	readonly Expired: "ERR_EXPIRED";
	readonly LoopDetected: "ERR_LOOP_DETECTED";
};
type InternalErrorCode = (typeof InternalErrorCode)[keyof typeof InternalErrorCode];
```

## `JWT_BEARER_CLIENT_ASSERTION_TYPE`

[Source](../../../packages/core/src/constants.ts#L177)

The JWT bearer assertion-type value placed in client_assertion_type for private-key JWT authentication.

```typescript signature
const JWT_BEARER_CLIENT_ASSERTION_TYPE: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
```

## `JwtTyp`

[Source](../../../packages/core/src/constants.ts#L34)

A JWT `typ` value recognized by the library.

```typescript signature
const JwtTyp: {
	readonly EntityEventsStatement: "entity-events-statement+jwt";
	readonly EntityStatement: "entity-statement+jwt";
	readonly TrustMark: "trust-mark+jwt";
	readonly TrustMarkDelegation: "trust-mark-delegation+jwt";
	readonly ResolveResponse: "resolve-response+jwt";
	readonly JwkSet: "jwk-set+jwt";
	readonly TrustMarkStatusResponse: "trust-mark-status-response+jwt";
};
type JwtTyp = (typeof JwtTyp)[keyof typeof JwtTyp];
```

## `MediaType`

[Source](../../../packages/core/src/constants.ts#L19)

An HTTP media type used by federation artifacts and endpoints.

```typescript signature
const MediaType: {
	readonly EntityEventsStatement: "application/entity-events-statement+jwt";
	readonly EntityStatement: "application/entity-statement+jwt";
	readonly TrustMark: "application/trust-mark+jwt";
	readonly ResolveResponse: "application/resolve-response+jwt";
	readonly TrustChain: "application/trust-chain+json";
	readonly TrustMarkDelegation: "application/trust-mark-delegation+jwt";
	readonly JwkSet: "application/jwk-set+jwt";
	readonly TrustMarkStatusResponse: "application/trust-mark-status-response+jwt";
	readonly Json: "application/json";
	readonly JwkSetJson: "application/jwk-set+json";
	readonly TextPlain: "text/plain";
};
type MediaType = (typeof MediaType)[keyof typeof MediaType];
```

## `PolicyOperator`

[Source](../../../packages/core/src/constants.ts#L77)

A standard metadata-policy operator name.

```typescript signature
const PolicyOperator: {
	readonly Value: StandardPolicyOperator.VALUE;
	readonly Add: StandardPolicyOperator.ADD;
	readonly Default: StandardPolicyOperator.DEFAULT;
	readonly OneOf: StandardPolicyOperator.ONE_OF;
	readonly SubsetOf: StandardPolicyOperator.SUBSET_OF;
	readonly SupersetOf: StandardPolicyOperator.SUPERSET_OF;
	readonly Essential: StandardPolicyOperator.ESSENTIAL;
};
type PolicyOperator = (typeof PolicyOperator)[keyof typeof PolicyOperator];
```

## `REQUIRED_ALGORITHMS`

[Source](../../../packages/core/src/constants.ts#L180)

Signature algorithms designated as required by the supported federation profile.

```typescript signature
const REQUIRED_ALGORITHMS: readonly ["ES256", "PS256"];
```

Runtime value: `["ES256", "PS256"]`.

## `STANDARD_ENTITY_STATEMENT_CLAIMS`

[Source](../../../packages/core/src/constants.ts#L139)

Claims that MUST NOT appear in the `crit` array.

```typescript signature
const STANDARD_ENTITY_STATEMENT_CLAIMS: Set<string>;
```

## `StandardPolicyOperator`

[Source](../../../packages/core/src/constants.ts#L67)

String enum naming the seven built-in policy operators. It is available as both a runtime enum and its TypeScript enum type; custom definitions cannot replace these names.

```typescript signature
enum StandardPolicyOperator {
	VALUE = "value",
	ADD = "add",
	DEFAULT = "default",
	ESSENTIAL = "essential",
	ONE_OF = "one_of",
	SUBSET_OF = "subset_of",
	SUPERSET_OF = "superset_of"
}
```

## `SUPPORTED_ALGORITHMS`

[Source](../../../packages/core/src/constants.ts#L181)

Signature algorithms supported by this implementation. A protocol or deployment can narrow the accepted set.

```typescript signature
const SUPPORTED_ALGORITHMS: readonly ["ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256"];
```

Runtime value: `["ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256"]`.

## `SupportedAlgorithm`

[Source](../../../packages/core/src/constants.ts#L192)

A signing algorithm supported by the library.

```typescript signature
type SupportedAlgorithm = (typeof SUPPORTED_ALGORITHMS)[number];
```

## `TrustMarkStatus`

[Source](../../../packages/core/src/constants.ts#L130)

A Trust Mark status value.

```typescript signature
const TrustMarkStatus: {
	readonly Active: "active";
	readonly Expired: "expired";
	readonly Revoked: "revoked";
	readonly Invalid: "invalid";
};
type TrustMarkStatus = (typeof TrustMarkStatus)[keyof typeof TrustMarkStatus];
```

## `WELL_KNOWN_OPENID_FEDERATION`

[Source](../../../packages/core/src/constants.ts#L3)

Well-known discovery suffix `/.well-known/openid-federation`. Entity Configuration clients append it after applying the Entity Identifier path rules.

```typescript signature
const WELL_KNOWN_OPENID_FEDERATION = "/.well-known/openid-federation";
```

