# Metadata policies and constraints

[`@oidfed/core`](README.md)

Apply policy to authenticated statements in superior order. Custom operators and constraints are synchronous host extensions with controlled failure results. Unknown non-critical extensions remain distinct from required extensions.

## `applyAllowedEntityTypes`

[Source](../../../packages/core/src/constraints/index.ts#L63)

Return a new outer metadata record retaining allowed Entity Types and always retaining `federation_entity`. The call does not mutate the input, but retained metadata blocks are shared by reference rather than deeply cloned.

```typescript signature
applyAllowedEntityTypes(allowedEntityTypes: string[], metadata: Record<string, Record<string, unknown>>): Record<string, Record<string, unknown>>;
```

## `applyMetadataPolicy`

[Source](../../../packages/core/src/metadata-policy/apply.ts#L16)

Apply a resolved metadata policy to federation metadata, returning the transformed metadata.

```typescript signature
applyMetadataPolicy(metadata: FederationMetadata, policy: ResolvedMetadataPolicy, superiorMetadataOverride?: FederationMetadata, options?: MetadataPolicyOptions): Result<FederationMetadata, FederationError>;
```

## `checkConstraints`

[Source](../../../packages/core/src/constraints/index.ts#L93)

Validate all constraints from a subordinate statement against the chain.
position identifies the Subordinate Statement carrying the constraints.
Naming constraints cover its subject and that subject's subordinates (§3.1.3).
allowed_entity_types is handled separately during validation (modifies metadata, doesn't reject chain).

```typescript signature
checkConstraints(constraints: TrustChainConstraints, position: number, chain: ParsedEntityStatement[], customChecks?: readonly ConstraintCheckDefinition[]): Result<void, FederationError>;
```

## `checkMaxPathLength`

[Source](../../../packages/core/src/constraints/index.ts#L11)

Check whether the chain path length satisfies max_path_length.
Intermediates between constrainer (position i) and leaf = i - 1.

```typescript signature
checkMaxPathLength(maxPathLength: number, constrainerPosition: number, _chainLength: number): boolean;
```

## `checkNamingConstraints`

[Source](../../../packages/core/src/constraints/index.ts#L33)

Check whether an entityId's hostname passes naming constraints.
Excluded overrides permitted. No regex (ReDoS prevention).

```typescript signature
checkNamingConstraints(namingConstraints: { permitted?: string[] | undefined; excluded?: string[] | undefined }, entityId: EntityId): boolean;
```

### Usage example

An editor can preview a naming or entity-type restriction. Full chain validation remains responsible for applying constraints at the correct position in authenticated evidence.

```ts
import { applyAllowedEntityTypes, checkMaxPathLength, checkNamingConstraints, entityId } from "@oidfed/core";

export function previewCampusConstraint(metadata: Record<string, Record<string, unknown>>) {
  return {
    nameAllowed: checkNamingConstraints({ permitted: [".campus.example"] },
      entityId("https://harbor.campus.example")),
    pathAllowed: checkMaxPathLength(1, 2, 3),
    metadata: applyAllowedEntityTypes(["openid_provider"], metadata),
  };
}
```

## `MetadataPolicyOptions`

[Source](../../../packages/core/src/metadata-policy/custom-operators.ts#L19)

Options accepted by `resolveMetadataPolicy` and `applyMetadataPolicy` for
federation-defined extension operators.

```typescript signature
interface MetadataPolicyOptions {
	/**
	 * Federation-defined operators in addition to the seven standard ones.
	 * Validated by `validateCustomOperators` on every call. Operators with
	 * names colliding with standard operators, duplicate names within the
	 * supplied set, or invalid order/action combinations are rejected.
	 */
	customOperators?: readonly PolicyOperatorDefinition[] | undefined;
}
```

Fields (including inherited fields):

| Field | Declared type | Description |
|---|---|---|
| `customOperators?` | `readonly PolicyOperatorDefinition[] \| undefined` | Federation-defined operators in addition to the seven standard ones. Validated by `validateCustomOperators` on every call. Operators with names colliding with standard operators, duplicate names within the supplied set, or invalid order/action combinations are rejected. |

## `operators`

[Source](../../../packages/core/src/metadata-policy/operators.ts#L551)

The standard metadata-policy operator definitions used for merge, combination, and application rules. Register additional operators through the options contract.

```typescript signature
const operators: Record<string, PolicyOperatorDefinition>;
```

## `resolveMetadataPolicy`

[Source](../../../packages/core/src/metadata-policy/merge.ts#L26)

Merge metadata policies from subordinate statements in TA-to-leaf order.

Accepts statements in chain order (leaf-to-TA) and reverse-iterates
so that superior policies are applied first.

```typescript signature
resolveMetadataPolicy(subordinateStatements: ParsedEntityStatement[], options?: MetadataPolicyOptions): Result<ResolvedMetadataPolicy, FederationError>;
```

## `validateCustomOperators`

[Source](../../../packages/core/src/metadata-policy/custom-operators.ts#L69)

Validate a set of federation-defined custom policy operators.

Rules:
- Operator name must not collide with a standard operator.
- No duplicate names within the supplied set.
- `action: "modify"` operators must declare `order > 1` so they apply
  after the standard `value` operator (which has order 1).
- `action: "check"` operators must declare `order < 7` so they apply
  before the standard `essential` operator (which has order 7).
- `action: "both"` operators must declare `1 < order < 7`.

```typescript signature
validateCustomOperators(operators: readonly PolicyOperatorDefinition[]): Result<void, FederationError>;
```

## `validateMetadataPolicy`

[Source](../../../packages/core/src/metadata-policy/validate.ts#L30)

Validate a declaration without applying it or requiring extension operators to be understood.

```typescript signature
validateMetadataPolicy(policy: unknown, options?: MetadataPolicyOptions): Result<void, FederationError>;
```

