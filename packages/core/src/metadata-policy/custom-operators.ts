/**
 * Validate federation-defined policy operators supplied through
 * `MetadataPolicyOptions.customOperators`. Unknown non-critical operators are ignored;
 * unknown critical operators cause a policy error.
 */

import { InternalErrorCode, PolicyOperator } from "../constants.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import type { PolicyOperatorDefinition } from "../types.js";
import { operators } from "./operators.js";

/**
 * Options accepted by `resolveMetadataPolicy` and `applyMetadataPolicy` for
 * federation-defined extension operators.
 */
export interface MetadataPolicyOptions {
	/**
	 * Federation-defined operators in addition to the seven standard ones.
	 * Validated by `validateCustomOperators` on every call. Operators with
	 * names colliding with standard operators, duplicate names within the
	 * supplied set, or invalid order/action combinations are rejected.
	 */
	customOperators?: readonly PolicyOperatorDefinition[] | undefined;
}

/**
 * Build a per-call operator lookup combining the standard registry with the
 * supplied custom operators. Caller MUST have validated the custom set with
 * `validateCustomOperators` first; this helper is a pure merge.
 */
export function buildOperatorLookup(
	customOperators: readonly PolicyOperatorDefinition[] | undefined,
): Record<string, PolicyOperatorDefinition> {
	const merged: Record<string, PolicyOperatorDefinition> = Object.assign(
		Object.create(null) as Record<string, PolicyOperatorDefinition>,
		operators,
	);
	for (const op of customOperators ?? []) {
		merged[op.name] = op;
	}
	return merged;
}

const STANDARD_OPERATOR_NAMES: ReadonlySet<string> = new Set([
	PolicyOperator.Value,
	PolicyOperator.Add,
	PolicyOperator.Default,
	PolicyOperator.OneOf,
	PolicyOperator.SubsetOf,
	PolicyOperator.SupersetOf,
	PolicyOperator.Essential,
]);

/**
 * Validate a set of federation-defined custom policy operators.
 *
 * Rules:
 * - Operator name must not collide with a standard operator.
 * - No duplicate names within the supplied set.
 * - `action: "modify"` operators must declare `order > 1` so they apply
 *   after the standard `value` operator (which has order 1).
 * - `action: "check"` operators must declare `order < 7` so they apply
 *   before the standard `essential` operator (which has order 7).
 * - `action: "both"` operators must declare `1 < order < 7`.
 */
export function validateCustomOperators(
	operators: readonly PolicyOperatorDefinition[],
): Result<void, FederationError> {
	const definitions = operators;
	const seen = new Set<string>();
	if (!Array.isArray(operators))
		return err(
			federationError(
				InternalErrorCode.MetadataPolicyError,
				"Custom policy operators must be an array",
			),
		);
	for (const op of definitions) {
		if (
			!op ||
			typeof op.name !== "string" ||
			!Number.isFinite(op.order) ||
			!["check", "modify", "both"].includes(op.action) ||
			typeof op.apply !== "function" ||
			typeof op.merge !== "function" ||
			typeof op.canCombineWith !== "function"
		)
			return err(
				federationError(
					InternalErrorCode.MetadataPolicyError,
					"Custom policy operators require a name, finite order, supported action, and callable apply, merge, and canCombineWith methods",
				),
			);
		if (STANDARD_OPERATOR_NAMES.has(op.name)) {
			return err(
				federationError(
					InternalErrorCode.MetadataPolicyError,
					`Custom policy operator name '${op.name}' conflicts with a standard operator`,
				),
			);
		}
		if (seen.has(op.name)) {
			return err(
				federationError(
					InternalErrorCode.MetadataPolicyError,
					`Duplicate custom policy operator name: '${op.name}'`,
				),
			);
		}
		seen.add(op.name);

		if (op.action === "modify" && op.order <= 1) {
			return err(
				federationError(
					InternalErrorCode.MetadataPolicyError,
					`Custom modify-action operator '${op.name}' must declare order > 1 (apply after standard 'value')`,
				),
			);
		}
		if (op.action === "check" && op.order >= 7) {
			return err(
				federationError(
					InternalErrorCode.MetadataPolicyError,
					`Custom check-action operator '${op.name}' must declare order < 7 (apply before standard 'essential')`,
				),
			);
		}
		if (op.action === "both" && (op.order <= 1 || op.order >= 7)) {
			return err(
				federationError(
					InternalErrorCode.MetadataPolicyError,
					`Custom 'both'-action operator '${op.name}' must declare 1 < order < 7`,
				),
			);
		}
	}
	return ok(undefined);
}
