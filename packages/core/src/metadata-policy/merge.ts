import { callSynchronous } from "../callbacks.js";
import { InternalErrorCode, PolicyOperator } from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import type {
	ParsedEntityStatement,
	PolicyOperatorDefinition,
	ResolvedMetadataPolicy,
} from "../types.js";
import {
	buildOperatorLookup,
	type MetadataPolicyOptions,
	validateCustomOperators,
} from "./custom-operators.js";
import { isPolicyResult, validatePolicyDeclaration } from "./validate.js";

const STANDARD_METADATA_POLICY_OPERATORS: ReadonlySet<string> = new Set(
	Object.values(PolicyOperator),
);

/**
 * Merge metadata policies from subordinate statements in TA-to-leaf order.
 *
 * Accepts statements in chain order (leaf-to-TA) and reverse-iterates
 * so that superior policies are applied first.
 */
export function resolveMetadataPolicy(
	subordinateStatements: ParsedEntityStatement[],
	options?: MetadataPolicyOptions,
): Result<ResolvedMetadataPolicy, FederationError> {
	const customCheck = validateCustomOperators(options?.customOperators ?? []);
	if (!customCheck.ok) return customCheck;
	const lookup: Record<string, PolicyOperatorDefinition> = buildOperatorLookup(
		options?.customOperators,
	);

	const criticalOps = new Set<string>();
	for (const stmt of subordinateStatements) {
		const crit = stmt.payload.metadata_policy_crit;
		if (crit) {
			for (const op of crit) {
				criticalOps.add(op);
			}
		}
	}

	for (const critOp of criticalOps) {
		if (STANDARD_METADATA_POLICY_OPERATORS.has(critOp)) {
			return err({
				code: InternalErrorCode.MetadataPolicyError,
				description: `metadata_policy_crit must not list standard metadata policy operator '${critOp}'`,
			});
		}
		if (!Object.hasOwn(lookup, critOp)) {
			return err({
				code: InternalErrorCode.MetadataPolicyError,
				description: `Unknown critical metadata policy operator: '${critOp}'`,
			});
		}
	}

	const merged: Record<string, Record<string, Record<string, unknown>>> = Object.create(null);

	for (let i = subordinateStatements.length - 1; i >= 0; i--) {
		const stmt = subordinateStatements[i] as ParsedEntityStatement;
		const policy = stmt.payload.metadata_policy;
		if (!policy) continue;

		const declaration = validatePolicyDeclaration(policy, lookup);
		if (!declaration.ok) return declaration;
		const clonedPolicy = structuredClone(policy) as Record<
			string,
			Record<string, Record<string, unknown>>
		>;

		for (const [entityType, paramPolicies] of Object.entries(clonedPolicy)) {
			if (!Object.hasOwn(merged, entityType)) {
				merged[entityType] = Object.create(null);
			}
			const mergedEntityType = merged[entityType] as Record<string, Record<string, unknown>>;

			for (const [paramName, opEntries] of Object.entries(paramPolicies)) {
				if (!Object.hasOwn(mergedEntityType, paramName)) {
					mergedEntityType[paramName] = Object.create(null);
				}
				const mergedParam = mergedEntityType[paramName] as Record<string, unknown>;

				for (const [opName, opValue] of Object.entries(opEntries as Record<string, unknown>)) {
					if (!Object.hasOwn(lookup, opName)) continue;

					const opDef = lookup[opName] as PolicyOperatorDefinition;

					if (Object.hasOwn(mergedParam, opName)) {
						const callback = callSynchronous(
							() => opDef.merge(mergedParam[opName], opValue),
							isPolicyResult,
						);
						if (!callback.ok)
							return err({
								code: InternalErrorCode.MetadataPolicyError,
								description: `Failed to merge '${opName}' for ${entityType}.${paramName}: ${callback.error}`,
							});
						const mergeResult = callback.value;
						if (mergeResult.ok && mergeResult.value === undefined)
							return err({
								code: InternalErrorCode.MetadataPolicyError,
								description: `Invalid merge output for ${entityType}.${paramName}`,
							});
						if (!mergeResult.ok) {
							return err({
								code: InternalErrorCode.MetadataPolicyError,
								description: `Failed to merge '${opName}' operator for ${entityType}.${paramName}: ${mergeResult.error}`,
							});
						}
						mergedParam[opName] = mergeResult.value;
					} else {
						mergedParam[opName] = opValue;
					}
				}

				const combined = validatePolicyDeclaration(
					{ [entityType]: { [paramName]: mergedParam } },
					lookup,
				);
				if (!combined.ok) return combined;
			}
		}
	}

	return ok(
		Object.fromEntries(
			Object.entries(merged).map(([type, parameters]) => [
				type,
				Object.fromEntries(
					Object.entries(parameters).map(([name, entries]) => [
						name,
						Object.fromEntries(Object.entries(entries)),
					]),
				),
			]),
		),
	);
}
