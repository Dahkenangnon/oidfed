import { InternalErrorCode } from "../constants.js";
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
	if (options?.customOperators && options.customOperators.length > 0) {
		const customCheck = validateCustomOperators(options.customOperators);
		if (!customCheck.ok) return customCheck;
	}
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
		if (!lookup[critOp]) {
			return err({
				code: InternalErrorCode.MetadataPolicyError,
				description: `Unknown critical metadata policy operator: '${critOp}'`,
			});
		}
	}

	const merged: Record<string, Record<string, Record<string, unknown>>> = {};

	for (let i = subordinateStatements.length - 1; i >= 0; i--) {
		const stmt = subordinateStatements[i] as ParsedEntityStatement;
		const policy = stmt.payload.metadata_policy;
		if (!policy) continue;

		const clonedPolicy = structuredClone(policy) as Record<
			string,
			Record<string, Record<string, unknown>>
		>;

		for (const [entityType, paramPolicies] of Object.entries(clonedPolicy)) {
			if (!merged[entityType]) {
				merged[entityType] = {};
			}
			const mergedEntityType = merged[entityType] as Record<string, Record<string, unknown>>;

			for (const [paramName, opEntries] of Object.entries(paramPolicies)) {
				if (!mergedEntityType[paramName]) {
					mergedEntityType[paramName] = {};
				}
				const mergedParam = mergedEntityType[paramName] as Record<string, unknown>;

				for (const [opName, opValue] of Object.entries(opEntries as Record<string, unknown>)) {
					if (!lookup[opName]) continue;

					const opDef = lookup[opName] as PolicyOperatorDefinition;

					if (mergedParam[opName] !== undefined) {
						const mergeResult = opDef.merge(mergedParam[opName], opValue);
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

				const opNames = Object.keys(mergedParam).filter((k) => lookup[k] !== undefined);
				for (let a = 0; a < opNames.length; a++) {
					for (let b = a + 1; b < opNames.length; b++) {
						const opA = opNames[a] as string;
						const opB = opNames[b] as string;
						const defA = lookup[opA] as PolicyOperatorDefinition;
						const defB = lookup[opB] as PolicyOperatorDefinition;
						const valA = mergedParam[opA];
						const valB = mergedParam[opB];

						if (!defA.canCombineWith(opB, valA, valB) || !defB.canCombineWith(opA, valB, valA)) {
							return err({
								code: InternalErrorCode.MetadataPolicyError,
								description: `Incompatible operators '${opA}' and '${opB}' for ${entityType}.${paramName}`,
							});
						}
					}
				}
			}
		}
	}

	return ok(merged);
}
