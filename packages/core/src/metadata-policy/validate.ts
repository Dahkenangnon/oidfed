import { callSynchronous, freezeSnapshot, isJsonData, isObject } from "../callbacks.js";
import { InternalErrorCode } from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import type {
	PolicyMergeResult,
	PolicyOperatorDefinition,
	PolicyOperatorResult,
} from "../types.js";
import {
	buildOperatorLookup,
	type MetadataPolicyOptions,
	validateCustomOperators,
} from "./custom-operators.js";
import { validateStandardPolicyOperatorConfiguration } from "./operators.js";

export function isPolicyResult(value: unknown): value is PolicyOperatorResult & PolicyMergeResult {
	return (
		isObject(value) &&
		Object.hasOwn(value, "ok") &&
		(value.ok === false
			? typeof value.error === "string"
			: value.ok === true &&
				Object.hasOwn(value, "value") &&
				(value.value === undefined || isJsonData(value.value)) &&
				(value.removed === undefined || typeof value.removed === "boolean"))
	);
}

/** Validate a declaration without applying it or requiring extension operators to be understood. */
export function validateMetadataPolicy(
	policy: unknown,
	options?: MetadataPolicyOptions,
): Result<void, FederationError> {
	const custom = validateCustomOperators(options?.customOperators ?? []);
	if (!custom.ok) return custom;
	return validatePolicyDeclaration(policy, buildOperatorLookup(options?.customOperators));
}

export function validatePolicyDeclaration(
	policy: unknown,
	lookup: Record<string, PolicyOperatorDefinition>,
): Result<void, FederationError> {
	const fail = (description: string) =>
		err({ code: InternalErrorCode.MetadataPolicyError, description });
	if (!isObject(policy) || !isJsonData(policy))
		return fail("metadata_policy must be a JSON object");
	for (const [type, parameters] of Object.entries(policy)) {
		if (!isObject(parameters)) return fail(`metadata_policy.${type} must be a JSON object`);
		for (const [parameter, entries] of Object.entries(parameters)) {
			if (!isObject(entries))
				return fail(`metadata_policy.${type}.${parameter} must be a JSON object`);
			const names = Object.keys(entries).filter((name) => Object.hasOwn(lookup, name));
			for (const name of names) {
				const error = validateStandardPolicyOperatorConfiguration(name, entries[name]);
				if (error) return fail(`Invalid '${name}' operator for ${type}.${parameter}: ${error}`);
			}
			for (let a = 0; a < names.length; a++) {
				for (let b = a + 1; b < names.length; b++) {
					const first = names[a] as string;
					const second = names[b] as string;
					const left = callSynchronous(
						() =>
							(lookup[first] as PolicyOperatorDefinition).canCombineWith(
								second,
								freezeSnapshot(structuredClone(entries[first])),
								freezeSnapshot(structuredClone(entries[second])),
							),
						(v): v is boolean => typeof v === "boolean",
					);
					const right = callSynchronous(
						() =>
							(lookup[second] as PolicyOperatorDefinition).canCombineWith(
								first,
								freezeSnapshot(structuredClone(entries[second])),
								freezeSnapshot(structuredClone(entries[first])),
							),
						(v): v is boolean => typeof v === "boolean",
					);
					if (!left.ok || !right.ok)
						return fail(
							`Operator combination callback failed for ${type}.${parameter}: ${!left.ok ? left.error : !right.ok ? right.error : "invalid result"}`,
						);
					if (!left.value || !right.value)
						return fail(
							`Incompatible operators '${first}' and '${second}' for ${type}.${parameter}`,
						);
				}
			}
		}
	}
	return ok(undefined);
}
