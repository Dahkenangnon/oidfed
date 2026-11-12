import {
	applyMetadataPolicy,
	err,
	type FederationError,
	FederationErrorCode,
	type FederationMetadata,
	type FederationOptions,
	ok,
	type Result,
	resolveMetadataPolicy,
	type ValidatedTrustChain,
} from "@oidfed/core";
import { rpMetadataChoices } from "../schemas/metadata.js";

/** Check that final registration metadata still satisfies its federation policy (§§12.2.2 and 12.2.5). */
export function validateRegistrationMetadataPolicy(
	metadata: Record<string, Record<string, unknown>>,
	chain: ValidatedTrustChain,
	options?: FederationOptions,
	declared: readonly string[] = Object.keys(chain.resolvedMetadata),
): Result<void, FederationError> {
	const fail = (description: string): Result<void, FederationError> =>
		err({ code: FederationErrorCode.InvalidMetadata, description });
	if (
		Object.keys(metadata).length !== declared.length ||
		declared.some((type) => !Object.hasOwn(metadata, type))
	) {
		return fail("Registration metadata must retain the resolved entity types");
	}
	const statements = chain.statements
		.slice(1)
		.filter((statement) => statement.payload.iss !== statement.payload.sub);
	const policyOptions = options?.customPolicyOperators
		? { customOperators: options.customPolicyOperators }
		: undefined;
	const policy = resolveMetadataPolicy(statements, policyOptions);
	if (!policy.ok) return fail(policy.error.description);
	const overrides = statements[0]?.payload.metadata;
	const modifiers = new Set(
		options?.customPolicyOperators
			?.filter((operator) => operator.action !== "check")
			.map((operator) => operator.name),
	);
	for (const type of declared) {
		const candidate = metadata[type];
		const baseline = chain.resolvedMetadata[type] ?? {};
		if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
			return fail(`Registration metadata for ${type} must be an object`);
		}
		for (const parameter of new Set([...Object.keys(baseline), ...Object.keys(candidate)])) {
			// RP Metadata Choices are federation inputs, never registration response members.
			if (
				type === "openid_relying_party" &&
				Object.hasOwn(rpMetadataChoices, parameter) &&
				!Object.hasOwn(candidate, parameter)
			)
				continue;
			const present = Object.hasOwn(candidate, parameter);
			if (
				present === Object.hasOwn(baseline, parameter) &&
				equalJson(candidate[parameter], baseline[parameter])
			)
				continue;
			const parameterPolicy = policy.value[type]?.[parameter] ?? {};
			// A custom transformation can be non-idempotent (§6.1.3.2). Its
			// already-resolved output remains authoritative for registration.
			if (Object.keys(parameterPolicy).some((name) => modifiers.has(name))) {
				return fail(
					`Registration metadata ${type}.${parameter} must retain its resolved custom-policy value`,
				);
			}
			const input = { [type]: present ? { [parameter]: candidate[parameter] } : {} };
			const superior = overrides?.[type];
			const applied = applyMetadataPolicy(
				input as FederationMetadata,
				{ [type]: { [parameter]: parameterPolicy } },
				superior && Object.hasOwn(superior, parameter)
					? ({ [type]: { [parameter]: superior[parameter] } } as FederationMetadata)
					: undefined,
				policyOptions,
			);
			if (!applied.ok) return fail(applied.error.description);
			if (!equalJson(input[type], applied.value[type])) {
				return fail(
					`Registration metadata ${type}.${parameter} conflicts with federation metadata policy or superior metadata`,
				);
			}
		}
	}
	return ok(undefined);
}

function equalJson(a: unknown, b: unknown): boolean {
	if (a === b) return true;
	if (Array.isArray(a) || Array.isArray(b)) {
		return (
			Array.isArray(a) &&
			Array.isArray(b) &&
			a.length === b.length &&
			a.every((v, i) => equalJson(v, b[i]))
		);
	}
	if (a && b && typeof a === "object" && typeof b === "object") {
		const left = a as Record<string, unknown>;
		const right = b as Record<string, unknown>;
		return (
			Object.keys(left).length === Object.keys(right).length &&
			Object.keys(left).every(
				(key) => Object.hasOwn(right, key) && equalJson(left[key], right[key]),
			)
		);
	}
	return false;
}
