import { InternalErrorCode } from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import type { FederationMetadata } from "../schemas/metadata.js";
import type { PolicyOperatorDefinition, ResolvedMetadataPolicy } from "../types.js";
import {
	buildOperatorLookup,
	type MetadataPolicyOptions,
	validateCustomOperators,
} from "./custom-operators.js";
import { hasOwn, isPrototypeKey } from "./safe-keys.js";

export type { MetadataPolicyOptions };

/** Apply a resolved metadata policy to federation metadata, returning the transformed metadata. */
export function applyMetadataPolicy(
	metadata: FederationMetadata,
	policy: ResolvedMetadataPolicy,
	superiorMetadataOverride?: FederationMetadata,
	options?: MetadataPolicyOptions,
): Result<FederationMetadata, FederationError> {
	if (options?.customOperators && options.customOperators.length > 0) {
		const customCheck = validateCustomOperators(options.customOperators);
		if (!customCheck.ok) return customCheck;
	}
	const lookup: Record<string, PolicyOperatorDefinition> = buildOperatorLookup(
		options?.customOperators,
	);

	const result = structuredClone(metadata) as Record<string, Record<string, unknown>>;
	const metadataKeyError = findUnsafeMetadataKey(result);
	if (metadataKeyError) return unsafeMetadataKey(metadataKeyError);

	if (superiorMetadataOverride) {
		for (const [entityType, params] of Object.entries(superiorMetadataOverride)) {
			if (isPrototypeKey(entityType)) return unsafeMetadataKey(entityType);
			if (!hasOwn(result, entityType)) {
				result[entityType] = {};
			}
			const entityResult = result[entityType];
			for (const [param, value] of Object.entries(params as Record<string, unknown>)) {
				if (isPrototypeKey(param)) return unsafeMetadataKey(`${entityType}.${param}`);
				if (entityResult) entityResult[param] = value;
			}
		}
	}

	for (const [entityType, paramPolicies] of Object.entries(policy)) {
		if (isPrototypeKey(entityType)) return unsafeMetadataKey(entityType);
		if (!hasOwn(result, entityType)) {
			result[entityType] = {};
		}
		const entityMetadata = result[entityType] as Record<string, unknown>;

		for (const [paramName, opEntries] of Object.entries(paramPolicies)) {
			if (isPrototypeKey(paramName)) return unsafeMetadataKey(`${entityType}.${paramName}`);
			const unsafeOperator = Object.keys(opEntries as Record<string, unknown>).find(isPrototypeKey);
			if (unsafeOperator) {
				return unsafeMetadataKey(`${entityType}.${paramName}.${unsafeOperator}`);
			}
			const sortedOps = Object.entries(opEntries as Record<string, unknown>)
				.filter(([opName]) => hasOwn(lookup, opName))
				.sort(([a], [b]) => (lookup[a]?.order ?? 0) - (lookup[b]?.order ?? 0));

			// Scope is space-delimited in OIDC but operators expect arrays
			const isScope = paramName === "scope";
			let scopeWasNormalized = false;
			if (isScope && typeof entityMetadata[paramName] === "string") {
				entityMetadata[paramName] = normalizeScope(entityMetadata[paramName] as string);
				scopeWasNormalized = true;
			}

			for (const [opName, opValue] of sortedOps) {
				const opDef = lookup[opName] as PolicyOperatorDefinition;
				const currentValue = entityMetadata[paramName];
				const applyResult = opDef.apply(currentValue, opValue);

				if (!applyResult.ok) {
					return err({
						code: InternalErrorCode.MetadataPolicyViolation,
						description: `Policy violation for ${entityType}.${paramName} (operator '${opName}'): ${applyResult.error}`,
					});
				}

				if (applyResult.removed) {
					delete entityMetadata[paramName];
				} else if (applyResult.value === null) {
					return err({
						code: InternalErrorCode.MetadataPolicyViolation,
						description: `Policy violation for ${entityType}.${paramName} (operator '${opName}'): operator output must not be null`,
					});
				} else {
					entityMetadata[paramName] = applyResult.value;
				}
			}

			if (scopeWasNormalized && Array.isArray(entityMetadata[paramName])) {
				entityMetadata[paramName] = denormalizeScope(entityMetadata[paramName] as string[]);
			}
		}
	}

	return ok(result as FederationMetadata);
}

function findUnsafeMetadataKey(
	metadata: Record<string, Record<string, unknown>>,
): string | undefined {
	for (const [entityType, params] of Object.entries(metadata)) {
		if (isPrototypeKey(entityType)) return entityType;
		for (const param of Object.keys(params)) {
			if (isPrototypeKey(param)) return `${entityType}.${param}`;
		}
	}
	return undefined;
}

function unsafeMetadataKey(path: string): Result<never, FederationError> {
	return err({
		code: InternalErrorCode.MetadataPolicyViolation,
		description: `Metadata policy contains unsafe key '${path}'`,
	});
}

export function normalizeScope(scope: string): string[] {
	return scope.split(" ").filter(Boolean);
}

export function denormalizeScope(values: string[]): string {
	return values.join(" ");
}
