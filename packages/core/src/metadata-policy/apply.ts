import { InternalErrorCode } from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import { type FederationMetadata, FederationMetadataValuesSchema } from "../schemas/metadata.js";
import type { PolicyOperatorDefinition, ResolvedMetadataPolicy } from "../types.js";
import {
	buildOperatorLookup,
	type MetadataPolicyOptions,
	validateCustomOperators,
} from "./custom-operators.js";

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
	// Federation §3.1.1 requires an object for every declared entity type.
	for (const [entityType, value] of Object.entries(result)) {
		if (value === null || typeof value !== "object" || Array.isArray(value)) {
			return err({
				code: InternalErrorCode.MetadataPolicyViolation,
				description: `Invalid metadata: ${entityType} must be a JSON object`,
			});
		}
	}

	if (superiorMetadataOverride) {
		for (const [entityType, params] of Object.entries(superiorMetadataOverride)) {
			// Federation §3.1.1: superior metadata applies to declared entity types.
			if (!Object.hasOwn(result, entityType)) continue;
			const entityResult = result[entityType];
			for (const [param, value] of Object.entries(params as Record<string, unknown>)) {
				if (entityResult) entityResult[param] = value;
			}
		}
	}

	for (const [entityType, paramPolicies] of Object.entries(policy)) {
		// §§6.1.1 and 6.2.3: apply policies only to types retained in the metadata.
		if (!Object.hasOwn(result, entityType)) continue;
		const entityMetadata = result[entityType] as Record<string, unknown>;

		for (const [paramName, opEntries] of Object.entries(paramPolicies)) {
			const sortedOps = Object.entries(opEntries as Record<string, unknown>)
				.filter(([opName]) => lookup[opName] !== undefined)
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

	// Federation §6.1.4.2: check the completed result after every operator has run.
	const validated = FederationMetadataValuesSchema.safeParse(result);
	if (!validated.success) {
		return err({
			code: InternalErrorCode.MetadataPolicyViolation,
			description: `Invalid resolved metadata: ${validated.error.issues.map((issue) => `${issue.path.map(String).join(".")}: ${issue.message}`).join("; ")}`,
		});
	}

	return ok(result as FederationMetadata);
}

export function normalizeScope(scope: string): string[] {
	return scope.split(" ").filter(Boolean);
}

export function denormalizeScope(values: string[]): string {
	return values.join(" ");
}
