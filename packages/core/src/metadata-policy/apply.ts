import { InternalErrorCode } from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import type { FederationMetadata } from "../schemas/metadata.js";
import type { ResolvedMetadataPolicy } from "../types.js";
import { operators } from "./operators.js";

/** Apply a resolved metadata policy to federation metadata, returning the transformed metadata. */
export function applyMetadataPolicy(
	metadata: FederationMetadata,
	policy: ResolvedMetadataPolicy,
	superiorMetadataOverride?: FederationMetadata,
): Result<FederationMetadata, FederationError> {
	const result = structuredClone(metadata) as Record<string, Record<string, unknown>>;

	if (superiorMetadataOverride) {
		for (const [entityType, params] of Object.entries(superiorMetadataOverride)) {
			if (!result[entityType]) {
				result[entityType] = {};
			}
			const entityResult = result[entityType];
			for (const [param, value] of Object.entries(params as Record<string, unknown>)) {
				if (entityResult) entityResult[param] = value;
			}
		}
	}

	for (const [entityType, paramPolicies] of Object.entries(policy)) {
		if (!result[entityType]) {
			result[entityType] = {};
		}
		const entityMetadata = result[entityType] as Record<string, unknown>;

		for (const [paramName, opEntries] of Object.entries(paramPolicies)) {
			const sortedOps = Object.entries(opEntries as Record<string, unknown>)
				.filter(([opName]) => operators[opName] !== undefined)
				.sort(([a], [b]) => (operators[a]?.order ?? 0) - (operators[b]?.order ?? 0));

			// Scope is space-delimited in OIDC but operators expect arrays
			const isScope = paramName === "scope";
			let scopeWasNormalized = false;
			if (isScope && typeof entityMetadata[paramName] === "string") {
				entityMetadata[paramName] = normalizeScope(entityMetadata[paramName] as string);
				scopeWasNormalized = true;
			}

			for (const [opName, opValue] of sortedOps) {
				const opDef = operators[opName] as (typeof operators)[string];
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

export function normalizeScope(scope: string): string[] {
	return scope.split(" ").filter(Boolean);
}

export function denormalizeScope(values: string[]): string {
	return values.join(" ");
}
