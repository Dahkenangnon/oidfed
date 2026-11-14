import { callSynchronous, setOwn } from "../callbacks.js";
import { EntityType, InternalErrorCode } from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import { type FederationMetadata, FederationMetadataValuesSchema } from "../schemas/metadata.js";
import type { PolicyOperatorDefinition, ResolvedMetadataPolicy } from "../types.js";
import {
	buildOperatorLookup,
	type MetadataPolicyOptions,
	validateCustomOperators,
} from "./custom-operators.js";
import { isPolicyResult } from "./validate.js";

export type { MetadataPolicyOptions };

/** Apply a resolved metadata policy to federation metadata, returning the transformed metadata. */
export function applyMetadataPolicy(
	metadata: FederationMetadata,
	policy: ResolvedMetadataPolicy,
	superiorMetadataOverride?: FederationMetadata,
	options?: MetadataPolicyOptions,
): Result<FederationMetadata, FederationError> {
	try {
		const customCheck = validateCustomOperators(options?.customOperators ?? []);
		if (!customCheck.ok) return customCheck;
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
					if (entityResult) setOwn(entityResult, param, structuredClone(value));
				}
			}
		}

		for (const [entityType, paramPolicies] of Object.entries(policy)) {
			// §§6.1.1 and 6.2.3: apply policies only to types retained in the metadata.
			if (!Object.hasOwn(result, entityType)) continue;
			const entityMetadata = result[entityType] as Record<string, unknown>;

			for (const [paramName, opEntries] of Object.entries(paramPolicies)) {
				const sortedOps = Object.entries(opEntries as Record<string, unknown>)
					.filter(([opName]) => Object.hasOwn(lookup, opName))
					.sort(([a], [b]) => (lookup[a]?.order ?? 0) - (lookup[b]?.order ?? 0));

				// Federation §6.1.3.1.8 applies to the OAuth client scope parameter.
				const isScope =
					paramName === "scope" &&
					(entityType === EntityType.OpenIDRelyingParty || entityType === EntityType.OAuthClient);
				if (isScope && typeof entityMetadata[paramName] === "string") {
					entityMetadata[paramName] = normalizeScope(entityMetadata[paramName] as string);
				}

				for (const [opName, opValue] of sortedOps) {
					const opDef = lookup[opName] as PolicyOperatorDefinition;
					const currentValue = Object.hasOwn(entityMetadata, paramName)
						? entityMetadata[paramName]
						: undefined;
					const callback = callSynchronous(
						() => opDef.apply(currentValue, opValue),
						isPolicyResult,
					);
					if (!callback.ok)
						return err({
							code: InternalErrorCode.MetadataPolicyViolation,
							description: `Policy callback for ${entityType}.${paramName} (operator '${opName}'): ${callback.error}`,
						});
					const applyResult = callback.value;

					if (!applyResult.ok) {
						return err({
							code: InternalErrorCode.MetadataPolicyViolation,
							description: `Policy violation for ${entityType}.${paramName} (operator '${opName}'): ${applyResult.error}`,
						});
					}

					if (applyResult.removed || applyResult.value === undefined) {
						delete entityMetadata[paramName];
					} else if (applyResult.value === null) {
						return err({
							code: InternalErrorCode.MetadataPolicyViolation,
							description: `Policy violation for ${entityType}.${paramName} (operator '${opName}'): operator output must not be null`,
						});
					} else {
						try {
							setOwn(entityMetadata, paramName, structuredClone(applyResult.value));
						} catch {
							return err({
								code: InternalErrorCode.MetadataPolicyViolation,
								description: `Invalid operator output for ${entityType}.${paramName}`,
							});
						}
					}
				}

				// Federation §6.1.3.1.8: policy-generated scopes also resolve to a string.
				const scopeValues = Object.hasOwn(entityMetadata, paramName)
					? entityMetadata[paramName]
					: undefined;
				if (isScope && Array.isArray(scopeValues)) {
					for (const value of scopeValues) {
						if (typeof value !== "string") {
							return err({
								code: InternalErrorCode.MetadataPolicyViolation,
								description: `Invalid resolved metadata: ${entityType}.scope must contain only strings`,
							});
						}
					}
					entityMetadata[paramName] = denormalizeScope(scopeValues as string[]);
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
	} catch {
		return err({
			code: InternalErrorCode.MetadataPolicyViolation,
			description: "Metadata policy data could not be processed safely",
		});
	}
}

export function normalizeScope(scope: string): string[] {
	return scope.split(" ").filter(Boolean);
}

export function denormalizeScope(values: string[]): string {
	return values.join(" ");
}
