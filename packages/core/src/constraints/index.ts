import { InternalErrorCode } from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import type { TrustChainConstraints } from "../schemas/constraints.js";
import type { EntityId, ParsedEntityStatement } from "../types.js";

/**
 * Check whether the chain path length satisfies max_path_length.
 * Intermediates between constrainer (position i) and leaf = i - 1.
 */
export function checkMaxPathLength(
	maxPathLength: number,
	constrainerPosition: number,
	_chainLength: number,
): boolean {
	return constrainerPosition - 1 <= maxPathLength;
}

function matchesDomainPattern(hostname: string, pattern: string): boolean {
	if (pattern.startsWith(".")) {
		return hostname.endsWith(pattern);
	}
	return hostname === pattern;
}

/**
 * Check whether an entityId's hostname passes naming constraints.
 * Excluded overrides permitted. No regex (ReDoS prevention).
 */
export function checkNamingConstraints(
	namingConstraints: { permitted?: string[] | undefined; excluded?: string[] | undefined },
	entityId: EntityId,
): boolean {
	const hostname = new URL(entityId).hostname;

	if (namingConstraints.excluded) {
		for (const pattern of namingConstraints.excluded) {
			if (matchesDomainPattern(hostname, pattern)) {
				return false;
			}
		}
	}

	if (namingConstraints.permitted) {
		return namingConstraints.permitted.some((pattern) => matchesDomainPattern(hostname, pattern));
	}

	return true;
}

/**
 * Filter metadata to only include allowed entity types.
 * Always keeps "federation_entity". Never mutates input.
 */
export function applyAllowedEntityTypes(
	allowedEntityTypes: string[],
	metadata: Record<string, Record<string, unknown>>,
): Record<string, Record<string, unknown>> {
	const allowed = new Set(allowedEntityTypes);
	allowed.add("federation_entity");

	const result: Record<string, Record<string, unknown>> = {};
	for (const key of Object.keys(metadata)) {
		if (allowed.has(key)) {
			const value = metadata[key];
			if (value !== undefined) {
				result[key] = value;
			}
		}
	}
	return result;
}

/**
 * Validate all constraints from a subordinate statement against the chain.
 * For naming_constraints: checks all entities below the constrainer.
 * allowed_entity_types is handled separately during validation (modifies metadata, doesn't reject chain).
 */
export function checkConstraints(
	constraints: TrustChainConstraints,
	position: number,
	chain: ParsedEntityStatement[],
): Result<void, FederationError> {
	if (constraints.max_path_length !== undefined) {
		if (!checkMaxPathLength(constraints.max_path_length, position, chain.length)) {
			return err({
				code: InternalErrorCode.ConstraintViolation,
				description: `max_path_length constraint violated: ${position - 1} intermediates exceed max ${constraints.max_path_length}`,
			});
		}
	}

	if (constraints.naming_constraints) {
		for (let i = 0; i < position; i++) {
			const entityId = chain[i]?.payload.sub as unknown as EntityId;
			if (!checkNamingConstraints(constraints.naming_constraints, entityId)) {
				return err({
					code: InternalErrorCode.ConstraintViolation,
					description: `naming_constraints violated by entity '${entityId}' at position ${i}`,
				});
			}
		}
	}

	return ok(undefined);
}
