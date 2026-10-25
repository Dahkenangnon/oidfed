import type { EntityContext, EntityRole } from "./types.js";

/** Validate detached metadata after all roles and host metadata have been composed. */
export function validateRoleMetadata(
	roles: readonly EntityRole[] | undefined,
	metadata: Readonly<Record<string, unknown>>,
	context: EntityContext,
): void {
	for (const role of roles ?? []) {
		if (role.validateMetadata) {
			const block = metadata[role.type];
			if (!block || typeof block !== "object" || Array.isArray(block)) {
				throw new Error(`Metadata for role '${role.type}' must be an object`);
			}
			role.validateMetadata(
				Object.freeze(structuredClone(block) as Record<string, unknown>),
				context,
			);
		}
	}
}
