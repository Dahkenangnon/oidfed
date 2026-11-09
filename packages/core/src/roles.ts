import { validatePublishedMetadataKeys } from "./schemas/jwk.js";
import type { EntityContext, EntityRole } from "./types.js";

/** Validate detached metadata after all roles and host metadata have been composed. */
export function validateRoleMetadata(
	roles: readonly EntityRole[] | undefined,
	metadata: Readonly<Record<string, unknown>>,
	context: EntityContext,
): void {
	validatePublishedMetadata(metadata, context.entityId);
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

/** Publication checks for supplied fields; superiors may complete partial metadata. */
export function validatePublishedMetadata(
	metadata: Readonly<Record<string, unknown>>,
	subject: string,
): void {
	validatePublishedMetadataKeys(metadata);
	for (const [type, value] of Object.entries(metadata)) {
		if (!value || typeof value !== "object" || Array.isArray(value)) continue;
		const block = value as Record<string, unknown>;
		// Federation §§5.1.3–5.1.4 bind protocol issuer identifiers to the subject.
		if (
			(type === "openid_provider" || type === "oauth_authorization_server") &&
			block.issuer !== undefined &&
			block.issuer !== subject
		)
			throw new TypeError(`${type}.issuer must equal the Entity Identifier`);
		// §5.2.1 separates protocol keys from top-level Federation Entity Keys.
		if (type === "federation_entity")
			for (const field of ["jwks", "jwks_uri", "signed_jwks_uri"])
				if (Object.hasOwn(block, field))
					throw new TypeError(`${field} must not appear in federation_entity metadata`);
	}
}
