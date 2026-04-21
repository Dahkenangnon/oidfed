import {
	type EntityId,
	entityId,
	err,
	FederationErrorCode,
	federationError,
	type JWKSet,
	ok,
	type Result,
} from "@oidfed/core";

export function parseEntityIdOrError(raw: string): Result<EntityId> {
	try {
		return ok(entityId(raw));
	} catch (e) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				e instanceof Error ? e.message : "Invalid entity ID",
			),
		);
	}
}

export function normalizeEntityId(raw: string): string {
	return raw.endsWith("/") ? raw.slice(0, -1) : raw;
}

export function isEntityId(value: string): boolean {
	return value.startsWith("http://") || value.startsWith("https://");
}

/**
 * Extract JWKS from an Entity Configuration payload.
 * Entity Configurations MUST contain `jwks`.
 */
export function extractJwks(payload: Record<string, unknown>): Result<JWKSet> {
	const jwks = payload.jwks as JWKSet | undefined;
	if (!jwks?.keys) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Entity Configuration missing required jwks",
			),
		);
	}
	return ok(jwks);
}
