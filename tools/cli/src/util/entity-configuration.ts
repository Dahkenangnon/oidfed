import {
	err,
	FederationErrorCode,
	federationError,
	type JWKSet,
	ok,
	type Result,
} from "@oidfed/core";

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
