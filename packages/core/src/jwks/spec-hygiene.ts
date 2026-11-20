/**
 * Optional checks for Signed JWK Set payload recommendations.
 *
 * `verifySignedJwkSet` checks the expected issuer and owner, JWT type, kid, signature,
 * and required claims. After it succeeds, this helper can enforce these recommendations:
 * - `sub` SHOULD equal `iss`.
 * - `aud` SHOULD NOT be present.
 * - `nbf` SHOULD be omitted.
 * - `jti` SHOULD be omitted.
 */

import { FederationErrorCode } from "../constants.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import type { SignedJwkSetPayload } from "../schemas/endpoints.js";

/**
 * Apply the optional Signed JWK Set claim recommendations after signature verification.
 * This function checks payload hygiene; it does not authenticate the JWT.
 */
export function validateSignedJwkSetSpecHygiene(
	payload: SignedJwkSetPayload,
): Result<void, FederationError> {
	if (payload.sub !== payload.iss) {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				`Signed JWK Set 'sub' ('${payload.sub}') should equal 'iss' ('${payload.iss}')`,
			),
		);
	}
	const extra = payload as Record<string, unknown>;
	if (extra.aud !== undefined) {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				"Signed JWK Set should not include 'aud'",
			),
		);
	}
	if (extra.nbf !== undefined) {
		return err(
			federationError(FederationErrorCode.InvalidMetadata, "Signed JWK Set should omit 'nbf'"),
		);
	}
	if (extra.jti !== undefined) {
		return err(
			federationError(FederationErrorCode.InvalidMetadata, "Signed JWK Set should omit 'jti'"),
		);
	}
	return ok(undefined);
}
