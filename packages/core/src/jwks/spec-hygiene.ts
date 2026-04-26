/**
 * Opt-in helper enforcing the recommended hygiene rules on a Signed JWK Set
 * payload that the default verification path does NOT enforce.
 *
 * The default `verifySignedJwkSet` enforces only the MUSTs (typ, kid,
 * signature, REQUIRED claims). This helper additionally checks the
 * recommendations:
 *   - `sub` SHOULD equal `iss`
 *   - `aud` SHOULD NOT be present
 *   - `nbf` SHOULD be omitted
 *   - `jti` SHOULD be omitted
 *
 * Integrators wanting recommendation-grade strictness compose this helper
 * after `verifySignedJwkSet` succeeds.
 */
import { FederationErrorCode } from "../constants.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import type { SignedJwkSetPayload } from "../schemas/entity-statement.js";

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
