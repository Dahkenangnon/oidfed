import { JwtTyp } from "../constants.js";
import { err, type FederationError, type Result } from "../errors.js";
import {
	apiError,
	buildVerifyOpts,
	type VerifyOptions,
	validateExpectedIssuer,
} from "../federation-api/verify-issuer.js";
import { verifyEntityStatement } from "../jose/verify.js";
import { type SignedJwkSetPayload, SignedJwkSetPayloadSchema } from "../schemas/endpoints.js";
import { EntityIdSchema } from "../schemas/entity-id.js";
import type { JWKSet } from "../schemas/jwk.js";
import { validateJwkSetUseRequirement } from "./use-requirement.js";

export interface VerifySignedJwkSetOptions extends VerifyOptions {
	/** Key owner from trusted context; §5.2.1 permits an owner distinct from the issuer. */
	expectedOwner: string;
}

/**
 * Verify and validate a Signed JWK Set JWT (returned by signed_jwks_uri).
 * Checks typ=jwk-set+jwt, signature, and required payload claims (iss, sub, keys).
 */
export async function verifySignedJwkSet(
	jwt: string,
	signerJwks: JWKSet,
	options: VerifySignedJwkSetOptions,
): Promise<Result<SignedJwkSetPayload, FederationError>> {
	const expectation = validateExpectedIssuer(options);
	if (!expectation.ok) return expectation;
	if (!EntityIdSchema.safeParse(options?.expectedOwner).success)
		return err(apiError("A valid expectedOwner is required"));
	const result = await verifyEntityStatement(
		jwt,
		signerJwks,
		buildVerifyOpts(JwtTyp.JwkSet, options),
	);
	if (!result.ok) return result;

	const parsed = SignedJwkSetPayloadSchema.safeParse(result.value.payload);
	if (!parsed.success) {
		return err(apiError(`Invalid signed JWK Set payload: ${parsed.error.message}`));
	}
	const useResult = validateJwkSetUseRequirement(parsed.data.keys, options.algorithmRegistry);
	if (!useResult.ok) return useResult;
	if (parsed.data.iss !== options.expectedIssuer)
		return err(apiError("Response issuer does not match expectedIssuer"));
	if (parsed.data.sub !== options.expectedOwner)
		return err(apiError("Signed JWK Set owner does not match expectedOwner"));
	return { ok: true, value: parsed.data };
}
