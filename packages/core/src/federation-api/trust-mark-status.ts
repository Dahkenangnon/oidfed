import { setOwn } from "../callbacks.js";
import { DEFAULT_CLOCK_SKEW_SECONDS, JwtTyp } from "../constants.js";
import { err, type FederationError, type Result } from "../errors.js";
import { verifyEntityStatement } from "../jose/verify.js";
import {
	type TrustMarkStatusResponsePayload,
	TrustMarkStatusResponsePayloadSchema,
} from "../schemas/endpoints.js";
import type { JWKSet } from "../schemas/jwk.js";
import { nowSeconds } from "../types.js";
import {
	apiError,
	buildVerifyOpts,
	type VerifyOptions,
	validateExpectedIssuer,
} from "./verify-issuer.js";

export interface VerifyTrustMarkStatusOptions extends VerifyOptions {
	/** The exact JWT submitted to the status endpoint (Federation §8.4.2). */
	expectedTrustMark: string;
	/** Host-selected maximum age; the specification supplies no universal limit. */
	maxAgeSeconds?: number;
	/** Enable future-iat rejection without selecting a maximum age. */
	checkIssuedAt?: boolean;
}

/**
 * Verify and validate a Trust Mark Status Response JWT.
 */
export async function verifyTrustMarkStatusResponse(
	jwt: string,
	issuerJwks: JWKSet,
	options: VerifyTrustMarkStatusOptions,
): Promise<Result<TrustMarkStatusResponsePayload, FederationError>> {
	const expectation = validateExpectedIssuer(options);
	if (!expectation.ok) return expectation;
	if (typeof options?.expectedTrustMark !== "string" || !options.expectedTrustMark)
		return err(apiError("A nonempty expectedTrustMark is required"));
	const result = await verifyEntityStatement(
		jwt,
		issuerJwks,
		buildVerifyOpts(JwtTyp.TrustMarkStatusResponse, options, "trust-mark-status"),
	);
	if (!result.ok) return result;

	const parsed = TrustMarkStatusResponsePayloadSchema.safeParse(result.value.payload);
	if (!parsed.success) {
		return err(apiError(`Invalid trust mark status response payload: ${parsed.error.message}`));
	}
	for (const [name, value] of Object.entries(result.value.payload))
		if (!Object.hasOwn(parsed.data, name)) setOwn(parsed.data, name, value);
	if (parsed.data.iss !== options.expectedIssuer)
		return err(apiError("Response issuer does not match expectedIssuer"));
	if (parsed.data.trust_mark !== options.expectedTrustMark)
		return err(apiError("Status response does not match the submitted Trust Mark"));
	if (options.checkIssuedAt || options.maxAgeSeconds !== undefined) {
		const now = nowSeconds(options.clock);
		if (parsed.data.iat > now + (options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS))
			return err(apiError("Trust Mark Status Response was issued in the future"));
		if (
			options.maxAgeSeconds !== undefined &&
			(!Number.isFinite(options.maxAgeSeconds) ||
				options.maxAgeSeconds <= 0 ||
				now >= parsed.data.iat + options.maxAgeSeconds)
		)
			return err(apiError("Trust Mark Status Response exceeds the selected maximum age"));
	}
	return { ok: true, value: parsed.data };
}
