/** Retrieval, verification, and key selection for Federation Historical Keys. */

import { FederationErrorCode, JwtTyp, MediaType } from "../constants.js";
import { cloneData } from "../data-copy.js";
import { fetchFederationEndpoint } from "../endpoint-client.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import { verifyEntityStatement } from "../jose/verify.js";
import { safeLogger } from "../logging.js";
import { parseMetadataUrl } from "../metadata-url.js";
import {
	type HistoricalKeyEntry,
	type HistoricalKeysPayload,
	HistoricalKeysPayloadSchema,
} from "../schemas/endpoints.js";
import type { JWKSet } from "../schemas/jwk.js";
import type { Clock, FederationOptions } from "../types.js";
import {
	apiError,
	buildVerifyOpts,
	type VerifyOptions,
	validateExpectedIssuer,
} from "./verify-issuer.js";

/**
 * Verify and validate a Historical Keys Response JWT.
 */
export async function verifyHistoricalKeysResponse(
	jwt: string,
	issuerJwks: JWKSet,
	options: VerifyOptions,
): Promise<Result<HistoricalKeysPayload, FederationError>> {
	const expectation = validateExpectedIssuer(options);
	if (!expectation.ok) return expectation;
	const result = await verifyEntityStatement(
		jwt,
		issuerJwks,
		buildVerifyOpts(JwtTyp.JwkSet, options),
	);
	if (!result.ok) return result;

	const parsed = HistoricalKeysPayloadSchema.safeParse(result.value.payload);
	if (!parsed.success) {
		return err(apiError(`Invalid historical keys response payload: ${parsed.error.message}`));
	}
	if (parsed.data.iss !== options.expectedIssuer)
		return err(apiError("Response issuer does not match expectedIssuer"));
	return { ok: true, value: parsed.data };
}

const SECURITY_REVOCATION_REASONS = new Set(["compromised", "keyCompromise", "key_compromise"]);

export interface SelectHistoricalVerificationKeyOptions {
	readonly kid: string;
	readonly validAt: number;
	/** Additional security-revocation reasons defined by the federation (§8.7.3), matched exactly. */
	readonly securityRevocationReasons?: readonly string[];
	/** Explicit non-security reasons allowing signatures strictly before revocation. Default rejects all revoked keys. */
	readonly allowedRevocationReasons?: readonly string[];
}

/** Select a historical key usable for verifying material issued at the supplied NumericDate. */
export function selectHistoricalVerificationKey(
	keys: readonly HistoricalKeyEntry[],
	options: SelectHistoricalVerificationKeyOptions,
): Result<HistoricalKeyEntry, FederationError> {
	if (!Number.isFinite(options.validAt) || !options.kid)
		return err(apiError("Historical key selection requires a finite time and kid"));
	const matchingKeys = keys.filter((key) => key.kid === options.kid);
	if (matchingKeys.length !== 1) return err(apiError("Historical key is missing or ambiguous"));
	const key = matchingKeys[0];
	if (!key) return err(apiError("Historical key is missing"));
	if (
		!Number.isFinite(key.exp) ||
		options.validAt >= key.exp ||
		(key.iat !== undefined && (!Number.isFinite(key.iat) || options.validAt < key.iat)) ||
		(key.nbf !== undefined && (!Number.isFinite(key.nbf) || options.validAt < key.nbf))
	)
		return err(apiError("Historical key was not eligible at signing time"));
	const revoked = key.revoked;
	if (revoked) {
		const reason = revoked.reason;
		if (
			!Number.isFinite(revoked.revoked_at) ||
			options.validAt >= revoked.revoked_at ||
			!reason ||
			reason === "unspecified" ||
			SECURITY_REVOCATION_REASONS.has(reason) ||
			options.securityRevocationReasons?.includes(reason) ||
			!options.allowedRevocationReasons?.includes(reason)
		)
			return err(apiError("Historical key is revoked"));
	}
	return ok(cloneData(key));
}

export interface FetchHistoricalKeysOptions extends FederationOptions, VerifyOptions {
	clockSkewSeconds?: number;
	clock?: Clock;
}

/** Fetch and verify a Historical Keys JWT from a federation Historical Keys endpoint. */
export async function fetchHistoricalKeys(
	endpoint: string,
	signerJwks: JWKSet,
	options: FetchHistoricalKeysOptions,
): Promise<Result<HistoricalKeysPayload, FederationError>> {
	safeLogger(options?.logger)?.debug("Starting fetch historical keys");

	const expectation = validateExpectedIssuer(options);
	if (!expectation.ok) return expectation;
	const parsed = parseMetadataUrl(endpoint, FederationErrorCode.InvalidRequest);
	if (!parsed.ok) return parsed;

	const fetched = await fetchFederationEndpoint(
		endpoint,
		new URLSearchParams(),
		{
			...options,
			expectedStatus: 200,
			accept: MediaType.JwkSet,
			expectedContentType: MediaType.JwkSet,
		},
		options.expectedIssuer,
	);
	if (!fetched.ok) return fetched;

	return verifyHistoricalKeysResponse(fetched.value, signerJwks, options);
}
