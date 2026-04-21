import { InternalErrorCode, JwtTyp } from "../constants.js";
import { err, type FederationError, type Result } from "../errors.js";
import { verifyEntityStatement } from "../jose/verify.js";
import {
	type HistoricalKeysPayload,
	HistoricalKeysPayloadSchema,
	type ResolveResponsePayload,
	ResolveResponsePayloadSchema,
	type SignedJwkSetPayload,
	SignedJwkSetPayloadSchema,
	type TrustMarkStatusResponsePayload,
	TrustMarkStatusResponsePayloadSchema,
} from "../schemas/entity-statement.js";
import type { JWKSet } from "../schemas/jwk.js";
import type { Clock } from "../types.js";

function apiError(description: string): FederationError {
	return { code: InternalErrorCode.SignatureInvalid, description };
}

interface VerifyOptions {
	clockSkewSeconds?: number;
	clock?: Clock;
}

function buildVerifyOpts(expectedTyp: string, options?: VerifyOptions) {
	const opts: { expectedTyp: string; clockSkewSeconds?: number; clock?: Clock } = { expectedTyp };
	if (options?.clockSkewSeconds !== undefined) opts.clockSkewSeconds = options.clockSkewSeconds;
	if (options?.clock !== undefined) opts.clock = options.clock;
	return opts;
}

/**
 * Verify and validate a Resolve Response JWT. Checks typ, signature, and claims.
 */
export async function verifyResolveResponse(
	jwt: string,
	issuerJwks: JWKSet,
	options?: VerifyOptions,
): Promise<Result<ResolveResponsePayload, FederationError>> {
	const result = await verifyEntityStatement(
		jwt,
		issuerJwks,
		buildVerifyOpts(JwtTyp.ResolveResponse, options),
	);
	if (!result.ok) return result;

	const parsed = ResolveResponsePayloadSchema.safeParse(result.value.payload);
	if (!parsed.success) {
		return err(apiError(`Invalid resolve response payload: ${parsed.error.message}`));
	}
	return { ok: true, value: parsed.data };
}

/**
 * Verify and validate a Trust Mark Status Response JWT.
 */
export async function verifyTrustMarkStatusResponse(
	jwt: string,
	issuerJwks: JWKSet,
	options?: VerifyOptions,
): Promise<Result<TrustMarkStatusResponsePayload, FederationError>> {
	const result = await verifyEntityStatement(
		jwt,
		issuerJwks,
		buildVerifyOpts(JwtTyp.TrustMarkStatusResponse, options),
	);
	if (!result.ok) return result;

	const parsed = TrustMarkStatusResponsePayloadSchema.safeParse(result.value.payload);
	if (!parsed.success) {
		return err(apiError(`Invalid trust mark status response payload: ${parsed.error.message}`));
	}
	return { ok: true, value: parsed.data };
}

/**
 * Verify and validate a Historical Keys Response JWT.
 */
export async function verifyHistoricalKeysResponse(
	jwt: string,
	issuerJwks: JWKSet,
	options?: VerifyOptions,
): Promise<Result<HistoricalKeysPayload, FederationError>> {
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
	return { ok: true, value: parsed.data };
}

/**
 * Verify and validate a Signed JWK Set JWT (returned by signed_jwks_uri).
 * Checks typ=jwk-set+jwt, signature, and required payload claims (iss, sub, keys).
 */
export async function verifySignedJwkSet(
	jwt: string,
	signerJwks: JWKSet,
	options?: VerifyOptions,
): Promise<Result<SignedJwkSetPayload, FederationError>> {
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
	return { ok: true, value: parsed.data };
}
