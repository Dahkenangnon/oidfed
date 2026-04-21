/** JWT signature verification with key matching by kid and algorithm. */
import * as jose from "jose";
import { DEFAULT_CLOCK_SKEW_SECONDS, JwtTyp } from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import type { JWKSet } from "../schemas/jwk.js";
import type { Clock, ParsedEntityStatement, UnverifiedEntityStatement } from "../types.js";
import { isValidAlgorithm, selectVerificationKey } from "./keys.js";

/** Verify a JWT entity statement signature against a JWKS. */
export async function verifyEntityStatement(
	jwt: string,
	jwks: JWKSet,
	options?: { clockSkewSeconds?: number; clock?: Clock; expectedTyp?: string },
): Promise<Result<ParsedEntityStatement, FederationError>> {
	const headerResult = decodeProtectedHeader(jwt);
	if (!headerResult.ok) return headerResult;
	const header = headerResult.value;

	const expectedTyp = options?.expectedTyp ?? JwtTyp.EntityStatement;
	if (header.typ !== expectedTyp) {
		return err({
			code: "ERR_SIGNATURE_INVALID",
			description: `Invalid typ header: expected '${expectedTyp}', got '${String(header.typ)}'`,
		});
	}

	if (!isValidAlgorithm(header.alg)) {
		return err({
			code: "ERR_UNSUPPORTED_ALG",
			description: `Unsupported algorithm: '${String(header.alg)}'`,
		});
	}

	if (!header.kid || typeof header.kid !== "string") {
		return err({
			code: "ERR_SIGNATURE_INVALID",
			description: "Missing or invalid kid header",
		});
	}

	const key = selectVerificationKey(header as { kid?: string; alg?: string }, jwks);
	if (!key) {
		return err({
			code: "ERR_SIGNATURE_INVALID",
			description: "No matching key found in JWKS for verification",
		});
	}

	try {
		const cryptoKey = await jose.importJWK(key as unknown as jose.JWK, header.alg as string);
		const clockSkew = options?.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;

		const { payload } = await jose.jwtVerify(
			jwt,
			cryptoKey as unknown as Parameters<typeof jose.jwtVerify>[1],
			{
				clockTolerance: clockSkew,
			},
		);

		return ok({
			header: header as Record<string, unknown>,
			payload: payload as unknown as ParsedEntityStatement["payload"],
		});
	} catch (cause) {
		return err({
			code: "ERR_SIGNATURE_INVALID",
			description: cause instanceof Error ? cause.message : "Signature verification failed",
			cause,
		});
	}
}

/** Decode a JWT entity statement without signature verification. */
export function decodeEntityStatement(
	jwt: string,
): Result<UnverifiedEntityStatement, FederationError> {
	try {
		const header = jose.decodeProtectedHeader(jwt);
		const payload = jose.decodeJwt(jwt);

		return ok({
			header: header as Record<string, unknown>,
			payload: payload as unknown as UnverifiedEntityStatement["payload"],
		} as UnverifiedEntityStatement);
	} catch (cause) {
		return err({
			code: "ERR_SIGNATURE_INVALID",
			description: cause instanceof Error ? cause.message : "Failed to decode JWT",
			cause,
		});
	}
}

function decodeProtectedHeader(
	jwt: string,
): Result<jose.ProtectedHeaderParameters, FederationError> {
	try {
		return ok(jose.decodeProtectedHeader(jwt));
	} catch (cause) {
		return err({
			code: "ERR_SIGNATURE_INVALID",
			description: cause instanceof Error ? cause.message : "Failed to decode JWT header",
			cause,
		});
	}
}

/** Assert that a JWT header has the expected `typ` value, throwing on mismatch. */
export function assertTypHeader(
	header: Record<string, unknown>,
	expectedTyp: string,
): asserts header is Record<string, unknown> & { typ: string } {
	if (header.typ !== expectedTyp) {
		throw new TypeError(`Expected typ '${expectedTyp}', got '${String(header.typ)}'`);
	}
}
