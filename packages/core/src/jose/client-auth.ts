import * as jose from "jose";
import { DEFAULT_CLOCK_SKEW_SECONDS } from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import type { JWKSet } from "../schemas/jwk.js";
import type { Clock } from "../types.js";
import { isValidAlgorithm, selectVerificationKey } from "./keys.js";

export interface VerifiedClientAssertion {
	readonly clientId: string;
	readonly issuedAt: number;
	readonly expiresAt: number;
	readonly jti?: string;
}

/** Verify a `private_key_jwt` client assertion against the client's JWKS and expected audience. */
export async function verifyClientAssertion(
	assertion: string,
	jwks: JWKSet,
	expectedAudience: string,
	options?: { clockSkewSeconds?: number; clock?: Clock },
): Promise<Result<VerifiedClientAssertion, FederationError>> {
	let header: jose.ProtectedHeaderParameters;
	try {
		header = jose.decodeProtectedHeader(assertion);
	} catch (cause) {
		return err({
			code: "ERR_SIGNATURE_INVALID",
			description: cause instanceof Error ? cause.message : "Failed to decode JWT header",
			cause,
		});
	}

	if (header.typ !== undefined && header.typ !== "JWT") {
		return err({
			code: "ERR_SIGNATURE_INVALID",
			description: `Invalid typ header: expected 'JWT' or absent, got '${String(header.typ)}'`,
		});
	}

	if (!isValidAlgorithm(header.alg)) {
		return err({
			code: "ERR_UNSUPPORTED_ALG",
			description: `Unsupported algorithm: '${String(header.alg)}'`,
		});
	}

	const key = selectVerificationKey(header as { kid?: string; alg?: string }, jwks);
	if (!key) {
		return err({
			code: "ERR_SIGNATURE_INVALID",
			description: "No matching key found in JWKS for verification",
		});
	}

	let payload: jose.JWTPayload;
	try {
		const cryptoKey = await jose.importJWK(key as unknown as jose.JWK, header.alg as string);
		const clockSkew = options?.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;

		const result = await jose.jwtVerify(
			assertion,
			cryptoKey as unknown as Parameters<typeof jose.jwtVerify>[1],
			{
				clockTolerance: clockSkew,
			},
		);
		payload = result.payload;
	} catch (cause) {
		return err({
			code: "ERR_SIGNATURE_INVALID",
			description: cause instanceof Error ? cause.message : "Signature verification failed",
			cause,
		});
	}

	if (!payload.iss || payload.iss !== payload.sub) {
		return err({
			code: "invalid_client",
			description: `Client assertion 'iss' must equal 'sub': iss='${String(payload.iss)}', sub='${String(payload.sub)}'`,
		});
	}

	const aud = payload.aud;
	if (typeof aud === "string") {
		if (aud !== expectedAudience) {
			return err({
				code: "invalid_client",
				description: `Invalid audience: expected '${expectedAudience}', got '${aud}'`,
			});
		}
	} else if (Array.isArray(aud)) {
		// Spec requires audience to contain only the expected Entity Identifier
		if (aud.length !== 1 || aud[0] !== expectedAudience) {
			return err({
				code: "invalid_client",
				description: `Invalid audience: must contain only '${expectedAudience}', got [${aud.map((a) => `'${a}'`).join(", ")}]`,
			});
		}
	} else {
		return err({
			code: "invalid_client",
			description: "Missing or invalid 'aud' claim",
		});
	}

	return ok({
		clientId: payload.iss,
		issuedAt: payload.iat ?? 0,
		expiresAt: payload.exp ?? 0,
		...(payload.jti ? { jti: payload.jti } : {}),
	});
}
