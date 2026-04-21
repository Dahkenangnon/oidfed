/** JWT signing for Entity Statements and other federation tokens. */
import * as jose from "jose";
import { JwtTyp, SUPPORTED_ALGORITHMS, type SupportedAlgorithm } from "../constants.js";
import type { JWK } from "../schemas/jwk.js";

/** Sign an entity statement payload as a JWT using the provided private key. */
export async function signEntityStatement(
	payload: Record<string, unknown>,
	privateKey: JWK,
	options?: { kid?: string; alg?: string; typ?: string; extraHeaders?: Record<string, unknown> },
): Promise<string> {
	if (privateKey.use && privateKey.use !== "sig") {
		throw new Error(`Key use must be "sig" for signing, got "${privateKey.use}"`);
	}

	const alg = options?.alg ?? privateKey.alg ?? "ES256";
	if (!SUPPORTED_ALGORITHMS.includes(alg as SupportedAlgorithm)) {
		throw new Error(
			`Unsupported signing algorithm: "${alg}". Supported: ${SUPPORTED_ALGORITHMS.join(", ")}`,
		);
	}
	const kid = options?.kid ?? privateKey.kid;
	const typ = options?.typ ?? JwtTyp.EntityStatement;

	const cryptoKey = await jose.importJWK(privateKey as unknown as jose.JWK, alg);

	const header: Record<string, unknown> = { alg, typ, ...options?.extraHeaders };
	if (kid) {
		header.kid = kid;
	}

	return new jose.SignJWT(payload as jose.JWTPayload)
		.setProtectedHeader(header as jose.JWTHeaderParameters)
		.sign(cryptoKey as Parameters<jose.SignJWT["sign"]>[0]);
}
