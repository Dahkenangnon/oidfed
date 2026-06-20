/** JWT signing for Entity Statements and other federation tokens. */
import { JwtTyp, SUPPORTED_ALGORITHMS, type SupportedAlgorithm } from "../constants.js";
import type { JwtSigner } from "./signer.js";
import { validateSigner } from "./signer.js";

export interface SignEntityStatementOptions {
	readonly alg?: SupportedAlgorithm;
	readonly typ?: string;
	readonly extraHeaders?: Record<string, unknown>;
}

/** Sign an entity statement payload as a compact JWT using the provided signing primitive. */
export async function signEntityStatement(
	payload: Record<string, unknown>,
	signer: JwtSigner,
	options?: SignEntityStatementOptions,
): Promise<string> {
	validateSigner(signer);

	const alg = options?.alg ?? signer.alg;
	if (!SUPPORTED_ALGORITHMS.includes(alg)) {
		throw new Error(
			`Unsupported signing algorithm: "${alg}". Supported: ${SUPPORTED_ALGORITHMS.join(", ")}`,
		);
	}
	if (alg !== signer.alg) {
		throw new Error(`Signing algorithm mismatch: signer uses "${signer.alg}", requested "${alg}"`);
	}
	const typ = options?.typ ?? JwtTyp.EntityStatement;

	const header: Record<string, unknown> = { alg, typ, kid: signer.kid, ...options?.extraHeaders };
	return signer.signJwt(new TextEncoder().encode(JSON.stringify(payload)), header);
}
