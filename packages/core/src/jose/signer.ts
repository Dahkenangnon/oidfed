import * as jose from "jose";
import { SUPPORTED_ALGORITHMS, type SupportedAlgorithm } from "../constants.js";
import type { JWK } from "../schemas/jwk.js";

/**
 * Runtime-agnostic JWT signing boundary.
 *
 * Implementations own key custody and JOSE operations. The core package never
 * imports private keys or calls Web Crypto directly.
 */
export interface JwtSigner {
	readonly kid: string;
	readonly alg: SupportedAlgorithm;
	signJwt(payload: Uint8Array, protectedHeader: Readonly<Record<string, unknown>>): Promise<string>;
}

export interface JwkSignerOptions {
	readonly alg?: SupportedAlgorithm;
}

/** Software-key signer backed entirely by the runtime-agnostic `jose` API. */
export class JwkSigner implements JwtSigner {
	readonly kid: string;
	readonly alg: SupportedAlgorithm;
	private readonly key: JWK;
	private importedKey: ReturnType<typeof jose.importJWK> | undefined;

	constructor(key: JWK, options?: JwkSignerOptions) {
		const { alg, kid } = validateSignerKey(key, options?.alg ?? key.alg);
		this.key = key;
		this.kid = kid;
		this.alg = alg;
	}

	async signJwt(
		payload: Uint8Array,
		protectedHeader: Readonly<Record<string, unknown>>,
	): Promise<string> {
		this.importedKey ??= jose.importJWK(this.key as unknown as jose.JWK, this.alg);
		return new jose.CompactSign(payload)
			.setProtectedHeader(protectedHeader as jose.CompactJWSHeaderParameters)
			.sign((await this.importedKey) as Parameters<jose.CompactSign["sign"]>[0]);
	}
}

export function validateSigner(signer: JwtSigner): void {
	if (!signer.kid) {
		throw new Error("JwtSigner kid MUST NOT be empty");
	}
	if (!SUPPORTED_ALGORITHMS.includes(signer.alg)) {
		throw new Error(
			`Unsupported signing algorithm: "${signer.alg}". Supported: ${SUPPORTED_ALGORITHMS.join(", ")}`,
		);
	}
}

function validateSignerKey(
	key: JWK,
	alg: string | undefined,
): { alg: SupportedAlgorithm; kid: string } {
	if (key.use && key.use !== "sig") {
		throw new Error(`Key use must be "sig" for signing, got "${key.use}"`);
	}
	if ((key as Record<string, unknown>).kty === "oct") {
		throw new Error("Symmetric keys (kty 'oct') cannot be used for federation signing");
	}
	if (Array.isArray(key.key_ops) && !key.key_ops.includes("sign")) {
		throw new Error("JWK key_ops must include 'sign' for signing");
	}
	if (!alg || !SUPPORTED_ALGORITHMS.includes(alg as SupportedAlgorithm)) {
		throw new Error(
			`Unsupported signing algorithm: "${String(alg)}". Supported: ${SUPPORTED_ALGORITHMS.join(", ")}`,
		);
	}
	if (!key.kid) {
		throw new Error("JwtSigner kid MUST NOT be empty");
	}
	if (typeof key.d !== "string" || key.d.length === 0) {
		throw new Error("JwkSigner requires private key material");
	}
	return { alg: alg as SupportedAlgorithm, kid: key.kid };
}
