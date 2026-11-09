import type { JwtSigner, SignEntityStatementOptions } from "../../../packages/core/src/index.js";

/** Sign exact test headers, including malformed envelopes and optional protocol key identifiers. */
export function signProtocolFixture(
	payload: Record<string, unknown>,
	signer: JwtSigner,
	options?: SignEntityStatementOptions,
): Promise<string> {
	return signer.signJwt(new TextEncoder().encode(JSON.stringify(payload)), {
		alg: signer.alg,
		kid: signer.kid,
		typ: options?.typ ?? "entity-statement+jwt",
		...options?.extraHeaders,
	});
}
