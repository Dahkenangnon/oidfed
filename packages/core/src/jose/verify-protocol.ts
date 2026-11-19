/** Protocol JWT verification against authenticated protocol keys. */

import type { Result } from "../errors.js";
import { JwsService, type JwsServiceOptions } from "../jws-service.js";
import type { JWKSet } from "../schemas/jwk.js";
export interface VerifyProtocolJwtOptions extends JwsServiceOptions {
	/** Undefined requires the protected typ to be absent. */
	readonly expectedTyp: string | undefined;
	readonly keyIdPolicy?: "required" | "single-key";
}
export interface VerifiedProtocolJwt {
	header: Record<string, unknown>;
	payload: Record<string, unknown>;
}
/** Check signature, token type and time claims. The caller establishes key provenance and protocol claims. */
export function verifyProtocolJwt(
	jwt: string,
	jwks: JWKSet,
	options: VerifyProtocolJwtOptions,
): Promise<Result<VerifiedProtocolJwt>> {
	return new JwsService(options).verifyJwt(jwt, jwks, {
		typ: options.expectedTyp === undefined ? "absent" : { expected: options.expectedTyp },
		keyId: options.keyIdPolicy === "single-key" ? "allow-single-key" : "required",
	});
}
