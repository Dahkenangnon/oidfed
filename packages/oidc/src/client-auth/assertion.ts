import {
	DEFAULT_CLIENT_ASSERTION_TTL_SECONDS,
	type JwtSigner,
	nowSeconds,
	signEntityStatement,
} from "@oidfed/core";

/**
 * Create a client assertion JWT for `private_key_jwt` authentication.
 *
 * This is an OIDC/OAuth2-specific concept used when the RP authenticates
 * to the OP's token endpoint using a signed JWT assertion.
 */
export async function createClientAssertion(
	clientId: string,
	audience: string,
	signer: JwtSigner,
	options?: { expiresInSeconds?: number },
): Promise<string> {
	const expiresIn = options?.expiresInSeconds ?? DEFAULT_CLIENT_ASSERTION_TTL_SECONDS;
	const now = nowSeconds();

	const payload: Record<string, unknown> = {
		iss: clientId,
		sub: clientId,
		aud: audience,
		jti: crypto.randomUUID(),
		iat: now,
		exp: now + expiresIn,
	};

	// signEntityStatement is a generic JWT signer despite its name
	return signEntityStatement(payload, signer, {
		typ: "JWT",
	});
}
