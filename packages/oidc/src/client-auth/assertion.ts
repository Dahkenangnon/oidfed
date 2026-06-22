import {
	type Clock,
	DEFAULT_CLIENT_ASSERTION_TTL_SECONDS,
	type JwtSigner,
	nowSeconds,
	signEntityStatement,
} from "@oidfed/core";

export interface ClientAssertionOptions {
	readonly expiresInSeconds?: number;
	/** NumericDate clock used for iat and exp. */
	readonly clock?: Clock;
}

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
	options?: ClientAssertionOptions,
): Promise<string> {
	const expiresIn = options?.expiresInSeconds ?? DEFAULT_CLIENT_ASSERTION_TTL_SECONDS;
	const now = nowSeconds(options?.clock);

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
