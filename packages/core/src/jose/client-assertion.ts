import { runAsyncOperation } from "../async-operation.js";
import { DEFAULT_CLIENT_ASSERTION_TTL_SECONDS } from "../constants.js";
import { type Clock, type FederationOptions, nowSeconds } from "../types.js";
import { signEntityStatement } from "./sign.js";
import type { JwtSigner } from "./signer.js";

export interface ClientAssertionOptions
	extends Pick<FederationOptions, "signal" | "httpTimeoutMs"> {
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

	if (
		typeof clientId !== "string" ||
		!clientId ||
		typeof audience !== "string" ||
		!audience ||
		!Number.isFinite(now) ||
		!Number.isFinite(expiresIn) ||
		expiresIn <= 0 ||
		!Number.isFinite(now + expiresIn) ||
		now + expiresIn <= now
	)
		throw new TypeError(
			"Client assertions require valid identifiers and a finite positive lifetime",
		);

	const payload: Record<string, unknown> = {
		iss: clientId,
		sub: clientId,
		aud: audience,
		jti: crypto.randomUUID(),
		iat: now,
		exp: now + expiresIn,
	};

	// signEntityStatement is a generic JWT signer despite its name
	return runAsyncOperation(
		() => signEntityStatement(payload, signer, { typ: "JWT" }),
		options ?? {},
	);
}
