import { randomUuid } from "../crypto-runtime.js";

/** Shared private_key_jwt assertion construction for federation and protocol clients. */

import type { KeyringEntry } from "@oidfed/crypto";
import { runAsyncOperation } from "../async-operation.js";
import { DEFAULT_CLIENT_ASSERTION_TTL_SECONDS } from "../constants.js";
import { JwsService } from "../jws-service.js";
import { type Clock, type FederationOptions, nowSeconds } from "../types.js";

export interface ClientAssertionOptions
	extends Pick<
		FederationOptions,
		| "signal"
		| "httpTimeoutMs"
		| "engine"
		| "maxCompactBytes"
		| "algorithmRegistry"
		| "allowedAlgorithms"
	> {
	readonly expiresInSeconds?: number;
	/** NumericDate clock used for iat and exp. */
	readonly clock?: Clock;
}

/**
 * Create a client assertion JWT for `private_key_jwt` authentication.
 *
 * Shared by Federation endpoint clients and OIDC/OAuth clients. The caller supplies
 * the recipient identifier required by the protocol; it is not inferred from a URL.
 */
export async function createClientAssertion(
	clientId: string,
	audience: string,
	signer: KeyringEntry,
	options: ClientAssertionOptions,
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
		jti: await randomUuid(options.engine),
		iat: now,
		exp: now + expiresIn,
	};

	return runAsyncOperation(
		() => new JwsService(options).signJwt(signer, payload, { typ: "JWT" }),
		options,
	);
}
