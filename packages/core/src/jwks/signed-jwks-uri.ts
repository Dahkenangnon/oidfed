/**
 * HTTP fetcher for `signed_jwks_uri` — performs the HTTPS GET, enforces the
 * URL/status/Content-Type requirements, and delegates JWT verification to
 * `verifySignedJwkSet`.
 */
import { FederationErrorCode, MediaType } from "../constants.js";
import { err, type FederationError, federationError, type Result } from "../errors.js";
import { verifySignedJwkSet } from "../federation-api/index.js";
import type { SignedJwkSetPayload } from "../schemas/entity-statement.js";
import type { JWKSet } from "../schemas/jwk.js";
import { performFetch } from "../trust-chain/fetch.js";
import type { Clock, FederationOptions } from "../types.js";

export interface FetchSignedJwkSetOptions extends FederationOptions {
	clockSkewSeconds?: number;
	clock?: Clock;
}

/**
 * Fetch and verify a Signed JWK Set from `signed_jwks_uri`.
 *
 * - URL MUST use https and MUST NOT contain a fragment.
 * - HTTP response Content-Type MUST be `application/jwk-set+jwt`.
 * - The returned JWT is then verified via `verifySignedJwkSet`
 *   (typ, signature against `signerJwks`, REQUIRED payload claims).
 */
export async function fetchSignedJwkSet(
	url: string,
	signerJwks: JWKSet,
	options?: FetchSignedJwkSetOptions,
): Promise<Result<SignedJwkSetPayload, FederationError>> {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return err(federationError(FederationErrorCode.InvalidMetadata, `Invalid URL: ${url}`));
	}
	if (parsed.protocol !== "https:") {
		return err(
			federationError(FederationErrorCode.InvalidMetadata, `URL must use https scheme: ${url}`),
		);
	}
	if (parsed.hash) {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				`URL must not contain a fragment: ${url}`,
			),
		);
	}

	const fetched = await performFetch(url, {
		...options,
		accept: MediaType.JwkSet,
		expectedContentType: MediaType.JwkSet,
	});
	if (!fetched.ok) return fetched;

	const verifyOpts: { clockSkewSeconds?: number; clock?: Clock } = {};
	if (options?.clockSkewSeconds !== undefined)
		verifyOpts.clockSkewSeconds = options.clockSkewSeconds;
	if (options?.clock !== undefined) verifyOpts.clock = options.clock;
	return verifySignedJwkSet(fetched.value, signerJwks, verifyOpts);
}
