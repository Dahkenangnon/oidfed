/**
 * Fetch a Signed JWK Set from `signed_jwks_uri`. Check the URL, status, and Content-Type,
 * then verify the JWT with `verifySignedJwkSet`.
 */

import { FederationErrorCode, MediaType } from "../constants.js";
import { err, type FederationError, federationError, type Result } from "../errors.js";
import {
	type VerifySignedJwkSetOptions,
	validateExpectedIssuer,
	verifySignedJwkSet,
} from "../federation-api/index.js";
import { safeLogger } from "./../logging.js";
import { parseMetadataUrl } from "../metadata-url.js";
import { EntityIdSchema } from "../schemas/entity-id.js";
import type { SignedJwkSetPayload } from "../schemas/entity-statement.js";
import type { JWKSet } from "../schemas/jwk.js";
import { performFetch } from "../trust-chain/fetch.js";
import type { Clock, FederationOptions } from "../types.js";

export interface FetchSignedJwkSetOptions extends FederationOptions, VerifySignedJwkSetOptions {
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
	options: FetchSignedJwkSetOptions,
): Promise<Result<SignedJwkSetPayload, FederationError>> {
	safeLogger(options?.logger)?.debug("Starting fetch signed jwk set");

	const expectation = validateExpectedIssuer(options);
	if (!expectation.ok) return expectation;
	if (!EntityIdSchema.safeParse(options?.expectedOwner).success)
		return err(
			federationError(FederationErrorCode.InvalidMetadata, "A valid expectedOwner is required"),
		);
	const parsed = parseMetadataUrl(url, FederationErrorCode.InvalidMetadata);
	if (!parsed.ok) return parsed;

	const fetched = await performFetch(url, {
		...options,
		expectedStatus: 200,
		accept: MediaType.JwkSet,
		expectedContentType: MediaType.JwkSet,
	});
	if (!fetched.ok) return fetched;

	const verified = await verifySignedJwkSet(fetched.value, signerJwks, options);
	if (!verified.ok) safeLogger(options.logger)?.warn("Signed JWK Set validation failed");
	return verified;
}
