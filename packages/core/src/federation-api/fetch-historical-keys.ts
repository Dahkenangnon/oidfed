/**
 * Client-side helper for the federation Historical Keys endpoint. Performs
 * the HTTPS GET, enforces URL/status/Content-Type, and delegates the JWT
 * verification (typ + signature + REQUIRED payload claims) to
 * `verifyHistoricalKeysResponse`.
 */
import { FederationErrorCode, MediaType } from "../constants.js";
import { fetchFederationEndpoint } from "../endpoint-client.js";
import { err, type FederationError, federationError, type Result } from "../errors.js";
import { safeLogger } from "./../logging.js";
import type { HistoricalKeysPayload } from "../schemas/entity-statement.js";
import type { JWKSet } from "../schemas/jwk.js";
import type { Clock, FederationOptions } from "../types.js";
import {
	type VerifyOptions,
	validateExpectedIssuer,
	verifyHistoricalKeysResponse,
} from "./index.js";

export interface FetchHistoricalKeysOptions extends FederationOptions, VerifyOptions {
	clockSkewSeconds?: number;
	clock?: Clock;
}

/** Fetch and verify a Historical Keys JWT from a federation Historical Keys endpoint. */
export async function fetchHistoricalKeys(
	endpoint: string,
	signerJwks: JWKSet,
	options: FetchHistoricalKeysOptions,
): Promise<Result<HistoricalKeysPayload, FederationError>> {
	safeLogger(options?.logger)?.debug("Starting fetch historical keys");

	const expectation = validateExpectedIssuer(options);
	if (!expectation.ok) return expectation;
	let parsed: URL;
	try {
		parsed = new URL(endpoint);
	} catch {
		return err(federationError(FederationErrorCode.InvalidRequest, `Invalid URL: ${endpoint}`));
	}
	if (parsed.protocol !== "https:") {
		return err(
			federationError(FederationErrorCode.InvalidRequest, `URL must use https scheme: ${endpoint}`),
		);
	}
	if (parsed.href.includes("#")) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`URL must not contain a fragment: ${endpoint}`,
			),
		);
	}

	const fetched = await fetchFederationEndpoint(
		endpoint,
		new URLSearchParams(),
		{
			...options,
			expectedStatus: 200,
			accept: MediaType.JwkSet,
			expectedContentType: MediaType.JwkSet,
		},
		options.expectedIssuer,
	);
	if (!fetched.ok) return fetched;

	return verifyHistoricalKeysResponse(fetched.value, signerJwks, options);
}
