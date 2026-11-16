/** Historical Keys retrieval with transport checks and signed-response verification. */

import { FederationErrorCode, MediaType } from "../constants.js";
import { fetchFederationEndpoint } from "../endpoint-client.js";
import type { FederationError, Result } from "../errors.js";
import { safeLogger } from "./../logging.js";
import { parseMetadataUrl } from "../metadata-url.js";
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
	const parsed = parseMetadataUrl(endpoint, FederationErrorCode.InvalidRequest);
	if (!parsed.ok) return parsed;

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
