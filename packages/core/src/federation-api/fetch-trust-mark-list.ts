/** Trust Marked Entities Listing requests with transport and response-shape checks. */

import { FederationErrorCode, InternalErrorCode, MediaType } from "../constants.js";
import { fetchFederationEndpoint } from "../endpoint-client.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import { safeLogger } from "../logging.js";
import { parseMetadataUrl } from "../metadata-url.js";
import { type EntityId, entityId, type FederationOptions, isValidEntityId } from "../types.js";

export interface FetchTrustMarkListParams {
	trustMarkType: string;
	sub?: EntityId;
}

/** Fetch a list of Entity Identifiers with active Trust Marks of the given type. */
export async function fetchTrustMarkList(
	endpoint: string,
	params: FetchTrustMarkListParams,
	options: FederationOptions,
): Promise<Result<EntityId[], FederationError>> {
	safeLogger(options?.logger)?.debug("Starting fetch trust mark list");

	if (!params.trustMarkType) {
		return err(
			federationError(FederationErrorCode.InvalidRequest, "Missing trust_mark_type parameter"),
		);
	}

	const parsed = parseMetadataUrl(endpoint, FederationErrorCode.InvalidRequest);
	if (!parsed.ok) return parsed;

	const selectors = new URLSearchParams({ trust_mark_type: params.trustMarkType });
	if (params.sub) selectors.set("sub", params.sub);

	const fetched = await fetchFederationEndpoint(parsed.value.toString(), selectors, {
		...options,
		expectedStatus: 200,
		accept: MediaType.Json,
		expectedContentType: MediaType.Json,
	});
	if (!fetched.ok) return fetched;

	let raw: unknown;
	try {
		raw = JSON.parse(fetched.value);
	} catch (cause) {
		return err({
			code: InternalErrorCode.Network,
			description: `Trust mark list response is not valid JSON: ${endpoint}`,
			cause,
		});
	}

	if (!Array.isArray(raw) || !raw.every((v): v is string => typeof v === "string")) {
		return err({
			code: InternalErrorCode.Network,
			description: `Trust mark list response is not a JSON array of strings: ${endpoint}`,
		});
	}

	for (const value of raw) {
		if (!isValidEntityId(value)) {
			return err({
				code: InternalErrorCode.Network,
				description: `Trust mark list response contains invalid Entity Identifier: ${value}`,
			});
		}
	}

	return ok((raw as string[]).map((s) => entityId(s)));
}
