/**
 * Client-side helper for the federation Trust Marked Entities Listing
 * endpoint. Performs the HTTPS GET, enforces URL/status/Content-Type, and
 * parses the JSON array of Entity Identifiers.
 */
import { FederationErrorCode, InternalErrorCode, MediaType } from "../constants.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import { performFetch } from "../trust-chain/fetch.js";
import { type EntityId, entityId, type FederationOptions, isValidEntityId } from "../types.js";

export interface FetchTrustMarkListParams {
	trustMarkType: string;
	sub?: EntityId;
}

/** Fetch a list of Entity Identifiers with active Trust Marks of the given type. */
export async function fetchTrustMarkList(
	endpoint: string,
	params: FetchTrustMarkListParams,
	options?: FederationOptions,
): Promise<Result<EntityId[], FederationError>> {
	if (!params.trustMarkType) {
		return err(
			federationError(FederationErrorCode.InvalidRequest, "Missing trust_mark_type parameter"),
		);
	}

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
	if (parsed.hash) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`URL must not contain a fragment: ${endpoint}`,
			),
		);
	}

	parsed.searchParams.set("trust_mark_type", params.trustMarkType);
	if (params.sub) parsed.searchParams.set("sub", params.sub);

	const fetched = await performFetch(parsed.toString(), {
		...options,
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
