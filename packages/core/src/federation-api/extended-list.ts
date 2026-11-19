/**
 * Client-side helper for the federation Extended Subordinate Listing endpoint.
 * Performs anonymous GET or authenticated POST, enforces URL/status/Content-Type, parses the JSON
 * response, and surfaces spec-defined error codes from 400 and 404 responses.
 */

import { FederationErrorCode, InternalErrorCode, MediaType } from "../constants.js";
import { fetchFederationEndpoint } from "../endpoint-client.js";
import { EXTENDED_LIST_UNORDERED_PARAMETERS } from "../endpoint-parameters.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import { safeLogger } from "./../logging.js";
import {
	type ExtendedListRequestParams,
	type ExtendedListResponse,
	ExtendedListResponseSchema,
} from "../schemas/extended-list.js";
import { httpFailureStatus } from "../trust-chain/fetch-failure.js";
import type { FederationOptions } from "../types.js";

/** Build standard Extended Listing selectors for HTTP clients and local authority calls. */
export function buildExtendedListRequestParameters(
	endpoint: string,
	params?: ExtendedListRequestParams,
): Result<URLSearchParams, FederationError> {
	let url: URL;
	try {
		url = new URL(endpoint);
	} catch {
		return err(federationError(FederationErrorCode.InvalidRequest, `Invalid URL: ${endpoint}`));
	}
	if (url.protocol !== "https:") {
		return err(
			federationError(FederationErrorCode.InvalidRequest, `URL must use https scheme: ${endpoint}`),
		);
	}
	if (url.href.includes("#")) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`URL must not contain a fragment: ${endpoint}`,
			),
		);
	}

	const selectors = new URLSearchParams();
	if (!params) return ok(selectors);

	if (params.from !== undefined) {
		selectors.set("from", params.from);
	}
	if (params.limit !== undefined) {
		if (!Number.isInteger(params.limit) || params.limit <= 0) {
			return err(
				federationError(FederationErrorCode.InvalidRequest, "limit must be a positive integer"),
			);
		}
		selectors.set("limit", String(params.limit));
	}
	if (params.updatedAfter !== undefined) {
		selectors.set("updated_after", String(params.updatedAfter));
	}
	if (params.updatedBefore !== undefined) {
		selectors.set("updated_before", String(params.updatedBefore));
	}
	if (params.auditTimestamps !== undefined) {
		selectors.set("audit_timestamps", params.auditTimestamps ? "true" : "false");
	}
	if (params.claims !== undefined) {
		const joined = Array.from(params.claims)
			.filter((c) => c.length > 0)
			.join(",");
		selectors.set("claims", joined);
	}
	if (params.entityType !== undefined) {
		const types = typeof params.entityType === "string" ? [params.entityType] : params.entityType;
		for (const t of types) selectors.append("entity_type", t);
	}
	if (params.trustMarked !== undefined) {
		selectors.set("trust_marked", params.trustMarked ? "true" : "false");
	}
	if (params.trustMarkType !== undefined) {
		const types =
			typeof params.trustMarkType === "string" ? [params.trustMarkType] : params.trustMarkType;
		for (const type of types) selectors.append("trust_mark_type", type);
	}
	if (params.intermediate !== undefined) {
		selectors.set("intermediate", params.intermediate ? "true" : "false");
	}

	return ok(selectors);
}

/**
 * Fetch an Extended Subordinate Listing and return the parsed response.
 * Configure the endpoint and authentication together from trusted configuration or validated metadata.
 * This standalone client uses authentication.audience without an independent responder identity;
 * getEndpointAuthentication receives no responder. Authenticated requests use POST and never retry anonymously.
 */
export async function fetchExtendedSubordinatesList(
	endpoint: string,
	params: ExtendedListRequestParams | undefined,
	options: FederationOptions,
): Promise<Result<ExtendedListResponse, FederationError>> {
	safeLogger(options?.logger)?.debug("Starting fetch extended subordinates list");

	const selectors = buildExtendedListRequestParameters(endpoint, params);
	if (!selectors.ok) return selectors;
	const result = await fetchFederationEndpoint(
		endpoint,
		selectors.value,
		{
			...options,
			method: "GET",
			accept: MediaType.Json,
			expectedStatus: 200,
			contentTypePolicy: "exact",
			federationErrors: [400, 401, 404],
		},
		undefined,
		EXTENDED_LIST_UNORDERED_PARAMETERS,
	);
	if (!result.ok) {
		const status = httpFailureStatus(result.error);
		if (status === 404 && result.error.code !== FederationErrorCode.PageNotFound)
			return err({ code: InternalErrorCode.Network, description: `HTTP 404 from ${endpoint}` });
		if (
			status === 400 &&
			!Object.values(FederationErrorCode).some((code) => code === result.error.code)
		)
			return err({
				code: FederationErrorCode.InvalidRequest,
				description: result.error.description,
			});
		if (result.error.cause instanceof RangeError)
			return err({ ...result.error, description: result.error.cause.message });
		return result;
	}
	let raw: unknown;
	try {
		raw = JSON.parse(result.value);
	} catch (cause) {
		return err({
			code: InternalErrorCode.Network,
			description: `Extended list response is not valid JSON: ${endpoint}`,
			cause,
		});
	}
	const parsed = ExtendedListResponseSchema.safeParse(raw);
	if (!parsed.success)
		return err({
			code: InternalErrorCode.Network,
			description: `Extended list response failed schema validation: ${parsed.error.message}`,
		});
	return ok(parsed.data);
}
