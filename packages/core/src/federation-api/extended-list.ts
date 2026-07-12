/**
 * Client-side helper for the federation Extended Subordinate Listing endpoint.
 * Performs the HTTPS GET, enforces URL/status/Content-Type, parses the JSON
 * response, and surfaces spec-defined error codes from 400 responses.
 */
import {
	DEFAULT_HTTP_TIMEOUT_MS,
	DEFAULT_MAX_RESPONSE_BYTES,
	FederationErrorCode,
	InternalErrorCode,
	MediaType,
} from "../constants.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import { isExactContentType } from "../http.js";
import {
	type ExtendedListRequestParams,
	type ExtendedListResponse,
	ExtendedListResponseSchema,
} from "../schemas/extended-list.js";
import { validateFetchUrl } from "../trust-chain/fetch.js";
import type { FederationOptions } from "../types.js";

function buildUrl(
	endpoint: string,
	params?: ExtendedListRequestParams,
): Result<URL, FederationError> {
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
	if (url.hash) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`URL must not contain a fragment: ${endpoint}`,
			),
		);
	}

	if (!params) return ok(url);

	if (params.fromEntityId !== undefined) {
		url.searchParams.set("from_entity_id", params.fromEntityId);
	}
	if (params.limit !== undefined) {
		if (!Number.isInteger(params.limit) || params.limit <= 0) {
			return err(
				federationError(FederationErrorCode.InvalidRequest, "limit must be a positive integer"),
			);
		}
		url.searchParams.set("limit", String(params.limit));
	}
	if (params.updatedAfter !== undefined) {
		url.searchParams.set("updated_after", String(params.updatedAfter));
	}
	if (params.updatedBefore !== undefined) {
		url.searchParams.set("updated_before", String(params.updatedBefore));
	}
	if (params.auditTimestamps !== undefined) {
		url.searchParams.set("audit_timestamps", params.auditTimestamps ? "true" : "false");
	}
	if (params.claims !== undefined) {
		const joined = Array.from(params.claims)
			.filter((c) => c.length > 0)
			.join(",");
		if (joined.length > 0) url.searchParams.set("claims", joined);
	}
	if (params.entityType !== undefined) {
		const types = Array.isArray(params.entityType) ? params.entityType : [params.entityType];
		for (const t of types) url.searchParams.append("entity_type", t);
	}
	if (params.trustMarked !== undefined) {
		url.searchParams.set("trust_marked", params.trustMarked ? "true" : "false");
	}
	if (params.trustMarkType !== undefined) {
		url.searchParams.set("trust_mark_type", params.trustMarkType);
	}
	if (params.intermediate !== undefined) {
		url.searchParams.set("intermediate", params.intermediate ? "true" : "false");
	}

	return ok(url);
}

function readBody(response: Response, maxBytes: number): Promise<string> {
	const contentLength = response.headers.get("content-length");
	if (contentLength) {
		const size = Number.parseInt(contentLength, 10);
		if (Number.isFinite(size) && size > maxBytes) {
			return Promise.resolve("");
		}
	}
	return response.text();
}

/** Fetch the Extended Subordinate Listing endpoint and return the parsed response. */
export async function fetchExtendedSubordinatesList(
	endpoint: string,
	params?: ExtendedListRequestParams,
	options?: FederationOptions,
): Promise<Result<ExtendedListResponse, FederationError>> {
	const urlResult = buildUrl(endpoint, params);
	if (!urlResult.ok) return urlResult;
	const url = urlResult.value.toString();

	const urlValidation = validateFetchUrl(url, options);
	if (!urlValidation.ok) return urlValidation;

	const fetchFn = options?.httpClient ?? fetch;
	const timeoutMs = options?.httpTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
	const maxBytes = options?.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;

	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	if (options?.signal) {
		if (options.signal.aborted) {
			clearTimeout(timer);
			controller.abort();
		} else {
			options.signal.addEventListener(
				"abort",
				() => {
					clearTimeout(timer);
					controller.abort();
				},
				{ once: true },
			);
		}
	}

	let response: Response;
	try {
		response = await fetchFn(url, {
			signal: controller.signal,
			headers: { Accept: MediaType.Json },
		});
	} catch (cause) {
		clearTimeout(timer);
		if (cause instanceof DOMException && cause.name === "AbortError") {
			return err({
				code: InternalErrorCode.Timeout,
				description: `Request aborted or timed out: ${endpoint}`,
				cause,
			});
		}
		return err({
			code: InternalErrorCode.Network,
			description: cause instanceof Error ? cause.message : `Network error fetching ${endpoint}`,
			cause,
		});
	}
	clearTimeout(timer);

	const contentType = response.headers.get("content-type");

	if (response.status === 400) {
		let body = "";
		try {
			body = await readBody(response, maxBytes);
		} catch {
			// fall through with empty body
		}
		let code: string | undefined;
		let description: string | undefined;
		if (isExactContentType(contentType, MediaType.Json)) {
			try {
				const parsedBody = JSON.parse(body) as { error?: unknown; error_description?: unknown };
				if (typeof parsedBody.error === "string") code = parsedBody.error;
				if (typeof parsedBody.error_description === "string") {
					description = parsedBody.error_description;
				}
			} catch {
				// non-JSON body — leave code undefined
			}
		}
		const knownCodes = new Set<string>(Object.values(FederationErrorCode));
		const mappedCode: FederationErrorCode = knownCodes.has(code ?? "")
			? (code as FederationErrorCode)
			: FederationErrorCode.InvalidRequest;
		return err(
			federationError(
				mappedCode,
				description ?? `HTTP 400 from ${endpoint}${code ? ` (${code})` : ""}`,
			),
		);
	}

	if (!response.ok) {
		return err({
			code: InternalErrorCode.Network,
			description: `HTTP ${response.status} from ${endpoint}`,
		});
	}

	if (!isExactContentType(contentType, MediaType.Json)) {
		const actual = contentType?.trim() || "<missing>";
		return err({
			code: InternalErrorCode.Network,
			description: `Unexpected Content-Type '${actual}' from ${endpoint}, expected '${MediaType.Json}'`,
		});
	}

	let body: string;
	try {
		body = await readBody(response, maxBytes);
	} catch (cause) {
		return err({
			code: InternalErrorCode.Network,
			description: cause instanceof Error ? cause.message : `Failed to read response body`,
			cause,
		});
	}

	let raw: unknown;
	try {
		raw = JSON.parse(body);
	} catch (cause) {
		return err({
			code: InternalErrorCode.Network,
			description: `Extended list response is not valid JSON: ${endpoint}`,
			cause,
		});
	}

	const parsed = ExtendedListResponseSchema.safeParse(raw);
	if (!parsed.success) {
		return err({
			code: InternalErrorCode.Network,
			description: `Extended list response failed schema validation: ${parsed.error.message}`,
		});
	}

	return ok(parsed.data);
}
