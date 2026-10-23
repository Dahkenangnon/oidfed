/**
 * Client-side helper for the federation Extended Subordinate Listing endpoint.
 * Performs the HTTPS GET, enforces URL/status/Content-Type, parses the JSON
 * response, and surfaces spec-defined error codes from 400 and 404 responses.
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

	if (params.from !== undefined) {
		url.searchParams.set("from", params.from);
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
		url.searchParams.set("claims", joined);
	}
	if (params.entityType !== undefined) {
		const types = Array.isArray(params.entityType) ? params.entityType : [params.entityType];
		for (const t of types) url.searchParams.append("entity_type", t);
	}
	if (params.trustMarked !== undefined) {
		url.searchParams.set("trust_marked", params.trustMarked ? "true" : "false");
	}
	if (params.trustMarkType !== undefined) {
		const types =
			typeof params.trustMarkType === "string" ? [params.trustMarkType] : params.trustMarkType;
		for (const type of types) url.searchParams.append("trust_mark_type", type);
	}
	if (params.intermediate !== undefined) {
		url.searchParams.set("intermediate", params.intermediate ? "true" : "false");
	}

	return ok(url);
}

async function readBody(
	response: Response,
	maxBytes: number,
	signal: AbortSignal,
): Promise<string> {
	if (!response.body) return "";
	const contentLength = response.headers.get("content-length");
	if (contentLength && Number.parseInt(contentLength, 10) > maxBytes) {
		void response.body.cancel().catch(() => {});
		throw new RangeError(`Response exceeds maximum size of ${maxBytes} bytes`);
	}
	const reader = response.body.getReader();
	// Cancel pending reads even when an injected HTTP client ignores the signal.
	const onAbort = () => {
		void reader.cancel().catch(() => {});
	};
	signal.addEventListener("abort", onAbort, { once: true });
	let finished = false;
	try {
		const decoder = new TextDecoder();
		let received = 0;
		let text = "";
		while (true) {
			if (signal.aborted) throw new DOMException("Request aborted", "AbortError");
			const { done, value } = await reader.read();
			if (signal.aborted) throw new DOMException("Request aborted", "AbortError");
			if (done) {
				finished = true;
				return text + decoder.decode();
			}
			received += value.byteLength;
			if (received > maxBytes) {
				throw new RangeError(`Response exceeds maximum size of ${maxBytes} bytes`);
			}
			text += decoder.decode(value, { stream: true });
		}
	} finally {
		signal.removeEventListener("abort", onAbort);
		if (!finished) void reader.cancel().catch(() => {});
		reader.releaseLock();
	}
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
	const onAbort = () => controller.abort();
	options?.signal?.addEventListener("abort", onAbort, { once: true });
	if (options?.signal?.aborted) controller.abort();

	try {
		if (controller.signal.aborted) throw new DOMException("Request aborted", "AbortError");
		const response = await fetchFn(url, {
			signal: controller.signal,
			headers: { Accept: MediaType.Json },
		});

		const contentType = response.headers.get("content-type");

		if (response.status === 400 || response.status === 404) {
			let code: string | undefined;
			let description: string | undefined;
			if (isExactContentType(contentType, MediaType.Json)) {
				const body = await readBody(response, maxBytes, controller.signal);
				try {
					const parsedBody = JSON.parse(body) as { error?: unknown; error_description?: unknown };
					if (typeof parsedBody.error === "string") code = parsedBody.error;
					if (typeof parsedBody.error_description === "string") {
						description = parsedBody.error_description;
					}
				} catch {
					// non-JSON body — leave code undefined
				}
			} else {
				void response.body?.cancel().catch(() => {});
			}
			const knownCodes = new Set<string>(Object.values(FederationErrorCode));
			if (response.status === 404 && code !== FederationErrorCode.PageNotFound) {
				return err({
					code: InternalErrorCode.Network,
					description: `HTTP 404 from ${endpoint}`,
				});
			}
			const mappedCode: FederationErrorCode = knownCodes.has(code ?? "")
				? (code as FederationErrorCode)
				: FederationErrorCode.InvalidRequest;
			return err(
				federationError(
					mappedCode,
					description ?? `HTTP ${response.status} from ${endpoint}${code ? ` (${code})` : ""}`,
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

		const body = await readBody(response, maxBytes, controller.signal);

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
	} catch (cause) {
		if (
			controller.signal.aborted ||
			(cause instanceof DOMException && cause.name === "AbortError")
		) {
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
	} finally {
		clearTimeout(timer);
		options?.signal?.removeEventListener("abort", onAbort);
	}
}
