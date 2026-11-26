/** Bounded HTTP transport for federation requests. */

import { waitForOperation } from "../async-operation.js";
import {
	DEFAULT_HTTP_TIMEOUT_MS,
	DEFAULT_MAX_RESPONSE_BYTES,
	FederationErrorCode,
	InternalErrorCode,
	MediaType,
} from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import { isExactContentType, parseContentTypeHeader } from "../http.js";
import { safeLogger } from "../logging.js";
import type { FederationOptions } from "../types.js";
import { fetchFailure } from "./fetch-failure.js";
import { validateFetchUrl } from "./fetch-url.js";
import { readResponseBody } from "./response-body.js";

export interface PerformFetchOptions extends FederationOptions {
	headers?: RequestInit["headers"];
	/** Matching override. JSON accepts parameters; Federation registered media types default to none. */
	contentTypePolicy?: "exact" | "media-type";
	/** Accept header to send. Defaults to application/entity-statement+jwt. */
	accept?: string;
	/**
	 * Content-Type the response is required to carry. Defaults to the value of `accept`.
	 * Pass `null` to skip Content-Type validation entirely (e.g. when the verifier downstream
	 * inspects the response body header itself).
	 */
	expectedContentType?: string | null;
	method?: "GET" | "POST";
	/** Explicit request redirect policy; omitted callers keep Fetch's default. */
	redirect?: RequestInit["redirect"];
	/** Form-encoded body for authenticated federation endpoint requests. */
	body?: URLSearchParams;
	/** Raw signed Entity Statement, used by the registration transport. */
	entityStatementBody?: string;
	expectedStatus?: number;
	/** Decode Federation JSON error responses when enabled. */
	federationErrors?: boolean | readonly number[];
}

/** Send an Entity Statement JWT once and return the bounded response for protocol verification. */
export function postFederationEntityStatement(
	url: string,
	jwt: string,
	options: FederationOptions & { readonly expectedContentType: string },
): Promise<Result<string, FederationError>> {
	return performFetch(url, {
		...options,
		method: "POST",
		redirect: "manual",
		entityStatementBody: jwt,
		accept: options.expectedContentType,
		contentTypePolicy: "exact",
		expectedStatus: 200,
		federationErrors: false,
	});
}

/**
 * Run a bounded HTTP request with configured URL, status, and response checks.
 * Transport failures are returned as federation errors; this does not authenticate a JWT body.
 */
export async function performFetch(
	url: string,
	options: PerformFetchOptions,
): Promise<Result<string, FederationError>> {
	if (options?.offline) {
		safeLogger(options.logger)?.warn(
			"Supply the missing federation evidence or protocol keys for offline trust evaluation",
		);
		return err({
			code: InternalErrorCode.Network,
			description: "Offline operation cannot access the network",
		});
	}
	const urlValidation = validateFetchUrl(url, options);
	if (!urlValidation.ok) return urlValidation;
	const statement = options.entityStatementBody;
	if (statement !== undefined && urlValidation.value.href.includes("#"))
		return err({
			code: FederationErrorCode.InvalidRequest,
			description: "Entity Statement POST URL must not contain a fragment",
		});

	const fetchFn = options?.httpClient ?? fetch;
	const timeoutMs = options?.httpTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
	const maxResponseBytes = options?.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
	if (statement !== undefined && (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 0))
		return err({
			code: FederationErrorCode.InvalidRequest,
			description: "Response byte limit must be a nonnegative safe integer",
		});
	const accept = options?.accept ?? MediaType.EntityStatement;
	const expectedContentType =
		options?.expectedContentType !== undefined ? options.expectedContentType : accept;
	const matchesContentType = (actual: string | null, expected: string) =>
		(options?.contentTypePolicy ??
			(expected.toLowerCase() === MediaType.Json ? "media-type" : "exact")) === "media-type"
			? parseContentTypeHeader(actual)?.mediaType.toLowerCase() === expected.toLowerCase()
			: isExactContentType(actual, expected);

	const controller = new AbortController();
	let timedOut = false;
	let receivedResponse = false;
	const timer = setTimeout(() => {
		timedOut = true;
		controller.abort();
	}, timeoutMs);

	const onAbort = () => controller.abort();
	options?.signal?.addEventListener("abort", onAbort, { once: true });
	if (options?.signal?.aborted) controller.abort();

	try {
		if (controller.signal.aborted) throw new DOMException("Request aborted", "AbortError");
		const init: RequestInit = {
			signal: controller.signal,
			...(options.redirect !== undefined ? { redirect: options.redirect } : {}),
			method: options.method ?? "GET",
			...(options.body ? { body: options.body.toString() } : {}),
			headers: {
				...Object.fromEntries(new Headers(options.headers).entries()),
				Accept: accept,
				...(options.body ? { "Content-Type": "application/x-www-form-urlencoded" } : {}),
			},
		};
		let response: Response;
		if (statement === undefined) {
			response = await fetchFn(url, init);
		} else {
			const headers = new Headers(init.headers);
			headers.set("Content-Type", MediaType.EntityStatement);
			const request = new Request(urlValidation.value, { ...init, headers, body: statement });
			// Release callers at the deadline even when a custom transport ignores the signal.
			const pending = fetchFn(request);
			try {
				response = await waitForOperation(pending, [controller.signal]);
			} catch (cause) {
				if (controller.signal.aborted)
					void pending.then((reply) => reply.body?.cancel()).catch(() => {});
				throw cause;
			}
		}
		receivedResponse = true;

		if (statement !== undefined && response.redirected) {
			void response.body?.cancel().catch(() => {});
			return err(
				fetchFailure(
					{
						code: InternalErrorCode.Network,
						description: "Entity Statement POST must not redirect",
					},
					{ kind: "response" },
				),
			);
		}

		if (
			!response.ok ||
			(options?.expectedStatus !== undefined && response.status !== options.expectedStatus)
		) {
			if (
				(options?.federationErrors === true ||
					(Array.isArray(options?.federationErrors) &&
						options.federationErrors.includes(response.status))) &&
				!response.ok &&
				matchesContentType(response.headers.get("content-type"), MediaType.Json)
			) {
				const body = await readResponseBody(response, maxResponseBytes, controller.signal);
				try {
					const parsed = JSON.parse(body) as { error?: unknown; error_description?: unknown };
					if (
						typeof parsed?.error === "string" &&
						/^[\x20-\x21\x23-\x5B\x5D-\x7E]+$/.test(parsed.error)
					) {
						return err(
							fetchFailure(
								{
									code: Object.values(FederationErrorCode).includes(
										parsed.error as FederationErrorCode,
									)
										? (parsed.error as FederationErrorCode)
										: InternalErrorCode.RemoteResponse,
									...(!Object.values(FederationErrorCode).includes(
										parsed.error as FederationErrorCode,
									)
										? { remoteError: { code: parsed.error, status: response.status } }
										: {}),
									description:
										typeof parsed.error_description === "string"
											? parsed.error_description
											: `HTTP ${response.status} from ${url}`,
								},
								{ kind: "http", status: response.status },
							),
						);
					}
				} catch {
					/* Fall back to the HTTP error for malformed JSON. */
				}
			} else {
				void response.body?.cancel().catch(() => {});
			}
			return err(
				fetchFailure(
					{
						code: InternalErrorCode.Network,
						description: `HTTP ${response.status} from ${url}`,
					},
					{ kind: "http", status: response.status },
				),
			);
		}

		const contentType = response.headers.get("content-type");
		if (expectedContentType !== null && !matchesContentType(contentType, expectedContentType)) {
			void response.body?.cancel().catch(() => {});
			const actual = contentType?.trim() || "<missing>";
			return err(
				fetchFailure(
					{
						code:
							statement === undefined
								? InternalErrorCode.Network
								: FederationErrorCode.InvalidRequest,
						description: `Unexpected Content-Type '${actual}' from ${url}, expected '${expectedContentType}'`,
					},
					{ kind: "response" },
				),
			);
		}

		if (!response.body)
			return err(
				fetchFailure(
					{
						code: InternalErrorCode.Network,
						description: `Empty response body from ${url}`,
					},
					{ kind: "response" },
				),
			);
		const body = await readResponseBody(response, maxResponseBytes, controller.signal);
		return ok(body);
	} catch (cause) {
		if (
			controller.signal.aborted ||
			(cause instanceof DOMException && cause.name === "AbortError")
		) {
			return err(
				fetchFailure(
					{
						code: InternalErrorCode.Timeout,
						description: `Request aborted or timed out: ${url}`,
						cause,
					},
					{ kind: timedOut && !options?.signal?.aborted ? "timeout" : "cancelled" },
				),
			);
		}
		return err(
			fetchFailure(
				{
					code: InternalErrorCode.Network,
					description:
						cause instanceof RangeError
							? `Response too large from ${url}`
							: cause instanceof Error
								? cause.message
								: `Network error fetching ${url}`,
					cause,
				},
				{ kind: receivedResponse ? "response" : "transport" },
			),
		);
	} finally {
		clearTimeout(timer);
		options?.signal?.removeEventListener("abort", onAbort);
	}
}
