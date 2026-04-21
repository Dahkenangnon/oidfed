/** HTTP response helpers, security headers, and request parameter extraction for federation endpoints. */
import { FederationErrorCode } from "./constants.js";
import type { FederationError } from "./errors.js";

/** Standard security headers applied to all federation responses. */
export const SECURITY_HEADERS: Record<string, string> = {
	"Cache-Control": "no-store",
	"X-Content-Type-Options": "nosniff",
	"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	"X-Frame-Options": "DENY",
	"Referrer-Policy": "no-referrer",
};

/** Creates a 200 response with the given JWT body and media type. */
export function jwtResponse(jwt: string, mediaType: string): Response {
	return new Response(jwt, {
		status: 200,
		headers: {
			...SECURITY_HEADERS,
			"Content-Type": mediaType,
		},
	});
}

/** Creates a JSON response with the given body and status. */
export function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			...SECURITY_HEADERS,
			"Content-Type": "application/json",
		},
	});
}

/** Creates an OAuth-style JSON error response. */
export function errorResponse(status: number, code: string, description: string): Response {
	const body: Record<string, string> = { error: code, error_description: description };
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			...SECURITY_HEADERS,
			"Content-Type": "application/json",
		},
	});
}

const PUBLIC_ERROR_CODES = new Set<string>(Object.values(FederationErrorCode));

/** Sanitizes internal errors into safe public-facing error details. */
export function toPublicError(error: FederationError): {
	status: number;
	code: string;
	description: string;
} {
	const code = PUBLIC_ERROR_CODES.has(error.code) ? error.code : FederationErrorCode.ServerError;

	const status = errorCodeToStatus(code);

	const description = PUBLIC_ERROR_CODES.has(error.code)
		? error.description
		: "An internal error occurred";

	return { status, code, description };
}

function errorCodeToStatus(code: string): number {
	switch (code) {
		case FederationErrorCode.InvalidRequest:
		case FederationErrorCode.InvalidTrustChain:
		case FederationErrorCode.InvalidMetadata:
		case FederationErrorCode.UnsupportedParameter:
			return 400;
		case FederationErrorCode.InvalidClient:
			return 401;
		case FederationErrorCode.NotFound:
		case FederationErrorCode.InvalidIssuer:
		case FederationErrorCode.InvalidSubject:
		case FederationErrorCode.InvalidTrustAnchor:
			return 404;
		case FederationErrorCode.TemporarilyUnavailable:
			return 503;
		default:
			return 500;
	}
}

/** Extracts query parameters from a request URL. */
export function parseQueryParams(request: Request): URLSearchParams {
	const url = new URL(request.url);
	return url.searchParams;
}

/** Returns a 405 response if the request method does not match, or null if it does. */
export function requireMethod(request: Request, method: string): Response | null {
	if (request.method.toUpperCase() !== method.toUpperCase()) {
		return new Response(JSON.stringify({ error: "method_not_allowed" }), {
			status: 405,
			headers: {
				...SECURITY_HEADERS,
				Allow: method,
				"Content-Type": "application/json",
			},
		});
	}
	return null;
}

/** Returns a 405 response if the request method is not in the allowed list, or null if it is. */
export function requireMethods(request: Request, methods: string[]): Response | null {
	const upper = request.method.toUpperCase();
	if (methods.some((m) => m.toUpperCase() === upper)) {
		return null;
	}
	return new Response(JSON.stringify({ error: "method_not_allowed" }), {
		status: 405,
		headers: {
			...SECURITY_HEADERS,
			Allow: methods.join(", "),
			"Content-Type": "application/json",
		},
	});
}

export interface ExtractedRequestParams {
	params: URLSearchParams;
	clientAssertion?: string | undefined;
	clientAssertionType?: string | undefined;
}

/** Extracts form/query params and client_assertion fields from a request. */
export async function extractRequestParams(request: Request): Promise<ExtractedRequestParams> {
	if (request.method.toUpperCase() === "POST") {
		const text = await request.text();
		const allParams = new URLSearchParams(text);
		const clientAssertion = allParams.get("client_assertion") ?? undefined;
		const clientAssertionType = allParams.get("client_assertion_type") ?? undefined;
		allParams.delete("client_assertion");
		allParams.delete("client_assertion_type");
		return { params: allParams, clientAssertion, clientAssertionType };
	}
	return { params: parseQueryParams(request) };
}

/**
 * Read a ReadableStream up to maxBytes, returning the decoded text or failure.
 * Shared streaming core used by both request and response body readers.
 */
export async function readStreamWithLimit(
	body: ReadableStream<Uint8Array>,
	maxBytes: number,
): Promise<{ ok: true; text: string } | { ok: false }> {
	const chunks: Uint8Array[] = [];
	let received = 0;
	for await (const chunk of body as AsyncIterable<Uint8Array>) {
		received += chunk.length;
		if (received > maxBytes) {
			return { ok: false };
		}
		chunks.push(chunk);
	}
	const buf = new Uint8Array(received);
	let off = 0;
	for (const c of chunks) {
		buf.set(c, off);
		off += c.length;
	}
	return { ok: true, text: new TextDecoder().decode(buf) };
}

/**
 * Stream-read a request body up to maxBytes, aborting if exceeded.
 * Checks Content-Length header first to reject oversized bodies early,
 * then counts actual bytes to catch a mismatched Content-Length.
 */
export async function readBodyWithLimit(
	request: Request,
	maxBytes: number,
): Promise<{ ok: true; text: string } | { ok: false }> {
	if (!request.body) return { ok: false };
	const contentLength = request.headers.get("content-length");
	if (contentLength && Number.parseInt(contentLength, 10) > maxBytes) {
		return { ok: false };
	}
	return readStreamWithLimit(request.body, maxBytes);
}
