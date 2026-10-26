import {
	DEFAULT_MAX_REQUEST_BODY_BYTES,
	decodeEntityStatement,
	FederationErrorCode,
	isOk,
	isValidEntityId,
	type JWKSet,
	JWT_BEARER_CLIENT_ASSERTION_TYPE,
	entityId as toEntityId,
	verifyClientAssertion,
} from "@oidfed/core";
import { InvalidAuthorityConfig } from "../errors.js";
import type { HandlerContext } from "./context.js";
import { errorResponse, readBodyWithLimit, requireMethods } from "./helpers.js";

/**
 * Apply Federation §8.8 authentication using the methods advertised by this host.
 * Most anonymous endpoints use GET; Trust Mark Status uses POST even without auth (§8.4.1).
 * Unsupported local methods fail construction rather than leaving a protected route open.
 */
export function createAuthenticatedHandler(
	ctx: HandlerContext,
	innerHandler: (request: Request) => Promise<Response>,
	authMethods: string[] | undefined,
	options?: {
		nativeMethod?: "GET" | "POST" | undefined;
		allowedAlgorithms?: readonly string[] | undefined;
	},
): (request: Request) => Promise<Response> {
	const nativeMethod = options?.nativeMethod ?? "GET";

	const methods = authMethods ?? ["none"];
	if (methods.length === 0)
		throw new InvalidAuthorityConfig("Endpoint auth methods must not be empty");
	const unsupported = methods.find((method) => method !== "none" && method !== "private_key_jwt");
	if (unsupported !== undefined)
		throw new InvalidAuthorityConfig(`Unsupported endpoint auth method: '${unsupported}'`);
	if (!methods.includes("private_key_jwt")) {
		return innerHandler;
	}

	const replayStore = ctx.storage.replay;
	if (!replayStore)
		throw new InvalidAuthorityConfig("private_key_jwt authentication requires storage.replay");

	const allowsNone = methods.includes("none");
	const allowedMethods = allowsNone && nativeMethod === "GET" ? ["GET", "POST"] : ["POST"];

	return async (request: Request) => {
		const methodError = requireMethods(request, allowedMethods);
		if (methodError) return methodError;

		if (request.method.toUpperCase() === "GET" && allowsNone) {
			const query = new URL(request.url).searchParams;
			if (query.has("client_assertion") || query.has("client_assertion_type")) {
				return errorResponse(
					401,
					FederationErrorCode.InvalidClient,
					"Client assertions require POST",
				);
			}
			return innerHandler(request);
		}

		let text = "";
		if (request.body) {
			try {
				const read = await readBodyWithLimit(request, DEFAULT_MAX_REQUEST_BODY_BYTES);
				if (!read.ok)
					return errorResponse(413, FederationErrorCode.InvalidRequest, "Request body too large");
				text = read.text;
			} catch {
				return errorResponse(
					400,
					FederationErrorCode.InvalidRequest,
					"Failed to read request body",
				);
			}
		}
		const params = new URLSearchParams(text);
		// Presence matters: empty or partial credentials must not select anonymous access.
		const supplied = params.has("client_assertion") || params.has("client_assertion_type");
		if (
			params.getAll("client_assertion").length > 1 ||
			params.getAll("client_assertion_type").length > 1
		) {
			return errorResponse(
				401,
				FederationErrorCode.InvalidClient,
				"Duplicate client assertion parameters",
			);
		}
		const clientAssertion = params.get("client_assertion");
		const clientAssertionType = params.get("client_assertion_type");
		params.delete("client_assertion");
		params.delete("client_assertion_type");

		function forward(authenticatedEntity?: string): Promise<Response> {
			const url = new URL(request.url);
			const headers = new Headers(request.headers);
			headers.delete("X-Authenticated-Entity");
			// Extraction changes the body length; do not forward a stale transport length.
			headers.delete("Content-Length");
			if (authenticatedEntity) headers.set("X-Authenticated-Entity", authenticatedEntity);
			if (nativeMethod === "POST") {
				headers.set("Content-Type", "application/x-www-form-urlencoded");
				return innerHandler(
					new Request(url, {
						method: "POST",
						headers,
						body: authenticatedEntity ? params.toString() : text,
						signal: request.signal,
					}),
				);
			}
			url.search = params.toString();
			headers.delete("Content-Type");
			return innerHandler(new Request(url, { method: "GET", headers, signal: request.signal }));
		}

		if (!supplied && allowsNone && nativeMethod === "POST") return forward();

		if (!clientAssertion) {
			return errorResponse(
				401,
				FederationErrorCode.InvalidClient,
				"Missing client_assertion parameter",
			);
		}

		if (clientAssertionType !== JWT_BEARER_CLIENT_ASSERTION_TYPE) {
			return errorResponse(
				401,
				FederationErrorCode.InvalidClient,
				`Invalid client_assertion_type: expected '${JWT_BEARER_CLIENT_ASSERTION_TYPE}'`,
			);
		}

		const decoded = decodeEntityStatement(clientAssertion);
		if (!isOk(decoded)) {
			return errorResponse(
				401,
				FederationErrorCode.InvalidClient,
				"Failed to decode client assertion",
			);
		}
		const iss = decoded.value.payload.iss as string;

		if (!isValidEntityId(iss)) {
			return errorResponse(
				401,
				FederationErrorCode.InvalidClient,
				"Client assertion 'iss' is not a valid Entity Identifier",
			);
		}

		let clientJwks: JWKSet | undefined;
		try {
			const clientEntityId = toEntityId(iss);
			clientJwks = await ctx.clientKeyProvider.getClientFederationJwks(clientEntityId);
		} catch {
			return errorResponse(500, FederationErrorCode.ServerError, "Client key lookup failed");
		}

		if (!clientJwks) {
			return errorResponse(
				401,
				FederationErrorCode.InvalidClient,
				"No federation keys found for client",
			);
		}

		const verifyResult = await verifyClientAssertion(clientAssertion, clientJwks, ctx.entityId, {
			replayStore,
			...(ctx.options?.clock ? { clock: ctx.options.clock } : {}),
			...(ctx.options?.clockSkewSeconds !== undefined
				? { clockSkewSeconds: ctx.options.clockSkewSeconds }
				: {}),
			...(options?.allowedAlgorithms !== undefined
				? { allowedAlgorithms: options.allowedAlgorithms }
				: {}),
		});

		if (!verifyResult.ok) {
			return errorResponse(
				verifyResult.error.code === "server_error" ? 500 : 401,
				verifyResult.error.code === "server_error"
					? FederationErrorCode.ServerError
					: FederationErrorCode.InvalidClient,
				verifyResult.error.description,
			);
		}

		return forward(iss);
	};
}
