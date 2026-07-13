import {
	decodeEntityStatement,
	FederationErrorCode,
	isOk,
	isValidEntityId,
	type JWKSet,
	JWT_BEARER_CLIENT_ASSERTION_TYPE,
	entityId as toEntityId,
	verifyClientAssertion,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { errorResponse, extractRequestParams, requireMethods } from "./helpers.js";

/** Wraps a handler with private_key_jwt client authentication when configured. */
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

	if (!authMethods || authMethods.length === 0 || isNoneOnly(authMethods)) {
		return innerHandler;
	}

	const requiresPrivateKeyJwt = authMethods.includes("private_key_jwt");
	if (!requiresPrivateKeyJwt) {
		return innerHandler;
	}

	const allowsNone = authMethods.includes("none");
	const allowedMethods = allowsNone ? ["GET", "POST"] : ["POST"];

	return async (request: Request) => {
		const methodError = requireMethods(request, allowedMethods);
		if (methodError) return methodError;

		if (request.method.toUpperCase() === "GET" && allowsNone) {
			return innerHandler(request);
		}

		const extracted = await extractRequestParams(request);
		const { params, clientAssertion, clientAssertionType } = extracted;

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

		const clockSkewSeconds = ctx.options?.clockSkewSeconds;
		const clock = ctx.options?.clock;
		const verifyResult = await verifyClientAssertion(
			clientAssertion,
			clientJwks,
			ctx.entityId,
			clockSkewSeconds !== undefined ||
				clock !== undefined ||
				options?.allowedAlgorithms !== undefined
				? {
						...(clockSkewSeconds !== undefined ? { clockSkewSeconds } : {}),
						...(clock !== undefined ? { clock } : {}),
						...(options?.allowedAlgorithms !== undefined
							? { allowedAlgorithms: options.allowedAlgorithms }
							: {}),
					}
				: undefined,
		);

		if (!verifyResult.ok) {
			return errorResponse(401, FederationErrorCode.InvalidClient, verifyResult.error.description);
		}

		if (nativeMethod === "POST") {
			const url = new URL(request.url);
			const newRequest = new Request(url.toString(), {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					"X-Authenticated-Entity": iss,
				},
				body: params.toString(),
			});
			return innerHandler(newRequest);
		}

		const url = new URL(request.url);
		url.search = params.toString();
		const newRequest = new Request(url.toString(), {
			method: "GET",
			headers: { "X-Authenticated-Entity": iss },
		});
		return innerHandler(newRequest);
	};
}

function isNoneOnly(methods: string[]): boolean {
	return methods.every((m) => m === "none");
}
