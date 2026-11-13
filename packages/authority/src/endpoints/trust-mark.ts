import { isValidEntityId, MediaType, safeLogger } from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { errorResponse, jwtResponse, requireMethod } from "./helpers.js";
import { trustMarkService } from "./trust-mark-service.js";

export function createTrustMarkHandler(
	ctx: HandlerContext,
): (request: Request) => Promise<Response> {
	return async (request) => {
		if (!ctx.storage.trustMarks)
			return errorResponse(501, "server_error", "Trust mark store not configured");
		return trustMarkService(ctx).handleRequest("retrieval", request);
	};
}
/** Administrative adapter; never mounted as the public retrieval endpoint. */
export function createTrustMarkIssuanceHandler(
	ctx: HandlerContext,
): (request: Request) => Promise<Response> {
	return async (request) => {
		const method = requireMethod(request, "GET");
		if (method) return method;
		if (!ctx.storage.trustMarks)
			return errorResponse(501, "server_error", "Trust mark store not configured");
		const params = new URL(request.url).searchParams;
		const type = params.get("trust_mark_type"),
			subject = params.get("sub");
		if (!type || !subject || !isValidEntityId(subject))
			return errorResponse(400, "invalid_request", "Missing or invalid Trust Mark selectors");
		try {
			const jwt = await trustMarkService(ctx).issueTrustMark(subject, type);
			return jwtResponse(jwt, MediaType.TrustMark);
		} catch (cause) {
			safeLogger(ctx.options?.logger)?.error("Failed to issue trust mark");
			const unauthorized = cause instanceof Error && cause.message.includes("not authorized");
			return errorResponse(
				unauthorized ? 403 : 500,
				unauthorized ? "unauthorized_issuer" : "server_error",
				"Failed to issue trust mark",
			);
		}
	};
}
