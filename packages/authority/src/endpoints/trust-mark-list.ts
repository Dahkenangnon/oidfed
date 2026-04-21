import { type EntityId, FederationErrorCode, isValidEntityId } from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { errorResponse, jsonResponse, parseQueryParams, requireMethod } from "./helpers.js";

/** Handles trust mark list requests, returning entity IDs with active marks of a given type. */
export function createTrustMarkListHandler(
	ctx: HandlerContext,
): (request: Request) => Promise<Response> {
	return async (request: Request) => {
		const methodError = requireMethod(request, "GET");
		if (methodError) return methodError;

		if (!ctx.trustMarkStore) {
			return errorResponse(501, "server_error", "Trust mark store not configured");
		}

		const params = parseQueryParams(request);
		const trustMarkType = params.get("trust_mark_type");

		if (!trustMarkType) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"Missing 'trust_mark_type' parameter",
			);
		}

		const sub = params.get("sub");

		if (sub && !isValidEntityId(sub)) {
			return errorResponse(400, FederationErrorCode.InvalidRequest, "Invalid 'sub' parameter");
		}

		try {
			const listOptions: { sub?: EntityId } = {};
			if (sub) {
				listOptions.sub = sub as EntityId;
			}
			const result = await ctx.trustMarkStore.list(trustMarkType, listOptions);

			const entityIds = result.items.filter((item) => item.active).map((item) => item.subject);

			return jsonResponse(entityIds);
		} catch (error) {
			ctx.options?.logger?.error("Failed to list trust marks", { error });
			return errorResponse(500, "server_error", "Failed to list trust marks");
		}
	};
}
