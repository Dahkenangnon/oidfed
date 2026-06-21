import { type EntityId, FederationErrorCode, isValidEntityId, nowSeconds } from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { errorResponse, jsonResponse, parseQueryParams, requireMethod } from "./helpers.js";

/** Handles trust mark list requests, returning entity IDs with active marks of a given type. */
export function createTrustMarkListHandler(
	ctx: HandlerContext,
): (request: Request) => Promise<Response> {
	return async (request: Request) => {
		const methodError = requireMethod(request, "GET");
		if (methodError) return methodError;

		if (!ctx.storage.trustMarks) {
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
			const entityIds: EntityId[] = [];
			const seenCursors = new Set<EntityId>();
			let cursor: EntityId | undefined;
			const validAt = nowSeconds(ctx.options?.clock);
			do {
				const result = await ctx.storage.trustMarks.listValid(trustMarkType, validAt, {
					limit: 500,
					...(sub ? { subject: sub as EntityId } : {}),
					...(cursor ? { cursor } : {}),
				});
				entityIds.push(...result.items.map((item) => item.subject));
				cursor = result.nextCursor;
				if (cursor && seenCursors.has(cursor)) {
					throw new Error("Trust mark storage returned a repeated cursor");
				}
				if (cursor) seenCursors.add(cursor);
			} while (cursor);

			return jsonResponse(entityIds);
		} catch (error) {
			ctx.options?.logger?.error("Failed to list trust marks", { error });
			return errorResponse(500, "server_error", "Failed to list trust marks");
		}
	};
}
