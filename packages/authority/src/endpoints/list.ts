import { EntityType, FederationErrorCode, nowSeconds } from "@oidfed/core";
import type { ListFilter } from "../storage/types.js";
import type { HandlerContext } from "./context.js";
import { errorResponse, jsonResponse, parseQueryParams, requireMethod } from "./helpers.js";

/** Handles subordinate listing requests with optional entity type and trust mark filters. */
export function createListHandler(ctx: HandlerContext): (request: Request) => Promise<Response> {
	return async (request: Request) => {
		const methodError = requireMethod(request, "GET");
		if (methodError) return methodError;

		const params = parseQueryParams(request);

		const validEntityTypes = new Set<string>(Object.values(EntityType));
		const rawEntityTypes = params.getAll("entity_type");
		for (const et of rawEntityTypes) {
			if (!validEntityTypes.has(et)) {
				return errorResponse(400, FederationErrorCode.InvalidRequest, "Unknown entity_type value");
			}
		}
		const entityTypes = rawEntityTypes as EntityType[];
		const trustMarked = params.get("trust_marked");
		const trustMarkType = params.get("trust_mark_type");
		const intermediate = params.get("intermediate");

		if ((trustMarked !== null || trustMarkType !== null) && !ctx.storage.trustMarks) {
			return errorResponse(
				400,
				FederationErrorCode.UnsupportedParameter,
				"Trust mark filtering not supported",
			);
		}

		const filter: ListFilter = {};
		if (entityTypes.length > 0) filter.entityTypes = entityTypes;
		if (intermediate !== null) filter.intermediate = intermediate === "true";
		if (trustMarked !== null) filter.trustMarked = trustMarked === "true";
		if (trustMarkType !== null) filter.trustMarkType = trustMarkType;
		if (trustMarked !== null || trustMarkType !== null) {
			filter.validAt = nowSeconds(ctx.options?.clock);
		}

		try {
			const page = await ctx.storage.subordinates.list(filter);
			const entityIds = page.items.map((record) => record.entityId);
			return jsonResponse(entityIds);
		} catch (error) {
			ctx.options?.logger?.error("Failed to list subordinates", { error });
			return errorResponse(500, "server_error", "Failed to list subordinates");
		}
	};
}
