import { EntityType, FederationErrorCode, nowSeconds } from "@oidfed/core";
import type { ListFilter } from "../storage/types.js";
import type { HandlerContext } from "./context.js";
import { errorResponse, jsonResponse, parseQueryParams, requireMethod } from "./helpers.js";

function parseBooleanQuery(value: string | null): boolean | null | undefined {
	if (value === null) return null;
	if (value === "true") return true;
	if (value === "false") return false;
	return undefined;
}

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
		const trustMarkedRaw = params.get("trust_marked");
		const trustMarked = parseBooleanQuery(trustMarkedRaw);
		if (trustMarkedRaw !== null && trustMarked === undefined) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"trust_marked must be 'true' or 'false'",
			);
		}
		const trustMarkType = params.get("trust_mark_type");
		const intermediateRaw = params.get("intermediate");
		const intermediate = parseBooleanQuery(intermediateRaw);
		if (intermediateRaw !== null && intermediate === undefined) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"intermediate must be 'true' or 'false'",
			);
		}

		if ((trustMarkedRaw !== null || trustMarkType !== null) && !ctx.storage.trustMarks) {
			return errorResponse(
				400,
				FederationErrorCode.UnsupportedParameter,
				"Trust mark filtering not supported",
			);
		}

		const filter: ListFilter = {};
		if (entityTypes.length > 0) filter.entityTypes = entityTypes;
		if (typeof intermediate === "boolean") filter.intermediate = intermediate;
		if (typeof trustMarked === "boolean") filter.trustMarked = trustMarked;
		if (trustMarkType !== null) filter.trustMarkType = trustMarkType;
		if (trustMarkedRaw !== null || trustMarkType !== null) {
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
