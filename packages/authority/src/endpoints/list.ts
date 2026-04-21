import { EntityType, FederationErrorCode } from "@oidfed/core";
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

		if ((trustMarked !== null || trustMarkType !== null) && !ctx.trustMarkStore) {
			return errorResponse(
				400,
				FederationErrorCode.UnsupportedParameter,
				"Trust mark filtering not supported",
			);
		}

		const filter: ListFilter = {};
		if (entityTypes.length > 0) filter.entityTypes = entityTypes;
		if (intermediate !== null) filter.intermediate = intermediate === "true";

		try {
			let records = await ctx.subordinateStore.list(filter);

			if (trustMarked === "true" && ctx.trustMarkStore) {
				const filtered = [];
				for (const record of records) {
					if (trustMarkType) {
						const active = await ctx.trustMarkStore.isActive(trustMarkType, record.entityId);
						if (active) filtered.push(record);
					} else {
						const hasAny = await ctx.trustMarkStore.hasAnyActive(record.entityId);
						if (hasAny) filtered.push(record);
					}
				}
				records = filtered;
			} else if (trustMarked === "false" && ctx.trustMarkStore) {
				const filtered = [];
				for (const record of records) {
					if (trustMarkType) {
						const active = await ctx.trustMarkStore.isActive(trustMarkType, record.entityId);
						if (!active) filtered.push(record);
					} else {
						const hasAny = await ctx.trustMarkStore.hasAnyActive(record.entityId);
						if (!hasAny) filtered.push(record);
					}
				}
				records = filtered;
			} else if (trustMarked === null && trustMarkType && ctx.trustMarkStore) {
				const filtered = [];
				for (const record of records) {
					const active = await ctx.trustMarkStore.isActive(trustMarkType, record.entityId);
					if (active) filtered.push(record);
				}
				records = filtered;
			}

			const entityIds = records.map((r) => r.entityId);
			return jsonResponse(entityIds);
		} catch (error) {
			ctx.options?.logger?.error("Failed to list subordinates", { error });
			return errorResponse(500, "server_error", "Failed to list subordinates");
		}
	};
}
