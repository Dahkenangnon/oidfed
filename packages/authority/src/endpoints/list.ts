import { listStoredSubordinates } from "@oidfed/core";
/** Subordinate Listing requests with standard filters and bounded storage traversal. */

import type { ListFilter } from "@oidfed/core";
import {
	errorResponse,
	FederationErrorCode,
	jsonResponse,
	nowSeconds,
	parseQueryParams,
	requireMethod,
	safeLogger,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { parseBooleanQuery, validateEntityTypes } from "./list-parameters.js";

/** Handles subordinate listing requests with optional entity type and trust mark filters. */
export function createListHandler(ctx: HandlerContext): (request: Request) => Promise<Response> {
	return async (request: Request) => {
		const methodError = requireMethod(request, "GET");
		if (methodError) return methodError;

		const params = parseQueryParams(request);

		// Federation 1.0 §5.1: "Additional Entity Type Identifiers MAY be defined
		// to support use cases for other protocols", and §20 establishes no
		// registry. Accept extension identifiers and filter by them (§8.2.1).
		// An identifier that no subordinate publishes produces an empty result.
		const entityTypes = params.getAll("entity_type");
		const entityTypeError = validateEntityTypes(entityTypes);
		if (entityTypeError) return entityTypeError;
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

		if (
			(trustMarkedRaw !== null || trustMarkType !== null) &&
			!ctx.storage.capabilities.includes("trustMark:read")
		) {
			return errorResponse(
				400,
				FederationErrorCode.UnsupportedParameter,
				"Trust mark filtering not supported",
			);
		}

		const filter: ListFilter = {};
		if (entityTypes.length > 0) filter.entityTypes = entityTypes;
		if (typeof intermediate === "boolean") filter.intermediate = intermediate;
		if (trustMarked === true) filter.trustMarked = true;
		if (trustMarkType !== null) filter.trustMarkType = trustMarkType;
		if (trustMarked === true || trustMarkType !== null) {
			filter.validAt = nowSeconds(ctx.options?.clock);
		}

		try {
			const page = await listStoredSubordinates(
				ctx.storage.subordinate,
				filter,
				undefined,
				ctx.options,
			);
			const entityIds = page.items.map((record) => record.entityId);

			return jsonResponse(entityIds);
		} catch {
			safeLogger(ctx.options?.logger)?.error("Failed to list subordinates");
			return errorResponse(500, "server_error", "Failed to list subordinates");
		}
	};
}
