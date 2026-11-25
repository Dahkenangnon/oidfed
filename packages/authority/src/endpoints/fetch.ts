/** Subordinate Statement signing and Fetch endpoint responses. */

import {
	type EntityId,
	errorResponse,
	FederationErrorCode,
	fetchStoredSubordinate,
	isValidEntityId,
	jwtResponse,
	MediaType,
	nowSeconds,
	parseQueryParams,
	requireMethod,
	safeLogger,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import {
	buildSubordinateStatement,
	createRetainedSubordinateReader,
	RetainedSubordinateUnavailable,
	retainedSubordinateUnavailableResponse,
} from "./subordinate-statement.js";

/** Handles fetch endpoint requests to return a subordinate statement. */
export function createFetchHandler(ctx: HandlerContext): (request: Request) => Promise<Response> {
	return async (request: Request) => {
		const methodError = requireMethod(request, "GET");
		if (methodError) return methodError;

		const params = parseQueryParams(request);
		const sub = params.get("sub");

		if (!sub || !isValidEntityId(sub)) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"Missing or invalid 'sub' parameter",
			);
		}

		try {
			if (sub === ctx.entityId) {
				return errorResponse(
					400,
					FederationErrorCode.InvalidRequest,
					"Use the Entity Configuration endpoint to fetch the issuer's own configuration",
				);
			}

			const record = await fetchStoredSubordinate(
				ctx.storage.subordinate,
				sub as EntityId,
				ctx.options,
			);
			if (!record) {
				return errorResponse(404, FederationErrorCode.NotFound, "Entity not found");
			}

			const readRetained = createRetainedSubordinateReader(ctx, request.signal);
			if (readRetained) {
				const statement = await readRetained(record);
				if (statement.expiresAt <= nowSeconds(ctx.options.clock))
					throw new RetainedSubordinateUnavailable();
				return jwtResponse(statement.jwt, MediaType.EntityStatement);
			}
			return jwtResponse(await buildSubordinateStatement(ctx, record), MediaType.EntityStatement);
		} catch (error) {
			if (error instanceof RetainedSubordinateUnavailable) {
				safeLogger(ctx.options.logger)?.warn("Approved subordinate statement is unavailable");
				return retainedSubordinateUnavailableResponse();
			}
			safeLogger(ctx.options?.logger)?.error("Failed to build subordinate statement");
			return errorResponse(500, "server_error", "Failed to build statement");
		}
	};
}
