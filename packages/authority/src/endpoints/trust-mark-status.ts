/** Authority adapter for signed Trust Mark Status responses. */

import { errorResponse } from "@oidfed/core";
import { trustMarkService } from "../trust-mark-service.js";
import type { HandlerContext } from "./context.js";

export function createTrustMarkStatusHandler(
	ctx: HandlerContext,
): (request: Request) => Promise<Response> {
	return async (request) => {
		if (!ctx.storage.capabilities.includes("trustMark:read"))
			return errorResponse(501, "server_error", "Trust mark store not configured");
		return trustMarkService(ctx).handleRequest("status", request);
	};
}
