/** Authority adapters for Trust Mark retrieval. */

import type { HandlerContext } from "./context.js";
import { errorResponse } from "./helpers.js";
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
