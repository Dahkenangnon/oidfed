/** Authority integration with the shared signed Resolve service. */

import { FederationResolverService } from "@oidfed/core";
import { trustMarkService } from "../trust-mark-service.js";
import type { HandlerContext } from "./context.js";

/** Authority adapter; resolution itself has no subordinate-store dependency. */
export function createResolveHandler(
	ctx: HandlerContext,
): (
	request: Request,
	local?: boolean,
	options?: import("@oidfed/core").BoundFederationOptions,
) => Promise<Response> {
	const service = new FederationResolverService({
		entityId: ctx.entityId,
		crypto: ctx.crypto,
		...(ctx.trustAnchors ? { trustAnchors: ctx.trustAnchors } : {}),
		options: { ...ctx.options, storage: ctx.storage },
		...(ctx.requireAuthForFreshResolution !== undefined
			? { requireAuthForFreshResolution: ctx.requireAuthForFreshResolution }
			: {}),
		...(ctx.storage.capabilities.includes("trustMark:read")
			? {
					assessLocalTrustMarkStatus: (jwt: string) =>
						trustMarkService(ctx).assessTrustMarkStatus(jwt),
				}
			: {}),
	});
	return (request, local = false, options) =>
		local ? service.resolve(request, options) : service.handleAuthenticatedRequest(request);
}
