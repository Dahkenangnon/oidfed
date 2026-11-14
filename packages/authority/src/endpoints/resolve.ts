import { type FederationOptions, FederationResolverService } from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { trustMarkService } from "./trust-mark-service.js";

/** Authority adapter; resolution itself has no subordinate-store dependency. */
export function createResolveHandler(
	ctx: HandlerContext,
): (request: Request, local?: boolean, options?: FederationOptions) => Promise<Response> {
	const service = new FederationResolverService({
		entityId: ctx.entityId,
		keyProvider: ctx.keyProvider,
		...(ctx.trustAnchors ? { trustAnchors: ctx.trustAnchors } : {}),
		...(ctx.storage.cache ? { cache: ctx.storage.cache } : {}),
		...(ctx.options ? { options: ctx.options } : {}),
		...(ctx.requireAuthForFreshResolution !== undefined
			? { requireAuthForFreshResolution: ctx.requireAuthForFreshResolution }
			: {}),
		...(ctx.storage.trustMarks
			? {
					assessLocalTrustMarkStatus: (jwt: string) =>
						trustMarkService(ctx).assessTrustMarkStatus(jwt),
				}
			: {}),
	});
	return (request, local = false, options) =>
		local ? service.resolve(request, options) : service.handleAuthenticatedRequest(request);
}
