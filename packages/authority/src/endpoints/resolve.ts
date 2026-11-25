/** Authority integration with the shared signed Resolve service. */

import { FederationResolverService } from "@oidfed/core";
import { trustMarkService } from "../trust-mark-service.js";
import type { HandlerContext } from "./context.js";

/** Authority adapter; resolution itself has no subordinate-store dependency. */
export function createAuthorityResolver(
	ctx: HandlerContext,
	fixedQuery?: URLSearchParams,
): FederationResolverService {
	return new FederationResolverService(
		{
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
		},
		fixedQuery,
	);
}
