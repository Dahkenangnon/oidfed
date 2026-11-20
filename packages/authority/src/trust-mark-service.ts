/** Per-authority Trust Mark service reuse and issuer-policy updates. */

import { type TrustMarkIssuerConfig, TrustMarkIssuerService } from "@oidfed/core";
import type { HandlerContext } from "./endpoints/context.js";

const services = new WeakMap<HandlerContext, TrustMarkIssuerService>();
/** Reuse one managed issuer service for this handler context and its storage dependencies. */
export function trustMarkService(ctx: HandlerContext): TrustMarkIssuerService {
	const existing = services.get(ctx);
	if (existing) return existing;
	const storage = ctx.storage;
	if (!storage.capabilities.includes("trustMark:read"))
		throw new Error("Trust mark storage is not configured");
	const configured: Omit<TrustMarkIssuerConfig, "storage"> = ctx.trustMarkIssuer ?? {};
	const service = new TrustMarkIssuerService({
		...configured,
		...(ctx.trustMarkDefaults ? { trustMarkDefaults: ctx.trustMarkDefaults } : {}),

		...(ctx.trustMarkStatusPolicy ? { trustMarkStatusPolicy: ctx.trustMarkStatusPolicy } : {}),
		...(ctx.trustMarkRequestExtensions
			? { trustMarkRequestExtensions: ctx.trustMarkRequestExtensions }
			: {}),
		issuer: ctx.entityId,
		crypto: ctx.crypto,
		statusEndpointPublished: !!ctx.metadata.federation_entity.federation_trust_mark_status_endpoint,
		storage,
		options: ctx.options,
		...(ctx.trustMarkOwners ? { trustMarkOwners: ctx.trustMarkOwners } : {}),
		...(ctx.trustMarkIssuers ? { trustMarkIssuers: ctx.trustMarkIssuers } : {}),
		...(ctx.trustMarkDelegations ? { delegations: ctx.trustMarkDelegations } : {}),
		defaults: {
			// Nested defaults select a lifetime mode before the authority-wide TTL fallback.
			...(configured.defaults?.noExpiry === undefined &&
			configured.defaults?.ttlSeconds === undefined &&
			ctx.trustMarkTtlSeconds !== undefined
				? { ttlSeconds: ctx.trustMarkTtlSeconds }
				: {}),
			...configured.defaults,
		},
	});
	services.set(ctx, service);
	return service;
}

/** Update local policy on the context's existing managed issuer service. */
export function updateTrustMarkServicePolicy(ctx: HandlerContext): void {
	services.get(ctx)?.updatePolicy(ctx.trustMarkOwners ?? {}, ctx.trustMarkIssuers);
}
