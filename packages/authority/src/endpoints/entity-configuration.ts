/** Authority Entity Configuration payload construction and HTTP publication. */

import {
	buildEntityConfigurationPayload,
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	JwtTyp,
	MediaType,
	nowSeconds,
	safeLogger,
	signEntityStatement,
	validateRoleMetadata,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { errorResponse, jwtResponse, requireMethod } from "./helpers.js";

const collectionNotices = new WeakSet<HandlerContext>();

/** Returns the authority's Entity Configuration as a signed JWT. */
export function createEntityConfigurationHandler(
	ctx: HandlerContext,
): (request: Request) => Promise<Response> {
	return async (request: Request) => {
		const methodError = requireMethod(request, "GET");
		if (methodError) return methodError;

		try {
			const jwt = await buildEntityConfiguration(ctx);
			return jwtResponse(jwt, MediaType.EntityStatement);
		} catch {
			safeLogger(ctx.options?.logger)?.error("Failed to build entity configuration");
			return errorResponse(500, "server_error", "Failed to build entity configuration");
		}
	};
}

/** Builds and signs the Entity Configuration JWT from the current context. */
export async function buildEntityConfiguration(ctx: HandlerContext): Promise<string> {
	validateRoleMetadata(ctx.roles, ctx.metadata, ctx);
	const keySet = await ctx.keyProvider.getFederationKeySet();
	const now = nowSeconds(ctx.options?.clock);
	const ttlSeconds = ctx.entityConfigurationTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS;

	const payloadOptions = {
		entityId: ctx.entityId,
		jwks: keySet.jwks,
		metadata: ctx.metadata,
		issuedAt: now,
		ttlSeconds,
	};

	// Publish trust_mark_issuers and trust_mark_owners only when this host acts
	// as a Trust Anchor; recipients ignore these claims on Intermediates.
	const isTrustAnchor = ctx.isTrustAnchor ?? !ctx.authorityHints?.length;
	const payload = buildEntityConfigurationPayload({
		...payloadOptions,
		additionalClaims: ctx.additionalClaims,
		crit: ctx.crit,
		...(ctx.authorityHints && ctx.authorityHints.length > 0
			? { authorityHints: ctx.authorityHints }
			: {}),
		...(ctx.trustAnchorHints && ctx.trustAnchorHints.length > 0
			? { trustAnchorHints: ctx.trustAnchorHints }
			: {}),
		...(ctx.trustMarks && ctx.trustMarks.length > 0 ? { trustMarks: ctx.trustMarks } : {}),
		...(isTrustAnchor && ctx.trustMarkIssuers ? { trustMarkIssuers: ctx.trustMarkIssuers } : {}),
		...(isTrustAnchor && ctx.trustMarkOwners ? { trustMarkOwners: ctx.trustMarkOwners } : {}),
	});

	const jwt = await signEntityStatement(payload, keySet.signer, {
		typ: JwtTyp.EntityStatement,
	});
	if (
		ctx.metadata.federation_entity.federation_collection_endpoint &&
		!ctx.metadata.federation_entity.federation_resolve_endpoint &&
		!collectionNotices.has(ctx)
	) {
		collectionNotices.add(ctx);
		safeLogger(ctx.options?.logger)?.info(
			"Federation Entities publishing a federation_collection_endpoint SHOULD also publish a federation_resolve_endpoint",
		);
	}
	return jwt;
}
