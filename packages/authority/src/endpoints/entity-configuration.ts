import {
	buildEntityConfigurationPayload,
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	JwtTyp,
	MediaType,
	nowSeconds,
	signEntityStatement,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { errorResponse, jwtResponse, requireMethod } from "./helpers.js";

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
		} catch (error) {
			ctx.options?.logger?.error("Failed to build entity configuration", { error });
			return errorResponse(500, "server_error", "Failed to build entity configuration");
		}
	};
}

/** Builds and signs the Entity Configuration JWT from the current context. */
export async function buildEntityConfiguration(ctx: HandlerContext): Promise<string> {
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

	// trust_mark_issuers and trust_mark_owners only have effect on a Trust
	// Anchor's Entity Configuration; readers ignore them on Intermediates. The
	// server constructor refuses to accept these fields on a non-TA config, so
	// the inline check below is belt-and-suspenders.
	const isTrustAnchor = (ctx.authorityHints?.length ?? 0) === 0;
	const payload = buildEntityConfigurationPayload({
		...payloadOptions,
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

	return signEntityStatement(payload, keySet.signer, {
		typ: JwtTyp.EntityStatement,
	});
}
