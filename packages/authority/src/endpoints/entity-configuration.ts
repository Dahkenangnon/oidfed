import {
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
	const activeKeys = await ctx.keyStore.getActiveKeys();
	if (activeKeys.keys.length === 0) {
		throw new Error("No active signing keys available");
	}
	const { key: signingKey, kid } = await ctx.getSigningKey();
	const now = nowSeconds(ctx.options?.clock);

	const payload: Record<string, unknown> = {
		iss: ctx.entityId,
		sub: ctx.entityId,
		iat: now,
		exp: now + (ctx.entityConfigurationTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS),
		jwks: activeKeys,
		metadata: ctx.metadata,
	};

	if (ctx.authorityHints && ctx.authorityHints.length > 0) {
		payload.authority_hints = ctx.authorityHints;
	}

	if (ctx.trustMarks && ctx.trustMarks.length > 0) {
		payload.trust_marks = ctx.trustMarks;
	}

	if (ctx.trustMarkIssuers) {
		payload.trust_mark_issuers = ctx.trustMarkIssuers;
	}

	if (ctx.trustMarkOwners) {
		payload.trust_mark_owners = ctx.trustMarkOwners;
	}

	return signEntityStatement(payload, signingKey, {
		kid,
		typ: JwtTyp.EntityStatement,
	});
}
