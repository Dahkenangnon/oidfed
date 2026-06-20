import { JwtTyp, MediaType, nowSeconds, signEntityStatement } from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { errorResponse, jwtResponse, requireMethod } from "./helpers.js";

/** Handles historical keys endpoint requests, returning all key states as a signed JWK Set. */
export function createHistoricalKeysHandler(
	ctx: HandlerContext,
): (request: Request) => Promise<Response> {
	return async (request: Request) => {
		const methodError = requireMethod(request, "GET");
		if (methodError) return methodError;

		try {
			const jwt = await buildHistoricalKeys(ctx);
			return jwtResponse(jwt, MediaType.JwkSet);
		} catch (error) {
			ctx.options?.logger?.error("Failed to build historical keys", { error });
			return errorResponse(500, "server_error", "Failed to build historical keys");
		}
	};
}

export async function buildHistoricalKeys(ctx: HandlerContext): Promise<string> {
	const keySet = await ctx.keyProvider.getFederationKeySet();
	const historicalKeys = await ctx.keyProvider.getHistoricalFederationKeys();
	const now = nowSeconds(ctx.options?.clock);

	const payload = {
		iss: ctx.entityId,
		iat: now,
		keys: historicalKeys,
	};

	return signEntityStatement(payload as Record<string, unknown>, keySet.signer, {
		typ: JwtTyp.JwkSet,
	});
}
