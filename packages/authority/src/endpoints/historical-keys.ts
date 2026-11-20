import { federationEntry, federationSigningOptions, HistoricalKeyEntrySchema } from "@oidfed/core";
import { assertPublicJwk, DEFAULT_JWS_REGISTRY } from "@oidfed/crypto";
/** Authority Historical Keys payload signing and endpoint responses. */

import {
	errorResponse,
	JwtTyp,
	jwtResponse,
	MediaType,
	nowSeconds,
	requireMethod,
	safeLogger,
	signEntityStatement,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";

/** Publish the provider's historical keys as a signed JWK Set (Federation §8.7.2). */
export function createHistoricalKeysHandler(
	ctx: HandlerContext,
): (request: Request) => Promise<Response> {
	return async (request: Request) => {
		const methodError = requireMethod(request, "GET");
		if (methodError) return methodError;

		try {
			const jwt = await buildHistoricalKeys(ctx);
			return jwtResponse(jwt, MediaType.JwkSet);
		} catch {
			safeLogger(ctx.options?.logger)?.error("Failed to build historical keys");
			return errorResponse(500, "server_error", "Failed to build historical keys");
		}
	};
}

/** Sign the key provider's historical public-key records with the current Federation Entity Key. */
export async function buildHistoricalKeys(ctx: HandlerContext): Promise<string> {
	const keySet = await federationEntry(ctx.crypto, { issuer: ctx.entityId });
	if (!ctx.crypto.history) throw new TypeError("Historical keys source is not configured");
	const historicalKeys = (await ctx.crypto.history.getHistoricalKeys()).map((key) => {
		const record = HistoricalKeyEntrySchema.parse(key);
		if (DEFAULT_JWS_REGISTRY.keyType(record.kty)) return record;
		const publicKey = assertPublicJwk(record, ctx.crypto.algorithmRegistry);
		const { exp, iat, nbf, revoked } = record;
		return { ...publicKey, exp, iat, nbf, revoked };
	});
	const now = nowSeconds(ctx.options?.clock);

	const payload = {
		iss: ctx.entityId,
		iat: now,
		keys: historicalKeys,
	};

	return signEntityStatement(payload as Record<string, unknown>, keySet, {
		...federationSigningOptions(ctx.options),
		typ: JwtTyp.JwkSet,
	});
}
