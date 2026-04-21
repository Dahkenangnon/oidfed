import {
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	JwtTyp,
	MediaType,
	nowSeconds,
	signEntityStatement,
} from "@oidfed/core";
import type { ManagedKey } from "../storage/types.js";
import type { HandlerContext } from "./context.js";
import { errorResponse, jwtResponse, requireMethod, stripPrivateFields } from "./helpers.js";

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

function mapManagedKey(
	managed: ManagedKey,
	ecExpSeconds: number,
	nowSeconds: number,
): Record<string, unknown> {
	const entry: Record<string, unknown> = { ...stripPrivateFields(managed.key) };
	if (managed.expiresAt) {
		entry.exp = Math.floor(managed.expiresAt / 1000);
	} else if (managed.scheduledRemovalAt) {
		entry.exp = Math.floor(managed.scheduledRemovalAt / 1000);
	} else if (managed.revokedAt) {
		entry.exp = Math.floor(managed.revokedAt / 1000);
	} else if (managed.state === "active") {
		entry.exp = ecExpSeconds;
	} else {
		entry.exp = nowSeconds;
	}

	if (managed.createdAt) {
		entry.iat = Math.floor(managed.createdAt / 1000);
	} else if (managed.activatedAt) {
		entry.iat = Math.floor(managed.activatedAt / 1000);
	}

	if (managed.activatedAt) {
		entry.nbf = Math.floor(managed.activatedAt / 1000);
	}

	if (managed.state === "revoked") {
		const revoked: Record<string, unknown> = {
			revoked_at: managed.revokedAt ? Math.floor(managed.revokedAt / 1000) : 0,
		};
		if (managed.revocationReason) {
			revoked.reason = managed.revocationReason;
		}
		entry.revoked = revoked;
	}

	return entry;
}

export async function buildHistoricalKeys(ctx: HandlerContext): Promise<string> {
	const allKeys = await ctx.keyStore.getHistoricalKeys();
	const { key: signingKey, kid } = await ctx.getSigningKey();
	const now = nowSeconds(ctx.options?.clock);
	const ecExp = now + (ctx.entityConfigurationTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS);

	const payload = {
		iss: ctx.entityId,
		iat: now,
		keys: allKeys.map((k) => mapManagedKey(k, ecExp, now)),
	};

	return signEntityStatement(payload as Record<string, unknown>, signingKey, {
		kid,
		typ: JwtTyp.JwkSet,
	});
}
