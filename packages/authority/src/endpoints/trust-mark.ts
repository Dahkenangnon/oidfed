import {
	DEFAULT_DELEGATION_TTL_SECONDS,
	type EntityId,
	FederationErrorCode,
	isValidEntityId,
	JwtTyp,
	MediaType,
	nowSeconds,
	signEntityStatement,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { errorResponse, jwtResponse, parseQueryParams, requireMethod } from "./helpers.js";

/** Trust Mark retrieval endpoint. Returns an active trust mark or 404 if not found. */
export function createTrustMarkHandler(
	ctx: HandlerContext,
): (request: Request) => Promise<Response> {
	return async (request: Request) => {
		const methodError = requireMethod(request, "GET");
		if (methodError) return methodError;

		if (!ctx.storage.trustMarks) {
			return errorResponse(501, "server_error", "Trust mark store not configured");
		}

		const params = parseQueryParams(request);
		const trustMarkType = params.get("trust_mark_type");
		const sub = params.get("sub");

		if (!trustMarkType) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"Missing 'trust_mark_type' parameter",
			);
		}

		if (!sub || !isValidEntityId(sub)) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"Missing or invalid 'sub' parameter",
			);
		}

		try {
			const existing = await ctx.storage.trustMarks.getValid(
				trustMarkType,
				sub as EntityId,
				nowSeconds(ctx.options?.clock),
			);
			if (existing) {
				return jwtResponse(existing.jwt, MediaType.TrustMark);
			}

			return errorResponse(404, FederationErrorCode.NotFound, "Trust mark not found");
		} catch (error) {
			ctx.options?.logger?.error("Failed to retrieve trust mark", { error });
			return errorResponse(500, "server_error", "Failed to retrieve trust mark");
		}
	};
}

/**
 * Programmatic trust mark issuance — not a spec endpoint.
 * Used by `AuthorityServer.issueTrustMark()` for administrative issuance.
 */
export function createTrustMarkIssuanceHandler(
	ctx: HandlerContext,
): (request: Request) => Promise<Response> {
	return async (request: Request) => {
		const methodError = requireMethod(request, "GET");
		if (methodError) return methodError;

		if (!ctx.storage.trustMarks) {
			return errorResponse(501, "server_error", "Trust mark store not configured");
		}

		const params = parseQueryParams(request);
		const trustMarkType = params.get("trust_mark_type");
		const sub = params.get("sub");

		if (!trustMarkType) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"Missing 'trust_mark_type' parameter",
			);
		}

		if (!sub || !isValidEntityId(sub)) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"Missing or invalid 'sub' parameter",
			);
		}

		if (ctx.trustMarkIssuers) {
			const authorizedIssuers = ctx.trustMarkIssuers[trustMarkType];
			if (authorizedIssuers && !authorizedIssuers.includes(ctx.entityId)) {
				return errorResponse(
					403,
					"unauthorized_issuer",
					`Not authorized to issue trust mark '${trustMarkType}'`,
				);
			}
		}

		try {
			const subject = sub as EntityId;
			const now = nowSeconds(ctx.options?.clock);
			const existing = await ctx.storage.trustMarks.getValid(trustMarkType, subject, now);
			if (existing) {
				return jwtResponse(existing.jwt, MediaType.TrustMark);
			}

			const ttl = ctx.trustMarkTtlSeconds ?? DEFAULT_DELEGATION_TTL_SECONDS;
			const jwt = await buildTrustMark(ctx, trustMarkType, sub, now, ttl);
			const candidate = {
				trustMarkType,
				subject,
				jwt,
				issuedAt: now,
				expiresAt: now + ttl,
				active: true,
			} as const;
			const selected = await ctx.storage.transaction(async (tx) => {
				if (!tx.trustMarks) throw new Error("Trust mark storage is not configured");
				const winner = await tx.trustMarks.getValid(trustMarkType, subject, now);
				if (winner) return winner;
				await tx.trustMarks.issue(candidate);
				return candidate;
			});

			return jwtResponse(selected.jwt, MediaType.TrustMark);
		} catch (error) {
			ctx.options?.logger?.error("Failed to issue trust mark", { error });
			return errorResponse(500, "server_error", "Failed to issue trust mark");
		}
	};
}

async function buildTrustMark(
	ctx: HandlerContext,
	trustMarkType: string,
	sub: string,
	now: number,
	ttl: number,
): Promise<string> {
	const keySet = await ctx.keyProvider.getFederationKeySet();

	const payload: Record<string, unknown> = {
		iss: ctx.entityId,
		sub,
		trust_mark_type: trustMarkType,
		iat: now,
		exp: now + ttl,
	};

	if (ctx.trustMarkDelegations?.[trustMarkType]) {
		payload.delegation = ctx.trustMarkDelegations[trustMarkType];
	}

	return signEntityStatement(payload, keySet.signer, {
		typ: JwtTyp.TrustMark,
	});
}
