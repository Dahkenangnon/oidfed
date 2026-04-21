import {
	DEFAULT_MAX_REQUEST_BODY_BYTES,
	decodeEntityStatement,
	type EntityId,
	FederationErrorCode,
	isOk,
	isValidEntityId,
	JwtTyp,
	MediaType,
	nowSeconds,
	signEntityStatement,
	TrustMarkStatus,
	verifyEntityStatement,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { errorResponse, jwtResponse, readBodyWithLimit, requireMethod } from "./helpers.js";

/** Handles trust mark status check requests, returning active/revoked/expired/invalid. */
export function createTrustMarkStatusHandler(
	ctx: HandlerContext,
): (request: Request) => Promise<Response> {
	return async (request: Request) => {
		const methodError = requireMethod(request, "POST");
		if (methodError) return methodError;

		if (!ctx.trustMarkStore) {
			return errorResponse(501, "server_error", "Trust mark store not configured");
		}

		const read = await readBodyWithLimit(request, DEFAULT_MAX_REQUEST_BODY_BYTES);
		if (!read.ok) {
			return errorResponse(413, FederationErrorCode.InvalidRequest, "Request body too large");
		}
		const params = new URLSearchParams(read.text);
		const body = Object.fromEntries(params.entries());

		let trustMarkJwt: string;
		const trustMarkValue = body.trust_mark;
		if (!trustMarkValue) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"Missing 'trust_mark' parameter",
			);
		}
		trustMarkJwt = trustMarkValue;

		const decoded = decodeEntityStatement(trustMarkJwt);
		if (!isOk(decoded)) {
			return buildStatusResponse(ctx, trustMarkJwt, TrustMarkStatus.Invalid);
		}

		const payload = decoded.value.payload as Record<string, unknown>;
		const trustMarkType = payload.trust_mark_type as string | undefined;
		const sub = payload.sub as string | undefined;
		const iss = payload.iss as string | undefined;

		if (!trustMarkType || !isValidEntityId(trustMarkType) || !sub) {
			return buildStatusResponse(ctx, trustMarkJwt, TrustMarkStatus.Invalid);
		}

		if (iss !== ctx.entityId) {
			return errorResponse(
				404,
				FederationErrorCode.NotFound,
				"Trust mark not issued by this entity",
			);
		}

		const now = nowSeconds(ctx.options?.clock);

		const exp = payload.exp as number | undefined;
		if (exp !== undefined && exp < now) {
			return buildStatusResponse(ctx, trustMarkJwt, TrustMarkStatus.Expired);
		}

		// Verify trust mark signature against all active+retiring keys
		// Placed after expiry check so expired-but-valid tokens return Expired correctly.
		const activeJwks = await ctx.keyStore.getActiveKeys();
		const sigResult = await verifyEntityStatement(trustMarkJwt, activeJwks, {
			expectedTyp: JwtTyp.TrustMark,
		});
		if (!isOk(sigResult)) {
			return buildStatusResponse(ctx, trustMarkJwt, TrustMarkStatus.Invalid);
		}

		const isActive = await ctx.trustMarkStore.isActive(trustMarkType, sub as EntityId);

		if (!isActive) {
			const record = await ctx.trustMarkStore.get(trustMarkType, sub as EntityId);
			if (!record) {
				return errorResponse(404, FederationErrorCode.NotFound, "Trust mark not found");
			}
			return buildStatusResponse(ctx, trustMarkJwt, TrustMarkStatus.Revoked);
		}

		return buildStatusResponse(ctx, trustMarkJwt, TrustMarkStatus.Active);
	};
}

async function buildStatusResponse(
	ctx: HandlerContext,
	trustMarkJwt: string,
	status: TrustMarkStatus,
): Promise<Response> {
	const { key: signingKey, kid } = await ctx.getSigningKey();
	const now = nowSeconds(ctx.options?.clock);

	const payload: Record<string, unknown> = {
		iss: ctx.entityId,
		iat: now,
		trust_mark: trustMarkJwt,
		status,
	};

	const jwt = await signEntityStatement(payload, signingKey, {
		kid,
		typ: JwtTyp.TrustMarkStatusResponse,
	});

	return jwtResponse(jwt, MediaType.TrustMarkStatusResponse);
}
