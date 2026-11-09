import {
	DEFAULT_MAX_REQUEST_BODY_BYTES,
	decodeEntityStatement,
	FederationErrorCode,
	isOk,
	JWKSchema,
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

		if (!ctx.storage.trustMarks) {
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

		// §7.1 defines a collision-resistant type string, not an Entity Identifier.
		if (typeof trustMarkType !== "string" || !trustMarkType || !sub) {
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
		const record = await ctx.storage.trustMarks.getByJwt(trustMarkJwt);
		if (!record) {
			return errorResponse(404, FederationErrorCode.NotFound, "Trust mark not found");
		}
		const exp = payload.exp as number | undefined;
		if (exp !== undefined && exp <= now) {
			return buildStatusResponse(ctx, trustMarkJwt, TrustMarkStatus.Expired);
		}

		// Prefer published keys. Retirement may leave a still-active mark signed by an older key.
		const keySet = await ctx.keyProvider.getFederationKeySet();
		let verificationKeys = keySet.jwks;
		const kid = decoded.value.header.kid;
		if (typeof kid === "string" && !keySet.jwks.keys.some((key) => key.kid === kid)) {
			const issuedAt = payload.iat;
			if (typeof issuedAt !== "number" || !Number.isFinite(issuedAt))
				return buildStatusResponse(ctx, trustMarkJwt, TrustMarkStatus.Invalid);
			// Historical lifetime (§8.7.2) establishes issuance eligibility, not current
			// signing authority. This fallback excludes revoked keys; the stored mark's
			// current status is evaluated separately under §8.4.
			const historical = await ctx.keyProvider.getHistoricalFederationKeys();
			const key = historical.find(
				(key) =>
					key.kid === kid &&
					key.revoked === undefined &&
					Number.isFinite(key.exp) &&
					issuedAt < key.exp &&
					(key.iat === undefined || (Number.isFinite(key.iat) && issuedAt >= key.iat)) &&
					(key.nbf === undefined || (Number.isFinite(key.nbf) && issuedAt >= key.nbf)),
			);
			if (!key) return buildStatusResponse(ctx, trustMarkJwt, TrustMarkStatus.Invalid);
			const parsedKey = JWKSchema.safeParse(key);
			if (!parsedKey.success)
				return buildStatusResponse(ctx, trustMarkJwt, TrustMarkStatus.Invalid);
			verificationKeys = { keys: [parsedKey.data] };
		}
		const sigResult = await verifyEntityStatement(trustMarkJwt, verificationKeys, {
			expectedTyp: JwtTyp.TrustMark,
			...(ctx.options?.clock ? { clock: ctx.options.clock } : {}),
			...(ctx.options?.clockSkewSeconds !== undefined
				? { clockSkewSeconds: ctx.options.clockSkewSeconds }
				: {}),
		});
		if (!isOk(sigResult)) {
			return buildStatusResponse(ctx, trustMarkJwt, TrustMarkStatus.Invalid);
		}

		// Signature verification alone does not check issuance time. Apply §7.3
		// against the authority's clock, as the current-validity storage queries do.
		const issuedAt = sigResult.value.payload.iat;
		if (typeof issuedAt !== "number" || !Number.isFinite(issuedAt) || issuedAt > now) {
			return buildStatusResponse(ctx, trustMarkJwt, TrustMarkStatus.Invalid);
		}

		if (!record.active) {
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
	const keySet = await ctx.keyProvider.getFederationKeySet();
	const now = nowSeconds(ctx.options?.clock);

	const payload: Record<string, unknown> = {
		iss: ctx.entityId,
		iat: now,
		trust_mark: trustMarkJwt,
		status,
	};

	const jwt = await signEntityStatement(payload, keySet.signer, {
		typ: JwtTyp.TrustMarkStatusResponse,
	});

	return jwtResponse(jwt, MediaType.TrustMarkStatusResponse);
}
