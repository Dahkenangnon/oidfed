import {
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	type EntityId,
	FederationErrorCode,
	isValidEntityId,
	JwtTyp,
	MediaType,
	nowSeconds,
	signEntityStatement,
} from "@oidfed/core";
import type { SubordinateRecord } from "../storage/types.js";
import type { HandlerContext } from "./context.js";
import { errorResponse, jwtResponse, parseQueryParams, requireMethod } from "./helpers.js";

/** Handles fetch endpoint requests to return a subordinate statement. */
export function createFetchHandler(ctx: HandlerContext): (request: Request) => Promise<Response> {
	return async (request: Request) => {
		const methodError = requireMethod(request, "GET");
		if (methodError) return methodError;

		const params = parseQueryParams(request);
		const sub = params.get("sub");

		if (!sub || !isValidEntityId(sub)) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"Missing or invalid 'sub' parameter",
			);
		}

		try {
			if (sub === ctx.entityId) {
				return errorResponse(
					400,
					FederationErrorCode.InvalidRequest,
					"Use the Entity Configuration endpoint to fetch the issuer's own configuration",
				);
			}

			const record = await ctx.subordinateStore.get(sub as EntityId);
			if (!record) {
				return errorResponse(404, FederationErrorCode.NotFound, "Entity not found");
			}

			const jwt = await buildSubordinateStatement(ctx, record);
			return jwtResponse(jwt, MediaType.EntityStatement);
		} catch (error) {
			ctx.options?.logger?.error("Failed to build subordinate statement", { error });
			return errorResponse(500, "server_error", "Failed to build statement");
		}
	};
}

/** Builds and signs a subordinate statement JWT for the given record. */
export async function buildSubordinateStatement(
	ctx: HandlerContext,
	record: SubordinateRecord,
): Promise<string> {
	const { key: signingKey, kid } = await ctx.getSigningKey();
	const now = nowSeconds(ctx.options?.clock);

	const payload: Record<string, unknown> = {
		iss: ctx.entityId,
		sub: record.entityId,
		iat: now,
		exp: now + (ctx.subordinateStatementTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS),
		jwks: record.jwks,
	};

	if (record.metadata) payload.metadata = record.metadata;
	if (record.metadataPolicy) payload.metadata_policy = record.metadataPolicy;
	if (record.constraints) payload.constraints = record.constraints;
	if (record.sourceEndpoint) payload.source_endpoint = record.sourceEndpoint;

	return signEntityStatement(payload, signingKey, {
		kid,
		typ: JwtTyp.EntityStatement,
	});
}
