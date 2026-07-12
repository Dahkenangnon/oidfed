import {
	buildSubordinateStatementPayload,
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
import { sanitizeSubordinateMetadata } from "../utils/subordinate-statement-shape.js";
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

			const record = await ctx.storage.subordinates.get(sub as EntityId);
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

/**
 * Builds and signs a subordinate statement JWT for the given record. When
 * `now` is supplied, it is used verbatim as the JWT `iat` (and `exp` is derived
 * from it) — this lets callers (e.g. the extended-listing handler) snapshot a
 * single timestamp for an entire page so synthetic `iat`/`exp` claims align
 * with the JWT.
 */
export async function buildSubordinateStatement(
	ctx: HandlerContext,
	record: SubordinateRecord,
	now?: number,
): Promise<string> {
	const keySet = await ctx.keyProvider.getFederationKeySet();
	const iat = now ?? nowSeconds(ctx.options?.clock);

	// Strip operational federation_entity fields (endpoint URLs, _auth_methods,
	// endpoint_auth_signing_alg_values_supported) — those belong only in the
	// subordinate's own Entity Configuration, not in this Subordinate Statement.
	const sanitized = sanitizeSubordinateMetadata(record.metadata);
	const payload = buildSubordinateStatementPayload({
		issuer: ctx.entityId,
		subject: record.entityId,
		jwks: record.jwks,
		...(sanitized !== undefined ? { metadata: sanitized } : {}),
		...(record.metadataPolicy ? { metadataPolicy: record.metadataPolicy } : {}),
		...(record.constraints ? { constraints: record.constraints } : {}),
		...(record.sourceEndpoint ? { sourceEndpoint: record.sourceEndpoint } : {}),
		...(record.crit && record.crit.length > 0 ? { crit: record.crit } : {}),
		...(record.metadataPolicyCrit && record.metadataPolicyCrit.length > 0
			? { metadataPolicyCrit: record.metadataPolicyCrit }
			: {}),
		issuedAt: iat,
		ttlSeconds: ctx.subordinateStatementTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	});

	return signEntityStatement(payload, keySet.signer, {
		typ: JwtTyp.EntityStatement,
	});
}
