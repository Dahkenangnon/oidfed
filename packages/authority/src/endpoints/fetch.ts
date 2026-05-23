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
import {
	assertCritShape,
	assertMetadataPolicyCritShape,
	assertMetadataPolicyShape,
	assertMetadataValuesNotNull,
	assertSubordinateStatementShape,
	sanitizeSubordinateMetadata,
} from "../utils/subordinate-statement-shape.js";
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
	const { key: signingKey, kid } = await ctx.getSigningKey();
	const iat = now ?? nowSeconds(ctx.options?.clock);

	const payload: Record<string, unknown> = {
		iss: ctx.entityId,
		sub: record.entityId,
		iat,
		exp: iat + (ctx.subordinateStatementTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS),
		jwks: record.jwks,
	};

	// Strip operational federation_entity fields (endpoint URLs, _auth_methods,
	// endpoint_auth_signing_alg_values_supported) — those belong only in the
	// subordinate's own Entity Configuration, not in this Subordinate Statement.
	const sanitized = sanitizeSubordinateMetadata(record.metadata);
	if (sanitized !== undefined) {
		assertMetadataValuesNotNull(sanitized);
		payload.metadata = sanitized;
	}

	if (record.metadataPolicy) payload.metadata_policy = record.metadataPolicy;
	if (record.constraints) payload.constraints = record.constraints;
	if (record.sourceEndpoint) payload.source_endpoint = record.sourceEndpoint;
	if (record.crit && record.crit.length > 0) payload.crit = [...record.crit];
	if (record.metadataPolicyCrit && record.metadataPolicyCrit.length > 0) {
		payload.metadata_policy_crit = [...record.metadataPolicyCrit];
	}

	// Defense in depth: fail loudly if any forbidden top-level claim slipped in
	// or if crit / metadata_policy_crit / metadata_policy carry illegal shapes.
	assertSubordinateStatementShape(payload);
	assertMetadataPolicyShape(payload);
	assertCritShape(payload);
	assertMetadataPolicyCritShape(payload);

	return signEntityStatement(payload, signingKey, {
		kid,
		typ: JwtTyp.EntityStatement,
	});
}
