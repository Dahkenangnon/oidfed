import { federationEntry, federationSigningOptions, fetchStoredSubordinate } from "@oidfed/core";

/** Subordinate Statement signing and Fetch endpoint responses. */

import type { SubordinateRecord } from "@oidfed/core";
import {
	assertSubordinatePublicationClaims,
	buildSubordinateStatementPayload,
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	type EntityId,
	type EntityStatementMetadata,
	errorResponse,
	FederationErrorCode,
	isValidEntityId,
	JwtTyp,
	jwtResponse,
	MediaType,
	nowSeconds,
	parseQueryParams,
	requireMethod,
	safeLogger,
	signEntityStatement,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { subordinatePublicationClaim } from "./subordinate-claims.js";

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

			const record = await fetchStoredSubordinate(
				ctx.storage.subordinate,
				sub as EntityId,
				ctx.options,
			);
			if (!record) {
				return errorResponse(404, FederationErrorCode.NotFound, "Entity not found");
			}

			const jwt = await buildSubordinateStatement(ctx, record);
			return jwtResponse(jwt, MediaType.EntityStatement);
		} catch {
			safeLogger(ctx.options?.logger)?.error("Failed to build subordinate statement");
			return errorResponse(500, "server_error", "Failed to build statement");
		}
	};
}

/**
 * Build and sign a Subordinate Statement for the record. Use a supplied `now` as
 * `iat` and derive `exp` from it. Extended Listing can share this timestamp across
 * a page so the response's `iat`/`exp` claims match its signed statements.
 */
export async function buildSubordinateStatement(
	ctx: HandlerContext,
	record: SubordinateRecord,
	now?: number,
): Promise<string> {
	assertSubordinatePublicationClaims(
		{ ...record, metadata: undefined },
		{ customOperators: ctx.options?.customPolicyOperators },
	);
	const keySet = await federationEntry(ctx.crypto, {
		artifact: "subordinate-statement",
		issuer: ctx.entityId,
		subject: record.entityId,
	});
	const iat = now ?? nowSeconds(ctx.options?.clock);

	// Operational fields are published through the subordinate's own Entity Configuration.
	// The sanitizer documents the specification restrictions and additional host policy.
	const sanitized = subordinatePublicationClaim(record, "metadata", ctx);
	subordinatePublicationClaim(record, "metadata_policy", ctx);
	subordinatePublicationClaim(record, "constraints", ctx);
	const payload = buildSubordinateStatementPayload({
		algorithmRegistry: ctx.options.algorithmRegistry,
		...(record.additionalClaims !== undefined ? { additionalClaims: record.additionalClaims } : {}),
		issuer: ctx.entityId,
		subject: record.entityId,
		jwks: record.jwks,
		...(sanitized !== undefined ? { metadata: sanitized as EntityStatementMetadata } : {}),
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

	return signEntityStatement(payload, keySet, {
		...federationSigningOptions(ctx.options, "subordinate-statement"),
		typ: JwtTyp.EntityStatement,
	});
}
