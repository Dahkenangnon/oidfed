import { federationEntry, federationSigningOptions } from "@oidfed/core";
/** Subordinate Statement signing and Fetch endpoint responses. */

import {
	buildSubordinateStatementPayload,
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	type EntityId,
	type EntityStatementMetadata,
	FederationErrorCode,
	isValidEntityId,
	JwtTyp,
	MediaType,
	nowSeconds,
	safeLogger,
	signEntityStatement,
} from "@oidfed/core";
import type { SubordinateRecord } from "../storage/types.js";
import {
	assertSubordinatePublicationClaims,
	subordinatePublicationClaim,
} from "../utils/subordinate-publication.js";
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
		...federationSigningOptions(ctx.options),
		typ: JwtTyp.EntityStatement,
	});
}
