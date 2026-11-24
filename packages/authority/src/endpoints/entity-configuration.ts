import {
	composeRolePublicationMetadata,
	federationEntry,
	federationSigningOptions,
} from "@oidfed/core";
/** Authority Entity Configuration payload construction and HTTP publication. */

import {
	assertEndpointAuthenticationCompanions,
	buildEntityConfigurationPayload,
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	errorResponse,
	JwtTyp,
	jwtResponse,
	MediaType,
	nowSeconds,
	requireMethod,
	safeLogger,
	signEntityStatement,
} from "@oidfed/core";
import { InvalidAuthorityConfig } from "../errors.js";
import type { HandlerContext } from "./context.js";

const collectionNotices = new WeakSet<HandlerContext>();

/** Ensure a role's publication callback cannot advertise different authentication for a managed route. */
export function assertAuthorityAuthenticationPublication(
	configured: Readonly<Record<string, unknown>>,
	published: Readonly<Record<string, unknown>> | undefined,
): void {
	assertEndpointAuthenticationCompanions(published, InvalidAuthorityConfig);
	const authFields = new Set([...Object.keys(configured), ...Object.keys(published ?? {})]);
	for (const field of authFields) {
		if (!field.endsWith("_endpoint_auth_methods")) continue;
		const endpoint = field.slice(0, -"_auth_methods".length);
		if (configured[endpoint] === undefined) continue;
		const expected = advertisedValues(configured[field]);
		const actual = advertisedValues(published?.[field]);
		if (!expected?.has("private_key_jwt") && !actual?.has("private_key_jwt")) continue;
		const algorithms = "endpoint_auth_signing_alg_values_supported";
		if (
			!sameValues(expected, actual) ||
			!sameValues(
				advertisedValues(configured[algorithms]),
				advertisedValues(published?.[algorithms]),
			)
		)
			throw new InvalidAuthorityConfig(
				`Published ${endpoint} authentication must match the managed route`,
			);
	}
}

/** Compare the supported values independently of JSON array ordering. */
function sameValues(
	expected: ReadonlySet<unknown> | undefined,
	actual: ReadonlySet<unknown> | undefined,
): boolean {
	if (!expected || !actual) return expected === actual;
	return expected.size === actual.size && [...expected].every((value) => actual.has(value));
}

/** Preserve the distinction between an omitted advertisement and an empty list. */
function advertisedValues(value: unknown): ReadonlySet<unknown> | undefined {
	return Array.isArray(value) ? new Set(value as readonly unknown[]) : undefined;
}

/** Returns the authority's Entity Configuration as a signed JWT. */
export function createEntityConfigurationHandler(
	ctx: HandlerContext,
): (request: Request) => Promise<Response> {
	return async (request: Request) => {
		const methodError = requireMethod(request, "GET");
		if (methodError) return methodError;

		try {
			const jwt = await buildEntityConfiguration(ctx);
			return jwtResponse(jwt, MediaType.EntityStatement);
		} catch {
			safeLogger(ctx.options?.logger)?.error("Failed to build entity configuration");
			return errorResponse(500, "server_error", "Failed to build entity configuration");
		}
	};
}

/** Builds and signs the Entity Configuration JWT from the current context. */
export async function buildEntityConfiguration(ctx: HandlerContext): Promise<string> {
	const publication = await composeRolePublicationMetadata(ctx.roles, ctx.metadata, ctx);
	assertAuthorityAuthenticationPublication(
		ctx.metadata.federation_entity,
		publication.federation_entity,
	);
	const keySet = await federationEntry(ctx.crypto, {
		artifact: "entity-configuration",
		issuer: ctx.entityId,
		subject: ctx.entityId,
	});
	const now = nowSeconds(ctx.options?.clock);
	const ttlSeconds = ctx.entityConfigurationTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS;

	const payloadOptions = {
		algorithmRegistry: ctx.options.algorithmRegistry,
		entityId: ctx.entityId,
		jwks: keySet.publishedJwks,
		metadata: publication,
		issuedAt: now,
		ttlSeconds,
	};

	// Publish trust_mark_issuers and trust_mark_owners only when this host acts
	// as a Trust Anchor; recipients ignore these claims on Intermediates.
	const isTrustAnchor = ctx.isTrustAnchor ?? !ctx.authorityHints?.length;
	const payload = buildEntityConfigurationPayload({
		...payloadOptions,
		additionalClaims: ctx.additionalClaims,
		crit: ctx.crit,
		...(ctx.authorityHints && ctx.authorityHints.length > 0
			? { authorityHints: ctx.authorityHints }
			: {}),
		...(ctx.trustAnchorHints && ctx.trustAnchorHints.length > 0
			? { trustAnchorHints: ctx.trustAnchorHints }
			: {}),
		...(ctx.trustMarks && ctx.trustMarks.length > 0 ? { trustMarks: ctx.trustMarks } : {}),
		...(isTrustAnchor && ctx.trustMarkIssuers ? { trustMarkIssuers: ctx.trustMarkIssuers } : {}),
		...(isTrustAnchor && ctx.trustMarkOwners ? { trustMarkOwners: ctx.trustMarkOwners } : {}),
	});

	const jwt = await signEntityStatement(payload, keySet, {
		...federationSigningOptions(ctx.options, "entity-configuration"),
		typ: JwtTyp.EntityStatement,
	});
	if (
		ctx.metadata.federation_entity.federation_collection_endpoint &&
		!ctx.metadata.federation_entity.federation_resolve_endpoint &&
		!collectionNotices.has(ctx)
	) {
		collectionNotices.add(ctx);
		safeLogger(ctx.options?.logger)?.info(
			"Federation Entities publishing a federation_collection_endpoint SHOULD also publish a federation_resolve_endpoint",
		);
	}
	return jwt;
}
