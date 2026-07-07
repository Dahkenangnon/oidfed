import {
	type EntityId,
	type EntityType,
	FederationErrorCode,
	isValidEntityId,
	type JWKSet,
	JwtTyp,
	MediaType,
	nowSeconds,
	resolveTrustChains,
	signEntityStatement,
	type TrustAnchorSet,
	validateTrustChain,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { errorResponse, jwtResponse, parseQueryParams, requireMethod } from "./helpers.js";

/** Handles resolve endpoint requests to produce a signed resolve response. */
export function createResolveHandler(ctx: HandlerContext): (request: Request) => Promise<Response> {
	return async (request: Request) => {
		const methodError = requireMethod(request, "GET");
		if (methodError) return methodError;

		const params = parseQueryParams(request);
		const sub = params.get("sub");
		const trustAnchorParam = params.getAll("trust_anchor");
		const entityTypeParam = params.getAll("entity_type");

		if (!sub || !isValidEntityId(sub)) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"Missing or invalid 'sub' parameter",
			);
		}

		if (trustAnchorParam.length === 0) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"Missing 'trust_anchor' parameter",
			);
		}

		// Validate X-Authenticated-Entity header before trust chain resolution
		const rawEntity = request.headers.get("X-Authenticated-Entity");
		if (rawEntity && !isValidEntityId(rawEntity)) {
			return errorResponse(400, "invalid_request", "Invalid X-Authenticated-Entity header value");
		}
		const isAuthenticated = Boolean(rawEntity);

		if (!ctx.trustAnchors) {
			return errorResponse(
				404,
				FederationErrorCode.InvalidTrustAnchor,
				"No trust anchors configured",
			);
		}

		const usableTrustAnchors: EntityId[] = [];
		for (const ta of trustAnchorParam) {
			if (!isValidEntityId(ta)) {
				return errorResponse(404, FederationErrorCode.InvalidTrustAnchor, "Unknown trust anchor");
			}
			if (ctx.trustAnchors.has(ta as EntityId)) {
				usableTrustAnchors.push(ta as EntityId);
			}
		}
		if (usableTrustAnchors.length === 0) {
			return errorResponse(404, FederationErrorCode.InvalidTrustAnchor, "Unknown trust anchor");
		}

		// Cache-first short-circuit: if a previously vetted Resolve Response is
		// available for this (sub, trustAnchors, entityTypes) tuple, serve it
		// directly without invoking fresh trust-chain resolution.
		if (ctx.cachedResolutionLookup) {
			const cached = await ctx.cachedResolutionLookup(
				sub as EntityId,
				usableTrustAnchors,
				entityTypeParam as EntityType[],
			);
			if (cached !== undefined) {
				return jwtResponse(cached, MediaType.ResolveResponse);
			}
			if (!isAuthenticated && ctx.requireAuthForFreshResolution) {
				return errorResponse(
					404,
					FederationErrorCode.NotFound,
					"No cached resolution available; fresh resolution requires authentication",
				);
			}
		} else if (!isAuthenticated && ctx.requireAuthForFreshResolution) {
			return errorResponse(
				404,
				FederationErrorCode.NotFound,
				"Fresh resolution requires authentication",
			);
		}

		try {
			const requestedAnchors: Map<EntityId, Readonly<{ jwks: JWKSet }>> = new Map();
			for (const ta of usableTrustAnchors) {
				const anchorData = ctx.trustAnchors.get(ta);
				if (anchorData) {
					requestedAnchors.set(ta, anchorData);
				}
			}

			const result = await resolveTrustChains(
				sub as EntityId,
				requestedAnchors as TrustAnchorSet,
				ctx.options,
			);

			if (result.chains.length === 0) {
				return errorResponse(404, FederationErrorCode.NotFound, "No valid trust chain found");
			}

			const chain = result.chains[0];
			if (!chain) {
				return errorResponse(404, FederationErrorCode.NotFound, "No valid trust chain found");
			}

			const validation = await validateTrustChain(
				[...chain.statements],
				requestedAnchors as TrustAnchorSet,
				ctx.options,
			);

			if (!validation.valid) {
				return errorResponse(404, FederationErrorCode.NotFound, "No valid trust chain found");
			}

			let resolvedMetadata = validation.chain.resolvedMetadata as
				| Record<string, unknown>
				| undefined;
			if (entityTypeParam.length > 0 && resolvedMetadata) {
				const filtered: Record<string, unknown> = {};
				for (const et of entityTypeParam) {
					if (et in resolvedMetadata) {
						filtered[et] = resolvedMetadata[et];
					}
				}
				if (Object.keys(filtered).length === 0) {
					return errorResponse(404, FederationErrorCode.NotFound, "No matching entity types found");
				}
				resolvedMetadata = filtered;
			}

			const keySet = await ctx.keyProvider.getFederationKeySet();
			const now = nowSeconds(ctx.options?.clock);

			// Exp is capped to the earliest expiry across the chain and trust marks
			let resolveExp = chain.expiresAt;
			if (validation.chain.trustMarks) {
				for (const tm of validation.chain.trustMarks) {
					if (tm.expiresAt !== undefined && tm.expiresAt < resolveExp) {
						resolveExp = tm.expiresAt;
					}
				}
			}

			const payload: Record<string, unknown> = {
				iss: ctx.entityId,
				sub,
				iat: now,
				exp: resolveExp,
				metadata: resolvedMetadata,
				trust_chain: [...chain.statements],
			};

			// Include aud only for authenticated requests (validated earlier)
			if (rawEntity) {
				payload.aud = rawEntity;
			}

			if (validation.chain.trustMarks && validation.chain.trustMarks.length > 0) {
				const leafStatement = validation.chain.statements[0];
				const leafTrustMarks = leafStatement
					? ((leafStatement.payload as Record<string, unknown>).trust_marks as
							| Array<{ trust_mark_type: string; trust_mark: string }>
							| undefined)
					: undefined;

				if (leafTrustMarks) {
					const validatedTypes = new Set(validation.chain.trustMarks.map((tm) => tm.trustMarkType));
					payload.trust_marks = leafTrustMarks.filter((ref) =>
						validatedTypes.has(ref.trust_mark_type),
					);
				}
			}

			const extraHeaders: Record<string, unknown> = {};
			if (!requestedAnchors.has(ctx.entityId as EntityId)) {
				try {
					const issuerResult = await resolveTrustChains(
						ctx.entityId as EntityId,
						requestedAnchors as TrustAnchorSet,
						ctx.options,
					);
					const firstChain = issuerResult.chains[0];
					if (firstChain) {
						extraHeaders.trust_chain = [...firstChain.statements];
					}
				} catch {
					/* MAY feature — silently ignore issuer chain resolution failures */
				}
			}

			const jwt = await signEntityStatement(payload, keySet.signer, {
				typ: JwtTyp.ResolveResponse,
				extraHeaders,
			});

			return jwtResponse(jwt, MediaType.ResolveResponse);
		} catch (error) {
			ctx.options?.logger?.error("Failed to resolve entity", { error });
			return errorResponse(500, "server_error", "Failed to resolve entity");
		}
	};
}
