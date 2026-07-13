import {
	type EntityId,
	type EntityType,
	FederationErrorCode,
	fetchTrustMarkStatus,
	isValidEntityId,
	type JWKSet,
	JwtTyp,
	MediaType,
	nowSeconds,
	type ParsedEntityStatement,
	resolveTrustChains,
	signEntityStatement,
	type TrustAnchorSet,
	TrustMarkStatus,
	type ValidatedTrustMark,
	validateTrustChain,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { errorResponse, jwtResponse, parseQueryParams, requireMethod } from "./helpers.js";

type ResolveTrustMarkRef = { trust_mark_type: string; trust_mark: string };

interface ActiveResolveTrustMark {
	ref: ResolveTrustMarkRef;
	mark: ValidatedTrustMark;
}

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
			const activeTrustMarks = await resolveActiveTrustMarks(
				ctx,
				validation.chain.statements,
				validation.chain.trustMarks,
				now,
			);

			// Exp is capped to the earliest expiry across the chain and trust marks
			let resolveExp = chain.expiresAt;
			for (const { mark } of activeTrustMarks) {
				if (mark.expiresAt !== undefined && mark.expiresAt < resolveExp) {
					resolveExp = mark.expiresAt;
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

			if (activeTrustMarks.length > 0) {
				payload.trust_marks = activeTrustMarks.map(({ ref }) => ref);
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

async function resolveActiveTrustMarks(
	ctx: HandlerContext,
	statements: ReadonlyArray<ParsedEntityStatement>,
	validatedTrustMarks: ReadonlyArray<ValidatedTrustMark>,
	now: number,
): Promise<ActiveResolveTrustMark[]> {
	if (validatedTrustMarks.length === 0) return [];
	const leafStatement = statements[0];
	const leafTrustMarks = leafStatement
		? ((leafStatement.payload as Record<string, unknown>).trust_marks as
				| ResolveTrustMarkRef[]
				| undefined)
		: undefined;
	if (!leafTrustMarks || leafTrustMarks.length === 0) return [];

	const active: ActiveResolveTrustMark[] = [];
	const usedValidatedIndexes = new Set<number>();
	for (const ref of leafTrustMarks) {
		const validatedIndex = validatedTrustMarks.findIndex(
			(mark, index) =>
				!usedValidatedIndexes.has(index) && mark.trustMarkType === ref.trust_mark_type,
		);
		if (validatedIndex === -1) continue;

		const mark = validatedTrustMarks[validatedIndex];
		if (!mark) continue;
		usedValidatedIndexes.add(validatedIndex);

		if (await isTrustMarkActiveForResolve(ctx, statements, ref, mark, now)) {
			active.push({ ref, mark });
		}
	}
	return active;
}

async function isTrustMarkActiveForResolve(
	ctx: HandlerContext,
	statements: ReadonlyArray<ParsedEntityStatement>,
	ref: ResolveTrustMarkRef,
	mark: ValidatedTrustMark,
	now: number,
): Promise<boolean> {
	if (mark.issuer === ctx.entityId && ctx.storage.trustMarks) {
		try {
			const record = await ctx.storage.trustMarks.getByJwt(ref.trust_mark);
			return (
				record?.active === true &&
				record.trustMarkType === ref.trust_mark_type &&
				record.subject === mark.subject &&
				(record.expiresAt === undefined || record.expiresAt > now)
			);
		} catch (error) {
			ctx.options?.logger?.debug("Failed to read local trust mark status", { error });
			return false;
		}
	}

	const issuerStatement = statements.find(
		(statement) => statement.payload.iss === mark.issuer && statement.payload.sub === mark.issuer,
	);
	const issuerPayload = issuerStatement?.payload as Record<string, unknown> | undefined;
	const issuerJwks = issuerPayload?.jwks as JWKSet | undefined;
	const metadata = issuerPayload?.metadata as Record<string, unknown> | undefined;
	const federationMetadata = metadata?.federation_entity as Record<string, unknown> | undefined;
	const statusEndpoint = federationMetadata?.federation_trust_mark_status_endpoint;
	if (typeof statusEndpoint !== "string" || !issuerJwks) return false;

	try {
		const status = await fetchTrustMarkStatus(
			statusEndpoint,
			ref.trust_mark,
			issuerJwks,
			ctx.options,
		);
		return (
			status.ok &&
			status.value.status === TrustMarkStatus.Active &&
			status.value.issuer === mark.issuer
		);
	} catch (error) {
		ctx.options?.logger?.debug("Failed to verify remote trust mark status", { error });
		return false;
	}
}
