import {
	DEFAULT_CACHE_TTL_SECONDS,
	decodeEntityStatement,
	type EntityId,
	FederationErrorCode,
	fetchTrustMarkStatus,
	isValidEntityId,
	type JWKSet,
	JwtTyp,
	MediaType,
	MemoryCache,
	nowSeconds,
	type ParsedEntityStatement,
	resolveTrustChains,
	signEntityStatement,
	type TrustAnchorSet,
	type TrustMarkEvaluation,
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

/** A completed assessment with a fixed reuse deadline and no requester identity. */
interface ResolutionSnapshot {
	payload: Record<string, unknown>;
	headers: Record<string, unknown>;
	reuseUntil: number;
}

/** HTTP callers use the cache policy; local server calls may explicitly perform discovery. */
export function createResolveHandler(
	ctx: HandlerContext,
): (request: Request, local?: boolean) => Promise<Response> {
	const cache =
		ctx.storage.cache ??
		new MemoryCache({
			maxEntries: 1000,
			...(ctx.options?.clock ? { clock: ctx.options.clock } : {}),
		});
	// Instance isolation prevents reuse across different authority policies and restarts.
	const namespace = `resolve:${crypto.randomUUID()}:`;
	return async (request: Request, local = false) => {
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

		const nowForCache = nowSeconds(ctx.options?.clock);
		const cacheKey =
			namespace +
			JSON.stringify([
				ctx.entityId,
				sub,
				usableTrustAnchors.map((id) => [id, ctx.trustAnchors?.get(id)?.jwks]),
				entityTypeParam,
			]);
		if (!local && !isAuthenticated && ctx.requireAuthForFreshResolution !== false) {
			try {
				const cached = await cache.get<ResolutionSnapshot>(cacheKey);
				if (!cached || !Number.isFinite(cached.reuseUntil) || cached.reuseUntil <= nowForCache) {
					return errorResponse(
						404,
						FederationErrorCode.NotFound,
						"No cached resolution available; fresh resolution requires authentication",
					);
				}
				const snapshot = structuredClone(cached);
				// §8.3.2 binds aud to this request. Stored assessments never carry a recipient.
				delete snapshot.payload.aud;
				// The optional issuer chain may describe a previous signing key. Cache hits
				// omit it rather than performing discovery to refresh that header (§8.3.2).
				delete snapshot.headers.trust_chain;
				const keySet = await ctx.keyProvider.getFederationKeySet();
				// Cache and key-provider reads may be asynchronous; recheck the fixed deadline.
				const issuedAt = nowSeconds(ctx.options?.clock);
				if (snapshot.reuseUntil <= issuedAt)
					return errorResponse(404, FederationErrorCode.NotFound, "Cached resolution has expired");
				// §8.3.2 derives exp from the subject's chain and included Trust Marks.
				// The local reuse deadline controls cache access; preserve the assessed exp.
				const jwt = await signEntityStatement(
					{ ...snapshot.payload, iat: issuedAt },
					keySet.signer,
					{ typ: JwtTyp.ResolveResponse, extraHeaders: snapshot.headers },
				);
				return jwtResponse(jwt, MediaType.ResolveResponse);
			} catch (error) {
				ctx.options?.logger?.error("Failed to read cached resolution", { error });
				return errorResponse(
					500,
					FederationErrorCode.ServerError,
					"Failed to read cached resolution",
				);
			}
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
				validation.chain.trustMarkEvaluations,
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

			// §18.1 permits anonymous callers to reuse completed assessments. Cap reuse
			// by both the configured TTL and every included piece of expiring evidence.
			let cacheExpiry = Math.min(
				resolveExp,
				now + (ctx.options?.cacheMaxTtlSeconds ?? DEFAULT_CACHE_TTL_SECONDS),
			);
			for (const { mark } of activeTrustMarks) {
				// Delegation validation is part of Trust Mark validity (§7.3).
				if (mark.delegation?.expiresAt !== undefined)
					cacheExpiry = Math.min(cacheExpiry, mark.delegation.expiresAt);
			}
			if (Array.isArray(extraHeaders.trust_chain)) {
				for (const statement of extraHeaders.trust_chain) {
					const decoded = decodeEntityStatement(statement);
					if (decoded.ok && typeof decoded.value.payload.exp === "number")
						cacheExpiry = Math.min(cacheExpiry, decoded.value.payload.exp);
				}
			}
			if (Number.isFinite(cacheExpiry) && cacheExpiry > nowSeconds(ctx.options?.clock)) {
				const cachedPayload = { ...payload };
				delete cachedPayload.aud;
				try {
					await cache.set(
						cacheKey,
						structuredClone({
							payload: cachedPayload,
							headers: extraHeaders,
							reuseUntil: cacheExpiry,
						}),
						cacheExpiry - nowSeconds(ctx.options?.clock),
					);
				} catch (error) {
					ctx.options?.logger?.debug("Could not cache successful resolution", { error });
				}
			}

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
	evaluations: ReadonlyArray<TrustMarkEvaluation>,
	now: number,
): Promise<ActiveResolveTrustMark[]> {
	if (evaluations.length === 0) return [];
	const leafStatement = statements[0];
	const leafTrustMarks = leafStatement
		? ((leafStatement.payload as Record<string, unknown>).trust_marks as
				| ResolveTrustMarkRef[]
				| undefined)
		: undefined;
	if (!leafTrustMarks || leafTrustMarks.length === 0) return [];

	const active: ActiveResolveTrustMark[] = [];
	for (const evaluation of evaluations) {
		if (evaluation.status !== "verified") continue;
		const ref = leafTrustMarks[evaluation.referenceIndex];
		if (!ref || ref.trust_mark_type !== evaluation.trustMarkType) continue;
		const mark = evaluation.mark;

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
		const status = await fetchTrustMarkStatus(statusEndpoint, ref.trust_mark, issuerJwks, {
			...ctx.options,
			expectedIssuer: mark.issuer,
		});
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
