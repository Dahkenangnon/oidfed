import {
	authenticatedEndpointCaller,
	calculateChainExpiration,
	DEFAULT_CACHE_TTL_SECONDS,
	decodeEntityStatement,
	type EntityId,
	type FederationError,
	FederationErrorCode,
	type FederationOptions,
	fetchTrustMarkStatus,
	InternalErrorCode,
	isValidEntityId,
	type JWKSet,
	JwtTyp,
	MediaType,
	MemoryCache,
	nowSeconds,
	type ParsedEntityStatement,
	resolveTrustChains,
	safeLogger,
	signEntityStatement,
	type TrustAnchorSet,
	type TrustChain,
	type TrustMarkEvaluation,
	type TrustMarkEvidence,
	type TrustMarkIssuerContext,
	TrustMarkStatus,
	trustMarkIssuerContext,
	type ValidatedTrustChain,
	type ValidatedTrustMark,
	validateTrustChain,
	validateTrustMarkWithIssuer,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { errorResponse, jwtResponse, parseQueryParams, requireMethod } from "./helpers.js";
import { trustMarkService } from "./trust-mark-service.js";

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

const metadataFailures = new Set<string>([
	InternalErrorCode.MetadataPolicyError,
	InternalErrorCode.MetadataPolicyViolation,
	FederationErrorCode.InvalidMetadata,
]);

/** Classify discovery outcomes without exposing upstream diagnostics or statements. */
function discoveryFailure(errors: readonly FederationError[], incomplete: boolean): Response {
	if (
		incomplete ||
		errors.some((error) =>
			[
				InternalErrorCode.Network,
				InternalErrorCode.Timeout,
				FederationErrorCode.TemporarilyUnavailable,
				FederationErrorCode.ServerError,
			].some((code) => code === error.code),
		)
	)
		return errorResponse(
			503,
			FederationErrorCode.TemporarilyUnavailable,
			"Trust chain discovery could not be completed",
		);
	const failures = errors.filter(
		(error) =>
			![
				FederationErrorCode.NotFound,
				FederationErrorCode.InvalidSubject,
				FederationErrorCode.InvalidIssuer,
			].some((code) => code === error.code),
	);
	if (!failures.length)
		return errorResponse(404, FederationErrorCode.NotFound, "No trust chain found");
	if (failures.every((error) => metadataFailures.has(error.code)))
		return errorResponse(
			400,
			FederationErrorCode.InvalidMetadata,
			"Metadata or Metadata Policy could not be validated",
		);
	if (
		failures.every(
			(error) =>
				metadataFailures.has(error.code) ||
				[
					InternalErrorCode.TrustChainInvalid,
					InternalErrorCode.SignatureInvalid,
					InternalErrorCode.Expired,
					InternalErrorCode.LoopDetected,
					InternalErrorCode.ConstraintViolation,
					InternalErrorCode.UnsupportedAlg,
					InternalErrorCode.TrustAnchorUnknown,
					FederationErrorCode.InvalidTrustChain,
					FederationErrorCode.InvalidTrustAnchor,
				].some((code) => code === error.code),
		)
	)
		return errorResponse(
			400,
			FederationErrorCode.InvalidTrustChain,
			"Trust chain could not be validated",
		);
	return errorResponse(500, FederationErrorCode.ServerError, "Trust chain discovery failed");
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

		// Authentication evidence belongs to the verified Request instance.
		const rawEntity = authenticatedEndpointCaller(request);
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
				if (snapshot.reuseUntil <= nowSeconds(ctx.options?.clock))
					return errorResponse(
						404,
						FederationErrorCode.NotFound,
						"Cached resolution expired during signing",
					);
				return jwtResponse(jwt, MediaType.ResolveResponse);
			} catch {
				safeLogger(ctx.options?.logger)?.error("Failed to read cached resolution");
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

			// All candidate attempts and their evidence checks share one network budget.
			let remainingFetches = ctx.options?.maxTotalFetches ?? 50;
			let budgetExhausted = false;
			const transport = ctx.options?.httpClient ?? fetch;
			const signal = ctx.options?.signal
				? AbortSignal.any([request.signal, ctx.options.signal])
				: request.signal;
			const options: FederationOptions = {
				...ctx.options,
				signal,
				httpClient: async (input, init) => {
					if (signal.aborted) throw new DOMException("Operation aborted", "AbortError");
					if (remainingFetches <= 0) {
						budgetExhausted = true;
						throw new Error("Fetch budget exhausted");
					}
					remainingFetches--;
					return transport(input, init);
				},
			};
			const operationContext = { ...ctx, options };
			const result = await resolveTrustChains(sub as EntityId, requestedAnchors, options);
			if (!result.chains.length)
				return discoveryFailure(
					result.errors,
					Boolean(result.incomplete || budgetExhausted || signal.aborted),
				);

			let selected: { chain: TrustChain; validated: ValidatedTrustChain } | undefined;
			const failures: FederationError[] = [...result.errors];
			for (const candidate of result.chains) {
				if (signal.aborted || budgetExhausted) break;
				const validation = await validateTrustChain(candidate.statements, requestedAnchors, {
					...options,
					entityConfigurations: candidate.entityConfigurations,
					verboseErrors: true,
				});
				if (validation.valid) {
					selected = { chain: candidate, validated: validation.chain };
					break;
				}
				failures.push(
					...validation.errors.map((error) => ({ code: error.code, description: error.message })),
				);
			}
			if (signal.aborted || budgetExhausted || (!selected && result.incomplete))
				return discoveryFailure([], true);
			if (!selected) return discoveryFailure(failures, false);
			const { chain, validated } = selected;

			let resolvedMetadata = validated.resolvedMetadata as Record<string, unknown> | undefined;
			if (entityTypeParam.length > 0 && resolvedMetadata) {
				const filtered: Record<string, unknown> = {};
				for (const et of entityTypeParam) {
					if (Object.hasOwn(resolvedMetadata, et)) {
						Object.defineProperty(filtered, et, {
							value: resolvedMetadata[et],
							enumerable: true,
							configurable: true,
							writable: true,
						});
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
				operationContext,
				validated.statements,
				validated.trustMarkEvaluations,
				now,
			);

			// Exp is capped to the earliest expiry across the chain and trust marks
			let resolveExp = calculateChainExpiration(validated.statements);
			let evidenceDeadline = validated.expiresAt;
			for (const { mark } of activeTrustMarks) {
				evidenceDeadline = Math.min(
					evidenceDeadline,
					mark.verificationExpiresAt ?? Infinity,
					mark.delegation?.expiresAt ?? Infinity,
				);
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
						options,
					);
					const firstChain = issuerResult.chains[0];
					if (firstChain) {
						extraHeaders.trust_chain = [...firstChain.statements];
					}
				} catch {
					/* MAY feature — silently ignore issuer chain resolution failures */
				}
			}

			if (
				signal.aborted ||
				Math.min(resolveExp, evidenceDeadline) <= nowSeconds(ctx.options?.clock)
			)
				return errorResponse(
					503,
					FederationErrorCode.TemporarilyUnavailable,
					"Resolution evidence has expired or the operation was cancelled",
				);
			const jwt = await signEntityStatement(payload, keySet.signer, {
				typ: JwtTyp.ResolveResponse,
				extraHeaders,
			});

			if (
				signal.aborted ||
				Math.min(resolveExp, evidenceDeadline) <= nowSeconds(ctx.options?.clock)
			)
				return errorResponse(
					503,
					FederationErrorCode.TemporarilyUnavailable,
					"Resolution evidence expired during signing",
				);

			// §18.1 permits anonymous callers to reuse completed assessments. Cap reuse
			// by both the configured TTL and every included piece of expiring evidence.
			let cacheExpiry = Math.min(
				resolveExp,
				evidenceDeadline,
				now + (ctx.options?.cacheMaxTtlSeconds ?? DEFAULT_CACHE_TTL_SECONDS),
			);
			for (const { mark } of activeTrustMarks) {
				// Delegation validation is part of Trust Mark validity (§7.3).
				if (mark.verificationExpiresAt !== undefined)
					cacheExpiry = Math.min(cacheExpiry, mark.verificationExpiresAt);
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
				} catch {
					safeLogger(ctx.options?.logger)?.debug("Could not cache successful resolution");
				}
			}

			// Cache storage is asynchronous, even when it eventually rejects the write.
			if (
				signal.aborted ||
				Math.min(resolveExp, evidenceDeadline) <= nowSeconds(ctx.options?.clock)
			)
				return errorResponse(
					503,
					FederationErrorCode.TemporarilyUnavailable,
					"Resolution evidence expired or the operation was cancelled before delivery",
				);

			return jwtResponse(jwt, MediaType.ResolveResponse);
		} catch {
			safeLogger(ctx.options?.logger)?.error("Failed to resolve entity");
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

		const assessed = await activeTrustMarkForResolve(ctx, statements, ref, mark, now);
		if (assessed) active.push({ ref, mark: assessed });
	}
	return active;
}

async function activeTrustMarkForResolve(
	ctx: HandlerContext,
	statements: ReadonlyArray<ParsedEntityStatement>,
	ref: ResolveTrustMarkRef,
	mark: ValidatedTrustMark,
	now: number,
): Promise<ValidatedTrustMark | undefined> {
	try {
		// Resolve vouches for the selected anchor's policy, not a caller's unrelated accreditation.
		const root = statements.at(-1)?.payload;
		const issuers = root?.iss === root?.sub ? root?.trust_mark_issuers : undefined;
		if (!issuers || !Object.hasOwn(issuers, ref.trust_mark_type)) return undefined;
		const allowed = issuers[ref.trust_mark_type];
		if (
			!Array.isArray(allowed) ||
			(allowed.length && !allowed.some((issuer) => issuer === mark.issuer))
		)
			return undefined;
		let context: TrustMarkIssuerContext | undefined = mark.issuerEvidence;
		if (!context) {
			const issuer = statements.find(
				(statement) =>
					statement.payload.iss === mark.issuer && statement.payload.sub === mark.issuer,
			)?.payload;
			if (!issuer?.jwks) return undefined;
			context = {
				kind: "out-of-band",
				issuer: mark.issuer,
				allowedTrustMarkTypes: [ref.trust_mark_type],
				keys: issuer.jwks,
				...(issuer.metadata?.federation_entity
					? { metadata: issuer.metadata.federation_entity }
					: {}),
			};
		}
		const trusted = trustMarkIssuerContext(context, ref.trust_mark_type, ctx.options);
		if (!trusted.ok) return undefined;
		// The original context has already authenticated the issuer. Apply the resolver's anchor policy independently.
		const selected: TrustMarkIssuerContext = {
			kind: "out-of-band",
			issuer: trusted.value.issuer,
			keys: trusted.value.keys,
			allowedTrustMarkTypes: [ref.trust_mark_type],
			trustMarkOwners: root?.trust_mark_owners ?? {},
			...(trusted.value.metadata ? { metadata: trusted.value.metadata } : {}),
		};
		const history = ctx.options?.trustMarkVerification?.historicalKeys;
		const historyResponse = (mark as Partial<TrustMarkEvidence>).verificationKey?.responseJwt;
		const checked = await validateTrustMarkWithIssuer(ref.trust_mark, selected, {
			...ctx.options,
			expectedSubject: mark.subject,
			expectedTrustMarkType: ref.trust_mark_type,
			...(history
				? {
						historicalKeys: {
							...history,
							...(historyResponse
								? { mode: "supplied-only" as const, responses: [historyResponse] }
								: {}),
						},
					}
				: {}),
		});
		if (!checked.ok) return undefined;
		let statusDeadline = Infinity;
		if (mark.issuer === ctx.entityId && ctx.storage.trustMarks) {
			const assessment = await trustMarkService(ctx).assessTrustMarkStatus(ref.trust_mark);
			if (assessment?.payload.status !== TrustMarkStatus.Active) return undefined;
			statusDeadline = assessment.verificationExpiresAt ?? Infinity;
		} else {
			const status = await fetchTrustMarkStatus({
				...ctx.options,
				jwt: ref.trust_mark,
				issuerEvidence: context,
				expectedSubject: mark.subject,
				expectedTrustMarkType: ref.trust_mark_type,
			});
			if (!status.ok || status.value.status !== TrustMarkStatus.Active) return undefined;
			statusDeadline = status.value.verificationExpiresAt ?? Infinity;
		}
		const deadline = Math.min(
			mark.verificationExpiresAt ?? Infinity,
			checked.value.verificationExpiresAt ?? Infinity,
			trusted.value.expiresAt ?? Infinity,
			statusDeadline,
		);
		if (deadline <= Math.max(now, nowSeconds(ctx.options?.clock)) || ctx.options?.signal?.aborted)
			return undefined;
		return { ...mark, ...(Number.isFinite(deadline) ? { verificationExpiresAt: deadline } : {}) };
	} catch {
		safeLogger(ctx.options?.logger)?.debug("Failed to verify trust mark status for resolution");
		return undefined;
	}
}
