import { bindFederationOptions, federationSigningOptions } from "../crypto-context.js";
import { randomUuid } from "../crypto-runtime.js";
import { cloneData } from "../data-copy.js";
import { federationEntry } from "../federation-keys.js";
/** Signed Resolve assessments, cache reuse, and authenticated HTTP hosting. */

import { MemoryCache } from "../cache/index.js";
import {
	DEFAULT_CACHE_TTL_SECONDS,
	FederationErrorCode,
	InternalErrorCode,
	JwtTyp,
	MediaType,
	TrustMarkStatus,
} from "../constants.js";
import {
	authenticatedEndpointCaller,
	createEndpointAuthenticatedHandler,
	type EndpointAuthenticationConfig,
} from "../endpoint-authentication.js";
import { RESOLVE_UNORDERED_PARAMETERS } from "../endpoint-parameters.js";
import type { FederationError } from "../errors.js";
import { errorResponse, jwtResponse, parseQueryParams, requireMethod } from "../http.js";
import { signEntityStatement } from "../jose/sign.js";
import { decodeEntityStatement } from "../jose/verify.js";
import { safeLogger } from "../logging.js";
import type { JWKSet } from "../schemas/jwk.js";
import { resolveTrustChainForAnchor } from "../trust-chain/peer.js";
import { resolveTrustChains } from "../trust-chain/resolve.js";
import { selectTrustChain } from "../trust-chain/selection.js";
import { calculateChainExpiration, validateTrustChain } from "../trust-chain/validate.js";
import {
	type TrustMarkIssuerContext,
	trustMarkIssuerContext,
	validateTrustMarkWithIssuer,
} from "../trust-marks/evidence.js";
import { fetchTrustMarkStatus } from "../trust-marks/fetch.js";
import type { TrustMarkStatusAssessment } from "../trust-marks/issuer.js";
import type { CryptoContext } from "../types.js";
import {
	type CacheProvider,
	type EntityId,
	entityId,
	type FederationOptions,
	isValidEntityId,
	nowSeconds,
	type ParsedEntityStatement,
	type TrustAnchorSet,
	type TrustChain,
	type TrustMarkEvaluation,
	type TrustMarkEvidence,
	type ValidatedTrustChain,
	type ValidatedTrustMark,
} from "../types.js";

export interface FederationResolverConfig {
	readonly entityId: EntityId | string;
	readonly crypto: CryptoContext;
	readonly trustAnchors?: TrustAnchorSet;
	readonly cache?: CacheProvider;
	readonly options: FederationOptions;
	readonly requireAuthForFreshResolution?: boolean;
	readonly authentication?: Omit<EndpointAuthenticationConfig, "receiverEntityId">;
	readonly assessLocalTrustMarkStatus?: (
		jwt: string,
	) => Promise<TrustMarkStatusAssessment | undefined>;
}
export type FederationResolverIntegration = Omit<
	FederationResolverConfig,
	"entityId" | "crypto" | "options"
> & { readonly options?: Omit<FederationOptions, "engine"> };
type ResolverContext = Omit<FederationResolverConfig, "entityId"> & { readonly entityId: EntityId };

/** Resolve hosting independent of subordinate storage and Authority endpoints. */
export class FederationResolverService {
	private readonly context: ResolverContext;
	private readonly inner: (request: Request, local?: boolean) => Promise<Response>;
	private readonly authenticated: (request: Request) => Promise<Response>;
	/** Capture resolver dependencies and build the authenticated public endpoint handler. */
	constructor(config: FederationResolverConfig) {
		const id = entityId(config.entityId);
		this.context = { ...config, entityId: id };
		this.inner = createResolveHandler(this.context);
		this.authenticated = createEndpointAuthenticatedHandler(
			{
				...config.authentication,
				receiverEntityId: id,
				methods: config.authentication?.methods ?? ["none"],
			},
			(request) => this.inner(request),
			config.options,
			"GET",
			RESOLVE_UNORDERED_PARAMETERS,
		);
	}
	/**
	 * Serve the public Resolve endpoint with configured client authentication and discovery limits.
	 */
	handleRequest(request: Request): Promise<Response> {
		return this.authenticated(request);
	}
	/** In-process callers may populate the cache without endpoint authentication. */
	resolve(request: Request, options?: Omit<FederationOptions, "engine">): Promise<Response> {
		// Overrides get an isolated cache namespace, so a different policy cannot reuse prior assessments.
		return options
			? createResolveHandler({
					...this.context,
					options: bindFederationOptions(this.context.crypto, this.context.options, options),
				})(request, true)
			: this.inner(request, true);
	}
	/** For hosts which have already applied the shared authentication wrapper. */
	handleAuthenticatedRequest(request: Request): Promise<Response> {
		return this.inner(request);
	}
}

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
function createResolveHandler(
	ctx: ResolverContext,
): (request: Request, local?: boolean) => Promise<Response> {
	const cache =
		ctx.cache ??
		new MemoryCache({
			maxEntries: 1000,
			...(ctx.options?.clock ? { clock: ctx.options.clock } : {}),
		});
	// Instance isolation prevents reuse across different authority policies and restarts.
	let namespace: Promise<string> | undefined;
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
		namespace ??= randomUuid(ctx.crypto.engine);
		const cacheKey =
			(await namespace) +
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
				const snapshot = cloneData(cached);
				// §8.3.2 binds aud to this request. Stored assessments never carry a recipient.
				delete snapshot.payload.aud;
				// The optional issuer chain may describe a previous signing key. Cache hits
				// omit it rather than performing discovery to refresh that header (§8.3.2).
				delete snapshot.headers.trust_chain;
				const keySet = await federationEntry(ctx.crypto, { issuer: ctx.entityId, subject: sub });
				// Cache and key-provider reads may be asynchronous; recheck the fixed deadline.
				const issuedAt = nowSeconds(ctx.options?.clock);
				if (snapshot.reuseUntil <= issuedAt)
					return errorResponse(404, FederationErrorCode.NotFound, "Cached resolution has expired");
				// §8.3.2 derives exp from the subject's chain and included Trust Marks.
				// The local reuse deadline controls cache access; preserve the assessed exp.
				const jwt = await signEntityStatement({ ...snapshot.payload, iat: issuedAt }, keySet, {
					...federationSigningOptions(ctx.options),
					typ: JwtTyp.ResolveResponse,
					extraHeaders: snapshot.headers,
				});
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
				trustResolution: { kind: "bottom-up" },
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
			const eligible: { chain: TrustChain; validated: ValidatedTrustChain }[] = [];
			const failures: FederationError[] = [...result.errors];
			for (const candidate of result.chains) {
				if (signal.aborted || budgetExhausted) break;
				const validation = await validateTrustChain(candidate.statements, requestedAnchors, {
					...options,
					entityConfigurations: candidate.entityConfigurations,
					verboseErrors: true,
				});
				if (validation.valid) {
					if (
						entityTypeParam.length &&
						!entityTypeParam.some((type) => Object.hasOwn(validation.chain.resolvedMetadata, type))
					)
						continue;
					selected = { chain: candidate, validated: validation.chain };
					eligible.push(selected);
					if (!options.chainSelection) break;
					continue;
				}
				failures.push(
					...validation.errors.map((error) => ({ code: error.code, description: error.message })),
				);
			}
			if (
				signal.aborted ||
				budgetExhausted ||
				(result.incomplete && (!selected || options.chainSelection))
			)
				return discoveryFailure([], true);
			if (!selected) return discoveryFailure(failures, false);
			if (options.chainSelection) {
				const choice = selectTrustChain(
					eligible.map((candidate) => candidate.validated),
					options,
				);
				if (!choice.ok) return discoveryFailure([choice.error], false);
				selected = eligible.find((candidate) => candidate.validated === choice.value);
				if (!selected) return discoveryFailure([], false);
			}
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

			const keySet = await federationEntry(ctx.crypto, { issuer: ctx.entityId, subject: sub });
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
					const issuerResult = await resolveTrustChainForAnchor(
						ctx.entityId,
						validated.trustAnchorId,
						requestedAnchors,
						options,
					);
					if (issuerResult.ok) extraHeaders.trust_chain = [...issuerResult.value];
				} catch {
					/* Omit the optional trust_chain header when the responder's chain cannot be resolved. */
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
			const jwt = await signEntityStatement(payload, keySet, {
				...federationSigningOptions(ctx.options),
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
				const statements: readonly unknown[] = extraHeaders.trust_chain;
				for (const statement of statements) {
					if (typeof statement !== "string") continue;
					const decoded = decodeEntityStatement(statement, ctx.options);
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
						cloneData({
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
	ctx: ResolverContext,
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
	ctx: ResolverContext,
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
		if (mark.issuer === ctx.entityId && ctx.assessLocalTrustMarkStatus) {
			const assessment = await ctx.assessLocalTrustMarkStatus(ref.trust_mark);
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
