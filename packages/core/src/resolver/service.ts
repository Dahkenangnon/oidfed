/** Signed Resolve assessments, cache reuse, and authenticated HTTP hosting. */

import { runAsyncOperation } from "../async-operation.js";
import { isObject } from "../callbacks.js";
import {
	DEFAULT_CACHE_TTL_SECONDS,
	FederationErrorCode,
	InternalErrorCode,
	JwtTyp,
	MediaType,
} from "../constants.js";
import { bindFederationOptions, federationSigningOptions, registryFor } from "../crypto-context.js";
import { randomUuid } from "../crypto-runtime.js";
import {
	authenticatedEndpointCaller,
	createEndpointAuthenticatedHandler,
	type EndpointAuthenticationConfig,
	endpointCredentialParameterNames,
} from "../endpoint-authentication.js";
import { authorizeFederationEndpoint } from "../endpoint-authorization.js";
import {
	ENDPOINT_OPERATION_PARAMETERS,
	endpointParameterValuesMatch,
	RESOLVE_UNORDERED_PARAMETERS,
} from "../endpoint-parameters.js";
import type { FederationError } from "../errors.js";
import { federationEntry, isSignerPublished } from "../federation-keys.js";
import { errorResponse, jwtResponse, parseQueryParams, requireMethod } from "../http.js";
import { signEntityStatement } from "../jose/sign.js";
import { decodeEntityStatement } from "../jose/verify.js";
import { safeLogger } from "../logging.js";
import type { JWKSet } from "../schemas/jwk.js";
import { MemoryCache } from "../storage/cache.js";
import {
	type ResolveAssessmentCacheValue,
	ResolveAssessmentCacheValueSchema,
	readResolveAssessment,
} from "../storage/cache-records.js";
import { getCacheStorage } from "../storage/capabilities.js";
import { resolveTrustChainForAnchor } from "../trust-chain/peer.js";
import { resolveTrustChains } from "../trust-chain/resolve.js";
import { selectTrustChain } from "../trust-chain/selection.js";
import { calculateChainExpiration, validateTrustChain } from "../trust-chain/validate.js";
import type { TrustMarkStatusAssessment } from "../trust-marks/issuer.js";
import type { BoundFederationOptions, CryptoContext } from "../types.js";
import {
	type EntityId,
	entityId,
	type FederationOptions,
	isValidEntityId,
	nowSeconds,
	type TrustAnchorSet,
	type TrustChain,
	type ValidatedTrustChain,
} from "../types.js";
import {
	hasCurrentLocalTrustMarks,
	localTrustMarkRevision,
	localTrustMarkRevisionMatches,
	resolveAssessmentKey,
	snapshotResolverCache,
} from "./assessment-cache.js";
import { resolveActiveTrustMarks } from "./mark-disclosure.js";

export interface FederationResolverConfig {
	readonly entityId: EntityId | string;
	readonly crypto: CryptoContext;
	readonly trustAnchors?: TrustAnchorSet;
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
> & { readonly options?: BoundFederationOptions };
type ResolverContext = Omit<FederationResolverConfig, "entityId"> & { readonly entityId: EntityId };
type ResolveMode = "http" | "local" | "prime";

export interface PrimeAnonymousResolveInput {
	readonly subject: string;
	readonly trustAnchor: string | readonly string[];
	readonly entityTypes?: readonly string[];
	readonly signal?: AbortSignal;
}

/** Resolve hosting independent of subordinate storage and Authority endpoints. */
export class FederationResolverService {
	private readonly context: ResolverContext;
	private readonly inner: (request: Request, mode?: ResolveMode) => Promise<Response>;
	private readonly authenticated: (request: Request) => Promise<Response>;
	private readonly fixedQuery: URLSearchParams;
	/** Capture resolver dependencies and build the authenticated public endpoint handler. */
	constructor(config: FederationResolverConfig, fixedQuery?: URLSearchParams) {
		const id = entityId(config.entityId);
		const resolverCache = snapshotResolverCache(config.options.resolverCache);
		this.fixedQuery = new URLSearchParams(fixedQuery);
		this.context = {
			...config,
			entityId: id,
			options: resolverCache ? { ...config.options, resolverCache } : config.options,
		};
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
			{
				fixedQuery: this.fixedQuery,
				operationParameterNames: ENDPOINT_OPERATION_PARAMETERS.resolve,
				endpointName: "Resolve endpoint",
				endpoint: "resolve",
			},
		);
	}
	/**
	 * Serve the public Resolve endpoint with configured client authentication and discovery limits.
	 */
	handleRequest(request: Request): Promise<Response> {
		return this.authenticated(request);
	}
	/** In-process callers may populate the cache without endpoint authentication. */
	resolve(request: Request, options?: BoundFederationOptions): Promise<Response> {
		// Trusted per-call overrides bypass the HTTP policy and the serving assessment cache.
		return options
			? createResolveHandler(
					{
						...this.context,
						options: bindFederationOptions(
							{ crypto: this.context.crypto, storage: this.context.options.storage },
							this.context.options,
							options,
						),
					},
					true,
				)(request, "local")
			: this.inner(request, "local");
	}
	/**
	 * Evaluate a request as an anonymous caller would see it, then store that assessment.
	 *
	 * Anonymous HTTP requests never trigger discovery, so their answer must be prepared in
	 * advance. This caller is trusted, but its privileges only decide that the resolution runs:
	 * the assessment is evaluated under anonymous authorization and disclosure policy, so a
	 * privileged view can never reach the public cache partition.
	 *
	 * @throws Error when a fixed selector conflicts, anonymous authorization denies the request,
	 * the cache policy declines it, or the assessment cannot be stored.
	 */
	async primeAnonymousResolve(input: PrimeAnonymousResolveInput): Promise<void> {
		const url = new URL(this.context.entityId);
		url.searchParams.set("sub", input.subject);
		const anchors = typeof input.trustAnchor === "string" ? [input.trustAnchor] : input.trustAnchor;
		for (const anchor of anchors) url.searchParams.append("trust_anchor", anchor);
		for (const type of input.entityTypes ?? this.fixedQuery.getAll("entity_type"))
			url.searchParams.append("entity_type", type);
		for (const name of ENDPOINT_OPERATION_PARAMETERS.resolve) {
			if (
				this.fixedQuery.has(name) &&
				!endpointParameterValuesMatch(
					name,
					this.fixedQuery.getAll(name),
					url.searchParams.getAll(name),
					RESOLVE_UNORDERED_PARAMETERS,
				)
			)
				throw primeError(
					400,
					"invalid_request",
					"Request conflicts with the Resolve endpoint's fixed selectors",
				);
		}
		const reply = await this.inner(
			new Request(url, input.signal ? { signal: input.signal } : {}),
			"prime",
		);
		if (reply.status === 200) return;
		const details: unknown = await reply.json().catch(() => undefined);
		throw primeError(
			reply.status,
			isObject(details) && typeof details.error === "string" ? details.error : undefined,
			isObject(details) && typeof details.error_description === "string"
				? details.error_description
				: undefined,
		);
	}
	/** For hosts which have already applied the shared authentication wrapper. */
	handleAuthenticatedRequest(request: Request): Promise<Response> {
		return this.inner(request);
	}
}

/** Report the safe protocol details of an unsuccessful in-process prime. */
function primeError(status: number, code?: string, description?: string): Error {
	return new Error(
		`Could not prime anonymous Resolve (HTTP ${status}${code ? ` ${code}` : ""})${description ? `: ${description}` : ""}`,
	);
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

/** Re-sign a stored assessment for this request without refreshing evidence over the network. */
async function signCachedAssessment(
	ctx: ResolverContext,
	snapshot: ResolveAssessmentCacheValue,
	subject: EntityId,
	caller: string | undefined,
): Promise<Response | undefined> {
	const keySet = await federationEntry(ctx.crypto, {
		artifact: "resolve-response",
		issuer: ctx.entityId,
		subject,
	});
	const issuedAt = nowSeconds(ctx.options.clock);
	if (snapshot.reuseUntil <= issuedAt || ctx.options.signal?.aborted) return undefined;
	// Stored assessments omit aud. The responder chain can describe an earlier signing key.
	const jwt = await signEntityStatement(
		{
			...snapshot.payload,
			iat: issuedAt,
			...(caller === undefined ? {} : { aud: caller }),
		},
		keySet,
		{
			...federationSigningOptions(ctx.options, "resolve-response"),
			typ: JwtTyp.ResolveResponse,
		},
	);
	if (
		snapshot.localTrustMarkRevision !== undefined &&
		!(await localTrustMarkRevisionMatches(snapshot.localTrustMarkRevision, ctx.options))
	)
		return undefined;
	if (snapshot.reuseUntil <= nowSeconds(ctx.options.clock) || ctx.options.signal?.aborted)
		return undefined;
	return jwtResponse(jwt, MediaType.ResolveResponse);
}

/** Keep application metrics off the critical path and contain observer failures. */
function reportCacheResult(options: FederationOptions, result: "hit" | "miss"): void {
	const observe = options.onResolverCacheResult;
	if (!observe) return;
	const failed = () => safeLogger(options.logger)?.warn("Resolve cache observer failed");
	try {
		void Promise.resolve(observe(result)).catch(failed);
	} catch {
		failed();
	}
}

/** HTTP callers use the cache policy; trusted local callers can evaluate the public partition. */
function createResolveHandler(
	ctx: ResolverContext,
	isolated = false,
): (request: Request, mode?: ResolveMode) => Promise<Response> {
	const cache = isolated
		? undefined
		: (getCacheStorage(ctx.options.storage) ??
			new MemoryCache({
				maxEntries: 1000,
				...(ctx.options.clock ? { clock: ctx.options.clock } : {}),
			}));
	let namespace: Promise<string> | undefined;
	return async (request, mode = "http") => {
		const methodError = requireMethod(request, "GET");
		if (methodError) return methodError;

		const params = parseQueryParams(request);
		const sub = params.get("sub");
		const trustAnchorParam = params.getAll("trust_anchor");
		const entityTypeParam = params.getAll("entity_type");
		if (!sub || !isValidEntityId(sub))
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"Missing or invalid 'sub' parameter",
			);
		if (trustAnchorParam.length === 0)
			return errorResponse(
				400,
				FederationErrorCode.InvalidRequest,
				"Missing 'trust_anchor' parameter",
			);
		if (!ctx.trustAnchors)
			return errorResponse(
				404,
				FederationErrorCode.InvalidTrustAnchor,
				"No trust anchors configured",
			);
		const requestedAnchors = new Map<EntityId, Readonly<{ jwks: JWKSet }>>();
		for (const candidate of trustAnchorParam) {
			if (!isValidEntityId(candidate))
				return errorResponse(404, FederationErrorCode.InvalidTrustAnchor, "Unknown trust anchor");
			const approved = ctx.trustAnchors.get(candidate);
			if (approved) requestedAnchors.set(candidate, approved);
		}
		if (!requestedAnchors.size)
			return errorResponse(404, FederationErrorCode.InvalidTrustAnchor, "Unknown trust anchor");

		// Only identity from the authentication wrapper can enter a private partition.
		const rawEntity = mode === "http" ? authenticatedEndpointCaller(request) : undefined;
		const requiresCache =
			mode === "http" && rawEntity === undefined && ctx.requireAuthForFreshResolution !== false;
		const signal = ctx.options.signal
			? AbortSignal.any([request.signal, ctx.options.signal])
			: request.signal;
		const requestOptions = { ...ctx.options, signal };

		let canStore = cache !== undefined;
		if (mode !== "http" && canStore) {
			const publicParameters = new URLSearchParams(params);
			for (const name of endpointCredentialParameterNames(ctx.authentication?.extensions))
				publicParameters.delete(name);
			const denied = await authorizeFederationEndpoint(
				requestOptions,
				{
					endpoint: "resolve",
					receiverEntityId: ctx.entityId,
					caller: undefined,
				},
				publicParameters,
				signal,
			);
			if (denied && mode === "prime") return denied;
			canStore = denied === undefined;
		}
		let cacheKey: string | undefined;
		try {
			if (canStore && (rawEntity === undefined || ctx.options.resolverCache)) {
				namespace ??= ctx.options.resolverCache
					? Promise.resolve("")
					: randomUuid(ctx.crypto.engine);
				cacheKey = await resolveAssessmentKey(
					requestOptions,
					await namespace,
					ctx.entityId,
					rawEntity,
					sub,
					requestedAnchors,
					entityTypeParam,
				);
			}
			if (cache && cacheKey && mode === "http" && (requiresCache || ctx.options.resolverCache)) {
				const key = cacheKey;
				const cached = readResolveAssessment(
					await runAsyncOperation(() => cache.get<unknown>(key), requestOptions),
					ctx.entityId,
					sub,
					[...requestedAnchors.keys()],
					nowSeconds(ctx.options.clock),
					ctx.options.maxCompactBytes,
				);
				if (
					cached &&
					(await hasCurrentLocalTrustMarks(
						cached,
						requestOptions,
						ctx.assessLocalTrustMarkStatus !== undefined,
					))
				) {
					const reply = await signCachedAssessment(
						{ ...ctx, options: requestOptions },
						cached,
						sub,
						rawEntity,
					);
					if (reply) {
						reportCacheResult(ctx.options, "hit");
						return reply;
					}
				}
			}
		} catch {
			safeLogger(ctx.options.logger)?.error("Failed to reuse Resolve assessment");
			return errorResponse(
				500,
				FederationErrorCode.ServerError,
				"Failed to reuse Resolve assessment",
			);
		}

		if (mode === "http") reportCacheResult(ctx.options, "miss");

		if (mode === "prime" && !cacheKey)
			return errorResponse(
				404,
				FederationErrorCode.NotFound,
				"Resolve cache policy declined this request",
			);
		if (requiresCache)
			return errorResponse(404, FederationErrorCode.NotFound, "No eligible cached resolution");

		try {
			// All candidate attempts and their evidence checks share one network budget.
			let remainingFetches = ctx.options?.maxTotalFetches ?? 50;
			let budgetExhausted = false;
			const transport = ctx.options?.httpClient ?? fetch;
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
			const result = await resolveTrustChains(sub, requestedAnchors, options);
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

			const keySet = await federationEntry(ctx.crypto, {
				artifact: "resolve-response",
				issuer: ctx.entityId,
				subject: sub,
			});
			const now = nowSeconds(ctx.options?.clock);
			const assessLocally = ctx.assessLocalTrustMarkStatus;
			let revision: Promise<string | undefined> | undefined;
			const activeTrustMarks = await resolveActiveTrustMarks(
				assessLocally
					? {
							...operationContext,
							async assessLocalTrustMarkStatus(jwt) {
								// Begin the freshness check only when a verified local mark needs status.
								revision ??= localTrustMarkRevision(options);
								await revision;
								return assessLocally(jwt);
							},
						}
					: operationContext,
				validated,
				rawEntity,
				now,
			);
			if (budgetExhausted || signal.aborted) return discoveryFailure([], true);
			const hasLocalMarks = Boolean(
				assessLocally && activeTrustMarks.some(({ mark }) => mark.issuer === ctx.entityId),
			);
			const assessmentRevision = hasLocalMarks ? await revision : undefined;

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
					if (issuerResult.ok) {
						const configuration = issuerResult.value[0];
						const decoded = configuration
							? decodeEntityStatement(configuration, options)
							: undefined;
						// The validated responder chain may still publish a key from before rollover.
						if (
							decoded?.ok &&
							decoded.value.payload.jwks &&
							isSignerPublished(keySet, decoded.value.payload.jwks.keys, registryFor(ctx.crypto))
						)
							extraHeaders.trust_chain = [...issuerResult.value];
					}
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
				...federationSigningOptions(ctx.options, "resolve-response"),
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
			if (Array.isArray(extraHeaders.trust_chain)) {
				const statements: readonly unknown[] = extraHeaders.trust_chain;
				for (const statement of statements) {
					if (typeof statement !== "string") continue;
					const decoded = decodeEntityStatement(statement, ctx.options);
					if (decoded.ok && typeof decoded.value.payload.exp === "number")
						cacheExpiry = Math.min(cacheExpiry, decoded.value.payload.exp);
				}
			}
			let stored = false;
			if (
				cache &&
				cacheKey &&
				(!hasLocalMarks || assessmentRevision !== undefined) &&
				Number.isFinite(cacheExpiry) &&
				cacheExpiry > nowSeconds(ctx.options?.clock)
			) {
				if (
					assessmentRevision !== undefined &&
					!(await localTrustMarkRevisionMatches(assessmentRevision, options))
				)
					return errorResponse(
						503,
						FederationErrorCode.TemporarilyUnavailable,
						"Local Trust Mark evidence changed during resolution",
					);
				const cachedPayload = { ...payload };
				delete cachedPayload.aud;
				try {
					await cache.set(
						cacheKey,
						ResolveAssessmentCacheValueSchema.parse({
							trustAnchor: validated.trustAnchorId,
							payload: cachedPayload,
							// Retain the cache record shape. Re-signed replies omit the responder chain.
							headers: {},
							reuseUntil: cacheExpiry,
							...(assessmentRevision !== undefined
								? { localTrustMarkRevision: assessmentRevision }
								: {}),
						}),
						cacheExpiry - nowSeconds(ctx.options?.clock),
					);
					stored = true;
				} catch {
					safeLogger(ctx.options?.logger)?.debug("Could not cache successful resolution");
				}
			}

			// Cache storage is asynchronous, even when it eventually rejects the write.
			const markEvidenceChanged =
				assessmentRevision !== undefined &&
				!(await localTrustMarkRevisionMatches(assessmentRevision, options));
			if (
				markEvidenceChanged ||
				signal.aborted ||
				Math.min(resolveExp, evidenceDeadline) <= nowSeconds(ctx.options?.clock)
			)
				return errorResponse(
					503,
					FederationErrorCode.TemporarilyUnavailable,
					"Resolution evidence expired or the operation was cancelled before delivery",
				);

			if (mode === "prime" && !stored)
				return errorResponse(
					503,
					FederationErrorCode.TemporarilyUnavailable,
					"Could not store public resolution",
				);
			return jwtResponse(jwt, MediaType.ResolveResponse);
		} catch {
			safeLogger(ctx.options?.logger)?.error("Failed to resolve entity");
			return errorResponse(500, "server_error", "Failed to resolve entity");
		}
	};
}
