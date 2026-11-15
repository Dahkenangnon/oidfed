/** Leaf entity class: Entity Configuration serving with caching and trust chain discovery. */
import {
	type AttachTrustMarkOptions,
	assessEntity,
	buildEntityConfigurationPayload,
	composeEntityMetadata,
	createEndpointAuthenticatedHandler,
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	decodeEntityStatement,
	discoverEntityFromChain,
	discoverEntity as discoverEntityThroughTrustChain,
	type EntityAssessmentOptions,
	type EntityCollectionIntegration,
	EntityCollectionService,
	type EntityContext,
	type EntityId,
	type EntityRole,
	type EntityStatementExtensions,
	type EntityStatementMetadata,
	endpointParameterValuesMatch,
	entityId,
	errorResponse,
	type FederationKeyProvider,
	type FederationOptions,
	type FederationResolverIntegration,
	FederationResolverService,
	type FetchAndAttachTrustMarkOptions,
	isValidEntityId,
	JwtTyp,
	jwtResponse,
	MediaType,
	nowSeconds,
	prepareEntityStatementExtensions,
	RESOLVE_UNORDERED_PARAMETERS,
	type RemoveTrustMarkSelector,
	requireMethod,
	safeLogger,
	signEntityStatement,
	type TrustAnchorSet,
	TrustMarkHolder,
	type TrustMarkIssuanceOptions,
	type TrustMarkIssuerConfig,
	TrustMarkIssuerService,
	type TrustMarkRef,
	validateFederationKeySet,
	validateRoleMetadata,
	WELL_KNOWN_OPENID_FEDERATION,
} from "@oidfed/core";

export interface LeafConfig extends EntityStatementExtensions {
	resolver?: FederationResolverIntegration;
	trustMarkIssuer?: TrustMarkIssuerConfig;
	collection?: EntityCollectionIntegration;
	entityId: EntityId | string;
	authorityHints: readonly (EntityId | string)[];
	metadata: EntityStatementMetadata;
	keyProvider: FederationKeyProvider;
	roles?: EntityRole[];
	options?: FederationOptions;
	trustMarks?: TrustMarkRef[];
	trustAnchorHints?: readonly (EntityId | string)[];
	entityConfigurationTtlSeconds?: number;
	trustAnchors?: TrustAnchorSet;
}

function wellKnownPathForEntityId(value: EntityId): string {
	const base = value.endsWith("/") ? value.slice(0, -1) : value;
	return new URL(`${base}${WELL_KNOWN_OPENID_FEDERATION}`).pathname;
}

export class Leaf {
	readonly resolver?: FederationResolverService;
	static assessEntity = assessEntity;
	static discoverEntityFromChain = discoverEntityFromChain;
	assessEntity(
		target: EntityId,
		options: EntityAssessmentOptions & { trustAnchors?: TrustAnchorSet } = {},
	) {
		return assessEntity(target, options.trustAnchors ?? this.config.trustAnchors ?? new Map(), {
			...this.config.options,
			...options,
		});
	}
	discoverEntity(
		target: EntityId,
		options: FederationOptions & { trustAnchors?: TrustAnchorSet } = {},
	) {
		return discoverEntityThroughTrustChain(
			target,
			options.trustAnchors ?? this.config.trustAnchors ?? new Map(),
			{ ...this.config.options, ...options },
		);
	}
	discoverEntityFromChain(
		target: EntityId,
		statements: readonly string[],
		options: FederationOptions & { trustAnchors?: TrustAnchorSet } = {},
	) {
		return discoverEntityFromChain(
			target,
			statements,
			options.trustAnchors ?? this.config.trustAnchors ?? new Map(),
			{ ...this.config.options, ...options },
		);
	}
	readonly collection?: EntityCollectionService;
	private readonly issuerService?: TrustMarkIssuerService;
	private readonly holder: TrustMarkHolder;
	static discoverEntity(
		targetEntityId: EntityId | string,
		trustAnchors: TrustAnchorSet,
		options?: FederationOptions,
	) {
		return discoverEntityThroughTrustChain(entityId(targetEntityId), trustAnchors, options);
	}

	public readonly entityId: EntityId;
	private readonly routes = new Map<string, (request: Request) => Promise<Response>>();
	private readonly config: LeafConfig;
	private readonly metadata: Record<string, Record<string, unknown>>;
	private readonly roleContext: EntityContext;

	private cachedJwt: string | null = null;
	private cachedExp: number | null = null;
	private inflight: Promise<string> | null = null;
	private generation = 0;
	private collectionNoticeEmitted = false;

	constructor(config: LeafConfig) {
		const rawEntityId = (
			config.entityId.endsWith("/") ? config.entityId.slice(0, -1) : config.entityId
		) as EntityId;

		if (!isValidEntityId(rawEntityId)) {
			throw new Error("entityId MUST be a valid HTTPS URL without query or fragment");
		}
		this.entityId = rawEntityId;
		this.config = {
			...config,
			...prepareEntityStatementExtensions(config),
			authorityHints: [...config.authorityHints],
			...(config.trustMarks ? { trustMarks: structuredClone(config.trustMarks) } : {}),
		};
		this.holder = new TrustMarkHolder(this.entityId, config.trustMarks ?? [], async (refs) => {
			const jwt = await this.buildEntityConfiguration(this.generation, refs, false);
			const parsed = decodeEntityStatement(jwt);
			if (!parsed.ok) throw new Error("Unable to publish Entity Configuration");
			this.config.trustMarks = structuredClone([...refs]);
			this.generation++;
			this.cachedJwt = jwt;
			this.cachedExp = parsed.value.payload.exp;
			this.inflight = null;
		});

		if (!config.keyProvider) {
			throw new Error("keyProvider MUST be provided");
		}

		if (!config.authorityHints || config.authorityHints.length === 0) {
			throw new Error("authorityHints MUST NOT be empty for leaf entities");
		}
		for (const hint of config.authorityHints) {
			if (!isValidEntityId(hint)) {
				throw new Error(
					`authorityHint '${hint}' is not a valid Entity Identifier — MUST be HTTPS URL without query or fragment`,
				);
			}
		}
		if (config.trustAnchorHints !== undefined && config.trustAnchorHints.length === 0) {
			throw new Error("trustAnchorHints MUST NOT be empty when provided");
		}
		for (const hint of config.trustAnchorHints ?? []) {
			if (!isValidEntityId(hint)) {
				throw new Error(
					`trustAnchorHint '${hint}' is not a valid Entity Identifier — MUST be HTTPS URL without query or fragment`,
				);
			}
		}

		// Initialize roles & merge metadata/routes
		let metadata = composeEntityMetadata(config.metadata);
		const context: EntityContext = {
			entityId: this.entityId,
			keyProvider: config.keyProvider,
			options: config.options,
			...(config.trustAnchors ? { trustAnchors: config.trustAnchors } : {}),
			authorityHints: config.authorityHints as readonly EntityId[],
		};
		this.roleContext = context;

		if (config.roles) {
			for (const role of config.roles) {
				if (role.initialize) {
					role.initialize(context);
				}
				metadata = composeEntityMetadata(metadata, { [role.type]: role.metadata });
				if (role.routes) {
					for (const [path, handler] of role.routes.entries()) {
						const resolvedPath = path.startsWith("http") ? new URL(path).pathname : path;
						if (
							this.routes.has(resolvedPath) ||
							resolvedPath === wellKnownPathForEntityId(this.entityId)
						)
							throw new Error(`Role route '${resolvedPath}' conflicts with an existing route`);
						this.routes.set(resolvedPath, handler);
					}
				}
			}
		}
		validateRoleMetadata(config.roles, metadata, context);
		this.metadata = metadata;
		this.config.metadata = metadata;
		const collectionEndpoint = metadata.federation_entity?.federation_collection_endpoint;
		if (collectionEndpoint !== undefined && typeof collectionEndpoint !== "string")
			throw new Error("Collection endpoint must be an HTTPS URL");
		if (collectionEndpoint !== undefined && !config.collection)
			throw new Error("The collection endpoint requires collection configuration");
		if (config.collection) {
			const endpoint = typeof collectionEndpoint === "string" ? collectionEndpoint : undefined;
			const declaredMethods =
				metadata.federation_entity?.federation_collection_endpoint_auth_methods;
			const methods = Array.isArray(declaredMethods) ? declaredMethods : ["none"];
			if (
				config.collection.authentication &&
				JSON.stringify([...new Set(config.collection.authentication.methods)].sort()) !==
					JSON.stringify([...new Set(methods)].sort())
			)
				throw new Error(
					"Collection authentication methods must match federation_collection_endpoint_auth_methods (default: none)",
				);
			this.collection = new EntityCollectionService({
				...config.collection,
				responder: { entityId: this.entityId, isTrustAnchor: false },
				...(endpoint ? { endpoint } : {}),
				options: { ...config.options, ...config.collection.options },
				authentication: {
					...config.collection.authentication,
					methods: methods as ("none" | "private_key_jwt")[],
					receiverEntityId: this.entityId,
					...(Array.isArray(metadata.federation_entity?.endpoint_auth_signing_alg_values_supported)
						? {
								allowedAlgorithms: metadata.federation_entity
									.endpoint_auth_signing_alg_values_supported as string[],
							}
						: {}),
				},
			});
			if (endpoint) {
				const path = new URL(endpoint).pathname;
				const wellKnownPath = wellKnownPathForEntityId(this.entityId);
				if (this.routes.has(path) || path === wellKnownPath)
					throw new Error("Collection endpoint conflicts with an existing route");
				const collection = this.collection;
				this.routes.set(path, (request) => collection.handleRequest(request));
			}
		}

		const resolveEndpoint = metadata.federation_entity?.federation_resolve_endpoint;
		if (config.resolver) {
			const methods = metadata.federation_entity?.federation_resolve_endpoint_auth_methods ?? [
				"none",
			];
			if (!Array.isArray(methods) || !methods.every((method) => typeof method === "string"))
				throw new Error("Invalid resolver authentication methods");
			if (
				config.resolver.authentication &&
				JSON.stringify([...new Set(config.resolver.authentication.methods)].sort()) !==
					JSON.stringify([...new Set(methods)].sort())
			)
				throw new Error("Resolver authentication must match published metadata");
			const publishedAlgorithms =
				metadata.federation_entity?.endpoint_auth_signing_alg_values_supported;
			const configuredAlgorithms = config.resolver.authentication?.allowedAlgorithms;
			const allowedAlgorithms = Array.isArray(publishedAlgorithms)
				? (publishedAlgorithms as string[]).filter(
						(algorithm) => !configuredAlgorithms || configuredAlgorithms.includes(algorithm),
					)
				: configuredAlgorithms;
			if (methods.includes("private_key_jwt") && allowedAlgorithms?.length === 0)
				throw new Error("Endpoint authentication algorithms have no permitted intersection");
			this.resolver = new FederationResolverService({
				...config.resolver,
				entityId: this.entityId,
				keyProvider: config.keyProvider,
				...(config.trustAnchors ? { trustAnchors: config.trustAnchors } : {}),
				...(config.resolver.trustAnchors ? { trustAnchors: config.resolver.trustAnchors } : {}),
				options: { ...config.options, ...config.resolver.options },
				authentication: {
					...config.resolver.authentication,
					...(allowedAlgorithms ? { allowedAlgorithms } : {}),
					methods,
				},
			});
			if (resolveEndpoint !== undefined) {
				if (
					typeof resolveEndpoint !== "string" ||
					!isValidEntityId(resolveEndpoint.split("?")[0] ?? "")
				)
					throw new Error("Invalid Resolve endpoint URL");
				const path = new URL(resolveEndpoint).pathname;
				if (this.routes.has(path) || path === wellKnownPathForEntityId(this.entityId))
					throw new Error("Resolve endpoint conflicts with an existing route");
				const resolver = this.resolver;
				const advertised = new URL(resolveEndpoint);
				this.routes.set(path, (request) => {
					const incoming = new URL(request.url).searchParams;
					for (const name of new Set(advertised.searchParams.keys())) {
						if (
							!endpointParameterValuesMatch(
								name,
								advertised.searchParams.getAll(name),
								incoming.getAll(name),
								RESOLVE_UNORDERED_PARAMETERS,
							)
						)
							return Promise.resolve(errorResponse(404, "not_found", "Unknown endpoint"));
					}
					return resolver.handleRequest(request);
				});
			}
		}

		const markEndpoints = [
			["federation_trust_mark_status_endpoint", "status"],
			["federation_trust_mark_list_endpoint", "list"],
			["federation_trust_mark_endpoint", "retrieval"],
		] as const;
		if (config.trustMarkIssuer)
			this.issuerService = new TrustMarkIssuerService({
				...config.trustMarkIssuer,
				issuer: this.entityId,
				keyProvider: config.keyProvider,
				statusEndpointPublished:
					!!metadata.federation_entity?.federation_trust_mark_status_endpoint,
				...(config.options ? { options: config.options } : {}),
			});
		for (const [field, kind] of markEndpoints) {
			const endpoint = metadata.federation_entity?.[field];
			if (endpoint === undefined) continue;
			if (typeof endpoint !== "string" || !this.issuerService)
				throw new Error("Trust Mark endpoints require trustMarkIssuer configuration");
			const url = new URL(endpoint);
			if (url.protocol !== "https:" || url.hash || url.href.includes("#"))
				throw new Error("Trust Mark endpoint must use HTTPS without a fragment");
			const wellKnown = wellKnownPathForEntityId(this.entityId);
			if (this.routes.has(url.pathname) || url.pathname === wellKnown)
				throw new Error("Trust Mark endpoint conflicts with an existing route");
			const service = this.issuerService;
			const declared = metadata.federation_entity?.[`${field}_auth_methods`];
			if (
				declared !== undefined &&
				(!Array.isArray(declared) || !declared.every((value) => typeof value === "string"))
			)
				throw new Error("Invalid endpoint authentication methods");
			const advertisedAlgorithms =
				metadata.federation_entity?.endpoint_auth_signing_alg_values_supported;
			if (
				advertisedAlgorithms !== undefined &&
				(!Array.isArray(advertisedAlgorithms) ||
					!advertisedAlgorithms.every((value) => typeof value === "string"))
			)
				throw new Error("Invalid endpoint authentication algorithms");
			const configuredAlgorithms = config.trustMarkIssuer?.authentication?.allowedAlgorithms;
			const allowedAlgorithms =
				advertisedAlgorithms === undefined
					? configuredAlgorithms
					: (advertisedAlgorithms as string[]).filter(
							(algorithm) => !configuredAlgorithms || configuredAlgorithms.includes(algorithm),
						);
			if (declared?.includes("private_key_jwt") && allowedAlgorithms?.length === 0)
				throw new Error("Endpoint authentication algorithms have no permitted intersection");
			const authenticated = createEndpointAuthenticatedHandler(
				{
					...config.trustMarkIssuer?.authentication,
					...(allowedAlgorithms ? { allowedAlgorithms } : {}),
					receiverEntityId: this.entityId,
					methods: (declared as string[] | undefined) ?? ["none"],
				},
				(request) => service.handleRequest(kind, request),
				config.options,
				kind === "status" ? "POST" : "GET",
			);
			this.routes.set(url.pathname, (request) => {
				const incoming = new URL(request.url).searchParams;
				for (const name of new Set(url.searchParams.keys())) {
					const expected = url.searchParams.getAll(name),
						actual = incoming.getAll(name);
					if (!endpointParameterValuesMatch(name, expected, actual, []))
						return Promise.resolve(errorResponse(404, "not_found", "Unknown endpoint"));
				}
				return authenticated(request);
			});
		}

		if (Object.keys(this.metadata).length === 0) {
			throw new Error("metadata MUST contain at least one Entity Type Identifier");
		}

		const fedEntity = this.metadata.federation_entity;
		if (fedEntity) {
			for (const endpoint of [
				"federation_fetch_endpoint",
				"federation_list_endpoint",
				"federation_extended_list_endpoint",
			]) {
				if (`${endpoint}_auth_methods` in fedEntity)
					throw new Error(`Leaf entities cannot publish ${endpoint}_auth_methods`);
			}
			if ("federation_fetch_endpoint" in fedEntity) {
				throw new Error("Leaf entities MUST NOT publish federation_fetch_endpoint");
			}
			if ("federation_list_endpoint" in fedEntity) {
				throw new Error("Leaf entities MUST NOT publish federation_list_endpoint");
			}
			if (
				"federation_subordinate_events_endpoint" in fedEntity ||
				"federation_subordinate_events_endpoint_auth_methods" in fedEntity
			) {
				throw new Error("Leaf entities cannot publish federation_subordinate_events_endpoint");
			}
			if ("federation_extended_list_endpoint" in fedEntity) {
				throw new Error("Leaf entities MUST NOT publish federation_extended_list_endpoint");
			}
		}

		const ttlSeconds = config.entityConfigurationTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS;
		if (ttlSeconds <= 0) {
			throw new Error("entityConfigurationTtlSeconds must be positive");
		}
	}

	private async buildEntityConfiguration(
		generation: number,
		refs: readonly TrustMarkRef[] | undefined = this.config.trustMarks,
		publish = true,
	): Promise<string> {
		validateRoleMetadata(this.config.roles, this.metadata, this.roleContext);
		const keySet = await this.config.keyProvider.getFederationKeySet();
		validateFederationKeySet(keySet);
		const now = nowSeconds(this.config.options?.clock);
		const ttlSeconds =
			this.config.entityConfigurationTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS;
		const payload = buildEntityConfigurationPayload({
			additionalClaims: this.config.additionalClaims,
			crit: this.config.crit,
			entityId: this.entityId,
			jwks: keySet.jwks,
			metadata: this.metadata,
			authorityHints: this.config.authorityHints,
			...(this.config.trustAnchorHints ? { trustAnchorHints: this.config.trustAnchorHints } : {}),
			...(refs ? { trustMarks: refs } : {}),
			issuedAt: now,
			ttlSeconds,
		});

		const jwt = await signEntityStatement(payload, keySet.signer, {
			typ: JwtTyp.EntityStatement,
		});

		if (publish && generation === this.generation) {
			this.cachedJwt = jwt;
			this.cachedExp = payload.exp;
		}
		if (
			this.metadata.federation_entity?.federation_collection_endpoint &&
			!this.metadata.federation_entity.federation_resolve_endpoint &&
			!this.collectionNoticeEmitted
		) {
			this.collectionNoticeEmitted = true;
			safeLogger(this.config.options?.logger)?.info(
				"Federation Entities publishing a federation_collection_endpoint SHOULD also publish a federation_resolve_endpoint",
			);
		}
		safeLogger(this.config.options?.logger)?.info("Entity Configuration generated");
		return jwt;
	}

	async getEntityConfiguration(): Promise<string> {
		safeLogger(this.config.options?.logger)?.debug("Starting get entity configuration");

		if (this.cachedJwt && !this.isEntityConfigurationExpired()) {
			return this.cachedJwt;
		}
		if (this.inflight) return this.inflight;
		const generation = this.generation;
		this.inflight = this.buildEntityConfiguration(generation).finally(() => {
			if (generation === this.generation) this.inflight = null;
		});
		return this.inflight;
	}

	isEntityConfigurationExpired(): boolean {
		if (this.cachedExp === null) return true;
		const now = nowSeconds(this.config.options?.clock);
		return now >= this.cachedExp;
	}

	async refreshEntityConfiguration(): Promise<string> {
		safeLogger(this.config.options?.logger)?.debug("Starting refresh entity configuration");

		const generation = ++this.generation;
		this.cachedJwt = null;
		this.cachedExp = null;
		this.inflight = this.buildEntityConfiguration(generation).finally(() => {
			if (generation === this.generation) this.inflight = null;
		});
		return this.inflight;
	}

	getTrustMarks() {
		return this.holder.getTrustMarks();
	}
	async attachTrustMark(jwt: string, options: AttachTrustMarkOptions) {
		return this.holder.attachTrustMark(jwt, options);
	}
	async fetchAndAttachTrustMark(options: FetchAndAttachTrustMarkOptions) {
		return this.holder.fetchAndAttachTrustMark(options);
	}
	async removeTrustMark(selector: RemoveTrustMarkSelector) {
		return this.holder.removeTrustMark(selector);
	}

	private requireIssuer(): TrustMarkIssuerService {
		if (!this.issuerService) throw new Error("Trust Mark issuer is not configured");
		return this.issuerService;
	}
	async issueTrustMark(
		subject: string,
		type: string,
		options?: TrustMarkIssuanceOptions,
	): Promise<string> {
		return this.requireIssuer().issueTrustMark(subject, type, options);
	}
	async revokeTrustMark(type: string, subject: string): Promise<void> {
		return this.requireIssuer().revokeTrustMark(type, subject);
	}
	async listTrustMarksForSubject(subject: string) {
		return this.requireIssuer().listTrustMarksForSubject(subject);
	}
	async listTrustMarkedEntities(type: string, subject?: string) {
		return this.requireIssuer().listTrustMarkedEntities(type, subject);
	}
	async setTrustMarkDelegations(delegations: Readonly<Record<string, string>>): Promise<void> {
		return this.requireIssuer().setDelegations(delegations);
	}

	async handleRequest(request: Request): Promise<Response> {
		safeLogger(this.config.options?.logger)?.debug("Starting handle request");

		const url = new URL(request.url);
		const pathname = url.pathname;

		// 1. Check role-specific routes first
		const roleHandler = this.routes.get(pathname);
		if (roleHandler) {
			return roleHandler(request);
		}

		// Standard GET discovery (§9.1) is separate from the optional Collection authentication.
		const wellKnownPath = wellKnownPathForEntityId(this.entityId);
		if (pathname === wellKnownPath) {
			const methodError = requireMethod(request, "GET");
			if (methodError) return methodError;

			try {
				const jwt = await this.getEntityConfiguration();
				return jwtResponse(jwt, MediaType.EntityStatement);
			} catch {
				safeLogger(this.config.options?.logger)?.error("Failed to serve entity configuration");
				return errorResponse(500, "server_error", "An internal error occurred");
			}
		}

		return errorResponse(404, "not_found", "Unknown endpoint");
	}
}
