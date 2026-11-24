import {
	assertStorageCapabilities,
	type BoundFederationOptions,
	bindFederationOptions,
	cloneData,
	composeRolePublicationMetadata,
	describeStorageRequirements,
	type FederationStorage,
	federationEntry,
	federationSigningOptions,
	snapshotCryptoContext,
	validateCryptoContext,
} from "@oidfed/core";
/** Leaf host for Entity Configuration publication, role routes, and optional federation services. */

import {
	type AttachTrustMarkOptions,
	assertEndpointAuthenticationCompanions,
	assertPositiveTtlSeconds,
	assessEntity,
	buildEntityConfigurationPayload,
	type CryptoContext,
	composeEntityMetadata,
	createEndpointAuthenticatedHandler,
	createHistoricalKeysHandler,
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	decodeEntityStatement,
	discoverEntityFromChain,
	discoverEntity as discoverEntityThroughTrustChain,
	ENDPOINT_OPERATION_PARAMETERS,
	type EndpointAuthenticationConfig,
	type EntityAssessmentOptions,
	type EntityCollectionIntegration,
	EntityCollectionService,
	type EntityContext,
	type EntityId,
	type EntityRole,
	type EntityStatementExtensions,
	type EntityStatementMetadata,
	endpointCredentialParameterNames,
	endpointParameterValuesMatch,
	entityConfigurationUrl,
	errorResponse,
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
	signHistoricalKeysResponse,
	type TrustAnchorSet,
	TrustMarkHolder,
	type TrustMarkIssuanceOptions,
	type TrustMarkIssuerConfig,
	TrustMarkIssuerService,
	type TrustMarkRef,
	validateFederationKeySet,
	validateRoleMetadata,
} from "@oidfed/core";

/**
 * Construction configuration. Metadata is copied; services such as keyrings
 * and storage retain their identity. Roles contribute metadata after initialization,
 * overriding host parameters in role order. Re-create the host to change general
 * metadata; refreshing its EC re-reads keys, not the original metadata object.
 */
export interface LeafConfig extends EntityStatementExtensions {
	resolver?: FederationResolverIntegration;
	trustMarkIssuer?: Omit<TrustMarkIssuerConfig, "storage">;
	/** Caller key lookup or custom authentication for the managed Historical Keys endpoint. */
	historicalKeysAuthentication?: Omit<
		EndpointAuthenticationConfig,
		"receiverEntityId" | "methods" | "allowedAlgorithms"
	>;
	readonly storage?: FederationStorage;
	collection?: EntityCollectionIntegration;
	entityId: EntityId | string;
	authorityHints: readonly (EntityId | string)[];
	metadata: EntityStatementMetadata;
	/** Explicit host crypto operations and signing snapshots. */
	crypto: CryptoContext;
	roles?: EntityRole[];
	options?: BoundFederationOptions;
	trustMarks?: TrustMarkRef[];
	trustAnchorHints?: readonly (EntityId | string)[];
	/** Positive safe-integer EC lifetime in seconds; omission uses the core default. */
	entityConfigurationTtlSeconds?: number;
	trustAnchors?: TrustAnchorSet;
}

function wellKnownPathForEntityId(value: EntityId): string {
	return new URL(entityConfigurationUrl(value)).pathname;
}

const trustMarkEndpoints = [
	["federation_trust_mark_status_endpoint", "status"],
	["federation_trust_mark_list_endpoint", "list"],
	["federation_trust_mark_endpoint", "retrieval"],
] as const;

function validateLeafEndpointMetadata(
	metadata: Readonly<Record<string, unknown>> | undefined,
): void {
	if (!metadata) return;
	for (const endpoint of [
		"federation_fetch_endpoint",
		"federation_list_endpoint",
		"federation_extended_list_endpoint",
	]) {
		if (`${endpoint}_auth_methods` in metadata)
			throw new Error(`Leaf entities cannot publish ${endpoint}_auth_methods`);
		if (endpoint in metadata) throw new Error(`Leaf entities MUST NOT publish ${endpoint}`);
	}
	if (
		"federation_subordinate_events_endpoint" in metadata ||
		"federation_subordinate_events_endpoint_auth_methods" in metadata
	)
		throw new Error("Leaf entities cannot publish federation_subordinate_events_endpoint");
	assertEndpointAuthenticationCompanions(metadata);
}

function sameAdvertisedValues(expected: unknown, published: unknown): boolean {
	if (expected === undefined && published === undefined) return true;
	if (!Array.isArray(expected) || !Array.isArray(published)) return false;
	const supported = new Set(expected);
	const advertised = new Set(published);
	return (
		supported.size === advertised.size && [...advertised].every((value) => supported.has(value))
	);
}

export class Leaf {
	readonly resolver?: FederationResolverService;
	/** Initialize roles and validate mandatory signing purposes before returning a host. */
	static async create(config: LeafConfig): Promise<Leaf> {
		validateCryptoContext(config.crypto);
		const crypto = snapshotCryptoContext(config.crypto);
		if (config.storage) assertStorageCapabilities(config.storage, [], `Leaf ${config.entityId}`);
		const normalized = {
			...config,
			...prepareEntityStatementExtensions(config),
			crypto,
			metadata: composeEntityMetadata(config.metadata),
			authorityHints: [...config.authorityHints],
			...(config.roles ? { roles: [...config.roles] } : {}),
			...(config.trustMarks ? { trustMarks: cloneData(config.trustMarks) } : {}),
			options: bindFederationOptions({ crypto, storage: config.storage }, config.options),
		};
		const id = config.entityId;
		if (!isValidEntityId(id)) {
			throw new Error("entityId MUST be a valid HTTPS URL without query or fragment");
		}
		const context: EntityContext = Object.freeze({
			entityId: id,
			crypto: normalized.crypto,
			...(config.storage ? { storage: config.storage } : {}),
			options: normalized.options,
			...(config.trustAnchors ? { trustAnchors: config.trustAnchors } : {}),
			authorityHints: normalized.authorityHints as readonly EntityId[],
		});
		await federationEntry(normalized.crypto, { issuer: id, subject: id });
		for (const role of normalized.roles ?? []) await role.initialize?.(context);
		const host = new Leaf({ ...normalized, entityId: id }, context);
		await host.publicationMetadata();
		return host;
	}

	/** Per-call options override host options; explicit anchors override configured anchors. Returns an assessment Result, not protocol authorization. */
	assessEntity(
		target: EntityId,
		options: BoundFederationOptions<EntityAssessmentOptions> & {
			trustAnchors?: TrustAnchorSet;
		} = {},
	) {
		return assessEntity(
			target,
			options.trustAnchors ?? this.config.trustAnchors ?? new Map(),
			bindFederationOptions(this.config, this.config.options, options),
		);
	}
	/**
	 * Resolve, validate, and select a target chain using configured anchors and per-call overrides.
	 */
	discoverEntity(
		target: EntityId,
		options: BoundFederationOptions & { trustAnchors?: TrustAnchorSet } = {},
	) {
		return discoverEntityThroughTrustChain(
			target,
			options.trustAnchors ?? this.config.trustAnchors ?? new Map(),
			bindFederationOptions(this.config, this.config.options, options),
		);
	}
	/** Validate supplied target statements and return discovery evidence using configured anchors. */
	discoverEntityFromChain(
		target: EntityId,
		statements: readonly string[],
		options: BoundFederationOptions & { trustAnchors?: TrustAnchorSet } = {},
	) {
		return discoverEntityFromChain(
			target,
			statements,
			options.trustAnchors ?? this.config.trustAnchors ?? new Map(),
			bindFederationOptions(this.config, this.config.options, options),
		);
	}
	readonly collection?: EntityCollectionService;
	private readonly issuerService?: TrustMarkIssuerService;
	private readonly holder: TrustMarkHolder;

	public readonly entityId: EntityId;
	private readonly routes = new Map<string, (request: Request) => Promise<Response>>();
	private readonly config: Omit<LeafConfig, "options"> & { options: FederationOptions };
	private readonly metadata: Record<string, Record<string, unknown>>;
	private readonly roleContext: EntityContext;
	private readonly managesHistoricalKeys: boolean;

	private cachedJwt: string | null = null;
	private cachedExp: number | null = null;
	private inflight: Promise<string> | null = null;
	private generation = 0;
	private collectionNoticeEmitted = false;
	private readonly externalEndpointNotices = new Set<string>();

	/**
	 * Validate and compose Leaf metadata and routes; retain key and service dependencies for later
	 * operations.
	 */
	private constructor(
		config: Omit<LeafConfig, "options" | "entityId"> & {
			options: FederationOptions;
			entityId: EntityId;
		},
		context: EntityContext,
	) {
		this.entityId = config.entityId;
		this.config = {
			...config,
			...prepareEntityStatementExtensions(config),
			authorityHints: [...config.authorityHints],
			...(config.trustMarks ? { trustMarks: cloneData(config.trustMarks) } : {}),
		};
		this.holder = new TrustMarkHolder(this.entityId, config.trustMarks ?? [], async (refs) => {
			const jwt = await this.buildEntityConfiguration(this.generation, refs, false);
			const parsed = decodeEntityStatement(jwt, this.config.options);
			if (!parsed.ok) throw new Error("Unable to publish Entity Configuration");
			this.config.trustMarks = cloneData([...refs]);
			this.generation++;
			this.cachedJwt = jwt;
			this.cachedExp = parsed.value.payload.exp;
			this.inflight = null;
		});

		if (!config.crypto) {
			throw new Error("crypto MUST be provided");
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
		this.roleContext = context;

		if (config.roles) {
			for (const role of config.roles) {
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
		validateLeafEndpointMetadata(metadata.federation_entity);
		this.metadata = metadata;
		this.config.metadata = metadata;
		// Role routes are already registered. Reserve the built-in route before other services mount.
		this.managesHistoricalKeys = this.registerHistoricalKeysEndpoint();
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
				options: bindFederationOptions(config, config.options, config.collection.options),
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
			let resolveUrl: URL | undefined;
			if (resolveEndpoint !== undefined) {
				if (
					typeof resolveEndpoint !== "string" ||
					resolveEndpoint.includes("#") ||
					!isValidEntityId(resolveEndpoint.split("?")[0] ?? "")
				)
					throw new Error("Invalid Resolve endpoint URL");
				resolveUrl = new URL(resolveEndpoint);
			}
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
			this.resolver = new FederationResolverService(
				{
					...config.resolver,
					entityId: this.entityId,
					crypto: config.crypto,
					...(config.trustAnchors ? { trustAnchors: config.trustAnchors } : {}),
					...(config.resolver.trustAnchors ? { trustAnchors: config.resolver.trustAnchors } : {}),
					options: bindFederationOptions(config, config.options, config.resolver.options),
					authentication: {
						...config.resolver.authentication,
						...(allowedAlgorithms ? { allowedAlgorithms } : {}),
						methods,
					},
				},
				resolveUrl?.searchParams,
			);
			if (resolveUrl) {
				const resolver = this.resolver;
				this.registerSelectedEndpoint(
					resolveUrl,
					"Resolve",
					(request) => resolver.handleRequest(request),
					config.resolver.authentication?.extensions,
					RESOLVE_UNORDERED_PARAMETERS,
				);
			}
		}

		if (config.trustMarkIssuer) {
			const storage = config.storage;
			assertStorageCapabilities(
				storage,
				describeStorageRequirements(
					storage?.capabilities.includes("trustMark:write") ? "trustMarkWrite" : "trustMarkRead",
				),
				`Leaf ${this.entityId} Trust Mark issuer`,
			);
			this.issuerService = new TrustMarkIssuerService({
				...config.trustMarkIssuer,
				storage,
				issuer: this.entityId,
				crypto: config.crypto,
				statusEndpointPublished:
					!!metadata.federation_entity?.federation_trust_mark_status_endpoint,
				options: config.options,
			});
		}
		for (const [field, kind] of trustMarkEndpoints) {
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
				[],
				{
					fixedQuery: url.searchParams,
					operationParameterNames: [
						...(kind === "status"
							? ENDPOINT_OPERATION_PARAMETERS.trustMarkStatus
							: ENDPOINT_OPERATION_PARAMETERS.trustMark),
						...Object.keys(config.trustMarkIssuer?.trustMarkRequestExtensions ?? {}),
					],
				},
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

		const ttlSeconds = config.entityConfigurationTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS;
		assertPositiveTtlSeconds(ttlSeconds, "entityConfigurationTtlSeconds", "safe-integer");
	}

	private registerHistoricalKeysEndpoint(): boolean {
		const metadata = this.metadata.federation_entity;
		const endpoint = metadata?.federation_historical_keys_endpoint;
		const { crypto, historicalKeysAuthentication, options } = this.config;
		if (!metadata || endpoint === undefined || !crypto.history) {
			if (historicalKeysAuthentication)
				throw new TypeError(
					"Historical keys authentication requires a managed endpoint and crypto.history",
				);
			return false;
		}
		if (
			typeof endpoint !== "string" ||
			endpoint.includes("#") ||
			!isValidEntityId(endpoint.split("?")[0] ?? "")
		)
			throw new TypeError("Historical keys endpoint must use HTTPS without a fragment");
		const url = new URL(endpoint);
		if (this.routes.has(url.pathname)) {
			if (historicalKeysAuthentication)
				throw new TypeError("Historical keys authentication conflicts with a role-owned route");
			return false;
		}
		const methods = metadata.federation_historical_keys_endpoint_auth_methods;
		const algorithms = metadata.endpoint_auth_signing_alg_values_supported;
		if (
			methods !== undefined &&
			(!Array.isArray(methods) || !methods.every((method) => typeof method === "string"))
		)
			throw new TypeError("Invalid historical keys authentication methods");
		if (
			algorithms !== undefined &&
			(!Array.isArray(algorithms) ||
				!algorithms.every((algorithm) => typeof algorithm === "string"))
		)
			throw new TypeError("Invalid endpoint authentication algorithms");
		const handle = createEndpointAuthenticatedHandler(
			{
				...historicalKeysAuthentication,
				receiverEntityId: this.entityId,
				methods: methods ?? ["none"],
				...(algorithms ? { allowedAlgorithms: algorithms } : {}),
			},
			createHistoricalKeysHandler(this.roleContext),
			options,
			"GET",
			[],
			{ fixedQuery: url.searchParams },
		);
		this.registerSelectedEndpoint(
			url,
			"Historical keys",
			handle,
			historicalKeysAuthentication?.extensions,
		);
		return true;
	}

	private registerSelectedEndpoint(
		url: URL,
		label: string,
		handle: (request: Request) => Promise<Response>,
		extensions: EndpointAuthenticationConfig["extensions"],
		unordered: readonly string[] = [],
	): void {
		if (this.routes.has(url.pathname) || url.pathname === wellKnownPathForEntityId(this.entityId))
			throw new Error(`${label} endpoint conflicts with an existing route`);
		const selectors = [...new Set(url.searchParams.keys())];
		const credentialNames = endpointCredentialParameterNames(extensions);
		if (selectors.some((name) => credentialNames.has(name)))
			throw new TypeError(`${label} endpoint query must not contain credential parameters`);
		this.routes.set(url.pathname, (request) => {
			const incoming = new URL(request.url).searchParams;
			for (const name of selectors)
				if (
					!endpointParameterValuesMatch(
						name,
						url.searchParams.getAll(name),
						incoming.getAll(name),
						unordered,
					)
				)
					return Promise.resolve(errorResponse(404, "not_found", "Unknown endpoint"));
			return handle(request);
		});
	}

	private async publicationMetadata(): Promise<Record<string, Record<string, unknown>>> {
		const publication = await composeRolePublicationMetadata(
			this.config.roles,
			this.metadata,
			this.roleContext,
		);
		const published = publication.federation_entity;
		validateLeafEndpointMetadata(published);
		this.validateEndpointPublication(
			published,
			"federation_resolve_endpoint",
			"Resolve",
			!this.resolver,
		);
		this.validateEndpointPublication(
			published,
			"federation_historical_keys_endpoint",
			"Historical Keys",
			!this.managesHistoricalKeys,
		);
		this.validateEndpointPublication(published, "federation_collection_endpoint", "Collection");
		for (const [field] of trustMarkEndpoints)
			this.validateEndpointPublication(published, field, "Trust Mark");
		return publication;
	}

	private validateEndpointPublication(
		published: Readonly<Record<string, unknown>> | undefined,
		field: string,
		label: string,
		external = false,
	): void {
		const endpoint = published?.[field];
		if (!external) {
			const configured = this.metadata.federation_entity;
			if (endpoint !== configured?.[field])
				throw new TypeError(`Published ${label} URL must match the managed route`);
			if (
				endpoint !== undefined &&
				[`${field}_auth_methods`, "endpoint_auth_signing_alg_values_supported"].some(
					(name) => !sameAdvertisedValues(configured?.[name], published?.[name]),
				)
			)
				throw new TypeError(`Published ${label} authentication must match the managed route`);
			return;
		}
		if (
			!this.externalEndpointNotices.has(field) &&
			typeof endpoint === "string" &&
			URL.canParse(endpoint) &&
			!this.routes.has(new URL(endpoint).pathname)
		) {
			this.externalEndpointNotices.add(field);
			safeLogger(this.config.options.logger)?.warn(
				`Leaf advertises a ${label} endpoint without a local handler. Serve the advertised URL in the host application.`,
			);
		}
	}

	private async buildEntityConfiguration(
		generation: number,
		refs: readonly TrustMarkRef[] | undefined = this.config.trustMarks,
		publish = true,
	): Promise<string> {
		const publication = await this.publicationMetadata();
		const keySet = await federationEntry(this.config.crypto, {
			issuer: this.entityId,
			subject: this.entityId,
		});
		validateFederationKeySet(keySet, this.config.crypto.algorithmRegistry);
		const now = nowSeconds(this.config.options?.clock);
		const ttlSeconds =
			this.config.entityConfigurationTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS;
		const payload = buildEntityConfigurationPayload({
			algorithmRegistry: this.config.options.algorithmRegistry,
			additionalClaims: this.config.additionalClaims,
			crit: this.config.crit,
			entityId: this.entityId,
			jwks: keySet.publishedJwks,
			metadata: publication,
			authorityHints: this.config.authorityHints,
			...(this.config.trustAnchorHints ? { trustAnchorHints: this.config.trustAnchorHints } : {}),
			...(refs ? { trustMarks: refs } : {}),
			issuedAt: now,
			ttlSeconds,
		});

		const jwt = await signEntityStatement(payload, keySet, {
			...federationSigningOptions(this.config.options),
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

	/**
	 * Reuse an unexpired cached Entity Configuration or share an in-flight generation with other
	 * callers.
	 */
	async getEntityConfiguration(): Promise<string> {
		safeLogger(this.config.options?.logger)?.debug("Starting get entity configuration");

		if (this.cachedJwt && !this.isEntityConfigurationExpired()) {
			return this.cachedJwt;
		}
		if (this.inflight !== null) return this.inflight;
		const generation = this.generation;
		this.inflight = this.buildEntityConfiguration(generation).finally(() => {
			if (generation === this.generation) this.inflight = null;
		});
		return this.inflight;
	}

	/** Report whether no cached Entity Configuration exists or its expiry has been reached. */
	isEntityConfigurationExpired(): boolean {
		if (this.cachedExp === null) return true;
		const now = nowSeconds(this.config.options?.clock);
		return now >= this.cachedExp;
	}

	/**
	 * Force a new generation with the current keys, superseding prior cache writes without cancelling
	 * their callers.
	 */
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

	/** Return a detached copy of this host's published Trust Mark references. */
	getTrustMarks() {
		return this.holder.getTrustMarks();
	}
	/**
	 * Validate a mark for this host and publish it; failed validation leaves prior references intact.
	 */
	async attachTrustMark(jwt: string, options: BoundFederationOptions<AttachTrustMarkOptions>) {
		return this.holder.attachTrustMark(jwt, {
			...options,
			...bindFederationOptions(this.config, this.config.options, options),
		});
	}
	/** Establish issuer trust and retrieve a mark for this host before validated publication. */
	async fetchAndAttachTrustMark(
		options: Omit<FetchAndAttachTrustMarkOptions, "options"> & {
			readonly options?: BoundFederationOptions;
		},
	) {
		return this.holder.fetchAndAttachTrustMark({
			...options,
			options: bindFederationOptions(this.config, this.config.options, options.options),
		});
	}
	/** Remove matching references from this host's publication; this does not revoke issuance. */
	async removeTrustMark(selector: RemoveTrustMarkSelector) {
		return this.holder.removeTrustMark(selector, this.config.options);
	}

	private requireIssuer(): TrustMarkIssuerService {
		if (!this.issuerService) throw new Error("Trust Mark issuer is not configured");
		return this.issuerService;
	}
	/**
	 * Issue or reuse a managed Trust Mark for a subject under the configured issuer policy. Requires
	 * trustMarkIssuer configuration.
	 */
	async issueTrustMark(
		subject: string,
		type: string,
		options?: TrustMarkIssuanceOptions,
	): Promise<string> {
		return this.requireIssuer().issueTrustMark(subject, type, options);
	}
	/**
	 * Revoke this issuer's matching local records for the type and subject. Requires trustMarkIssuer
	 * configuration.
	 */
	async revokeTrustMark(type: string, subject: string): Promise<void> {
		return this.requireIssuer().revokeTrustMark(type, subject);
	}
	/**
	 * Return detached, eligible local issuance records for the subject. Requires trustMarkIssuer
	 * configuration.
	 */
	async listTrustMarksForSubject(subject: string) {
		return this.requireIssuer().listTrustMarksForSubject(subject);
	}
	/** List eligible local subjects for a Trust Mark type. Requires trustMarkIssuer configuration. */
	async listTrustMarkedEntities(type: string, subject?: string) {
		return this.requireIssuer().listTrustMarkedEntities(type, subject);
	}
	/**
	 * Replace owner-delegation JWTs used by this host's managed issuer service. Requires
	 * trustMarkIssuer configuration.
	 */
	async setTrustMarkDelegations(delegations: Readonly<Record<string, string>>): Promise<void> {
		return this.requireIssuer().setDelegations(delegations);
	}

	/** Sign this Leaf's historical public keys. Requires a configured history source. */
	async getHistoricalKeys(): Promise<string> {
		return signHistoricalKeysResponse(this.roleContext);
	}

	/** Serve role and optional service routes, or the GET Entity Configuration discovery endpoint. */
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
