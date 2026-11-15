/** Federation Authority server: wires endpoint handlers, key management, and subordinate storage into an HTTP server. */
import type {
	AttachTrustMarkOptions,
	EndpointAuthentication,
	EntityCollectionIntegration,
	EntityContext,
	EntityId,
	EntityRole,
	EntityStatementExtensions,
	EntityType,
	EntityTypeMetadataMap,
	ExtendedListRequestParams,
	FederationEntityMetadata,
	FederationError,
	FederationKeyLifecycleProvider,
	FederationOptions,
	FetchAndAttachTrustMarkOptions,
	RemoveTrustMarkSelector,
	Result,
	SubordinateEvent,
	TrustAnchorSet,
	TrustMarkDelegationIssuanceOptions,
	TrustMarkIssuanceOptions,
	TrustMarkIssuerConfig,
	TrustMarkOwner,
	TrustMarkRecord,
	TrustMarkRef,
	TrustMarkStatusResponsePayload,
} from "@oidfed/core";
import {
	assertPositiveTtlSeconds,
	assessEntity,
	buildExtendedListRequestParameters,
	COLLECTION_UNORDERED_PARAMETERS,
	composeEntityMetadata,
	decodeEntityStatement,
	discoverEntity,
	discoverEntityFromChain,
	type EntityAssessmentOptions,
	EntityCollectionService,
	EXTENDED_LIST_UNORDERED_PARAMETERS,
	endpointParameterValuesMatch,
	err,
	FederationEndpoint,
	FederationErrorCode,
	federationError,
	isOk,
	isValidEntityId,
	LIST_UNORDERED_PARAMETERS,
	ok,
	prepareEndpointParameters,
	prepareEntityStatementExtensions,
	RESOLVE_UNORDERED_PARAMETERS,
	safeLogger,
	signTrustMarkDelegation,
	TrustMarkHolder,
	validateRoleMetadata,
	WELL_KNOWN_OPENID_FEDERATION,
} from "@oidfed/core";
import { createAuthenticatedHandler } from "./endpoints/client-auth.js";
import type { AuthorityClientKeyProvider, HandlerContext } from "./endpoints/context.js";
import {
	buildEntityConfiguration,
	createEntityConfigurationHandler,
} from "./endpoints/entity-configuration.js";
import {
	createExtendedListHandler,
	type ExtendedListingConfig,
} from "./endpoints/extended-list.js";
import { buildSubordinateStatement, createFetchHandler } from "./endpoints/fetch.js";
import { SECURITY_HEADERS } from "./endpoints/helpers.js";
import { buildHistoricalKeys, createHistoricalKeysHandler } from "./endpoints/historical-keys.js";
import { createListHandler } from "./endpoints/list.js";
import { createResolveHandler } from "./endpoints/resolve.js";
import {
	buildSubordinateEvents,
	createSubordinateEventsHandler,
	withSubordinateEventsMethodErrors,
} from "./endpoints/subordinate-events.js";
import { createTrustMarkHandler } from "./endpoints/trust-mark.js";
import { createTrustMarkListHandler } from "./endpoints/trust-mark-list.js";
import { trustMarkService, updateTrustMarkServicePolicy } from "./endpoints/trust-mark-service.js";
import { createTrustMarkStatusHandler } from "./endpoints/trust-mark-status.js";
import { InvalidAuthorityConfig } from "./errors.js";
import type {
	ListFilter,
	StorageAdapter,
	SubordinateEventAnnotations,
	SubordinateRecord,
	SubordinateRecordUpdate,
} from "./storage/types.js";
import { createSubordinateLifecycle } from "./subordinate-lifecycle.js";
import {
	assertMetadataValuesNotNull,
	sanitizeSubordinateMetadata,
} from "./utils/subordinate-statement-shape.js";

export type { AuthorityClientKeyProvider } from "./endpoints/context.js";

/** Parameters accepted by {@link AuthorityServer.listSubordinatesExtended}. */
export type ExtendedSubordinateListingParams = ExtendedListRequestParams;

/** In-process extension selectors and cancellation; no HTTP authentication is performed. */
export type ExtendedSubordinateListingOptions = Pick<
	FederationOptions,
	"additionalParameters" | "signal"
>;

/** Decoded body returned by {@link AuthorityServer.listSubordinatesExtended}. */
export interface ExtendedSubordinateListingResult {
	immediate_subordinate_entities: Array<Record<string, unknown> & { id: string }>;
	next?: string;
}

function assertTrustAnchorHintsConfig(config: AuthorityConfig, isTrustAnchor: boolean): void {
	if (config.trustAnchorHints !== undefined && config.trustAnchorHints.length === 0) {
		throw new InvalidAuthorityConfig("trustAnchorHints must be a non-empty array when provided.");
	}
	for (const hint of config.trustAnchorHints ?? []) {
		if (!isValidEntityId(hint)) {
			throw new InvalidAuthorityConfig(
				`trustAnchorHint '${hint}' is not a valid Entity Identifier; it must be an HTTPS URL without query or fragment.`,
			);
		}
	}
	if (isTrustAnchor && !config.authorityHints?.length && config.trustAnchorHints !== undefined) {
		throw new InvalidAuthorityConfig(
			"Trust Anchors without Superiors MUST NOT publish trust_anchor_hints.",
		);
	}
}

export interface AuthorityConfig extends EntityStatementExtensions {
	trustMarkDefaults?: TrustMarkIssuerConfig["trustMarkDefaults"];
	trustMarkSigner?: TrustMarkIssuerConfig["trustMarkSigner"];
	trustMarkStatusPolicy?: TrustMarkIssuerConfig["trustMarkStatusPolicy"];
	trustMarkRequestExtensions?: TrustMarkIssuerConfig["trustMarkRequestExtensions"];
	endpointAuthentication?: EndpointAuthentication;
	trustMarkIssuer?: Omit<TrustMarkIssuerConfig, "storage">;
	/**
	 * Require authentication for fresh HTTP Resolve discovery (default: true).
	 * Anonymous requests use cached assessments, per Federation §18.1.
	 * Local resolveEntity() calls can discover and warm the cache.
	 */
	requireAuthForFreshResolution?: boolean;
	/** Optional shared collection service; snapshots are independent of registrations. */
	collection?: EntityCollectionIntegration;
	/** The entity identifier (URL) for this authority. */
	entityId: EntityId | string;
	/** Copied at construction; must include federation_entity. Initialized roles override parameters in role order. Re-create the host to change general metadata. */
	metadata: { federation_entity: FederationEntityMetadata } & Partial<{
		[K in EntityType]: EntityTypeMetadataMap[K];
	}>;
	/** Unified persistence adapter for all non-key authority state. */
	storage: StorageAdapter;
	/** Federation-only signing key provider and lifecycle manager. */
	keyProvider: FederationKeyLifecycleProvider;
	/**
	 * Resolves public Federation Entity Keys for authenticated remote authority
	 * endpoint clients. Defaults to `storage.subordinates.get(entityId)?.jwks`.
	 */
	clientKeyProvider?: AuthorityClientKeyProvider;
	/** Roles (like OIDC OP, RP etc.) bound to this authority. */
	roles?: EntityRole[];
	/** Trust marks this authority claims about itself. */
	trustMarks?: TrustMarkRef[];
	/** Mapping of trust mark type → authorized issuer entity IDs. */
	trustMarkIssuers?: Record<string, string[]>;
	/** Mapping of trust mark type → owner declaration (for delegated trust marks). */
	trustMarkOwners?: Record<string, TrustMarkOwner>;
	/** Pre-signed trust mark delegation JWTs, keyed by trust mark type. */
	trustMarkDelegations?: Record<string, string>;
	/** Superior authorities this entity is subordinate to. */
	authorityHints?: readonly (EntityId | string)[];
	/** Preferred trust anchors this entity hints to resolvers in its Entity Configuration. */
	trustAnchorHints?: readonly (EntityId | string)[];
	/** Trust anchors used for trust chain resolution (e.g., during registration). */
	trustAnchors?: TrustAnchorSet;
	/** Positive safe-integer TTL in seconds for the Entity Configuration JWT. */
	entityConfigurationTtlSeconds?: number;
	/** Positive safe-integer TTL in seconds for subordinate statement JWTs. */
	subordinateStatementTtlSeconds?: number;
	/** Optional positive, finite history-response TTL; omission leaves exp absent. */
	subordinateEventsTtlSeconds?: number;
	/** Positive finite TTL in seconds for issued Trust Marks; fractional values are allowed. */
	trustMarkTtlSeconds?: number;
	/** Federation-wide options (httpClient, clock, etc.). */
	options?: Omit<FederationOptions, "cache">;
	/**
	 * Configuration for the Extended Subordinate Listing endpoint. Set
	 * `enabled: false` to keep the endpoint disabled (router returns 404) and
	 * omit `federation_extended_list_endpoint` from your metadata. Defaults
	 * enable the endpoint with `maxPageSize=500`, `defaultPageSize=100`,
	 * time-filters and audit timestamps supported.
	 */
	extendedListing?: ExtendedListingConfig;
}

export interface AuthorityServer {
	readonly collection?: EntityCollectionService;
	registerSubordinate(
		record: Omit<SubordinateRecord, "createdAt" | "updatedAt">,
		annotations?: SubordinateEventAnnotations,
	): Promise<void>;
	updateSubordinate(
		subject: EntityId,
		updates: SubordinateRecordUpdate,
		annotations?: SubordinateEventAnnotations,
	): Promise<void>;
	revokeSubordinate(subject: EntityId, annotations?: SubordinateEventAnnotations): Promise<void>;
	recordSubordinateEvents(subject: EntityId, events: readonly SubordinateEvent[]): Promise<void>;
	getSubordinateEvents(subject: EntityId): Promise<string>;

	getEntityConfiguration(): Promise<string>;
	getSubordinateStatement(sub: EntityId): Promise<string>;
	listSubordinates(filter?: ListFilter): Promise<EntityId[]>;
	/**
	 * Direct access to the Extended Subordinate Listing response (skipping HTTP).
	 * Mirrors the wire-level handler — used for in-process pagination,
	 * server-side rendering, and tests.
	 */
	listSubordinatesExtended(
		params?: ExtendedSubordinateListingParams,
		options?: ExtendedSubordinateListingOptions,
	): Promise<Result<ExtendedSubordinateListingResult, FederationError>>;
	resolveEntity(sub: EntityId, ta?: EntityId, options?: FederationOptions): Promise<string>;
	getTrustMarkStatus(trustMark: string): Promise<TrustMarkStatusResponsePayload>;
	listTrustMarkedEntities(trustMarkType: string): Promise<string[]>;
	revokeTrustMark(type: string, subject: string): Promise<void>;
	listTrustMarksForSubject(subject: string): Promise<TrustMarkRecord[]>;
	getTrustMarks(): TrustMarkRef[];
	attachTrustMark(jwt: string, options: AttachTrustMarkOptions): Promise<void>;
	fetchAndAttachTrustMark(options: FetchAndAttachTrustMarkOptions): Promise<void>;
	removeTrustMark(selector: RemoveTrustMarkSelector): Promise<void>;
	setTrustMarkIssuers(issuers: Record<string, string[]>): Promise<void>;
	setTrustMarkOwners(owners: Record<string, TrustMarkOwner>): Promise<void>;
	setTrustMarkDelegations(delegations: Record<string, string>): Promise<void>;
	issueTrustMark(
		sub: string,
		trustMarkType: string,
		options?: TrustMarkIssuanceOptions,
	): Promise<string>;
	issueTrustMarkDelegation(
		subject: string,
		trustMarkType: string,
		options?: TrustMarkDelegationIssuanceOptions,
	): Promise<string>;
	getHistoricalKeys(): Promise<string>;
	handler(): (request: Request) => Promise<Response>;
}

/** Creates a federation authority server with all spec-defined endpoints. */
export function createAuthorityServer(config: AuthorityConfig): AuthorityServer {
	return createAuthorityServerWithIdentity({
		...config,
		entityId: normalizeAuthorityEntityId(config.entityId),
		metadata: composeEntityMetadata(config.metadata) as AuthorityConfig["metadata"],
	});
}

/** Build around the established published identity without normalizing it again. */
function createAuthorityServerWithIdentity(
	config: AuthorityConfig & { entityId: EntityId },
	roleRoutes: ReadonlyMap<string, (request: Request) => Promise<Response>> = new Map(),
	isTrustAnchor = !config.authorityHints?.length,
): AuthorityServer {
	const normalizedEntityId = config.entityId;

	const ttlFields = [
		["entityConfigurationTtlSeconds", config.entityConfigurationTtlSeconds, "safe-integer"],
		["subordinateStatementTtlSeconds", config.subordinateStatementTtlSeconds, "safe-integer"],
		["trustMarkTtlSeconds", config.trustMarkTtlSeconds, "finite"],
		["subordinateEventsTtlSeconds", config.subordinateEventsTtlSeconds, "finite"],
	] as const;
	for (const [name, value, mode] of ttlFields) {
		if (value !== undefined) assertPositiveTtlSeconds(value, name, mode);
	}

	// Superior hints describe topology independently of the authority role.
	// Entities without Superiors omit the claim; an explicit empty array is invalid.
	if (config.authorityHints !== undefined && config.authorityHints.length === 0) {
		throw new InvalidAuthorityConfig(
			"authorityHints must be omitted without Superiors or contain a non-empty array of superior Entity Identifiers; an empty array is not allowed.",
		);
	}

	assertTrustAnchorHintsConfig(config, isTrustAnchor);

	// trust_mark_issuers / trust_mark_owners only have effect on a Trust Anchor's
	// Entity Configuration. Refuse to construct an Intermediate that carries
	// these — readers ignore them, and silently emitting ignored claims is a footgun.
	if (!isTrustAnchor) {
		if (config.trustMarkIssuers !== undefined) {
			throw new InvalidAuthorityConfig(
				"trustMarkIssuers is only meaningful for a Trust Anchor (including an anchor with Superiors). Remove it from the Intermediate's config.",
			);
		}
		if (config.trustMarkOwners !== undefined) {
			throw new InvalidAuthorityConfig(
				"trustMarkOwners is only meaningful for a Trust Anchor (including an anchor with Superiors). Remove it from the Intermediate's config.",
			);
		}
	}

	// Any Authority (Trust Anchor or Intermediate) MUST publish a fetch endpoint
	// and a list endpoint in its own Entity Configuration. Refuse to start an
	// authority that doesn't advertise either.
	const fedEntity = config.metadata.federation_entity as FederationEntityMetadata | undefined;
	if (!fedEntity?.federation_fetch_endpoint || !fedEntity?.federation_list_endpoint)
		safeLogger(config.options?.logger)?.warn("Authorities MUST publish fetch and list endpoints");
	if (!fedEntity) {
		throw new InvalidAuthorityConfig(
			"metadata.federation_entity.federation_fetch_endpoint is required for an Authority. Set it to the URL where this server serves the fetch endpoint.",
		);
	}
	const fetchEndpointPath = requireAdvertisedEndpointPath(
		"federation_fetch_endpoint",
		fedEntity.federation_fetch_endpoint,
	);
	const listEndpointPath = requireAdvertisedEndpointPath(
		"federation_list_endpoint",
		fedEntity.federation_list_endpoint,
	);
	const advertisedTrustMarkEndpoints = [
		fedEntity.federation_trust_mark_endpoint,
		fedEntity.federation_trust_mark_status_endpoint,
		fedEntity.federation_trust_mark_list_endpoint,
	].some((endpoint) => typeof endpoint === "string");
	if (advertisedTrustMarkEndpoints && !config.storage.trustMarks) {
		throw new InvalidAuthorityConfig(
			"Trust mark endpoints require storage.trustMarks to be configured.",
		);
	}

	if (
		fedEntity.federation_subordinate_events_endpoint !== undefined &&
		!config.storage.subordinateEvents
	) {
		throw new InvalidAuthorityConfig(
			"The subordinate events endpoint requires storage.subordinateEvents",
		);
	}

	// No metadata claim may carry a null leaf at any depth — omit the field instead.
	assertMetadataValuesNotNull(config.metadata as Record<string, unknown>);

	const clientKeyProvider =
		config.clientKeyProvider ?? createStorageBackedClientKeyProvider(config.storage);

	const base: HandlerContext = {
		...prepareEntityStatementExtensions(config),
		...(config.roles ? { roles: config.roles } : {}),
		entityId: normalizedEntityId,
		keyProvider: config.keyProvider,
		storage: config.storage,
		clientKeyProvider,
		metadata: config.metadata,
	};
	const effectiveOptions: FederationOptions | undefined =
		config.options || config.storage.cache
			? { ...config.options, ...(config.storage.cache ? { cache: config.storage.cache } : {}) }
			: undefined;
	const ctx: HandlerContext = Object.assign(
		base,
		{ isTrustAnchor, requireAuthForFreshResolution: config.requireAuthForFreshResolution ?? true },
		...[
			config.authorityHints && { authorityHints: config.authorityHints },
			config.trustAnchorHints && { trustAnchorHints: config.trustAnchorHints },
			config.endpointAuthentication && { endpointAuthentication: config.endpointAuthentication },
			config.trustMarkDefaults && { trustMarkDefaults: structuredClone(config.trustMarkDefaults) },
			config.trustMarkSigner && { trustMarkSigner: config.trustMarkSigner },
			config.trustMarkStatusPolicy && { trustMarkStatusPolicy: config.trustMarkStatusPolicy },
			config.trustMarkRequestExtensions && {
				trustMarkRequestExtensions: { ...config.trustMarkRequestExtensions },
			},
			config.trustMarkIssuer && { trustMarkIssuer: config.trustMarkIssuer },
			config.trustMarks && { trustMarks: structuredClone(config.trustMarks) },
			config.trustMarkIssuers && { trustMarkIssuers: structuredClone(config.trustMarkIssuers) },
			config.trustMarkOwners && { trustMarkOwners: structuredClone(config.trustMarkOwners) },
			config.trustMarkDelegations && {
				trustMarkDelegations: structuredClone(config.trustMarkDelegations),
			},
			config.trustAnchors && { trustAnchors: config.trustAnchors },
			config.entityConfigurationTtlSeconds !== undefined && {
				entityConfigurationTtlSeconds: config.entityConfigurationTtlSeconds,
			},
			config.subordinateStatementTtlSeconds !== undefined && {
				subordinateStatementTtlSeconds: config.subordinateStatementTtlSeconds,
			},
			config.subordinateEventsTtlSeconds !== undefined && {
				subordinateEventsTtlSeconds: config.subordinateEventsTtlSeconds,
			},
			config.trustMarkTtlSeconds !== undefined && {
				trustMarkTtlSeconds: config.trustMarkTtlSeconds,
			},
			effectiveOptions && { options: effectiveOptions },
		].filter(Boolean),
	);

	validateRoleMetadata(config.roles, config.metadata, ctx);
	if (ctx.storage.trustMarks) trustMarkService(ctx);
	const lifecycle = createSubordinateLifecycle(ctx);
	const meta = config.metadata.federation_entity;
	const collectionMethods = meta.federation_collection_endpoint_auth_methods ?? ["none"];
	if (
		config.collection?.authentication &&
		JSON.stringify([...new Set(config.collection.authentication.methods)].sort()) !==
			JSON.stringify([...new Set(collectionMethods)].sort())
	)
		throw new InvalidAuthorityConfig(
			"Collection authentication methods must match federation_collection_endpoint_auth_methods (default: none)",
		);
	if (meta.federation_collection_endpoint && !config.collection)
		throw new InvalidAuthorityConfig("The collection endpoint requires collection configuration");
	const collection = config.collection
		? new EntityCollectionService({
				...config.collection,
				responder: { entityId: normalizedEntityId, isTrustAnchor },
				...(meta.federation_collection_endpoint
					? { endpoint: meta.federation_collection_endpoint }
					: {}),
				...((config.collection.store ?? config.storage.collections)
					? { store: config.collection.store ?? config.storage.collections }
					: {}),
				options: { ...effectiveOptions, ...config.collection.options },
				authentication: {
					...config.collection.authentication,
					methods: collectionMethods as ("none" | "private_key_jwt")[],
					receiverEntityId: normalizedEntityId,
					getClientFederationJwks: (id) => clientKeyProvider.getClientFederationJwks(id),
					...(config.storage.replay
						? {
								replayStore: config.collection.authentication?.replayStore ?? config.storage.replay,
							}
						: {}),
					...(meta.endpoint_auth_signing_alg_values_supported
						? { allowedAlgorithms: meta.endpoint_auth_signing_alg_values_supported }
						: {}),
				},
			})
		: undefined;

	validateEndpointCompanions(meta);

	function withAuth(
		handler: (req: Request) => Promise<Response>,
		authMethods: string[] | undefined,
		nativeMethod?: "GET" | "POST",
		unorderedParameters?: readonly string[],
	): (req: Request) => Promise<Response> {
		return createAuthenticatedHandler(ctx, handler, authMethods, {
			...(nativeMethod !== undefined ? { nativeMethod } : {}),
			...(unorderedParameters ? { unorderedParameters } : {}),
			...(meta.endpoint_auth_signing_alg_values_supported !== undefined
				? { allowedAlgorithms: meta.endpoint_auth_signing_alg_values_supported }
				: {}),
		});
	}

	const subordinateEventsHandler = createSubordinateEventsHandler(ctx);
	const holder = new TrustMarkHolder(ctx.entityId, ctx.trustMarks ?? [], async (refs) => {
		await buildEntityConfiguration({ ...ctx, trustMarks: refs });
		Object.defineProperty(ctx, "trustMarks", {
			value: structuredClone(refs),
			enumerable: true,
			configurable: true,
		});
	});
	const ecHandler = createEntityConfigurationHandler(ctx);
	const fetchHandler = createFetchHandler(ctx);
	const listHandler = createListHandler(ctx);
	const extendedListHandler = createExtendedListHandler(ctx, config.extendedListing);
	const historicalKeysHandler = createHistoricalKeysHandler(ctx);
	const trustMarkStatusHandler = createTrustMarkStatusHandler(ctx);
	const trustMarkListHandler = createTrustMarkListHandler(ctx);
	const trustMarkHandler = createTrustMarkHandler(ctx);

	const resolveHandler = createResolveHandler(ctx);

	const routeMap = new Map<string, (request: Request) => Promise<Response>>();
	const routeNames = new Map<string, string>();
	// Entity Configuration discovery is GET (§9.1), separate from §8.8 endpoint authentication.
	addAuthorityRoute(
		routeMap,
		routeNames,
		"entity configuration",
		wellKnownPathForEntityId(normalizedEntityId),
		ecHandler,
	);
	addAuthorityRoute(
		routeMap,
		routeNames,
		"federation_fetch_endpoint",
		fetchEndpointPath,
		withAuth(fetchHandler, meta.federation_fetch_endpoint_auth_methods),
	);
	addAuthorityRoute(
		routeMap,
		routeNames,
		"federation_list_endpoint",
		listEndpointPath,
		withAuth(
			listHandler,
			meta.federation_list_endpoint_auth_methods,
			undefined,
			LIST_UNORDERED_PARAMETERS,
		),
	);
	addOptionalAuthorityRoute(
		routeMap,
		routeNames,
		"federation_extended_list_endpoint",
		meta.federation_extended_list_endpoint,
		withAuth(
			extendedListHandler,
			meta.federation_extended_list_endpoint_auth_methods,
			undefined,
			EXTENDED_LIST_UNORDERED_PARAMETERS,
		),
	);
	addOptionalAuthorityRoute(
		routeMap,
		routeNames,
		"federation_historical_keys_endpoint",
		meta.federation_historical_keys_endpoint,
		withAuth(historicalKeysHandler, meta.federation_historical_keys_endpoint_auth_methods),
	);
	addOptionalAuthorityRoute(
		routeMap,
		routeNames,
		"federation_trust_mark_status_endpoint",
		meta.federation_trust_mark_status_endpoint,
		withAuth(
			trustMarkStatusHandler,
			meta.federation_trust_mark_status_endpoint_auth_methods,
			"POST",
		),
	);
	addOptionalAuthorityRoute(
		routeMap,
		routeNames,
		"federation_trust_mark_list_endpoint",
		meta.federation_trust_mark_list_endpoint,
		withAuth(trustMarkListHandler, meta.federation_trust_mark_list_endpoint_auth_methods),
	);
	addOptionalAuthorityRoute(
		routeMap,
		routeNames,
		"federation_trust_mark_endpoint",
		meta.federation_trust_mark_endpoint,
		withAuth(trustMarkHandler, meta.federation_trust_mark_endpoint_auth_methods),
	);
	addOptionalAuthorityRoute(
		routeMap,
		routeNames,
		"federation_resolve_endpoint",
		meta.federation_resolve_endpoint,
		withAuth(
			resolveHandler,
			meta.federation_resolve_endpoint_auth_methods,
			undefined,
			RESOLVE_UNORDERED_PARAMETERS,
		),
	);

	addOptionalAuthorityRoute(
		routeMap,
		routeNames,
		"federation_subordinate_events_endpoint",
		meta.federation_subordinate_events_endpoint,
		withSubordinateEventsMethodErrors(
			withAuth(subordinateEventsHandler, meta.federation_subordinate_events_endpoint_auth_methods),
		),
	);

	if (collection)
		addOptionalAuthorityRoute(
			routeMap,
			routeNames,
			"federation_collection_endpoint",
			meta.federation_collection_endpoint,
			(request) => collection.handleRequest(request),
		);

	// Role routes match the whole pathname, including requests with fixed selectors.
	// Compare against the registered endpoints after metadata composition.
	for (const [path, name] of routeNames) {
		const pathname = new URL(`https://routing.invalid${path}`).pathname;
		if (roleRoutes.has(pathname))
			throw new InvalidAuthorityConfig(`Role route '${pathname}' conflicts with ${name}`);
	}

	const router = async (request: Request): Promise<Response> => {
		// Remove legacy identity headers; authentication context is carried separately.
		const headers = new Headers(request.headers);
		headers.delete("X-Authenticated-Entity");
		const init: RequestInit = {
			method: request.method,
			signal: request.signal,
			headers,
			body: request.body,
		};
		if (request.body) {
			(init as Record<string, unknown>).duplex = "half";
		}
		const sanitizedRequest = new Request(request.url, init);

		const url = new URL(sanitizedRequest.url);
		const pathname = url.pathname;

		for (const [route, handler] of routeMap) {
			const expected = new URL(`https://routing.invalid${route}`);
			if (
				expected.pathname === pathname &&
				fixedQueryMatches(expected.searchParams, url.searchParams, routeNames.get(route))
			)
				return handler(sanitizedRequest);
		}

		return new Response(
			JSON.stringify({ error: "not_found", error_description: "Unknown endpoint" }),
			{
				status: 404,
				headers: {
					...SECURITY_HEADERS,
					"Content-Type": "application/json",
				},
			},
		);
	};

	return {
		...lifecycle,
		...(collection ? { collection } : {}),
		async getSubordinateEvents(subject: EntityId): Promise<string> {
			safeLogger(config.options?.logger)?.debug("Starting get subordinate events");

			const jwt = await buildSubordinateEvents(ctx, subject);
			if (jwt === undefined) throw new Error(`Subordinate history '${subject}' not found`);
			return jwt;
		},
		async getEntityConfiguration(): Promise<string> {
			safeLogger(config.options?.logger)?.debug("Starting get entity configuration");

			return buildEntityConfiguration(ctx);
		},

		async getSubordinateStatement(sub: EntityId): Promise<string> {
			safeLogger(config.options?.logger)?.debug("Starting get subordinate statement");

			const record = await config.storage.subordinates.get(sub);
			if (!record) {
				throw new Error(`Subordinate '${sub}' not found`);
			}
			return buildSubordinateStatement(ctx, record);
		},

		async listSubordinates(filter?: ListFilter): Promise<EntityId[]> {
			safeLogger(config.options?.logger)?.debug("Starting list subordinates");

			const page = await config.storage.subordinates.list(filter);
			return page.items.map((r) => r.entityId);
		},

		async listSubordinatesExtended(
			params?: ExtendedSubordinateListingParams,
			options?: ExtendedSubordinateListingOptions,
		): Promise<Result<ExtendedSubordinateListingResult, FederationError>> {
			safeLogger(config.options?.logger)?.debug("Starting list subordinates extended");

			const url = new URL(FederationEndpoint.ExtendedList, normalizedEntityId);
			const selectors = buildExtendedListRequestParameters(url.href, params);
			if (!selectors.ok) return selectors;
			let req: Request;
			try {
				url.search = prepareEndpointParameters(
					selectors.value,
					options?.additionalParameters,
				).toString();
				req = new Request(url, options?.signal ? { signal: options.signal } : undefined);
			} catch {
				return err(
					federationError(
						FederationErrorCode.InvalidRequest,
						"Invalid extended listing parameters",
					),
				);
			}
			const res = await extendedListHandler(req);
			if (res.status !== 200) {
				const body = (await res.json()) as { error?: string; error_description?: string };
				const knownCodes = new Set<string>(Object.values(FederationErrorCode));
				const code: FederationErrorCode =
					body.error !== undefined && knownCodes.has(body.error)
						? (body.error as FederationErrorCode)
						: FederationErrorCode.ServerError;
				return err(federationError(code, body.error_description ?? code));
			}
			return ok((await res.json()) as ExtendedSubordinateListingResult);
		},

		async resolveEntity(
			sub: EntityId,
			_ta?: EntityId,
			options?: FederationOptions,
		): Promise<string> {
			safeLogger(config.options?.logger)?.debug("Starting resolve entity");

			const baseUrl = normalizedEntityId;
			const url = new URL(FederationEndpoint.Resolve, baseUrl);
			url.searchParams.set("sub", sub);
			if (_ta) url.searchParams.set("trust_anchor", _ta);
			const req = new Request(url.toString());
			const res = await resolveHandler(req, true, options);
			if (res.status !== 200) {
				const body = (await res.json()) as { error: string; error_description?: string };
				throw new Error(body.error_description ?? body.error);
			}
			return res.text();
		},

		async getTrustMarkStatus(trustMark: string): Promise<TrustMarkStatusResponsePayload> {
			safeLogger(config.options?.logger)?.debug("Starting get trust mark status");

			const req = new Request(
				new URL(FederationEndpoint.TrustMarkStatus, normalizedEntityId).toString(),
				{
					method: "POST",
					headers: { "Content-Type": "application/x-www-form-urlencoded" },
					body: `trust_mark=${encodeURIComponent(trustMark)}`,
				},
			);
			const res = await trustMarkStatusHandler(req);
			if (res.status !== 200) {
				const body = (await res.json()) as { error: string; error_description?: string };
				throw new Error(body.error_description ?? body.error);
			}
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			if (!isOk(decoded)) {
				throw new Error("Failed to decode trust mark status response");
			}
			return decoded.value.payload as unknown as TrustMarkStatusResponsePayload;
		},

		async listTrustMarkedEntities(trustMarkType: string): Promise<string[]> {
			safeLogger(config.options?.logger)?.debug("Starting list trust marked entities");
			return trustMarkService(ctx).listTrustMarkedEntities(trustMarkType);
		},

		getTrustMarks: () => holder.getTrustMarks(),
		attachTrustMark: (jwt, options) => holder.attachTrustMark(jwt, options),
		fetchAndAttachTrustMark: (options) => holder.fetchAndAttachTrustMark(options),
		removeTrustMark: (selector) => holder.removeTrustMark(selector),
		async setTrustMarkIssuers(issuers) {
			if (!ctx.isTrustAnchor) throw new Error("Only Trust Anchors publish trust_mark_issuers");
			const owned = structuredClone(issuers);
			await holder.updatePublication(async () => {
				await buildEntityConfiguration({ ...ctx, trustMarkIssuers: owned });
				Object.defineProperty(ctx, "trustMarkIssuers", {
					value: owned,
					enumerable: true,
					configurable: true,
				});
				updateTrustMarkServicePolicy(ctx);
			});
		},
		async setTrustMarkOwners(owners) {
			if (!ctx.isTrustAnchor) throw new Error("Only Trust Anchors publish trust_mark_owners");
			const owned = structuredClone(owners);
			await holder.updatePublication(async () => {
				await buildEntityConfiguration({ ...ctx, trustMarkOwners: owned });
				Object.defineProperty(ctx, "trustMarkOwners", {
					value: owned,
					enumerable: true,
					configurable: true,
				});
				updateTrustMarkServicePolicy(ctx);
			});
		},
		async setTrustMarkDelegations(delegations) {
			await trustMarkService(ctx).setDelegations(delegations);
		},

		async revokeTrustMark(type: string, subject: string) {
			return trustMarkService(ctx).revokeTrustMark(type, subject);
		},
		async listTrustMarksForSubject(subject: string) {
			return trustMarkService(ctx).listTrustMarksForSubject(subject);
		},

		async issueTrustMark(
			sub: string,
			trustMarkType: string,
			options?: TrustMarkIssuanceOptions,
		): Promise<string> {
			safeLogger(config.options?.logger)?.debug("Starting issue trust mark");

			return trustMarkService(ctx).issueTrustMark(sub, trustMarkType, options);
		},

		async issueTrustMarkDelegation(
			subject: string,
			trustMarkType: string,
			options?: TrustMarkDelegationIssuanceOptions,
		): Promise<string> {
			safeLogger(config.options?.logger)?.debug("Starting issue trust mark delegation");

			const keySet = await ctx.keyProvider.getFederationKeySet();
			const params = {
				issuer: normalizedEntityId,
				subject,
				trustMarkType,
				signer: keySet.signer,
				...(options?.noExpiry
					? {}
					: config.trustMarkTtlSeconds !== undefined
						? { ttlSeconds: config.trustMarkTtlSeconds }
						: {}),
				...options,
				...(config.options?.clock ? { clock: config.options.clock } : {}),
			};
			return signTrustMarkDelegation(params);
		},

		async getHistoricalKeys(): Promise<string> {
			safeLogger(config.options?.logger)?.debug("Starting get historical keys");

			return buildHistoricalKeys(ctx);
		},

		handler(): (request: Request) => Promise<Response> {
			return router;
		},
	};
}

function normalizeAuthorityEntityId(value: EntityId | string): EntityId {
	const normalized = value.endsWith("/") ? value.slice(0, -1) : value;
	if (!isValidEntityId(normalized)) {
		throw new Error("entityId MUST be a valid HTTPS URL without query or fragment");
	}
	return normalized as EntityId;
}

function validateEndpointCompanions(metadata: Record<string, unknown>): void {
	for (const endpoint of [
		"fetch",
		"list",
		"extended_list",
		"subordinate_events",
		"resolve",
		"collection",
		"trust_mark",
		"trust_mark_status",
		"trust_mark_list",
		"historical_keys",
	]) {
		const name = `federation_${endpoint}_endpoint`;
		if (metadata[`${name}_auth_methods`] !== undefined && metadata[name] === undefined)
			throw new InvalidAuthorityConfig(`${name}_auth_methods requires ${name}`);
	}
}

function wellKnownPathForEntityId(value: EntityId): string {
	// Section 9 constructs the URL from the published identifier, independently of host normalization.
	const base = value.endsWith("/") ? value.slice(0, -1) : value;
	return new URL(`${base}${WELL_KNOWN_OPENID_FEDERATION}`).pathname;
}

function addRoleRoutes(
	routes: Map<string, (request: Request) => Promise<Response>>,
	role: EntityRole,
	entityId: EntityId,
): void {
	for (const [path, handler] of role.routes ?? []) {
		const resolvedPath = path.startsWith("http") ? new URL(path).pathname : path;
		if (routes.has(resolvedPath) || resolvedPath === wellKnownPathForEntityId(entityId))
			throw new InvalidAuthorityConfig(
				`Role route '${resolvedPath}' conflicts with an existing route`,
			);
		routes.set(resolvedPath, handler);
	}
}

function requireAdvertisedEndpointPath(endpointName: string, endpoint: unknown): string {
	if (typeof endpoint !== "string") {
		throw new InvalidAuthorityConfig(
			`metadata.federation_entity.${endpointName} is required for an Authority.`,
		);
	}
	const path = advertisedEndpointPath(endpointName, endpoint);
	if (path === undefined) {
		throw new InvalidAuthorityConfig(
			`metadata.federation_entity.${endpointName} is required for an Authority.`,
		);
	}
	return path;
}

function advertisedEndpointPath(endpointName: string, endpoint: unknown): string | undefined {
	if (endpoint === undefined) {
		return undefined;
	}
	if (typeof endpoint !== "string") {
		throw new InvalidAuthorityConfig(
			`metadata.federation_entity.${endpointName} must be an HTTPS URL without fragment.`,
		);
	}

	let url: URL;
	try {
		url = new URL(endpoint);
	} catch {
		throw new InvalidAuthorityConfig(
			`metadata.federation_entity.${endpointName} must be an HTTPS URL without fragment.`,
		);
	}
	if (url.protocol !== "https:" || url.href.includes("#")) {
		throw new InvalidAuthorityConfig(
			`metadata.federation_entity.${endpointName} must be an HTTPS URL without fragment.`,
		);
	}
	return url.pathname + url.search;
}

function unorderedEndpointParameters(endpointName: string | undefined): readonly string[] {
	switch (endpointName) {
		case "federation_list_endpoint":
			return LIST_UNORDERED_PARAMETERS;
		case "federation_extended_list_endpoint":
			return EXTENDED_LIST_UNORDERED_PARAMETERS;
		case "federation_resolve_endpoint":
			return RESOLVE_UNORDERED_PARAMETERS;
		case "federation_collection_endpoint":
			return COLLECTION_UNORDERED_PARAMETERS;
		default:
			return [];
	}
}

/** Match fixed selectors using the same semantics as the endpoint's request parameters. */
function fixedQueryMatches(
	expected: URLSearchParams,
	actual: URLSearchParams,
	endpointName: string | undefined,
): boolean {
	const unordered = unorderedEndpointParameters(endpointName);
	return [...new Set(expected.keys())].every((name) =>
		endpointParameterValuesMatch(name, expected.getAll(name), actual.getAll(name), unordered),
	);
}

function addAuthorityRoute(
	routeMap: Map<string, (request: Request) => Promise<Response>>,
	routeNames: Map<string, string>,
	endpointName: string,
	path: string,
	handler: (request: Request) => Promise<Response>,
): void {
	const incoming = new URL(`https://routing.invalid${path}`);
	for (const [existingPath, existingEndpoint] of routeNames) {
		const existing = new URL(`https://routing.invalid${existingPath}`);
		if (existing.pathname !== incoming.pathname) continue;
		// Two selectors overlap unless a shared fixed name requires different values.
		const disjoint = [...new Set(incoming.searchParams.keys())].some(
			(name) =>
				existing.searchParams.has(name) &&
				!endpointParameterValuesMatch(
					name,
					incoming.searchParams.getAll(name),
					existing.searchParams.getAll(name),
					// If either route uses membership, its accepted representations can overlap
					// the other route's exact sequence. Otherwise both sequences must be identical.
					[
						...unorderedEndpointParameters(endpointName),
						...unorderedEndpointParameters(existingEndpoint),
					],
				),
		);
		if (!disjoint)
			throw new InvalidAuthorityConfig(
				`Authority endpoint route path '${incoming.pathname}' is used by both ${existingEndpoint} and ${endpointName} with overlapping query selectors.`,
			);
	}
	routeNames.set(path, endpointName);
	routeMap.set(path, handler);
}

function addOptionalAuthorityRoute(
	routeMap: Map<string, (request: Request) => Promise<Response>>,
	routeNames: Map<string, string>,
	endpointName: string,
	endpoint: unknown,
	handler: (request: Request) => Promise<Response>,
): void {
	const path = advertisedEndpointPath(endpointName, endpoint);
	if (path === undefined) {
		return;
	}
	addAuthorityRoute(routeMap, routeNames, endpointName, path, handler);
}

function createStorageBackedClientKeyProvider(storage: StorageAdapter): AuthorityClientKeyProvider {
	return {
		async getClientFederationJwks(entityId: EntityId) {
			const record = await storage.subordinates.get(entityId);
			return record?.jwks;
		},
	};
}

/** Compose owned metadata after each role initializes its generated fields. */
function prepareAuthorityHost(
	config: AuthorityConfig,
	routes: Map<string, (request: Request) => Promise<Response>>,
	isTrustAnchor: boolean,
): { config: AuthorityConfig & { entityId: EntityId }; context: EntityContext } {
	if (!isTrustAnchor && !config.authorityHints?.length)
		throw new Error("Intermediate MUST have at least one authorityHint");
	assertTrustAnchorHintsConfig(config, isTrustAnchor);
	const normalized: AuthorityConfig & { entityId: EntityId } = {
		...config,
		entityId: normalizeAuthorityEntityId(config.entityId),
		metadata: composeEntityMetadata(config.metadata) as AuthorityConfig["metadata"],
	};
	const context: EntityContext = {
		entityId: normalized.entityId,
		keyProvider: normalized.keyProvider,
		options: normalized.options,
		...(normalized.authorityHints
			? { authorityHints: normalized.authorityHints as readonly EntityId[] }
			: {}),
		...(normalized.trustAnchors ? { trustAnchors: normalized.trustAnchors } : {}),
	};
	for (const role of normalized.roles ?? []) {
		role.initialize?.(context);
		normalized.metadata = composeEntityMetadata(normalized.metadata, {
			[role.type]: role.metadata,
		}) as AuthorityConfig["metadata"];
		addRoleRoutes(routes, role, normalized.entityId);
	}
	return { config: normalized, context };
}

export class TrustAnchor {
	static assessEntity = assessEntity;
	static discoverEntity = discoverEntity;
	static discoverEntityFromChain = discoverEntityFromChain;
	private readonly trustContext: EntityContext;
	assessEntity(
		target: EntityId,
		options: EntityAssessmentOptions & { trustAnchors?: TrustAnchorSet } = {},
	) {
		return assessEntity(
			target,
			options.trustAnchors ?? this.trustContext.trustAnchors ?? new Map(),
			{ ...this.trustContext.options, ...options },
		);
	}
	discoverEntity(
		target: EntityId,
		options: FederationOptions & { trustAnchors?: TrustAnchorSet } = {},
	) {
		return discoverEntity(
			target,
			options.trustAnchors ?? this.trustContext.trustAnchors ?? new Map(),
			{ ...this.trustContext.options, ...options },
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
			options.trustAnchors ?? this.trustContext.trustAnchors ?? new Map(),
			{ ...this.trustContext.options, ...options },
		);
	}

	get collection(): EntityCollectionService | undefined {
		return this.server.collection;
	}
	static sanitizeSubordinateMetadata = sanitizeSubordinateMetadata;

	public readonly entityId: EntityId;
	private readonly routes = new Map<string, (request: Request) => Promise<Response>>();
	private readonly server: AuthorityServer;

	constructor(config: AuthorityConfig) {
		const prepared = prepareAuthorityHost(config, this.routes, true);
		this.entityId = prepared.config.entityId;
		this.trustContext = prepared.context;
		this.server = createAuthorityServerWithIdentity(prepared.config, this.routes, true);
	}

	async getEntityConfiguration(): Promise<string> {
		return this.server.getEntityConfiguration();
	}

	async getSubordinateStatement(sub: EntityId): Promise<string> {
		return this.server.getSubordinateStatement(sub);
	}

	async listSubordinates(filter?: ListFilter): Promise<EntityId[]> {
		return this.server.listSubordinates(filter);
	}

	async listSubordinatesExtended(
		params?: ExtendedSubordinateListingParams,
		options?: ExtendedSubordinateListingOptions,
	): Promise<Result<ExtendedSubordinateListingResult, FederationError>> {
		return this.server.listSubordinatesExtended(params, options);
	}

	async resolveEntity(sub: EntityId, ta?: EntityId, options?: FederationOptions): Promise<string> {
		return this.server.resolveEntity(sub, ta, options);
	}

	async getTrustMarkStatus(trustMark: string): Promise<TrustMarkStatusResponsePayload> {
		return this.server.getTrustMarkStatus(trustMark);
	}

	async listTrustMarkedEntities(trustMarkType: string): Promise<string[]> {
		return this.server.listTrustMarkedEntities(trustMarkType);
	}

	getTrustMarks() {
		return this.server.getTrustMarks();
	}
	async attachTrustMark(jwt: string, options: AttachTrustMarkOptions) {
		return this.server.attachTrustMark(jwt, options);
	}
	async fetchAndAttachTrustMark(options: FetchAndAttachTrustMarkOptions) {
		return this.server.fetchAndAttachTrustMark(options);
	}
	async removeTrustMark(selector: RemoveTrustMarkSelector) {
		return this.server.removeTrustMark(selector);
	}
	async setTrustMarkIssuers(issuers: Record<string, string[]>) {
		return this.server.setTrustMarkIssuers(issuers);
	}
	async setTrustMarkOwners(owners: Record<string, TrustMarkOwner>) {
		return this.server.setTrustMarkOwners(owners);
	}
	async setTrustMarkDelegations(delegations: Record<string, string>) {
		return this.server.setTrustMarkDelegations(delegations);
	}
	async revokeTrustMark(type: string, subject: string) {
		return this.server.revokeTrustMark(type, subject);
	}
	async listTrustMarksForSubject(subject: string) {
		return this.server.listTrustMarksForSubject(subject);
	}
	async issueTrustMark(
		sub: string,
		trustMarkType: string,
		options?: TrustMarkIssuanceOptions,
	): Promise<string> {
		return this.server.issueTrustMark(sub, trustMarkType, options);
	}

	async issueTrustMarkDelegation(
		subject: string,
		trustMarkType: string,
		options?: TrustMarkDelegationIssuanceOptions,
	): Promise<string> {
		return this.server.issueTrustMarkDelegation(subject, trustMarkType, options);
	}

	async getHistoricalKeys(): Promise<string> {
		return this.server.getHistoricalKeys();
	}

	async registerSubordinate(
		record: Omit<SubordinateRecord, "createdAt" | "updatedAt">,
		annotations?: SubordinateEventAnnotations,
	): Promise<void> {
		return this.server.registerSubordinate(record, annotations);
	}
	async updateSubordinate(
		subject: EntityId,
		updates: SubordinateRecordUpdate,
		annotations?: SubordinateEventAnnotations,
	): Promise<void> {
		return this.server.updateSubordinate(subject, updates, annotations);
	}
	async revokeSubordinate(
		subject: EntityId,
		annotations?: SubordinateEventAnnotations,
	): Promise<void> {
		return this.server.revokeSubordinate(subject, annotations);
	}
	async recordSubordinateEvents(
		subject: EntityId,
		events: readonly SubordinateEvent[],
	): Promise<void> {
		return this.server.recordSubordinateEvents(subject, events);
	}
	async getSubordinateEvents(subject: EntityId): Promise<string> {
		return this.server.getSubordinateEvents(subject);
	}

	async handleRequest(request: Request): Promise<Response> {
		const url = new URL(request.url);
		const pathname = url.pathname;
		const roleHandler = this.routes.get(pathname);
		if (roleHandler) {
			return roleHandler(request);
		}
		return this.server.handler()(request);
	}
}

export class Intermediate {
	static assessEntity = assessEntity;
	static discoverEntity = discoverEntity;
	static discoverEntityFromChain = discoverEntityFromChain;
	private readonly trustContext: EntityContext;
	assessEntity(
		target: EntityId,
		options: EntityAssessmentOptions & { trustAnchors?: TrustAnchorSet } = {},
	) {
		return assessEntity(
			target,
			options.trustAnchors ?? this.trustContext.trustAnchors ?? new Map(),
			{ ...this.trustContext.options, ...options },
		);
	}
	discoverEntity(
		target: EntityId,
		options: FederationOptions & { trustAnchors?: TrustAnchorSet } = {},
	) {
		return discoverEntity(
			target,
			options.trustAnchors ?? this.trustContext.trustAnchors ?? new Map(),
			{ ...this.trustContext.options, ...options },
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
			options.trustAnchors ?? this.trustContext.trustAnchors ?? new Map(),
			{ ...this.trustContext.options, ...options },
		);
	}

	get collection(): EntityCollectionService | undefined {
		return this.server.collection;
	}
	static sanitizeSubordinateMetadata = sanitizeSubordinateMetadata;

	public readonly entityId: EntityId;
	private readonly routes = new Map<string, (request: Request) => Promise<Response>>();
	private readonly server: AuthorityServer;

	constructor(config: AuthorityConfig) {
		const prepared = prepareAuthorityHost(config, this.routes, false);
		this.entityId = prepared.config.entityId;
		this.trustContext = prepared.context;
		this.server = createAuthorityServerWithIdentity(prepared.config, this.routes, false);
	}

	async getEntityConfiguration(): Promise<string> {
		return this.server.getEntityConfiguration();
	}

	async getSubordinateStatement(sub: EntityId): Promise<string> {
		return this.server.getSubordinateStatement(sub);
	}

	async listSubordinates(filter?: ListFilter): Promise<EntityId[]> {
		return this.server.listSubordinates(filter);
	}

	async listSubordinatesExtended(
		params?: ExtendedSubordinateListingParams,
		options?: ExtendedSubordinateListingOptions,
	): Promise<Result<ExtendedSubordinateListingResult, FederationError>> {
		return this.server.listSubordinatesExtended(params, options);
	}

	async resolveEntity(sub: EntityId, ta?: EntityId, options?: FederationOptions): Promise<string> {
		return this.server.resolveEntity(sub, ta, options);
	}

	async getTrustMarkStatus(trustMark: string): Promise<TrustMarkStatusResponsePayload> {
		return this.server.getTrustMarkStatus(trustMark);
	}

	async listTrustMarkedEntities(trustMarkType: string): Promise<string[]> {
		return this.server.listTrustMarkedEntities(trustMarkType);
	}

	getTrustMarks() {
		return this.server.getTrustMarks();
	}
	async attachTrustMark(jwt: string, options: AttachTrustMarkOptions) {
		return this.server.attachTrustMark(jwt, options);
	}
	async fetchAndAttachTrustMark(options: FetchAndAttachTrustMarkOptions) {
		return this.server.fetchAndAttachTrustMark(options);
	}
	async removeTrustMark(selector: RemoveTrustMarkSelector) {
		return this.server.removeTrustMark(selector);
	}
	async setTrustMarkIssuers(issuers: Record<string, string[]>) {
		return this.server.setTrustMarkIssuers(issuers);
	}
	async setTrustMarkOwners(owners: Record<string, TrustMarkOwner>) {
		return this.server.setTrustMarkOwners(owners);
	}
	async setTrustMarkDelegations(delegations: Record<string, string>) {
		return this.server.setTrustMarkDelegations(delegations);
	}
	async revokeTrustMark(type: string, subject: string) {
		return this.server.revokeTrustMark(type, subject);
	}
	async listTrustMarksForSubject(subject: string) {
		return this.server.listTrustMarksForSubject(subject);
	}
	async issueTrustMark(
		sub: string,
		trustMarkType: string,
		options?: TrustMarkIssuanceOptions,
	): Promise<string> {
		return this.server.issueTrustMark(sub, trustMarkType, options);
	}

	async issueTrustMarkDelegation(
		subject: string,
		trustMarkType: string,
		options?: TrustMarkDelegationIssuanceOptions,
	): Promise<string> {
		return this.server.issueTrustMarkDelegation(subject, trustMarkType, options);
	}

	async getHistoricalKeys(): Promise<string> {
		return this.server.getHistoricalKeys();
	}

	async registerSubordinate(
		record: Omit<SubordinateRecord, "createdAt" | "updatedAt">,
		annotations?: SubordinateEventAnnotations,
	): Promise<void> {
		return this.server.registerSubordinate(record, annotations);
	}
	async updateSubordinate(
		subject: EntityId,
		updates: SubordinateRecordUpdate,
		annotations?: SubordinateEventAnnotations,
	): Promise<void> {
		return this.server.updateSubordinate(subject, updates, annotations);
	}
	async revokeSubordinate(
		subject: EntityId,
		annotations?: SubordinateEventAnnotations,
	): Promise<void> {
		return this.server.revokeSubordinate(subject, annotations);
	}
	async recordSubordinateEvents(
		subject: EntityId,
		events: readonly SubordinateEvent[],
	): Promise<void> {
		return this.server.recordSubordinateEvents(subject, events);
	}
	async getSubordinateEvents(subject: EntityId): Promise<string> {
		return this.server.getSubordinateEvents(subject);
	}

	async handleRequest(request: Request): Promise<Response> {
		const url = new URL(request.url);
		const pathname = url.pathname;
		const roleHandler = this.routes.get(pathname);
		if (roleHandler) {
			return roleHandler(request);
		}
		return this.server.handler()(request);
	}
}
