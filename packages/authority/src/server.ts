import {
	assertStorageCapabilities,
	type BoundFederationOptions,
	bindFederationOptions,
	cloneData,
	composeRolePublicationMetadata,
	describeStorageRequirements,
	federationEntry,
	fetchStoredSubordinate,
	listStoredSubordinates,
	snapshotCryptoContext,
	validateCryptoContext,
} from "@oidfed/core";

/** Authority hosts composing federation handlers, role metadata, signing keys, and storage. */

import type {
	FederationStorage,
	ListFilter,
	SubordinateEventAnnotations,
	SubordinateRecord,
	SubordinateRecordUpdate,
} from "@oidfed/core";
import {
	type AttachTrustMarkOptions,
	assertMetadataValuesNotNull,
	assertPositiveTtlSeconds,
	assessEntity,
	buildExtendedListRequestParameters,
	COLLECTION_UNORDERED_PARAMETERS,
	type CryptoContext,
	composeEntityMetadata,
	decodeEntityStatement,
	discoverEntity,
	discoverEntityFromChain,
	type EndpointAuthentication,
	type EntityAssessmentOptions,
	type EntityCollectionIntegration,
	EntityCollectionService,
	type EntityContext,
	type EntityId,
	type EntityRole,
	type EntityStatementExtensions,
	type EntityType,
	type EntityTypeMetadataMap,
	EXTENDED_LIST_UNORDERED_PARAMETERS,
	type ExtendedListRequestParams,
	endpointParameterValuesMatch,
	entityConfigurationUrl,
	err,
	FederationEndpoint,
	type FederationEntityMetadata,
	type FederationError,
	FederationErrorCode,
	type FederationOptions,
	type FetchAndAttachTrustMarkOptions,
	federationError,
	isOk,
	isValidEntityId,
	LIST_UNORDERED_PARAMETERS,
	ok,
	prepareEndpointParameters,
	prepareEntityStatementExtensions,
	RESOLVE_UNORDERED_PARAMETERS,
	type RemoveTrustMarkSelector,
	type Result,
	SECURITY_HEADERS,
	type SubordinateEvent,
	safeLogger,
	signTrustMarkDelegation,
	type TrustAnchorSet,
	type TrustMarkDelegationIssuanceOptions,
	TrustMarkHolder,
	type TrustMarkIssuanceOptions,
	type TrustMarkIssuerConfig,
	type TrustMarkOwner,
	type TrustMarkRecord,
	type TrustMarkRef,
	type TrustMarkStatusResponsePayload,
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
import { createTrustMarkStatusHandler } from "./endpoints/trust-mark-status.js";
import { InvalidAuthorityConfig } from "./errors.js";
import { createSubordinateLifecycle } from "./subordinate-lifecycle.js";
import { trustMarkService, updateTrustMarkServicePolicy } from "./trust-mark-service.js";

export type { AuthorityClientKeyProvider } from "./endpoints/context.js";

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
	storage: FederationStorage;
	/** Host engine and keyring; supply history when historical-key features are enabled. */
	crypto: CryptoContext;
	/**
	 * Resolves public Federation Entity Keys for authenticated remote authority
	 * endpoint clients. Defaults to `storage.subordinate.fetch(entityId)?.jwks`.
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
	options?: BoundFederationOptions;
	/**
	 * Configuration for the Extended Subordinate Listing endpoint. Set
	 * `enabled: false` to keep the endpoint disabled (router returns 404) and
	 * omit `federation_extended_list_endpoint` from your metadata. Defaults
	 * enable the endpoint with `maxPageSize=500`, `defaultPageSize=100`,
	 * time-filters and audit timestamps supported.
	 */
	extendedListing?: ExtendedListingConfig;
}

/** An Intermediate has at least one Superior and publishes its own delegation JWTs when configured. */
export interface IntermediateConfig
	extends Omit<AuthorityConfig, "authorityHints" | "trustMarkIssuers" | "trustMarkOwners"> {
	authorityHints: readonly [EntityId | string, ...(EntityId | string)[]];
	trustMarkIssuers?: never;
	trustMarkOwners?: never;
}

interface AuthorityServer {
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
	 * Run Extended Listing locally with the same filtering and pagination as the HTTP handler.
	 * Use it for in-process pagination, server-side rendering, or tests.
	 */
	listSubordinatesExtended(
		params?: ExtendedListRequestParams,
		options?: ExtendedSubordinateListingOptions,
	): Promise<Result<ExtendedSubordinateListingResult, FederationError>>;
	resolveEntity(sub: EntityId, ta?: EntityId, options?: BoundFederationOptions): Promise<string>;
	getTrustMarkStatus(trustMark: string): Promise<TrustMarkStatusResponsePayload>;
	listTrustMarkedEntities(trustMarkType: string): Promise<string[]>;
	revokeTrustMark(type: string, subject: string): Promise<void>;
	listTrustMarksForSubject(subject: string): Promise<TrustMarkRecord[]>;
	getTrustMarks(): TrustMarkRef[];
	attachTrustMark(
		jwt: string,
		options: BoundFederationOptions<AttachTrustMarkOptions>,
	): Promise<void>;
	fetchAndAttachTrustMark(
		options: Omit<FetchAndAttachTrustMarkOptions, "options"> & {
			readonly options?: BoundFederationOptions;
		},
	): Promise<void>;
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

/** Build around the established published identity without normalizing it again. */
function createAuthorityServerWithIdentity(
	config: PreparedAuthorityConfig,
	roleRoutes: ReadonlyMap<string, (request: Request) => Promise<Response>>,
	isTrustAnchor: boolean,
): AuthorityServer {
	const entityId = config.entityId;

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

	// trust_mark_issuers and trust_mark_owners apply to Trust Anchor policy.
	// Reject them on an Intermediate so operators receive a configuration error
	// instead of publishing claims that recipients ignore.
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
	const storage = config.storage;
	assertStorageCapabilities(storage, ["subordinate:read"], `Authority ${entityId}`);
	const has = (capability: import("@oidfed/core").StorageCapability) =>
		storage.capabilities.includes(capability);
	const historyPublished = fedEntity.federation_subordinate_events_endpoint !== undefined;
	const features: import("@oidfed/core").StorageFeature[] = ["authority"];
	if (historyPublished) features.push("eventHistory");
	if (has("subordinate:write")) features.push("subordinateLifecycle");
	if (has("subordinateEvent:write")) features.push("eventCapture");
	if (advertisedTrustMarkEndpoints || config.trustMarkIssuer || has("trustMark:read"))
		features.push(has("trustMark:write") ? "trustMarkWrite" : "trustMarkRead");
	if (config.collection) features.push("collection");
	assertStorageCapabilities(
		storage,
		describeStorageRequirements(...features),
		`Authority ${entityId}`,
	);
	if (historyPublished && !has("snapshot") && !has("transaction"))
		throw new InvalidAuthorityConfig(
			"Subordinate Events requires a consistent storage snapshot or transaction",
		);

	// Reject null entity-type blocks and direct metadata parameters; nested JSON nulls are allowed.
	assertMetadataValuesNotNull(config.metadata as Record<string, unknown>);

	const clientKeyProvider =
		config.clientKeyProvider ?? createStorageBackedClientKeyProvider(storage, config.options);

	const base: HandlerContext = {
		...prepareEntityStatementExtensions(config),
		...(config.roles ? { roles: config.roles } : {}),
		entityId,
		crypto: config.crypto,
		storage,
		clientKeyProvider,
		metadata: config.metadata,
		options: config.options,
	};
	const effectiveOptions = config.options;
	// Object.assign loses its result type for the conditional list of typed config fragments.
	// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
	const ctx: HandlerContext = Object.assign(
		base,
		{ isTrustAnchor, requireAuthForFreshResolution: config.requireAuthForFreshResolution ?? true },
		...[
			config.authorityHints && { authorityHints: config.authorityHints },
			config.trustAnchorHints && { trustAnchorHints: config.trustAnchorHints },
			config.endpointAuthentication && { endpointAuthentication: config.endpointAuthentication },
			config.trustMarkDefaults && { trustMarkDefaults: cloneData(config.trustMarkDefaults) },
			config.trustMarkStatusPolicy && { trustMarkStatusPolicy: config.trustMarkStatusPolicy },
			config.trustMarkRequestExtensions && {
				trustMarkRequestExtensions: { ...config.trustMarkRequestExtensions },
			},
			config.trustMarkIssuer && { trustMarkIssuer: config.trustMarkIssuer },
			config.trustMarks && { trustMarks: cloneData(config.trustMarks) },
			config.trustMarkIssuers && { trustMarkIssuers: cloneData(config.trustMarkIssuers) },
			config.trustMarkOwners && { trustMarkOwners: cloneData(config.trustMarkOwners) },
			config.trustMarkDelegations && {
				trustMarkDelegations: cloneData(config.trustMarkDelegations),
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

	if (has("trustMark:read")) trustMarkService(ctx);
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
				responder: { entityId, isTrustAnchor },
				...(meta.federation_collection_endpoint
					? { endpoint: meta.federation_collection_endpoint }
					: {}),
				options: bindFederationOptions(ctx, effectiveOptions, config.collection.options),
				authentication: {
					...config.collection.authentication,
					methods: collectionMethods as ("none" | "private_key_jwt")[],
					receiverEntityId: entityId,
					getClientFederationJwks: (id) => clientKeyProvider.getClientFederationJwks(id),
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
			value: cloneData(refs),
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
		wellKnownPathForEntityId(entityId),
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
		// Ignore caller-supplied identity headers; verified caller context is carried separately.
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

			const record = await fetchStoredSubordinate(storage.subordinate, sub, ctx.options);
			if (!record) {
				throw new Error(`Subordinate '${sub}' not found`);
			}
			return buildSubordinateStatement(ctx, record);
		},

		async listSubordinates(filter?: ListFilter): Promise<EntityId[]> {
			safeLogger(config.options?.logger)?.debug("Starting list subordinates");

			const page = await listStoredSubordinates(
				storage.subordinate,
				filter,
				undefined,
				ctx.options,
			);
			return page.items.map((r) => r.entityId);
		},

		async listSubordinatesExtended(
			params?: ExtendedListRequestParams,
			options?: ExtendedSubordinateListingOptions,
		): Promise<Result<ExtendedSubordinateListingResult, FederationError>> {
			safeLogger(config.options?.logger)?.debug("Starting list subordinates extended");

			const url = new URL(FederationEndpoint.ExtendedList, entityId);
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
			options?: BoundFederationOptions,
		): Promise<string> {
			safeLogger(config.options?.logger)?.debug("Starting resolve entity");

			const baseUrl = entityId;
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

			const req = new Request(new URL(FederationEndpoint.TrustMarkStatus, entityId).toString(), {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: `trust_mark=${encodeURIComponent(trustMark)}`,
			});
			const res = await trustMarkStatusHandler(req);
			if (res.status !== 200) {
				const body = (await res.json()) as { error: string; error_description?: string };
				throw new Error(body.error_description ?? body.error);
			}
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt, ctx.options);
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
		attachTrustMark: (jwt, options) =>
			holder.attachTrustMark(jwt, {
				...options,
				...bindFederationOptions(ctx, ctx.options, options),
			}),
		fetchAndAttachTrustMark: (options) =>
			holder.fetchAndAttachTrustMark({
				...options,
				options: bindFederationOptions(ctx, ctx.options, options.options),
			}),
		removeTrustMark: (selector) => holder.removeTrustMark(selector, ctx.options),
		async setTrustMarkIssuers(issuers) {
			if (!ctx.isTrustAnchor) throw new Error("Only Trust Anchors publish trust_mark_issuers");
			const owned = cloneData(issuers);
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
			const owned = cloneData(owners);
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

			const keySet = await federationEntry(ctx.crypto, {
				issuer: ctx.entityId,
				subject,
				trustMarkType,
			});
			const ttlSeconds =
				options?.ttlSeconds ?? (options?.noExpiry ? undefined : config.trustMarkTtlSeconds);
			const policy = bindFederationOptions(ctx, ctx.options, {
				maxCompactBytes: options?.maxCompactBytes,
				allowedFederationAlgorithms: options?.allowedFederationAlgorithms,
			});
			return signTrustMarkDelegation({
				issuer: entityId,
				subject,
				trustMarkType,
				signer: keySet,
				maxCompactBytes: policy.maxCompactBytes,
				algorithmRegistry: policy.algorithmRegistry,
				allowedFederationAlgorithms: policy.allowedFederationAlgorithms,
				...(ttlSeconds !== undefined ? { ttlSeconds } : {}),
				...(options?.noExpiry !== undefined ? { noExpiry: options.noExpiry } : {}),
				...(options?.ref !== undefined ? { ref: options.ref } : {}),
				...(options?.additionalClaims !== undefined
					? { additionalClaims: options.additionalClaims }
					: {}),
				...(ctx.options.clock ? { clock: ctx.options.clock } : {}),
			});
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

function validateAuthorityEntityId(value: EntityId | string): EntityId {
	if (!isValidEntityId(value)) {
		throw new Error("entityId MUST be a valid HTTPS URL without query or fragment");
	}
	return value;
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
	return new URL(entityConfigurationUrl(value)).pathname;
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
	if (endpointName === undefined) return [];
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

function createStorageBackedClientKeyProvider(
	storage: HandlerContext["storage"],
	options: FederationOptions,
): AuthorityClientKeyProvider {
	return {
		async getClientFederationJwks(entityId: EntityId) {
			const record = await fetchStoredSubordinate(storage.subordinate, entityId, options);
			return record?.jwks;
		},
	};
}

/** Compose owned metadata after each role initializes its generated fields. */
type PreparedAuthorityConfig = Omit<AuthorityConfig, "options"> & {
	entityId: EntityId;
	options: FederationOptions;
};
type PreparedAuthorityHost = {
	config: PreparedAuthorityConfig;
	context: EntityContext;
	routes: Map<string, (request: Request) => Promise<Response>>;
};

async function prepareAuthorityHost(
	config: AuthorityConfig,
	routes: Map<string, (request: Request) => Promise<Response>>,
	isTrustAnchor: boolean,
): Promise<PreparedAuthorityHost> {
	if (!isTrustAnchor && !config.authorityHints?.length)
		throw new Error("Intermediate MUST have at least one authorityHint");
	assertTrustAnchorHintsConfig(config, isTrustAnchor);
	const crypto = snapshotCryptoContext(config.crypto);
	const normalized: PreparedAuthorityConfig = {
		...config,
		...prepareEntityStatementExtensions(config),
		crypto,
		...(config.authorityHints ? { authorityHints: [...config.authorityHints] } : {}),
		...(config.roles ? { roles: [...config.roles] } : {}),
		...(config.trustMarks ? { trustMarks: cloneData(config.trustMarks) } : {}),
		options: bindFederationOptions({ crypto, storage: config.storage }, config.options),
		entityId: validateAuthorityEntityId(config.entityId),
		metadata: composeEntityMetadata(config.metadata) as AuthorityConfig["metadata"],
	};
	const context: EntityContext = Object.freeze({
		entityId: normalized.entityId,
		crypto: normalized.crypto,
		storage: normalized.storage,
		options: normalized.options,
		...(normalized.authorityHints
			? { authorityHints: normalized.authorityHints as readonly EntityId[] }
			: {}),
		...(normalized.trustAnchors ? { trustAnchors: normalized.trustAnchors } : {}),
	});
	for (const role of normalized.roles ?? []) {
		await role.initialize?.(context);
		normalized.metadata = composeEntityMetadata(normalized.metadata, {
			[role.type]: role.metadata,
		}) as AuthorityConfig["metadata"];
		addRoleRoutes(routes, role, normalized.entityId);
	}
	await federationEntry(normalized.crypto, {
		issuer: normalized.entityId,
		subject: normalized.entityId,
	});
	await composeRolePublicationMetadata(normalized.roles, normalized.metadata, context);
	if (
		normalized.metadata.federation_entity.federation_historical_keys_endpoint &&
		!normalized.crypto.history
	)
		throw new TypeError("Historical keys endpoint requires crypto.history");
	return { config: normalized, context, routes };
}

/** Shared authority host lifecycle, storage forwarding, and request dispatch. */
abstract class AuthorityHost {
	private readonly trustContext: EntityContext;
	/** Assess a target using configured anchors and options, overridden by per-call settings. */
	assessEntity(
		target: EntityId,
		options: BoundFederationOptions<EntityAssessmentOptions> & {
			trustAnchors?: TrustAnchorSet;
		} = {},
	) {
		return assessEntity(
			target,
			options.trustAnchors ?? this.trustContext.trustAnchors ?? new Map(),
			bindFederationOptions(this.trustContext, this.trustContext.options, options),
		);
	}
	/**
	 * Resolve, validate, and select a target chain using configured anchors and per-call overrides.
	 */
	discoverEntity(
		target: EntityId,
		options: BoundFederationOptions & { trustAnchors?: TrustAnchorSet } = {},
	) {
		return discoverEntity(
			target,
			options.trustAnchors ?? this.trustContext.trustAnchors ?? new Map(),
			bindFederationOptions(this.trustContext, this.trustContext.options, options),
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
			options.trustAnchors ?? this.trustContext.trustAnchors ?? new Map(),
			bindFederationOptions(this.trustContext, this.trustContext.options, options),
		);
	}

	/** Access the configured collection service, when this host has one. */
	get collection(): EntityCollectionService | undefined {
		return this.server.collection;
	}

	public readonly entityId: EntityId;
	private readonly routes: Map<string, (request: Request) => Promise<Response>>;
	protected readonly server: AuthorityServer;

	/**
	 * Validate and compose host and role configuration; storage and crypto services retain their
	 * identity.
	 */
	protected constructor(prepared: PreparedAuthorityHost, isTrustAnchor: boolean) {
		this.routes = prepared.routes;
		this.entityId = prepared.config.entityId;
		this.trustContext = prepared.context;
		this.server = createAuthorityServerWithIdentity(prepared.config, this.routes, isTrustAnchor);
	}

	/** Build and sign this authority's Entity Configuration using one current keyring snapshot. */
	async getEntityConfiguration(): Promise<string> {
		return this.server.getEntityConfiguration();
	}

	/** Sign the stored enrollment for a direct subordinate; reject when no record exists. */
	async getSubordinateStatement(sub: EntityId): Promise<string> {
		return this.server.getSubordinateStatement(sub);
	}

	/** Return identifiers from the local subordinate storage listing with the supplied filter. */
	async listSubordinates(filter?: ListFilter): Promise<EntityId[]> {
		return this.server.listSubordinates(filter);
	}

	/** Run local Extended Listing with filtering and pagination, returning a Result. */
	async listSubordinatesExtended(
		params?: ExtendedListRequestParams,
		options?: ExtendedSubordinateListingOptions,
	): Promise<Result<ExtendedSubordinateListingResult, FederationError>> {
		return this.server.listSubordinatesExtended(params, options);
	}

	/** Build a local signed Resolve response; per-call federation options override host defaults. */
	async resolveEntity(
		sub: EntityId,
		ta?: EntityId,
		options?: BoundFederationOptions,
	): Promise<string> {
		return this.server.resolveEntity(sub, ta, options);
	}

	/** Obtain this issuer's local status assessment; this is not a remote issuer lookup. */
	async getTrustMarkStatus(trustMark: string): Promise<TrustMarkStatusResponsePayload> {
		return this.server.getTrustMarkStatus(trustMark);
	}

	/** List eligible local subjects for a Trust Mark type. */
	async listTrustMarkedEntities(trustMarkType: string): Promise<string[]> {
		return this.server.listTrustMarkedEntities(trustMarkType);
	}

	/** Return a detached copy of this host's published Trust Mark references. */
	getTrustMarks() {
		return this.server.getTrustMarks();
	}
	/**
	 * Validate a mark for this host and publish it; failed validation leaves prior references intact.
	 */
	async attachTrustMark(jwt: string, options: BoundFederationOptions<AttachTrustMarkOptions>) {
		return this.server.attachTrustMark(jwt, options);
	}
	/** Establish issuer trust and retrieve a mark for this host before validated publication. */
	async fetchAndAttachTrustMark(
		options: Omit<FetchAndAttachTrustMarkOptions, "options"> & {
			readonly options?: BoundFederationOptions;
		},
	) {
		return this.server.fetchAndAttachTrustMark(options);
	}
	/** Remove matching references from this host's publication; this does not revoke issuance. */
	async removeTrustMark(selector: RemoveTrustMarkSelector) {
		return this.server.removeTrustMark(selector);
	}
	/** Replace owner-delegation JWTs used by this host's managed issuer service. */
	async setTrustMarkDelegations(delegations: Record<string, string>) {
		return this.server.setTrustMarkDelegations(delegations);
	}
	/** Revoke this issuer's matching local records for the type and subject. */
	async revokeTrustMark(type: string, subject: string) {
		return this.server.revokeTrustMark(type, subject);
	}
	/** Return detached, eligible local issuance records for the subject. */
	async listTrustMarksForSubject(subject: string) {
		return this.server.listTrustMarksForSubject(subject);
	}
	/** Issue or reuse a managed Trust Mark for a subject under the configured issuer policy. */
	async issueTrustMark(
		sub: string,
		trustMarkType: string,
		options?: TrustMarkIssuanceOptions,
	): Promise<string> {
		return this.server.issueTrustMark(sub, trustMarkType, options);
	}

	/** Sign an owner-to-issuer delegation; the host supplies the authority to make that delegation. */
	async issueTrustMarkDelegation(
		subject: string,
		trustMarkType: string,
		options?: TrustMarkDelegationIssuanceOptions,
	): Promise<string> {
		return this.server.issueTrustMarkDelegation(subject, trustMarkType, options);
	}

	/** Sign the recorded keys returned by the configured history source. */
	async getHistoricalKeys(): Promise<string> {
		return this.server.getHistoricalKeys();
	}

	/** Validate and persist an enrollment, recording lifecycle events when supported by storage. */
	async registerSubordinate(
		record: Omit<SubordinateRecord, "createdAt" | "updatedAt">,
		annotations?: SubordinateEventAnnotations,
	): Promise<void> {
		return this.server.registerSubordinate(record, annotations);
	}
	/**
	 * Validate and persist enrollment changes, recording supported lifecycle events transactionally.
	 */
	async updateSubordinate(
		subject: EntityId,
		updates: SubordinateRecordUpdate,
		annotations?: SubordinateEventAnnotations,
	): Promise<void> {
		return this.server.updateSubordinate(subject, updates, annotations);
	}
	/** Remove an enrollment and record revocation when event storage is available. */
	async revokeSubordinate(
		subject: EntityId,
		annotations?: SubordinateEventAnnotations,
	): Promise<void> {
		return this.server.revokeSubordinate(subject, annotations);
	}
	/**
	 * Validate and detach manually supplied events before queuing their transactional storage write.
	 */
	async recordSubordinateEvents(
		subject: EntityId,
		events: readonly SubordinateEvent[],
	): Promise<void> {
		return this.server.recordSubordinateEvents(subject, events);
	}
	/** Sign stored history for the subject; reject when no history exists. */
	async getSubordinateEvents(subject: EntityId): Promise<string> {
		return this.server.getSubordinateEvents(subject);
	}

	/** Dispatch role routes and federation endpoints, including configured endpoint authentication. */
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

/** Federation authority acting as a local policy anchor, optionally with Superiors of its own. */
export class TrustAnchor extends AuthorityHost {
	/** Replace the anchor's detached issuer declarations after validating the new publication. */
	async setTrustMarkIssuers(issuers: Record<string, string[]>) {
		return this.server.setTrustMarkIssuers(issuers);
	}
	/** Replace the anchor's detached owner declarations after validating the new publication. */
	async setTrustMarkOwners(owners: Record<string, TrustMarkOwner>) {
		return this.server.setTrustMarkOwners(owners);
	}

	declare private readonly trustAnchorBrand: undefined;

	/** Validate host and role configuration, retaining storage and key provider identity. */
	private constructor(prepared: PreparedAuthorityHost) {
		super(prepared, true);
	}
	/** Await role setup and validate signing purposes before returning a ready host. */
	static async create(config: AuthorityConfig): Promise<TrustAnchor> {
		validateCryptoContext(config.crypto);
		assertStorageCapabilities(config.storage, ["subordinate:read"], `Authority ${config.entityId}`);
		return new TrustAnchor(await prepareAuthorityHost(config, new Map(), true));
	}
}

/** Federation authority with at least one configured Superior. */
export class Intermediate extends AuthorityHost {
	declare private readonly intermediateBrand: undefined;

	/** Validate host and role configuration, retaining storage and key provider identity. */
	private constructor(prepared: PreparedAuthorityHost) {
		super(prepared, false);
	}
	/** Await role setup and validate signing purposes before returning a ready host. */
	static async create(config: IntermediateConfig): Promise<Intermediate> {
		validateCryptoContext(config.crypto);
		assertStorageCapabilities(config.storage, ["subordinate:read"], `Authority ${config.entityId}`);
		return new Intermediate(await prepareAuthorityHost(config, new Map(), false));
	}
}
