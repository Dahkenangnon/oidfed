/** Federation Authority server: wires endpoint handlers, key management, and subordinate storage into an HTTP server. */
import type {
	EntityContext,
	EntityId,
	EntityRole,
	EntityType,
	EntityTypeMetadataMap,
	FederationEntityMetadata,
	FederationError,
	FederationOptions,
	FederationSigningKey,
	ManagedFederationKeyProvider,
	Result,
	TrustAnchorSet,
	TrustMarkOwner,
	TrustMarkRef,
	TrustMarkStatusResponsePayload,
} from "@oidfed/core";
import {
	decodeEntityStatement,
	err,
	FederationEndpoint,
	FederationErrorCode,
	federationError,
	isOk,
	isValidEntityId,
	ok,
	signTrustMarkDelegation,
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
import { createTrustMarkHandler, createTrustMarkIssuanceHandler } from "./endpoints/trust-mark.js";
import { createTrustMarkListHandler } from "./endpoints/trust-mark-list.js";
import { createTrustMarkStatusHandler } from "./endpoints/trust-mark-status.js";
import { InvalidAuthorityConfig } from "./errors.js";
import { rotateKey } from "./keys/index.js";
import type { ListFilter, StorageAdapter, SubordinateRecord } from "./storage/types.js";
import {
	assertMetadataValuesNotNull,
	sanitizeSubordinateMetadata,
} from "./utils/subordinate-statement-shape.js";

export type { AuthorityClientKeyProvider } from "./endpoints/context.js";

/** Parameters accepted by {@link AuthorityServer.listSubordinatesExtended}. */
export interface ExtendedListInProcessParams {
	fromEntityId?: EntityId;
	limit?: number;
	updatedAfter?: number;
	updatedBefore?: number;
	auditTimestamps?: boolean;
	claims?: ReadonlyArray<string>;
	entityType?: EntityType | ReadonlyArray<EntityType>;
	trustMarked?: boolean;
	trustMarkType?: string;
	intermediate?: boolean;
}

/** Decoded body returned by {@link AuthorityServer.listSubordinatesExtended}. */
export interface ExtendedListInProcessResult {
	immediate_subordinate_entities: Array<Record<string, unknown> & { id: string }>;
	next_entity_id?: string;
}

export interface AuthorityConfig {
	/** The entity identifier (URL) for this authority. */
	entityId: EntityId | string;
	/** Metadata published in this authority's Entity Configuration. Must include `federation_entity`. */
	metadata: { federation_entity: FederationEntityMetadata } & Partial<{
		[K in EntityType]: EntityTypeMetadataMap[K];
	}>;
	/** Unified persistence adapter for all non-key authority state. */
	storage: StorageAdapter;
	/** Federation-only signing key provider and lifecycle manager. */
	keyProvider: ManagedFederationKeyProvider;
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
	/** Trust anchors used for trust chain resolution (e.g., during registration). */
	trustAnchors?: TrustAnchorSet;
	/** TTL in seconds for the Entity Configuration JWT. */
	entityConfigurationTtlSeconds?: number;
	/** TTL in seconds for subordinate statement JWTs. */
	subordinateStatementTtlSeconds?: number;
	/** TTL in seconds for issued trust mark JWTs. */
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
	getEntityConfiguration(): Promise<string>;
	getSubordinateStatement(sub: EntityId): Promise<string>;
	listSubordinates(filter?: ListFilter): Promise<EntityId[]>;
	/**
	 * Direct access to the Extended Subordinate Listing response (skipping HTTP).
	 * Mirrors the wire-level handler — used for in-process pagination,
	 * server-side rendering, and tests.
	 */
	listSubordinatesExtended(
		params?: ExtendedListInProcessParams,
	): Promise<Result<ExtendedListInProcessResult, FederationError>>;
	resolveEntity(sub: EntityId, ta?: EntityId): Promise<string>;
	getTrustMarkStatus(trustMark: string): Promise<TrustMarkStatusResponsePayload>;
	listTrustMarkedEntities(trustMarkType: string): Promise<string[]>;
	issueTrustMark(sub: string, trustMarkType: string): Promise<string>;
	issueTrustMarkDelegation(subject: string, trustMarkType: string): Promise<string>;
	getHistoricalKeys(): Promise<string>;
	rotateSigningKey(newKey: FederationSigningKey): Promise<void>;
	handler(): (request: Request) => Promise<Response>;
}

/** Creates a federation authority server with all spec-defined endpoints. */
export function createAuthorityServer(config: AuthorityConfig): AuthorityServer {
	const normalizedEntityId = normalizeAuthorityEntityId(config.entityId);

	const ttlFields = [
		["entityConfigurationTtlSeconds", config.entityConfigurationTtlSeconds],
		["subordinateStatementTtlSeconds", config.subordinateStatementTtlSeconds],
		["trustMarkTtlSeconds", config.trustMarkTtlSeconds],
	] as const;
	for (const [name, value] of ttlFields) {
		if (value !== undefined && value <= 0) {
			throw new Error(`${name} must be positive`);
		}
	}

	// authorityHints: must be undefined (Trust Anchor) or a non-empty array (Intermediate).
	// An explicit empty array would advertise "I am an Intermediate but I have no superiors",
	// which is contradictory and never valid.
	if (config.authorityHints !== undefined && config.authorityHints.length === 0) {
		throw new InvalidAuthorityConfig(
			"authorityHints must be undefined (Trust Anchor) or a non-empty array of superior Entity Identifiers (Intermediate); an empty array is not allowed.",
		);
	}

	const isTrustAnchor = (config.authorityHints?.length ?? 0) === 0;

	// trust_mark_issuers / trust_mark_owners only have effect on a Trust Anchor's
	// Entity Configuration. Refuse to construct an Intermediate that carries
	// these — readers ignore them, and silently emitting ignored claims is a footgun.
	if (!isTrustAnchor) {
		if (config.trustMarkIssuers !== undefined) {
			throw new InvalidAuthorityConfig(
				"trustMarkIssuers is only meaningful for a Trust Anchor (an authority with no authorityHints). Remove it from the Intermediate's config.",
			);
		}
		if (config.trustMarkOwners !== undefined) {
			throw new InvalidAuthorityConfig(
				"trustMarkOwners is only meaningful for a Trust Anchor (an authority with no authorityHints). Remove it from the Intermediate's config.",
			);
		}
	}

	// Any Authority (Trust Anchor or Intermediate) MUST publish a fetch endpoint
	// and a list endpoint in its own Entity Configuration. Refuse to start an
	// authority that doesn't advertise either.
	const fedEntity = config.metadata.federation_entity as FederationEntityMetadata | undefined;
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

	// No metadata claim may carry a null leaf at any depth — omit the field instead.
	assertMetadataValuesNotNull(config.metadata as Record<string, unknown>);

	const clientKeyProvider =
		config.clientKeyProvider ?? createStorageBackedClientKeyProvider(config.storage);

	const base: HandlerContext = {
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
		...[
			config.authorityHints && { authorityHints: config.authorityHints },
			config.trustMarks && { trustMarks: config.trustMarks },
			config.trustMarkIssuers && { trustMarkIssuers: config.trustMarkIssuers },
			config.trustMarkOwners && { trustMarkOwners: config.trustMarkOwners },
			config.trustMarkDelegations && { trustMarkDelegations: config.trustMarkDelegations },
			config.trustAnchors && { trustAnchors: config.trustAnchors },
			config.entityConfigurationTtlSeconds !== undefined && {
				entityConfigurationTtlSeconds: config.entityConfigurationTtlSeconds,
			},
			config.subordinateStatementTtlSeconds !== undefined && {
				subordinateStatementTtlSeconds: config.subordinateStatementTtlSeconds,
			},
			config.trustMarkTtlSeconds !== undefined && {
				trustMarkTtlSeconds: config.trustMarkTtlSeconds,
			},
			effectiveOptions && { options: effectiveOptions },
		].filter(Boolean),
	);

	const meta = config.metadata.federation_entity;

	function withAuth(
		handler: (req: Request) => Promise<Response>,
		authMethods: string[] | undefined,
		nativeMethod?: "GET" | "POST",
	): (req: Request) => Promise<Response> {
		return createAuthenticatedHandler(ctx, handler, authMethods, { nativeMethod });
	}

	const ecHandler = createEntityConfigurationHandler(ctx);
	const fetchHandler = createFetchHandler(ctx);
	const listHandler = createListHandler(ctx);
	const extendedListHandler = createExtendedListHandler(ctx, config.extendedListing);
	const historicalKeysHandler = createHistoricalKeysHandler(ctx);
	const trustMarkStatusHandler = createTrustMarkStatusHandler(ctx);
	const trustMarkListHandler = createTrustMarkListHandler(ctx);
	const trustMarkHandler = createTrustMarkHandler(ctx);
	const trustMarkIssuanceHandler = createTrustMarkIssuanceHandler(ctx);
	const resolveHandler = createResolveHandler(ctx);

	const routeMap = new Map<string, (request: Request) => Promise<Response>>();
	const routeNames = new Map<string, string>();
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
		withAuth(listHandler, meta.federation_list_endpoint_auth_methods),
	);
	addOptionalAuthorityRoute(
		routeMap,
		routeNames,
		"federation_extended_list_endpoint",
		meta.federation_extended_list_endpoint,
		withAuth(extendedListHandler, meta.federation_extended_list_endpoint_auth_methods),
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
		withAuth(resolveHandler, meta.federation_resolve_endpoint_auth_methods),
	);

	const router = async (request: Request): Promise<Response> => {
		// Strip X-Authenticated-Entity to prevent spoofing — the auth wrapper re-adds it after verification
		const headers = new Headers(request.headers);
		headers.delete("X-Authenticated-Entity");
		const init: RequestInit = {
			method: request.method,
			headers,
			body: request.body,
		};
		if (request.body) {
			(init as Record<string, unknown>).duplex = "half";
		}
		const sanitizedRequest = new Request(request.url, init);

		const url = new URL(sanitizedRequest.url);
		const pathname = url.pathname;

		const handler = routeMap.get(pathname);
		if (handler) {
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
		async getEntityConfiguration(): Promise<string> {
			return buildEntityConfiguration(ctx);
		},

		async getSubordinateStatement(sub: EntityId): Promise<string> {
			const record = await config.storage.subordinates.get(sub);
			if (!record) {
				throw new Error(`Subordinate '${sub}' not found`);
			}
			return buildSubordinateStatement(ctx, record);
		},

		async listSubordinates(filter?: ListFilter): Promise<EntityId[]> {
			const page = await config.storage.subordinates.list(filter);
			return page.items.map((r) => r.entityId);
		},

		async listSubordinatesExtended(
			params?: ExtendedListInProcessParams,
		): Promise<Result<ExtendedListInProcessResult, FederationError>> {
			const url = new URL(FederationEndpoint.ExtendedList, normalizedEntityId);
			if (params?.fromEntityId !== undefined) {
				url.searchParams.set("from_entity_id", params.fromEntityId);
			}
			if (params?.limit !== undefined) {
				url.searchParams.set("limit", String(params.limit));
			}
			if (params?.updatedAfter !== undefined) {
				url.searchParams.set("updated_after", String(params.updatedAfter));
			}
			if (params?.updatedBefore !== undefined) {
				url.searchParams.set("updated_before", String(params.updatedBefore));
			}
			if (params?.auditTimestamps !== undefined) {
				url.searchParams.set("audit_timestamps", params.auditTimestamps ? "true" : "false");
			}
			if (params?.claims !== undefined) {
				const joined = Array.from(params.claims)
					.filter((c) => c.length > 0)
					.join(",");
				if (joined.length > 0) url.searchParams.set("claims", joined);
			}
			if (params?.entityType !== undefined) {
				const types = Array.isArray(params.entityType) ? params.entityType : [params.entityType];
				for (const t of types) url.searchParams.append("entity_type", t as string);
			}
			if (params?.trustMarked !== undefined) {
				url.searchParams.set("trust_marked", params.trustMarked ? "true" : "false");
			}
			if (params?.trustMarkType !== undefined) {
				url.searchParams.set("trust_mark_type", params.trustMarkType);
			}
			if (params?.intermediate !== undefined) {
				url.searchParams.set("intermediate", params.intermediate ? "true" : "false");
			}
			const req = new Request(url.toString());
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
			return ok((await res.json()) as ExtendedListInProcessResult);
		},

		async resolveEntity(sub: EntityId, _ta?: EntityId): Promise<string> {
			const baseUrl = normalizedEntityId;
			const url = new URL(FederationEndpoint.Resolve, baseUrl);
			url.searchParams.set("sub", sub);
			if (_ta) url.searchParams.set("trust_anchor", _ta);
			const req = new Request(url.toString());
			const res = await resolveHandler(req);
			if (res.status !== 200) {
				const body = (await res.json()) as { error: string; error_description?: string };
				throw new Error(body.error_description ?? body.error);
			}
			return res.text();
		},

		async getTrustMarkStatus(trustMark: string): Promise<TrustMarkStatusResponsePayload> {
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
			const url = new URL(FederationEndpoint.TrustMarkList, normalizedEntityId);
			url.searchParams.set("trust_mark_type", trustMarkType);
			const req = new Request(url.toString());
			const res = await trustMarkListHandler(req);
			return res.json() as Promise<string[]>;
		},

		async issueTrustMark(sub: string, trustMarkType: string): Promise<string> {
			const url = new URL(FederationEndpoint.TrustMark, normalizedEntityId);
			url.searchParams.set("trust_mark_type", trustMarkType);
			url.searchParams.set("sub", sub);
			const req = new Request(url.toString());
			const res = await trustMarkIssuanceHandler(req);
			if (res.status !== 200) {
				const body = (await res.json()) as { error: string; error_description?: string };
				throw new Error(body.error_description ?? body.error);
			}
			return res.text();
		},

		async issueTrustMarkDelegation(subject: string, trustMarkType: string): Promise<string> {
			const keySet = await ctx.keyProvider.getFederationKeySet();
			const params: Parameters<typeof signTrustMarkDelegation>[0] = {
				issuer: normalizedEntityId,
				subject,
				trustMarkType,
				signer: keySet.signer,
			};
			if (config.trustMarkTtlSeconds !== undefined) {
				params.ttlSeconds = config.trustMarkTtlSeconds;
			}
			if (config.options?.clock !== undefined) {
				params.clock = config.options.clock;
			}
			return signTrustMarkDelegation(params);
		},

		async getHistoricalKeys(): Promise<string> {
			return buildHistoricalKeys(ctx);
		},

		async rotateSigningKey(newKey: FederationSigningKey): Promise<void> {
			await rotateKey(config.keyProvider, newKey);
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

function wellKnownPathForEntityId(value: EntityId): string {
	const basePath = new URL(value).pathname.replace(/\/$/, "");
	return `${basePath}${WELL_KNOWN_OPENID_FEDERATION}`;
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
	if (url.protocol !== "https:" || url.hash) {
		throw new InvalidAuthorityConfig(
			`metadata.federation_entity.${endpointName} must be an HTTPS URL without fragment.`,
		);
	}
	return url.pathname;
}

function addAuthorityRoute(
	routeMap: Map<string, (request: Request) => Promise<Response>>,
	routeNames: Map<string, string>,
	endpointName: string,
	path: string,
	handler: (request: Request) => Promise<Response>,
): void {
	const existingEndpoint = routeNames.get(path);
	if (existingEndpoint !== undefined) {
		throw new InvalidAuthorityConfig(
			`Authority endpoint route path '${path}' is used by both ${existingEndpoint} and ${endpointName}. Advertise distinct endpoint URLs.`,
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

export class TrustAnchor {
	static sanitizeSubordinateMetadata = sanitizeSubordinateMetadata;

	public readonly entityId: EntityId;
	private readonly routes = new Map<string, (request: Request) => Promise<Response>>();
	private readonly server: AuthorityServer;
	private readonly storage: StorageAdapter;

	constructor(config: AuthorityConfig) {
		if (config.authorityHints !== undefined && config.authorityHints.length > 0) {
			throw new Error("Trust Anchor MUST NOT have authorityHints");
		}
		const normalizedConfig: AuthorityConfig = {
			...config,
			entityId: normalizeAuthorityEntityId(config.entityId),
		};
		this.entityId = normalizedConfig.entityId as EntityId;
		this.storage = normalizedConfig.storage;

		const context: EntityContext = {
			entityId: this.entityId,
			keyProvider: normalizedConfig.keyProvider,
			options: normalizedConfig.options,
			...(normalizedConfig.trustAnchors ? { trustAnchors: normalizedConfig.trustAnchors } : {}),
		};

		if (normalizedConfig.roles) {
			for (const role of normalizedConfig.roles) {
				if (role.initialize) {
					role.initialize(context);
				}
				const metadataRecord = normalizedConfig.metadata as Record<string, unknown>;
				metadataRecord[role.type] = {
					...(metadataRecord[role.type] as Record<string, unknown>),
					...role.metadata,
				};
				if (role.routes) {
					for (const [path, handler] of role.routes.entries()) {
						const resolvedPath = path.startsWith("http") ? new URL(path).pathname : path;
						this.routes.set(resolvedPath, handler);
					}
				}
			}
		}

		this.server = createAuthorityServer(normalizedConfig);
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
		params?: ExtendedListInProcessParams,
	): Promise<Result<ExtendedListInProcessResult, FederationError>> {
		return this.server.listSubordinatesExtended(params);
	}

	async resolveEntity(sub: EntityId, ta?: EntityId): Promise<string> {
		return this.server.resolveEntity(sub, ta);
	}

	async getTrustMarkStatus(trustMark: string): Promise<TrustMarkStatusResponsePayload> {
		return this.server.getTrustMarkStatus(trustMark);
	}

	async listTrustMarkedEntities(trustMarkType: string): Promise<string[]> {
		return this.server.listTrustMarkedEntities(trustMarkType);
	}

	async issueTrustMark(sub: string, trustMarkType: string): Promise<string> {
		return this.server.issueTrustMark(sub, trustMarkType);
	}

	async issueTrustMarkDelegation(subject: string, trustMarkType: string): Promise<string> {
		return this.server.issueTrustMarkDelegation(subject, trustMarkType);
	}

	async getHistoricalKeys(): Promise<string> {
		return this.server.getHistoricalKeys();
	}

	async rotateSigningKey(newKey: FederationSigningKey): Promise<void> {
		return this.server.rotateSigningKey(newKey);
	}

	async registerSubordinate(
		record: Omit<SubordinateRecord, "createdAt" | "updatedAt">,
	): Promise<void> {
		const sanitizedMetadata = record.metadata
			? sanitizeSubordinateMetadata(record.metadata)
			: undefined;
		const now = Math.floor(Date.now() / 1000);
		await this.storage.subordinates.add({
			...record,
			...(sanitizedMetadata ? { metadata: sanitizedMetadata } : {}),
			createdAt: now,
			updatedAt: now,
		});
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
	static sanitizeSubordinateMetadata = sanitizeSubordinateMetadata;

	public readonly entityId: EntityId;
	private readonly routes = new Map<string, (request: Request) => Promise<Response>>();
	private readonly server: AuthorityServer;
	private readonly storage: StorageAdapter;

	constructor(config: AuthorityConfig) {
		if (config.authorityHints === undefined || config.authorityHints.length === 0) {
			throw new Error("Intermediate MUST have at least one authorityHint");
		}
		const normalizedConfig: AuthorityConfig = {
			...config,
			entityId: normalizeAuthorityEntityId(config.entityId),
		};
		this.entityId = normalizedConfig.entityId as EntityId;
		this.storage = normalizedConfig.storage;

		const context: EntityContext = {
			entityId: this.entityId,
			keyProvider: normalizedConfig.keyProvider,
			options: normalizedConfig.options,
			...(normalizedConfig.trustAnchors ? { trustAnchors: normalizedConfig.trustAnchors } : {}),
			...(normalizedConfig.authorityHints
				? { authorityHints: normalizedConfig.authorityHints as readonly EntityId[] }
				: {}),
		};

		if (normalizedConfig.roles) {
			for (const role of normalizedConfig.roles) {
				if (role.initialize) {
					role.initialize(context);
				}
				const metadataRecord = normalizedConfig.metadata as Record<string, unknown>;
				metadataRecord[role.type] = {
					...(metadataRecord[role.type] as Record<string, unknown>),
					...role.metadata,
				};
				if (role.routes) {
					for (const [path, handler] of role.routes.entries()) {
						const resolvedPath = path.startsWith("http") ? new URL(path).pathname : path;
						this.routes.set(resolvedPath, handler);
					}
				}
			}
		}

		this.server = createAuthorityServer(normalizedConfig);
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
		params?: ExtendedListInProcessParams,
	): Promise<Result<ExtendedListInProcessResult, FederationError>> {
		return this.server.listSubordinatesExtended(params);
	}

	async resolveEntity(sub: EntityId, ta?: EntityId): Promise<string> {
		return this.server.resolveEntity(sub, ta);
	}

	async getTrustMarkStatus(trustMark: string): Promise<TrustMarkStatusResponsePayload> {
		return this.server.getTrustMarkStatus(trustMark);
	}

	async listTrustMarkedEntities(trustMarkType: string): Promise<string[]> {
		return this.server.listTrustMarkedEntities(trustMarkType);
	}

	async issueTrustMark(sub: string, trustMarkType: string): Promise<string> {
		return this.server.issueTrustMark(sub, trustMarkType);
	}

	async issueTrustMarkDelegation(subject: string, trustMarkType: string): Promise<string> {
		return this.server.issueTrustMarkDelegation(subject, trustMarkType);
	}

	async getHistoricalKeys(): Promise<string> {
		return this.server.getHistoricalKeys();
	}

	async rotateSigningKey(newKey: FederationSigningKey): Promise<void> {
		return this.server.rotateSigningKey(newKey);
	}

	async registerSubordinate(
		record: Omit<SubordinateRecord, "createdAt" | "updatedAt">,
	): Promise<void> {
		const sanitizedMetadata = record.metadata
			? sanitizeSubordinateMetadata(record.metadata)
			: undefined;
		const now = Math.floor(Date.now() / 1000);
		await this.storage.subordinates.add({
			...record,
			...(sanitizedMetadata ? { metadata: sanitizedMetadata } : {}),
			createdAt: now,
			updatedAt: now,
		});
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
