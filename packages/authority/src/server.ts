/** Federation Authority server: wires endpoint handlers, key management, and subordinate storage into an HTTP server. */
import type {
	EntityId,
	EntityType,
	EntityTypeMetadataMap,
	FederationEntityMetadata,
	FederationError,
	FederationOptions,
	JWK,
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
import type { HandlerContext } from "./endpoints/context.js";
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
import { createRegistrationHandler } from "./endpoints/registration.js";
import { createResolveHandler } from "./endpoints/resolve.js";
import { createTrustMarkHandler, createTrustMarkIssuanceHandler } from "./endpoints/trust-mark.js";
import { createTrustMarkListHandler } from "./endpoints/trust-mark-list.js";
import { createTrustMarkStatusHandler } from "./endpoints/trust-mark-status.js";
import { InvalidAuthorityConfig } from "./errors.js";
import { rotateKey } from "./keys/index.js";
import type { KeyStore, ListFilter, SubordinateStore, TrustMarkStore } from "./storage/types.js";
import { assertMetadataValuesNotNull } from "./utils/subordinate-statement-shape.js";

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
	entityId: EntityId;
	/** Metadata published in this authority's Entity Configuration. Must include `federation_entity`. */
	metadata: { federation_entity: FederationEntityMetadata } & Partial<{
		[K in EntityType]: EntityTypeMetadataMap[K];
	}>;
	/** Persistent store for subordinate entity records. */
	subordinateStore: SubordinateStore;
	/** Persistent store for signing key lifecycle (rotation, revocation). */
	keyStore: KeyStore;
	/** Optional store for issued trust marks. Required if this authority issues trust marks. */
	trustMarkStore?: TrustMarkStore;
	/** Trust marks this authority claims about itself. */
	trustMarks?: TrustMarkRef[];
	/** Mapping of trust mark type → authorized issuer entity IDs. */
	trustMarkIssuers?: Record<string, string[]>;
	/** Mapping of trust mark type → owner declaration (for delegated trust marks). */
	trustMarkOwners?: Record<string, TrustMarkOwner>;
	/** Pre-signed trust mark delegation JWTs, keyed by trust mark type. */
	trustMarkDelegations?: Record<string, string>;
	/** Superior authorities this entity is subordinate to. */
	authorityHints?: EntityId[];
	/** Trust anchors used for trust chain resolution (e.g., during registration). */
	trustAnchors?: TrustAnchorSet;
	/** TTL in seconds for the Entity Configuration JWT. */
	entityConfigurationTtlSeconds?: number;
	/** TTL in seconds for subordinate statement JWTs. */
	subordinateStatementTtlSeconds?: number;
	/** TTL in seconds for registration response JWTs. */
	registrationResponseTtlSeconds?: number;
	/** TTL in seconds for issued trust mark JWTs. */
	trustMarkTtlSeconds?: number;
	/** Federation-wide options (httpClient, clock, etc.). */
	options?: FederationOptions;
	/** Registration-specific callbacks. */
	registrationConfig?: {
		generateClientSecret?: (sub: EntityId) => Promise<string | undefined>;
	};
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
	rotateSigningKey(newKey: JWK): Promise<void>;
	handler(): (request: Request) => Promise<Response>;
}

/** Creates a federation authority server with all spec-defined endpoints. */
export function createAuthorityServer(config: AuthorityConfig): AuthorityServer {
	if (!isValidEntityId(config.entityId)) {
		throw new Error("entityId MUST be a valid HTTPS URL without query or fragment");
	}

	const ttlFields = [
		["entityConfigurationTtlSeconds", config.entityConfigurationTtlSeconds],
		["subordinateStatementTtlSeconds", config.subordinateStatementTtlSeconds],
		["registrationResponseTtlSeconds", config.registrationResponseTtlSeconds],
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
	const fedEntity = config.metadata.federation_entity as Record<string, unknown> | undefined;
	if (!fedEntity || typeof fedEntity.federation_fetch_endpoint !== "string") {
		throw new InvalidAuthorityConfig(
			"metadata.federation_entity.federation_fetch_endpoint is required for an Authority. Set it to the URL where this server serves the fetch endpoint.",
		);
	}
	if (typeof fedEntity.federation_list_endpoint !== "string") {
		throw new InvalidAuthorityConfig(
			"metadata.federation_entity.federation_list_endpoint is required for an Authority. Set it to the URL where this server serves the list endpoint.",
		);
	}

	// No metadata claim may carry a null leaf at any depth — omit the field instead.
	assertMetadataValuesNotNull(config.metadata as Record<string, unknown>);

	const base: HandlerContext = {
		entityId: config.entityId,
		keyStore: config.keyStore,
		subordinateStore: config.subordinateStore,
		metadata: config.metadata,
		getSigningKey: async () => {
			const managed = await config.keyStore.getSigningKey();
			const kid = managed.key.kid;
			if (!kid) throw new Error("Signing key must have a kid");
			return { key: managed.key, kid };
		},
	};
	const ctx: HandlerContext = Object.assign(
		base,
		...[
			config.authorityHints && { authorityHints: config.authorityHints },
			config.trustMarks && { trustMarks: config.trustMarks },
			config.trustMarkStore && { trustMarkStore: config.trustMarkStore },
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
			config.registrationResponseTtlSeconds !== undefined && {
				registrationResponseTtlSeconds: config.registrationResponseTtlSeconds,
			},
			config.trustMarkTtlSeconds !== undefined && {
				trustMarkTtlSeconds: config.trustMarkTtlSeconds,
			},
			config.options && { options: config.options },
			config.registrationConfig && { registrationConfig: config.registrationConfig },
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
	const registrationHandler = createRegistrationHandler(ctx);

	const routeMap = new Map<string, (request: Request) => Promise<Response>>([
		[WELL_KNOWN_OPENID_FEDERATION, ecHandler], // Entity Configuration — never authenticated
		[FederationEndpoint.Fetch, withAuth(fetchHandler, meta.federation_fetch_endpoint_auth_methods)],
		[FederationEndpoint.List, withAuth(listHandler, meta.federation_list_endpoint_auth_methods)],
		[
			FederationEndpoint.ExtendedList,
			withAuth(extendedListHandler, meta.federation_extended_list_endpoint_auth_methods),
		],
		[
			FederationEndpoint.HistoricalKeys,
			withAuth(historicalKeysHandler, meta.federation_historical_keys_endpoint_auth_methods),
		],
		[
			FederationEndpoint.TrustMarkStatus,
			withAuth(
				trustMarkStatusHandler,
				meta.federation_trust_mark_status_endpoint_auth_methods,
				"POST",
			),
		],
		[
			FederationEndpoint.TrustMarkList,
			withAuth(trustMarkListHandler, meta.federation_trust_mark_list_endpoint_auth_methods),
		],
		[
			FederationEndpoint.TrustMark,
			withAuth(trustMarkHandler, meta.federation_trust_mark_endpoint_auth_methods),
		],
		[
			FederationEndpoint.Resolve,
			withAuth(resolveHandler, meta.federation_resolve_endpoint_auth_methods),
		],
		[FederationEndpoint.Registration, registrationHandler],
	]);

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
			const record = await config.subordinateStore.get(sub);
			if (!record) {
				throw new Error(`Subordinate '${sub}' not found`);
			}
			return buildSubordinateStatement(ctx, record);
		},

		async listSubordinates(filter?: ListFilter): Promise<EntityId[]> {
			const page = await config.subordinateStore.list(filter);
			return page.items.map((r) => r.entityId);
		},

		async listSubordinatesExtended(
			params?: ExtendedListInProcessParams,
		): Promise<Result<ExtendedListInProcessResult, FederationError>> {
			const url = new URL(FederationEndpoint.ExtendedList, config.entityId);
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
			const baseUrl = config.entityId;
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
				new URL(FederationEndpoint.TrustMarkStatus, config.entityId).toString(),
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
			const url = new URL(FederationEndpoint.TrustMarkList, config.entityId);
			url.searchParams.set("trust_mark_type", trustMarkType);
			const req = new Request(url.toString());
			const res = await trustMarkListHandler(req);
			return res.json() as Promise<string[]>;
		},

		async issueTrustMark(sub: string, trustMarkType: string): Promise<string> {
			const url = new URL(FederationEndpoint.TrustMark, config.entityId);
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
			const { key: signingKey, kid } = await ctx.getSigningKey();
			const params: Parameters<typeof signTrustMarkDelegation>[0] = {
				issuer: config.entityId,
				subject,
				trustMarkType,
				privateKey: { ...signingKey, kid },
			};
			if (config.trustMarkTtlSeconds !== undefined) {
				params.ttlSeconds = config.trustMarkTtlSeconds;
			}
			return signTrustMarkDelegation(params);
		},

		async getHistoricalKeys(): Promise<string> {
			return buildHistoricalKeys(ctx);
		},

		async rotateSigningKey(newKey: JWK): Promise<void> {
			await rotateKey(config.keyStore, newKey);
		},

		handler(): (request: Request) => Promise<Response> {
			return router;
		},
	};
}
