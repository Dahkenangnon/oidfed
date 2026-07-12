/** Leaf entity class: Entity Configuration serving with caching and trust chain discovery. */
import {
	buildEntityConfigurationPayload,
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	discoverEntity as discoverEntityThroughTrustChain,
	type EntityContext,
	type EntityId,
	type EntityRole,
	type EntityStatementMetadata,
	entityId,
	errorResponse,
	type FederationKeyProvider,
	type FederationOptions,
	isValidEntityId,
	JwtTyp,
	jwtResponse,
	MediaType,
	nowSeconds,
	requireMethod,
	signEntityStatement,
	type TrustAnchorSet,
	type TrustMarkRef,
	validateFederationKeySet,
} from "@oidfed/core";

export interface LeafConfig {
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

function cloneMetadata(metadata: EntityStatementMetadata): Record<string, Record<string, unknown>> {
	const cloned: Record<string, Record<string, unknown>> = {};
	for (const [entityType, entityMetadata] of Object.entries(metadata)) {
		cloned[entityType] = { ...entityMetadata };
	}
	return cloned;
}

export class Leaf {
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

	private cachedJwt: string | null = null;
	private cachedExp: number | null = null;
	private inflight: Promise<string> | null = null;

	constructor(config: LeafConfig) {
		const rawEntityId = (
			config.entityId.endsWith("/") ? config.entityId.slice(0, -1) : config.entityId
		) as EntityId;

		if (!isValidEntityId(rawEntityId)) {
			throw new Error("entityId MUST be a valid HTTPS URL without query or fragment");
		}
		this.entityId = rawEntityId;
		this.config = config;

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
		const metadata = cloneMetadata(config.metadata);
		const context: EntityContext = {
			entityId: this.entityId,
			keyProvider: config.keyProvider,
			options: config.options,
			...(config.trustAnchors ? { trustAnchors: config.trustAnchors } : {}),
			authorityHints: config.authorityHints as readonly EntityId[],
		};

		if (config.roles) {
			for (const role of config.roles) {
				if (role.initialize) {
					role.initialize(context);
				}
				metadata[role.type] = {
					...(metadata[role.type] ?? {}),
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
		this.metadata = metadata;

		if (Object.keys(this.metadata).length === 0) {
			throw new Error("metadata MUST contain at least one Entity Type Identifier");
		}

		const fedEntity = this.metadata.federation_entity;
		if (fedEntity) {
			if ("federation_fetch_endpoint" in fedEntity) {
				throw new Error("Leaf entities MUST NOT publish federation_fetch_endpoint");
			}
			if ("federation_list_endpoint" in fedEntity) {
				throw new Error("Leaf entities MUST NOT publish federation_list_endpoint");
			}
		}

		const ttlSeconds = config.entityConfigurationTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS;
		if (ttlSeconds <= 0) {
			throw new Error("entityConfigurationTtlSeconds must be positive");
		}
	}

	private async buildEntityConfiguration(): Promise<string> {
		const keySet = await this.config.keyProvider.getFederationKeySet();
		validateFederationKeySet(keySet);
		const now = nowSeconds(this.config.options?.clock);
		const ttlSeconds =
			this.config.entityConfigurationTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS;
		const payload = buildEntityConfigurationPayload({
			entityId: this.entityId,
			jwks: keySet.jwks,
			metadata: this.metadata,
			authorityHints: this.config.authorityHints,
			...(this.config.trustAnchorHints ? { trustAnchorHints: this.config.trustAnchorHints } : {}),
			...(this.config.trustMarks ? { trustMarks: this.config.trustMarks } : {}),
			issuedAt: now,
			ttlSeconds,
		});

		const jwt = await signEntityStatement(payload, keySet.signer, {
			typ: JwtTyp.EntityStatement,
		});

		this.cachedJwt = jwt;
		this.cachedExp = payload.exp;
		return jwt;
	}

	async getEntityConfiguration(): Promise<string> {
		if (this.cachedJwt && !this.isEntityConfigurationExpired()) {
			return this.cachedJwt;
		}
		if (this.inflight) return this.inflight;
		this.inflight = this.buildEntityConfiguration().finally(() => {
			this.inflight = null;
		});
		return this.inflight;
	}

	isEntityConfigurationExpired(): boolean {
		if (this.cachedExp === null) return true;
		const now = nowSeconds(this.config.options?.clock);
		return now >= this.cachedExp;
	}

	async refreshEntityConfiguration(): Promise<string> {
		this.inflight = null;
		return this.buildEntityConfiguration();
	}

	async handleRequest(request: Request): Promise<Response> {
		const url = new URL(request.url);
		const pathname = url.pathname;

		// 1. Check role-specific routes first
		const roleHandler = this.routes.get(pathname);
		if (roleHandler) {
			return roleHandler(request);
		}

		// 2. Check standard well-known route
		const basePath = new URL(this.entityId).pathname.replace(/\/$/, "");
		const wellKnownPath = `${basePath}/.well-known/openid-federation`;
		if (pathname === wellKnownPath) {
			const methodError = requireMethod(request, "GET");
			if (methodError) return methodError;

			try {
				const jwt = await this.getEntityConfiguration();
				return jwtResponse(jwt, MediaType.EntityStatement);
			} catch (error) {
				this.config.options?.logger?.error("Failed to serve entity configuration", { error });
				return errorResponse(500, "server_error", "An internal error occurred");
			}
		}

		return errorResponse(404, "not_found", "Unknown endpoint");
	}
}
