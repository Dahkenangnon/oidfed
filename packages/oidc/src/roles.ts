import type {
	DiscoveryResult,
	EntityContext,
	EntityId,
	EntityRole,
	FederationError,
	FederationOptions,
	JWKSet,
	ReplayStore,
	Result,
	TrustAnchorSet,
} from "@oidfed/core";
import { discoverEntity, err, FederationErrorCode, federationError } from "@oidfed/core";
import type { ClientAssertionOptions } from "./client-auth/assertion.js";
import { createClientAssertion } from "./client-auth/assertion.js";
import type { ProtocolSigningKeyProvider } from "./protocol-keys.js";
import type { RegistrationProtocolAdapter } from "./registration/adapter-types.js";
import {
	type AutomaticRegistrationResult,
	automaticRegistration,
	type RequestDelivery,
} from "./registration/automatic.js";
import { type ExplicitRegistrationResult, explicitRegistration } from "./registration/explicit.js";
import { createExplicitRegistrationHandler } from "./registration/handler.js";
import { assertNonEmptyTrustAnchors } from "./registration/helpers.js";
import {
	type ProcessAutomaticRegistrationOptions,
	type ProcessedRegistration,
	processAutomaticRegistration,
} from "./registration/process-automatic.js";

export interface OidcRelyingPartyRoleConfig {
	readonly protocolKeyProvider: ProtocolSigningKeyProvider;
	readonly metadata?: Record<string, unknown>;
	readonly requestObjectTtlSeconds?: number;
	readonly includePeerTrustChain?: boolean;
	readonly requestDelivery?: RequestDelivery;
	readonly requestUri?: string;
	readonly trustAnchors?: TrustAnchorSet;
	readonly authorityHints?: readonly EntityId[];
}

export interface CreateAuthorizationRequestOptions extends FederationOptions {
	readonly requestDelivery?: RequestDelivery;
	readonly requestUri?: string;
	readonly includePeerTrustChain?: boolean;
	readonly requestObjectTtlSeconds?: number;
	readonly trustAnchors?: TrustAnchorSet;
}

export class OidcRelyingPartyRole implements EntityRole {
	static createClientAssertion = createClientAssertion;

	public readonly type = "openid_relying_party";
	public readonly metadata: Record<string, unknown>;
	private context?: EntityContext;

	constructor(public readonly config: OidcRelyingPartyRoleConfig) {
		this.metadata = config.metadata ?? {};
	}

	initialize(context: EntityContext): void {
		this.context = context;
	}

	async createClientAssertion(audience: string, options?: ClientAssertionOptions): Promise<string> {
		if (!this.context) {
			throw new Error("Role has not been initialized.");
		}
		const signer = this.config.protocolKeyProvider.getClientAssertionSigner
			? await this.config.protocolKeyProvider.getClientAssertionSigner()
			: await this.config.protocolKeyProvider.getRequestObjectSigner();

		return createClientAssertion(
			this.context.entityId as EntityId,
			audience,
			signer,
			options ?? this.context.options,
		);
	}

	async automaticallyRegister(
		params: {
			readonly opEntityId: string;
			readonly redirect_uri: string;
			readonly scope?: string;
			readonly state?: string;
			readonly nonce?: string;
			readonly requestDelivery?: RequestDelivery;
			readonly requestUri?: string;
		},
		options?: CreateAuthorizationRequestOptions,
	): Promise<Result<AutomaticRegistrationResult>> {
		if (!this.context) {
			throw new Error(
				"Role has not been initialized. Ensure it is passed to an Entity constructor.",
			);
		}
		const trustAnchors =
			options?.trustAnchors ?? this.config.trustAnchors ?? this.context.trustAnchors;
		if (!trustAnchors) {
			throw new Error("No trustAnchors configured. Set them in config, options, or context.");
		}
		const opEntityId = params.opEntityId as EntityId;
		const discoveryResult = await discoverEntity(
			opEntityId,
			trustAnchors,
			options ?? this.context.options,
		);
		if (!discoveryResult.ok) {
			return err(discoveryResult.error);
		}

		const authzRequestParams: Record<string, string> = {
			client_id: this.context.entityId,
			response_type: "code",
			redirect_uri: params.redirect_uri,
			...(params.scope ? { scope: params.scope } : {}),
			...(params.state ? { state: params.state } : {}),
			...(params.nonce ? { nonce: params.nonce } : {}),
		};

		const overrideConfig = {
			...this.config,
			...(params.requestDelivery ? { requestDelivery: params.requestDelivery } : {}),
			...(options?.requestDelivery ? { requestDelivery: options.requestDelivery } : {}),
			...(params.requestUri ? { requestUri: params.requestUri } : {}),
			...(options?.requestUri ? { requestUri: options.requestUri } : {}),
			...(options?.includePeerTrustChain !== undefined
				? { includePeerTrustChain: options.includePeerTrustChain }
				: {}),
			...(options?.requestObjectTtlSeconds !== undefined
				? { requestObjectTtlSeconds: options.requestObjectTtlSeconds }
				: {}),
		};

		const rpConfig = {
			entityId: this.context.entityId as EntityId,
			protocolKeyProvider: overrideConfig.protocolKeyProvider,
			authorityHints: (this.context.authorityHints ??
				this.config.authorityHints ??
				[]) as readonly [EntityId, ...EntityId[]],
			metadata: {
				[this.type]: this.metadata,
			},
			...(overrideConfig.requestObjectTtlSeconds !== undefined
				? { requestObjectTtlSeconds: overrideConfig.requestObjectTtlSeconds }
				: {}),
			...(overrideConfig.includePeerTrustChain !== undefined
				? { includePeerTrustChain: overrideConfig.includePeerTrustChain }
				: {}),
			...(overrideConfig.requestDelivery !== undefined
				? { requestDelivery: overrideConfig.requestDelivery }
				: {}),
			...(overrideConfig.requestUri !== undefined ? { requestUri: overrideConfig.requestUri } : {}),
		};

		return automaticRegistration(
			discoveryResult.value,
			rpConfig,
			authzRequestParams,
			trustAnchors,
			options ?? this.context.options,
		);
	}

	async explicitlyRegister(
		opEntityId: string,
		options?: FederationOptions & { readonly trustAnchors?: TrustAnchorSet },
	): Promise<Result<ExplicitRegistrationResult>> {
		if (!this.context) {
			throw new Error(
				"Role has not been initialized. Ensure it is passed to an Entity constructor.",
			);
		}
		const trustAnchors =
			options?.trustAnchors ?? this.config.trustAnchors ?? this.context.trustAnchors;
		if (!trustAnchors) {
			throw new Error("No trustAnchors configured. Set them in config, options, or context.");
		}
		const discoveryResult = await discoverEntity(
			opEntityId as EntityId,
			trustAnchors,
			options ?? this.context.options,
		);
		if (!discoveryResult.ok) {
			return err(discoveryResult.error);
		}

		const rpConfig = {
			entityId: this.context.entityId as EntityId,
			keyProvider: this.context.keyProvider,
			authorityHints: (this.context.authorityHints ??
				this.config.authorityHints ??
				[]) as readonly [EntityId, ...EntityId[]],
			metadata: {
				[this.type]: this.metadata,
			},
			...(this.config.includePeerTrustChain !== undefined
				? { includePeerTrustChain: this.config.includePeerTrustChain }
				: {}),
		};

		return explicitRegistration(
			discoveryResult.value,
			rpConfig,
			trustAnchors,
			options ?? this.context.options,
		);
	}

	async createAuthorizationRequest(
		discovery: DiscoveryResult,
		authzRequestParams: Record<string, string>,
		trustAnchors: TrustAnchorSet,
		options?: CreateAuthorizationRequestOptions,
	): Promise<Result<AutomaticRegistrationResult>> {
		if (!this.context) {
			throw new Error(
				"Role has not been initialized. Ensure it is passed to an Entity constructor.",
			);
		}
		const overrideConfig = {
			...this.config,
			...(options?.requestDelivery ? { requestDelivery: options.requestDelivery } : {}),
		};
		const rpConfig = {
			entityId: this.context.entityId as EntityId,
			protocolKeyProvider: overrideConfig.protocolKeyProvider,
			authorityHints: (this.context.authorityHints ??
				this.config.authorityHints ??
				[]) as readonly [EntityId, ...EntityId[]],
			metadata: {
				[this.type]: this.metadata,
			},
			...(overrideConfig.requestObjectTtlSeconds !== undefined
				? { requestObjectTtlSeconds: overrideConfig.requestObjectTtlSeconds }
				: {}),
			...(overrideConfig.includePeerTrustChain !== undefined
				? { includePeerTrustChain: overrideConfig.includePeerTrustChain }
				: {}),
			...(overrideConfig.requestDelivery !== undefined
				? { requestDelivery: overrideConfig.requestDelivery }
				: {}),
			...(overrideConfig.requestUri !== undefined ? { requestUri: overrideConfig.requestUri } : {}),
		};
		return automaticRegistration(
			discovery,
			rpConfig,
			authzRequestParams,
			options?.trustAnchors ?? trustAnchors,
			options ?? this.context.options,
		);
	}
}

export interface OidcProviderRoleConfig {
	readonly registrationPath?: string;
	readonly metadata?: Record<string, unknown>;
	readonly trustAnchors?: TrustAnchorSet;
	readonly registrationResponseTtlSeconds?: number;
	readonly registrationProtocolAdapter?: RegistrationProtocolAdapter;
	readonly generateClientSecret?: (sub: EntityId) => Promise<string | undefined>;
	/** Late pre-commit hook called after validation and response preparation, before `onRegistration`. */
	readonly onRegistrationInvalidation?: (sub: EntityId) => Promise<void>;
	readonly replayStore?: ReplayStore;
	readonly onRegistration?: (
		sub: EntityId,
		clientMetadata: Record<string, unknown>,
		clientSecret?: string,
	) => Promise<void>;
}

export class OidcProviderRole implements EntityRole {
	public readonly type = "openid_provider";
	public readonly metadata: Record<string, unknown> = {};
	public readonly routes = new Map<string, (request: Request) => Promise<Response>>();
	private context?: EntityContext;

	constructor(public readonly config: OidcProviderRoleConfig) {
		this.metadata = config.metadata ?? {};
	}

	initialize(context: EntityContext): void {
		this.context = context;
		const registrationPath = this.config.registrationPath ?? "/registration";
		const registrationUrl = new URL(registrationPath, context.entityId).toString();
		const trustAnchors = assertNonEmptyTrustAnchors(
			this.config.trustAnchors ?? context.trustAnchors,
		);

		this.metadata.federation_registration_endpoint = registrationUrl;

		const handler = createExplicitRegistrationHandler({
			opEntityId: context.entityId as EntityId,
			keyProvider: context.keyProvider,
			trustAnchors,
			...(this.config.registrationResponseTtlSeconds !== undefined
				? { registrationResponseTtlSeconds: this.config.registrationResponseTtlSeconds }
				: {}),
			...(this.config.registrationProtocolAdapter !== undefined
				? { registrationProtocolAdapter: this.config.registrationProtocolAdapter }
				: {}),
			...(this.config.generateClientSecret !== undefined
				? { generateClientSecret: this.config.generateClientSecret }
				: {}),
			...(this.config.onRegistrationInvalidation !== undefined
				? { onRegistrationInvalidation: this.config.onRegistrationInvalidation }
				: {}),
			...(this.config.onRegistration !== undefined
				? { onRegistration: this.config.onRegistration }
				: {}),
			...(context.options !== undefined ? { options: context.options } : {}),
		});

		this.routes.set(registrationPath, handler);
	}

	async processAutomaticRegistration(
		requestObjectJwt: string,
		options?: Omit<ProcessAutomaticRegistrationOptions, "opEntityId" | "replayStore">,
	): Promise<Result<ProcessedRegistration, FederationError>> {
		if (!this.context) {
			throw new Error("Provider role is not initialized.");
		}
		const replayStore = this.config.replayStore;
		if (!replayStore) {
			throw new Error("replayStore is required to process automatic registration.");
		}
		const trustAnchors = assertNonEmptyTrustAnchors(
			this.config.trustAnchors ?? this.context.trustAnchors,
		);
		const result = await processAutomaticRegistration(requestObjectJwt, trustAnchors, {
			opEntityId: this.context.entityId as EntityId,
			replayStore,
			...options,
		});

		if (!result.ok) return result;

		if (this.config.registrationProtocolAdapter?.validateClientMetadata) {
			const validationResult = await this.config.registrationProtocolAdapter.validateClientMetadata(
				result.value.resolvedRpMetadata,
			);
			if (!validationResult.ok) {
				return err(
					federationError(FederationErrorCode.InvalidMetadata, validationResult.error.description),
				);
			}
		}

		if (this.config.onRegistration) {
			const federationJwks = result.value.trustChain.statements[0]?.payload.jwks;
			const jwks = result.value.resolvedRpMetadata.jwks ?? federationJwks ?? { keys: [] };
			await this.config.onRegistration(result.value.rpEntityId, {
				...result.value.resolvedRpMetadata,
				jwks,
			});
		}

		return result;
	}

	async processExplicitRegistration(request: Request): Promise<Response> {
		const registrationPath = this.config.registrationPath ?? "/registration";
		const handler = this.routes.get(registrationPath);
		if (!handler) {
			throw new Error("Explicit registration handler is not mounted.");
		}
		return handler(request);
	}
}

export interface OAuthClientRoleConfig {
	readonly protocolKeyProvider: ProtocolSigningKeyProvider;
	readonly metadata?: Record<string, unknown>;
	readonly requestObjectTtlSeconds?: number;
	readonly includePeerTrustChain?: boolean;
	readonly requestDelivery?: RequestDelivery;
	readonly requestUri?: string;
}

export class OAuthClientRole implements EntityRole {
	static createClientAssertion = createClientAssertion;

	public readonly type = "oauth_client";
	public readonly metadata: Record<string, unknown>;
	private context?: EntityContext;

	constructor(public readonly config: OAuthClientRoleConfig) {
		this.metadata = config.metadata ?? {};
	}

	initialize(context: EntityContext): void {
		this.context = context;
	}

	async createAuthorizationRequest(
		discovery: DiscoveryResult,
		authzRequestParams: Record<string, string>,
		trustAnchors: TrustAnchorSet,
		options?: FederationOptions,
	): Promise<Result<AutomaticRegistrationResult>> {
		if (!this.context) {
			throw new Error(
				"Role has not been initialized. Ensure it is passed to an Entity constructor.",
			);
		}
		const rpConfig = {
			entityId: this.context.entityId as EntityId,
			protocolKeyProvider: this.config.protocolKeyProvider,
			authorityHints: (this.context.authorityHints ?? []) as readonly [EntityId, ...EntityId[]],
			metadata: {
				[this.type]: this.metadata,
			},
			...(this.config.requestObjectTtlSeconds !== undefined
				? { requestObjectTtlSeconds: this.config.requestObjectTtlSeconds }
				: {}),
			...(this.config.includePeerTrustChain !== undefined
				? { includePeerTrustChain: this.config.includePeerTrustChain }
				: {}),
			...(this.config.requestDelivery !== undefined
				? { requestDelivery: this.config.requestDelivery }
				: {}),
			...(this.config.requestUri !== undefined ? { requestUri: this.config.requestUri } : {}),
		};
		return automaticRegistration(
			discovery,
			rpConfig,
			authzRequestParams,
			trustAnchors,
			options ?? this.context.options,
		);
	}
}

export interface OAuthAuthorizationServerRoleConfig {
	readonly registrationPath?: string;
	readonly metadata?: Record<string, unknown>;
	readonly trustAnchors?: TrustAnchorSet;
	readonly registrationResponseTtlSeconds?: number;
	readonly registrationProtocolAdapter?: RegistrationProtocolAdapter;
	readonly generateClientSecret?: (sub: EntityId) => Promise<string | undefined>;
	/** Late pre-commit hook called after validation and response preparation. */
	readonly onRegistrationInvalidation?: (sub: EntityId) => Promise<void>;
}

export class OAuthAuthorizationServerRole implements EntityRole {
	public readonly type = "oauth_authorization_server";
	public readonly metadata: Record<string, unknown> = {};
	public readonly routes = new Map<string, (request: Request) => Promise<Response>>();

	constructor(public readonly config: OAuthAuthorizationServerRoleConfig) {
		this.metadata = config.metadata ?? {};
	}

	initialize(context: EntityContext): void {
		const registrationPath = this.config.registrationPath ?? "/registration";
		const registrationUrl = new URL(registrationPath, context.entityId).toString();
		const trustAnchors = assertNonEmptyTrustAnchors(
			this.config.trustAnchors ?? context.trustAnchors,
		);

		this.metadata.federation_registration_endpoint = registrationUrl;

		const handler = createExplicitRegistrationHandler({
			opEntityId: context.entityId as EntityId,
			keyProvider: context.keyProvider,
			trustAnchors,
			...(this.config.registrationResponseTtlSeconds !== undefined
				? { registrationResponseTtlSeconds: this.config.registrationResponseTtlSeconds }
				: {}),
			...(this.config.registrationProtocolAdapter !== undefined
				? { registrationProtocolAdapter: this.config.registrationProtocolAdapter }
				: {}),
			...(this.config.generateClientSecret !== undefined
				? { generateClientSecret: this.config.generateClientSecret }
				: {}),
			...(this.config.onRegistrationInvalidation !== undefined
				? { onRegistrationInvalidation: this.config.onRegistrationInvalidation }
				: {}),
			...(context.options !== undefined ? { options: context.options } : {}),
		});

		this.routes.set(registrationPath, handler);
	}
}

export interface OAuthResourceRoleConfig {
	readonly metadata?: Record<string, unknown>;
	readonly jwks?: JWKSet;
}

export class OAuthResourceRole implements EntityRole {
	public readonly type = "oauth_resource";
	public readonly metadata: Record<string, unknown> = {};
	public readonly routes = new Map<string, (request: Request) => Promise<Response>>();

	constructor(public readonly config: OAuthResourceRoleConfig) {
		this.metadata = config.metadata ?? {};
		if (config.jwks) {
			this.metadata.jwks = config.jwks;
		}
	}

	initialize(_context: EntityContext): void {}
}
