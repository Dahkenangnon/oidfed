import type {
	DiscoveryResult,
	EntityContext,
	EntityId,
	EntityRole,
	FederationOptions,
	JWKSet,
	ReplayStore,
	Result,
	TrustAnchorSet,
} from "@oidfed/core";
import {
	assessEntity,
	authenticateClientAttestation,
	type ClientAttestationError,
	clientAttestationHeaders,
	createAttestationChallengeHandler,
	createClientAttestationProof,
	discoverEntity,
	type EntityAssessmentOptions,
	entityId,
	err,
	FederationErrorCode,
	federationError,
	fetchAttestationChallenge,
	readAttestationChallenge,
	runAsyncOperation,
	safeLogger,
	serializeClientAttestation,
	shortestChain,
	verifyClientAttestation,
} from "@oidfed/core";
import type { ClientAssertionOptions } from "./client-auth/assertion.js";
import { createClientAssertion } from "./client-auth/assertion.js";
import {
	assertPublicationMetadata,
	effectiveMetadata,
	type ProtocolEntityType,
} from "./metadata.js";
import type { ProtocolSigningKeyProvider } from "./protocol-keys.js";
import type { RegistrationAccreditationPolicy } from "./registration/accreditation.js";
import type { RegistrationProtocolAdapter } from "./registration/adapter-types.js";
import {
	type AutomaticRegistrationResult,
	automaticRegistration,
	type RequestDelivery,
} from "./registration/automatic.js";
import { type ExplicitRegistrationResult, explicitRegistration } from "./registration/explicit.js";
import {
	createExplicitRegistrationHandler,
	type ExplicitRegistrationHandlerConfig,
} from "./registration/handler.js";
import { assertNonEmptyTrustAnchors } from "./registration/helpers.js";
import {
	checkRegistrationAuthentication,
	type ProcessAutomaticRegistrationOptions,
	type ProcessedAutomaticRegistration,
	processAutomaticRegistration,
} from "./registration/process-automatic.js";
import { registrationProfile } from "./registration/profile.js";
import {
	createPushedAuthorizationRequest,
	type PreparedPushedAuthorizationRequest,
	type ProcessedPushedAuthorizationRequest,
	type ProcessPushedAuthorizationRequestOptions,
	type PushedAuthorizationProof,
	processPushedAuthorizationRequest,
} from "./registration/pushed.js";
import {
	effectiveRoleSchemas,
	OAuthResourceDocumentMetadataSchema,
	publicationRoleSchemas,
} from "./schemas/metadata.js";

export interface OidcRelyingPartyRoleConfig {
	readonly options?: FederationOptions;
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

abstract class ClientRole implements EntityRole {
	static createClientAttestationProof = createClientAttestationProof;
	static clientAttestationHeaders = clientAttestationHeaders;
	static serializeClientAttestation = serializeClientAttestation;
	static fetchAttestationChallenge = fetchAttestationChallenge;
	static readAttestationChallenge = readAttestationChallenge;
	async createPushedAuthorizationRequest(
		discovery: DiscoveryResult,
		parameters: Readonly<Record<string, unknown>>,
		proof: PushedAuthorizationProof,
		options: FederationOptions & { trustAnchors?: TrustAnchorSet } = {},
	): Promise<Result<PreparedPushedAuthorizationRequest>> {
		if (!this.context) throw new Error("Role has not been initialized.");
		const anchors = assertNonEmptyTrustAnchors(
			options.trustAnchors ?? this.config.trustAnchors ?? this.context.trustAnchors,
		);
		return createPushedAuthorizationRequest(
			discovery,
			{
				entityId: this.context.entityId as EntityId,
				protocolKeyProvider: this.config.protocolKeyProvider,
				authorityHints: (this.context.authorityHints ??
					this.config.authorityHints ??
					[]) as readonly [EntityId, ...EntityId[]],
				metadata: { [this.type]: this.composedMetadata ?? this.metadata },
				...(this.config.requestObjectTtlSeconds !== undefined
					? { requestObjectTtlSeconds: this.config.requestObjectTtlSeconds }
					: {}),
				...(this.config.includePeerTrustChain !== undefined
					? { includePeerTrustChain: this.config.includePeerTrustChain }
					: {}),
			},
			parameters,
			anchors,
			proof,
			{ ...this.context.options, ...this.config.options, ...options },
			this.profile,
		);
	}

	static assessEntity = assessProtocolEntity;
	assessEntity(
		target: string,
		type: ProtocolEntityType,
		options: EntityAssessmentOptions & { trustAnchors?: TrustAnchorSet } = {},
	) {
		return assessProtocolEntity(
			target,
			type,
			options.trustAnchors ?? this.config.trustAnchors ?? this.context?.trustAnchors ?? new Map(),
			{ ...this.context?.options, ...this.config.options, ...options },
		);
	}

	static createClientAssertion = createClientAssertion;

	abstract readonly type: "openid_relying_party" | "oauth_client";
	private get profile() {
		return registrationProfile(
			this.type === "oauth_client" ? "oauth_authorization_server" : "openid_provider",
		);
	}
	public readonly metadata: Record<string, unknown>;
	private context?: EntityContext;
	private composedMetadata?: Record<string, unknown>;

	constructor(public readonly config: OidcRelyingPartyRoleConfig) {
		this.metadata = structuredClone(config.metadata ?? {});
	}

	validateMetadata(metadata: Readonly<Record<string, unknown>>): void {
		assertPublicationMetadata(this.type, metadata);
		this.composedMetadata = structuredClone(metadata);
	}

	initialize(context: EntityContext): void {
		assertRoleOwner(this.context, context);
		this.context = context;
	}

	async createClientAssertion(audience: string, options?: ClientAssertionOptions): Promise<string> {
		if (!this.context) {
			throw new Error("Role has not been initialized.");
		}
		const signer = this.config.protocolKeyProvider.getClientAssertionSigner
			? await this.config.protocolKeyProvider.getClientAssertionSigner()
			: await this.config.protocolKeyProvider.getRequestObjectSigner();

		return createClientAssertion(this.context.entityId as EntityId, audience, signer, {
			...this.context.options,
			...this.config.options,
			...options,
		});
	}

	protected async registerAutomatically(
		params: {
			readonly serverEntityId: string;
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
		const opEntityId = params.serverEntityId as EntityId;
		const discoveryResult = await discoverEntity(
			opEntityId,
			trustAnchors,
			protocolDiscoveryOptions(this.profile.providerType, opEntityId, {
				...this.context.options,
				...this.config.options,
				...options,
			}),
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
				[this.type]: this.composedMetadata ?? this.metadata,
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
			{ ...this.context.options, ...this.config.options, ...options },
			"resolved",
			this.profile,
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
			protocolDiscoveryOptions(this.profile.providerType, opEntityId, {
				...this.context.options,
				...this.config.options,
				...options,
			}),
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
				[this.type]: this.composedMetadata ?? this.metadata,
			},
			...(this.config.includePeerTrustChain !== undefined
				? { includePeerTrustChain: this.config.includePeerTrustChain }
				: {}),
		};

		return explicitRegistration(
			discoveryResult.value,
			rpConfig,
			trustAnchors,
			{
				...this.context.options,
				...this.config.options,
				...options,
			},
			"resolved",
			this.profile,
		);
	}

	async createAuthorizationRequest(
		discovery: DiscoveryResult,
		authzRequestParams: Readonly<Record<string, unknown>>,
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
			...(options?.requestUri !== undefined ? { requestUri: options.requestUri } : {}),
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
				[this.type]: this.composedMetadata ?? this.metadata,
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
			{ ...this.context.options, ...this.config.options, ...options },
			"supplied",
			this.profile,
		);
	}
}

export class OidcRelyingPartyRole extends ClientRole {
	readonly type = "openid_relying_party";
	static parseMetadata(metadata: unknown) {
		return effectiveRoleSchemas.openid_relying_party.safeParse(metadata);
	}
	static parsePublicationMetadata(metadata: unknown) {
		return publicationRoleSchemas.openid_relying_party.safeParse(metadata);
	}
	automaticallyRegister(
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
		return this.registerAutomatically({ ...params, serverEntityId: params.opEntityId }, options);
	}
}

export interface OidcProviderRoleConfig extends RegistrationAccreditationPolicy {
	/** Opt in to adapter-issued read-only registration access; the host enforces token permissions. Default disabled. */
	readonly registrationManagement?: ExplicitRegistrationHandlerConfig["registrationManagement"];
	readonly options?: FederationOptions;
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

abstract class ProviderRole implements EntityRole {
	static verifyClientAttestation = verifyClientAttestation;
	static authenticateClientAttestation = authenticateClientAttestation;
	static createAttestationChallengeHandler = createAttestationChallengeHandler;
	async processPushedAuthorizationRequest(
		request: Request,
		options: Omit<
			ProcessPushedAuthorizationRequestOptions,
			"opEntityId" | "replayStore" | "providerMetadataType" | "providerMetadata"
		> & { readonly providerMetadata?: Readonly<Record<string, unknown>> } = {},
	): Promise<Result<ProcessedPushedAuthorizationRequest, ClientAttestationError>> {
		if (!this.context || !this.config.replayStore)
			throw new Error("Initialize the provider role with a replayStore.");
		const effectiveOptions = { ...this.context.options, ...this.config.options, ...options };
		effectiveOptions.signal ??= request.signal;
		const result = await processPushedAuthorizationRequest(
			request,
			assertNonEmptyTrustAnchors(this.config.trustAnchors ?? this.context.trustAnchors),
			{
				...effectiveOptions,
				opEntityId: this.context.entityId as EntityId,
				replayStore: this.config.replayStore,
				providerMetadataType: this.type,
				providerMetadata: options.providerMetadata ?? this.metadata,
				...(this.config.trustMarkRequirements
					? { trustMarkRequirements: structuredClone(this.config.trustMarkRequirements) }
					: {}),
				...(this.config.beforeRegistration
					? { beforeRegistration: this.config.beforeRegistration }
					: {}),
			},
		);
		try {
			return await this.persistAutomaticRegistration(result, effectiveOptions);
		} catch {
			return err(
				federationError(FederationErrorCode.ServerError, "PAR registration persistence failed"),
			);
		}
	}

	static assessEntity = assessProtocolEntity;
	assessEntity(
		target: string,
		type: ProtocolEntityType,
		options: EntityAssessmentOptions & { trustAnchors?: TrustAnchorSet } = {},
	) {
		return assessProtocolEntity(
			target,
			type,
			options.trustAnchors ?? this.config.trustAnchors ?? this.context?.trustAnchors ?? new Map(),
			{ ...this.context?.options, ...this.config.options, ...options },
		);
	}

	abstract readonly type: "openid_provider" | "oauth_authorization_server";
	public readonly metadata: Record<string, unknown> = {};
	public readonly routes = new Map<string, (request: Request) => Promise<Response>>();
	private context?: EntityContext;

	constructor(public readonly config: OidcProviderRoleConfig) {
		this.metadata = structuredClone(config.metadata ?? {});
	}

	validateMetadata(metadata: Readonly<Record<string, unknown>>): void {
		// Federation §12.2 requires both the endpoint and its explicit capability.
		const methods = metadata.client_registration_types_supported;
		if (
			!Array.isArray(methods) ||
			!methods.every((method) => typeof method === "string") ||
			!methods.includes("explicit")
		)
			throw new TypeError(
				"An installed registration endpoint requires client_registration_types_supported to include explicit",
			);
		assertPublicationMetadata(this.type, metadata);
	}

	initialize(context: EntityContext): void {
		assertRoleOwner(this.context, context);
		this.context = context;
		const registrationPath = this.config.registrationPath ?? "/registration";
		const registrationUrl = new URL(registrationPath, context.entityId).toString();
		const trustAnchors = assertNonEmptyTrustAnchors(
			this.config.trustAnchors ?? context.trustAnchors,
		);

		this.metadata.federation_registration_endpoint = registrationUrl;

		const handler = createExplicitRegistrationHandler({
			opEntityId: context.entityId as EntityId,
			...(this.config.trustMarkRequirements
				? { trustMarkRequirements: structuredClone(this.config.trustMarkRequirements) }
				: {}),
			...(this.config.beforeRegistration
				? { beforeRegistration: this.config.beforeRegistration }
				: {}),
			providerMetadataType: this.type,
			...(this.config.registrationManagement !== undefined
				? { registrationManagement: this.config.registrationManagement }
				: {}),
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
			options: { ...context.options, ...this.config.options },
		});

		this.routes.set(registrationPath, handler);
	}

	async processAutomaticRegistration(
		requestObjectJwt: string,
		options?: Omit<
			ProcessAutomaticRegistrationOptions,
			"opEntityId" | "replayStore" | "providerMetadataType"
		>,
	): Promise<Result<ProcessedAutomaticRegistration, ClientAttestationError>> {
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
		const effectiveOptions = { ...this.context.options, ...this.config.options, ...options };
		const result = await processAutomaticRegistration(requestObjectJwt, trustAnchors, {
			...effectiveOptions,
			...(this.config.trustMarkRequirements
				? { trustMarkRequirements: structuredClone(this.config.trustMarkRequirements) }
				: {}),
			...(this.config.beforeRegistration
				? { beforeRegistration: this.config.beforeRegistration }
				: {}),
			opEntityId: this.context.entityId as EntityId,
			replayStore,
			providerMetadataType: this.type,
			providerMetadata: options?.providerMetadata ?? this.metadata,
		});

		return this.persistAutomaticRegistration(result, effectiveOptions);
	}
	private async persistAutomaticRegistration<T extends ProcessedAutomaticRegistration>(
		result: Result<T, ClientAttestationError>,
		effectiveOptions: FederationOptions,
	): Promise<Result<T, ClientAttestationError>> {
		if (!result.ok) return result;

		const logger = safeLogger(effectiveOptions.logger);
		if (this.config.registrationProtocolAdapter?.validateClientMetadata) {
			let validationResult: Awaited<
				ReturnType<RegistrationProtocolAdapter["validateClientMetadata"]>
			>;
			try {
				const adapter = this.config.registrationProtocolAdapter;
				validationResult = await runAsyncOperation(
					(signal) =>
						adapter.validateClientMetadata(structuredClone(result.value.resolvedRpMetadata), {
							signal,
						}),
					effectiveOptions,
				);
			} catch (error) {
				logger?.error("RP metadata validation failed in registrationProtocolAdapter");
				throw error;
			}
			if (!validationResult.ok) {
				logger?.warn("RP metadata was rejected by registrationProtocolAdapter");
				return err(
					federationError(FederationErrorCode.InvalidMetadata, validationResult.error.description),
				);
			}
		}

		const current = checkRegistrationAuthentication(result.value, effectiveOptions);
		if (!current.ok) return current;
		if (this.config.onRegistration) {
			// Persist the protocol keys actually used for §12.1.1.1.2 verification.
			try {
				const onRegistration = this.config.onRegistration;
				await runAsyncOperation(
					() =>
						onRegistration(
							result.value.rpEntityId,
							structuredClone({
								...result.value.resolvedRpMetadata,
								jwks: { keys: result.value.protocolKeys.keys },
							}),
						),
					effectiveOptions,
				);
			} catch (error) {
				logger?.error("Automatic Client Registration failed in onRegistration");
				throw error;
			}
		}

		logger?.info("Automatic Client Registration completed");
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

export class OidcProviderRole extends ProviderRole {
	readonly type = "openid_provider";
	static parseMetadata(metadata: unknown) {
		return effectiveRoleSchemas.openid_provider.safeParse(metadata);
	}
	static parsePublicationMetadata(metadata: unknown) {
		return publicationRoleSchemas.openid_provider.safeParse(metadata);
	}
}

export type OAuthClientRoleConfig = OidcRelyingPartyRoleConfig;
export class OAuthClientRole extends ClientRole {
	readonly type = "oauth_client";
	static parseMetadata(metadata: unknown) {
		return effectiveRoleSchemas.oauth_client.safeParse(metadata);
	}
	static parsePublicationMetadata(metadata: unknown) {
		return publicationRoleSchemas.oauth_client.safeParse(metadata);
	}
	automaticallyRegister(
		params: {
			readonly authorizationServerEntityId: string;
			readonly redirect_uri: string;
			readonly scope?: string;
			readonly state?: string;
			readonly nonce?: string;
			readonly requestDelivery?: RequestDelivery;
			readonly requestUri?: string;
		},
		options?: CreateAuthorizationRequestOptions,
	): Promise<Result<AutomaticRegistrationResult>> {
		return this.registerAutomatically(
			{ ...params, serverEntityId: params.authorizationServerEntityId },
			options,
		);
	}
}

export type OAuthAuthorizationServerRoleConfig = OidcProviderRoleConfig;
export class OAuthAuthorizationServerRole extends ProviderRole {
	readonly type = "oauth_authorization_server";
	static parseMetadata(metadata: unknown) {
		return effectiveRoleSchemas.oauth_authorization_server.safeParse(metadata);
	}
	static parsePublicationMetadata(metadata: unknown) {
		return publicationRoleSchemas.oauth_authorization_server.safeParse(metadata);
	}
}

export interface OAuthResourceRoleConfig {
	readonly trustAnchors?: TrustAnchorSet;
	readonly options?: FederationOptions;
	readonly metadata?: Record<string, unknown>;
	readonly jwks?: JWKSet;
}

export class OAuthResourceRole implements EntityRole {
	static assessEntity = assessProtocolEntity;
	assessEntity(
		target: string,
		type: ProtocolEntityType,
		options: EntityAssessmentOptions & { trustAnchors?: TrustAnchorSet } = {},
	) {
		return assessProtocolEntity(
			target,
			type,
			options.trustAnchors ?? this.config.trustAnchors ?? this.context?.trustAnchors ?? new Map(),
			{ ...this.context?.options, ...this.config.options, ...options },
		);
	}

	static parseMetadata(metadata: unknown, options: { profile?: "federation" | "rfc9728" } = {}) {
		return (
			options.profile === "rfc9728"
				? OAuthResourceDocumentMetadataSchema
				: effectiveRoleSchemas.oauth_resource
		).safeParse(metadata);
	}
	static parsePublicationMetadata(metadata: unknown) {
		return publicationRoleSchemas.oauth_resource.safeParse(metadata);
	}
	validateMetadata(metadata: Readonly<Record<string, unknown>>): void {
		assertPublicationMetadata(this.type, metadata);
	}

	public readonly type = "oauth_resource";
	public readonly metadata: Record<string, unknown> = {};
	public readonly routes = new Map<string, (request: Request) => Promise<Response>>();

	constructor(public readonly config: OAuthResourceRoleConfig) {
		this.metadata = structuredClone(config.metadata ?? {});
		if (config.jwks) {
			this.metadata.jwks = structuredClone(config.jwks);
		}
	}

	private context?: EntityContext;
	initialize(context: EntityContext): void {
		assertRoleOwner(this.context, context);
		this.context = context;
	}
}

function assertRoleOwner(current: EntityContext | undefined, context: EntityContext): void {
	if (current && current !== context)
		throw new Error("Create a separate OIDC/OAuth role instance for each host");
}

async function assessProtocolEntity(
	target: string,
	type: ProtocolEntityType,
	anchors: TrustAnchorSet,
	options: EntityAssessmentOptions = {},
) {
	const assessed = await assessEntity(
		entityId(target),
		anchors,
		options.mode === "resolver"
			? options
			: { ...options, ...protocolDiscoveryOptions(type, target, options) },
	);
	if (!assessed.ok) return assessed;
	const metadata = effectiveMetadata(type, assessed.value.resolvedMetadata[type], target);
	return metadata.ok ? assessed : metadata;
}

function protocolDiscoveryOptions(
	type: ProtocolEntityType,
	target: string,
	options: FederationOptions,
): FederationOptions {
	return {
		...options,
		chainSelection: (chains) => {
			// Accreditation issuers need not implement the subject's application protocol (§17.5).
			const eligible = chains.filter(
				(chain) =>
					chain.entityId !== target ||
					effectiveMetadata(type, chain.resolvedMetadata[type], target).ok,
			);
			if (!eligible.length) throw new Error("No chain supplies valid protocol metadata");
			return (options.chainSelection ?? shortestChain)(eligible);
		},
	};
}
