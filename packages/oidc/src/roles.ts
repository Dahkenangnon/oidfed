import type {
	DiscoveryResult,
	EntityContext,
	EntityId,
	EntityRole,
	FederationOptions,
	Result,
	TrustAnchorSet,
} from "@oidfed/core";
import type { OidcProtocolKeyProvider } from "./protocol-keys.js";
import {
	type AutomaticRegistrationResult,
	automaticRegistration,
	type RequestDelivery,
} from "./registration/automatic.js";
import { createExplicitRegistrationHandler } from "./registration/handler.js";

export interface FedOidcClientConfig {
	readonly protocolKeyProvider: OidcProtocolKeyProvider;
	readonly metadata?: Record<string, unknown>;
	readonly requestObjectTtlSeconds?: number;
	readonly includePeerTrustChain?: boolean;
	readonly requestDelivery?: RequestDelivery;
	readonly requestUri?: string;
}

export class FedOidcClient implements EntityRole {
	public readonly type = "openid_relying_party";
	public readonly metadata: Record<string, unknown>;
	private context?: EntityContext;

	constructor(public readonly config: FedOidcClientConfig) {
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
			authorityHints: ((this.context as any).authorityHints ?? []) as readonly [
				EntityId,
				...EntityId[],
			],
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

export interface FedOidcProviderConfig {
	readonly registrationPath?: string;
	readonly metadata?: Record<string, unknown>;
	readonly registrationResponseTtlSeconds?: number;
	readonly registrationProtocolAdapter?: any;
	readonly generateClientSecret?: (sub: EntityId) => Promise<string | undefined>;
	readonly onRegistrationInvalidation?: (sub: EntityId) => Promise<void>;
}

export class FedOidcProvider implements EntityRole {
	public readonly type = "openid_provider";
	public readonly metadata: Record<string, unknown> = {};
	public readonly routes = new Map<string, (request: Request) => Promise<Response>>();
	private context?: EntityContext;

	constructor(public readonly config: FedOidcProviderConfig) {
		this.metadata = config.metadata ?? {};
	}

	initialize(context: EntityContext): void {
		this.context = context;
		const registrationPath = this.config.registrationPath ?? "/registration";
		const registrationUrl = new URL(registrationPath, context.entityId).toString();

		this.metadata.federation_registration_endpoint = registrationUrl;

		const handler = createExplicitRegistrationHandler({
			opEntityId: context.entityId as EntityId,
			keyProvider: context.keyProvider,
			trustAnchors: (context as any).trustAnchors,
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

export interface FedOauthClientConfig {
	readonly protocolKeyProvider: OidcProtocolKeyProvider;
	readonly metadata?: Record<string, unknown>;
	readonly requestObjectTtlSeconds?: number;
	readonly includePeerTrustChain?: boolean;
	readonly requestDelivery?: RequestDelivery;
	readonly requestUri?: string;
}

export class FedOauthClient implements EntityRole {
	public readonly type = "oauth_client";
	public readonly metadata: Record<string, unknown>;
	private context?: EntityContext;

	constructor(public readonly config: FedOauthClientConfig) {
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
			authorityHints: ((this.context as any).authorityHints ?? []) as readonly [
				EntityId,
				...EntityId[],
			],
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

export interface FedOauthProviderConfig {
	readonly registrationPath?: string;
	readonly metadata?: Record<string, unknown>;
	readonly registrationResponseTtlSeconds?: number;
	readonly registrationProtocolAdapter?: any;
	readonly generateClientSecret?: (sub: EntityId) => Promise<string | undefined>;
	readonly onRegistrationInvalidation?: (sub: EntityId) => Promise<void>;
}

export class FedOauthProvider implements EntityRole {
	public readonly type = "oauth_authorization_server";
	public readonly metadata: Record<string, unknown> = {};
	public readonly routes = new Map<string, (request: Request) => Promise<Response>>();
	private context?: EntityContext;

	constructor(public readonly config: FedOauthProviderConfig) {
		this.metadata = config.metadata ?? {};
	}

	initialize(context: EntityContext): void {
		this.context = context;
		const registrationPath = this.config.registrationPath ?? "/registration";
		const registrationUrl = new URL(registrationPath, context.entityId).toString();

		this.metadata.federation_registration_endpoint = registrationUrl;

		const handler = createExplicitRegistrationHandler({
			opEntityId: context.entityId as EntityId,
			keyProvider: context.keyProvider,
			trustAnchors: (context as any).trustAnchors,
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
