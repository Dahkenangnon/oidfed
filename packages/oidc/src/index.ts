// @oidfed/oidc — OIDC/OAuth2 protocol layer for OpenID Federation

// Re-export common core types
export type {
	EntityId,
	FederationError,
	FederationOptions,
	Result,
	TrustAnchorSet,
} from "@oidfed/core";

// Client authentication
export type { ClientAssertionOptions } from "./client-auth/assertion.js";

// Protocol keys
export {
	type OidcProtocolKeyProvider,
	StaticOidcProtocolKeyProvider,
} from "./protocol-keys.js";

// Registration types
export type {
	RegistrationProtocolAdapter,
	RegistrationProtocolAdapterContext,
} from "./registration/adapter-types.js";
export type {
	AutomaticRegistrationConfig,
	AutomaticRegistrationResult,
	RequestDelivery,
} from "./registration/automatic.js";
export type {
	ExplicitRegistrationConfig,
	ExplicitRegistrationResult,
} from "./registration/explicit.js";
export type { ExplicitRegistrationHandlerConfig } from "./registration/handler.js";
export type {
	ProcessAutomaticRegistrationOptions,
	ProcessedRegistration,
} from "./registration/process-automatic.js";
export type { ProcessExplicitRegistrationOptions } from "./registration/process-explicit.js";
export type {
	AutomaticRegistrationContext,
	ValidatedRequestObject,
	ValidatedRequestObjectResult,
} from "./registration/types.js";

// Roles composition
export {
	FedOauthClient,
	type FedOauthClientConfig,
	FedOauthProvider,
	type FedOauthProviderConfig,
	FedOauthResource,
	type FedOauthResourceConfig,
	FedOidcClient,
	type FedOidcClientConfig,
	FedOidcProvider,
	type FedOidcProviderConfig,
} from "./roles.js";

// Schemas & Types
export type {
	ExplicitRegistrationRequestPayload,
	ExplicitRegistrationResponsePayload,
} from "./schemas/explicit-registration.js";
export type {
	OAuthAuthorizationServerMetadata,
	OAuthClientMetadata,
	OAuthResourceMetadata,
	OIDCFederationMetadata,
	OpenIDProviderMetadata,
	OpenIDRelyingPartyMetadata,
} from "./schemas/metadata.js";
