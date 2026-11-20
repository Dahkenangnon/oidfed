export type {
	RegistrationAccreditationContext,
	RegistrationAccreditationPolicy,
} from "./registration/accreditation.js";
// Registration types
export type {
	RegistrationProtocolAdapter,
	RegistrationProtocolAdapterContext,
} from "./registration/adapter-types.js";
export type {
	AutomaticRegistrationResult,
	RequestDelivery,
} from "./registration/automatic-client.js";
export type {
	ProcessedAutomaticRegistration,
	ProcessedRegistration,
} from "./registration/automatic-server.js";
export type { ExplicitRegistrationResult } from "./registration/explicit-client.js";
export type {
	PreparedPushedAuthorizationRequest,
	ProcessedPushedAuthorizationRequest,
	PushedAuthorizationProof,
} from "./registration/pushed.js";

// Roles composition
export {
	type CreateAuthorizationRequestOptions,
	OAuthAuthorizationServerRole,
	type OAuthAuthorizationServerRoleConfig,
	OAuthClientRole,
	type OAuthClientRoleConfig,
	OAuthResourceRole,
	type OAuthResourceRoleConfig,
	OidcProviderRole,
	type OidcProviderRoleConfig,
	OidcRelyingPartyRole,
	type OidcRelyingPartyRoleConfig,
	type ProcessAutomaticRegistrationOptions,
	type ProcessPushedAuthorizationRequestOptions,
} from "./roles.js";

// Schemas & Types
export type {
	ExplicitRegistrationRequestPayload,
	ExplicitRegistrationResponsePayload,
} from "./schemas/explicit-registration.js";
export type {
	OAuthAuthorizationServerMetadata,
	OAuthAuthorizationServerPublicationMetadata,
	OAuthClientMetadata,
	OAuthClientPublicationMetadata,
	OAuthClientRegistrationResponseMetadata,
	OAuthResourceMetadata,
	OAuthResourcePublicationMetadata,
	OIDCFederationMetadata,
	OIDCFederationPublicationMetadata,
	OpenIDProviderMetadata,
	OpenIDProviderPublicationMetadata,
	OpenIDRelyingPartyMetadata,
	OpenIDRelyingPartyPublicationMetadata,
	OpenIDRelyingPartyRegistrationResponseMetadata,
} from "./schemas/metadata.js";
