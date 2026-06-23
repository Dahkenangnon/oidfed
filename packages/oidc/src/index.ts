// @oidfed/oidc — OIDC/OAuth2 protocol layer for OpenID Federation

// Re-export common core types
export type {
	EntityId,
	FederationError,
	FederationOptions,
	Result,
	TrustAnchorSet,
} from "@oidfed/core";
// Re-export common core functions & enums
export { entityId, err, isErr, isOk, ok, StandardPolicyOperator } from "@oidfed/core";
// Client authentication
export {
	type ClientAssertionOptions,
	createClientAssertion,
} from "./client-auth/assertion.js";
// Constants
export {
	ClientRegistrationType,
	OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE,
	OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE,
	OIDCRegistrationErrorCode,
	RequestObjectTyp,
} from "./constants.js";
export {
	type OidcProtocolKeyProvider,
	StaticOidcProtocolKeyProvider,
} from "./protocol-keys.js";
// Registration — OIDC protocol adapter
export { OIDCRegistrationAdapter } from "./registration/adapter.js";
// Registration — adapter interface
export type {
	RegistrationProtocolAdapter,
	RegistrationProtocolAdapterContext,
} from "./registration/adapter-types.js";
// Registration — RP-side flows
export {
	type AutomaticRegistrationConfig,
	type AutomaticRegistrationResult,
	automaticRegistration,
	type RequestDelivery,
} from "./registration/automatic.js";
export {
	type ExplicitRegistrationConfig,
	type ExplicitRegistrationResult,
	explicitRegistration,
} from "./registration/explicit.js";
// Registration — OP-side explicit registration handler
export {
	createExplicitRegistrationHandler,
	type ExplicitRegistrationHandlerConfig,
} from "./registration/handler.js";
// Registration — OP-side processing
export {
	type ProcessAutomaticRegistrationOptions,
	type ProcessedRegistration,
	processAutomaticRegistration,
} from "./registration/process-automatic.js";
export {
	type ProcessExplicitRegistrationOptions,
	processExplicitRegistration,
} from "./registration/process-explicit.js";
// Registration types
export type {
	AutomaticRegistrationContext,
	ValidatedRequestObject,
	ValidatedRequestObjectResult,
} from "./registration/types.js";
// Registration — Request Object validation
export { validateAutomaticRegistrationRequest } from "./registration/validate-request-object.js";
// Schemas
export {
	type ExplicitRegistrationRequestPayload,
	ExplicitRegistrationRequestPayloadSchema,
	type ExplicitRegistrationResponsePayload,
	ExplicitRegistrationResponsePayloadSchema,
} from "./schemas/explicit-registration.js";
export {
	FederationEntityMetadataSchema,
	FederationMetadataSchema,
	type OIDCFederationMetadata,
	OIDCFederationMetadataSchema,
	type OpenIDProviderMetadata,
	OpenIDProviderMetadataSchema,
	type OpenIDRelyingPartyMetadata,
	OpenIDRelyingPartyMetadataSchema,
	validateOIDCMetadata,
} from "./schemas/metadata.js";
