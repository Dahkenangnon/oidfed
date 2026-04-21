// @oidfed/oidc — OIDC/OAuth2 protocol layer for OpenID Federation

// Client authentication
export { createClientAssertion } from "./client-auth/assertion.js";

// Constants
export {
	OIDCRegistrationErrorCode,
	RequestObjectTyp,
} from "./constants.js";
// Registration — OIDC protocol adapter
export { OIDCRegistrationAdapter } from "./registration/adapter.js";
// Registration — RP-side flows
export {
	type AutomaticRegistrationConfig,
	type AutomaticRegistrationResult,
	automaticRegistration,
} from "./registration/automatic.js";
export {
	type ExplicitRegistrationConfig,
	type ExplicitRegistrationResult,
	explicitRegistration,
} from "./registration/explicit.js";
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
