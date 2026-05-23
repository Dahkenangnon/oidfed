/**
 * Error codes for OIDC-specific federation registration errors.
 * These error codes are used in authorization error responses.
 *
 * These errors should only be returned in PAR responses, not in redirected
 * authorization error responses, to avoid leaking federation internals to the User-Agent.
 */
export const OIDCRegistrationErrorCode = {
	InvalidTrustAnchor: "invalid_trust_anchor",
	InvalidTrustChain: "invalid_trust_chain",
	InvalidMetadata: "invalid_metadata",
} as const;
export type OIDCRegistrationErrorCode =
	(typeof OIDCRegistrationErrorCode)[keyof typeof OIDCRegistrationErrorCode];

/** JWT `typ` header value for OAuth 2.0 Authorization Request Objects */
export const RequestObjectTyp = "oauth-authz-req+jwt" as const;

/** Client registration types advertised by an OP in `client_registration_types_supported`. */
export const ClientRegistrationType = {
	Automatic: "automatic",
	Explicit: "explicit",
} as const;
export type ClientRegistrationType =
	(typeof ClientRegistrationType)[keyof typeof ClientRegistrationType];

/** JWT `typ` header value for an explicit-registration response. */
export const OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE = "explicit-registration-response+jwt";

/** HTTP `Content-Type` value for an explicit-registration response. */
export const OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE =
	"application/explicit-registration-response+jwt";
