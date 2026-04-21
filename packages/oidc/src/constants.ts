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
