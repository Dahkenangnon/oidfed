/**
 * Typed Zod schemas for all OpenID Federation 1.0 entity type metadata.
 *
 * Covers:
 *   - openid_relying_party  (OIDC Dynamic Registration 1.0 + Federation 1.0)
 *   - openid_provider       (OIDC Discovery 1.0 + Federation 1.0)
 *   - oauth_authorization_server (RFC 8414 + Federation 1.0)
 *   - oauth_client           (RFC 7591 + Federation 1.0)
 *   - oauth_resource          (RFC 9728 + Federation 1.0)
 */

import {
	FederationEntityMetadataSchema,
	type FederationMetadata,
	FederationMetadataSchema,
	JWKSetSchema,
} from "@oidfed/core";
import { z } from "zod";

export type { FederationMetadata };
// Re-export core schemas for consumers that need OIDC-strict + base schemas together
export { FederationEntityMetadataSchema, FederationMetadataSchema };

/** URL that MUST use https scheme and MUST NOT contain a fragment */
const httpsUrlNoFragment = z.url().refine(
	(val) => {
		try {
			const u = new URL(val);
			return u.protocol === "https:" && !u.hash;
		} catch {
			return false;
		}
	},
	{ message: "URL must use https scheme and must not contain a fragment" },
);

// ---------------------------------------------------------------------------
// 1. OpenID Connect Relying Party (OIDC Registration 1.0 + Federation 1.0)
// ---------------------------------------------------------------------------

/**
 * Typed OpenID Relying Party metadata schema.
 * Validates parameters from OIDC Dynamic Client Registration 1.0 (Section 2),
 * RFC 7591 core client metadata, logout / CIBA extensions, and
 * OpenID Federation 1.0 Section 5.1/5.2 federation-specific parameters.
 */
export const OpenIDRelyingPartyMetadataSchema = z.looseObject({
	// RFC 7591 / OIDC Registration core
	redirect_uris: z.array(z.string().url()).optional(),
	response_types: z.array(z.string()).optional(),
	grant_types: z.array(z.string()).optional(),
	application_type: z.enum(["web", "native"]).optional(),
	contacts: z.array(z.string().email()).optional(),
	client_name: z.string().optional(),
	logo_uri: z.string().url().optional(),
	client_uri: z.string().url().optional(),
	policy_uri: z.string().url().optional(),
	tos_uri: z.string().url().optional(),
	jwks_uri: httpsUrlNoFragment.optional(),
	jwks: JWKSetSchema.optional(),
	sector_identifier_uri: z.string().url().optional(),
	subject_type: z.enum(["public", "pairwise"]).optional(),
	// ID Token signing/encryption
	id_token_signed_response_alg: z.string().optional(),
	id_token_encrypted_response_alg: z.string().optional(),
	id_token_encrypted_response_enc: z.string().optional(),
	// UserInfo signing/encryption
	userinfo_signed_response_alg: z.string().optional(),
	userinfo_encrypted_response_alg: z.string().optional(),
	userinfo_encrypted_response_enc: z.string().optional(),
	// Request Object signing/encryption
	request_object_signing_alg: z.string().optional(),
	request_object_encryption_alg: z.string().optional(),
	request_object_encryption_enc: z.string().optional(),
	// Token endpoint auth
	token_endpoint_auth_method: z.string().optional(),
	token_endpoint_auth_signing_alg: z.string().optional(),
	// Session
	default_max_age: z.number().int().nonnegative().optional(),
	require_auth_time: z.boolean().optional(),
	default_acr_values: z.array(z.string()).optional(),
	initiate_login_uri: z.string().url().optional(),
	post_logout_redirect_uris: z.array(z.string().url()).optional(),
	// CIBA (OpenID Connect CIBA Core 1.0)
	backchannel_token_delivery_mode: z.string().optional(),
	backchannel_client_notification_endpoint: z.string().url().optional(),
	backchannel_authentication_request_signing_alg: z.string().optional(),
	backchannel_user_code_parameter: z.boolean().optional(),
	// Registration output parameters
	client_id: z.string().optional(),
	client_secret: z.string().optional(),
	client_id_issued_at: z.number().int().nonnegative().optional(),
	client_secret_expires_at: z.number().int().nonnegative().optional(),
	// Federation-specific (OpenID Federation 1.0 Section 5.1/5.2)
	client_registration_types: z.array(z.string()).optional(),
	signed_jwks_uri: httpsUrlNoFragment.optional(),
	organization_name: z.string().optional(),
	organization_identifier: z.string().optional(),
	scope: z.string().optional(),
});

// ---------------------------------------------------------------------------
// 2. OpenID Connect Provider (OIDC Discovery 1.0 + Federation 1.0)
// ---------------------------------------------------------------------------

/**
 * Typed OpenID Provider metadata schema.
 * Validates parameters from OIDC Discovery 1.0 (Section 3),
 * IANA OAuth AS Metadata registry entries, session management / logout,
 * CIBA, and OpenID Federation 1.0 Section 5.1 federation-specific parameters.
 */
export const OpenIDProviderMetadataSchema = z
	.looseObject({
		issuer: z.string().url(),
		authorization_endpoint: z.string().url(),
		token_endpoint: z.string().url().optional(),
		userinfo_endpoint: z.string().url().optional(),
		jwks_uri: httpsUrlNoFragment.optional(),
		jwks: JWKSetSchema.optional(),
		registration_endpoint: httpsUrlNoFragment.optional(),
		scopes_supported: z.array(z.string()).optional(),
		response_types_supported: z.array(z.string()),
		response_modes_supported: z.array(z.string()).optional(),
		grant_types_supported: z.array(z.string()).optional(),
		acr_values_supported: z.array(z.string()).optional(),
		subject_types_supported: z.array(z.string()),
		// ID Token signing/encryption
		id_token_signing_alg_values_supported: z.array(z.string()),
		id_token_encryption_alg_values_supported: z.array(z.string()).optional(),
		id_token_encryption_enc_values_supported: z.array(z.string()).optional(),
		// UserInfo signing/encryption
		userinfo_signing_alg_values_supported: z.array(z.string()).optional(),
		userinfo_encryption_alg_values_supported: z.array(z.string()).optional(),
		userinfo_encryption_enc_values_supported: z.array(z.string()).optional(),
		// Request Object signing/encryption
		request_object_signing_alg_values_supported: z.array(z.string()).optional(),
		request_object_encryption_alg_values_supported: z.array(z.string()).optional(),
		request_object_encryption_enc_values_supported: z.array(z.string()).optional(),
		// Token endpoint auth
		token_endpoint_auth_methods_supported: z.array(z.string()).optional(),
		token_endpoint_auth_signing_alg_values_supported: z.array(z.string()).optional(),
		// Display / claims
		display_values_supported: z.array(z.string()).optional(),
		claim_types_supported: z.array(z.string()).optional(),
		claims_supported: z.array(z.string()).optional(),
		service_documentation: z.string().url().optional(),
		claims_locales_supported: z.array(z.string()).optional(),
		ui_locales_supported: z.array(z.string()).optional(),
		claims_parameter_supported: z.boolean().optional(),
		request_parameter_supported: z.boolean().optional(),
		request_uri_parameter_supported: z.boolean().optional(),
		require_request_uri_registration: z.boolean().optional(),
		op_policy_uri: z.string().url().optional(),
		op_tos_uri: z.string().url().optional(),
		// Session Management / Logout
		end_session_endpoint: z.string().url().optional(),
		frontchannel_logout_supported: z.boolean().optional(),
		frontchannel_logout_session_supported: z.boolean().optional(),
		backchannel_logout_supported: z.boolean().optional(),
		backchannel_logout_session_supported: z.boolean().optional(),
		// CIBA (OpenID Connect CIBA Core 1.0)
		backchannel_token_delivery_modes_supported: z.array(z.string()).optional(),
		backchannel_authentication_endpoint: z.string().url().optional(),
		backchannel_user_code_parameter_supported: z.boolean().optional(),
		// Federation-specific (OpenID Federation 1.0 Section 5.1)
		client_registration_types_supported: z.array(z.string()).optional(),
		federation_registration_endpoint: httpsUrlNoFragment.optional(),
		signed_jwks_uri: httpsUrlNoFragment.optional(),
		organization_name: z.string().optional(),
		organization_identifier: z.string().optional(),
	})
	.superRefine((meta, ctx) => {
		// issuer must use https and have no query/fragment (RFC 8414 Section 2)
		try {
			const u = new URL(meta.issuer);
			if (u.protocol !== "https:") {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: "issuer URL must use https scheme",
					path: ["issuer"],
				});
			}
			if (u.hash || u.search) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: "issuer URL must not contain query or fragment components",
					path: ["issuer"],
				});
			}
		} catch {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "issuer must be a valid URL",
				path: ["issuer"],
			});
		}

		// federation_registration_endpoint required when 'explicit' registration is supported
		if (
			meta.client_registration_types_supported?.includes("explicit") &&
			!meta.federation_registration_endpoint
		) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message:
					"federation_registration_endpoint is REQUIRED when client_registration_types_supported includes 'explicit'",
				path: ["federation_registration_endpoint"],
			});
		}
	});

export type OpenIDRelyingPartyMetadata = z.infer<typeof OpenIDRelyingPartyMetadataSchema>;
export type OpenIDProviderMetadata = z.infer<typeof OpenIDProviderMetadataSchema>;

// ---------------------------------------------------------------------------
// 3. OAuth 2.0 Authorization Server (RFC 8414 + Federation 1.0)
// ---------------------------------------------------------------------------

/**
 * Typed OAuth 2.0 Authorization Server metadata schema.
 * Validates parameters from RFC 8414 (Section 2), extension RFCs
 * (RFC 7636 PKCE, RFC 8628 Device Auth, RFC 9126 PAR, RFC 9207 Issuer ID,
 * RFC 9449 DPoP), and OpenID Federation 1.0 Section 5.1.3 extensions.
 */
export const OAuthAuthorizationServerMetadataSchema = z
	.looseObject({
		issuer: z.string().url(),
		authorization_endpoint: z.string().url().optional(),
		token_endpoint: z.string().url().optional(),
		jwks_uri: httpsUrlNoFragment.optional(),
		jwks: JWKSetSchema.optional(),
		registration_endpoint: httpsUrlNoFragment.optional(),
		scopes_supported: z.array(z.string()).optional(),
		response_types_supported: z.array(z.string()),
		response_modes_supported: z.array(z.string()).optional(),
		grant_types_supported: z.array(z.string()).optional(),
		token_endpoint_auth_methods_supported: z.array(z.string()).optional(),
		token_endpoint_auth_signing_alg_values_supported: z.array(z.string()).optional(),
		service_documentation: z.string().url().optional(),
		ui_locales_supported: z.array(z.string()).optional(),
		op_policy_uri: z.string().url().optional(),
		op_tos_uri: z.string().url().optional(),
		// Revocation (RFC 7009)
		revocation_endpoint: z.string().url().optional(),
		revocation_endpoint_auth_methods_supported: z.array(z.string()).optional(),
		revocation_endpoint_auth_signing_alg_values_supported: z.array(z.string()).optional(),
		// Introspection (RFC 7662)
		introspection_endpoint: z.string().url().optional(),
		introspection_endpoint_auth_methods_supported: z.array(z.string()).optional(),
		introspection_endpoint_auth_signing_alg_values_supported: z.array(z.string()).optional(),
		// PKCE (RFC 7636)
		code_challenge_methods_supported: z.array(z.string()).optional(),
		// Device Authorization (RFC 8628)
		device_authorization_endpoint: z.string().url().optional(),
		// PAR (RFC 9126)
		pushed_authorization_request_endpoint: z.string().url().optional(),
		require_pushed_authorization_requests: z.boolean().optional(),
		// DPoP (RFC 9449)
		dpop_signing_alg_values_supported: z.array(z.string()).optional(),
		// Issuer Identification (RFC 9207)
		authorization_response_iss_parameter_supported: z.boolean().optional(),
		// Federation-specific (OpenID Federation 1.0 Section 5.1.3)
		client_registration_types_supported: z.array(z.string()).optional(),
		federation_registration_endpoint: httpsUrlNoFragment.optional(),
		signed_jwks_uri: httpsUrlNoFragment.optional(),
		organization_name: z.string().optional(),
		organization_identifier: z.string().optional(),
	})
	.superRefine((meta, ctx) => {
		try {
			const u = new URL(meta.issuer);
			if (u.protocol !== "https:") {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: "issuer URL must use https scheme",
					path: ["issuer"],
				});
			}
			if (u.hash || u.search) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: "issuer URL must not contain query or fragment components",
					path: ["issuer"],
				});
			}
		} catch {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "issuer must be a valid URL",
				path: ["issuer"],
			});
		}

		if (
			meta.client_registration_types_supported?.includes("explicit") &&
			!meta.federation_registration_endpoint
		) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message:
					"federation_registration_endpoint is REQUIRED when client_registration_types_supported includes 'explicit'",
				path: ["federation_registration_endpoint"],
			});
		}
	});

export type OAuthAuthorizationServerMetadata = z.infer<
	typeof OAuthAuthorizationServerMetadataSchema
>;

// ---------------------------------------------------------------------------
// 4. OAuth 2.0 Client (RFC 7591 + Federation 1.0)
// ---------------------------------------------------------------------------

/**
 * Typed OAuth 2.0 Client metadata schema.
 * Validates parameters from RFC 7591 (OAuth 2.0 Dynamic Client Registration)
 * and OpenID Federation 1.0 Section 5.1.4 extensions.
 */
export const OAuthClientMetadataSchema = z.looseObject({
	redirect_uris: z.array(z.string().url()).optional(),
	token_endpoint_auth_method: z.string().optional(),
	token_endpoint_auth_signing_alg: z.string().optional(),
	grant_types: z.array(z.string()).optional(),
	response_types: z.array(z.string()).optional(),
	client_name: z.string().optional(),
	client_uri: z.string().url().optional(),
	logo_uri: z.string().url().optional(),
	scope: z.string().optional(),
	contacts: z.array(z.string().email()).optional(),
	tos_uri: z.string().url().optional(),
	policy_uri: z.string().url().optional(),
	jwks_uri: httpsUrlNoFragment.optional(),
	jwks: JWKSetSchema.optional(),
	software_id: z.string().optional(),
	software_version: z.string().optional(),
	// Federation-specific (OpenID Federation 1.0 Section 5.1.4)
	client_registration_types: z.array(z.string()).optional(),
	signed_jwks_uri: httpsUrlNoFragment.optional(),
	organization_name: z.string().optional(),
	organization_identifier: z.string().optional(),
});

export type OAuthClientMetadata = z.infer<typeof OAuthClientMetadataSchema>;

// ---------------------------------------------------------------------------
// 5. OAuth 2.0 Protected Resource (RFC 9728 + Federation 1.0)
// ---------------------------------------------------------------------------

/**
 * Typed OAuth 2.0 Protected Resource metadata schema.
 * Validates parameters from RFC 9728 (OAuth 2.0 Protected Resource Metadata)
 * and OpenID Federation 1.0 Section 5.1.5 extensions.
 */
export const OAuthResourceMetadataSchema = z.looseObject({
	resource: z.string().url(),
	authorization_servers: z.array(z.string().url()).optional(),
	bearer_methods_supported: z.array(z.enum(["header", "body", "query"])).optional(),
	resource_signing_alg_values_supported: z.array(z.string()).optional(),
	dpop_signing_alg_values_supported: z.array(z.string()).optional(),
	scopes_supported: z.array(z.string()).optional(),
	jwks_uri: httpsUrlNoFragment.optional(),
	jwks: JWKSetSchema.optional(),
	// Federation-specific (OpenID Federation 1.0 Section 5.2)
	signed_jwks_uri: httpsUrlNoFragment.optional(),
	organization_name: z.string().optional(),
	organization_identifier: z.string().optional(),
});

export type OAuthResourceMetadata = z.infer<typeof OAuthResourceMetadataSchema>;

// ---------------------------------------------------------------------------
// Combined Federation OIDC Metadata Schema
// ---------------------------------------------------------------------------

/**
 * Extended federation metadata schema with strict validation for all entity types.
 * Ensures that each metadata block conforms to its authoritative specification
 * (not just `z.record()`).
 */
export const OIDCFederationMetadataSchema = FederationMetadataSchema.pipe(
	z.looseObject({
		federation_entity: FederationEntityMetadataSchema.optional(),
		openid_relying_party: OpenIDRelyingPartyMetadataSchema.optional(),
		openid_provider: OpenIDProviderMetadataSchema.optional(),
		oauth_authorization_server: OAuthAuthorizationServerMetadataSchema.optional(),
		oauth_client: OAuthClientMetadataSchema.optional(),
		oauth_resource: OAuthResourceMetadataSchema.optional(),
	}),
);

export type OIDCFederationMetadata = z.infer<typeof OIDCFederationMetadataSchema>;

/**
 * Parse and validate metadata with OIDC-strict validation.
 */
export function validateOIDCMetadata(raw: unknown): OIDCFederationMetadata {
	return OIDCFederationMetadataSchema.parse(raw);
}
