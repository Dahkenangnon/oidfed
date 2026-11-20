/**
 * Protocol metadata schemas for the five OIDC and OAuth Federation Entity Types.
 *
 * Covers:
 *   - openid_relying_party  (OIDC Dynamic Registration 1.0 + Federation 1.0)
 *   - openid_provider       (OIDC Discovery 1.0 + Federation 1.0)
 *   - oauth_authorization_server (RFC 8414 + Federation 1.0)
 *   - oauth_client           (RFC 7591 + Federation 1.0)
 *   - oauth_resource          (RFC 9728 + Federation 1.0)
 */

import {
	type FederationEntityMetadataSchema,
	type FederationMetadata,
	MetadataJWKSetSchema,
	type MetadataValidationOptions,
	parseOAuthAuthorizationServerMetadata,
	parseOAuthAuthorizationServerPublicationMetadata,
	withMetadataJwkUse,
} from "@oidfed/core";
import { z } from "zod";

const httpsUrl = z
	.url()
	.refine(
		(value) => URL.canParse(value) && new URL(value).protocol === "https:",
		"URL must use https",
	);

/** URL that MUST use https scheme and MUST NOT contain a fragment */
const httpsUrlNoFragment = z.url().refine(
	(val) => {
		try {
			const u = new URL(val);
			return u.protocol === "https:" && !u.href.includes("#");
		} catch {
			return false;
		}
	},
	{ message: "URL must use https scheme and must not contain a fragment" },
);

const nonEmptyStringArray = z.array(z.string()).min(1);

const CommonInformationalMetadataShape = {
	organization_name: z.string().optional(),
	display_name: z.string().optional(),
	description: z.string().optional(),
	keywords: nonEmptyStringArray.optional(),
	contacts: nonEmptyStringArray.optional(),
	logo_uri: z.string().url().optional(),
	policy_uri: z.string().url().optional(),
	information_uri: z.string().url().optional(),
	organization_uri: z.string().url().optional(),
};

const ClientExtensionShape = {
	software_id: z.string().optional(),
	software_version: z.string().optional(),
	software_statement: z.string().optional(),
	claims_redirect_uris: z.array(z.url()).optional(),
	nfv_token_signed_response_alg: z.string().optional(),
	nfv_token_encrypted_response_alg: z.string().optional(),
	nfv_token_encrypted_response_enc: z.string().optional(),
	tls_client_certificate_bound_access_tokens: z.boolean().optional(),
	tls_client_auth_subject_dn: z.string().optional(),
	tls_client_auth_san_dns: z.string().optional(),
	tls_client_auth_san_uri: z.string().optional(),
	tls_client_auth_san_ip: z.string().optional(),
	tls_client_auth_san_email: z.string().optional(),
	require_signed_request_object: z.boolean().optional(),
	require_pushed_authorization_requests: z.boolean().optional(),
	use_mtls_endpoint_aliases: z.boolean().optional(),
	authorization_details_types: z.array(z.string()).optional(),
	dpop_bound_access_tokens: z.boolean().optional(),
	introspection_signed_response_alg: z
		.string()
		.refine((value) => value !== "none", "none MUST NOT be used")
		.optional(),
	introspection_encrypted_response_alg: z.string().optional(),
	introspection_encrypted_response_enc: z.string().optional(),
	authorization_signed_response_alg: z
		.string()
		.refine((value) => value !== "none", "none MUST NOT be used")
		.optional(),
	authorization_encrypted_response_alg: z.string().optional(),
	authorization_encrypted_response_enc: z.string().optional(),
};

/** RP Metadata Choices are registration inputs; responses use the singular member. */
export const rpMetadataChoices = {
	subject_types_supported: "subject_type",
	id_token_signing_alg_values_supported: "id_token_signed_response_alg",
	id_token_encryption_alg_values_supported: "id_token_encrypted_response_alg",
	id_token_encryption_enc_values_supported: "id_token_encrypted_response_enc",
	userinfo_signing_alg_values_supported: "userinfo_signed_response_alg",
	userinfo_encryption_alg_values_supported: "userinfo_encrypted_response_alg",
	userinfo_encryption_enc_values_supported: "userinfo_encrypted_response_enc",
	request_object_signing_alg_values_supported: "request_object_signing_alg",
	request_object_encryption_alg_values_supported: "request_object_encryption_alg",
	request_object_encryption_enc_values_supported: "request_object_encryption_enc",
	token_endpoint_auth_methods_supported: "token_endpoint_auth_method",
	token_endpoint_auth_signing_alg_values_supported: "token_endpoint_auth_signing_alg",
	backchannel_authentication_request_signing_alg_values_supported:
		"backchannel_authentication_request_signing_alg",
	authorization_signing_alg_values_supported: "authorization_signed_response_alg",
	authorization_encryption_alg_values_supported: "authorization_encrypted_response_alg",
	authorization_encryption_enc_values_supported: "authorization_encrypted_response_enc",
	introspection_signing_alg_values_supported: "introspection_signed_response_alg",
	introspection_encryption_alg_values_supported: "introspection_encrypted_response_alg",
	introspection_encryption_enc_values_supported: "introspection_encrypted_response_enc",
} as const;
const ChoiceShape = {
	subject_types_supported: z.array(z.string()).optional(),
	id_token_signing_alg_values_supported: z.array(z.string()).optional(),
	id_token_encryption_alg_values_supported: z.array(z.string()).optional(),
	id_token_encryption_enc_values_supported: z.array(z.string()).optional(),
	userinfo_signing_alg_values_supported: z.array(z.string()).optional(),
	userinfo_encryption_alg_values_supported: z.array(z.string()).optional(),
	userinfo_encryption_enc_values_supported: z.array(z.string()).optional(),
	request_object_signing_alg_values_supported: z.array(z.string()).optional(),
	request_object_encryption_alg_values_supported: z.array(z.string()).optional(),
	request_object_encryption_enc_values_supported: z.array(z.string()).optional(),
	token_endpoint_auth_methods_supported: z.array(z.string()).optional(),
	token_endpoint_auth_signing_alg_values_supported: z.array(z.string()).optional(),
	backchannel_authentication_request_signing_alg_values_supported: z.array(z.string()).optional(),
	authorization_signing_alg_values_supported: z.array(z.string()).optional(),
	authorization_encryption_alg_values_supported: z.array(z.string()).optional(),
	authorization_encryption_enc_values_supported: z.array(z.string()).optional(),
	introspection_signing_alg_values_supported: z.array(z.string()).optional(),
	introspection_encryption_alg_values_supported: z.array(z.string()).optional(),
	introspection_encryption_enc_values_supported: z.array(z.string()).optional(),
};

function clientRequirements(
	meta: Record<string, unknown>,
	ctx: z.RefinementCtx,
	publication: boolean,
	oidc: boolean,
) {
	const add = (field: string, message: string) =>
		ctx.addIssue({ code: "custom", path: [field], message });
	const grants = (meta.grant_types as string[] | undefined) ?? ["authorization_code"];
	const usesRedirect = grants.some(
		(grant) => grant === "authorization_code" || grant === "implicit",
	);
	if (!publication && usesRedirect && !(meta.redirect_uris as string[] | undefined)?.length)
		add("redirect_uris", "redirect_uris is REQUIRED for redirect-based flows");
	if (!publication || (meta.grant_types !== undefined && meta.response_types !== undefined)) {
		const responses =
			(meta.response_types as string[] | undefined) ?? (usesRedirect ? ["code"] : []);
		for (const response of responses) {
			const parts = response.split(" ");
			if (parts.includes("code") && !grants.includes("authorization_code"))
				add("grant_types", "authorization_code MUST be included for code response types");
			if ((parts.includes("token") || parts.includes("id_token")) && !grants.includes("implicit"))
				add("grant_types", "implicit MUST be included for implicit response types");
		}
	}
	for (const uri of (meta.redirect_uris as string[] | undefined) ?? []) {
		if (!URL.canParse(uri)) continue;
		const url = new URL(uri);
		if (uri.includes("#")) add("redirect_uris", "redirect_uris MUST NOT contain fragments");
		if (oidc) {
			const app = meta.application_type ?? (publication ? undefined : "web");
			const implicit = ((meta.response_types as string[] | undefined) ?? ["code"]).some((value) =>
				value.split(" ").some((part) => part === "token" || part === "id_token"),
			);
			if (app === "web" && implicit && (url.protocol !== "https:" || url.hostname === "localhost"))
				add(
					"redirect_uris",
					"Web implicit-flow redirect_uris MUST use https and MUST NOT use localhost",
				);
			if (
				app === "native" &&
				(url.protocol === "https:" ||
					(url.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))
			)
				add(
					"redirect_uris",
					"Native redirect_uris must use a custom scheme or an http loopback URI",
				);
		}
	}
	for (const [plural, singular] of Object.entries(rpMetadataChoices)) {
		const choices = meta[plural] as string[] | undefined;
		if (
			choices &&
			typeof meta[singular] === "string" &&
			!choices.includes(meta[singular] as string)
		)
			add(singular, `${singular} MUST be included in ${plural}`);
	}
	for (const prefix of [
		"id_token",
		"userinfo",
		"request_object",
		"authorization",
		"introspection",
	]) {
		const alg =
			prefix === "request_object"
				? "request_object_encryption_alg"
				: `${prefix}_encrypted_response_alg`;
		const enc =
			prefix === "request_object"
				? "request_object_encryption_enc"
				: `${prefix}_encrypted_response_enc`;
		if (!publication && meta[enc] !== undefined && meta[alg] === undefined)
			add(alg, `${alg} is REQUIRED when ${enc} is provided`);
	}
	if (!publication) {
		const mode = meta.backchannel_token_delivery_mode;
		const cibaGrant = "urn:openid:params:grant-type:ciba";
		if (grants.includes(cibaGrant) && mode === undefined)
			add(
				"backchannel_token_delivery_mode",
				"backchannel_token_delivery_mode is REQUIRED for CIBA",
			);
		if ((mode === "ping" || mode === "poll") && !grants.includes(cibaGrant))
			add("grant_types", "The CIBA grant type MUST be included for ping or poll delivery");
		if (
			(mode === "ping" || mode === "push") &&
			meta.backchannel_client_notification_endpoint === undefined
		)
			add(
				"backchannel_client_notification_endpoint",
				"backchannel_client_notification_endpoint is REQUIRED for ping or push delivery",
			);
	}
	if (meta.token_endpoint_auth_signing_alg === "none")
		add("token_endpoint_auth_signing_alg", "none MUST NOT be used for client authentication");
	const selectors = [
		"tls_client_auth_subject_dn",
		"tls_client_auth_san_dns",
		"tls_client_auth_san_uri",
		"tls_client_auth_san_ip",
		"tls_client_auth_san_email",
	].filter((key) => meta[key] !== undefined);
	if (
		meta.token_endpoint_auth_method === "tls_client_auth" &&
		(selectors.length > 1 || (!publication && selectors.length !== 1))
	)
		add(
			"token_endpoint_auth_method",
			"tls_client_auth requires exactly one certificate subject selector",
		);
}

// ---------------------------------------------------------------------------
// 1. OpenID Connect Relying Party (OIDC Registration 1.0 + Federation 1.0)
// ---------------------------------------------------------------------------

/**
 * Typed OpenID Relying Party metadata schema.
 * Validates parameters from OIDC Dynamic Client Registration 1.0 (Section 2),
 * RFC 7591 core client metadata, logout / CIBA extensions, and
 * OpenID Federation 1.0 Section 5.1/5.2 federation-specific parameters.
 */
const OpenIDRelyingPartyMetadataShape = {
	...ClientExtensionShape,
	...ChoiceShape,
	frontchannel_logout_uri: httpsUrlNoFragment.optional(),
	frontchannel_logout_session_required: z.boolean().optional(),
	backchannel_logout_uri: httpsUrlNoFragment.optional(),
	backchannel_logout_session_required: z.boolean().optional(),
	// RFC 7591 / OIDC Registration core
	redirect_uris: z.array(z.string().url()).optional(),
	response_types: z.array(z.string()).optional(),
	grant_types: z.array(z.string()).optional(),
	application_type: z.enum(["web", "native"]).optional(),
	client_name: z.string().optional(),
	client_uri: z.string().url().optional(),
	tos_uri: z.string().url().optional(),
	...CommonInformationalMetadataShape,
	jwks_uri: httpsUrlNoFragment.optional(),
	jwks: z.looseObject(MetadataJWKSetSchema.shape).optional(),
	sector_identifier_uri: z
		.url()
		.refine((value) => value.startsWith("https:"), "sector_identifier_uri MUST use https")
		.optional(),
	request_uris: z.array(z.url()).optional(),
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
	initiate_login_uri: httpsUrl.optional(),
	post_logout_redirect_uris: z.array(z.string().url()).optional(),
	// CIBA (OpenID Connect CIBA Core 1.0)
	backchannel_token_delivery_mode: z.enum(["poll", "ping", "push"]).optional(),
	backchannel_client_notification_endpoint: httpsUrl.optional(),
	backchannel_authentication_request_signing_alg: z.string().optional(),
	backchannel_user_code_parameter: z.boolean().optional(),
	// Federation-specific (OpenID Federation 1.0 Section 5.1/5.2)
	client_registration_types: z.array(z.string()).optional(),
	signed_jwks_uri: httpsUrlNoFragment.optional(),
	// Optional organization identifier extension supplied by the deployment.
	organization_identifier: z.string().optional(),
	scope: z.string().optional(),
};

const OPENID_RP_REGISTRATION_RESPONSE_FIELDS = [
	"client_id",
	"client_secret",
	"client_id_issued_at",
	"client_secret_expires_at",
	"registration_access_token",
	"registration_client_uri",
] as const;

function relyingPartyRequirements(
	meta: Record<string, unknown>,
	ctx: z.RefinementCtx,
	publication: boolean,
) {
	clientRequirements(meta, ctx, publication, true);
	for (const field of OPENID_RP_REGISTRATION_RESPONSE_FIELDS)
		if (Object.hasOwn(meta, field))
			ctx.addIssue({
				code: "custom",
				path: [field],
				message: `${field} is only valid in registration response metadata`,
			});
}
export const OpenIDRelyingPartyMetadataSchema = z
	.looseObject(OpenIDRelyingPartyMetadataShape)
	.superRefine((meta, ctx) => relyingPartyRequirements(meta, ctx, false));
const OpenIDRelyingPartyPublicationMetadataSchema = z
	.looseObject(OpenIDRelyingPartyMetadataShape)
	.superRefine((meta, ctx) => relyingPartyRequirements(meta, ctx, true));

/**
 * Typed OpenID Relying Party metadata as carried in an Explicit Registration Response.
 * Includes registration-response credential fields that are not valid in Entity
 * Configuration or Subordinate Statement metadata.
 */
const RegistrationCredentialShape = {
	client_id: z.string(),
	client_secret: z.string().optional(),
	client_id_issued_at: z.number().int().nonnegative().optional(),
	client_secret_expires_at: z.number().int().nonnegative().optional(),
	registration_access_token: z.string().min(1).optional(),
	registration_client_uri: httpsUrlNoFragment.optional(),
};
function registrationResponseRequirements(
	meta: Record<string, unknown>,
	ctx: z.RefinementCtx,
	oidc: boolean,
) {
	clientRequirements(meta, ctx, false, oidc);
	if (
		(meta.registration_access_token !== undefined) !==
		(meta.registration_client_uri !== undefined)
	)
		ctx.addIssue({
			code: "custom",
			path: [
				meta.registration_access_token === undefined
					? "registration_access_token"
					: "registration_client_uri",
			],
			message: "registration_access_token and registration_client_uri MUST be returned together",
		});
	for (const field of oidc ? Object.keys(rpMetadataChoices) : [])
		if (Object.hasOwn(meta, field))
			ctx.addIssue({
				code: "custom",
				path: [field],
				message: `${field} MUST only be used as a registration input`,
			});
}
export const OpenIDRelyingPartyRegistrationResponseMetadataSchema = z
	.looseObject({
		...OpenIDRelyingPartyMetadataShape,
		...RegistrationCredentialShape,
	})
	.superRefine((meta, ctx) => registrationResponseRequirements(meta, ctx, true));

// ---------------------------------------------------------------------------
// 2. OpenID Connect Provider (OIDC Discovery 1.0 + Federation 1.0)
// ---------------------------------------------------------------------------

/**
 * Typed OpenID Provider metadata schema.
 * Validates parameters from OIDC Discovery 1.0 (Section 3),
 * IANA OAuth AS Metadata registry entries, session management / logout,
 * CIBA, and OpenID Federation 1.0 Section 5.1 federation-specific parameters.
 */
// The shared AS validator lives in core because wallet discovery also consumes it.
const oauthAuthorizationServerMetadataSchema = (options?: MetadataValidationOptions) =>
	z.record(z.string(), z.unknown()).transform((raw, ctx) => {
		const parsed = parseOAuthAuthorizationServerMetadata(raw, options);
		if (!parsed.success) {
			for (const issue of parsed.error.issues)
				ctx.addIssue({ code: "custom", path: issue.path, message: issue.message });
			return z.NEVER;
		}
		return parsed.data;
	});
const oauthAuthorizationServerPublicationMetadataSchema = (options?: MetadataValidationOptions) =>
	z.record(z.string(), z.unknown()).transform((raw, ctx) => {
		const parsed = parseOAuthAuthorizationServerPublicationMetadata(raw, options);
		if (!parsed.success) {
			for (const issue of parsed.error.issues)
				ctx.addIssue({ code: "custom", path: issue.path, message: issue.message });
			return z.NEVER;
		}
		return parsed.data;
	});
export type OAuthAuthorizationServerMetadata = z.infer<
	ReturnType<typeof oauthAuthorizationServerMetadataSchema>
>;

const OpenIDProviderMetadataShape = {
	issuer: z.string().url(),
	authorization_endpoint: httpsUrlNoFragment,
	token_endpoint: httpsUrlNoFragment.optional(),
	userinfo_endpoint: httpsUrl.optional(),
	jwks_uri: httpsUrlNoFragment.optional(),
	jwks: z.looseObject(MetadataJWKSetSchema.shape).optional(),
	registration_endpoint: httpsUrlNoFragment.optional(),
	scopes_supported: z.array(z.string()).optional(),
	response_types_supported: z.array(z.string()),
	response_modes_supported: z.array(z.string()).optional(),
	grant_types_supported: z.array(z.string()).optional(),
	acr_values_supported: z.array(z.string()).optional(),
	subject_types_supported: z.array(z.enum(["public", "pairwise"])).min(1),
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
	end_session_endpoint: httpsUrl.optional(),
	frontchannel_logout_supported: z.boolean().optional(),
	frontchannel_logout_session_supported: z.boolean().optional(),
	backchannel_logout_supported: z.boolean().optional(),
	backchannel_logout_session_supported: z.boolean().optional(),
	// CIBA (OpenID Connect CIBA Core 1.0)
	backchannel_token_delivery_modes_supported: z.array(z.string()).optional(),
	backchannel_authentication_endpoint: httpsUrl.optional(),
	backchannel_user_code_parameter_supported: z.boolean().optional(),
	...CommonInformationalMetadataShape,
	// Federation-specific (OpenID Federation 1.0 Section 5.1)
	client_registration_types_supported: z.array(z.string()).optional(),
	federation_registration_endpoint: z.url().optional(),
	signed_jwks_uri: httpsUrlNoFragment.optional(),
	// Optional organization identifier extension supplied by the deployment.
	organization_identifier: z.string().optional(),
	check_session_iframe: httpsUrl.optional(),
	backchannel_authentication_request_signing_alg_values_supported: z.array(z.string()).optional(),
	authorization_signing_alg_values_supported: z.array(z.string()).optional(),
	authorization_encryption_alg_values_supported: z.array(z.string()).optional(),
	authorization_encryption_enc_values_supported: z.array(z.string()).optional(),
};
function providerRequirements(
	meta: Record<string, unknown>,
	ctx: z.RefinementCtx,
	publication: boolean,
) {
	if (!publication && !(meta.id_token_signing_alg_values_supported as string[]).includes("RS256"))
		ctx.addIssue({
			code: "custom",
			path: ["id_token_signing_alg_values_supported"],
			message: "RS256 MUST be included",
		});
	if (!publication && !meta.jwks && !meta.jwks_uri && !meta.signed_jwks_uri)
		ctx.addIssue({
			code: "custom",
			path: ["jwks_uri"],
			message: "OP metadata requires jwks, jwks_uri, or signed_jwks_uri",
		});
}
const openIDProviderMetadataSchema = (options?: MetadataValidationOptions) =>
	z
		.looseObject(OpenIDProviderMetadataShape)
		.superRefine((meta, ctx) => providerRequirements(meta, ctx, false))
		.and(oauthAuthorizationServerMetadataSchema(options));
const openIDProviderPublicationMetadataSchema = (options?: MetadataValidationOptions) =>
	z
		.looseObject(OpenIDProviderMetadataShape)
		.partial()
		.superRefine((meta, ctx) => providerRequirements(meta, ctx, true))
		.and(oauthAuthorizationServerPublicationMetadataSchema(options));

type OpenIDRelyingPartyResponseOnlyFields = {
	readonly [K in (typeof OPENID_RP_REGISTRATION_RESPONSE_FIELDS)[number]]?: never;
};
export type OpenIDRelyingPartyMetadata = z.infer<typeof OpenIDRelyingPartyMetadataSchema> &
	OpenIDRelyingPartyResponseOnlyFields;
export type OpenIDRelyingPartyRegistrationResponseMetadata = z.infer<
	typeof OpenIDRelyingPartyRegistrationResponseMetadataSchema
>;
export type OpenIDProviderMetadata = z.infer<ReturnType<typeof openIDProviderMetadataSchema>>;

// ---------------------------------------------------------------------------
// 4. OAuth 2.0 Client (RFC 7591 + Federation 1.0)
// ---------------------------------------------------------------------------

/**
 * Typed OAuth 2.0 Client metadata schema.
 * Validates parameters from RFC 7591 (OAuth 2.0 Dynamic Client Registration)
 * and OpenID Federation 1.0 Section 5.1.5 extensions.
 */
const OAuthClientMetadataShape = {
	...OpenIDRelyingPartyMetadataShape,
	redirect_uris: z.array(z.string().url()).optional(),
	token_endpoint_auth_method: z.string().optional(),
	token_endpoint_auth_signing_alg: z.string().optional(),
	grant_types: z.array(z.string()).optional(),
	response_types: z.array(z.string()).optional(),
	client_name: z.string().optional(),
	client_uri: z.string().url().optional(),
	scope: z.string().optional(),
	tos_uri: z.string().url().optional(),
	...CommonInformationalMetadataShape,
	jwks_uri: httpsUrlNoFragment.optional(),
	jwks: z.looseObject(MetadataJWKSetSchema.shape).optional(),
	software_id: z.string().optional(),
	software_version: z.string().optional(),
	// Federation-specific (OpenID Federation 1.0 Section 5.1.5)
	client_registration_types: z.array(z.string()).optional(),
	signed_jwks_uri: httpsUrlNoFragment.optional(),
	// Optional organization identifier extension supplied by the deployment.
	organization_identifier: z.string().optional(),
};
function oauthClientRequirements(
	meta: Record<string, unknown>,
	ctx: z.RefinementCtx,
	publication: boolean,
) {
	clientRequirements(meta, ctx, publication, false);
	for (const field of OPENID_RP_REGISTRATION_RESPONSE_FIELDS)
		if (Object.hasOwn(meta, field))
			ctx.addIssue({
				code: "custom",
				path: [field],
				message: `${field} is only valid in registration response metadata`,
			});
}
const OAuthClientMetadataSchema = z
	.looseObject(OAuthClientMetadataShape)
	.superRefine((meta, ctx) => oauthClientRequirements(meta, ctx, false));
const OAuthClientPublicationMetadataSchema = z
	.looseObject(OAuthClientMetadataShape)
	.superRefine((meta, ctx) => oauthClientRequirements(meta, ctx, true));

/** OAuth client credentials belong in registration responses, never publication metadata. */
export const OAuthClientRegistrationResponseMetadataSchema = z
	.looseObject({
		...OAuthClientMetadataShape,
		...RegistrationCredentialShape,
	})
	.superRefine((meta, ctx) => registrationResponseRequirements(meta, ctx, false));
export type OAuthClientRegistrationResponseMetadata = z.infer<
	typeof OAuthClientRegistrationResponseMetadataSchema
>;

export type OAuthClientMetadata = z.infer<typeof OAuthClientMetadataSchema>;

// ---------------------------------------------------------------------------
// 5. OAuth 2.0 Protected Resource (RFC 9728 + Federation 1.0)
// ---------------------------------------------------------------------------

/**
 * Typed OAuth 2.0 Protected Resource metadata schema.
 * Validates parameters from RFC 9728 (OAuth 2.0 Protected Resource Metadata)
 * and OpenID Federation 1.0 Section 5.1.6 extensions.
 */
const OAuthResourceMetadataShape = {
	resource: httpsUrlNoFragment.optional(),
	resource_name: z.string().optional(),
	resource_documentation: z.url().optional(),
	resource_policy_uri: z.url().optional(),
	resource_tos_uri: z.url().optional(),
	tls_client_certificate_bound_access_tokens: z.boolean().optional(),
	authorization_details_types_supported: z.array(z.string()).optional(),
	dpop_bound_access_tokens_required: z.boolean().optional(),
	signed_metadata: z.string().optional(),
	authorization_servers: z
		.array(
			httpsUrlNoFragment.refine((value) => !value.includes("?"), "issuer must not contain a query"),
		)
		.optional(),
	bearer_methods_supported: z.array(z.enum(["header", "body", "query"])).optional(),
	resource_signing_alg_values_supported: z
		.array(z.string())
		.refine((values) => !values.includes("none"), "none MUST NOT be used")
		.optional(),
	dpop_signing_alg_values_supported: z
		.array(z.string())
		.refine(
			(values) => !values.some((value) => ["none", "HS256", "HS384", "HS512"].includes(value)),
			"DPoP requires asymmetric signing algorithms",
		)
		.optional(),
	scopes_supported: z.array(z.string()).optional(),
	jwks_uri: httpsUrlNoFragment.optional(),
	jwks: z.looseObject(MetadataJWKSetSchema.shape).optional(),
	...CommonInformationalMetadataShape,
	// Federation-specific (OpenID Federation 1.0 Section 5.2)
	signed_jwks_uri: httpsUrlNoFragment.optional(),
	// Optional organization identifier extension supplied by the deployment.
	organization_identifier: z.string().optional(),
};
const OAuthResourceMetadataSchema = z.looseObject(OAuthResourceMetadataShape);
export const OAuthResourceDocumentMetadataSchema = z.looseObject({
	...OAuthResourceMetadataShape,
	resource: httpsUrlNoFragment,
});

export type OAuthResourceMetadata = z.infer<typeof OAuthResourceMetadataSchema>;

export const effectiveRoleSchemas = {
	openid_relying_party: (options?: MetadataValidationOptions) =>
		withMetadataJwkUse(OpenIDRelyingPartyMetadataSchema, options),
	openid_provider: openIDProviderMetadataSchema,
	oauth_authorization_server: oauthAuthorizationServerMetadataSchema,
	oauth_client: (options?: MetadataValidationOptions) =>
		withMetadataJwkUse(OAuthClientMetadataSchema, options),
	oauth_resource: (options?: MetadataValidationOptions) =>
		withMetadataJwkUse(OAuthResourceMetadataSchema, options),
};
export const publicationRoleSchemas = {
	openid_relying_party: (options?: MetadataValidationOptions) =>
		withMetadataJwkUse(OpenIDRelyingPartyPublicationMetadataSchema, options),
	openid_provider: openIDProviderPublicationMetadataSchema,
	oauth_authorization_server: oauthAuthorizationServerPublicationMetadataSchema,
	oauth_client: (options?: MetadataValidationOptions) =>
		withMetadataJwkUse(OAuthClientPublicationMetadataSchema, options),
	oauth_resource: (options?: MetadataValidationOptions) =>
		withMetadataJwkUse(OAuthResourceMetadataSchema, options),
};

/** Publication types follow the same schemas used by role publication hooks. */
export type OpenIDRelyingPartyPublicationMetadata = z.infer<
	ReturnType<typeof publicationRoleSchemas.openid_relying_party>
> &
	OpenIDRelyingPartyResponseOnlyFields;
export type OpenIDProviderPublicationMetadata = z.infer<
	ReturnType<typeof publicationRoleSchemas.openid_provider>
>;
export type OAuthAuthorizationServerPublicationMetadata = z.infer<
	ReturnType<typeof publicationRoleSchemas.oauth_authorization_server>
>;
export type OAuthClientPublicationMetadata = z.infer<
	ReturnType<typeof publicationRoleSchemas.oauth_client>
>;
export type OAuthResourcePublicationMetadata = z.infer<
	ReturnType<typeof publicationRoleSchemas.oauth_resource>
>;

/** Effective metadata, after federation processing and protocol validation. */
export type OIDCFederationMetadata = FederationMetadata & {
	readonly federation_entity?: z.infer<typeof FederationEntityMetadataSchema>;
	readonly openid_relying_party?: OpenIDRelyingPartyMetadata;
	readonly openid_provider?: OpenIDProviderMetadata;
	readonly oauth_authorization_server?: OAuthAuthorizationServerMetadata;
	readonly oauth_client?: OAuthClientMetadata;
	readonly oauth_resource?: OAuthResourceMetadata;
};

/** Publication can omit protocol fields completed by superiors (Federation §5). */
export type OIDCFederationPublicationMetadata = FederationMetadata & {
	readonly openid_relying_party?: OpenIDRelyingPartyPublicationMetadata;
	readonly openid_provider?: OpenIDProviderPublicationMetadata;
	readonly oauth_authorization_server?: OAuthAuthorizationServerPublicationMetadata;
	readonly oauth_client?: OAuthClientPublicationMetadata;
	readonly oauth_resource?: OAuthResourcePublicationMetadata;
};
