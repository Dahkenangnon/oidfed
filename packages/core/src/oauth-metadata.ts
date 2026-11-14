/** Shared RFC 8414 metadata validation for OIDC and wallet protocol consumers. */
import { z } from "zod";
import { validateJwkSetUseRequirement } from "./jwks/use-requirement.js";
import { MetadataJWKSetSchema } from "./schemas/jwk.js";

const strings = z.array(z.string());
const httpsUrl = z
	.url()
	.refine(
		(value) => URL.canParse(value) && new URL(value).protocol === "https:",
		"URL must use https",
	);
const endpoint = httpsUrl.refine(
	(value) => !value.includes("#"),
	"URL must not contain a fragment",
);
const issuer = endpoint.refine((value) => !value.includes("?"), "issuer must not contain a query");
const signingAlgorithms = strings.refine(
	(values) => !values.includes("none"),
	"none MUST NOT be used",
);

const shape = {
	issuer,
	authorization_endpoint: endpoint.optional(),
	token_endpoint: endpoint.optional(),
	response_types_supported: strings,
	response_modes_supported: strings.optional(),
	grant_types_supported: strings.optional(),
	scopes_supported: strings.optional(),
	jwks_uri: endpoint.optional(),
	signed_jwks_uri: endpoint.optional(),
	jwks: z.looseObject(MetadataJWKSetSchema.shape).optional(),
	registration_endpoint: endpoint.optional(),
	token_endpoint_auth_methods_supported: strings.optional(),
	client_attestation_signing_alg_values_supported: signingAlgorithms.optional(),
	client_attestation_pop_signing_alg_values_supported: signingAlgorithms.optional(),
	challenge_endpoint: z.url().optional(),
	token_endpoint_auth_signing_alg_values_supported: signingAlgorithms.optional(),
	revocation_endpoint: endpoint.optional(),
	revocation_endpoint_auth_methods_supported: strings.optional(),
	revocation_endpoint_auth_signing_alg_values_supported: signingAlgorithms.optional(),
	introspection_endpoint: endpoint.optional(),
	introspection_endpoint_auth_methods_supported: strings.optional(),
	introspection_endpoint_auth_signing_alg_values_supported: signingAlgorithms.optional(),
	introspection_signing_alg_values_supported: signingAlgorithms.optional(),
	introspection_encryption_alg_values_supported: strings.optional(),
	introspection_encryption_enc_values_supported: strings.optional(),
	// Registered AS extensions remain optional, including OpenID-specific capabilities.
	userinfo_endpoint: httpsUrl.optional(),
	acr_values_supported: strings.optional(),
	subject_types_supported: strings.optional(),
	id_token_signing_alg_values_supported: strings.optional(),
	id_token_encryption_alg_values_supported: strings.optional(),
	id_token_encryption_enc_values_supported: strings.optional(),
	userinfo_signing_alg_values_supported: strings.optional(),
	userinfo_encryption_alg_values_supported: strings.optional(),
	userinfo_encryption_enc_values_supported: strings.optional(),
	request_object_signing_alg_values_supported: strings.optional(),
	request_object_encryption_alg_values_supported: strings.optional(),
	request_object_encryption_enc_values_supported: strings.optional(),
	display_values_supported: strings.optional(),
	claim_types_supported: strings.optional(),
	claims_supported: strings.optional(),
	claims_locales_supported: strings.optional(),
	claims_parameter_supported: z.boolean().optional(),
	request_parameter_supported: z.boolean().optional(),
	request_uri_parameter_supported: z.boolean().optional(),
	require_request_uri_registration: z.boolean().optional(),
	check_session_iframe: httpsUrl.optional(),
	frontchannel_logout_supported: z.boolean().optional(),
	frontchannel_logout_session_supported: z.boolean().optional(),
	backchannel_logout_supported: z.boolean().optional(),
	backchannel_logout_session_supported: z.boolean().optional(),
	end_session_endpoint: httpsUrl.optional(),
	backchannel_token_delivery_modes_supported: z
		.array(z.enum(["poll", "ping", "push"]))
		.min(1)
		.optional(),
	backchannel_authentication_endpoint: httpsUrl.optional(),
	backchannel_authentication_request_signing_alg_values_supported: signingAlgorithms.optional(),
	backchannel_user_code_parameter_supported: z.boolean().optional(),
	authorization_signing_alg_values_supported: signingAlgorithms.optional(),
	authorization_encryption_alg_values_supported: strings.optional(),
	authorization_encryption_enc_values_supported: strings.optional(),
	nfv_token_signing_alg_values_supported: strings.optional(),
	nfv_token_encryption_alg_values_supported: strings.optional(),
	nfv_token_encryption_enc_values_supported: strings.optional(),
	code_challenge_methods_supported: strings.optional(),
	device_authorization_endpoint: endpoint.optional(),
	pushed_authorization_request_endpoint: endpoint.optional(),
	require_pushed_authorization_requests: z.boolean().optional(),
	require_signed_request_object: z.boolean().optional(),
	dpop_signing_alg_values_supported: strings
		.refine(
			(values) => !values.some((value) => ["none", "HS256", "HS384", "HS512"].includes(value)),
			"DPoP requires asymmetric signing algorithms",
		)
		.optional(),
	authorization_response_iss_parameter_supported: z.boolean().optional(),
	authorization_details_types_supported: strings.optional(),
	protected_resources: z.array(z.url()).optional(),
	tls_client_certificate_bound_access_tokens: z.boolean().optional(),
	mtls_endpoint_aliases: z
		.looseObject({
			token_endpoint: endpoint.optional(),
			revocation_endpoint: endpoint.optional(),
			introspection_endpoint: endpoint.optional(),
			device_authorization_endpoint: endpoint.optional(),
			pushed_authorization_request_endpoint: endpoint.optional(),
			userinfo_endpoint: httpsUrl.optional(),
			backchannel_authentication_endpoint: httpsUrl.optional(),
		})
		.optional(),
	signed_metadata: z.string().optional(),
	service_documentation: z.url().optional(),
	ui_locales_supported: strings.optional(),
	op_policy_uri: z.url().optional(),
	op_tos_uri: z.url().optional(),
	organization_name: z.string().optional(),
	display_name: z.string().optional(),
	description: z.string().optional(),
	keywords: strings.min(1).optional(),
	contacts: strings.min(1).optional(),
	logo_uri: z.url().optional(),
	policy_uri: z.url().optional(),
	information_uri: z.url().optional(),
	organization_uri: z.url().optional(),
	organization_identifier: z.string().optional(),
	client_registration_types_supported: strings.optional(),
	// Federation makes the HTTPS/no-fragment requirement conditional on explicit support.
	federation_registration_endpoint: z.url().optional(),
};

function requirements(meta: Record<string, unknown>, ctx: z.RefinementCtx, publication: boolean) {
	const keys = MetadataJWKSetSchema.safeParse(meta.jwks);
	if (keys.success) {
		const use = validateJwkSetUseRequirement(keys.data.keys);
		if (!use.ok) ctx.addIssue({ code: "custom", path: ["jwks"], message: use.error.description });
	}
	const requireField = (field: string, message: string) => {
		if (!publication && meta[field] === undefined)
			ctx.addIssue({ code: "custom", path: [field], message });
	};
	if (
		(meta.token_endpoint_auth_methods_supported as string[] | undefined)?.includes(
			"attest_jwt_client_auth",
		)
	) {
		for (const field of [
			"client_attestation_signing_alg_values_supported",
			"client_attestation_pop_signing_alg_values_supported",
		])
			requireField(field, `${field} is REQUIRED for attest_jwt_client_auth`);
	}
	const grants = (meta.grant_types_supported as string[] | undefined) ?? [
		"authorization_code",
		"implicit",
	];
	if (grants.some((grant) => grant === "authorization_code" || grant === "implicit"))
		requireField(
			"authorization_endpoint",
			"authorization_endpoint is REQUIRED for authorization endpoint grant types",
		);
	if (!(grants.length === 1 && grants[0] === "implicit"))
		requireField(
			"token_endpoint",
			"token_endpoint is REQUIRED unless only the implicit grant type is supported",
		);
	const cibaModes = meta.backchannel_token_delivery_modes_supported as string[] | undefined;
	if (
		grants.includes("urn:openid:params:grant-type:ciba") ||
		cibaModes !== undefined ||
		meta.backchannel_authentication_endpoint !== undefined
	) {
		requireField(
			"backchannel_authentication_endpoint",
			"backchannel_authentication_endpoint is REQUIRED for CIBA",
		);
		requireField(
			"backchannel_token_delivery_modes_supported",
			"backchannel_token_delivery_modes_supported is REQUIRED for CIBA",
		);
		if (
			(!publication || meta.grant_types_supported !== undefined) &&
			cibaModes?.some((mode) => mode === "ping" || mode === "poll") &&
			!grants.includes("urn:openid:params:grant-type:ciba")
		)
			ctx.addIssue({
				code: "custom",
				path: ["grant_types_supported"],
				message: "The CIBA grant type MUST be included for ping or poll delivery",
			});
	}
	if ((meta.client_registration_types_supported as string[] | undefined)?.includes("explicit")) {
		requireField(
			"federation_registration_endpoint",
			"federation_registration_endpoint is REQUIRED for Explicit Client Registration",
		);
		if (meta.federation_registration_endpoint !== undefined) {
			const checked = endpoint.safeParse(meta.federation_registration_endpoint);
			if (!checked.success)
				ctx.addIssue({
					code: "custom",
					path: ["federation_registration_endpoint"],
					message:
						"federation_registration_endpoint must use https and must not contain a fragment",
				});
		}
	}
}

const effective = z.looseObject(shape).superRefine((meta, ctx) => requirements(meta, ctx, false));
// Wallet Federation imports OpenID4VCI §12.2.4's pre-authorized-only AS exception.
const vciEffective = z
	.looseObject({ ...shape, response_types_supported: strings.optional() })
	.superRefine((meta, ctx) => {
		requirements(meta, ctx, false);
		const grants = meta.grant_types_supported;
		if (
			meta.response_types_supported === undefined &&
			!(
				grants?.length &&
				grants.every((grant) => grant === "urn:ietf:params:oauth:grant-type:pre-authorized_code")
			)
		)
			ctx.addIssue({
				code: "custom",
				path: ["response_types_supported"],
				message:
					"response_types_supported is REQUIRED unless only the pre-authorized-code grant is supported",
			});
	});
const publication = z
	.looseObject(shape)
	.partial()
	.superRefine((meta, ctx) => requirements(meta, ctx, true));

export type OAuthAuthorizationServerMetadata = z.infer<typeof effective>;
export type OAuthAuthorizationServerPublicationMetadata = z.infer<typeof publication>;

/** Parse effective protocol metadata. This does not authenticate its issuer or signed_metadata. */
export function parseOAuthAuthorizationServerMetadata(
	metadata: unknown,
	options?: { profile?: "oauth" },
): ReturnType<typeof effective.safeParse>;
export function parseOAuthAuthorizationServerMetadata(
	metadata: unknown,
	options: { profile: "openid4vci" },
): ReturnType<typeof vciEffective.safeParse>;
export function parseOAuthAuthorizationServerMetadata(
	metadata: unknown,
	options: { profile?: "oauth" | "openid4vci" },
): ReturnType<typeof effective.safeParse> | ReturnType<typeof vciEffective.safeParse>;
export function parseOAuthAuthorizationServerMetadata(
	metadata: unknown,
	options: { profile?: "oauth" | "openid4vci" } = {},
) {
	return options.profile === "openid4vci"
		? vciEffective.safeParse(metadata)
		: effective.safeParse(metadata);
}

/** Check supplied publication fields while allowing a Superior to complete missing fields. */
export function parseOAuthAuthorizationServerPublicationMetadata(metadata: unknown) {
	return publication.safeParse(metadata);
}
