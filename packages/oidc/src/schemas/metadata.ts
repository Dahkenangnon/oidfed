/** Typed Zod schemas for OpenID Provider and Relying Party metadata with federation-specific fields. */

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

/**
 * Typed OpenID Relying Party metadata schema.
 * Provides OIDC-specific field-level validation beyond the federation layer's `z.record()`.
 */
export const OpenIDRelyingPartyMetadataSchema = z.looseObject({
	redirect_uris: z.array(z.string().url()).optional(),
	response_types: z.array(z.string()).optional(),
	grant_types: z.array(z.string()).optional(),
	application_type: z.enum(["web", "native"]).optional(),
	client_name: z.string().optional(),
	token_endpoint_auth_method: z.string().optional(),
	jwks: JWKSetSchema.optional(),
	jwks_uri: httpsUrlNoFragment.optional(),
	signed_jwks_uri: httpsUrlNoFragment.optional(),
	client_registration_types: z.array(z.string()).optional(),
	scope: z.string().optional(),
});

/**
 * Typed OpenID Provider metadata schema.
 * Provides OIDC-specific field-level validation beyond the federation layer's `z.record()`.
 */
export const OpenIDProviderMetadataSchema = z.looseObject({
	issuer: z.string().url(),
	authorization_endpoint: z.string().url(),
	token_endpoint: z.string().url(),
	jwks_uri: httpsUrlNoFragment.optional(),
	signed_jwks_uri: httpsUrlNoFragment.optional(),
	jwks: JWKSetSchema.optional(),
	response_types_supported: z.array(z.string()),
	subject_types_supported: z.array(z.string()),
	id_token_signing_alg_values_supported: z.array(z.string()),
	client_registration_types_supported: z.array(z.string()).optional(),
	federation_registration_endpoint: httpsUrlNoFragment.optional(),
});

export type OpenIDRelyingPartyMetadata = z.infer<typeof OpenIDRelyingPartyMetadataSchema>;
export type OpenIDProviderMetadata = z.infer<typeof OpenIDProviderMetadataSchema>;

/**
 * Extended federation metadata schema with OIDC-strict validation.
 * Ensures that `openid_provider` or `openid_relying_party` metadata
 * conforms to their typed schemas (not just `z.record()`).
 */
export const OIDCFederationMetadataSchema = FederationMetadataSchema.pipe(
	z.looseObject({
		federation_entity: FederationEntityMetadataSchema.optional(),
		openid_relying_party: OpenIDRelyingPartyMetadataSchema.optional(),
		openid_provider: OpenIDProviderMetadataSchema.optional(),
		oauth_authorization_server: z.record(z.string(), z.unknown()).optional(),
		oauth_client: z.record(z.string(), z.unknown()).optional(),
		oauth_resource: z.record(z.string(), z.unknown()).optional(),
	}),
);

export type OIDCFederationMetadata = z.infer<typeof OIDCFederationMetadataSchema>;

/**
 * Parse and validate metadata with OIDC-strict validation.
 */
export function validateOIDCMetadata(raw: unknown): OIDCFederationMetadata {
	return OIDCFederationMetadataSchema.parse(raw);
}
