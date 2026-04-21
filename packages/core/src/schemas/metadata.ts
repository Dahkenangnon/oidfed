/** Zod schemas for federation entity metadata types (openid_provider, openid_relying_party, etc.). */
import { z } from "zod";
import { EntityType } from "../constants.js";

/** URL that MUST use https scheme and MUST NOT contain a fragment. */
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

export const FederationEntityMetadataSchema = z.looseObject({
	federation_fetch_endpoint: httpsUrlNoFragment.optional(),
	federation_list_endpoint: httpsUrlNoFragment.optional(),
	federation_resolve_endpoint: httpsUrlNoFragment.optional(),
	federation_trust_mark_status_endpoint: httpsUrlNoFragment.optional(),
	federation_trust_mark_list_endpoint: httpsUrlNoFragment.optional(),
	federation_trust_mark_endpoint: httpsUrlNoFragment.optional(),
	federation_historical_keys_endpoint: httpsUrlNoFragment.optional(),
	federation_fetch_endpoint_auth_methods: z.array(z.string()).optional(),
	federation_list_endpoint_auth_methods: z.array(z.string()).optional(),
	federation_resolve_endpoint_auth_methods: z.array(z.string()).optional(),
	federation_trust_mark_status_endpoint_auth_methods: z.array(z.string()).optional(),
	federation_trust_mark_list_endpoint_auth_methods: z.array(z.string()).optional(),
	federation_trust_mark_endpoint_auth_methods: z.array(z.string()).optional(),
	federation_historical_keys_endpoint_auth_methods: z.array(z.string()).optional(),
	endpoint_auth_signing_alg_values_supported: z
		.array(z.string())
		.refine((arr) => !arr.includes("none"), { message: "The value 'none' MUST NOT be used" })
		.optional(),
	organization_name: z.string().optional(),
	display_name: z.string().optional(),
	description: z.string().optional(),
	keywords: z.array(z.string()).optional(),
	contacts: z.array(z.string()).optional(),
	logo_uri: z.string().url().optional(),
	policy_uri: z.string().url().optional(),
	information_uri: z.string().url().optional(),
	organization_uri: z.string().url().optional(),
});

/**
 * OpenID Relying Party metadata schema.
 *
 * In the federation layer, this is a loose record — protocol-specific
 * field validation is done by `@oidfed/oidc`.
 */
export const OpenIDRelyingPartyMetadataSchema = z.record(z.string(), z.unknown());

/**
 * OpenID Provider metadata schema.
 *
 * In the federation layer, this is a loose record — protocol-specific
 * field validation is done by `@oidfed/oidc`.
 */
export const OpenIDProviderMetadataSchema = z.record(z.string(), z.unknown());

export const FederationMetadataSchema = z
	.looseObject({
		federation_entity: FederationEntityMetadataSchema.optional(),
		openid_relying_party: OpenIDRelyingPartyMetadataSchema.optional(),
		openid_provider: OpenIDProviderMetadataSchema.optional(),
		oauth_authorization_server: z.record(z.string(), z.unknown()).optional(),
		oauth_client: z.record(z.string(), z.unknown()).optional(),
		oauth_resource: z.record(z.string(), z.unknown()).optional(),
	})
	.refine(
		(m) =>
			!!(
				m.federation_entity ||
				m.openid_relying_party ||
				m.openid_provider ||
				m.oauth_authorization_server ||
				m.oauth_client ||
				m.oauth_resource
			),
		{ message: "Metadata must contain at least one entity type" },
	);

export type FederationEntityMetadata = z.infer<typeof FederationEntityMetadataSchema>;
/** Federation-layer RP metadata (loose record). For typed OIDC fields, use `@oidfed/oidc`. */
export type OpenIDRelyingPartyMetadata = Record<string, unknown>;
/** Federation-layer OP metadata (loose record). For typed OIDC fields, use `@oidfed/oidc`. */
export type OpenIDProviderMetadata = Record<string, unknown>;
export type FederationMetadata = z.infer<typeof FederationMetadataSchema>;

export function getEntityTypes(metadata: FederationMetadata): ReadonlyArray<EntityType> {
	const types: EntityType[] = [];
	if (metadata.federation_entity) types.push(EntityType.FederationEntity);
	if (metadata.openid_relying_party) types.push(EntityType.OpenIDRelyingParty);
	if (metadata.openid_provider) types.push(EntityType.OpenIDProvider);
	if (metadata.oauth_authorization_server) types.push(EntityType.OAuthAuthorizationServer);
	if (metadata.oauth_client) types.push(EntityType.OAuthClient);
	if (metadata.oauth_resource) types.push(EntityType.OAuthResource);
	return types;
}

export type EntityTypeMetadataMap = {
	readonly [EntityType.FederationEntity]: FederationEntityMetadata;
	readonly [EntityType.OpenIDRelyingParty]: OpenIDRelyingPartyMetadata;
	readonly [EntityType.OpenIDProvider]: OpenIDProviderMetadata;
	readonly [EntityType.OAuthAuthorizationServer]: Record<string, unknown>;
	readonly [EntityType.OAuthClient]: Record<string, unknown>;
	readonly [EntityType.OAuthResource]: Record<string, unknown>;
};
