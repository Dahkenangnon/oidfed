/** Structural federation metadata schemas; protocol packages enforce role-specific conformance. */

import { z } from "zod";
import { EntityType, type EntityTypeIdentifier } from "../constants.js";

const nonEmptyStringArray = z.array(z.string()).min(1);

/** URL that MUST use https scheme and MUST NOT contain a fragment. */
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

export const FederationEntityMetadataSchema = z.looseObject({
	federation_fetch_endpoint: httpsUrlNoFragment.optional(),
	federation_list_endpoint: httpsUrlNoFragment.optional(),
	federation_extended_list_endpoint: httpsUrlNoFragment.optional(),
	federation_subordinate_events_endpoint: httpsUrlNoFragment.optional(),
	federation_resolve_endpoint: httpsUrlNoFragment.optional(),
	federation_collection_endpoint: httpsUrlNoFragment.optional(),
	federation_trust_mark_status_endpoint: httpsUrlNoFragment.optional(),
	federation_trust_mark_list_endpoint: httpsUrlNoFragment.optional(),
	federation_trust_mark_endpoint: httpsUrlNoFragment.optional(),
	federation_historical_keys_endpoint: httpsUrlNoFragment.optional(),
	federation_fetch_endpoint_auth_methods: z.array(z.string()).optional(),
	federation_list_endpoint_auth_methods: z.array(z.string()).optional(),
	federation_extended_list_endpoint_auth_methods: z.array(z.string()).optional(),
	federation_subordinate_events_endpoint_auth_methods: z.array(z.string()).optional(),
	federation_resolve_endpoint_auth_methods: z.array(z.string()).optional(),
	federation_collection_endpoint_auth_methods: z.array(z.string()).optional(),
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
	keywords: nonEmptyStringArray.optional(),
	contacts: nonEmptyStringArray.optional(),
	logo_uri: z.string().url().optional(),
	policy_uri: z.string().url().optional(),
	information_uri: z.string().url().optional(),
	organization_uri: z.string().url().optional(),
});

/** Structural OpenID Relying Party metadata. `@oidfed/oidc` validates protocol-specific fields. */
export const OpenIDRelyingPartyMetadataSchema = z.record(z.string(), z.unknown());

/** Structural OpenID Provider metadata. `@oidfed/oidc` validates protocol-specific fields. */
export const OpenIDProviderMetadataSchema = z.record(z.string(), z.unknown());

/** Internal schema for supplied and resolved metadata, including empty results. */
export const FederationMetadataValuesSchema = z
	.looseObject({
		federation_entity: FederationEntityMetadataSchema.optional(),
		openid_relying_party: OpenIDRelyingPartyMetadataSchema.optional(),
		openid_provider: OpenIDProviderMetadataSchema.optional(),
		oauth_authorization_server: z.record(z.string(), z.unknown()).optional(),
		oauth_client: z.record(z.string(), z.unknown()).optional(),
		oauth_resource: z.record(z.string(), z.unknown()).optional(),
		openid_wallet_provider: z.record(z.string(), z.unknown()).optional(),
		openid_credential_issuer: z.record(z.string(), z.unknown()).optional(),
		openid_credential_verifier: z.record(z.string(), z.unknown()).optional(),
	})
	.superRefine((metadata, ctx) => {
		const entries = Object.entries(metadata);
		for (const [entityType, value] of entries) {
			if (!value || typeof value !== "object" || Array.isArray(value)) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: "Entity type metadata must be a JSON object",
					path: [entityType],
				});
			}
		}
	});

export const FederationMetadataSchema = FederationMetadataValuesSchema.superRefine(
	(metadata, ctx) => {
		if (Object.keys(metadata).length === 0) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "Metadata must contain at least one entity type",
			});
		}
	},
);

export type FederationEntityMetadata = z.infer<typeof FederationEntityMetadataSchema>;
/** Federation-layer RP metadata (loose record). For typed OIDC fields, use `@oidfed/oidc`. */
export type OpenIDRelyingPartyMetadata = Record<string, unknown>;
/** Federation-layer OP metadata (loose record). For typed OIDC fields, use `@oidfed/oidc`. */
export type OpenIDProviderMetadata = Record<string, unknown>;
export type FederationMetadata = z.infer<typeof FederationMetadataSchema>;

/** Federation §5.1 allows framework-defined entity type identifiers. */
export function getEntityTypes(metadata: FederationMetadata): ReadonlyArray<EntityTypeIdentifier> {
	return Object.keys(metadata).filter((type) => metadata[type] !== undefined);
}

export type EntityTypeMetadataMap = {
	readonly [EntityType.OpenIDWalletProvider]: Record<string, unknown>;
	readonly [EntityType.OpenIDCredentialIssuer]: Record<string, unknown>;
	readonly [EntityType.OpenIDCredentialVerifier]: Record<string, unknown>;
	readonly [EntityType.FederationEntity]: FederationEntityMetadata;
	readonly [EntityType.OpenIDRelyingParty]: OpenIDRelyingPartyMetadata;
	readonly [EntityType.OpenIDProvider]: OpenIDProviderMetadata;
	readonly [EntityType.OAuthAuthorizationServer]: Record<string, unknown>;
	readonly [EntityType.OAuthClient]: Record<string, unknown>;
	readonly [EntityType.OAuthResource]: Record<string, unknown>;
};
