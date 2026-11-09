/** Zod schemas for Entity Statements (configurations and subordinate), including trust marks and registration payloads. */
import { z } from "zod";
import { TrustChainConstraintsSchema } from "./constraints.js";
import { EntityIdSchema } from "./entity-id.js";
import { JWKSetSchema, MetadataJWKSetSchema } from "./jwk.js";
import { FederationMetadataSchema, FederationMetadataValuesSchema } from "./metadata.js";
import { TrustMarkOwnerSchema, TrustMarkRefSchema } from "./trust-mark.js";

export { EntityIdSchema };

/** Base fields shared by Entity Configurations and Subordinate Statements. */
const BaseEntityStatementFields = {
	iss: EntityIdSchema,
	sub: EntityIdSchema,
	iat: z.number().finite(),
	exp: z.number().finite(),
	jwks: JWKSetSchema,
	metadata: z.record(z.string(), z.record(z.string(), z.unknown())).optional(),
	metadata_policy: z.record(z.string(), z.record(z.string(), z.unknown())).optional(),
	constraints: TrustChainConstraintsSchema.optional(),
	crit: z.array(z.string()).min(1).optional(),
	metadata_policy_crit: z.array(z.string()).min(1).optional(),
	trust_marks: z.array(TrustMarkRefSchema).optional(),
	trust_mark_issuers: z.record(z.string(), z.array(EntityIdSchema)).optional(),
	trust_mark_owners: z.record(z.string(), TrustMarkOwnerSchema).optional(),
	aud: z.union([z.string(), z.array(z.string())]).optional(),
} as const;

export const BaseEntityStatementSchema = z
	.looseObject(BaseEntityStatementFields)
	.refine((obj) => obj.exp > obj.iat, {
		message: "exp must be after iat",
		path: ["exp"],
	});

/** Self-signed Entity Configuration: iss === sub, may include authority_hints. */
export const EntityConfigurationSchema = z
	.looseObject({
		...BaseEntityStatementFields,
		jwks: JWKSetSchema,
		metadata: FederationMetadataSchema.optional(),
		authority_hints: z.array(EntityIdSchema).min(1).optional(),
		trust_anchor_hints: z.array(EntityIdSchema).min(1).optional(),
	})
	.refine((obj) => obj.exp > obj.iat, {
		message: "exp must be after iat",
		path: ["exp"],
	})
	.refine((obj) => obj.iss === obj.sub, {
		message: "Entity Configuration must be self-signed (iss === sub)",
	});

/** Subordinate Statement issued by a superior about a subordinate entity. */
export const SubordinateStatementSchema = z
	.looseObject({
		...BaseEntityStatementFields,
		metadata: FederationMetadataValuesSchema.optional(),
		jwks: JWKSetSchema,
		source_endpoint: z.string().url().optional(),
		trust_anchor: z.string().url().optional(),
	})
	.refine((obj) => obj.exp > obj.iat, {
		message: "exp must be after iat",
		path: ["exp"],
	})
	.refine((obj) => obj.iss !== obj.sub, {
		message: "Subordinate Statement iss must differ from sub",
	});

/** Fields recognized before the token profile is established. */
const CombinedEntityStatementFields = {
	...BaseEntityStatementFields,
	authority_hints: z.array(EntityIdSchema).min(1).optional(),
	trust_anchor_hints: z.array(EntityIdSchema).min(1).optional(),
	source_endpoint: z.string().url().optional(),
	trust_anchor: z.string().url().optional(),
};
const DecodedFederationJwtPayloadSchema = z.looseObject({
	...CombinedEntityStatementFields,
	jwks: JWKSetSchema.optional(),
});
/** Decoded federation tokens still need profile-specific claim validation. */
export type DecodedFederationJwtPayload = z.infer<typeof DecodedFederationJwtPayloadSchema>;

/** Combined Entity Statement schema accepting both ECs and SSs. */
export const EntityStatementPayloadSchema = z
	.looseObject(CombinedEntityStatementFields)
	.refine((obj) => obj.exp > obj.iat, { message: "exp must be after iat", path: ["exp"] });

/** Historical key entry for the federation_historical_keys endpoint. */
export const HistoricalKeyEntrySchema = z.looseObject({
	kty: z.string(),
	kid: z.string(),
	use: z.string().optional(),
	alg: z.string().optional(),
	key_ops: z.array(z.string()).optional(),
	exp: z.number().finite(),
	iat: z.number().finite().optional(),
	nbf: z.number().finite().optional(),
	revoked: z
		.looseObject({
			revoked_at: z.number().finite(),
			reason: z.string().optional(),
		})
		.optional(),
});

export const HistoricalKeysPayloadSchema = z.object({
	iss: EntityIdSchema,
	iat: z.number().finite(),
	keys: z.array(HistoricalKeyEntrySchema),
});

/** Signed JWK Set payload — returned by signed_jwks_uri. typ must be jwk-set+jwt. */
export const SignedJwkSetPayloadSchema = z.looseObject({
	iss: EntityIdSchema,
	sub: EntityIdSchema,
	keys: MetadataJWKSetSchema.shape.keys,
	iat: z.number().int().positive().optional(),
	exp: z.number().int().positive().optional(),
});
export type SignedJwkSetPayload = z.infer<typeof SignedJwkSetPayloadSchema>;

const ResolveResponseAudienceEntitySchema = z
	.string()
	.refine((value) => EntityIdSchema.safeParse(value).success, "Invalid audience Entity Identifier");

// RFC 7519 §4.1.3 allows arrays; Federation §8.3.2 limits them to one distinct recipient.
const ResolveResponseAudienceSchema = z.union([
	ResolveResponseAudienceEntitySchema,
	z
		.array(ResolveResponseAudienceEntitySchema)
		.min(1)
		.refine(
			(values) => values.every((value) => value === values[0]),
			"Resolve response audience must identify only the requesting party",
		),
]);

/** Resolve Response payload for the federation_resolve endpoint. */
export const ResolveResponsePayloadSchema = z.looseObject({
	iss: EntityIdSchema,
	sub: EntityIdSchema,
	iat: z.number().int().positive(),
	exp: z.number().int().positive(),
	metadata: FederationMetadataSchema,
	trust_marks: z.array(TrustMarkRefSchema).optional(),
	trust_chain: z.array(z.string()),
	aud: ResolveResponseAudienceSchema.optional(),
});

/** Trust Mark Status Response payload. */
export const TrustMarkStatusResponsePayloadSchema = z.looseObject({
	iss: EntityIdSchema,
	iat: z.number().finite(),
	trust_mark: z.string(),
	status: z.string(),
});

export const FetchQuerySchema = z.object({
	sub: EntityIdSchema,
	iss: EntityIdSchema.optional(),
});

export const ListQuerySchema = z.object({
	entity_type: z.string().optional(),
	trust_marked: z
		.enum(["true", "false"])
		.transform((v) => v === "true")
		.optional(),
	trust_mark_type: z.string().optional(),
	intermediate: z
		.enum(["true", "false"])
		.transform((v) => v === "true")
		.optional(),
});

export const ResolveQuerySchema = z.object({
	sub: EntityIdSchema,
	trust_anchor: z.union([EntityIdSchema, z.array(EntityIdSchema)]),
	entity_type: z.union([z.string(), z.array(z.string())]).optional(),
});

export const TrustMarkStatusBodySchema = z.object({
	trust_mark: z.string().min(1),
});

export type EntityStatementPayload = z.infer<typeof EntityStatementPayloadSchema>;
export type EntityConfigurationPayload = z.infer<typeof EntityConfigurationSchema>;
export type SubordinateStatementPayload = z.infer<typeof SubordinateStatementSchema>;
export type HistoricalKeyEntry = z.infer<typeof HistoricalKeyEntrySchema>;
export type HistoricalKeysPayload = z.infer<typeof HistoricalKeysPayloadSchema>;
export type ResolveResponsePayload = z.infer<typeof ResolveResponsePayloadSchema>;
export type TrustMarkStatusResponsePayload = z.infer<typeof TrustMarkStatusResponsePayloadSchema>;
