/** Zod schemas for Entity Statements (configurations and subordinate), including trust marks and registration payloads. */
import { z } from "zod";
import { TrustChainConstraintsSchema } from "./constraints.js";
import { EntityIdSchema } from "./entity-id.js";
import { JWKSetSchema } from "./jwk.js";
import { FederationMetadataSchema } from "./metadata.js";
import { TrustMarkOwnerSchema, TrustMarkRefSchema } from "./trust-mark.js";

export { EntityIdSchema };

/** Base fields shared by Entity Configurations and Subordinate Statements. */
const BaseEntityStatementFields = {
	iss: EntityIdSchema,
	sub: EntityIdSchema,
	iat: z.number().int().positive(),
	exp: z.number().int().positive(),
	jwks: JWKSetSchema.optional(),
	metadata: z.record(z.string(), z.record(z.string(), z.unknown())).optional(),
	metadata_policy: z.record(z.string(), z.record(z.string(), z.unknown())).optional(),
	constraints: TrustChainConstraintsSchema.optional(),
	crit: z.array(z.string()).min(1).optional(),
	metadata_policy_crit: z.array(z.string()).min(1).optional(),
	trust_marks: z.array(TrustMarkRefSchema).optional(),
	trust_mark_issuers: z.record(z.string(), z.array(z.string())).optional(),
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
		authority_hints: z.array(EntityIdSchema).optional(),
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

/** Combined Entity Statement schema accepting both ECs and SSs. */
export const EntityStatementPayloadSchema = z
	.looseObject({
		...BaseEntityStatementFields,
		authority_hints: z.array(EntityIdSchema).optional(),
		trust_anchor_hints: z.array(EntityIdSchema).min(1).optional(),
		source_endpoint: z.string().url().optional(),
		trust_anchor: z.string().url().optional(),
	})
	.refine((obj) => obj.exp > obj.iat, {
		message: "exp must be after iat",
		path: ["exp"],
	});

/** Explicit registration request payload. */
export const ExplicitRegistrationRequestPayloadSchema = z
	.looseObject({
		iss: EntityIdSchema,
		sub: EntityIdSchema,
		aud: z.string(),
		iat: z.number().int().positive(),
		exp: z.number().int().positive(),
		jwks: JWKSetSchema,
		authority_hints: z.array(EntityIdSchema).min(1),
		metadata: FederationMetadataSchema,
		trust_marks: z.array(TrustMarkRefSchema).optional(),
	})
	.refine((obj) => obj.exp > obj.iat, {
		message: "exp must be after iat",
		path: ["exp"],
	})
	.refine((obj) => obj.iss === obj.sub, {
		message: "Registration request must be self-signed (iss === sub)",
	})
	.refine(
		(obj) => {
			const meta = obj.metadata as Record<string, unknown> | undefined;
			return meta !== undefined && "openid_relying_party" in meta;
		},
		{
			message: "Explicit registration request metadata MUST contain 'openid_relying_party'",
			path: ["metadata"],
		},
	);

/** Explicit registration response payload. */
export const ExplicitRegistrationResponsePayloadSchema = z
	.looseObject({
		iss: EntityIdSchema,
		sub: EntityIdSchema,
		aud: z.string(),
		iat: z.number().int().positive(),
		exp: z.number().int().positive(),
		metadata: z.record(z.string(), z.record(z.string(), z.unknown())).optional(),
		trust_anchor: EntityIdSchema,
		authority_hints: z.array(EntityIdSchema).length(1),
		client_secret: z.string().optional(),
	})
	.refine((obj) => obj.exp > obj.iat, {
		message: "exp must be after iat",
		path: ["exp"],
	});

/** Historical key entry for the federation_historical_keys endpoint. */
export const HistoricalKeyEntrySchema = z.looseObject({
	kty: z.string(),
	kid: z.string(),
	use: z.string().optional(),
	alg: z.string().optional(),
	key_ops: z.array(z.string()).optional(),
	exp: z.number().int(),
	iat: z.number().int().optional(),
	nbf: z.number().int().optional(),
	revoked: z
		.looseObject({
			revoked_at: z.number().int(),
			reason: z.string().optional(),
		})
		.optional(),
});

export const HistoricalKeysPayloadSchema = z.object({
	iss: EntityIdSchema,
	iat: z.number().int().positive(),
	keys: z.array(HistoricalKeyEntrySchema),
});

/** Resolve Response payload for the federation_resolve endpoint. */
export const ResolveResponsePayloadSchema = z.looseObject({
	iss: EntityIdSchema,
	sub: EntityIdSchema,
	iat: z.number().int().positive(),
	exp: z.number().int().positive(),
	metadata: FederationMetadataSchema,
	trust_marks: z.array(TrustMarkRefSchema).optional(),
	trust_chain: z.array(z.string()),
	aud: z.union([z.string(), z.array(z.string())]).optional(),
});

/** Trust Mark Status Response payload. */
export const TrustMarkStatusResponsePayloadSchema = z.looseObject({
	iss: EntityIdSchema,
	iat: z.number().int().positive(),
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
