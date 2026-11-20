/** Entity Configuration and Subordinate Statement schemas. */

import { z } from "zod";
import { TrustChainConstraintsSchema } from "./constraints.js";
import { EntityIdSchema } from "./entity-id.js";
import { JWKSetSchema } from "./jwk.js";
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

export type EntityStatementPayload = z.infer<typeof EntityStatementPayloadSchema>;
export type EntityConfigurationPayload = z.infer<typeof EntityConfigurationSchema>;
export type SubordinateStatementPayload = z.infer<typeof SubordinateStatementSchema>;
