/** Zod schemas for Trust Mark JWTs and Trust Mark Owner declarations. */
import { z } from "zod";
import { EntityIdSchema } from "./entity-id.js";
import { JWKSetSchema } from "./jwk.js";

export const TrustMarkRefSchema = z.object({
	trust_mark_type: z.string(),
	trust_mark: z.string(),
});

export const TrustMarkOwnerSchema = z.looseObject({
	sub: z.string(),
	jwks: JWKSetSchema,
});

export const TrustMarkPayloadSchema = z.looseObject({
	iss: EntityIdSchema,
	sub: EntityIdSchema,
	trust_mark_type: z.string(),
	iat: z.number().int().positive(),
	exp: z.number().int().positive().optional(),
	logo_uri: z.string().url().optional(),
	ref: z.string().url().optional(),
	delegation: z.string().optional(),
});

export const TrustMarkDelegationPayloadSchema = z.looseObject({
	iss: EntityIdSchema,
	sub: EntityIdSchema,
	trust_mark_type: z.string(),
	iat: z.number().int().positive(),
	exp: z.number().int().positive().optional(),
	ref: z.string().url().optional(),
});

export type TrustMarkRef = z.infer<typeof TrustMarkRefSchema>;
export type TrustMarkOwner = z.infer<typeof TrustMarkOwnerSchema>;
export type TrustMarkPayload = z.infer<typeof TrustMarkPayloadSchema>;
export type TrustMarkDelegationPayload = z.infer<typeof TrustMarkDelegationPayloadSchema>;
