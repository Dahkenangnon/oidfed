/** Query and response schemas for Federation endpoints and Signed JWK Sets. */

import type { Jwk } from "@oidfed/crypto";
import { z } from "zod";
import { EntityIdSchema } from "./entity-id.js";
import { JWKSchema, MetadataJWKSetSchema } from "./jwk.js";
import { FederationMetadataValuesSchema } from "./metadata.js";
import { TrustMarkRefSchema } from "./trust-mark.js";

/** Historical key entry for the federation_historical_keys endpoint. */
export const HistoricalKeyEntrySchema = JWKSchema.safeExtend({
	kid: z.string(),
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

export const HistoricalKeysPayloadSchema = z.looseObject({
	iss: EntityIdSchema,
	iat: z.number().finite(),
	keys: z.array(HistoricalKeyEntrySchema),
});

/** Payload returned by signed_jwks_uri, with JWT typ jwk-set+jwt. */
export const SignedJwkSetPayloadSchema = z.looseObject({
	iss: EntityIdSchema,
	sub: EntityIdSchema,
	keys: MetadataJWKSetSchema.shape.keys,
	iat: z.number().finite().optional(),
	exp: z.number().finite().optional(),
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
	iat: z.number().finite(),
	exp: z.number().finite(),
	metadata: FederationMetadataValuesSchema,
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

/** Public key and recorded protocol lifetime; timestamps are finite NumericDates. */
export interface HistoricalKeyEntry extends Jwk {
	readonly kid: string;
	readonly exp: number;
	readonly iat?: number | undefined;
	readonly nbf?: number | undefined;
	readonly revoked?:
		| { readonly revoked_at: number; readonly reason?: string | undefined }
		| undefined;
}
export type HistoricalKeysPayload = z.infer<typeof HistoricalKeysPayloadSchema>;
export type ResolveResponsePayload = z.infer<typeof ResolveResponsePayloadSchema>;
export type TrustMarkStatusResponsePayload = z.infer<typeof TrustMarkStatusResponsePayloadSchema>;
