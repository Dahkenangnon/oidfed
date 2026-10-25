/** OpenID Federation Entity Collection Endpoint 1.0, Draft 01. */
import { z } from "zod";
import { isLanguageTag } from "../language-tags.js";
import { EntityIdSchema } from "./entity-id.js";
import { FederationEntityMetadataSchema } from "./metadata.js";
import { TrustMarkRefSchema } from "./trust-mark.js";

export const COLLECTION_INFO_CLAIMS = [
	"organization_name",
	"display_name",
	"description",
	"keywords",
	"contacts",
	"logo_uri",
	"policy_uri",
	"information_uri",
	"organization_uri",
] as const;

export const EntityTypeInfoSchema = z.record(z.string(), z.unknown()).superRefine((info, ctx) => {
	for (const [name, value] of Object.entries(info)) {
		const [base = name, ...tags] = name.split("#");
		if (!(COLLECTION_INFO_CLAIMS as readonly string[]).includes(base)) continue;
		if (
			(tags.length > 0 && (tags.length !== 1 || !isLanguageTag(tags[0] ?? ""))) ||
			!FederationEntityMetadataSchema.shape[
				base as (typeof COLLECTION_INFO_CLAIMS)[number]
			].safeParse(value).success
		)
			ctx.addIssue({
				code: "custom",
				path: [name],
				message: `Invalid informational claim ${name}`,
			});
	}
});
export const EntityCollectionEntitySchema = z.looseObject({
	entity_id: EntityIdSchema,
	entity_types: z.array(z.string()).optional(),
	entity_infos: z.record(z.string(), EntityTypeInfoSchema).optional(),
	trust_marks: z.array(TrustMarkRefSchema).optional(),
});
export const EntityCollectionResponseSchema = z.looseObject({
	entities: z.array(EntityCollectionEntitySchema),
	next: z.string().optional(),
	last_updated: z.number().finite().optional(),
});
export const EntityCollectionRequestSchema = z.strictObject({
	from: z.string().min(1).optional(),
	limit: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
	trustAnchor: EntityIdSchema.optional(),
	entityType: z.array(z.string().min(1)).optional(),
	trustMarkType: z.array(z.string().min(1)).optional(),
	query: z.string().optional(),
	entityClaims: z.array(z.string().min(1)).optional(),
	infoClaims: z.array(z.string().min(1)).optional(),
	locale: z
		.array(z.string().min(1).refine(isLanguageTag, "Expected a BCP47 language tag"))
		.optional(),
});
export type EntityCollectionEntity = z.infer<typeof EntityCollectionEntitySchema>;
export type EntityTypeInfo = z.infer<typeof EntityTypeInfoSchema>;
export type EntityCollectionResponse = z.infer<typeof EntityCollectionResponseSchema>;
export type EntityCollectionRequestParams = z.input<typeof EntityCollectionRequestSchema>;
