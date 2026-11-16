/** OpenID Federation Entity Collection Endpoint 1.0, Draft 01. */

import { z } from "zod";
import { isLanguageTag, splitInformationalClaim } from "../language-tags.js";
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

/** Use the same declared-name interpretation on refresh, publication and consumption. */
export function createCollectionSchemas(infoClaims: readonly string[] = []) {
	const declared = new Set<string>([...COLLECTION_INFO_CLAIMS, ...infoClaims]);
	const info = z.record(z.string(), z.unknown()).superRefine((values, ctx) => {
		for (const [name, value] of Object.entries(values)) {
			const parsed = splitInformationalClaim(name, declared);
			const standard = (COLLECTION_INFO_CLAIMS as readonly string[]).includes(parsed.base);
			if (
				parsed.malformed ||
				(standard &&
					!FederationEntityMetadataSchema.shape[
						parsed.base as (typeof COLLECTION_INFO_CLAIMS)[number]
					].safeParse(value).success)
			)
				ctx.addIssue({
					code: "custom",
					path: [name],
					message: `Invalid informational claim ${name}`,
				});
		}
	});
	const entity = z.looseObject({
		entity_id: EntityIdSchema,
		entity_types: z.array(z.string()).optional(),
		entity_infos: z.record(z.string(), info).optional(),
		trust_marks: z.array(TrustMarkRefSchema).optional(),
	});
	const response = z.looseObject({
		entities: z.array(entity),
		next: z.string().optional(),
		last_updated: z.number().finite().optional(),
	});
	return { info, entity, response };
}
const defaultSchemas = createCollectionSchemas();
export const EntityTypeInfoSchema = defaultSchemas.info;
export const EntityCollectionEntitySchema = defaultSchemas.entity;
export const EntityCollectionResponseSchema = defaultSchemas.response;
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
