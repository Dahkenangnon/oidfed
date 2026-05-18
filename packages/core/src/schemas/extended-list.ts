/** Zod schemas for the Extended Subordinate Listing endpoint (request query, per-entity entries, and response). */
import { z } from "zod";
import { EntityIdSchema } from "./entity-id.js";

/** Top-level Entity Statement claims that the extended listing endpoint can return per entity. */
export const ExtendedListClaim = {
	SubordinateStatement: "subordinate_statement",
	Iss: "iss",
	Sub: "sub",
	Iat: "iat",
	Exp: "exp",
	Jwks: "jwks",
	Metadata: "metadata",
	MetadataPolicy: "metadata_policy",
	Constraints: "constraints",
	Crit: "crit",
	MetadataPolicyCrit: "metadata_policy_crit",
	TrustMarks: "trust_marks",
	SourceEndpoint: "source_endpoint",
} as const;
export type ExtendedListClaim = (typeof ExtendedListClaim)[keyof typeof ExtendedListClaim];

export const EXTENDED_LIST_SUPPORTED_CLAIMS: ReadonlySet<ExtendedListClaim> = new Set(
	Object.values(ExtendedListClaim),
);

const booleanQueryValue = z
	.enum(["true", "false"])
	.transform((v) => v === "true")
	.optional();

const positiveIntQueryValue = z
	.string()
	.regex(/^[1-9][0-9]*$/, "limit must be a positive integer")
	.transform((v) => Number.parseInt(v, 10))
	.optional();

const numericDateQueryValue = z
	.string()
	.regex(/^[0-9]+$/, "must be a NumericDate (non-negative integer)")
	.transform((v) => Number.parseInt(v, 10))
	.optional();

/** Server-side query schema. Accepts raw HTTP query strings and coerces them into typed values. */
export const ExtendedListQuerySchema = z.object({
	from_entity_id: EntityIdSchema.optional(),
	limit: positiveIntQueryValue,
	updated_after: numericDateQueryValue,
	updated_before: numericDateQueryValue,
	audit_timestamps: booleanQueryValue,
	claims: z.array(z.string()).optional(),
	entity_type: z.array(z.string()).optional(),
	trust_marked: booleanQueryValue,
	trust_mark_type: z.string().optional(),
	intermediate: booleanQueryValue,
});

/** Per-entity object inside `immediate_subordinate_entities`. Loose so custom claims may be present. */
export const ExtendedListEntitySchema = z.looseObject({
	id: EntityIdSchema,
	subordinate_statement: z.string().optional(),
	registered: z.number().int().nonnegative().optional(),
	updated: z.number().int().nonnegative().optional(),
});

/** Top-level response shape. */
export const ExtendedListResponseSchema = z.object({
	immediate_subordinate_entities: z.array(ExtendedListEntitySchema),
	next_entity_id: EntityIdSchema.optional(),
});

export type ExtendedListQuery = z.infer<typeof ExtendedListQuerySchema>;
export type ExtendedListEntity = z.infer<typeof ExtendedListEntitySchema>;
export type ExtendedListResponse = z.infer<typeof ExtendedListResponseSchema>;

/** Client-facing request parameters; serialised into URL query string by the fetch helper. */
export interface ExtendedListRequestParams {
	fromEntityId?: string;
	limit?: number;
	updatedAfter?: number;
	updatedBefore?: number;
	auditTimestamps?: boolean;
	claims?: ReadonlyArray<ExtendedListClaim | string>;
	entityType?: string | ReadonlyArray<string>;
	trustMarked?: boolean;
	trustMarkType?: string;
	intermediate?: boolean;
}
