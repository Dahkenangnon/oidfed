import { z } from "zod";
import { decodeEntityStatement } from "../jose/verify.js";
import { ResolveResponsePayloadSchema } from "../schemas/endpoints.js";
import { StorageEntityIdSchema, StorageJsonSchema } from "./record-schemas.js";

/** A compact cached statement. Callers still authenticate it and enforce its profile. */
export const StatementCacheValueSchema = z.string().regex(/^[\w-]+\.[\w-]+\.[\w-]+$/);

/** Optional Resolver evidence kept separately from the shared subject assessment. */
export const ResponderEvidenceSchema = z.strictObject({
	statements: z.array(StatementCacheValueSchema).min(1),
	entityConfigurations: z.array(z.tuple([StorageEntityIdSchema, StatementCacheValueSchema])),
	expiresAt: z.number().finite(),
});

export type CachedResponderEvidence = z.infer<typeof ResponderEvidenceSchema>;

/** A previously validated Resolve assessment and its local reuse deadline. */
export const ResolveAssessmentCacheValueSchema = z
	.strictObject({
		trustAnchor: StorageEntityIdSchema,
		payload: ResolveResponsePayloadSchema,
		// Older workers require this field. Writers leave it empty and readers ignore its contents.
		headers: z.strictObject({ trust_chain: z.array(StatementCacheValueSchema).min(1).optional() }),
		reuseUntil: z.number().finite(),
		localTrustMarkRevision: z.string().min(1).optional(),
	})
	.refine(
		({ payload, reuseUntil }) =>
			!Object.hasOwn(payload, "aud") &&
			payload.trust_chain.length > 0 &&
			payload.trust_chain.every((jwt) => StatementCacheValueSchema.safeParse(jwt).success) &&
			payload.iat < reuseUntil &&
			reuseUntil <= payload.exp &&
			StorageJsonSchema.safeParse(payload).success,
	);

export type ResolveAssessmentCacheValue = z.infer<typeof ResolveAssessmentCacheValueSchema>;

/** Bind a stored assessment to the request and the anchors allowed under the current configuration. */
export function readResolveAssessment(
	value: unknown,
	issuer: string,
	subject: string,
	anchors: readonly string[],
	now: number,
	maxCompactBytes?: number,
): ResolveAssessmentCacheValue | undefined {
	const parsed = ResolveAssessmentCacheValueSchema.safeParse(value);
	if (!parsed.success) return undefined;
	const { payload, reuseUntil, trustAnchor } = parsed.data;
	if (
		reuseUntil <= now ||
		payload.iss !== issuer ||
		payload.sub !== subject ||
		!anchors.includes(trustAnchor)
	)
		return undefined;
	// The subject chain is ordered from the Entity Configuration to a statement signed by the
	// selected anchor. This checks the cached association without redoing a network resolution.
	const first = decodeEntityStatement(payload.trust_chain[0] as string, { maxCompactBytes });
	const last = decodeEntityStatement(
		payload.trust_chain[payload.trust_chain.length - 1] as string,
		{ maxCompactBytes },
	);
	if (
		!first.ok ||
		first.value.payload.iss !== subject ||
		first.value.payload.sub !== subject ||
		!last.ok ||
		String(last.value.payload.iss) !== trustAnchor
	)
		return undefined;
	return parsed.data;
}
