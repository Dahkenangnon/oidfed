/**
 * Per-entity claim extractors used by the Extended Subordinate Listing endpoint.
 * Each extractor maps a top-level Entity Statement claim name to a value that is
 * derived from the stored {@link SubordinateRecord} (and, for trust marks, from
 * the trust mark store).
 *
 * Some claims (iss, sub, iat, exp, subordinate_statement) are synthetic: they
 * are computed from the handler context plus a per-request "now" snapshot. The
 * snapshot lets callers align the synthetic iat/exp with the iat/exp inside the
 * signed subordinate_statement JWT for the same record.
 */
import { DEFAULT_ENTITY_STATEMENT_TTL_SECONDS, ExtendedListClaim } from "@oidfed/core";
import type { SubordinateRecord } from "../storage/types.js";
import type { HandlerContext } from "./context.js";
import { buildSubordinateStatement } from "./fetch.js";

export type ClaimExtractor = (
	record: SubordinateRecord,
	ctx: HandlerContext,
	now: number,
) => Promise<unknown> | unknown;

function statementExp(ctx: HandlerContext, now: number): number {
	return now + (ctx.subordinateStatementTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS);
}

export const EXTENDED_LIST_CLAIM_EXTRACTORS: Readonly<Record<string, ClaimExtractor>> = {
	[ExtendedListClaim.SubordinateStatement]: async (record, ctx, now) =>
		buildSubordinateStatement(ctx, record, now),
	[ExtendedListClaim.Iss]: (_record, ctx) => ctx.entityId,
	[ExtendedListClaim.Sub]: (record) => record.entityId,
	[ExtendedListClaim.Iat]: (_record, _ctx, now) => now,
	[ExtendedListClaim.Exp]: (_record, ctx, now) => statementExp(ctx, now),
	[ExtendedListClaim.Jwks]: (record) => record.jwks,
	[ExtendedListClaim.Metadata]: (record) => record.metadata,
	[ExtendedListClaim.MetadataPolicy]: (record) => record.metadataPolicy,
	[ExtendedListClaim.Constraints]: (record) => record.constraints,
	[ExtendedListClaim.Crit]: (record) =>
		record.crit && record.crit.length > 0 ? [...record.crit] : undefined,
	[ExtendedListClaim.MetadataPolicyCrit]: (record) =>
		record.metadataPolicyCrit && record.metadataPolicyCrit.length > 0
			? [...record.metadataPolicyCrit]
			: undefined,
	[ExtendedListClaim.SourceEndpoint]: (record) => record.sourceEndpoint,
	[ExtendedListClaim.TrustMarks]: async (record, ctx) => {
		if (!ctx.trustMarkStore?.listForSubject) return [];
		const marks = await ctx.trustMarkStore.listForSubject(record.entityId);
		return marks.map((m) => ({ id: m.trustMarkType, trust_mark: m.jwt }));
	},
};

/**
 * Resolve the set of requested claims into per-entity fields. Unknown claim
 * names are silently ignored. Extractors that return undefined are omitted so
 * the response object stays minimal. The `now` argument is a NumericDate snapshot
 * shared across all entries in the same response.
 */
export async function extractClaims(
	record: SubordinateRecord,
	ctx: HandlerContext,
	requestedClaims: ReadonlyArray<string>,
	now: number,
): Promise<Record<string, unknown>> {
	const out: Record<string, unknown> = {};
	for (const claim of requestedClaims) {
		const extractor = EXTENDED_LIST_CLAIM_EXTRACTORS[claim];
		if (!extractor) continue;
		const value = await extractor(record, ctx, now);
		if (value !== undefined) out[claim] = value;
	}
	return out;
}
