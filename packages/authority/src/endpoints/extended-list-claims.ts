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

import {
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	decodeEntityStatement,
	ExtendedListClaim,
	JwtTyp,
	prepareEntityStatementExtensions,
	preparePublicJwkSet,
	setOwn,
	TrustMarkRefSchema,
} from "@oidfed/core";
import type { SubordinateRecord } from "../storage/types.js";
import {
	assertSubordinatePublicationClaims,
	subordinatePublicationClaim,
} from "../utils/subordinate-publication.js";
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
	[ExtendedListClaim.Jwks]: (record) => {
		// Extended Listing §3.2 selects the public statement keys defined by Federation §3.1.1.
		const prepared = preparePublicJwkSet(record.jwks);
		if (!prepared.ok) throw new Error(prepared.error.description);
		return prepared.value;
	},
	[ExtendedListClaim.Metadata]: (record, ctx) =>
		subordinatePublicationClaim(record, "metadata", ctx),
	[ExtendedListClaim.MetadataPolicy]: (record, ctx) =>
		subordinatePublicationClaim(record, "metadata_policy", ctx),
	[ExtendedListClaim.Constraints]: (record, ctx) =>
		subordinatePublicationClaim(record, "constraints", ctx),
	[ExtendedListClaim.Crit]: (record) =>
		record.crit && record.crit.length > 0 ? [...record.crit] : undefined,
	[ExtendedListClaim.MetadataPolicyCrit]: (record) =>
		record.metadataPolicyCrit && record.metadataPolicyCrit.length > 0
			? [...record.metadataPolicyCrit]
			: undefined,
	[ExtendedListClaim.SourceEndpoint]: (record) => record.sourceEndpoint,
	[ExtendedListClaim.TrustMarks]: async (record, ctx, now) => {
		if (!ctx.storage.trustMarks) return [];
		const marks = await ctx.storage.trustMarks.listValidForSubject(record.entityId, now);
		return marks.map((mark) => {
			// Federation §3.1.2 binds the reference type to the enclosed Trust Mark.
			// This checks stored data consistency; ingestion establishes signature trust.
			const ref = TrustMarkRefSchema.safeParse({
				trust_mark_type: mark.trustMarkType,
				trust_mark: mark.jwt,
			});
			const decoded = ref.success ? decodeEntityStatement(ref.data.trust_mark) : undefined;
			if (
				!ref.success ||
				!decoded?.ok ||
				decoded.value.header.typ !== JwtTyp.TrustMark ||
				decoded.value.payload.trust_mark_type !== ref.data.trust_mark_type ||
				(decoded.value.payload.sub as string) !== mark.subject ||
				mark.subject !== record.entityId
			) {
				throw new Error("Invalid stored Trust Mark reference");
			}
			return ref.data;
		});
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
	let extensions: ReturnType<typeof prepareEntityStatementExtensions> | undefined;
	for (const claim of requestedClaims) {
		if (!Object.hasOwn(EXTENDED_LIST_CLAIM_EXTRACTORS, claim)) {
			// Listing fields retain their own meaning even when an SS extension uses that name.
			if (["id", "registered", "updated"].includes(claim)) continue;
			if (!record.additionalClaims || !Object.hasOwn(record.additionalClaims, claim)) continue;
			extensions ??= prepareEntityStatementExtensions(record);
			if (extensions.additionalClaims && Object.hasOwn(extensions.additionalClaims, claim))
				setOwn(out, claim, extensions.additionalClaims[claim]);
			continue;
		}
		if (claim === ExtendedListClaim.Crit || claim === ExtendedListClaim.MetadataPolicyCrit)
			assertSubordinatePublicationClaims({
				additionalClaims: record.additionalClaims,
				crit: record.crit,
				metadataPolicyCrit: record.metadataPolicyCrit,
			});
		const extractor = EXTENDED_LIST_CLAIM_EXTRACTORS[claim];
		if (!extractor) continue;
		const value = await extractor(record, ctx, now);
		if (value !== undefined) setOwn(out, claim, value);
	}
	return out;
}
