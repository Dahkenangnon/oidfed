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

import type { SubordinateRecord } from "@oidfed/core";
import {
	assertSubordinatePublicationClaims,
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	ExtendedListClaim,
	isStoredTrustMarkEligible,
	parseStoredTrustMark,
	prepareEntityStatementExtensions,
	preparePublicJwkSet,
	setOwn,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { buildSubordinateStatement } from "./fetch.js";
import { subordinatePublicationClaim } from "./subordinate-claims.js";

type ClaimExtractor = (
	record: SubordinateRecord,
	ctx: HandlerContext,
	now: number,
) => Promise<unknown> | unknown;

function statementExp(ctx: HandlerContext, now: number): number {
	return now + (ctx.subordinateStatementTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS);
}

const EXTENDED_LIST_CLAIM_EXTRACTORS: Readonly<Record<string, ClaimExtractor>> = {
	[ExtendedListClaim.SubordinateStatement]: async (record, ctx, now) =>
		buildSubordinateStatement(ctx, record, now),
	[ExtendedListClaim.Iss]: (_record, ctx) => ctx.entityId,
	[ExtendedListClaim.Sub]: (record) => record.entityId,
	[ExtendedListClaim.Iat]: (_record, _ctx, now) => now,
	[ExtendedListClaim.Exp]: (_record, ctx, now) => statementExp(ctx, now),
	[ExtendedListClaim.Jwks]: (record, ctx) => {
		// Extended Listing §3.2 selects the public statement keys defined by Federation §3.1.1.
		const prepared = preparePublicJwkSet(record.jwks, ctx.options.algorithmRegistry);
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
		const { trustMark, capabilities } = ctx.storage;
		if (!trustMark || !capabilities.includes("trustMark:read")) return [];
		const marks = await trustMark.forSubject(record.entityId, now);
		const references = [];
		for (const raw of marks) {
			const mark = parseStoredTrustMark(raw, ctx.options, "forSubject", {
				subject: record.entityId,
			});
			if (isStoredTrustMarkEligible(mark, now, ctx.options))
				references.push({ trust_mark_type: mark.trustMarkType, trust_mark: mark.jwt });
		}
		return references;
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
