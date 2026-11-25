/**
 * Per-entity claim extractors used by the Extended Subordinate Listing endpoint.
 * Each extractor maps a top-level Entity Statement claim name to a value that is
 * derived from the stored {@link SubordinateRecord} (and, for trust marks, from
 * the trust mark store).
 *
 * On-demand issuance uses the page's clock and one lifetime per row. Retained
 * mode projects statement claims from the approved and verified signed payload.
 */

import type { SubordinateRecord } from "@oidfed/core";
import {
	assertSubordinatePublicationClaims,
	ExtendedListClaim,
	isStoredTrustMarkEligible,
	parseStoredTrustMark,
	prepareEntityStatementExtensions,
	preparePublicJwkSet,
	setOwn,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { subordinatePublicationClaim } from "./subordinate-claims.js";
import {
	buildSubordinateStatement,
	type RetainedSubordinateStatement,
	subordinateLifetime,
} from "./subordinate-statement.js";

type ClaimExtractor = (
	record: SubordinateRecord,
	ctx: HandlerContext,
	now: number,
	lifetime?: number,
) => Promise<unknown> | unknown;

const EXTENDED_LIST_CLAIM_EXTRACTORS: Readonly<Record<string, ClaimExtractor>> = {
	[ExtendedListClaim.SubordinateStatement]: (record, ctx, now, lifetime) =>
		buildSubordinateStatement(ctx, record, now, lifetime),
	[ExtendedListClaim.Iss]: (_record, ctx) => ctx.entityId,
	[ExtendedListClaim.Sub]: (record) => record.entityId,
	[ExtendedListClaim.Iat]: (_record, _ctx, now) => now,
	[ExtendedListClaim.Exp]: (record, ctx, now, lifetime) => {
		const exp = now + (lifetime ?? subordinateLifetime(ctx, record));
		if (!Number.isFinite(exp) || exp <= now) throw new TypeError("Invalid statement expiry");
		return exp;
	},
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

const independentListingClaims = new Set([
	"id",
	"registered",
	"updated",
	ExtendedListClaim.TrustMarks,
]);

/** An unknown requested name needs evidence only when it names an approved extension on the row. */
function isStatementClaim(claim: string, record?: SubordinateRecord): boolean {
	return (
		!independentListingClaims.has(claim) &&
		(record === undefined ||
			Object.hasOwn(EXTENDED_LIST_CLAIM_EXTRACTORS, claim) ||
			(record.additionalClaims !== undefined && Object.hasOwn(record.additionalClaims, claim)))
	);
}

/** Identify listing work that depends on retained statement evidence. */
export function requestsSubordinatePublication(
	claims: readonly string[],
	record?: SubordinateRecord,
): boolean {
	return claims.some((claim) => isStatementClaim(claim, record));
}

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
	retained?: RetainedSubordinateStatement,
): Promise<Record<string, unknown>> {
	const out: Record<string, unknown> = {};
	const lifetime =
		!retained &&
		(requestedClaims.includes(ExtendedListClaim.Exp) ||
			requestedClaims.includes(ExtendedListClaim.SubordinateStatement))
			? subordinateLifetime(ctx, record)
			: undefined;
	let extensions: ReturnType<typeof prepareEntityStatementExtensions> | undefined;
	for (const claim of requestedClaims) {
		if (retained && isStatementClaim(claim, record)) {
			if (claim === ExtendedListClaim.SubordinateStatement) setOwn(out, claim, retained.jwt);
			else if (Object.hasOwn(retained.payload, claim)) setOwn(out, claim, retained.payload[claim]);
			continue;
		}
		if (!Object.hasOwn(EXTENDED_LIST_CLAIM_EXTRACTORS, claim)) {
			// Listing fields retain their own meaning even when an SS extension uses that name.
			if (independentListingClaims.has(claim)) continue;
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
		const value = await extractor(record, ctx, now, lifetime);
		if (value !== undefined) setOwn(out, claim, value);
	}
	return out;
}
