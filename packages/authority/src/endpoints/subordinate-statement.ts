/** Build new Subordinate Statements and verify retained evidence through public keys. */

import {
	assertPositiveTtlSeconds,
	assertSubordinatePublicationClaims,
	buildSubordinateStatementPayload,
	cloneData,
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	type EntityStatementMetadata,
	errorResponse,
	FederationErrorCode,
	federationEntry,
	federationPublicationJwks,
	federationSigningOptions,
	freezeSnapshot,
	type JWKSet,
	JwtTyp,
	nowSeconds,
	runAsyncOperation,
	type SubordinateRecord,
	type SubordinateStatementPayload,
	SubordinateStatementSchema,
	signEntityStatement,
	verifyEntityStatement,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { canonicalSubordinateJson, subordinatePublicationClaim } from "./subordinate-claims.js";

/** Distinguish unavailable retained evidence from on-demand signing and storage errors. */
export class RetainedSubordinateUnavailable extends Error {}

/** Use a generic Federation error whenever an approved live statement cannot be served. */
export function retainedSubordinateUnavailableResponse(): Response {
	return errorResponse(
		503,
		FederationErrorCode.TemporarilyUnavailable,
		"Approved subordinate statement is unavailable",
	);
}

/** Resolve the lifetime for one newly issued statement or its on-demand listing projection. */
export function subordinateLifetime(ctx: HandlerContext, record: SubordinateRecord): number {
	const selected: unknown = ctx.subordinateLifetime?.(freezeSnapshot(cloneData(record)));
	if (selected === undefined)
		return ctx.subordinateStatementTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS;
	if (typeof selected !== "number") {
		void Promise.resolve(selected).catch(() => {});
		throw new TypeError("subordinateLifetime must return a number or undefined synchronously");
	}
	assertPositiveTtlSeconds(selected, "subordinateLifetime", "safe-integer");
	return selected;
}

/** Use the same publication claims for issuance and verification of retained evidence. */
function buildPublicationPayload(
	ctx: HandlerContext,
	record: SubordinateRecord,
	issuedAt: number,
	ttlSeconds: number,
): SubordinateStatementPayload {
	assertSubordinatePublicationClaims(
		{ ...record, metadata: undefined },
		{ customOperators: ctx.options?.customPolicyOperators },
	);
	// Operational fields are published through the subordinate's own Entity Configuration.
	// The sanitizer documents the specification restrictions and additional host policy.
	const sanitized = subordinatePublicationClaim(record, "metadata", ctx);
	subordinatePublicationClaim(record, "metadata_policy", ctx);
	subordinatePublicationClaim(record, "constraints", ctx);
	return buildSubordinateStatementPayload({
		algorithmRegistry: ctx.options.algorithmRegistry,
		...(record.additionalClaims !== undefined ? { additionalClaims: record.additionalClaims } : {}),
		issuer: ctx.entityId,
		subject: record.entityId,
		jwks: record.jwks,
		...(sanitized !== undefined ? { metadata: sanitized as EntityStatementMetadata } : {}),
		...(record.metadataPolicy ? { metadataPolicy: record.metadataPolicy } : {}),
		...(record.constraints ? { constraints: record.constraints } : {}),
		...(record.sourceEndpoint ? { sourceEndpoint: record.sourceEndpoint } : {}),
		...(record.crit && record.crit.length > 0 ? { crit: record.crit } : {}),
		...(record.metadataPolicyCrit && record.metadataPolicyCrit.length > 0
			? { metadataPolicyCrit: record.metadataPolicyCrit }
			: {}),
		issuedAt,
		ttlSeconds,
	});
}

/** Issue a fresh statement, including when public endpoints serve retained evidence. */
export async function buildSubordinateStatement(
	ctx: HandlerContext,
	record: SubordinateRecord,
	now?: number,
	ttlSeconds?: number,
): Promise<string> {
	const keySet = await federationEntry(ctx.crypto, {
		artifact: "subordinate-statement",
		issuer: ctx.entityId,
		subject: record.entityId,
	});
	const payload = buildPublicationPayload(
		ctx,
		record,
		now ?? nowSeconds(ctx.options.clock),
		ttlSeconds ?? subordinateLifetime(ctx, record),
	);

	return signEntityStatement(payload, keySet, {
		...federationSigningOptions(ctx.options, "subordinate-statement"),
		typ: JwtTyp.EntityStatement,
	});
}

export interface RetainedSubordinateStatement {
	readonly jwt: string;
	readonly payload: Readonly<Record<string, unknown>>;
	readonly expiresAt: number;
}

/** Compare approved publication data, ignoring issuance dates and order in a JWK Set. */
function publicationClaims(
	{ iat: _iat, exp: _exp, jwks: _jwks, ...claims }: Readonly<Record<string, unknown>>,
	jwks: JWKSet,
) {
	return canonicalSubordinateJson({
		...claims,
		jwks: { ...jwks, keys: jwks.keys.map(canonicalSubordinateJson).sort() },
	});
}

/** Read and authenticate retained evidence, reusing the published keys within one request. */
export function createRetainedSubordinateReader(
	ctx: HandlerContext,
	signal: AbortSignal,
): ((record: SubordinateRecord) => Promise<RetainedSubordinateStatement>) | undefined {
	const load = ctx.loadSubordinateStatement;
	if (!load) return undefined;
	const options = {
		...ctx.options,
		signal: ctx.options.signal ? AbortSignal.any([ctx.options.signal, signal]) : signal,
	};
	let publishedKeys: Promise<JWKSet> | undefined;
	return async (record) => {
		try {
			return await runAsyncOperation(async (signal) => {
				const jwt = await load(freezeSnapshot(cloneData(record)), signal);
				if (typeof jwt !== "string" || jwt.length === 0 || signal.aborted)
					throw new RetainedSubordinateUnavailable();
				// A retained reader must continue to work without a live signer or keyring entry.
				if (!ctx.crypto.readPublishedFederationJwks) throw new RetainedSubordinateUnavailable();
				publishedKeys ??= federationPublicationJwks(ctx.crypto, ctx.entityId).then(({ keys }) => ({
					keys: keys.filter((key) => key.revoked === undefined),
				}));
				const verified = await verifyEntityStatement(jwt, await publishedKeys, {
					...options,
					signal,
					artifact: "subordinate-statement",
					expectedTyp: JwtTyp.EntityStatement,
					clockSkewSeconds: 0,
				});
				if (!verified.ok) throw new RetainedSubordinateUnavailable();
				const parsed = SubordinateStatementSchema.safeParse(verified.value.payload);
				if (!parsed.success) throw new RetainedSubordinateUnavailable();
				const { iat, exp, iss, sub, jwks } = parsed.data;
				const payload = verified.value.payload;

				// The builder validates the current record. Its placeholder dates are excluded from
				// the comparison because the saved statement has its own signed validity window.
				const approved = buildPublicationPayload(ctx, record, 0, 1);
				const now = nowSeconds(options.clock);
				if (
					iss !== ctx.entityId ||
					sub !== record.entityId ||
					iat > now ||
					exp <= now ||
					publicationClaims(payload, { ...payload.jwks, keys: jwks.keys }) !==
						publicationClaims(approved, approved.jwks)
				)
					throw new RetainedSubordinateUnavailable();
				return { jwt, payload, expiresAt: exp };
			}, options);
		} catch {
			throw new RetainedSubordinateUnavailable("Approved subordinate statement is unavailable");
		}
	};
}
