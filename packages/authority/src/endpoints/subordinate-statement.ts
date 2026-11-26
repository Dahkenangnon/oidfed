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
	InternalErrorCode,
	isSignerPublished,
	type JWKSet,
	JwtTyp,
	nowSeconds,
	runAsyncOperation,
	type SubordinateRecord,
	type SubordinateStatementPayload,
	SubordinateStatementSchema,
	safeLogger,
	signEntityStatement,
	verifyEntityStatement,
} from "@oidfed/core";
import type { KeyringEntry } from "@oidfed/crypto";
import type { HandlerContext } from "./context.js";
import { canonicalSubordinateJson, subordinatePublicationClaim } from "./subordinate-claims.js";

type RetainedFailure =
	| "missing-evidence"
	| "loader-failure"
	| "key-lookup-failure"
	| "verification-failure"
	| "identity-mismatch"
	| "approval-mismatch"
	| "invalid-validity-window"
	| "invalid-approved-record"
	| "timeout"
	| "cancelled";

/** Preserve an internal diagnostic without exposing artifact or adapter data. */
export class RetainedSubordinateUnavailable extends Error {
	constructor(readonly reason: RetainedFailure) {
		super("Approved subordinate statement is unavailable");
	}
}

/** Use a generic Federation error whenever an approved live statement cannot be served. */
export function retainedSubordinateUnavailableResponse(
	ctx: HandlerContext,
	reason: RetainedFailure,
): Response {
	safeLogger(ctx.options.logger)?.warn(`Approved subordinate statement is unavailable (${reason})`);
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
	return (await issueSubordinateStatement(ctx, record, now, ttlSeconds)).jwt;
}

/** Return the captured signing binding so the listing can recheck it before delivery. */
async function issueSubordinateStatement(
	ctx: HandlerContext,
	record: SubordinateRecord,
	now?: number,
	ttlSeconds?: number,
) {
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

	const jwt = await signEntityStatement(payload, keySet, {
		...federationSigningOptions(ctx.options, "subordinate-statement"),
		typ: JwtTyp.EntityStatement,
	});
	return { jwt, keySet };
}

/** Share the issuer's published keys within one on-demand page while selecting each row's signer. */
export function createSubordinatePageSigner(ctx: HandlerContext, signal: AbortSignal) {
	const readLiveKeys = () =>
		runAsyncOperation(() => federationPublicationJwks(ctx.crypto, ctx.entityId), {
			...ctx.options,
			signal,
		});
	let published: Promise<JWKSet> | undefined;
	const signingContext: HandlerContext = {
		...ctx,
		crypto: {
			...ctx.crypto,
			keyring: {
				async entry(purpose, context) {
					const entry = await ctx.crypto.keyring.entry(purpose, context);
					published ??= readLiveKeys();
					const keys = await published;
					// A new row signer may have been published after this page began.
					if (!isSignerPublished(entry, keys.keys, ctx.crypto.algorithmRegistry))
						published = readLiveKeys();
					return entry;
				},
			},
			readPublishedFederationJwks: () => (published ??= readLiveKeys()),
		},
	};
	return {
		sign: (record: SubordinateRecord, now: number, lifetime?: number) =>
			issueSubordinateStatement(signingContext, record, now, lifetime),
		async verifyPublished(signers: readonly KeyringEntry[]) {
			if (signers.length === 0) return;
			const currentKeys = await readLiveKeys();
			if (
				!signers.every((entry) =>
					isSignerPublished(entry, currentKeys.keys, ctx.crypto.algorithmRegistry),
				)
			)
				throw new Error("A listing signer is absent from the issuer's current Federation JWKS");
		},
	};
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
		let phase: RetainedFailure = "loader-failure";
		try {
			return await runAsyncOperation(async (signal) => {
				const jwt = await load(freezeSnapshot(cloneData(record)), signal);
				if (signal.aborted) throw new RetainedSubordinateUnavailable("cancelled");
				if (jwt === undefined || jwt === "")
					throw new RetainedSubordinateUnavailable("missing-evidence");
				if (typeof jwt !== "string") throw new RetainedSubordinateUnavailable("loader-failure");
				// A retained reader must continue to work without a live signer or keyring entry.
				phase = "key-lookup-failure";
				if (!ctx.crypto.readPublishedFederationJwks)
					throw new RetainedSubordinateUnavailable(phase);
				publishedKeys ??= federationPublicationJwks(ctx.crypto, ctx.entityId).then(({ keys }) => ({
					keys: keys.filter((key) => key.revoked === undefined),
				}));
				const keys = await publishedKeys;
				phase = "verification-failure";
				const verified = await verifyEntityStatement(jwt, keys, {
					...options,
					signal,
					artifact: "subordinate-statement",
					expectedTyp: JwtTyp.EntityStatement,
					clockSkewSeconds: 0,
				});
				if (!verified.ok)
					throw new RetainedSubordinateUnavailable(
						verified.error.code === InternalErrorCode.Expired ? "invalid-validity-window" : phase,
					);
				const payload = verified.value.payload;
				const parsed = SubordinateStatementSchema.safeParse(payload);
				if (!parsed.success || !payload.jwks) throw new RetainedSubordinateUnavailable(phase);
				const { iat, exp, iss, sub } = parsed.data;
				if (iss !== ctx.entityId || sub !== record.entityId)
					throw new RetainedSubordinateUnavailable("identity-mismatch");
				const now = nowSeconds(options.clock);
				if (iat > now || exp <= now)
					throw new RetainedSubordinateUnavailable("invalid-validity-window");

				// The builder validates the current record. Its placeholder dates are excluded from
				// the comparison because the saved statement has its own signed validity window.
				phase = "invalid-approved-record";
				const approved = buildPublicationPayload(ctx, record, 0, 1);
				// Compare the signed bytes' data. Schema output may omit a JWK extension member.
				if (publicationClaims(payload, payload.jwks) !== publicationClaims(approved, approved.jwks))
					throw new RetainedSubordinateUnavailable("approval-mismatch");
				return { jwt, payload, expiresAt: exp };
			}, options);
		} catch (error) {
			if (error instanceof RetainedSubordinateUnavailable) throw error;
			if (error instanceof DOMException) {
				if (error.name === "TimeoutError") throw new RetainedSubordinateUnavailable("timeout");
				if (error.name === "AbortError") throw new RetainedSubordinateUnavailable("cancelled");
			}
			throw new RetainedSubordinateUnavailable(phase);
		}
	};
}
