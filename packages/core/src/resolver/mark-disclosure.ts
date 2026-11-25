/** Select and validate Trust Marks disclosed in a signed Resolve response. */
import { runAsyncOperation } from "../async-operation.js";
import { DEFAULT_MAX_RESPONSE_BYTES, TrustMarkStatus } from "../constants.js";
import { decodeEntityStatement } from "../jose/verify.js";
import { safeLogger } from "../logging.js";
import { TrustMarkPayloadSchema, type TrustMarkRef } from "../schemas/trust-mark.js";
import { calculateChainExpiration } from "../trust-chain/validate.js";
import {
	establishTrustMarkIssuerTrust,
	type TrustMarkIssuerContext,
	trustMarkIssuerContext,
	validateTrustMarkWithIssuer,
} from "../trust-marks/evidence.js";
import { fetchTrustMarkStatus } from "../trust-marks/fetch.js";
import type { TrustMarkStatusAssessment } from "../trust-marks/issuer.js";
import type { HttpClient } from "../types.js";
import {
	type EntityId,
	type FederationOptions,
	nowSeconds,
	type ParsedEntityStatement,
	type TrustAnchorSet,
	type TrustMarkEvidence,
	type ValidatedTrustChain,
	type ValidatedTrustMark,
} from "../types.js";

const MAX_RESOLVE_TRUST_MARK_CANDIDATES = 100;

/** A Resolve network request was declined before it reached the transport. */
export class ResolveFetchBudgetExhausted extends Error {}

export interface ResolveTrustMarkCandidateLimits {
	readonly maxCandidates: number;
	readonly maxBytes: number;
}

export interface ResolveTrustMarkCandidateInput {
	readonly caller: string | undefined;
	readonly subject: EntityId;
	readonly trustAnchor: EntityId;
	readonly held: readonly string[];
	/** Held marks already verified under the selected anchor and assessed as active. */
	readonly verifiedHeld: readonly Readonly<{
		ref: Readonly<Pick<TrustMarkRef, "trust_mark_type" | "trust_mark">>;
		mark: Readonly<Pick<ValidatedTrustMark, "issuer" | "expiresAt">>;
	}>[];
	/** Expiry of the selected chain before any disclosed mark shortens the response. */
	readonly chainExpiresAt: number;
	/** Limits applied to the returned JWT candidates before verification. */
	readonly candidateLimits: ResolveTrustMarkCandidateLimits;
	/** Optional issuer work shares the Resolve fetch budget with required verification. */
	readonly httpClient: HttpClient;
	readonly signal: AbortSignal;
}

export type ResolveTrustMarkCandidates = (
	input: Readonly<ResolveTrustMarkCandidateInput>,
) => readonly string[] | Promise<readonly string[]>;
export type ResolveTrustMarkStatusMaxAge = (trustMarkType: string) => number | undefined;

interface ResolveMarkContext {
	readonly entityId: EntityId;
	readonly options: FederationOptions;
	readonly trustAnchors?: TrustAnchorSet;
	readonly assessLocalTrustMarkStatus?: (
		jwt: string,
	) => Promise<TrustMarkStatusAssessment | undefined>;
}

interface ActiveResolveTrustMark {
	readonly ref: TrustMarkRef;
	readonly mark: ValidatedTrustMark;
}

/** Read accredited issuers from the anchor that validated the subject. */
function permitsIssuer(
	chain: readonly ParsedEntityStatement[],
	type: string,
	issuer: string,
): boolean {
	const root = chain.at(-1)?.payload;
	const issuers = root?.iss === root?.sub ? root?.trust_mark_issuers : undefined;
	if (!issuers || !Object.hasOwn(issuers, type)) return false;
	const allowed = issuers[type];
	return Array.isArray(allowed) && (allowed.length === 0 || allowed.some((id) => id === issuer));
}

/** Reuse a self-statement that is already verified under the selected anchor. */
function issuerInChain(
	chain: readonly ParsedEntityStatement[],
	type: string,
	id: string,
): TrustMarkIssuerContext | undefined {
	const issuer = chain.find(({ payload }) => payload.iss === id && payload.sub === id)?.payload;
	if (!issuer?.jwks) return undefined;
	return {
		kind: "out-of-band",
		issuer: id,
		keys: issuer.jwks,
		allowedTrustMarkTypes: [type],
		...(issuer.metadata?.federation_entity ? { metadata: issuer.metadata.federation_entity } : {}),
	};
}

/** Read the exact instances the disclosure policy allows. */
async function disclosureCandidates(
	ctx: ResolveMarkContext,
	chain: ValidatedTrustChain,
	caller: string | undefined,
	held: readonly TrustMarkRef[],
	verified: readonly ActiveResolveTrustMark[],
	policy: ResolveTrustMarkCandidates,
): Promise<Set<string>> {
	const limits: ResolveTrustMarkCandidateLimits = Object.freeze({
		maxCandidates: MAX_RESOLVE_TRUST_MARK_CANDIDATES,
		maxBytes: Math.min(
			ctx.options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
			ctx.options.maxCompactBytes ?? Infinity,
		),
	});
	let returned: unknown;
	try {
		returned = await runAsyncOperation(
			(signal) =>
				policy(
					Object.freeze({
						caller,
						subject: chain.entityId,
						trustAnchor: chain.trustAnchorId,
						held: Object.freeze(held.map((ref) => ref.trust_mark)),
						verifiedHeld: Object.freeze(
							verified.map(
								({ ref: { trust_mark_type, trust_mark }, mark: { issuer, expiresAt } }) =>
									Object.freeze({
										ref: Object.freeze({ trust_mark_type, trust_mark }),
										mark: Object.freeze({
											issuer,
											...(expiresAt === undefined ? {} : { expiresAt }),
										}),
									}),
							),
						),
						chainExpiresAt: calculateChainExpiration(chain.statements),
						candidateLimits: limits,
						httpClient: ctx.options.httpClient ?? fetch,
						signal,
					}),
				),
			ctx.options,
		);
	} catch (error) {
		// An interrupted policy has not approved any candidates for disclosure.
		if (error instanceof ResolveFetchBudgetExhausted) return new Set();
		throw error;
	}
	if (!Array.isArray(returned) || returned.length > limits.maxCandidates)
		throw new TypeError(
			"Resolve Trust Mark policy returned too many candidates or an invalid list",
		);
	let remaining = limits.maxBytes;
	const candidates = new Set<string>();
	for (const jwt of returned as readonly unknown[]) {
		if (typeof jwt !== "string")
			throw new TypeError("Resolve Trust Mark candidates must be compact JWTs");
		remaining -= jwt.length; // Compact JWTs use ASCII.
		if (remaining < 0)
			throw new TypeError("Resolve Trust Mark candidates exceed the input byte budget");
		candidates.add(jwt);
	}
	return candidates;
}

type ResolveMarkEvidence = Pick<
	ValidatedTrustMark,
	"issuer" | "subject" | "issuerEvidence" | "verificationExpiresAt"
> &
	Partial<Pick<TrustMarkEvidence, "verificationKey">>;

/** Check held marks under the selected anchor, then choose which verified JWTs to disclose. */
export async function resolveActiveTrustMarks(
	ctx: ResolveMarkContext,
	chain: ValidatedTrustChain,
	caller: string | undefined,
	now: number,
	optionalHttpClient: HttpClient,
): Promise<ActiveResolveTrustMark[]> {
	const held = chain.statements[0]?.payload.trust_marks ?? [];
	const anchor = ctx.trustAnchors?.get(chain.trustAnchorId);
	if (!anchor) return [];
	const anchors = new Map([[chain.trustAnchorId, anchor]]);
	const trusted = new Map<string, TrustMarkIssuerContext | undefined>();
	const assessed = new Map<string, ActiveResolveTrustMark | undefined>();
	const policy = ctx.options.resolveTrustMarkCandidates;

	async function assessMark(
		ref: TrustMarkRef,
		issuer: string,
		evidence?: ResolveMarkEvidence,
		work = ctx,
	): Promise<ActiveResolveTrustMark | undefined> {
		const jwt = ref.trust_mark;
		if (assessed.has(jwt)) return assessed.get(jwt);
		const type = ref.trust_mark_type;
		if (!permitsIssuer(chain.statements, type, issuer)) return undefined;
		let issuerEvidence = evidence?.issuerEvidence;
		// A disclosure candidate needs issuer proof under the selected federation.
		// Chain selection may also consider independently configured issuer evidence.
		if (
			policy &&
			issuerEvidence &&
			(issuerEvidence.kind !== "federation" || issuerEvidence.trustAnchorId !== chain.trustAnchorId)
		) {
			issuerEvidence = undefined;
			evidence = undefined;
		}
		if (!issuerEvidence) {
			const group = JSON.stringify([issuer, type]);
			if (!trusted.has(group)) {
				let context = issuerInChain(chain.statements, type, issuer);
				if (!context) {
					const checked = await establishTrustMarkIssuerTrust({
						issuer,
						trustMarkType: type,
						trustAnchors: anchors,
						options: work.options,
					});
					if (checked.ok) context = checked.value;
				}
				trusted.set(group, context);
			}
			issuerEvidence = trusted.get(group);
		}
		const mark =
			issuerEvidence &&
			(await activeTrustMarkForResolve(
				work,
				chain.statements,
				ref,
				{ ...evidence, issuer, subject: chain.entityId, issuerEvidence },
				now,
			));
		const active = mark ? { ref, mark } : undefined;
		assessed.set(jwt, active);
		return active;
	}

	// The signed chain may carry held marks even when the top-level list is withheld.
	const defaults: ActiveResolveTrustMark[] = [];
	for (const evaluation of chain.trustMarkEvaluations) {
		if (ctx.options.signal?.aborted) break;
		const ref = held[evaluation.referenceIndex];
		if (!ref || ref.trust_mark_type !== evaluation.trustMarkType) continue;
		const claims = readCandidateClaims(ref.trust_mark, chain.entityId, ctx.options);
		if (claims?.trust_mark_type !== ref.trust_mark_type) continue;
		const evidence = evaluation.status === "verified" ? evaluation.mark : undefined;
		const active = await assessMark(ref, claims.iss, evidence);
		if (active && evidence) defaults.push(active);
	}

	if (!policy) return defaults;
	if (ctx.options.signal?.aborted) return [];
	// A failed attempt to improve eligible evidence cannot make required verification incomplete.
	const optional = { ...ctx, options: { ...ctx.options, httpClient: optionalHttpClient } };
	const candidates = await disclosureCandidates(optional, chain, caller, held, defaults, policy);
	const selected = new Map<string, ActiveResolveTrustMark>();
	for (const jwt of candidates) {
		if (ctx.options.signal?.aborted) break;
		let active = assessed.get(jwt);
		if (!assessed.has(jwt)) {
			const claims = readCandidateClaims(jwt, chain.entityId, ctx.options);
			if (!claims) continue;
			active = await assessMark(
				{ trust_mark_type: claims.trust_mark_type, trust_mark: jwt },
				claims.iss,
				undefined,
				optional,
			);
		}
		if (!active) continue;
		const { mark, ref } = active;
		const group = JSON.stringify([mark.issuer, ref.trust_mark_type]);
		const existing = selected.get(group)?.mark;
		const expiry = mark.expiresAt ?? Infinity;
		const previousExpiry = existing?.expiresAt ?? Infinity;
		if (
			!existing ||
			expiry > previousExpiry ||
			(expiry === previousExpiry && mark.issuedAt > existing.issuedAt)
		)
			selected.set(group, active);
	}
	return [...selected.values()];
}

/** Read candidate selectors without trusting the claims until signature verification succeeds. */
function readCandidateClaims(jwt: string, subject: EntityId, options: FederationOptions) {
	const decoded = decodeEntityStatement(jwt, options);
	if (!decoded.ok) return undefined;
	const claims = TrustMarkPayloadSchema.safeParse(decoded.value.payload);
	return claims.success && claims.data.sub === subject ? claims.data : undefined;
}

async function activeTrustMarkForResolve(
	ctx: ResolveMarkContext,
	statements: ReadonlyArray<ParsedEntityStatement>,
	ref: TrustMarkRef,
	mark: ResolveMarkEvidence,
	now: number,
): Promise<ValidatedTrustMark | undefined> {
	try {
		const root = statements.at(-1)?.payload;
		if (!permitsIssuer(statements, ref.trust_mark_type, mark.issuer)) return undefined;
		const context =
			mark.issuerEvidence ?? issuerInChain(statements, ref.trust_mark_type, mark.issuer);
		if (!context) return undefined;
		const trusted = trustMarkIssuerContext(context, ref.trust_mark_type, ctx.options);
		if (!trusted.ok) return undefined;
		// The original context has already authenticated the issuer. Apply the resolver's anchor policy independently.
		const selected: TrustMarkIssuerContext = {
			kind: "out-of-band",
			issuer: trusted.value.issuer,
			keys: trusted.value.keys,
			allowedTrustMarkTypes: [ref.trust_mark_type],
			trustMarkOwners: root?.trust_mark_owners ?? {},
			...(trusted.value.metadata ? { metadata: trusted.value.metadata } : {}),
		};
		const history = ctx.options?.trustMarkVerification?.historicalKeys;
		const historyResponse = mark.verificationKey?.responseJwt;
		const checked = await validateTrustMarkWithIssuer(ref.trust_mark, selected, {
			...ctx.options,
			expectedSubject: mark.subject,
			expectedTrustMarkType: ref.trust_mark_type,
			...(history
				? {
						historicalKeys: {
							...history,
							...(historyResponse
								? { mode: "supplied-only" as const, responses: [historyResponse] }
								: {}),
						},
					}
				: {}),
		});
		if (!checked.ok) return undefined;
		const maxAge = ctx.options.resolveTrustMarkStatusMaxAge?.(ref.trust_mark_type);
		if (maxAge !== undefined && (!Number.isFinite(maxAge) || maxAge <= 0)) return undefined;
		let statusDeadline = Infinity;
		if (mark.issuer === ctx.entityId && ctx.assessLocalTrustMarkStatus) {
			const assess = ctx.assessLocalTrustMarkStatus;
			const assessment = await runAsyncOperation(() => assess(ref.trust_mark), ctx.options);
			if (
				assessment?.payload.status !== TrustMarkStatus.Active ||
				assessment.payload.iss !== mark.issuer ||
				assessment.payload.trust_mark !== ref.trust_mark ||
				!Number.isFinite(assessment.payload.iat) ||
				assessment.payload.iat > nowSeconds(ctx.options.clock)
			)
				return undefined;
			statusDeadline = Math.min(
				assessment.verificationExpiresAt ?? Infinity,
				typeof assessment.payload.exp === "number" ? assessment.payload.exp : Infinity,
				maxAge === undefined ? Infinity : assessment.payload.iat + maxAge,
			);
		} else {
			const status = await fetchTrustMarkStatus({
				...ctx.options,
				jwt: ref.trust_mark,
				issuerEvidence: context,
				expectedSubject: mark.subject,
				expectedTrustMarkType: ref.trust_mark_type,
				...(maxAge === undefined ? {} : { freshness: { maxAgeSeconds: maxAge } }),
			});
			if (!status.ok || status.value.status !== TrustMarkStatus.Active) return undefined;
			statusDeadline = status.value.verificationExpiresAt ?? Infinity;
		}
		const deadline = Math.min(
			mark.verificationExpiresAt ?? Infinity,
			checked.value.verificationExpiresAt ?? Infinity,
			trusted.value.expiresAt ?? Infinity,
			statusDeadline,
		);
		if (deadline <= Math.max(now, nowSeconds(ctx.options?.clock)) || ctx.options?.signal?.aborted)
			return undefined;
		return {
			...checked.value,
			...(Number.isFinite(deadline) ? { verificationExpiresAt: deadline } : {}),
		};
	} catch {
		safeLogger(ctx.options?.logger)?.debug("Failed to verify trust mark status for resolution");
		return undefined;
	}
}
