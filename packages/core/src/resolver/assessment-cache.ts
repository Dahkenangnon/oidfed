/** Cache keys and local revocation evidence for previously evaluated Resolve requests. */
import { runAsyncOperation } from "../async-operation.js";
import { sha256Hex } from "../crypto-runtime.js";
import { decodeEntityStatement } from "../jose/verify.js";
import { safeLogger } from "../logging.js";
import type { JWKSet } from "../schemas/jwk.js";
import type { TrustMarkRef } from "../schemas/trust-mark.js";
import {
	type CachedResponderEvidence,
	type ResolveAssessmentCacheValue,
	ResponderEvidenceSchema,
} from "../storage/cache-records.js";
import { assertStorageView, storageSnapshot } from "../storage/capabilities.js";
import type { CacheStore } from "../storage/contracts.js";
import { isStoredTrustMarkEligible } from "../storage/trust-mark-eligibility.js";
import { type EntityId, type FederationOptions, nowSeconds } from "../types.js";

export interface ResolveCacheScopeInput {
	readonly caller: string | undefined;
	readonly subject: EntityId;
	readonly trustAnchor: EntityId;
	readonly entityTypes: readonly string[];
	readonly signal: AbortSignal;
}

export interface ResolverCacheOptions {
	readonly namespace: string;
	readonly policyRevision: string;
	/** Return undefined to skip reuse and publication for this request. */
	readonly scope?: (
		input: Readonly<ResolveCacheScopeInput>,
	) => string | undefined | Promise<string | undefined>;
}

/** Capture the cache policy so one running host uses one policy revision. */
export function snapshotResolverCache(
	config: ResolverCacheOptions | undefined,
): ResolverCacheOptions | undefined {
	if (!config) return undefined;
	if (
		typeof config.namespace !== "string" ||
		!config.namespace.trim() ||
		typeof config.policyRevision !== "string" ||
		!config.policyRevision.trim() ||
		(config.scope !== undefined && typeof config.scope !== "function")
	)
		throw new TypeError(
			"Resolve cache requires a namespace, a policy revision, and an optional scope callback",
		);
	return Object.freeze({ ...config });
}

/** Hash authority keys and request selectors together with the verified caller and workflow scope. */
export async function resolveAssessmentKey(
	options: FederationOptions,
	namespace: string,
	resolver: EntityId,
	caller: string | undefined,
	subject: EntityId,
	anchors: ReadonlyMap<EntityId, Readonly<{ jwks: JWKSet }>>,
	entityTypes: readonly string[],
): Promise<string | undefined> {
	const config = options.resolverCache;
	const sortedAnchors = [...anchors].sort(([left], [right]) =>
		left < right ? -1 : left > right ? 1 : 0,
	);
	const types = Object.freeze([...new Set(entityTypes)].sort());
	const scopes: string[] = [];
	const select = config?.scope;
	if (select) {
		for (const [trustAnchor] of sortedAnchors) {
			const scope = await runAsyncOperation(
				(signal) =>
					select(Object.freeze({ caller, subject, trustAnchor, entityTypes: types, signal })),
				options,
			);
			if (scope === undefined) return undefined;
			if (typeof scope !== "string" || !scope.trim())
				throw new TypeError("Resolve cache scope must be a nonempty string");
			scopes.push(scope);
		}
	}
	const partition = [
		config?.namespace ?? namespace,
		config?.policyRevision ?? null,
		resolver,
		caller ?? null,
		subject,
		sortedAnchors.map(([id, { jwks }]) => [id, jwks]),
		types,
		scopes,
	];
	return `resolve:v2:${await sha256Hex(JSON.stringify(partition), options.engine)}`;
}

/** Separate optional proof from the record understood by all serving workers. */
async function resolveResponderEvidenceKey(
	options: FederationOptions,
	assessmentKey: string,
	{ trustAnchor, reuseUntil, payload }: ResolveAssessmentCacheValue,
): Promise<string> {
	const assessment = [
		assessmentKey,
		trustAnchor,
		payload.iat,
		payload.exp,
		reuseUntil,
		payload.trust_chain,
	];
	return `resolve-responder:v1:${await sha256Hex(JSON.stringify(assessment), options.engine)}`;
}

/** Read optional proof only after the shared subject assessment has passed its checks. */
export async function readCachedResponderEvidence(
	cache: CacheStore,
	options: FederationOptions,
	assessmentKey: string,
	assessment: ResolveAssessmentCacheValue,
): Promise<CachedResponderEvidence | undefined> {
	const key = await resolveResponderEvidenceKey(options, assessmentKey, assessment);
	if (options.signal?.aborted) return undefined;
	return ResponderEvidenceSchema.safeParse(await cache.get<unknown>(key)).data;
}

/** Keep optional proof no longer than either the proof or the assessment is useful. */
export async function storeCachedResponderEvidence(
	cache: CacheStore,
	options: FederationOptions,
	assessmentKey: string,
	assessment: ResolveAssessmentCacheValue,
	evidence: CachedResponderEvidence,
): Promise<void> {
	try {
		const key = await resolveResponderEvidenceKey(options, assessmentKey, assessment);
		const ttl = Math.min(assessment.reuseUntil, evidence.expiresAt) - nowSeconds(options.clock);
		if (!options.signal?.aborted && ttl > 0) await cache.set(key, evidence, ttl);
	} catch {
		safeLogger(options.logger)?.debug("Could not cache optional Resolve responder evidence");
	}
}

/** Read the authoritative issuer revision for a locally assessed mark. */
export async function localTrustMarkRevision(
	options: FederationOptions,
): Promise<string | undefined> {
	const storage = options.storage;
	if (!storage?.capabilities.includes("trustMark:read")) return undefined;
	const marks = storage.trustMark;
	return marks ? runAsyncOperation(() => marks.revision(), options) : undefined;
}

/** Recheck the revision after asynchronous work. An unavailable store cannot confirm freshness. */
export async function localTrustMarkRevisionMatches(
	expected: string,
	options: FederationOptions,
): Promise<boolean> {
	try {
		return expected === (await localTrustMarkRevision(options));
	} catch {
		safeLogger(options.logger)?.debug("Could not confirm the local Resolve Trust Mark revision");
		return false;
	}
}

/** Confirm exact local records against one snapshot. Revision counters can repeat after a reset. */
export async function hasCurrentLocalTrustMarks(
	snapshot: ResolveAssessmentCacheValue,
	options: FederationOptions,
	assessesLocally: boolean,
): Promise<boolean> {
	const expected = snapshot.localTrustMarkRevision;
	if (expected === undefined && !assessesLocally) return true;
	const { payload } = snapshot;
	const local: TrustMarkRef[] = [];
	for (const ref of payload.trust_marks ?? []) {
		const decoded = decodeEntityStatement(ref.trust_mark, options);
		if (!decoded.ok) return false;
		if (decoded.value.payload.iss === payload.iss) local.push(ref);
	}
	if (!local.length) return expected === undefined;
	const storage = options.storage;
	if (expected === undefined || !storage?.capabilities.includes("snapshot")) return false;
	try {
		return await runAsyncOperation(
			() =>
				storageSnapshot(
					storage,
					async (view) => {
						assertStorageView(view, ["trustMark:read"], "Resolve Trust Mark cache");
						const store = view.trustMark;
						if ((await store.revision()) !== expected) return false;
						for (const ref of local) {
							const record = await store.status(ref.trust_mark);
							if (
								!record ||
								record.jwt !== ref.trust_mark ||
								record.subject !== payload.sub ||
								record.trustMarkType !== ref.trust_mark_type ||
								!isStoredTrustMarkEligible(record, nowSeconds(options.clock), options)
							)
								return false;
						}
						return true;
					},
					options,
				),
			options,
		);
	} catch {
		safeLogger(options.logger)?.debug("Could not verify exact local Trust Marks for Resolve reuse");
		return false;
	}
}
