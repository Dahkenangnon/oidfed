/** Trust chain refresh with fresh statement retrieval when required or explicitly requested. */

import { MemoryCache } from "../cache/index.js";
import { CachePrefix, InternalErrorCode } from "../constants.js";
import { err, federationError, ok, type Result } from "../errors.js";
import { safeLogger } from "./../logging.js";
import {
	type CacheProvider,
	type Clock,
	type FederationOptions,
	nowSeconds,
	type TrustAnchorSet,
	type ValidatedTrustChain,
} from "../types.js";
import { createTrustChainOperation } from "./operation.js";
import { resolveTrustChains } from "./resolve.js";
import { selectTrustChain } from "./selection.js";
import { isChainExpired, validateTrustChain } from "./validate.js";

export interface RefreshOptions extends FederationOptions {
	/** Retrieve fresh ECs and Subordinate Statements, bypassing pre-existing statement cache entries. */
	forceRefresh?: boolean;
}

/** Keep newly retrieved statements reusable without reading old statements from the host cache. */
function freshStatementCache(shared: CacheProvider | undefined, clock: Clock): CacheProvider {
	const local = new MemoryCache({ clock });
	if (!shared) return local;
	const statementKey = (key: string) =>
		key.startsWith(CachePrefix.EntityConfiguration) || key.startsWith(CachePrefix.EntityStatement);
	return {
		get: <T>(key: string) => (statementKey(key) ? local.get<T>(key) : shared.get<T>(key)),
		async set<T>(key: string, value: T, ttlSeconds: number) {
			await shared.set(key, value, ttlSeconds);
			if (statementKey(key)) await local.set(key, value, ttlSeconds);
		},
		delete: (key: string) => (statementKey(key) ? local.delete(key) : shared.delete(key)),
		// The operation owns only this view, never the application's cache lifetime.
		clear: () => local.clear(),
		[Symbol.asyncDispose]: () => local[Symbol.asyncDispose](),
	};
}

/**
 * Refreshes a trust chain if it has expired (or if forceRefresh is set).
 * Participants must support refreshing expired trust chains.
 * The explicit clock argument takes precedence over options.clock throughout the operation.
 * Forced refresh bypasses existing statement cache entries, writes fetched statements back,
 * and never falls back to the previous chain on failure. Transport/upstream caches remain host-owned.
 */
export async function refreshTrustChain(
	chain: ValidatedTrustChain,
	trustAnchors: TrustAnchorSet,
	options: RefreshOptions,
	clock?: Clock,
): Promise<Result<ValidatedTrustChain>> {
	safeLogger(options?.logger)?.debug("Starting refresh trust chain");

	const effectiveClock = clock ?? options?.clock ?? { now: nowSeconds };
	if (!options?.forceRefresh && !isChainExpired(chain, effectiveClock)) {
		return ok(chain);
	}

	const operation = createTrustChainOperation(options);
	if (!operation.ok) return operation;
	const operationOptions: FederationOptions = {
		...operation.value.options,
		clock: effectiveClock,
		...(options?.forceRefresh ? { cache: freshStatementCache(options.cache, effectiveClock) } : {}),
	};
	const entityId = chain.entityId;
	const resolveResult = await resolveTrustChains(entityId, trustAnchors, operationOptions);

	if (resolveResult.chains.length === 0) {
		const errMsgs = resolveResult.errors.map((e) => e.description).join("; ");
		return err(
			federationError(
				InternalErrorCode.TrustChainInvalid,
				`Failed to refresh trust chain for '${entityId}': ${errMsgs || "no chains resolved"}`,
			),
		);
	}

	const eligible: ValidatedTrustChain[] = [];
	// Use the first valid candidate in resolver order (§10.3 permits local selection policy).
	for (const candidate of resolveResult.chains) {
		const result = await validateTrustChain(candidate.statements as string[], trustAnchors, {
			...operationOptions,
			entityConfigurations: candidate.entityConfigurations,
		});
		if (operation.value.exhausted())
			return err(
				federationError(InternalErrorCode.TrustChainInvalid, "Trust chain operation exhausted"),
			);
		if (result.valid) {
			if (!options?.chainSelection) return ok(result.chain);
			eligible.push(result.chain);
		}
	}

	if (options?.chainSelection && resolveResult.incomplete)
		return err(
			federationError(InternalErrorCode.TrustChainInvalid, "Trust chain discovery was incomplete"),
		);
	if (eligible.length) return selectTrustChain(eligible, operationOptions);
	return err(
		federationError(
			InternalErrorCode.TrustChainInvalid,
			`Failed to refresh trust chain for '${entityId}': all resolved chains failed validation`,
		),
	);
}
