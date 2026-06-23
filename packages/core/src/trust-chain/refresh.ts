import { InternalErrorCode } from "../constants.js";
import { err, federationError, ok, type Result } from "../errors.js";
import type { Clock, FederationOptions, TrustAnchorSet, ValidatedTrustChain } from "../types.js";
import { resolveTrustChains } from "./resolve.js";
import { isChainExpired, validateTrustChain } from "./validate.js";

export interface RefreshOptions extends FederationOptions {
	forceRefresh?: boolean;
}

/**
 * Refreshes a trust chain if it has expired (or if forceRefresh is set).
 * Participants must support refreshing expired trust chains.
 */
export async function refreshTrustChain(
	chain: ValidatedTrustChain,
	trustAnchors: TrustAnchorSet,
	options?: RefreshOptions,
	clock?: Clock,
): Promise<Result<ValidatedTrustChain>> {
	if (!options?.forceRefresh && !isChainExpired(chain, clock)) {
		return ok(chain);
	}

	const entityId = chain.entityId;
	const resolveResult = await resolveTrustChains(entityId, trustAnchors, options);

	if (resolveResult.chains.length === 0) {
		const errMsgs = resolveResult.errors.map((e) => e.description).join("; ");
		return err(
			federationError(
				InternalErrorCode.TrustChainInvalid,
				`Failed to refresh trust chain for '${entityId}': ${errMsgs || "no chains resolved"}`,
			),
		);
	}

	// Validate the best chain (shortest)
	for (const candidate of resolveResult.chains) {
		const result = await validateTrustChain(
			candidate.statements as string[],
			trustAnchors,
			options,
		);
		if (result.valid) {
			return ok(result.chain);
		}
	}

	return err(
		federationError(
			InternalErrorCode.TrustChainInvalid,
			`Failed to refresh trust chain for '${entityId}': all resolved chains failed validation`,
		),
	);
}
