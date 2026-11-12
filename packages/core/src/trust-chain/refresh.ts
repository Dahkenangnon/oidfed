import { InternalErrorCode } from "../constants.js";
import { err, federationError, ok, type Result } from "../errors.js";
import { safeLogger } from "./../logging.js";
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
	safeLogger(options?.logger)?.debug("Starting refresh trust chain");

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

	// Use the first valid candidate in resolver order (§10.3 permits local selection policy).
	for (const candidate of resolveResult.chains) {
		const result = await validateTrustChain(candidate.statements as string[], trustAnchors, {
			...options,
			entityConfigurations: candidate.entityConfigurations,
		});
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
