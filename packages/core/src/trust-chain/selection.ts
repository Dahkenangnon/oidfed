import { cloneData } from "../data-copy.js";
/** Application-controlled chain selection without exposing authenticated evidence to mutation. */

import { callSynchronous, freezeSnapshot } from "../callbacks.js";
import { InternalErrorCode } from "../constants.js";
import { err, federationError, ok, type Result } from "../errors.js";
import {
	type ChainSelectionStrategy,
	type FederationOptions,
	nowSeconds,
	type ValidatedTrustChain,
} from "../types.js";

/** Select without exposing authenticated evidence to application mutation. */
export function selectTrustChain(
	chains: readonly ValidatedTrustChain[],
	options: FederationOptions,
	fallback: ChainSelectionStrategy = (candidates) => candidates[0] as ValidatedTrustChain,
): Result<ValidatedTrustChain> {
	const fail = (message: string) =>
		err(federationError(InternalErrorCode.TrustChainInvalid, message));
	if (!chains.length) return fail("No eligible trust chains");
	try {
		const snapshots = chains.map((chain) => freezeSnapshot(cloneData(chain)));
		const selected = callSynchronous(
			() => (options?.chainSelection ?? fallback)([...snapshots]),
			(value): value is ValidatedTrustChain => snapshots.includes(value as ValidatedTrustChain),
		);
		if (!selected.ok) return fail(`Trust chain selection failed: ${selected.error}`);
		const chain = chains[snapshots.indexOf(selected.value)];
		if (!chain) return fail("Selected trust chain is unavailable");
		if (options?.signal?.aborted) return fail("Trust chain selection cancelled");
		if (chain.expiresAt <= nowSeconds(options?.clock))
			return fail("Selected trust chain has expired");
		return ok(chain);
	} catch {
		return fail("Trust chain selection failed");
	}
}

/** Select the chain with the fewest statements. */
export const shortestChain: ChainSelectionStrategy = (
	chains: ValidatedTrustChain[],
): ValidatedTrustChain => {
	return chains
		.slice()
		.sort((a, b) => a.statements.length - b.statements.length)[0] as ValidatedTrustChain;
};

/** Select the chain that expires last. */
export const longestExpiry: ChainSelectionStrategy = (
	chains: ValidatedTrustChain[],
): ValidatedTrustChain => {
	return chains.slice().sort((a, b) => b.expiresAt - a.expiresAt)[0] as ValidatedTrustChain;
};

/** Create a strategy that prefers chains terminating at the given trust anchor. */
export function preferTrustAnchor(taId: string): ChainSelectionStrategy {
	return (chains: ValidatedTrustChain[]): ValidatedTrustChain => {
		const matching = chains.filter((c) => c.trustAnchorId === taId);
		if (matching.length > 0) {
			return shortestChain(matching);
		}
		return shortestChain(chains);
	};
}
