/** Trust chain discovery: resolves and validates chains, returning a branded DiscoveryResult. */
import {
	type DiscoveryResult,
	type EntityId,
	type FederationOptions,
	resolveTrustChains,
	shortestChain,
	type TrustAnchorSet,
	type ValidatedTrustChain,
	validateTrustChain,
} from "@oidfed/core";

/**
 * Resolves and validates trust chains for a target entity, returning the shortest valid chain.
 *
 * Callers should re-invoke when `result.trustChain.expiresAt` is reached to refresh
 * the chain.
 */
export async function discoverEntity(
	entityId: EntityId,
	trustAnchors: TrustAnchorSet,
	options?: FederationOptions,
): Promise<DiscoveryResult> {
	const chainResult = await resolveTrustChains(entityId, trustAnchors, options);

	if (chainResult.chains.length === 0) {
		const details = chainResult.errors.length
			? `: ${chainResult.errors.map((e) => e.description).join("; ")}`
			: "";
		throw new Error(`No trust chains resolved for entity${details}`);
	}

	const validChains: ValidatedTrustChain[] = [];
	const validationErrors: string[] = [];

	for (const chain of chainResult.chains) {
		// Type friction: validateTrustChain accepts string[] but chain.statements is ReadonlyArray<string>.
		// Real fix belongs in core (validateTrustChain should accept ReadonlyArray<string>).
		const result = await validateTrustChain(chain.statements as string[], trustAnchors, options);
		if (result.valid) {
			validChains.push(result.chain);
		} else {
			validationErrors.push(result.errors.map((e) => e.message).join("; "));
		}
	}

	if (validChains.length === 0) {
		const details = validationErrors.length ? `: ${validationErrors.join(" | ")}` : "";
		throw new Error(`No valid trust chains for entity${details}`);
	}

	const bestChain = shortestChain(validChains);

	// Brand applied here; leaf is the sole authorised DiscoveryResult producer (see core types.ts).
	return {
		entityId,
		resolvedMetadata: bestChain.resolvedMetadata,
		trustChain: bestChain,
		trustMarks: bestChain.trustMarks,
	} as DiscoveryResult;
}
