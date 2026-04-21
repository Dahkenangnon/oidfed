import {
	type EntityId,
	err,
	type FederationError,
	FederationErrorCode,
	type FederationOptions,
	federationError,
	ok,
	type Result,
	resolveTrustChains,
	shortestChain,
	type TrustAnchorSet,
	type ValidatedTrustChain,
	validateTrustChain,
} from "@oidfed/core";

/** Extracts `client_registration_types_supported` from OP metadata. */
export function getRegistrationTypes(opMeta: Record<string, unknown> | undefined): string[] {
	return (opMeta?.client_registration_types_supported as string[] | undefined) ?? [];
}

/**
 * Resolve trust chains for an entity and return the shortest valid chain.
 *
 * Shared by automatic and explicit registration flows.
 */
export async function resolveAndValidateBestChain(
	rpEntityId: EntityId,
	trustAnchors: TrustAnchorSet,
	options: FederationOptions,
): Promise<Result<ValidatedTrustChain, FederationError>> {
	const chainResult = await resolveTrustChains(rpEntityId, trustAnchors, options);

	if (chainResult.chains.length === 0) {
		const errorMsgs = chainResult.errors.map((e) => e.description).join("; ");
		return err(
			federationError(
				FederationErrorCode.InvalidTrustChain,
				`Failed to resolve trust chain for RP: ${errorMsgs || "no chains found"}`,
			),
		);
	}

	const validChains: ValidatedTrustChain[] = [];
	for (const chain of chainResult.chains) {
		const result = await validateTrustChain(chain.statements as string[], trustAnchors, options);
		if (result.valid) {
			validChains.push(result.chain);
		}
	}

	if (validChains.length === 0) {
		return err(
			federationError(FederationErrorCode.InvalidTrustChain, "No valid trust chains found for RP"),
		);
	}

	return ok(shortestChain(validChains));
}
