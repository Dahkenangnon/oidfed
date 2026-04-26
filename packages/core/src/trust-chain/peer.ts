/** Peer-chain helper: build a Trust Chain ending at a specific Trust Anchor. */
import { InternalErrorCode } from "../constants.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import type { EntityId, FederationOptions, TrustAnchorSet } from "../types.js";
import { resolveTrustChains } from "./resolve.js";
import { validateTrustChain } from "./validate.js";

/**
 * Build a Trust Chain for `subject` that ends at the given `trustAnchorId`.
 *
 * Returns the array of Entity Statement JWTs ready to attach as a
 * `trust_chain` or `peer_trust_chain` JWS header value, or an error if no
 * valid chain to that anchor exists from this resolver's vantage point.
 */
export async function resolveTrustChainForAnchor(
	subject: EntityId,
	trustAnchorId: EntityId,
	trustAnchors: TrustAnchorSet,
	options?: FederationOptions,
): Promise<Result<readonly string[], FederationError>> {
	if (!trustAnchors.has(trustAnchorId)) {
		return err(
			federationError(
				InternalErrorCode.TrustAnchorUnknown,
				`Requested Trust Anchor '${trustAnchorId}' is not in the pre-trusted set`,
			),
		);
	}

	const chainResult = await resolveTrustChains(subject, trustAnchors, options);
	if (chainResult.chains.length === 0) {
		const firstError = chainResult.errors[0];
		return err(
			firstError ??
				federationError(
					InternalErrorCode.TrustChainInvalid,
					`No Trust Chain could be built for ${subject}`,
				),
		);
	}

	const candidates = chainResult.chains.filter((c) => c.trustAnchorId === trustAnchorId);
	if (candidates.length === 0) {
		return err(
			federationError(
				InternalErrorCode.TrustChainInvalid,
				`No Trust Chain ending at '${trustAnchorId}' was found for ${subject}`,
			),
		);
	}

	for (const candidate of candidates) {
		const validation = await validateTrustChain(
			candidate.statements as string[],
			trustAnchors,
			options,
		);
		if (validation.valid) {
			return ok(candidate.statements as readonly string[]);
		}
	}

	return err(
		federationError(
			InternalErrorCode.TrustChainInvalid,
			`No valid Trust Chain ending at '${trustAnchorId}' was found for ${subject}`,
		),
	);
}
