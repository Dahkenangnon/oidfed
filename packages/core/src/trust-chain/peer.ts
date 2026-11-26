/** Peer-chain helper: build a Trust Chain ending at a specific Trust Anchor. */

import { InternalErrorCode } from "../constants.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import { safeLogger } from "../logging.js";
import type {
	EntityId,
	FederationOptions,
	TrustAnchorSet,
	TrustChain,
	ValidatedTrustChain,
} from "../types.js";
import { createTrustChainOperation } from "./operation.js";
import { resolveTrustChains } from "./resolve.js";
import { selectTrustChain } from "./selection.js";
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
	options: FederationOptions,
): Promise<Result<readonly string[], FederationError>> {
	const result = await resolveTrustChainEvidenceForAnchor(
		subject,
		trustAnchorId,
		trustAnchors,
		options,
	);
	return result.ok ? ok(result.value.chain.statements) : result;
}

/** Keep the selected path and the validation result available to the Resolve cache. */
export async function resolveTrustChainEvidenceForAnchor(
	subject: EntityId,
	trustAnchorId: EntityId,
	trustAnchors: TrustAnchorSet,
	options: FederationOptions,
): Promise<Result<{ chain: TrustChain; validated: ValidatedTrustChain }, FederationError>> {
	safeLogger(options?.logger)?.debug("Starting resolve trust chain for anchor");

	if (!trustAnchors.has(trustAnchorId)) {
		return err(
			federationError(
				InternalErrorCode.TrustAnchorUnknown,
				`Requested Trust Anchor '${trustAnchorId}' is not in the pre-trusted set`,
			),
		);
	}

	const operation = createTrustChainOperation(options);
	if (!operation.ok) return operation;
	options = operation.value.options;
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

	const eligible: ValidatedTrustChain[] = [];
	const raw = new Map<ValidatedTrustChain, TrustChain>();
	for (const candidate of candidates) {
		const validation = await validateTrustChain(candidate.statements as string[], trustAnchors, {
			...options,
			entityConfigurations: candidate.entityConfigurations,
		});
		if (operation.value.exhausted())
			return err(
				federationError(InternalErrorCode.TrustChainInvalid, "Trust chain operation exhausted"),
			);
		if (validation.valid) {
			if (!options?.chainSelection) return ok({ chain: candidate, validated: validation.chain });
			eligible.push(validation.chain);
			raw.set(validation.chain, candidate);
		}
	}

	if (options?.chainSelection && chainResult.incomplete)
		return err(
			federationError(InternalErrorCode.TrustChainInvalid, "Trust chain discovery was incomplete"),
		);
	if (eligible.length) {
		const selected = selectTrustChain(eligible, options);
		if (!selected.ok) return selected;
		const chain = raw.get(selected.value);
		if (chain) return ok({ chain, validated: selected.value });
	}
	return err(
		federationError(
			InternalErrorCode.TrustChainInvalid,
			`No valid Trust Chain ending at '${trustAnchorId}' was found for ${subject}`,
		),
	);
}
