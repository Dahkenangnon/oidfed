/** Trust chain discovery: resolves and validates chains, returning a branded DiscoveryResult. */
import { InternalErrorCode } from "../constants.js";
import { err, federationError, ok, type Result } from "../errors.js";
import { safeLogger } from "./../logging.js";
import type {
	DiscoveryResult,
	EntityId,
	FederationOptions,
	TrustAnchorSet,
	ValidatedTrustChain,
} from "../types.js";
import { createTrustChainOperation } from "./operation.js";
import { resolveTrustChains } from "./resolve.js";
import { selectTrustChain } from "./selection.js";
import { shortestChain, validateTrustChain } from "./validate.js";

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
): Promise<Result<DiscoveryResult>> {
	safeLogger(options?.logger)?.debug("Starting discover entity");

	const operation = createTrustChainOperation(options);
	if (!operation.ok) return operation;
	options = operation.value.options;
	const chainResult = await resolveTrustChains(entityId, trustAnchors, options);

	if (chainResult.chains.length === 0) {
		const details = chainResult.errors.length
			? `: ${chainResult.errors.map((e) => e.description).join("; ")}`
			: "";
		return err(
			federationError(
				InternalErrorCode.TrustChainInvalid,
				`No trust chains resolved for entity${details}`,
			),
		);
	}

	const validChains: ValidatedTrustChain[] = [];
	const validationErrors: string[] = [];

	for (const chain of chainResult.chains) {
		const result = await validateTrustChain(chain.statements, trustAnchors, {
			...options,
			entityConfigurations: chain.entityConfigurations,
		});
		if (result.valid) {
			validChains.push(result.chain);
		} else {
			validationErrors.push(result.errors.map((e) => e.message).join("; "));
		}
	}

	if (validChains.length === 0) {
		const details = validationErrors.length ? `: ${validationErrors.join(" | ")}` : "";
		return err(
			federationError(
				InternalErrorCode.TrustChainInvalid,
				`No valid trust chains for entity${details}`,
			),
		);
	}

	if (operation.value.exhausted() || (options?.chainSelection && chainResult.incomplete))
		return err(
			federationError(InternalErrorCode.TrustChainInvalid, "Trust chain discovery was incomplete"),
		);
	const selected = selectTrustChain(validChains, options, shortestChain);
	if (!selected.ok) return selected;
	const bestChain = selected.value;

	// Core creates discovery results only after validating their evidence.
	return ok({
		entityId,
		resolvedMetadata: bestChain.resolvedMetadata,
		trustChain: bestChain,
		trustMarks: bestChain.trustMarks,
	} as DiscoveryResult);
}

/** Validate supplied statements before exposing them to protocol operations. */
export async function discoverEntityFromChain(
	entityId: EntityId,
	statements: readonly string[],
	trustAnchors: TrustAnchorSet,
	options?: FederationOptions,
): Promise<Result<DiscoveryResult>> {
	const operation = createTrustChainOperation(options);
	if (!operation.ok) return operation;
	options = operation.value.options;
	const checked = await validateTrustChain(statements, trustAnchors, options);
	if (!checked.valid)
		return err(
			federationError(
				InternalErrorCode.TrustChainInvalid,
				checked.errors.map((error) => error.message).join("; "),
			),
		);
	if (checked.chain.entityId !== entityId)
		return err(
			federationError(
				InternalErrorCode.TrustChainInvalid,
				"Trust chain subject does not match the requested entity",
			),
		);
	const selected = selectTrustChain([checked.chain], options);
	if (!selected.ok) return selected;
	return ok({
		entityId,
		resolvedMetadata: checked.chain.resolvedMetadata,
		trustChain: checked.chain,
		trustMarks: checked.chain.trustMarks,
	} as DiscoveryResult);
}
