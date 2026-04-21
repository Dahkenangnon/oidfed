import type { FederationError, Result } from "./errors.js";
import type { ValidatedTrustChain } from "./types.js";

/**
 * Protocol-specific adapter for the federation registration endpoint.
 *
 * The federation registration handler is protocol-agnostic by default.
 * When an adapter is provided, it is called for protocol-specific metadata
 * validation and enrichment (e.g., OIDC RP metadata validation).
 */
export interface RegistrationProtocolAdapter {
	/**
	 * Validate protocol-specific client metadata from the registration request.
	 * Called after federation-layer validation succeeds.
	 *
	 * @param raw - The raw metadata object from the registration request
	 * @returns The validated metadata or a federation error
	 */
	validateClientMetadata(
		raw: Record<string, unknown>,
	): Result<Record<string, unknown>, FederationError>;

	/**
	 * Enrich the registration response metadata with protocol-specific fields.
	 * Called before the response is signed and returned.
	 *
	 * @param rpMeta - The RP's resolved metadata
	 * @param trustChain - The validated trust chain for the RP
	 * @returns The enriched metadata for the response
	 */
	enrichResponseMetadata(
		rpMeta: Record<string, unknown>,
		trustChain: ValidatedTrustChain,
	): Record<string, unknown>;
}
