import type { FederationError, Result } from "./errors.js";
import type { ValidatedTrustChain } from "./types.js";

/**
 * Optional context passed to adapter methods when the registration request
 * carried a `peer_trust_chain` JWS header. The peer chain provides the OP's
 * metadata/policy as the RP resolved it; the adapter MAY consult these
 * RP-chosen values when validating client metadata or constructing the
 * response.
 */
export interface RegistrationProtocolAdapterContext {
	/**
	 * The OP's resolved metadata as derived from the validated peer chain
	 * (validated by the federation handler before this is passed in). When
	 * absent, no peer chain was supplied or it failed validation.
	 */
	readonly peerResolvedOpMetadata?: Readonly<Record<string, unknown>>;
}

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
	 * @param context - Optional adapter context (peer chain metadata, etc.)
	 * @returns The validated metadata or a federation error
	 */
	validateClientMetadata(
		raw: Record<string, unknown>,
		context?: RegistrationProtocolAdapterContext,
	): Result<Record<string, unknown>, FederationError>;

	/**
	 * Enrich the registration response metadata with protocol-specific fields.
	 * Called before the response is signed and returned.
	 *
	 * @param rpMeta - The RP's resolved metadata
	 * @param trustChain - The validated trust chain for the RP
	 * @param context - Optional adapter context (peer chain metadata, etc.)
	 * @returns The enriched metadata for the response
	 */
	enrichResponseMetadata(
		rpMeta: Record<string, unknown>,
		trustChain: ValidatedTrustChain,
		context?: RegistrationProtocolAdapterContext,
	): Record<string, unknown>;
}
