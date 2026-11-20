/** Protocol-engine callbacks for client metadata validation and registration responses. */

import type { FederationError, Result, ValidatedTrustChain } from "@oidfed/core";

export interface RegistrationProtocolAdapterContext {
	readonly flow: "explicit" | "automatic" | "par";
	readonly clientMetadataType: "openid_relying_party" | "oauth_client";
	/** Effective server metadata from a verified peer chain, when supplied. */
	readonly peerResolvedOpMetadata?: Readonly<Record<string, unknown>>;
	/** Cancellation signal for the registration operation. */
	readonly signal?: AbortSignal;
}

/** Add host protocol checks and customize explicit registration responses. */
export interface RegistrationProtocolAdapter {
	/**
	 * Accept or reject the detached effective metadata after federation validation.
	 * Use clientMetadataType to find the relevant client block.
	 */
	validateClientMetadata(
		metadata: Readonly<Record<string, Readonly<Record<string, unknown>>>>,
		context: RegistrationProtocolAdapterContext,
	): Result<void, FederationError>;

	/** Customize the explicit response metadata before policy checks, signing, and persistence. */
	enrichResponseMetadata?(
		metadata: Record<string, Record<string, unknown>>,
		trustChain: ValidatedTrustChain,
		context: RegistrationProtocolAdapterContext & { readonly flow: "explicit" },
	): Record<string, Record<string, unknown>>;
}
