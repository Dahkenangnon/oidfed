/** Protocol signing-key contracts separate from Federation Entity Keys. */

import type { JwtSigner } from "@oidfed/core";

/** Supply protocol signing identities independently of the host's Federation Entity Keys. */
export interface ProtocolSigningKeyProvider {
	getRequestObjectSigner(): Promise<JwtSigner>;
	getClientAssertionSigner?(): Promise<JwtSigner>;
}

/**
 * Retain protocol signers supplied by the host; no key rotation or key generation is performed
 * here.
 */
export class StaticProtocolSigningKeyProvider implements ProtocolSigningKeyProvider {
	private readonly requestObjectSigner: JwtSigner;
	private readonly clientAssertionSigner: JwtSigner | undefined;

	constructor(options: { requestObjectSigner: JwtSigner; clientAssertionSigner?: JwtSigner }) {
		this.requestObjectSigner = options.requestObjectSigner;
		this.clientAssertionSigner = options.clientAssertionSigner;
	}

	async getRequestObjectSigner(): Promise<JwtSigner> {
		return this.requestObjectSigner;
	}

	/** Return the configured assertion signer, falling back to the Request Object signer. */
	async getClientAssertionSigner(): Promise<JwtSigner> {
		return this.clientAssertionSigner ?? this.requestObjectSigner;
	}
}
