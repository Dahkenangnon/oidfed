import type { JwtSigner } from "@oidfed/core";

export interface OidcProtocolKeyProvider {
	getRequestObjectSigner(): Promise<JwtSigner>;
	getClientAssertionSigner?(): Promise<JwtSigner>;
}

export class StaticOidcProtocolKeyProvider implements OidcProtocolKeyProvider {
	private readonly requestObjectSigner: JwtSigner;
	private readonly clientAssertionSigner: JwtSigner | undefined;

	constructor(options: { requestObjectSigner: JwtSigner; clientAssertionSigner?: JwtSigner }) {
		this.requestObjectSigner = options.requestObjectSigner;
		this.clientAssertionSigner = options.clientAssertionSigner;
	}

	async getRequestObjectSigner(): Promise<JwtSigner> {
		return this.requestObjectSigner;
	}

	async getClientAssertionSigner(): Promise<JwtSigner> {
		return this.clientAssertionSigner ?? this.requestObjectSigner;
	}
}
