/** Typed errors raised by Authority configuration and shape validation. */

/** Configuration error raised by Authority validation. Other checks may throw Error or TypeError. */
export class InvalidAuthorityConfig extends Error {
	constructor(message: string) {
		super(message);
		this.name = "InvalidAuthorityConfig";
	}
}
