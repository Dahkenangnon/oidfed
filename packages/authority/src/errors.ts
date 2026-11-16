/** Typed errors raised by Authority configuration and shape validation. */

/** Configuration error raised by Authority validation. Other checks may throw Error or TypeError. */
export class InvalidAuthorityConfig extends Error {
	constructor(message: string) {
		super(message);
		this.name = "InvalidAuthorityConfig";
	}
}

/** Thrown when a subordinate record violates Subordinate Statement shape rules. */
export class InvalidSubordinateRecord extends Error {
	constructor(message: string) {
		super(message);
		this.name = "InvalidSubordinateRecord";
	}
}

/** Error available to integrations for reporting EC-only claims in a Subordinate Statement. */
export class InvalidSubordinateStatementShape extends Error {
	constructor(public readonly forbiddenClaims: readonly string[]) {
		super(
			`Subordinate Statement payload must not contain top-level claims that belong only to an Entity Configuration: ${forbiddenClaims.join(", ")}`,
		);
		this.name = "InvalidSubordinateStatementShape";
	}
}

/** Reports a null entity-type block or direct metadata parameter value; this check does not reject nested JSON nulls. */
export class InvalidMetadata extends Error {
	constructor(public readonly path: string) {
		super(
			`metadata entity-type blocks and direct parameter values must not be null; null found at path "${path}". Omit the field instead.`,
		);
		this.name = "InvalidMetadata";
	}
}
