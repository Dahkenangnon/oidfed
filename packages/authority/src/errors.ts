/** Typed errors raised by Authority configuration and shape validation. */

/** Thrown by `createAuthorityServer` when the supplied configuration is invalid. */
export class InvalidAuthorityConfig extends Error {
	constructor(message: string) {
		super(message);
		this.name = "InvalidAuthorityConfig";
	}
}

/** Thrown by `MemorySubordinateStore.add()` when a record violates record-shape rules. */
export class InvalidSubordinateRecord extends Error {
	constructor(message: string) {
		super(message);
		this.name = "InvalidSubordinateRecord";
	}
}

/** Thrown when a payload destined for a Subordinate Statement carries an EC-only top-level claim. */
export class InvalidSubordinateStatementShape extends Error {
	constructor(public readonly forbiddenClaims: readonly string[]) {
		super(
			`Subordinate Statement payload must not contain top-level claims that belong only to an Entity Configuration: ${forbiddenClaims.join(", ")}`,
		);
		this.name = "InvalidSubordinateStatementShape";
	}
}

/** Thrown when a metadata object contains a `null` leaf at any depth. */
export class InvalidMetadata extends Error {
	constructor(public readonly path: string) {
		super(
			`metadata values must not be null; null found at path "${path}". Omit the field instead.`,
		);
		this.name = "InvalidMetadata";
	}
}
