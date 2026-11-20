/** Reports invalid durable data without including its contents. */
export class InvalidStorageRecordError extends Error {
	constructor(
		readonly kind: string,
		readonly operation: string,
		detail: string,
	) {
		super(`Invalid ${kind} record (${operation}): ${detail}`);
		this.name = "InvalidStorageRecordError";
	}
}

/** Thrown when a subordinate record violates Subordinate Statement shape rules. */
export class InvalidSubordinateRecord extends InvalidStorageRecordError {
	constructor(message: string, operation = "validate") {
		super("subordinate", operation, message);
		this.name = "InvalidSubordinateRecord";
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
