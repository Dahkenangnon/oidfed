import type { FederationError } from "../errors.js";

type FetchFailure =
	| { kind: "transport" | "timeout" | "cancelled" | "response" }
	| { kind: "http"; status: number };

// Preserve the public, serializable error shape. Unclassified/copied errors fail closed.
const failures = new WeakMap<FederationError, FetchFailure>();

export function fetchFailure(error: FederationError, failure: FetchFailure): FederationError {
	failures.set(error, failure);
	return error;
}

export function isAvailabilityFailure(error: FederationError): boolean {
	const failure = failures.get(error);
	return (
		failure?.kind === "transport" ||
		failure?.kind === "timeout" ||
		(failure?.kind === "http" && [404, 410, 500, 502, 503, 504].includes(failure.status))
	);
}
