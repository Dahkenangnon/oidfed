import type { FederationErrorCode, InternalErrorCode } from "./constants.js";

/** Discriminated union error — plain data, serializable, structurally typed. */
export type FederationError = {
	readonly code: FederationErrorCode | InternalErrorCode;
	readonly description: string;
	readonly cause?: unknown;
};

/** Construct a FederationError value. */
export function federationError(
	code: FederationErrorCode | InternalErrorCode,
	description: string,
	cause?: unknown,
): FederationError {
	return { code, description, cause };
}

/** Typed Result pattern — no silent failures. */
export type Result<T, E = FederationError> =
	| { readonly ok: true; readonly value: T }
	| { readonly ok: false; readonly error: E };

/** Wrap a success value in a Result. */
export function ok<T>(value: T): Result<T, never> {
	return { ok: true, value };
}

/** Wrap an error in a Result. */
export function err<E>(error: E): Result<never, E> {
	return { ok: false, error };
}

/** Type guard narrowing a Result to its success variant. */
export function isOk<T, E>(result: Result<T, E>): result is { ok: true; value: T } {
	return result.ok;
}

/** Type guard narrowing a Result to its error variant. */
export function isErr<T, E>(result: Result<T, E>): result is { ok: false; error: E } {
	return !result.ok;
}

export function map<T, U, E>(result: Result<T, E>, fn: (value: T) => U): Result<U, E> {
	if (result.ok) {
		return ok(fn(result.value));
	}
	return result;
}

export function flatMap<T, U, E>(
	result: Result<T, E>,
	fn: (value: T) => Result<U, E>,
): Result<U, E> {
	if (result.ok) {
		return fn(result.value);
	}
	return result;
}

export function mapErr<T, E, F>(result: Result<T, E>, fn: (error: E) => F): Result<T, F> {
	if (!result.ok) {
		return err(fn(result.error));
	}
	return result;
}

export function unwrapOr<T, E>(result: Result<T, E>, fallback: T): T {
	if (result.ok) {
		return result.value;
	}
	return fallback;
}
