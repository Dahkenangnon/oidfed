/** Serializable federation errors and discriminated Result helpers. */

import type { FederationErrorCode, InternalErrorCode } from "./constants.js";

/** Plain, serializable, structurally typed federation error data. */
export type FederationError = {
	readonly code: FederationErrorCode | InternalErrorCode;
	readonly description: string;
	readonly cause?: unknown;
	/** Untrusted responder details; code remains a typed local classification. */
	readonly remoteError?: { readonly code: string; readonly status: number };
};

/** Construct a FederationError value. */
export function federationError(
	code: FederationErrorCode | InternalErrorCode,
	description: string,
	cause?: unknown,
): FederationError {
	return { code, description, cause };
}

/** A success value or error, distinguished by the ok field. */
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

/** Apply fn to a successful value; return errors as received. Exceptions from fn propagate. */
export function map<T, U, E>(result: Result<T, E>, fn: (value: T) => U): Result<U, E> {
	if (result.ok) {
		return ok(fn(result.value));
	}
	return result;
}

/**
 * Pass a successful value to a Result-returning fn; return errors as received. Exceptions from fn
 * propagate.
 */
export function flatMap<T, U, E>(
	result: Result<T, E>,
	fn: (value: T) => Result<U, E>,
): Result<U, E> {
	if (result.ok) {
		return fn(result.value);
	}
	return result;
}

/** Apply fn to an error; return successful results as received. Exceptions from fn propagate. */
export function mapErr<T, E, F>(result: Result<T, E>, fn: (error: E) => F): Result<T, F> {
	if (!result.ok) {
		return err(fn(result.error));
	}
	return result;
}

/** Return the successful value, or the supplied fallback for an error Result. */
export function unwrapOr<T, E>(result: Result<T, E>, fallback: T): T {
	if (result.ok) {
		return result.value;
	}
	return fallback;
}
