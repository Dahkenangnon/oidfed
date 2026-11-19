/** Cancellation and timeout boundaries for independently owned asynchronous operations. */

import { DEFAULT_HTTP_TIMEOUT_MS } from "./constants.js";
import type { FederationOptions } from "./types.js";

/** Release a waiting caller on cancellation without cancelling an independently owned operation. */
export async function waitForOperation<T>(
	pending: Promise<T>,
	signals: readonly (AbortSignal | undefined)[],
): Promise<T> {
	let abort: () => void = () => {};
	const stopped = new Promise<never>((_, reject) => {
		abort = () => reject(new DOMException("Operation cancelled", "AbortError"));
		for (const signal of signals) signal?.addEventListener("abort", abort, { once: true });
		if (signals.some((signal) => signal?.aborted)) abort();
	});
	try {
		const result = await Promise.race([pending, stopped]);
		if (signals.some((signal) => signal?.aborted))
			throw new DOMException("Operation cancelled", "AbortError");
		return result;
	} finally {
		for (const signal of signals) signal?.removeEventListener("abort", abort);
	}
}

/** Bound application-controlled async work without retaining abort listeners afterward. */
export async function runAsyncOperation<T>(
	operation: (signal: AbortSignal) => T | Promise<T>,
	options: Pick<FederationOptions, "signal" | "httpTimeoutMs">,
): Promise<T> {
	if (options.signal?.aborted) throw new DOMException("Operation cancelled", "AbortError");
	const timeout = options.httpTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
	if (!Number.isFinite(timeout) || timeout <= 0)
		throw new TypeError("Operation timeout must be positive and finite");
	const controller = new AbortController();
	let timer: ReturnType<typeof setTimeout> | undefined;
	let onAbort: (() => void) | undefined;
	const stopped = new Promise<never>((_, reject) => {
		onAbort = () => {
			controller.abort(options.signal?.reason);
			reject(new DOMException("Operation cancelled", "AbortError"));
		};
		options.signal?.addEventListener("abort", onAbort, { once: true });
		timer = setTimeout(() => {
			controller.abort();
			reject(new DOMException("Operation timed out", "TimeoutError"));
		}, timeout);
	});
	try {
		const result = await Promise.race([
			Promise.resolve().then(() => {
				if (controller.signal.aborted) throw new DOMException("Operation cancelled", "AbortError");
				return operation(controller.signal);
			}),
			stopped,
		]);
		if (options.signal?.aborted) throw new DOMException("Operation cancelled", "AbortError");
		return result;
	} finally {
		if (timer !== undefined) clearTimeout(timer);
		if (onAbort) options.signal?.removeEventListener("abort", onAbort);
	}
}

/** Create a concurrency limiter that allows at most `maxConcurrent` parallel executions. */
export function createConcurrencyLimiter(
	maxConcurrent: number,
	signal?: AbortSignal,
): <T>(fn: () => Promise<T>) => Promise<T> {
	if (!Number.isSafeInteger(maxConcurrent) || maxConcurrent <= 0)
		throw new RangeError("maxConcurrent must be a positive safe integer");
	let active = 0;
	const queue: Array<{ resolve: () => void; reject: (reason: unknown) => void }> = [];
	const aborted = () => new DOMException("Operation aborted", "AbortError");
	const onAbort = () => {
		for (const pending of queue.splice(0)) pending.reject(aborted());
		signal?.removeEventListener("abort", onAbort);
	};
	async function acquire(): Promise<void> {
		if (signal?.aborted) throw aborted();
		if (active < maxConcurrent) {
			active++;
			return;
		}
		await new Promise<void>((resolve, reject) => {
			queue.push({ resolve, reject });
			if (queue.length === 1) signal?.addEventListener("abort", onAbort, { once: true });
			if (signal?.aborted) onAbort();
		});
	}

	return async <T>(fn: () => Promise<T>): Promise<T> => {
		await acquire();
		try {
			if (signal?.aborted) throw aborted();
			return await fn();
		} finally {
			const next = queue.shift();
			if (!queue.length) signal?.removeEventListener("abort", onAbort);
			// Transfer the occupied slot directly to a waiter before admitting new work.
			if (next) next.resolve();
			else active--;
		}
	};
}
