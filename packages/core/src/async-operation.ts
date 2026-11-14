import { DEFAULT_HTTP_TIMEOUT_MS } from "./constants.js";
import type { FederationOptions } from "./types.js";

/** Bound application-controlled async work without retaining abort listeners afterward. */
export async function runAsyncOperation<T>(
	operation: (signal: AbortSignal) => T | Promise<T>,
	options: FederationOptions,
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
