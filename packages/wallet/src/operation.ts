import { DEFAULT_HTTP_TIMEOUT_MS, type FederationOptions } from "@oidfed/core";

/** Bound application-controlled async work without retaining abort listeners afterward. */
export async function runOperation<T>(
	operation: (signal: AbortSignal) => T | Promise<T>,
	options: FederationOptions,
): Promise<T> {
	if (options.signal?.aborted) throw new Error("Operation cancelled");
	const timeout = options.httpTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
	if (!Number.isFinite(timeout) || timeout <= 0)
		throw new TypeError("Operation timeout must be positive and finite");
	const controller = new AbortController();
	let timer: ReturnType<typeof setTimeout> | undefined;
	let onAbort: (() => void) | undefined;
	const stopped = new Promise<never>((_, reject) => {
		onAbort = () => {
			controller.abort(options.signal?.reason);
			reject(new Error("Operation cancelled"));
		};
		options.signal?.addEventListener("abort", onAbort, { once: true });
		timer = setTimeout(() => {
			controller.abort();
			reject(new Error("Operation timed out"));
		}, timeout);
	});
	try {
		const result = await Promise.race([
			Promise.resolve().then(() => operation(controller.signal)),
			stopped,
		]);
		if (options.signal?.aborted) throw new Error("Operation cancelled");
		return result;
	} finally {
		if (timer !== undefined) clearTimeout(timer);
		if (onAbort) options.signal?.removeEventListener("abort", onAbort);
	}
}
