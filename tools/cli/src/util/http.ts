import type { HttpClient } from "@oidfed/core";

export function createHttpClient(timeoutMs?: number): HttpClient {
	if (!timeoutMs) return fetch;
	return (input, init) => {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), timeoutMs);
		return fetch(input, { ...init, signal: controller.signal }).finally(() => clearTimeout(timer));
	};
}
