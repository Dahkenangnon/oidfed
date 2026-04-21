import { MediaType } from "@oidfed/core";

export interface EndpointResult {
	readonly name: string;
	readonly url: string;
	readonly status: number | null;
	readonly latency: number | null;
	readonly contentType: string | null;
	readonly expectedContentType: string;
	readonly ok: boolean;
	readonly error: string | null;
}

export type ProbeStrategy = "get-bare" | "get-with-sub" | "post-form" | "reachability-only";

export const ENDPOINT_EXPECTED_TYPES: ReadonlyArray<{
	readonly key: string;
	readonly label: string;
	readonly expectedContentType: string;
	readonly strategy: ProbeStrategy;
}> = [
	{
		key: "federation_fetch_endpoint",
		label: "federation_fetch_endpoint",
		expectedContentType: MediaType.EntityStatement,
		strategy: "get-with-sub",
	},
	{
		key: "federation_list_endpoint",
		label: "federation_list_endpoint",
		expectedContentType: MediaType.Json,
		strategy: "get-bare",
	},
	{
		key: "federation_resolve_endpoint",
		label: "federation_resolve_endpoint",
		expectedContentType: MediaType.ResolveResponse,
		strategy: "reachability-only",
	},
	{
		key: "federation_trust_mark_status_endpoint",
		label: "federation_trust_mark_status_endpoint",
		expectedContentType: MediaType.TrustMarkStatusResponse,
		strategy: "post-form",
	},
	{
		key: "federation_historical_keys_endpoint",
		label: "federation_historical_keys_endpoint",
		expectedContentType: MediaType.EntityStatement,
		strategy: "get-bare",
	},
];

export async function probeEndpoint(
	name: string,
	url: string,
	expectedContentType: string,
	timeoutMs: number,
	strategy: ProbeStrategy,
	entityId: string,
): Promise<EndpointResult> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	const start = performance.now();

	try {
		let probeUrl = url;
		let fetchInit: RequestInit = { signal: controller.signal };

		if (strategy === "get-with-sub") {
			probeUrl = `${url}?sub=${encodeURIComponent(entityId)}`;
		} else if (strategy === "post-form") {
			fetchInit = {
				...fetchInit,
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: "trust_mark=probe",
			};
		}

		const response = await fetch(probeUrl, fetchInit);
		const latency = Math.round(performance.now() - start);
		clearTimeout(timer);

		const contentType = response.headers.get("content-type");
		const statusOk = response.status >= 200 && response.status < 300;
		const ctOk = contentType?.includes(expectedContentType) ?? false;

		let ok: boolean;
		if (strategy === "reachability-only" || strategy === "post-form") {
			ok = true;
		} else {
			ok = statusOk && ctOk;
		}

		return {
			name,
			url,
			status: response.status,
			latency,
			contentType,
			expectedContentType,
			ok,
			error: null,
		};
	} catch (err) {
		clearTimeout(timer);
		const latency = Math.round(performance.now() - start);
		const isAbort = err instanceof DOMException && err.name === "AbortError";
		return {
			name,
			url,
			status: null,
			latency,
			contentType: null,
			expectedContentType,
			ok: false,
			error: isAbort ? "Request timed out" : err instanceof Error ? err.message : "Unknown error",
		};
	}
}
