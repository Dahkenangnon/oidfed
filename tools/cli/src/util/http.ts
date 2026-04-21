import {
	err,
	FederationErrorCode,
	federationError,
	type HttpClient,
	ok,
	type Result,
} from "@oidfed/core";

export function createHttpClient(timeoutMs?: number): HttpClient {
	if (!timeoutMs) return fetch;
	return (input, init) => {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), timeoutMs);
		return fetch(input, { ...init, signal: controller.signal }).finally(() => clearTimeout(timer));
	};
}

export async function fetchTextOrError(
	httpClient: HttpClient,
	url: string,
	errorPrefix: string,
): Promise<Result<string>> {
	const response = await httpClient(url);
	if (!response.ok) {
		return err(
			federationError(
				FederationErrorCode.NotFound,
				`${errorPrefix} with status ${response.status}`,
			),
		);
	}
	const body = await response.text();
	return ok(body);
}
