import { MemoryCache } from "../cache/index.js";
import { FederationErrorCode, MediaType } from "../constants.js";
import { fetchFederationEndpoint } from "../endpoint-client.js";
import { err, type Result } from "../errors.js";
import type { PerformFetchOptions } from "../trust-chain/fetch.js";
import type { FederationOptions, HttpClient } from "../types.js";

const scopedClients = new WeakSet<HttpClient>();
const historicalRequests = new WeakMap<
	HttpClient,
	Map<
		FederationOptions["authentication"] | FederationOptions["getEndpointAuthentication"],
		Map<string, Promise<Result<string>>>
	>
>();
/** One HTTP allowance shared by discovery, validation, and historical evidence. */
export function trustMarkOperation<T extends FederationOptions>(options: T): T {
	if (options.httpClient && scopedClients.has(options.httpClient)) return options;
	const limit = options.maxTotalFetches ?? 50;
	let remaining = limit;
	const client = options.httpClient ?? fetch;
	const httpClient: HttpClient = async (input, init) => {
		if (options.offline) throw new Error("Offline operation cannot access the network");
		if (options.signal?.aborted) throw new Error("Operation cancelled");
		if (!Number.isSafeInteger(limit) || limit <= 0 || remaining-- <= 0)
			throw new Error("Trust Mark fetch budget exhausted");
		return client(input, init);
	};
	scopedClients.add(httpClient);
	return {
		...options,
		httpClient,
		cache: options.cache ?? new MemoryCache(options.clock ? { clock: options.clock } : undefined),
	};
}

/** Share transport only within an operation; every consumer still authenticates the response. */
export function fetchTrustMarkHistoricalResponse(
	endpoint: string,
	issuer: string,
	options: PerformFetchOptions,
): Promise<Result<string>> {
	if (options.authentication !== undefined && options.getEndpointAuthentication !== undefined)
		return Promise.resolve(
			err({
				code: FederationErrorCode.InvalidRequest,
				description: "Static and selected authentication cannot be combined",
			}),
		);
	const scoped = trustMarkOperation(options);
	const client = scoped.httpClient;
	if (!client) throw new Error("Trust Mark operation requires an HTTP client");
	let requests = historicalRequests.get(client);
	if (!requests) {
		requests = new Map();
		historicalRequests.set(client, requests);
	}
	const authenticationScope = scoped.getEndpointAuthentication ?? scoped.authentication;
	let authenticated = requests.get(authenticationScope);
	if (!authenticated) {
		authenticated = new Map();
		requests.set(authenticationScope, authenticated);
	}
	const key = JSON.stringify([
		issuer,
		endpoint,
		scoped.additionalParameters,
		scoped.contentTypePolicy,
		scoped.maxResponseBytes,
		scoped.httpTimeoutMs,
	]);
	let response = authenticated.get(key);
	if (!response) {
		response = fetchFederationEndpoint(
			endpoint,
			new URLSearchParams(),
			{ ...scoped, expectedStatus: 200, accept: MediaType.JwkSet, redirect: "manual" },
			issuer,
		);
		authenticated.set(key, response);
	}
	return response;
}
