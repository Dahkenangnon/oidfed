/** Application authorization shared by managed Federation endpoints. */
import { runAsyncOperation } from "./async-operation.js";
import { freezeSnapshot } from "./callbacks.js";
import { errorResponse } from "./http.js";
import { safeLogger } from "./logging.js";
import type { FederationOptions } from "./types.js";

export type FederationEndpointOperation =
	| "fetch"
	| "list"
	| "extended-list"
	| "resolve"
	| "collection"
	| "historical-keys"
	| "subordinate-events"
	| "trust-mark"
	| "trust-mark-list"
	| "trust-mark-status"
	| "custom";

export interface EndpointAuthorizationInput {
	readonly endpoint: FederationEndpointOperation;
	readonly receiverEntityId: string;
	readonly caller: string | undefined;
	readonly parameters: Readonly<Record<string, readonly string[] | undefined>>;
	readonly signal: AbortSignal;
}

export type EndpointAuthorizationPolicy = (
	input: Readonly<EndpointAuthorizationInput>,
) => boolean | Promise<boolean>;

/** Evaluate the host policy before the handler can read or mutate a protected resource. */
export async function authorizeFederationEndpoint(
	options: FederationOptions,
	input: Omit<EndpointAuthorizationInput, "parameters" | "signal">,
	form: URLSearchParams,
	signal: AbortSignal,
): Promise<Response | undefined> {
	const policy = options.authorizeEndpointRequest;
	if (policy === undefined) return undefined;
	const cancellation = options.signal ? AbortSignal.any([options.signal, signal]) : signal;
	try {
		const parameters = Object.create(null) as Record<string, readonly string[]>;
		for (const name of new Set(form.keys())) parameters[name] = form.getAll(name);
		const allowed = await runAsyncOperation(
			(signal) =>
				policy(Object.freeze({ ...input, parameters: freezeSnapshot(parameters), signal })),
			{ ...options, signal: cancellation },
		);
		if (allowed === true) return undefined;
		if (allowed === false) return errorResponse(401, "invalid_client", "Endpoint access denied");
		safeLogger(options.logger)?.error(
			`Authorization policy returned a non-boolean result for ${input.endpoint}`,
		);
	} catch (error) {
		if (cancellation.aborted)
			return errorResponse(503, "temporarily_unavailable", "Endpoint authorization unavailable");
		if (error instanceof DOMException && error.name === "TimeoutError") {
			safeLogger(options.logger)?.warn(`Authorization policy timed out for ${input.endpoint}`);
			return errorResponse(503, "temporarily_unavailable", "Endpoint authorization unavailable");
		}
		safeLogger(options.logger)?.error(`Authorization policy failed for ${input.endpoint}`);
	}
	return errorResponse(500, "server_error", "Endpoint authorization failed");
}
