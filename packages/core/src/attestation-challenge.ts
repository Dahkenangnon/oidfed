/** HTTP challenge retrieval and response handling for client attestation authentication. */

import { runAsyncOperation } from "./async-operation.js";
import { FederationErrorCode } from "./constants.js";
import { err, ok, type Result } from "./errors.js";
import { errorResponse, jsonResponse, requireMethods } from "./http.js";
import { performFetch } from "./trust-chain/fetch.js";
import type { FederationOptions } from "./types.js";

const invalid = () =>
	err({ code: FederationErrorCode.InvalidRequest, description: "Invalid attestation challenge" });
function valid(value: unknown): value is string {
	return typeof value === "string" && value.length > 0 && !/[\r\n]/.test(value);
}
/** Fetch a challenge without caching it or automatically retrying the protected request. */
export async function fetchAttestationChallenge(
	endpoint: string,
	options: FederationOptions,
): Promise<Result<string>> {
	const response = await performFetch(endpoint, {
		...options,
		method: "POST",
		accept: "application/json",
		expectedStatus: 200,
		contentTypePolicy: "media-type",
		redirect: "manual",
	});
	if (!response.ok) return response;
	try {
		const body: unknown = JSON.parse(response.value);
		return body &&
			typeof body === "object" &&
			Object.hasOwn(body, "attestation_challenge") &&
			valid((body as Record<string, unknown>).attestation_challenge)
			? ok((body as { attestation_challenge: string }).attestation_challenge)
			: invalid();
	} catch {
		return invalid();
	}
}
/** A returned challenge replaces the previous challenge for the next request (draft-07 §8.1). */
export function readAttestationChallenge(headers: Headers): Result<string | undefined> {
	const value = headers.get("OAuth-Client-Attestation-Challenge");
	return value === null ? ok(undefined) : valid(value) ? ok(value) : invalid();
}
/** Create a non-cacheable JSON challenge response; malformed challenge values throw. */
export function createAttestationChallengeResponse(challenge: string): Response {
	if (!valid(challenge)) throw new TypeError("Invalid attestation challenge");
	const response = jsonResponse({ attestation_challenge: challenge });
	response.headers.set("Cache-Control", "no-store");
	return response;
}
/** Host owns challenge generation, validity and optional atomic consumption. */
export function createAttestationChallengeHandler(
	issue: (request: Request, signal: AbortSignal) => string | Promise<string>,
	options: FederationOptions,
): (request: Request) => Promise<Response> {
	return async (request) => {
		const method = requireMethods(request, ["POST"]);
		if (method) return method;
		try {
			return createAttestationChallengeResponse(
				await runAsyncOperation((signal) => issue(request, signal), {
					...options,
					signal: options.signal ?? request.signal,
				}),
			);
		} catch {
			return errorResponse(500, "server_error", "Challenge issuance failed");
		}
	};
}
