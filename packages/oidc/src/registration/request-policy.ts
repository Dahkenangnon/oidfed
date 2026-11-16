/** Authorization parameter parsing and effective Request Object requirements. */

import {
	err,
	FederationErrorCode,
	isJsonData,
	ok,
	type Result,
	SUPPORTED_ALGORITHMS,
} from "@oidfed/core";

const invalid = (description: string): Result<never> =>
	err({ code: FederationErrorCode.InvalidRequest, description });

/** Validate and detach JSON authorization parameters before signing or returning them. */
export function authorizationParameters(
	input: Readonly<Record<string, unknown>>,
): Result<Record<string, unknown>> {
	try {
		if (!input || typeof input !== "object" || Array.isArray(input) || !isJsonData(input))
			return invalid("Authorization parameters must be JSON data");
		if (Object.hasOwn(input, "request") || Object.hasOwn(input, "request_uri"))
			return invalid("Request Objects MUST NOT contain request or request_uri");
		if (Object.hasOwn(input, "resource")) {
			const resources = Array.isArray(input.resource) ? input.resource : [input.resource];
			if (
				!resources.length ||
				resources.some((value) => {
					// biome-ignore lint/suspicious/noControlCharactersInRegex: Reject URI characters that URL parsing would silently normalize.
					if (typeof value !== "string" || /[\u0000-\u0020\u007f\\#]/u.test(value)) return true;
					try {
						new URL(value);
						return false;
					} catch {
						return true;
					}
				})
			)
				return invalid("resource must contain absolute URIs without fragments");
		}
		return ok(structuredClone(input));
	} catch {
		return invalid("Invalid authorization parameters");
	}
}

/** RFC 9126 uses form encoding; RFC 8707 permits repeated resource values. */
export function authorizationForm(parameters: Readonly<Record<string, unknown>>): URLSearchParams {
	const form = new URLSearchParams();
	for (const [name, value] of Object.entries(parameters)) {
		if (name === "resource" && Array.isArray(value))
			for (const resource of value) form.append(name, resource as string);
		else form.set(name, typeof value === "string" ? value : JSON.stringify(value));
	}
	return form;
}

export function requiresRequestObject(
	client: Readonly<Record<string, unknown>>,
	server: Readonly<Record<string, unknown>>,
): boolean {
	return (
		client.require_signed_request_object === true || server.require_signed_request_object === true
	);
}

/** Missing optional declarations add no restriction to the supported signing algorithms. */
export function requestObjectAlgorithms(
	client: Readonly<Record<string, unknown>>,
	server: Readonly<Record<string, unknown>>,
): Result<readonly string[]> {
	const declared = server.request_object_signing_alg_values_supported;
	const selected = client.request_object_signing_alg;
	const clientSupported = client.request_object_signing_alg_values_supported;
	const lists = [declared, clientSupported];
	if (
		lists.some(
			(list) =>
				list !== undefined && (!Array.isArray(list) || !list.every((v) => typeof v === "string")),
		) ||
		(selected !== undefined && typeof selected !== "string")
	)
		return invalid("Invalid Request Object signing algorithm metadata");
	const algorithms = SUPPORTED_ALGORITHMS.filter(
		(alg) =>
			lists.every((list) => list === undefined || (list as string[]).includes(alg)) &&
			(selected === undefined || selected === alg),
	);
	return algorithms.length
		? ok(algorithms)
		: invalid("No mutually supported Request Object signing algorithm");
}
