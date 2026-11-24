import { federationJwsOptions } from "./crypto-context.js";
/** Federation endpoint requests with selector handling and configurable client authentication. */

import type { KeyringEntry } from "@oidfed/crypto";
import { runAsyncOperation } from "./async-operation.js";
import {
	FederationErrorCode,
	InternalErrorCode,
	JWT_BEARER_CLIENT_ASSERTION_TYPE,
} from "./constants.js";
import {
	endpointParameterValuesMatch,
	isReservedEndpointParameter,
	prepareEndpointParameters,
} from "./endpoint-parameters.js";
import { err, type Result } from "./errors.js";
import { type PerformFetchOptions, performFetch } from "./http/fetch.js";
import { validateFetchUrl } from "./http/fetch-url.js";
import { createClientAssertion } from "./jose/client-assertion.js";
import { type EntityId, entityId } from "./types.js";

export interface PrivateKeyJwtEndpointAuthentication {
	readonly method: "private_key_jwt";
	readonly clientId: string;
	/** Entity Identifier of the responder, which may differ from the endpoint origin (§8.8). */
	readonly audience: string;
	readonly signer: KeyringEntry;
}
export interface CustomEndpointClientAuthentication {
	readonly method: string;
	/** Responder Entity Identifier for credential audience binding; do not infer it from the URL origin. */
	readonly audience: string;
	readonly prepare: (
		input: Readonly<{ endpoint: string; audience: string; signal: AbortSignal }>,
	) =>
		| {
				readonly parameters?: Readonly<Record<string, string>>;
				readonly headers?: Readonly<Record<string, string>>;
		  }
		| Promise<{
				readonly parameters?: Readonly<Record<string, string>>;
				readonly headers?: Readonly<Record<string, string>>;
		  }>;
}
export type EndpointClientAuthentication =
	| PrivateKeyJwtEndpointAuthentication
	| CustomEndpointClientAuthentication;
/** Request context from traversal; standalone clients may not know the responder identity. */
export interface EndpointAuthenticationContext {
	readonly endpoint: string;
	/** Entity Identifier from the calling operation, never inferred from the endpoint origin. */
	readonly responder?: EntityId;
	readonly signal?: AbortSignal;
}
/** Return undefined to request anonymous access. Failure never falls back to anonymous access. */
export type EndpointAuthenticationProvider = (
	context: Readonly<EndpointAuthenticationContext>,
) => EndpointClientAuthentication | undefined | Promise<EndpointClientAuthentication | undefined>;

export type { EndpointAdditionalParameters } from "./endpoint-parameters.js";

const credentials = new Set([
	"client_id",
	"client_assertion",
	"client_assertion_type",
	"client_secret",
]);

/** Compose authenticated POST or anonymous requests without rewriting fixed selectors. */
export async function fetchFederationEndpoint(
	endpoint: string,
	selectors: URLSearchParams,
	options: PerformFetchOptions & { readonly clientAssertion?: string },
	expectedAudience?: string,
	unorderedParameters: readonly string[] = [],
	operationParameterNames: readonly string[] = [],
): Promise<Result<string>> {
	try {
		const url = new URL(endpoint);
		if (url.protocol !== "https:")
			return err({
				code: FederationErrorCode.InvalidRequest,
				description: "Endpoint URL must use https",
			});
		if (url.href.includes("#") || url.username || url.password)
			throw new Error("Invalid endpoint URL");
		const form = prepareEndpointParameters(selectors, options.additionalParameters);
		const fixedAdditional = Object.keys(options.additionalParameters ?? {}).filter((name) =>
			url.searchParams.has(name),
		);
		if ([...credentials].some((name) => url.searchParams.has(name) || form.has(name)))
			throw new Error("Endpoint selectors cannot contain credentials");
		if (options.authentication !== undefined && options.getEndpointAuthentication !== undefined)
			throw new Error("Static and selected authentication cannot be combined");
		if (
			(options.authentication !== undefined || options.getEndpointAuthentication !== undefined) &&
			options.clientAssertion !== undefined
		)
			throw new Error("Authentication and clientAssertion cannot be combined");
		for (const name of new Set([...form.keys(), ...fixedAdditional])) {
			if (!url.searchParams.has(name)) continue;
			const fixed = url.searchParams.getAll(name),
				supplied = form.getAll(name);
			if (!endpointParameterValuesMatch(name, fixed, supplied, unorderedParameters))
				throw new Error("Parameters conflict with endpoint fixed query");
			// Echo fixed values in their advertised order, even for set-like selectors.
			form.delete(name);
			for (const value of fixed) form.append(name, value);
		}
		if (options.signal?.aborted) throw new DOMException("Operation aborted", "AbortError");
		let auth = options.authentication;
		if (options.getEndpointAuthentication !== undefined) {
			if (typeof options.getEndpointAuthentication !== "function")
				throw new Error("Invalid authentication provider");
			if (options.offline) throw new Error("Offline operation cannot access the network");
			const permitted = validateFetchUrl(url.href, options);
			if (!permitted.ok) return permitted;
			const provider = options.getEndpointAuthentication;
			auth = await runAsyncOperation(
				(signal) =>
					provider(
						Object.freeze({
							endpoint: url.href,
							...(expectedAudience !== undefined ? { responder: entityId(expectedAudience) } : {}),
							signal: options.signal ?? signal,
						}),
					),
				options,
			);
			if (auth !== undefined && (!auth || typeof auth !== "object" || Array.isArray(auth)))
				throw new Error("Invalid authentication selection");
			if (options.signal?.aborted) throw new DOMException("Operation aborted", "AbortError");
		}
		const method =
			auth || options.clientAssertion !== undefined ? "POST" : (options.method ?? "GET");
		if (method !== "POST" && fixedAdditional.length)
			throw new Error("Additional parameters cannot replace fixed query parameters");
		if (method === "POST")
			for (const name of operationParameterNames)
				if (!form.has(name))
					for (const fixedValue of url.searchParams.getAll(name)) form.append(name, fixedValue);
		const headers = new Headers(options.headers);
		if (auth) {
			const audience = entityId(auth.audience);
			if (expectedAudience !== undefined && audience !== expectedAudience)
				return err({
					code: FederationErrorCode.InvalidRequest,
					description: "Authentication audience must match the responder Entity Identifier",
				});
			if (auth.method === "private_key_jwt" && "signer" in auth) {
				const assertion = await createClientAssertion(
					entityId(auth.clientId),
					audience,
					auth.signer,
					federationJwsOptions(options),
				);
				form.set("client_assertion_type", JWT_BEARER_CLIENT_ASSERTION_TYPE);
				form.set("client_assertion", assertion);
			} else if (
				"prepare" in auth &&
				typeof auth.prepare === "function" &&
				auth.method !== "none" &&
				auth.method !== "private_key_jwt"
			) {
				const prepared = await runAsyncOperation(
					(signal) => auth.prepare(Object.freeze({ endpoint: url.href, audience, signal })),
					options,
				);
				if (!prepared || typeof prepared !== "object")
					throw new Error("Invalid authentication output");
				for (const [name, value] of Object.entries(prepared.parameters ?? {})) {
					if (
						form.has(name) ||
						url.searchParams.has(name) ||
						(isReservedEndpointParameter(name) && !credentials.has(name)) ||
						typeof value !== "string"
					)
						throw new Error("Authentication cannot override request selectors");
					form.set(name, value);
				}
				for (const [name, value] of Object.entries(prepared.headers ?? {})) {
					if (
						["content-type", "content-length", "host", "accept"].includes(name.toLowerCase()) ||
						typeof value !== "string"
					)
						throw new Error("Invalid authentication header");
					headers.set(name, value);
				}
			} else throw new Error("Unsupported client authentication");
		}
		if (options.clientAssertion !== undefined) {
			if (typeof options.clientAssertion !== "string" || !options.clientAssertion)
				throw new Error("Invalid client assertion");

			form.set("client_assertion_type", JWT_BEARER_CLIENT_ASSERTION_TYPE);
			form.set("client_assertion", options.clientAssertion);
		}
		if (method === "GET")
			for (const name of new Set(form.keys()))
				if (!url.searchParams.has(name))
					for (const value of form.getAll(name)) url.searchParams.append(name, value);
		return performFetch(url.href, {
			...options,
			method,
			...(method === "POST" ? { body: form } : {}),
			headers,
			// Edge runtimes may reject "error". Manual mode keeps credentials at this
			// endpoint; performFetch rejects every non-success status, including 3xx.
			redirect: "manual",
		});
	} catch (cause) {
		if (options.signal?.aborted || (cause instanceof DOMException && cause.name === "TimeoutError"))
			return err({
				code: InternalErrorCode.Timeout,
				description: "Federation endpoint authentication timed out or was cancelled",
			});
		return err({
			code: FederationErrorCode.InvalidRequest,
			description: "Invalid federation endpoint request or authentication configuration",
		});
	}
}
