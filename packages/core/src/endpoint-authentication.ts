/** Federation endpoint authentication, trusted caller context, and method enforcement. */

import { runAsyncOperation } from "./async-operation.js";
import { callSynchronous, freezeSnapshot } from "./callbacks.js";
import {
	DEFAULT_MAX_REQUEST_BODY_BYTES,
	FederationErrorCode,
	JWT_BEARER_CLIENT_ASSERTION_TYPE,
} from "./constants.js";
import { federationAlgorithms, registryFor } from "./crypto-context.js";
import { cloneData } from "./data-copy.js";
import {
	authorizeFederationEndpoint,
	type FederationEndpointOperation,
} from "./endpoint-authorization.js";
import { validateEndpointPostParameters } from "./endpoint-parameters.js";
import { err, type FederationError, ok, type Result } from "./errors.js";
import { errorResponse, readBodyWithLimit, requireMethods } from "./http.js";
import { verifyClientAssertion } from "./jose/client-auth.js";
import { decodeEntityStatement } from "./jose/verify.js";
import type { JWKSet } from "./schemas/jwk.js";
import { requireReplayStorage } from "./storage/capabilities.js";
import type { FederationStorage } from "./storage/contracts.js";
import { type EntityId, entityId, type FederationOptions } from "./types.js";

/** Controlled protocol response from a host authentication verifier. */
export interface EndpointAuthenticationError extends FederationError {
	readonly authenticationResponse?: {
		readonly error:
			| "invalid_client"
			| "invalid_client_attestation"
			| "use_attestation_challenge"
			| "use_fresh_attestation";
		readonly status?: 400 | 401;
		readonly headers?: Readonly<Record<string, string>>;
	};
}

/** Render only approved authentication headers; arbitrary host errors remain private. */
export function endpointAuthenticationErrorResponse(error: EndpointAuthenticationError): Response {
	try {
		const protocol = error.authenticationResponse;
		if (!protocol)
			return errorResponse(
				error.code === "server_error" ? 500 : 401,
				error.code,
				error.description,
			);
		if (
			![
				"invalid_client",
				"invalid_client_attestation",
				"use_attestation_challenge",
				"use_fresh_attestation",
			].includes(protocol.error) ||
			(protocol.status !== undefined && protocol.status !== 400 && protocol.status !== 401)
		)
			throw new Error();
		const headers = new Headers();
		for (const [name, value] of Object.entries(protocol.headers ?? {})) {
			if (
				!["oauth-client-attestation-challenge", "www-authenticate"].includes(name.toLowerCase()) ||
				typeof value !== "string"
			)
				throw new Error();
			headers.set(name, value);
		}
		if (
			protocol.error === "use_attestation_challenge" &&
			!headers.get("OAuth-Client-Attestation-Challenge")
		)
			throw new Error();
		const response = errorResponse(
			protocol.status ?? (protocol.error === "invalid_client" ? 401 : 400),
			protocol.error,
			"Client authentication failed",
		);
		for (const [name, value] of headers) response.headers.set(name, value);
		response.headers.set("Cache-Control", "no-store");
		return response;
	} catch {
		return errorResponse(401, "invalid_client", "Client authentication failed");
	}
}

export interface EndpointAuthenticationMethod {
	readonly parameters?: readonly string[];
	readonly headers?: readonly string[];
	readonly detect?: (input: EndpointAuthenticationInput) => boolean;
	readonly authenticate: (
		input: EndpointAuthenticationInput,
	) =>
		| Result<{ entityId: string }, EndpointAuthenticationError>
		| Promise<Result<{ entityId: string }, EndpointAuthenticationError>>;
}
export interface EndpointAuthenticationInput {
	readonly signal?: AbortSignal;
	readonly receiverEntityId: string;
	readonly parameters: Readonly<Record<string, readonly string[]>>;
	readonly headers: Readonly<Record<string, string>>;
	/** Supplied by the host transport integration, never inferred from identity headers. */
	readonly transport?: unknown;
}
export interface EndpointAuthentication {
	readonly methods?: Readonly<Record<string, EndpointAuthenticationMethod>>;
	/** May return evidence synchronously or asynchronously; failures reject authentication. */
	readonly transportEvidence?: (request: Request) => unknown | Promise<unknown>;
}
export interface EndpointAuthenticationConfig {
	readonly receiverEntityId: string;
	readonly methods: readonly string[];
	readonly getClientFederationJwks?: (client: EntityId) => Promise<JWKSet | undefined>;
	readonly allowedAlgorithms?: readonly string[];
	/** Algorithms the host advertises for this endpoint in Federation metadata. */
	readonly advertisedAlgorithms?: readonly string[];
	readonly extensions?: EndpointAuthentication;
	/** Operation parameters that require a matching form value when present in a POST URL. */
	readonly operationParameterNames?: readonly string[];
}
const identities = new WeakMap<Request, string>();
/** Read the authenticated caller identifier associated with this exact Request object. */
export function authenticatedEndpointCaller(request: Request): string | undefined {
	return identities.get(request);
}
const invalid = (description: string) =>
	err({ code: FederationErrorCode.InvalidClient, description });

/** Keep the algorithms advertised for private_key_jwt consistent with what can be verified. */
function clientAssertionAlgorithms(
	config: EndpointAuthenticationConfig,
	options: FederationOptions,
	endpointName = "Federation endpoint",
): readonly string[] {
	const registry = registryFor(options);
	const supported = federationAlgorithms(options, "client-assertion").filter(
		(algorithm) =>
			registry.algorithm(algorithm) !== undefined &&
			options.engine.algorithms.includes(algorithm) &&
			(config.allowedAlgorithms?.includes(algorithm) ?? true),
	);
	const advertised: unknown = config.advertisedAlgorithms;
	if (
		advertised !== undefined &&
		(!Array.isArray(advertised) ||
			!(advertised as readonly unknown[]).every(
				(algorithm) => typeof algorithm === "string" && supported.includes(algorithm),
			))
	)
		throw new TypeError(`${endpointName} advertises unsupported private_key_jwt algorithms`);
	const allowed = config.advertisedAlgorithms ?? supported;
	if (allowed.length === 0)
		throw new TypeError(`${endpointName} has no usable private_key_jwt algorithm`);
	return allowed;
}

/** Validate and capture endpoint authentication configuration. Invalid configuration throws. */
export function validateEndpointAuthentication(
	config: EndpointAuthenticationConfig,
	storage?: FederationStorage,
	options?: FederationOptions,
	endpointName?: string,
): EndpointAuthenticationConfig {
	if (!config.methods.length) throw new TypeError("Endpoint auth methods must not be empty");
	const declaredNames: unknown = config.operationParameterNames;
	if (
		declaredNames !== undefined &&
		(!Array.isArray(declaredNames) ||
			[...(declaredNames as readonly unknown[])].some((name) => typeof name !== "string" || !name))
	)
		throw new TypeError("Invalid endpoint operation parameter names");
	const operationParameterNames = config.operationParameterNames;
	const entries = Object.entries(config.extensions?.methods ?? {}).map(([name, definition]) => {
		if (
			name === "none" ||
			name === "private_key_jwt" ||
			!name ||
			!definition ||
			typeof definition.authenticate !== "function" ||
			(definition.detect !== undefined && typeof definition.detect !== "function")
		)
			throw new TypeError("Invalid endpoint authentication method registration");
		for (const values of [definition.parameters, definition.headers])
			if (
				values &&
				(!Array.isArray(values) || values.some((value) => typeof value !== "string" || !value))
			)
				throw new TypeError("Invalid credential names");
		if (
			definition.parameters?.some((name) =>
				["trust_mark", "trust_mark_type", "sub", "trust_anchor", "entity_type", "iss"].includes(
					name,
				),
			)
		)
			throw new TypeError("Authentication credentials cannot replace protocol selectors");
		return [
			name,
			Object.freeze({
				...definition,
				parameters: [...(definition.parameters ?? [])],
				headers: [...(definition.headers ?? [])],
			}),
		] as const;
	});
	for (const [, definition] of entries) {
		if (
			definition.parameters.some(
				(name) => name === "client_assertion" || name === "client_assertion_type",
			) &&
			!definition.detect
		)
			throw new TypeError("Shared assertion credentials require an explicit detector");
	}
	const methods = Object.fromEntries(entries);
	const credentialNames = endpointCredentialParameterNames({ methods });
	if (operationParameterNames?.some((name) => credentialNames.has(name)))
		throw new TypeError("Endpoint operation parameters cannot be credentials");
	for (const name of config.methods)
		if (name !== "none" && name !== "private_key_jwt" && !Object.hasOwn(methods, name))
			throw new TypeError(`Unsupported endpoint auth method: '${name}'`);
	if (config.methods.includes("private_key_jwt")) {
		requireReplayStorage(storage, "private_key_jwt");
		if (!config.getClientFederationJwks)
			throw new TypeError("private_key_jwt requires client keys");
		if (options) clientAssertionAlgorithms(config, options, endpointName);
	}
	return {
		...config,
		methods: [...config.methods],
		...(config.allowedAlgorithms ? { allowedAlgorithms: [...config.allowedAlgorithms] } : {}),
		...(config.advertisedAlgorithms
			? { advertisedAlgorithms: [...config.advertisedAlgorithms] }
			: {}),
		extensions: { ...config.extensions, methods },
		...(operationParameterNames ? { operationParameterNames: [...operationParameterNames] } : {}),
	};
}

/** Shared credential verification for Authority, Leaf, and Collection endpoints. */
export async function authenticateEndpointRequest(
	request: Request,
	form: URLSearchParams,
	config: EndpointAuthenticationConfig,
	options: FederationOptions,
): Promise<Result<string | undefined, EndpointAuthenticationError>> {
	try {
		const registry = new Map(Object.entries(config.extensions?.methods ?? {}));
		const input: EndpointAuthenticationInput = freezeSnapshot({
			receiverEntityId: config.receiverEntityId,
			parameters: Object.fromEntries(
				[...new Set(form.keys())].map((name) => [name, form.getAll(name)]),
			),
			headers: Object.fromEntries(request.headers.entries()),
			...(config.extensions?.transportEvidence
				? {
						transport: cloneData(
							await runAsyncOperation(() => config.extensions?.transportEvidence?.(request), {
								...options,
								signal: options?.signal ?? request.signal,
							}),
						),
					}
				: {}),
		});
		const assertion = form.has("client_assertion") || form.has("client_assertion_type");
		const selected: string[] = [];
		let credentialsPresent =
			assertion || request.headers.has("authorization") || form.has("client_secret");
		for (const [name, plugin] of registry) {
			const detected = plugin.detect
				? callSynchronous(
						() => plugin.detect?.(input),
						(value): value is boolean => typeof value === "boolean",
					)
				: { ok: true as const, value: false };
			if (!detected.ok) return invalid("Authentication detection failed");
			const present =
				plugin.parameters?.some((name) => form.has(name)) ||
				plugin.headers?.some((name) => request.headers.has(name));
			credentialsPresent ||= present === true || detected.value;
			if (plugin.detect ? detected.value : present) selected.push(name);
		}
		// An explicit extension detector can own the assertion carrier; otherwise it is private_key_jwt.
		if (
			assertion &&
			!selected.some((name) => registry.get(name)?.parameters?.includes("client_assertion"))
		)
			selected.push("private_key_jwt");

		// Unclaimed Authorization is still supplied credentials, never anonymous access.
		if (
			request.headers.has("authorization") &&
			![...registry.values()].some((plugin) =>
				plugin.headers?.some((name) => name.toLowerCase() === "authorization"),
			)
		)
			return invalid("Unsupported authentication credentials");
		if (!selected.length)
			return !credentialsPresent && config.methods.includes("none")
				? ok(undefined)
				: invalid("Client authentication is required");
		const selectedMethod = selected[0];
		if (
			selectedMethod === undefined ||
			selected.length !== 1 ||
			request.method !== "POST" ||
			!config.methods.includes(selectedMethod)
		)
			return invalid("Ambiguous or unsupported client authentication");
		let identity: string;
		if (selectedMethod === "private_key_jwt") {
			if (
				form.getAll("client_assertion").length !== 1 ||
				form.getAll("client_assertion_type").length !== 1 ||
				form.get("client_assertion_type") !== JWT_BEARER_CLIENT_ASSERTION_TYPE
			)
				return invalid("Invalid client_assertion_type or duplicate client assertion parameters");
			const jwt = form.get("client_assertion") ?? "",
				decoded = decodeEntityStatement(jwt, options);
			if (!decoded.ok) return invalid("Invalid client assertion");
			const issuer = entityId(decoded.value.payload.iss);
			if (
				form.getAll("client_id").length > 1 ||
				(form.has("client_id") && form.get("client_id") !== issuer)
			)
				return invalid("client_id must match the client assertion issuer");
			if (!config.getClientFederationJwks || !options.storage?.capabilities.includes("replay"))
				return invalid("Client authentication is not configured");
			let allowedAlgorithms: readonly string[];
			try {
				allowedAlgorithms = clientAssertionAlgorithms(config, options);
			} catch {
				return err({
					code: FederationErrorCode.ServerError,
					description: "Federation client assertion algorithm policy could not be applied",
				});
			}
			const algorithm = decoded.value.header.alg;
			if (typeof algorithm !== "string" || !allowedAlgorithms.includes(algorithm))
				return invalid("Client assertion algorithm is not allowed or supported");
			const getKeys = config.getClientFederationJwks;
			let keys: JWKSet | undefined;
			try {
				keys = await runAsyncOperation(() => getKeys(issuer), {
					...options,
					signal: options?.signal ?? request.signal,
				});
			} catch {
				return err({
					code: FederationErrorCode.ServerError,
					description: "Client key lookup failed",
				});
			}
			if (!keys) return invalid("No federation keys found for client");
			const checked = await verifyClientAssertion(jwt, keys, config.receiverEntityId, {
				...options,
				allowedAlgorithms,
			});
			if (!checked.ok)
				return [
					FederationErrorCode.ServerError,
					"ERR_CRYPTO_OPERATION_FAILED",
					"ERR_INVALID_CLOCK",
				].includes(checked.error.code)
					? err({
							code: FederationErrorCode.ServerError,
							description: "Client assertion verification could not be completed",
							cause: checked.error,
						})
					: invalid(checked.error.description);
			identity = issuer;
		} else {
			const plugin = registry.get(selectedMethod);
			if (!plugin) return invalid("Unsupported authentication method");
			const result = await runAsyncOperation(
				(signal) => plugin.authenticate(Object.freeze({ ...input, signal })),
				{ ...options, signal: options?.signal ?? request.signal },
			);
			if (result?.ok === false && result.error?.authenticationResponse) return err(result.error);
			if (result?.ok !== true || !result.value) return invalid("Client authentication failed");
			identity = entityId(result.value.entityId);
		}
		if ((options?.signal ?? request.signal).aborted)
			return invalid("Client authentication was cancelled");
		for (const name of endpointCredentialParameterNames(config.extensions)) form.delete(name);
		return ok(identity);
	} catch {
		return invalid("Client authentication failed");
	}
}

/** Credentials declared by authentication methods belong in the POST form, never the URL. */
export function endpointCredentialParameterNames(
	extensions?: EndpointAuthentication,
): ReadonlySet<string> {
	return new Set([
		"client_id",
		"client_secret",
		"client_assertion",
		"client_assertion_type",
		...Object.values(extensions?.methods ?? {}).flatMap((method) => method.parameters ?? []),
	]);
}

/**
 * Check request methods, credential placement, and client authentication before running the
 * handler.
 * Associate the verified caller identity with the Request for downstream checks.
 */
export function createEndpointAuthenticatedHandler(
	config: EndpointAuthenticationConfig,
	inner: (request: Request) => Promise<Response>,
	options: FederationOptions,
	nativeMethod: "GET" | "POST" = "GET",
	unorderedParameters: readonly string[] = [],
	route?: {
		readonly fixedQuery?: URLSearchParams;
		readonly operationParameterNames?: readonly string[];
		readonly endpointName?: string;
		readonly endpoint?: FederationEndpointOperation;
	},
): (request: Request) => Promise<Response> {
	const captured = validateEndpointAuthentication(
		config,
		options.storage,
		options,
		route?.endpointName,
	);
	const allowsNone = captured.methods.includes("none");
	const credentialNames = endpointCredentialParameterNames(captured.extensions);
	const unordered = [...unorderedParameters].filter((name) => !credentialNames.has(name));
	const operationNames = new Set([
		...unordered,
		...(captured.operationParameterNames ?? []),
		...(route?.operationParameterNames ?? []),
	]);
	if ([...operationNames].some((name) => credentialNames.has(name)))
		throw new TypeError("Endpoint operation parameters cannot be credentials");
	const routingNames = new Set(route?.fixedQuery?.keys());
	return async (request) => {
		const methods = captured.methods.every((method) => method === "none")
			? [nativeMethod]
			: allowsNone && nativeMethod === "GET"
				? ["GET", "POST"]
				: ["POST"];
		const method = requireMethods(request, methods);
		if (method) return method;
		try {
			const url = new URL(request.url);
			const query = url.searchParams;
			if ([...credentialNames].some((name) => query.has(name)))
				return errorResponse(401, "invalid_client", "Credentials require the POST form");
			let form: URLSearchParams;
			if (request.method === "POST") {
				if (
					request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() !==
					"application/x-www-form-urlencoded"
				)
					return errorResponse(
						400,
						"invalid_request",
						"POST requires application/x-www-form-urlencoded",
					);
				const body = await readBodyWithLimit(request, DEFAULT_MAX_REQUEST_BODY_BYTES);
				if (!body.ok) return errorResponse(413, "invalid_request", "Request body too large");
				form = new URLSearchParams(body.text);
				const error = validateEndpointPostParameters(
					query,
					form,
					unordered,
					operationNames,
					routingNames,
				);
				if (error) return errorResponse(400, "invalid_request", error);
			} else form = new URLSearchParams(query);
			const checked = await authenticateEndpointRequest(request, form, captured, options);
			if (!checked.ok) return endpointAuthenticationErrorResponse(checked.error);
			if (request.method === "POST" && nativeMethod === "GET" && checked.value === undefined)
				return errorResponse(401, "invalid_client", "Authenticated POST required");
			if (checked.value === undefined) for (const name of credentialNames) form.delete(name);
			const authorizationParameters = routingNames.size ? new URLSearchParams(form) : form;
			for (const name of routingNames)
				if (!operationNames.has(name)) authorizationParameters.delete(name);
			const denied = await authorizeFederationEndpoint(
				options,
				{
					endpoint: route?.endpoint ?? "custom",
					receiverEntityId: captured.receiverEntityId,
					caller: checked.value,
				},
				authorizationParameters,
				request.signal,
			);
			if (denied) return denied;
			const headers = new Headers(request.headers);
			headers.delete("X-Authenticated-Entity");
			headers.delete("Content-Length");
			headers.delete("Authorization");
			for (const plugin of Object.values(captured.extensions?.methods ?? {}))
				for (const name of plugin.headers ?? []) headers.delete(name);
			let forwarded: Request;
			if (nativeMethod === "GET") {
				url.search = form.toString();
				headers.delete("Content-Type");
				forwarded = new Request(url, { method: "GET", headers, signal: request.signal });
			} else {
				url.search = "";
				headers.set("Content-Type", "application/x-www-form-urlencoded");
				forwarded = new Request(url, {
					method: "POST",
					headers,
					body: form,
					signal: request.signal,
				});
			}
			if (checked.value !== undefined) identities.set(forwarded, checked.value);
			return inner(forwarded);
		} catch {
			return errorResponse(500, "server_error", "Endpoint authentication failed");
		}
	};
}
