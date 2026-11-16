/** Pushed authorization requests with Request Object and client authentication handling. */

import {
	type AuthenticateClientAttestationOptions,
	authenticateClientAttestation,
	type ClientAttestationError,
	clientAttestationHeaders,
	createClientAssertion,
	createTrustChainOperation,
	DEFAULT_CLOCK_SKEW_SECONDS,
	DEFAULT_MAX_REQUEST_BODY_BYTES,
	type DiscoveryResult,
	decodeApplicationJwt,
	type EntityId,
	entityId,
	err,
	FederationErrorCode,
	type FederationOptions,
	isValidAlgorithm,
	JWT_BEARER_CLIENT_ASSERTION_TYPE,
	type JwtSigner,
	nowSeconds,
	ok,
	parseClientAttestationHeaders,
	type Result,
	readBodyWithLimit,
	runAsyncOperation,
	type TrustAnchorSet,
	type ValidatedTrustChain,
	verifyClientAssertion,
} from "@oidfed/core";
import { effectiveMetadata } from "../metadata.js";
import { checkRegistrationAccreditation } from "./accreditation.js";
import {
	type AutomaticRegistrationConfig,
	assertProtocolSignerPublished,
	automaticRegistration,
} from "./automatic.js";
import { resolveAndValidateBestChain, selectSharedRegistrationTrustChains } from "./helpers.js";
import {
	type ProcessAutomaticRegistrationOptions,
	type ProcessedAutomaticRegistration,
	processAutomaticRegistration,
	registrationClientFromChain,
} from "./process-automatic.js";
import { type RegistrationProfile, registrationProfile } from "./profile.js";
import {
	authorizationForm,
	authorizationParameters,
	requiresRequestObject,
} from "./request-policy.js";

const invalid = (description: string): Result<never> =>
	err({ code: FederationErrorCode.InvalidRequest, description });
export type PushedAuthorizationProof =
	| { readonly mode: "request_object" }
	| { readonly mode: "private_key_jwt" }
	| { readonly mode: "self_signed_tls_client_auth"; readonly certificate: string }
	| {
			readonly mode: "attest_jwt_client_auth";
			readonly attestationJwt: string;
			readonly popJwt: string;
	  };
/** Prepared POST. The host supplies the transport, including its TLS client certificate. */
export interface PreparedPushedAuthorizationRequest {
	readonly endpoint: string;
	/** Complete form body, including repeated resource parameters. */
	readonly parameters: URLSearchParams;
	readonly headers: Headers;
	readonly trustChain: ValidatedTrustChain;
	readonly requestObjectJwt?: string;
}
export interface ProcessPushedAuthorizationRequestOptions
	extends ProcessAutomaticRegistrationOptions {
	/** Effective server metadata; partial publication metadata is insufficient for method negotiation. */
	readonly providerMetadata: Readonly<Record<string, unknown>>;
	/** Trusted host TLS integration must return the certificate proven by the connection (base64 DER). */
	readonly clientCertificate?: (
		request: Request,
		signal: AbortSignal,
	) => string | undefined | Promise<string | undefined>;
	readonly clientAttestation?: Omit<AuthenticateClientAttestationOptions, "audience" | "clientId">;
}
export interface ProcessedPushedAuthorizationRequest extends ProcessedAutomaticRegistration {
	readonly parameters: Readonly<Record<string, unknown>>;
}
function mutual(
	method: string,
	client: Readonly<Record<string, unknown>>,
	server: Readonly<Record<string, unknown>>,
): boolean {
	const clientMethods = client.token_endpoint_auth_methods_supported ?? [
		client.token_endpoint_auth_method ?? "client_secret_basic",
	];
	const serverMethods = server.token_endpoint_auth_methods_supported ?? ["client_secret_basic"];
	return (
		Array.isArray(clientMethods) &&
		clientMethods.includes(method) &&
		Array.isArray(serverMethods) &&
		serverMethods.includes(method)
	);
}
function certificateMatches(
	certificate: string,
	keys: ProcessedAutomaticRegistration["protocolKeys"],
): boolean {
	return (
		!!certificate && keys.keys.some((key) => Array.isArray(key.x5c) && key.x5c[0] === certificate)
	);
}

/**
 * Create a signed client request and the selected proof for submission to a trusted provider's PAR
 * endpoint.
 */
export async function createPushedAuthorizationRequest(
	discovery: DiscoveryResult,
	config: AutomaticRegistrationConfig,
	parameters: Readonly<Record<string, unknown>>,
	anchors: TrustAnchorSet,
	proof: PushedAuthorizationProof,
	options: FederationOptions,
	profile: RegistrationProfile,
): Promise<Result<PreparedPushedAuthorizationRequest>> {
	try {
		const checkedParameters = authorizationParameters(parameters);
		if (!checkedParameters.ok) return checkedParameters;
		parameters = checkedParameters.value;
		const operation = createTrustChainOperation(options);
		if (!operation.ok) return operation;
		options = operation.value.options;
		const selected = await selectSharedRegistrationTrustChains(
			config.entityId,
			discovery.entityId as EntityId,
			discovery.trustChain,
			anchors,
			options,
			{ profile },
		);
		if (!selected.ok) return selected;
		const server = selected.value.opChain.resolvedMetadata[profile.providerType];
		const client = selected.value.rpChain.resolvedMetadata[profile.clientType];
		if (!server || !client) return invalid("Protocol metadata is required for PAR");
		const endpoint = server.pushed_authorization_request_endpoint;
		if (
			typeof endpoint !== "string" ||
			!(server.client_registration_types_supported as string[] | undefined)?.includes("automatic")
		)
			return invalid("The server must support PAR and Automatic Client Registration");
		for (const key of [
			"request",
			"request_uri",
			"client_assertion",
			"client_assertion_type",
			"client_secret",
			"registration",
		])
			if (Object.hasOwn(parameters, key))
				return invalid("Authorization parameters cannot replace authentication proofs");
		if (parameters.client_id !== undefined && parameters.client_id !== config.entityId)
			return invalid("client_id must match the client Entity Identifier");
		if (proof.mode !== "request_object" && !mutual(proof.mode, client, server))
			return invalid("PAR authentication must be mutually supported");
		if (
			proof.mode !== "request_object" &&
			proof.mode !== "attest_jwt_client_auth" &&
			requiresRequestObject(client, server)
		)
			return invalid("Effective client or server policy requires a signed Request Object");
		let form = authorizationForm({ ...parameters, client_id: config.entityId });
		let headers = new Headers({ "Content-Type": "application/x-www-form-urlencoded" });
		let requestObjectJwt: string | undefined;
		if (proof.mode === "request_object" || proof.mode === "attest_jwt_client_auth") {
			const signed = await automaticRegistration(
				discovery,
				{ ...config, requestDelivery: "form_post" },
				{ ...parameters },
				anchors,
				options,
				"supplied",
				profile,
				selected.value,
			);
			if (!signed.ok) return signed;
			requestObjectJwt = signed.value.requestObjectJwt;
			form = new URLSearchParams({ client_id: config.entityId, request: requestObjectJwt });
		}
		if (proof.mode === "private_key_jwt") {
			const signer: JwtSigner = await runAsyncOperation(
				() =>
					config.protocolKeyProvider.getClientAssertionSigner?.() ??
					config.protocolKeyProvider.getRequestObjectSigner(),
				options,
			);
			const published = assertProtocolSignerPublished(
				selected.value.rpChain.resolvedMetadata,
				signer,
				"client assertion",
				profile.clientType,
			);
			if (!published.ok) return published;
			const algorithms = server.token_endpoint_auth_signing_alg_values_supported;
			if (Array.isArray(algorithms) && !algorithms.includes(signer.alg))
				return invalid("Server does not support the client assertion algorithm");
			form.set("client_assertion_type", JWT_BEARER_CLIENT_ASSERTION_TYPE);
			form.set(
				"client_assertion",
				await createClientAssertion(config.entityId, discovery.entityId, signer, options),
			);
		} else if (proof.mode === "self_signed_tls_client_auth") {
			const resolved = await registrationClientFromChain(selected.value.rpChain, {
				...options,
				providerMetadataType: profile.providerType,
			});
			if (!resolved.ok) return resolved;
			if (!certificateMatches(proof.certificate, resolved.value.protocolKeys))
				return invalid("The TLS certificate must appear in the client's resolved protocol JWK Set");
		} else if (proof.mode === "attest_jwt_client_auth") {
			const pair = clientAttestationHeaders(proof.attestationJwt, proof.popJwt);
			if (!pair.ok) return pair;
			headers = pair.value;
			headers.set("Content-Type", "application/x-www-form-urlencoded");
			const attestation = decodeApplicationJwt(proof.attestationJwt, options),
				pop = decodeApplicationJwt(proof.popJwt, options);
			if (
				!attestation.ok ||
				!pop.ok ||
				attestation.value.payload.sub !== config.entityId ||
				pop.value.payload.iss !== config.entityId ||
				!(Array.isArray(pop.value.payload.aud)
					? pop.value.payload.aud.includes(discovery.entityId)
					: pop.value.payload.aud === discovery.entityId)
			)
				return invalid("Client Attestation must match the PAR client and server");
			if (
				server.challenge_endpoint !== undefined &&
				typeof pop.value.payload.challenge !== "string"
			)
				return invalid("Retrieve and include the server attestation challenge before PAR");
			for (const [field, algorithm] of [
				["client_attestation_signing_alg_values_supported", attestation.value.header.alg],
				["client_attestation_pop_signing_alg_values_supported", pop.value.header.alg],
			] as const)
				if (!(server[field] as string[] | undefined)?.includes(algorithm ?? ""))
					return invalid("The server does not support the attestation algorithms");
		} else if (proof.mode !== "request_object") return invalid("Unsupported PAR proof mode");
		if (
			selected.value.opChain.expiresAt <= nowSeconds(options.clock) ||
			selected.value.rpChain.expiresAt <= nowSeconds(options.clock) ||
			options.signal?.aborted
		)
			return invalid("PAR trust expired or was cancelled");
		return ok({
			endpoint,
			parameters: form,
			headers,
			trustChain: selected.value.opChain,
			...(requestObjectJwt ? { requestObjectJwt } : {}),
		});
	} catch {
		return invalid("Pushed Authorization Request preparation failed");
	}
}

/**
 * Validate a pushed request's federation evidence and supported proof; return protocol context for
 * the host engine.
 */
export async function processPushedAuthorizationRequest(
	request: Request,
	anchors: TrustAnchorSet,
	options: ProcessPushedAuthorizationRequestOptions,
): Promise<Result<ProcessedPushedAuthorizationRequest, ClientAttestationError>> {
	try {
		if (
			request.method !== "POST" ||
			request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() !==
				"application/x-www-form-urlencoded"
		)
			return invalid("PAR requires a form-encoded POST");
		const operation = createTrustChainOperation({
			...options,
			signal: options.signal ?? request.signal,
		});
		if (!operation.ok) return operation;
		options = { ...options, ...operation.value.options };
		const body = await runAsyncOperation(
			() => readBodyWithLimit(request, DEFAULT_MAX_REQUEST_BODY_BYTES),
			options,
		);
		if (!body.ok) return invalid("PAR request body exceeds the size limit");
		const form = new URLSearchParams(body.text);
		if (
			[...new Set(form.keys())].some(
				(key) => key !== "resource" && form.getAll(key).length !== 1,
			) ||
			form.has("request_uri") ||
			form.has("registration") ||
			form.has("client_secret") ||
			request.headers.has("authorization")
		)
			return invalid("Invalid or ambiguous PAR parameters or credentials");
		const id = entityId(form.get("client_id") ?? "");
		const profile = registrationProfile(options.providerMetadataType);
		const server = effectiveMetadata(
			profile.providerType,
			options.providerMetadata,
			options.opEntityId,
		);
		if (!server.ok) return server;
		if (
			!(server.value.client_registration_types_supported as string[] | undefined)?.includes(
				"automatic",
			)
		)
			return invalid("The server does not support Automatic Client Registration");
		const requestObject = form.get("request");
		let parameterInput: Readonly<Record<string, unknown>>;
		if (requestObject !== null) {
			const decoded = decodeApplicationJwt(requestObject, options);
			if (!decoded.ok) return decoded;
			if (
				[...form.keys()].some(
					(name) =>
						!["request", "client_id", "client_assertion", "client_assertion_type"].includes(name),
				)
			)
				return invalid("PAR authorization parameters MUST appear inside the Request Object");
			if (decoded.value.payload.client_id !== id)
				return invalid("PAR client_id must match the Request Object");
			parameterInput = decoded.value.payload;
		} else {
			parameterInput = Object.fromEntries(
				[...new Set(form.keys())]
					.filter((name) => !["client_assertion", "client_assertion_type"].includes(name))
					.map((name) => [
						name,
						name === "resource" && form.getAll(name).length > 1
							? form.getAll(name)
							: form.get(name),
					]),
			);
		}
		const checkedParameters = authorizationParameters(parameterInput);
		if (!checkedParameters.ok) return checkedParameters;
		const parameters = checkedParameters.value;
		const hasAssertion = form.has("client_assertion") || form.has("client_assertion_type");
		const hasAttestation =
			request.headers.has("OAuth-Client-Attestation") ||
			request.headers.has("OAuth-Client-Attestation-PoP");
		const certificate = options.clientCertificate
			? await runAsyncOperation((signal) => options.clientCertificate?.(request, signal), options)
			: undefined;
		const methods = [
			hasAssertion ? "private_key_jwt" : undefined,
			hasAttestation ? "attest_jwt_client_auth" : undefined,
			certificate ? "self_signed_tls_client_auth" : undefined,
		].filter((value): value is string => value !== undefined);
		if (
			methods.length > 1 ||
			(!requestObject && methods.length !== 1) ||
			(!requestObject && hasAttestation)
		)
			return invalid(
				"Federation PAR requires a Request Object or RP protocol-key possession proof",
			);
		const { replayStore: _registrationReplay, ...authenticationOptions } = options;
		let proofExpiresAt = Infinity;
		const verifyProof = async (
			client: ProcessedAutomaticRegistration,
		): Promise<Result<void, ClientAttestationError>> => {
			if (client.rpEntityId !== id || client.trustChain.expiresAt <= nowSeconds(options.clock))
				return invalid("PAR client identity or trust does not match");
			if (requestObject === null && requiresRequestObject(client.resolvedRpMetadata, server.value))
				return invalid("Effective client or server policy requires a signed Request Object");
			if (
				parameters.redirect_uri !== undefined &&
				(typeof parameters.redirect_uri !== "string" ||
					!(client.resolvedRpMetadata.redirect_uris as string[] | undefined)?.includes(
						parameters.redirect_uri,
					))
			)
				return invalid("redirect_uri must match registered client metadata");
			if (methods.some((method) => !mutual(method, client.resolvedRpMetadata, server.value)))
				return invalid("PAR authentication must be mutually supported");
			if (hasAssertion) {
				if (form.get("client_assertion_type") !== JWT_BEARER_CLIENT_ASSERTION_TYPE)
					return invalid("Invalid PAR client assertion type");
				const verified = await runAsyncOperation(
					() =>
						verifyClientAssertion(
							form.get("client_assertion") ?? "",
							{ keys: client.protocolKeys.keys },
							options.opEntityId,
							{
								...authenticationOptions,
								...(Array.isArray(server.value.token_endpoint_auth_signing_alg_values_supported)
									? {
											allowedAlgorithms: server.value
												.token_endpoint_auth_signing_alg_values_supported as string[],
										}
									: {}),
							},
						),
					options,
				);
				if (!verified.ok) return verified;
				if (verified.value.clientId !== id) return invalid("Client assertion must match client_id");
				proofExpiresAt =
					verified.value.expiresAt + (options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS);
				const claimed = await runAsyncOperation(
					() =>
						options.replayStore.useJti({
							issuer: id,
							audience: options.opEntityId,
							jti: verified.value.jti,
							expiresAt:
								verified.value.expiresAt + (options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS),
						}),
					options,
				);
				if (
					!claimed ||
					verified.value.expiresAt + (options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS) <=
						nowSeconds(options.clock)
				)
					return invalid("PAR assertion was replayed or expired");
			} else if (hasAttestation) {
				if (!options.clientAttestation)
					return invalid("Client Attestation verification is not configured");
				if (
					server.value.challenge_endpoint !== undefined &&
					options.clientAttestation.expectedChallenge === undefined &&
					options.clientAttestation.freshness?.mode !== "challenge"
				)
					return invalid(
						"The advertised challenge endpoint requires server challenge verification",
					);
				const pair = parseClientAttestationHeaders(request.headers, options);
				if (!pair.ok) return pair;
				const checked = await authenticateClientAttestation(
					pair.value.attestationJwt,
					pair.value.popJwt,
					{
						...authenticationOptions,
						...options.clientAttestation,
						...(options.signal ? { signal: options.signal } : {}),
						...(options.clock ? { clock: options.clock } : {}),
						audience: options.opEntityId,
						clientId: id,
						allowedAttestationAlgorithms: (
							server.value.client_attestation_signing_alg_values_supported as string[]
						).filter(
							(alg) =>
								isValidAlgorithm(alg) &&
								(!options.clientAttestation?.allowedAttestationAlgorithms ||
									options.clientAttestation.allowedAttestationAlgorithms.includes(alg)),
						),
						allowedProofAlgorithms: (
							server.value.client_attestation_pop_signing_alg_values_supported as string[]
						).filter(
							(alg) =>
								isValidAlgorithm(alg) &&
								(!options.clientAttestation?.allowedProofAlgorithms ||
									options.clientAttestation.allowedProofAlgorithms.includes(alg)),
						),
					},
				);
				if (!checked.ok) return checked;
				proofExpiresAt = checked.value.expiresAt;
			} else if (certificate && !certificateMatches(certificate, client.protocolKeys))
				return invalid("TLS certificate is not in the RP protocol JWK Set");
			return client.trustChain.expiresAt > nowSeconds(options.clock) && !options.signal?.aborted
				? ok(undefined)
				: invalid("PAR trust expired or was cancelled");
		};
		let client: Result<ProcessedAutomaticRegistration, ClientAttestationError>;
		if (requestObject !== null) {
			client = await processAutomaticRegistration(requestObject, anchors, options, verifyProof);
		} else {
			const chain = await resolveAndValidateBestChain(id, anchors, options, profile);
			if (!chain.ok) return chain;
			client = await registrationClientFromChain(chain.value, options);
			if (!client.ok) return client;
			const accreditation = await checkRegistrationAccreditation(
				chain.value,
				"automatic",
				options,
				options,
			);
			if (!accreditation.ok) return accreditation;
			const verified = await verifyProof(client.value);
			if (!verified.ok) return verified;
		}
		if (!client.ok) return client;
		if (
			client.value.trustChain.expiresAt <= nowSeconds(options.clock) ||
			proofExpiresAt <= nowSeconds(options.clock) ||
			options.signal?.aborted
		)
			return invalid("PAR verification expired or was cancelled");
		return ok({
			...client.value,
			authenticationExpiresAt: Math.min(client.value.authenticationExpiresAt, proofExpiresAt),
			parameters,
		});
	} catch {
		return invalid("Pushed Authorization Request verification failed");
	}
}
