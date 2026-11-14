/** RP-side automatic registration: builds a signed Request Object with embedded trust chain. */
import {
	DEFAULT_REQUEST_OBJECT_TTL_SECONDS,
	type DiscoveryResult,
	type EntityId,
	err,
	FederationErrorCode,
	type FederationOptions,
	federationError,
	InternalErrorCode,
	type JwtSigner,
	nowSeconds,
	ok,
	type Result,
	resolveTrustChainForAnchor,
	safeLogger,
	signEntityStatement,
	type TrustAnchorSet,
	type ValidatedTrustChain,
} from "@oidfed/core";
import { createClientAssertion } from "../client-auth/assertion.js";
import { ClientRegistrationType, RequestObjectTyp } from "../constants.js";
import type { ProtocolSigningKeyProvider } from "../protocol-keys.js";
import { getRegistrationTypes, selectSharedRegistrationTrustChains } from "./helpers.js";
import { oidcRegistrationProfile, type RegistrationProfile } from "./profile.js";

const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

export type RequestDelivery = "query" | "form_post" | "request_uri" | "par";

/** Reserved claims that authzRequestParams MUST NOT overwrite. */
const RESERVED_REQUEST_OBJECT_CLAIMS = new Set([
	"iss",
	"client_id",
	"aud",
	"jti",
	"iat",
	"exp",
	"sub",
	"registration",
]);

export interface AutomaticRegistrationConfig {
	readonly entityId: EntityId;
	readonly protocolKeyProvider: ProtocolSigningKeyProvider;
	readonly authorityHints: readonly [EntityId, ...EntityId[]];
	readonly metadata: Record<string, Record<string, unknown>>;
	/** TTL for the Request Object JWT in seconds (default: 300). */
	readonly requestObjectTtlSeconds?: number;
	/**
	 * When true, attach the peer_trust_chain JWS header — a Trust Chain for
	 * the OP that ends at the same Trust Anchor as the RP chain. Disabled by
	 * default; set to true only when the RP wants the OP to use the
	 * metadata/policy values from the RP-built peer chain (for the
	 * Federation/Metadata Integrity properties). The library throws if the
	 * peer chain to the shared Trust Anchor cannot be built.
	 */
	readonly includePeerTrustChain?: boolean;
	/**
	 * Selects how the signed Request Object reaches the OP's authorization
	 * endpoint. Defaults to `"form_post"` — the safest choice for Request
	 * Objects that carry an embedded `trust_chain` (the JWT can easily exceed
	 * the practical URL/header length limits of HTTP intermediaries).
	 *
	 * Pass `"query"` to preserve the historical 0.3.x GET-query behavior.
	 */
	readonly requestDelivery?: RequestDelivery;
	/**
	 * For `requestDelivery: "request_uri"`: the publicly-reachable URL at
	 * which the RP will host the signed Request Object JWT. REQUIRED in that
	 * mode and ignored otherwise. The library does NOT host the JWT — the
	 * caller must serve the returned `requestObjectJwt` at this URL with
	 * Content-Type `application/oauth-authz-req+jwt`, typically with a short
	 * TTL and single-use semantics.
	 */
	readonly requestUri?: string;
}

interface AutomaticRegistrationResultBase {
	readonly requestObjectJwt: string;
	readonly trustChain: ValidatedTrustChain;
	readonly trustChainExpiresAt: number;
}

/**
 * Discriminated union over `delivery`. Each variant carries exactly the
 * additional fields the caller needs to dispatch the Request Object.
 */
export type AutomaticRegistrationResult =
	| (AutomaticRegistrationResultBase & {
			readonly delivery: "query";
			/** Full authorization-endpoint URL with `?request=…&client_id=…`. Redirect the user-agent here. */
			readonly authorizationUrl: string;
	  })
	| (AutomaticRegistrationResultBase & {
			readonly delivery: "form_post";
			/** Bare authorization-endpoint URL. POST `formParams` here. */
			readonly authorizationEndpoint: string;
			/** Form fields to submit as `application/x-www-form-urlencoded` body. */
			readonly formParams: Record<string, string>;
	  })
	| (AutomaticRegistrationResultBase & {
			readonly delivery: "request_uri";
			/** Echoes the caller-supplied URI; cache the `requestObjectJwt` under this URL. */
			readonly requestUri: string;
			/** Full authorization-endpoint URL with `?request_uri=…&client_id=…`. Redirect the user-agent here. */
			readonly authorizationUrl: string;
	  })
	| (AutomaticRegistrationResultBase & {
			readonly delivery: "par";
			/** PAR endpoint URL the library POSTed to. */
			readonly pushedAuthorizationRequestEndpoint: string;
			/** Full authorization-endpoint URL with `?request_uri=urn:…&client_id=…`. Redirect the user-agent here. */
			readonly authorizationUrl: string;
			/** The `urn:`-style request URI returned by the PAR endpoint. */
			readonly parRequestUri: string;
			/** Absolute expiration time (seconds since epoch) computed from the PAR `expires_in` response. */
			readonly parExpiresAt: number;
	  });

/**
 * RP-side automatic registration: build a Request Object JWT and authorization URL.
 *
 * Accepts a `DiscoveryResult` (from `discoverEntity()`) to ensure the OP
 * has been validated through the federation before registration.
 */
export async function automaticRegistration(
	discovery: DiscoveryResult,
	rpConfig: AutomaticRegistrationConfig,
	authzRequestParams: Record<string, string>,
	trustAnchors: TrustAnchorSet,
	options?: FederationOptions,
	providerDiscovery: "supplied" | "resolved" = "supplied",
	profile: RegistrationProfile = oidcRegistrationProfile,
): Promise<Result<AutomaticRegistrationResult>> {
	safeLogger(options?.logger)?.debug("Creating an Automatic Client Registration Request");
	if (!rpConfig.metadata[profile.clientType])
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				"openid_relying_party or oauth_client metadata is required for automatic registration",
			),
		);

	const sharedChains = await selectSharedRegistrationTrustChains(
		rpConfig.entityId,
		discovery.entityId as EntityId,
		discovery.trustChain,
		trustAnchors,
		options,
		{
			allowAlternativeProvider: providerDiscovery === "resolved",
			profile,
		},
	);
	if (!sharedChains.ok) return err(sharedChains.error);

	const opMeta = sharedChains.value.opChain.resolvedMetadata[profile.providerType] as
		| Record<string, unknown>
		| undefined;
	const registrationTypes = getRegistrationTypes(opMeta);
	if (!registrationTypes.includes(ClientRegistrationType.Automatic)) {
		safeLogger(options?.logger)?.warn("OP does not support Automatic Client Registration");
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"OP does not support automatic registration",
			),
		);
	}

	const authorizationEndpoint = opMeta?.authorization_endpoint as string | undefined;
	if (!authorizationEndpoint) {
		safeLogger(options?.logger)?.warn("OP metadata is missing authorization_endpoint");
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				`OP has no authorization_endpoint in ${profile.providerType} metadata`,
			),
		);
	}

	const requestObjectSigner = await rpConfig.protocolKeyProvider.getRequestObjectSigner();
	const assertSignerResult = assertProtocolSignerPublished(
		rpConfig.metadata,
		requestObjectSigner,
		"Request Object",
		profile.clientType,
	);
	if (!assertSignerResult.ok) {
		return assertSignerResult;
	}
	const now = nowSeconds(options?.clock);

	const selectedChain = [...sharedChains.value.rpChainStatements];
	const selectedTrustAnchorId = sharedChains.value.trustAnchorId;

	// Reserved claims must not be overwritten by caller-supplied params
	const filteredParams: Record<string, string> = {};
	for (const [key, value] of Object.entries(authzRequestParams)) {
		if (!RESERVED_REQUEST_OBJECT_CLAIMS.has(key)) {
			filteredParams[key] = value;
		}
	}

	// sub intentionally omitted — forbidden in automatic registration Request Objects
	const payload: Record<string, unknown> = {
		iss: rpConfig.entityId,
		client_id: rpConfig.entityId,
		aud: discovery.entityId,
		jti: crypto.randomUUID(),
		iat: now,
		exp: now + (rpConfig.requestObjectTtlSeconds ?? DEFAULT_REQUEST_OBJECT_TTL_SECONDS),
		...filteredParams,
	};

	const extraHeaders: Record<string, unknown> = {};
	if (selectedChain.length > 0) {
		extraHeaders.trust_chain = selectedChain;
	}

	if (rpConfig.includePeerTrustChain) {
		if (!selectedTrustAnchorId) {
			safeLogger(options?.logger)?.warn(
				"includePeerTrustChain requires a selected RP Trust Anchor",
			);
			return err(
				federationError(
					InternalErrorCode.TrustAnchorUnknown,
					"includePeerTrustChain requires a selected RP Trust Anchor; no valid RP chain was built",
				),
			);
		}
		const peerChainResult = await resolveTrustChainForAnchor(
			discovery.entityId as EntityId,
			selectedTrustAnchorId,
			trustAnchors,
			options,
		);
		if (!peerChainResult.ok) {
			safeLogger(options?.logger)?.warn(
				"Cannot build peer_trust_chain to the selected Trust Anchor",
			);
			return err(
				federationError(
					InternalErrorCode.TrustChainInvalid,
					`includePeerTrustChain: cannot build peer Trust Chain for ${discovery.entityId} ending at ${selectedTrustAnchorId}: ${peerChainResult.error.description}`,
				),
			);
		}
		extraHeaders.peer_trust_chain = peerChainResult.value;
	}

	const requestObjectJwt = await signEntityStatement(payload, requestObjectSigner, {
		typ: RequestObjectTyp,
		...(Object.keys(extraHeaders).length > 0 ? { extraHeaders } : {}),
	});

	const base: AutomaticRegistrationResultBase = {
		requestObjectJwt,
		trustChain: sharedChains.value.opChain,
		trustChainExpiresAt: sharedChains.value.opChain.expiresAt,
	};

	const delivery: RequestDelivery = rpConfig.requestDelivery ?? "form_post";
	const clientIdStr = rpConfig.entityId as string;
	// OIDC Core §§6.1–6.2 require these outer parameters; RFC 9101 §5
	// permits matching duplicates. Copy the signed values to prevent divergence.
	const oidcParams: Record<string, string> = {};
	if (profile.oidc) {
		for (const name of ["scope", "response_type"]) {
			const value = payload[name];
			if (typeof value === "string") oidcParams[name] = value;
		}
	}

	switch (delivery) {
		case "query":
			return ok({
				...base,
				delivery: "query",
				authorizationUrl: buildAuthorizationUrl(authorizationEndpoint, {
					...oidcParams,
					request: requestObjectJwt,
					client_id: clientIdStr,
				}),
			});

		case "form_post":
			return ok({
				...base,
				delivery: "form_post",
				authorizationEndpoint,
				formParams: {
					...oidcParams,
					request: requestObjectJwt,
					client_id: clientIdStr,
				},
			});

		case "request_uri": {
			if (opMeta?.request_uri_parameter_supported === false) {
				safeLogger(options?.logger)?.warn("OP does not support the request_uri parameter");
				return err(
					federationError(
						FederationErrorCode.InvalidRequest,
						"requestDelivery 'request_uri' requires the OP to support the request_uri parameter",
					),
				);
			}
			const hostedUri = rpConfig.requestUri;
			if (!hostedUri) {
				safeLogger(options?.logger)?.warn("Provide requestUri to host the Request Object");
				return err(
					federationError(
						FederationErrorCode.InvalidRequest,
						"requestDelivery 'request_uri' requires rpConfig.requestUri to be set to the URL at which the RP will host the Request Object JWT",
					),
				);
			}
			if (!hostedUri.startsWith("https://")) {
				safeLogger(options?.logger)?.warn("Request Object request_uri must use HTTPS");
				return err(
					federationError(
						FederationErrorCode.InvalidRequest,
						"rpConfig.requestUri must be an https:// URL",
					),
				);
			}
			safeLogger(options?.logger)?.info("Automatic registration completed");
			return ok({
				...base,
				delivery: "request_uri",
				requestUri: hostedUri,
				authorizationUrl: buildAuthorizationUrl(authorizationEndpoint, {
					...oidcParams,
					request_uri: hostedUri,
					client_id: clientIdStr,
				}),
			});
		}

		case "par": {
			const parEndpoint = opMeta?.pushed_authorization_request_endpoint as string | undefined;
			if (!parEndpoint) {
				safeLogger(options?.logger)?.warn(
					"PAR requires pushed_authorization_request_endpoint in OP metadata",
				);
				return err(
					federationError(
						FederationErrorCode.InvalidRequest,
						`requestDelivery 'par' requires the OP to advertise pushed_authorization_request_endpoint in its ${profile.providerType} metadata`,
					),
				);
			}
			const httpClient = options?.httpClient ?? fetch;
			// Use the calling role's metadata even when the entity hosts both client types.
			const clientType = profile.clientType;
			const authMethod = parJwtAuthentication(
				sharedChains.value.rpChain.resolvedMetadata[clientType] ?? {},
				opMeta ?? {},
			);
			if (!authMethod.ok) return authMethod;
			const form = new URLSearchParams({ request: requestObjectJwt, client_id: clientIdStr });
			// §12.1.1.2 permits the signed Request Object itself as PAR proof.
			// An additional assertion must use a mutually supported method (§12.1.4).
			if (authMethod.value) {
				try {
					const clientAssertionSigner = rpConfig.protocolKeyProvider.getClientAssertionSigner
						? await rpConfig.protocolKeyProvider.getClientAssertionSigner()
						: requestObjectSigner;

					const assertAssertionSignerResult = assertProtocolSignerPublished(
						rpConfig.metadata,
						clientAssertionSigner,
						"client assertion",
						profile.clientType,
					);
					if (!assertAssertionSignerResult.ok) {
						safeLogger(options?.logger)?.warn(
							"PAR client assertion signer does not match the RP protocol keys",
						);
						return err(assertAssertionSignerResult.error);
					}

					// Federation §12.1.1.2 requires the OP Entity Identifier as the assertion audience.
					const clientAssertion = await createClientAssertion(
						rpConfig.entityId as string,
						discovery.entityId as string,
						clientAssertionSigner,
						{
							expiresInSeconds: 60,
							...(options?.clock ? { clock: options.clock } : {}),
						},
					);
					form.set("client_assertion_type", CLIENT_ASSERTION_TYPE);
					form.set("client_assertion", clientAssertion);
				} catch (cause) {
					safeLogger(options?.logger)?.error("Failed to create the PAR client assertion");
					return err(
						federationError(
							FederationErrorCode.ServerError,
							"Failed to create PAR client assertion",
							cause,
						),
					);
				}
			}
			const formBody = form.toString();
			const response = await httpClient(parEndpoint, {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Accept: "application/json",
				},
				body: formBody,
			});
			if (response.status !== 201 && response.status !== 200) {
				safeLogger(options?.logger)?.warn("PAR endpoint returned an unsuccessful HTTP status");
				return err(
					federationError(
						InternalErrorCode.Network,
						`PAR request failed (HTTP ${response.status})`,
					),
				);
			}
			const parPayload = (await response.json()) as Record<string, unknown>;
			const parRequestUri = parPayload.request_uri;
			const expiresIn = parPayload.expires_in;
			if (typeof parRequestUri !== "string" || !parRequestUri.startsWith("urn:")) {
				safeLogger(options?.logger)?.warn("PAR response request_uri is missing or invalid");
				return err(
					federationError(InternalErrorCode.Network, "PAR response missing or invalid request_uri"),
				);
			}
			if (typeof expiresIn !== "number" || expiresIn <= 0) {
				safeLogger(options?.logger)?.warn("PAR response expires_in is missing or invalid");
				return err(
					federationError(InternalErrorCode.Network, "PAR response missing or invalid expires_in"),
				);
			}
			safeLogger(options?.logger)?.info("Automatic registration completed");
			return ok({
				...base,
				delivery: "par",
				pushedAuthorizationRequestEndpoint: parEndpoint,
				authorizationUrl: buildAuthorizationUrl(authorizationEndpoint, {
					request_uri: parRequestUri,
					client_id: clientIdStr,
				}),
				parRequestUri,
				parExpiresAt: nowSeconds(options?.clock) + expiresIn,
			});
		}
	}
}

function buildAuthorizationUrl(endpoint: string, params: Record<string, string>): string {
	const url = new URL(endpoint);
	for (const [key, value] of Object.entries(params)) {
		url.searchParams.set(key, value);
	}
	return url.toString();
}

/** Use the selected federation metadata to choose optional PAR JWT authentication. */
function parJwtAuthentication(
	rp: Record<string, unknown>,
	op: Record<string, unknown>,
): Result<boolean> {
	const methods = rp.token_endpoint_auth_methods_supported;
	const method = rp.token_endpoint_auth_method;
	const opMethods = op.token_endpoint_auth_methods_supported;
	for (const list of [methods, opMethods]) {
		if (
			list !== undefined &&
			(!Array.isArray(list) || !list.every((value) => typeof value === "string"))
		) {
			return err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					"Authentication methods must be arrays of strings",
				),
			);
		}
	}
	if (method !== undefined && typeof method !== "string") {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				"Client authentication method must be a string",
			),
		);
	}
	// RP Metadata Choices §2 requires the singular preference to belong to the list.
	if (Array.isArray(methods) && method !== undefined && !methods.includes(method)) {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				"Client authentication method must belong to its supported methods",
			),
		);
	}
	const rpSupports = Array.isArray(methods)
		? methods.includes("private_key_jwt")
		: method === "private_key_jwt";
	return ok(rpSupports && Array.isArray(opMethods) && opMethods.includes("private_key_jwt"));
}

function assertProtocolSignerPublished(
	metadata: Record<string, Record<string, unknown>>,
	signer: JwtSigner,
	purpose: string,
	type: RegistrationProfile["clientType"],
): Result<void> {
	const rpMetadata = metadata[type];
	if (!rpMetadata) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"metadata.openid_relying_party or metadata.oauth_client is required for automatic registration",
			),
		);
	}

	const inlineJwks = rpMetadata.jwks as { keys?: Array<{ kid?: unknown }> } | undefined;
	const hasInlineJwks = inlineJwks !== undefined;
	const hasUriPublication =
		typeof rpMetadata.jwks_uri === "string" || typeof rpMetadata.signed_jwks_uri === "string";

	if (hasInlineJwks) {
		const keys = inlineJwks.keys;
		if (!Array.isArray(keys)) {
			return err(
				federationError(
					FederationErrorCode.InvalidRequest,
					`metadata.${type}.jwks must be a JWK Set`,
				),
			);
		}
		if (!keys.some((key) => key.kid === signer.kid)) {
			return err(
				federationError(
					FederationErrorCode.InvalidRequest,
					`OIDC ${purpose} signer kid '${signer.kid}' is not published in metadata.${type}.jwks`,
				),
			);
		}
		return ok(undefined);
	}

	if (!hasUriPublication) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`metadata.${type} must publish OIDC protocol keys with jwks, jwks_uri, or signed_jwks_uri`,
			),
		);
	}

	return ok(undefined);
}
