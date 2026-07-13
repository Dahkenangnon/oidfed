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
	signEntityStatement,
	type TrustAnchorSet,
	type ValidatedTrustChain,
} from "@oidfed/core";
import { createClientAssertion } from "../client-auth/assertion.js";
import { ClientRegistrationType, RequestObjectTyp } from "../constants.js";
import type { OidcProtocolKeyProvider } from "../protocol-keys.js";
import { getRegistrationTypes, selectSharedRegistrationTrustChains } from "./helpers.js";

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
	readonly protocolKeyProvider: OidcProtocolKeyProvider;
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
): Promise<Result<AutomaticRegistrationResult>> {
	const sharedChains = await selectSharedRegistrationTrustChains(
		rpConfig.entityId,
		discovery.entityId as EntityId,
		discovery.trustChain,
		trustAnchors,
		options,
	);
	if (!sharedChains.ok) return err(sharedChains.error);

	const opMeta = sharedChains.value.opChain.resolvedMetadata.openid_provider as
		| Record<string, unknown>
		| undefined;
	const registrationTypes = getRegistrationTypes(opMeta);
	if (!registrationTypes.includes(ClientRegistrationType.Automatic)) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"OP does not support automatic registration",
			),
		);
	}

	const authorizationEndpoint = opMeta?.authorization_endpoint as string | undefined;
	if (!authorizationEndpoint) {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				"OP has no authorization_endpoint in openid_provider metadata",
			),
		);
	}

	const requestObjectSigner = await rpConfig.protocolKeyProvider.getRequestObjectSigner();
	const assertSignerResult = assertOidcSignerPublished(
		rpConfig.metadata,
		requestObjectSigner,
		"Request Object",
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

	switch (delivery) {
		case "query":
			return ok({
				...base,
				delivery: "query",
				authorizationUrl: buildAuthorizationUrl(authorizationEndpoint, {
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
					request: requestObjectJwt,
					client_id: clientIdStr,
				},
			});

		case "request_uri": {
			const hostedUri = rpConfig.requestUri;
			if (!hostedUri) {
				return err(
					federationError(
						FederationErrorCode.InvalidRequest,
						"requestDelivery 'request_uri' requires rpConfig.requestUri to be set to the URL at which the RP will host the Request Object JWT",
					),
				);
			}
			if (!hostedUri.startsWith("https://")) {
				return err(
					federationError(
						FederationErrorCode.InvalidRequest,
						"rpConfig.requestUri must be an https:// URL",
					),
				);
			}
			return ok({
				...base,
				delivery: "request_uri",
				requestUri: hostedUri,
				authorizationUrl: buildAuthorizationUrl(authorizationEndpoint, {
					request_uri: hostedUri,
					client_id: clientIdStr,
				}),
			});
		}

		case "par": {
			const parEndpoint = opMeta?.pushed_authorization_request_endpoint as string | undefined;
			if (!parEndpoint) {
				return err(
					federationError(
						FederationErrorCode.InvalidRequest,
						"requestDelivery 'par' requires the OP to advertise pushed_authorization_request_endpoint in its openid_provider metadata",
					),
				);
			}
			const httpClient = options?.httpClient ?? fetch;
			const clientAssertionSigner = rpConfig.protocolKeyProvider.getClientAssertionSigner
				? await rpConfig.protocolKeyProvider.getClientAssertionSigner()
				: requestObjectSigner;

			const assertAssertionSignerResult = assertOidcSignerPublished(
				rpConfig.metadata,
				clientAssertionSigner,
				"client assertion",
			);
			if (!assertAssertionSignerResult.ok) {
				return err(assertAssertionSignerResult.error);
			}

			// Client assertion audience is the OP's Entity Identifier under the
			// federation profile of PAR + automatic registration — not the PAR
			// endpoint URL.
			const clientAssertion = await createClientAssertion(
				rpConfig.entityId as string,
				discovery.entityId as string,
				clientAssertionSigner,
				{
					expiresInSeconds: 60,
					...(options?.clock ? { clock: options.clock } : {}),
				},
			);
			const formBody = new URLSearchParams({
				request: requestObjectJwt,
				client_id: clientIdStr,
				client_assertion_type: CLIENT_ASSERTION_TYPE,
				client_assertion: clientAssertion,
			}).toString();
			const response = await httpClient(parEndpoint, {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Accept: "application/json",
				},
				body: formBody,
			});
			if (response.status !== 201 && response.status !== 200) {
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
				return err(
					federationError(InternalErrorCode.Network, "PAR response missing or invalid request_uri"),
				);
			}
			if (typeof expiresIn !== "number" || expiresIn <= 0) {
				return err(
					federationError(InternalErrorCode.Network, "PAR response missing or invalid expires_in"),
				);
			}
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

function assertOidcSignerPublished(
	metadata: Record<string, Record<string, unknown>>,
	signer: JwtSigner,
	purpose: string,
): Result<void> {
	const type = metadata.openid_relying_party ? "openid_relying_party" : "oauth_client";
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
