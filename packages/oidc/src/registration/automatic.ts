/** RP-side automatic registration: builds a signed Request Object with embedded trust chain. */
import {
	DEFAULT_REQUEST_OBJECT_TTL_SECONDS,
	type DiscoveryResult,
	type EntityId,
	type FederationOptions,
	nowSeconds,
	resolveTrustChainForAnchor,
	resolveTrustChains,
	signEntityStatement,
	type TrustAnchorSet,
	type ValidatedTrustChain,
	validateTrustChain,
} from "@oidfed/core";
import { createClientAssertion } from "../client-auth/assertion.js";
import { ClientRegistrationType, RequestObjectTyp } from "../constants.js";
import { getRegistrationTypes } from "./helpers.js";

const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/**
 * How the Request Object reaches the OP's authorization endpoint.
 *
 * - `query` — Request Object value travels in the `request` query parameter of a
 *   GET to the authorization endpoint. Compact but constrained by URL/header
 *   length limits in HTTP intermediaries when the Request Object carries an
 *   embedded `trust_chain`.
 * - `form_post` — Default. Request Object value travels in an
 *   `application/x-www-form-urlencoded` body POSTed to the authorization
 *   endpoint. The user-agent submits an auto-submit HTML form supplied by the
 *   RP. Avoids URL/header length ceilings.
 * - `request_uri` — Request Object is hosted by the RP at a URL it provides;
 *   the OP fetches that URL. The library does NOT host the JWT — the caller
 *   must serve the returned `requestObjectJwt` at the supplied `requestUri`.
 * - `par` — Library coordinates a Pushed Authorization Request to the OP's
 *   `pushed_authorization_request_endpoint`, then returns the short-lived
 *   `urn:`-style request_uri ready to redirect through.
 */
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
	readonly signingKeys: ReadonlyArray<Record<string, unknown>>;
	readonly authorityHints: ReadonlyArray<EntityId>;
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
 *
 * @throws {Error} If the OP does not support automatic registration.
 * @throws {Error} If the OP has no `authorization_endpoint` in `openid_provider` metadata.
 * @throws {Error} on any validation or network failure (RP-side convention).
 *   OP-side handlers (`processAutomaticRegistration`) use `Result<T, FederationError>` instead.
 */
export async function automaticRegistration(
	discovery: DiscoveryResult,
	rpConfig: AutomaticRegistrationConfig,
	authzRequestParams: Record<string, string>,
	trustAnchors: TrustAnchorSet,
	options?: FederationOptions,
): Promise<AutomaticRegistrationResult> {
	const opMeta = discovery.resolvedMetadata.openid_provider as Record<string, unknown> | undefined;
	const registrationTypes = getRegistrationTypes(opMeta);
	if (!registrationTypes.includes(ClientRegistrationType.Automatic)) {
		throw new Error("OP does not support automatic registration");
	}

	const authorizationEndpoint = opMeta?.authorization_endpoint as string | undefined;
	if (!authorizationEndpoint) {
		throw new Error("OP has no authorization_endpoint in openid_provider metadata");
	}

	const signingKey = rpConfig.signingKeys[0] as Record<string, unknown>;
	const now = nowSeconds();

	// Select RP chain — prefer one whose Trust Anchor is shared with the OP (single pass)
	const opTrustAnchorId = discovery.trustChain.trustAnchorId;
	const rpChainResult = await resolveTrustChains(rpConfig.entityId, trustAnchors, options);

	let selectedChain: string[] = [];
	let selectedTrustAnchorId: EntityId | undefined;

	for (const chain of rpChainResult.chains) {
		const validationResult = await validateTrustChain(
			chain.statements as string[],
			trustAnchors,
			options,
		);
		if (validationResult.valid) {
			if (chain.trustAnchorId === opTrustAnchorId) {
				// Ideal: shared trust anchor — use immediately
				selectedChain = chain.statements as string[];
				selectedTrustAnchorId = chain.trustAnchorId as EntityId;
				break;
			}
			if (selectedChain.length === 0) {
				// Fallback: first valid chain as backup
				selectedChain = chain.statements as string[];
				selectedTrustAnchorId = chain.trustAnchorId as EntityId;
			}
		}
	}

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
			throw new Error(
				"includePeerTrustChain requires a selected RP Trust Anchor; no valid RP chain was built",
			);
		}
		const peerChainResult = await resolveTrustChainForAnchor(
			discovery.entityId as EntityId,
			selectedTrustAnchorId,
			trustAnchors,
			options,
		);
		if (!peerChainResult.ok) {
			throw new Error(
				`includePeerTrustChain: cannot build peer Trust Chain for ${discovery.entityId} ending at ${selectedTrustAnchorId}: ${peerChainResult.error.description}`,
			);
		}
		extraHeaders.peer_trust_chain = peerChainResult.value;
	}

	const requestObjectJwt = await signEntityStatement(
		payload,
		signingKey as Parameters<typeof signEntityStatement>[1],
		{
			kid: signingKey.kid as string,
			typ: RequestObjectTyp,
			...(Object.keys(extraHeaders).length > 0 ? { extraHeaders } : {}),
		},
	);

	const base: AutomaticRegistrationResultBase = {
		requestObjectJwt,
		trustChain: discovery.trustChain,
		trustChainExpiresAt: discovery.trustChain.expiresAt,
	};

	const delivery: RequestDelivery = rpConfig.requestDelivery ?? "form_post";
	const clientIdStr = rpConfig.entityId as string;

	switch (delivery) {
		case "query":
			return {
				...base,
				delivery: "query",
				authorizationUrl: buildAuthorizationUrl(authorizationEndpoint, {
					request: requestObjectJwt,
					client_id: clientIdStr,
				}),
			};

		case "form_post":
			return {
				...base,
				delivery: "form_post",
				authorizationEndpoint,
				formParams: {
					request: requestObjectJwt,
					client_id: clientIdStr,
				},
			};

		case "request_uri": {
			const hostedUri = rpConfig.requestUri;
			if (!hostedUri) {
				throw new Error(
					"requestDelivery 'request_uri' requires rpConfig.requestUri to be set to the URL at which the RP will host the Request Object JWT",
				);
			}
			if (!hostedUri.startsWith("https://")) {
				throw new Error("rpConfig.requestUri must be an https:// URL");
			}
			return {
				...base,
				delivery: "request_uri",
				requestUri: hostedUri,
				authorizationUrl: buildAuthorizationUrl(authorizationEndpoint, {
					request_uri: hostedUri,
					client_id: clientIdStr,
				}),
			};
		}

		case "par": {
			const parEndpoint = opMeta?.pushed_authorization_request_endpoint as string | undefined;
			if (!parEndpoint) {
				throw new Error(
					"requestDelivery 'par' requires the OP to advertise pushed_authorization_request_endpoint in its openid_provider metadata",
				);
			}
			const httpClient = options?.httpClient ?? fetch;
			// Client assertion audience is the OP's Entity Identifier under the
			// federation profile of PAR + automatic registration — not the PAR
			// endpoint URL.
			const clientAssertion = await createClientAssertion(
				rpConfig.entityId as string,
				discovery.entityId as string,
				signingKey as Parameters<typeof createClientAssertion>[2],
				{ expiresInSeconds: 60 },
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
				throw new Error(`PAR request failed (HTTP ${response.status})`);
			}
			const parPayload = (await response.json()) as Record<string, unknown>;
			const parRequestUri = parPayload.request_uri;
			const expiresIn = parPayload.expires_in;
			if (typeof parRequestUri !== "string" || !parRequestUri.startsWith("urn:")) {
				throw new Error("PAR response missing or invalid request_uri");
			}
			if (typeof expiresIn !== "number" || expiresIn <= 0) {
				throw new Error("PAR response missing or invalid expires_in");
			}
			return {
				...base,
				delivery: "par",
				pushedAuthorizationRequestEndpoint: parEndpoint,
				authorizationUrl: buildAuthorizationUrl(authorizationEndpoint, {
					request_uri: parRequestUri,
					client_id: clientIdStr,
				}),
				parRequestUri,
				parExpiresAt: nowSeconds() + expiresIn,
			};
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
