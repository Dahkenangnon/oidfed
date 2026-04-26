/** RP-side automatic registration: builds a signed Request Object with embedded trust chain. */
import {
	ClientRegistrationType,
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
import { RequestObjectTyp } from "../constants.js";
import { getRegistrationTypes } from "./helpers.js";

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
}

export interface AutomaticRegistrationResult {
	readonly requestObjectJwt: string;
	readonly authorizationUrl: string;
	readonly trustChain: ValidatedTrustChain;
	readonly trustChainExpiresAt: number;
}

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

	const url = new URL(authorizationEndpoint);
	url.searchParams.set("request", requestObjectJwt);
	url.searchParams.set("client_id", rpConfig.entityId as string);

	return {
		requestObjectJwt,
		authorizationUrl: url.toString(),
		trustChain: discovery.trustChain,
		trustChainExpiresAt: discovery.trustChain.expiresAt,
	};
}
