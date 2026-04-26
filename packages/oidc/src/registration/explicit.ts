import {
	ClientRegistrationType,
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	type DiscoveryResult,
	decodeEntityStatement,
	type EntityId,
	type FederationOptions,
	type JWK,
	JwtTyp,
	MediaType,
	nowSeconds,
	type ParsedEntityStatement,
	resolveTrustChainForAnchor,
	resolveTrustChains,
	signEntityStatement,
	stripPrivateFields,
	type TrustAnchorSet,
	verifyEntityStatement,
} from "@oidfed/core";
import { getRegistrationTypes } from "./helpers.js";

export interface ExplicitRegistrationConfig {
	readonly entityId: EntityId;
	readonly signingKeys: ReadonlyArray<Record<string, unknown>>;
	readonly authorityHints: ReadonlyArray<EntityId>;
	readonly metadata: Record<string, Record<string, unknown>>;
	readonly entityConfigurationTtlSeconds?: number;
	readonly trustMarks?: ReadonlyArray<Record<string, unknown>>;
	/**
	 * When true, attach the peer_trust_chain JWS header — a Trust Chain for
	 * the OP that ends at the same Trust Anchor as the RP chain. Disabled by
	 * default; set to true only when the RP wants the OP to use the
	 * metadata/policy values from the RP-built peer chain (Federation /
	 * Metadata Integrity properties). The library throws if the peer chain
	 * to the shared Trust Anchor cannot be built. The current emit path
	 * always sends an Entity Configuration JWT body (never a Trust-Chain
	 * JSON body), so the spec's mutual-exclusion rule between
	 * peer_trust_chain and Trust-Chain-JSON request body is structurally
	 * satisfied here; do NOT add a Trust-Chain-JSON body shape without also
	 * refusing this option in that branch.
	 */
	readonly includePeerTrustChain?: boolean;
}

export interface ExplicitRegistrationResult {
	readonly registrationStatement: ParsedEntityStatement;
	readonly clientId: string;
	readonly clientSecret?: string;
	readonly expiresAt: number;
	readonly registeredMetadata: Readonly<Record<string, unknown>>;
	/** Trust chain expiration — RP must not use the registration past this time. */
	readonly trustChainExpiresAt: number;
}

/**
 * RP-side explicit registration: POST Entity Configuration to OP's
 * federation_registration_endpoint and process the response.
 *
 * Accepts a `DiscoveryResult` (from `discoverEntity()`) to ensure the OP
 * has been validated through the federation before registration.
 *
 * @throws {Error} on any validation or network failure (RP-side convention).
 *   OP-side handlers (`processExplicitRegistration`) use `Result<T, FederationError>` instead.
 */
export async function explicitRegistration(
	discovery: DiscoveryResult,
	rpConfig: ExplicitRegistrationConfig,
	trustAnchors: TrustAnchorSet,
	options?: FederationOptions,
): Promise<ExplicitRegistrationResult> {
	const opMeta = discovery.resolvedMetadata.openid_provider as Record<string, unknown> | undefined;
	const registrationTypes = getRegistrationTypes(opMeta);
	if (!registrationTypes.includes(ClientRegistrationType.Explicit)) {
		throw new Error("OP does not support explicit registration");
	}

	const fedEntity = discovery.resolvedMetadata.federation_entity as
		| Record<string, unknown>
		| undefined;
	const registrationEndpoint = fedEntity?.federation_registration_endpoint as string | undefined;
	if (!registrationEndpoint) {
		throw new Error("OP has no federation_registration_endpoint in federation_entity metadata");
	}

	const opTrustAnchorId = discovery.trustChain.trustAnchorId;
	const rpTaIds = new Set<string>();
	for (const taId of trustAnchors.keys()) {
		rpTaIds.add(taId as string);
	}
	if (!rpTaIds.has(opTrustAnchorId as string)) {
		throw new Error("No shared Trust Anchor between RP and OP");
	}

	const authorityHints = rpConfig.authorityHints;

	const signingKey = rpConfig.signingKeys[0] as Record<string, unknown>;
	const now = nowSeconds();
	const ttl = rpConfig.entityConfigurationTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS;

	const publicKeys = rpConfig.signingKeys.map((k) => stripPrivateFields(k as JWK));

	// Include RP trust chain in header (recommended)
	const rpChainResult = await resolveTrustChains(rpConfig.entityId, trustAnchors, options);
	let rpChainStatements: string[] = [];
	let selectedTrustAnchorId: EntityId | undefined;
	if (rpChainResult.chains.length > 0) {
		for (const chain of rpChainResult.chains) {
			if (chain.trustAnchorId === opTrustAnchorId) {
				rpChainStatements = chain.statements as string[];
				selectedTrustAnchorId = chain.trustAnchorId as EntityId;
				break;
			}
		}
		if (rpChainStatements.length === 0) {
			rpChainStatements = (rpChainResult.chains[0]?.statements ?? []) as string[];
			selectedTrustAnchorId = rpChainResult.chains[0]?.trustAnchorId as EntityId | undefined;
		}
	}

	const ecPayload: Record<string, unknown> = {
		iss: rpConfig.entityId,
		sub: rpConfig.entityId,
		aud: discovery.entityId,
		iat: now,
		exp: now + ttl,
		jwks: { keys: publicKeys },
		authority_hints: authorityHints,
		metadata: rpConfig.metadata,
	};

	if (rpConfig.trustMarks && rpConfig.trustMarks.length > 0) {
		ecPayload.trust_marks = rpConfig.trustMarks;
	}

	const extraHeaders: Record<string, unknown> = {};
	if (rpChainStatements.length > 0) {
		extraHeaders.trust_chain = rpChainStatements;
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

	const ecJwt = await signEntityStatement(
		ecPayload,
		signingKey as Parameters<typeof signEntityStatement>[1],
		{
			kid: signingKey.kid as string,
			typ: JwtTyp.EntityStatement,
			...(Object.keys(extraHeaders).length > 0 ? { extraHeaders } : {}),
		},
	);

	const httpClient = options?.httpClient ?? fetch;
	const request = new Request(registrationEndpoint, {
		method: "POST",
		headers: {
			"Content-Type": MediaType.EntityStatement,
		},
		body: ecJwt,
	});

	const response = await httpClient(request);
	if (!response.ok) {
		// Intentionally omit response body to avoid leaking OP internals
		throw new Error(`Explicit registration failed (HTTP ${response.status})`);
	}

	const responseJwt = await response.text();

	// Verify using the subordinate statement's JWKS (not the self-signed EC)
	// because the OP's signing key authority comes from its superior in the chain.
	// The subordinate statement about the OP is the one where sub === OP entity ID and iss !== sub.
	// In a properly-ordered chain [leaf_EC, sub_stmt_from_superior, ..., TA_EC],
	// this is always opStatements[1] for the OP's chain.
	const opStatements = discovery.trustChain.statements;
	const subordinateStmt =
		opStatements.length > 1
			? (opStatements[1] as (typeof opStatements)[0])
			: (opStatements[0] as (typeof opStatements)[0]);
	const opJwks = subordinateStmt.payload.jwks;

	if (!opJwks) {
		throw new Error("OP trust chain has no JWKS — cannot verify registration response signature");
	}

	const verifyResult = await verifyEntityStatement(responseJwt, opJwks, {
		expectedTyp: JwtTyp.ExplicitRegistrationResponse,
	});
	if (!verifyResult.ok) {
		throw new Error("Registration response signature verification failed");
	}

	const decoded = decodeEntityStatement(responseJwt);
	if (!decoded.ok) {
		throw new Error("Failed to decode registration response");
	}

	if (decoded.value.header.typ !== JwtTyp.ExplicitRegistrationResponse) {
		throw new Error(`Invalid response typ: expected '${JwtTyp.ExplicitRegistrationResponse}'`);
	}

	const responsePayload = decoded.value.payload as Record<string, unknown>;

	if (responsePayload.iss !== (discovery.entityId as string)) {
		throw new Error("Response iss does not match OP");
	}

	if (responsePayload.aud !== (rpConfig.entityId as string)) {
		throw new Error("Response aud does not match RP");
	}

	// iat and exp are REQUIRED in the registration response
	const responseExp = responsePayload.exp as number | undefined;
	if (responseExp === undefined) {
		throw new Error("Registration response missing required 'exp' claim");
	}
	const responseNow = nowSeconds();
	if (responseNow >= responseExp) {
		throw new Error("Registration response has expired");
	}

	if (responsePayload.iat === undefined) {
		throw new Error("Registration response missing required 'iat' claim");
	}

	const trustAnchor = responsePayload.trust_anchor as string | undefined;
	if (!trustAnchor || !trustAnchors.has(trustAnchor as EntityId)) {
		throw new Error("Response trust_anchor is not in configured trust anchors");
	}

	if (trustAnchor !== (opTrustAnchorId as string)) {
		throw new Error("Response trust_anchor does not match OP trust chain root");
	}

	// Verify that at least one of the RP's authority_hints leads to the trust_anchor
	// the OP selected. This is guaranteed by the shared-TA check above which ensures
	// opTrustAnchorId is in the RP's configured trust anchors.

	const responseAuthorityHints = responsePayload.authority_hints as string[] | undefined;
	if (responseAuthorityHints) {
		if (!Array.isArray(responseAuthorityHints) || responseAuthorityHints.length !== 1) {
			throw new Error("Response authority_hints MUST be a single-element array");
		}
		for (const hint of responseAuthorityHints) {
			if (typeof hint !== "string") {
				throw new Error("Response authority_hints contains non-string value");
			}
		}
	}

	const responseMeta = responsePayload.metadata as
		| Record<string, Record<string, unknown>>
		| undefined;
	if (responseMeta) {
		const requestedTypes = new Set(Object.keys(rpConfig.metadata));
		const responseTypes = new Set(Object.keys(responseMeta));
		for (const requestedType of requestedTypes) {
			if (!responseTypes.has(requestedType)) {
				throw new Error("Response metadata missing requested entity type");
			}
		}
	}

	const registeredMetadata = responseMeta?.openid_relying_party ?? responseMeta ?? {};

	const clientSecret = responsePayload.client_secret as string | undefined;

	// RP must not use the registration past trust chain expiry
	const trustChainExpiresAt = discovery.trustChain.expiresAt;

	const result: ExplicitRegistrationResult = {
		registrationStatement: decoded.value,
		clientId: (responsePayload.sub as string) ?? (rpConfig.entityId as string),
		expiresAt: responsePayload.exp as number,
		registeredMetadata,
		trustChainExpiresAt,
	};
	if (clientSecret) {
		return { ...result, clientSecret };
	}
	return result;
}
