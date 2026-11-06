import {
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	type DiscoveryResult,
	decodeEntityStatement,
	type EntityId,
	err,
	FederationErrorCode,
	type FederationKeyProvider,
	type FederationOptions,
	federationError,
	InternalErrorCode,
	isExactContentType,
	JwtTyp,
	MediaType,
	nowSeconds,
	ok,
	type ParsedEntityStatement,
	type Result,
	resolveTrustChainForAnchor,
	signEntityStatement,
	type TrustAnchorSet,
	validateCriticalClaims,
	validateEntityStatementTimeClaims,
	validateFederationKeySet,
	validateTrustChain,
	verifyEntityStatement,
} from "@oidfed/core";
import {
	ClientRegistrationType,
	OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE,
	OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE,
} from "../constants.js";
import {
	OpenIDRelyingPartyMetadataSchema,
	OpenIDRelyingPartyRegistrationResponseMetadataSchema,
} from "../schemas/metadata.js";
import { getRegistrationTypes, selectSharedRegistrationTrustChains } from "./helpers.js";
import { validateRegistrationMetadataPolicy } from "./metadata-policy.js";

export interface ExplicitRegistrationConfig {
	readonly entityId: EntityId;
	readonly keyProvider: FederationKeyProvider;
	readonly authorityHints: readonly [EntityId, ...EntityId[]];
	readonly metadata: Record<string, Record<string, unknown>>;
	readonly entityConfigurationTtlSeconds?: number;
	readonly trustMarks?: ReadonlyArray<Record<string, unknown>>;
	/**
	 * Include the OP's chain to the selected shared anchor in the registration
	 * JWT header (§12.2.1). Defaults to false. Returns an error if no peer path
	 * can be resolved. Requests use the Entity Configuration JWT transport.
	 */
	readonly includePeerTrustChain?: boolean;
}

export interface ExplicitRegistrationResult {
	readonly registrationStatement: ParsedEntityStatement;
	readonly clientId: string;
	readonly clientSecret?: string;
	readonly expiresAt: number;
	readonly registeredMetadata: Readonly<Record<string, unknown>>;
	/** OP trust chain expiration; use the registration only until the earlier of this and expiresAt (§12.3). */
	readonly trustChainExpiresAt: number;
}

/**
 * RP-side explicit registration: POST Entity Configuration to OP's
 * federation_registration_endpoint and process the response.
 *
 * Accepts a `DiscoveryResult` (from `discoverEntity()`) to ensure the OP
 * has been validated through the federation before registration.
 */
export async function explicitRegistration(
	discovery: DiscoveryResult,
	rpConfig: ExplicitRegistrationConfig,
	trustAnchors: TrustAnchorSet,
	options?: FederationOptions,
): Promise<Result<ExplicitRegistrationResult>> {
	const keySet = await rpConfig.keyProvider.getFederationKeySet();
	validateFederationKeySet(keySet);
	const now = nowSeconds(options?.clock);
	const ttl = rpConfig.entityConfigurationTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS;
	const candidateRequest = await signEntityStatement(
		{
			iss: rpConfig.entityId,
			sub: rpConfig.entityId,
			aud: discovery.entityId,
			iat: now,
			exp: now + ttl,
			jwks: keySet.jwks,
			authority_hints: rpConfig.authorityHints,
			metadata: rpConfig.metadata,
			...(rpConfig.trustMarks?.length ? { trust_marks: rpConfig.trustMarks } : {}),
		},
		keySet.signer,
		{ typ: JwtTyp.EntityStatement },
	);
	const sharedChains = await selectSharedRegistrationTrustChains(
		rpConfig.entityId,
		discovery.entityId as EntityId,
		discovery.trustChain,
		trustAnchors,
		options,
		async (statements) => {
			const validation = await validateTrustChain(statements, trustAnchors, {
				...options,
				explicitRegistrationRequest: { jwt: candidateRequest, audience: discovery.entityId },
			});
			if (!validation.valid) return validation;
			const superior = validation.chain.statements[1]?.payload.iss;
			const resolved = validation.chain.resolvedMetadata;
			if (
				!rpConfig.authorityHints.some((hint) => String(hint) === String(superior)) ||
				!OpenIDRelyingPartyMetadataSchema.safeParse(resolved.openid_relying_party).success ||
				Object.keys(resolved).length !== Object.keys(rpConfig.metadata).length ||
				!Object.keys(rpConfig.metadata).every((type) => Object.hasOwn(resolved, type))
			) {
				return {
					valid: false,
					errors: [
						{
							code: InternalErrorCode.MetadataPolicyViolation,
							message: "RP path is incompatible with the registration request",
						},
					],
				} as const;
			}
			return validation;
		},
	);
	if (!sharedChains.ok) return err(sharedChains.error);

	const opMeta = sharedChains.value.opChain.resolvedMetadata.openid_provider as
		| Record<string, unknown>
		| undefined;
	const registrationTypes = getRegistrationTypes(opMeta);
	if (!registrationTypes.includes(ClientRegistrationType.Explicit)) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"OP does not support explicit registration",
			),
		);
	}

	const registrationEndpoint = opMeta?.federation_registration_endpoint as string | undefined;
	if (!registrationEndpoint) {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				"OP has no federation_registration_endpoint in openid_provider metadata",
			),
		);
	}

	const selectedTrustAnchorId = sharedChains.value.trustAnchorId;
	// Federation §12.2.1 permits selecting a single shared-anchor path.
	const authorityHints = [sharedChains.value.rpChain.statements[1]?.payload.iss as string];
	const rpChainStatements = [...sharedChains.value.rpChainStatements];

	const ecPayload: Record<string, unknown> = {
		iss: rpConfig.entityId,
		sub: rpConfig.entityId,
		aud: discovery.entityId,
		iat: now,
		exp: now + ttl,
		jwks: keySet.jwks,
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

	const ecJwt = await signEntityStatement(ecPayload, keySet.signer, {
		typ: JwtTyp.EntityStatement,
		...(Object.keys(extraHeaders).length > 0 ? { extraHeaders } : {}),
	});

	const httpClient = options?.httpClient ?? fetch;
	const request = new Request(registrationEndpoint, {
		method: "POST",
		headers: {
			"Content-Type": MediaType.EntityStatement,
		},
		body: ecJwt,
	});

	const response = await httpClient(request);
	if (response.status !== 200) {
		// Intentionally omit response body to avoid leaking OP internals
		return err(
			federationError(
				InternalErrorCode.Network,
				`Explicit registration failed (HTTP ${response.status})`,
			),
		);
	}

	const responseContentType = response.headers.get("Content-Type");
	if (!isExactContentType(responseContentType, OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE)) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Explicit registration response Content-Type must be '${OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE}'`,
			),
		);
	}

	const responseJwt = await response.text();

	// Verify using the subordinate statement's JWKS (not the self-signed EC)
	// because the OP's signing key authority comes from its superior in the chain.
	// The subordinate statement about the OP is the one where sub === OP entity ID and iss !== sub.
	// In a properly-ordered chain [leaf_EC, sub_stmt_from_superior, ..., TA_EC],
	// this is always opStatements[1] for the OP's chain.
	const opStatements = sharedChains.value.opChain.statements;
	const subordinateStmt =
		opStatements.length > 1
			? (opStatements[1] as (typeof opStatements)[0])
			: (opStatements[0] as (typeof opStatements)[0]);
	const opJwks = subordinateStmt.payload.jwks;

	if (!opJwks) {
		return err(
			federationError(
				InternalErrorCode.TrustChainInvalid,
				"OP trust chain has no JWKS — cannot verify registration response signature",
			),
		);
	}

	const verifyResult = await verifyEntityStatement(responseJwt, opJwks, {
		expectedTyp: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE,
		...(options?.clock ? { clock: options.clock } : {}),
		...(options?.clockSkewSeconds !== undefined
			? { clockSkewSeconds: options.clockSkewSeconds }
			: {}),
	});
	if (!verifyResult.ok) {
		return err(
			federationError(
				InternalErrorCode.SignatureInvalid,
				"Registration response signature verification failed",
			),
		);
	}

	const decoded = decodeEntityStatement(responseJwt);
	if (!decoded.ok) {
		return err(
			federationError(
				InternalErrorCode.TrustChainInvalid,
				"Failed to decode registration response",
			),
		);
	}

	if (decoded.value.header.typ !== OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Invalid response typ: expected '${OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE}'`,
			),
		);
	}

	const responsePayload = decoded.value.payload as Record<string, unknown>;
	const criticalClaims = validateCriticalClaims(responsePayload, options?.understoodCriticalClaims);
	if (!criticalClaims.ok) return criticalClaims;

	if (responsePayload.iss !== (discovery.entityId as string)) {
		return err(
			federationError(FederationErrorCode.InvalidIssuer, "Response iss does not match OP"),
		);
	}

	if (responsePayload.sub === undefined) {
		return err(
			federationError(
				FederationErrorCode.InvalidSubject,
				"Registration response missing required 'sub' claim",
			),
		);
	}

	if (responsePayload.sub !== (rpConfig.entityId as string)) {
		return err(
			federationError(FederationErrorCode.InvalidSubject, "Response sub does not match RP"),
		);
	}

	if (responsePayload.aud !== (rpConfig.entityId as string)) {
		return err(
			federationError(FederationErrorCode.InvalidSubject, "Response aud does not match RP"),
		);
	}

	// iat and exp are REQUIRED in the registration response
	const responseExp = responsePayload.exp as number | undefined;
	if (responseExp === undefined) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Registration response missing required 'exp' claim",
			),
		);
	}
	const responseNow = nowSeconds(options?.clock);
	if (responseNow >= responseExp) {
		return err(federationError(InternalErrorCode.Expired, "Registration response has expired"));
	}

	const responseIat = responsePayload.iat as number | undefined;
	if (responseIat === undefined) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Registration response missing required 'iat' claim",
			),
		);
	}

	const timeClaims = validateEntityStatementTimeClaims(responsePayload, options);
	if (!timeClaims.ok)
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Registration response ${timeClaims.error.description}`,
			),
		);

	const trustAnchor = responsePayload.trust_anchor as string | undefined;
	if (!trustAnchor || !trustAnchors.has(trustAnchor as EntityId)) {
		return err(
			federationError(
				FederationErrorCode.InvalidTrustAnchor,
				"Response trust_anchor is not in configured trust anchors",
			),
		);
	}

	if (trustAnchor !== (selectedTrustAnchorId as string)) {
		return err(
			federationError(
				FederationErrorCode.InvalidTrustAnchor,
				"Response trust_anchor does not match OP trust chain root",
			),
		);
	}

	// The response must name the Trust Anchor selected for both RP and OP chains.

	const responseAuthorityHints = responsePayload.authority_hints as string[] | undefined;
	if (!Array.isArray(responseAuthorityHints) || responseAuthorityHints.length !== 1) {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				"Response authority_hints MUST be a single-element array",
			),
		);
	}
	for (const hint of responseAuthorityHints) {
		if (typeof hint !== "string") {
			return err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					"Response authority_hints contains non-string value",
				),
			);
		}
	}
	const expectedAuthorityHint = expectedRegistrationAuthorityHint(
		sharedChains.value.rpChain,
		selectedTrustAnchorId,
	);
	if (responseAuthorityHints[0] !== expectedAuthorityHint) {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				"Response authority_hints does not match selected RP trust chain",
			),
		);
	}

	if (responseExp > sharedChains.value.rpChain.expiresAt) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Registration response exp exceeds selected RP trust chain expiry",
			),
		);
	}

	const responseMeta = responsePayload.metadata as
		| Record<string, Record<string, unknown>>
		| undefined;
	if (!responseMeta || typeof responseMeta !== "object") {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				"Registration response missing required 'metadata' claim",
			),
		);
	}
	const requestedTypes = new Set(Object.keys(rpConfig.metadata));
	const responseTypes = new Set(Object.keys(responseMeta));
	for (const requestedType of requestedTypes) {
		if (!responseTypes.has(requestedType)) {
			return err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					"Response metadata missing requested entity type",
				),
			);
		}
	}
	for (const responseType of responseTypes) {
		if (!requestedTypes.has(responseType)) {
			return err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					"Response metadata contains unrequested entity type",
				),
			);
		}
	}

	if (responsePayload.client_secret !== undefined) {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				"Registration response client_secret MUST be under metadata.openid_relying_party",
			),
		);
	}

	const registeredMetadata = responseMeta.openid_relying_party;
	if (
		!registeredMetadata ||
		typeof registeredMetadata !== "object" ||
		Array.isArray(registeredMetadata)
	) {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				"Registration response metadata MUST contain openid_relying_party",
			),
		);
	}

	const registeredMetadataResult =
		OpenIDRelyingPartyRegistrationResponseMetadataSchema.safeParse(registeredMetadata);
	if (!registeredMetadataResult.success) {
		const issuePaths = registeredMetadataResult.error.issues.map((issue) => issue.path.join("."));
		if (issuePaths.some((path) => path === "client_id")) {
			return err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					"Registration response metadata.openid_relying_party.client_id is required",
				),
			);
		}
		if (issuePaths.some((path) => path === "client_secret")) {
			return err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					"Registration response metadata.openid_relying_party.client_secret MUST be a string",
				),
			);
		}
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				"Registration response metadata.openid_relying_party is invalid",
			),
		);
	}

	const clientId = registeredMetadataResult.data.client_id;
	const clientSecret = registeredMetadataResult.data.client_secret;
	const clientSecretExpiresAt = registeredMetadataResult.data.client_secret_expires_at;
	if (clientSecret !== undefined && clientSecretExpiresAt !== undefined) {
		if (clientSecretExpiresAt < responseExp) {
			return err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					"Registration response client_secret_expires_at must not be earlier than response exp",
				),
			);
		}
	}

	if (
		responsePayload.jwks !== undefined &&
		JSON.stringify(responsePayload.jwks) !== JSON.stringify(keySet.jwks)
	) {
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				"Response jwks MUST be a verbatim copy of the request Entity Configuration jwks",
			),
		);
	}

	// RP must not use the registration past trust chain expiry
	const policyCheck = validateRegistrationMetadataPolicy(
		responseMeta,
		sharedChains.value.rpChain,
		options,
		Object.keys(rpConfig.metadata),
	);
	if (!policyCheck.ok) return policyCheck;
	const trustChainExpiresAt = sharedChains.value.opChain.expiresAt;

	const result: ExplicitRegistrationResult = {
		registrationStatement: decoded.value,
		clientId,
		expiresAt: responsePayload.exp as number,
		registeredMetadata,
		trustChainExpiresAt,
	};
	if (clientSecret !== undefined) {
		return ok({ ...result, clientSecret });
	}
	return ok(result);
}

function expectedRegistrationAuthorityHint(
	rpChain: { readonly statements: readonly { readonly payload: Record<string, unknown> }[] },
	trustAnchorId: EntityId,
): string {
	const superiorStatement = rpChain.statements[1];
	if (!superiorStatement) return trustAnchorId as string;
	return superiorStatement.payload.iss as string;
}
