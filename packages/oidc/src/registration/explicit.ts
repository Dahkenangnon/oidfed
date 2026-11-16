/** Client-side explicit registration with trusted provider discovery and signed-response checks. */

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
	safeLogger,
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
import { registrationResponseChoices } from "../metadata.js";
import {
	getRegistrationTypes,
	registrationChainHeaders,
	selectSharedRegistrationTrustChains,
} from "./helpers.js";
import { validateRegistrationMetadataPolicy } from "./metadata-policy.js";
import { oidcRegistrationProfile, type RegistrationProfile } from "./profile.js";

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
	providerDiscovery: "supplied" | "resolved" = "supplied",
	profile: RegistrationProfile = oidcRegistrationProfile,
): Promise<Result<ExplicitRegistrationResult>> {
	safeLogger(options?.logger)?.debug("Creating an Explicit Client Registration Request");

	const keySet = await rpConfig.keyProvider.getFederationKeySet();
	validateFederationKeySet(keySet);
	const now = nowSeconds(options?.clock);
	const ttl = rpConfig.entityConfigurationTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS;
	let candidateRequest: string | undefined;
	const makeCandidateRequest = () =>
		signEntityStatement(
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
		{
			validateRpCandidate: async (statements, validationOptions) => {
				candidateRequest ??= await makeCandidateRequest();
				const validation = await validateTrustChain(statements, trustAnchors, {
					...validationOptions,
					explicitRegistrationRequest: { jwt: candidateRequest, audience: discovery.entityId },
				});
				if (!validation.valid) return validation;
				const superior = validation.chain.statements[1]?.payload.iss;
				const resolved = validation.chain.resolvedMetadata;
				if (
					!rpConfig.authorityHints.some((hint) => String(hint) === String(superior)) ||
					!profile.clientSchema.safeParse(resolved[profile.clientType]).success ||
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
			allowAlternativeProvider: providerDiscovery === "resolved",
			profile,
		},
	);
	if (!sharedChains.ok) return err(sharedChains.error);

	const opMeta = sharedChains.value.opChain.resolvedMetadata[profile.providerType] as
		| Record<string, unknown>
		| undefined;
	const registrationTypes = getRegistrationTypes(opMeta);
	if (!registrationTypes.includes(ClientRegistrationType.Explicit)) {
		safeLogger(options?.logger)?.warn("OP does not support Explicit Client Registration");
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"OP does not support explicit registration",
			),
		);
	}

	const registrationEndpoint = opMeta?.federation_registration_endpoint as string | undefined;
	if (!registrationEndpoint) {
		safeLogger(options?.logger)?.warn("OP metadata is missing federation_registration_endpoint");
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				`OP has no federation_registration_endpoint in ${profile.providerType} metadata`,
			),
		);
	}

	// Federation §5.1.3 applies to the effective endpoint, before any POST.
	try {
		const endpoint = new URL(registrationEndpoint);
		if (endpoint.protocol !== "https:" || endpoint.href.includes("#")) throw new Error();
	} catch {
		safeLogger(options?.logger)?.warn(
			"federation_registration_endpoint must use HTTPS without a fragment",
		);
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				"federation_registration_endpoint must be an HTTPS URL without a fragment",
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

	const headers = await registrationChainHeaders(
		rpChainStatements,
		selectedTrustAnchorId,
		discovery.entityId as EntityId,
		rpConfig.includePeerTrustChain,
		trustAnchors,
		options,
	);
	if (!headers.ok) return headers;
	const extraHeaders = headers.value;

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
		safeLogger(options?.logger)?.warn("Explicit Client Registration response must use HTTP 200");
		return err(
			federationError(
				InternalErrorCode.Network,
				`Explicit registration failed (HTTP ${response.status})`,
			),
		);
	}

	const responseContentType = response.headers.get("Content-Type");
	if (!isExactContentType(responseContentType, OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE)) {
		safeLogger(options?.logger)?.warn(
			"Explicit Client Registration response Content-Type must be application/explicit-registration-response+jwt",
		);
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
		safeLogger(options?.logger)?.warn(
			"OP Trust Chain has no keys to verify the Explicit Client Registration response",
		);
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
		safeLogger(options?.logger)?.warn(
			"Explicit Client Registration response signature verification failed",
		);
		return err(
			federationError(
				InternalErrorCode.SignatureInvalid,
				"Registration response signature verification failed",
			),
		);
	}

	const decoded = decodeEntityStatement(responseJwt);
	if (!decoded.ok) {
		safeLogger(options?.logger)?.warn("Failed to decode the Explicit Client Registration response");
		return err(
			federationError(
				InternalErrorCode.TrustChainInvalid,
				"Failed to decode registration response",
			),
		);
	}

	if (decoded.value.header.typ !== OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE) {
		safeLogger(options?.logger)?.warn(
			"Explicit Client Registration response typ must be explicit-registration-response+jwt",
		);
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
		safeLogger(options?.logger)?.warn(
			"Explicit Client Registration response iss does not match the OP Entity Identifier",
		);
		return err(
			federationError(FederationErrorCode.InvalidIssuer, "Response iss does not match OP"),
		);
	}

	if (responsePayload.sub === undefined) {
		safeLogger(options?.logger)?.warn("Explicit Client Registration response is missing sub");
		return err(
			federationError(
				FederationErrorCode.InvalidSubject,
				"Registration response missing required 'sub' claim",
			),
		);
	}

	if (responsePayload.sub !== (rpConfig.entityId as string)) {
		safeLogger(options?.logger)?.warn(
			"Explicit Client Registration response sub does not match the RP Entity Identifier",
		);
		return err(
			federationError(FederationErrorCode.InvalidSubject, "Response sub does not match RP"),
		);
	}

	if (responsePayload.aud !== (rpConfig.entityId as string)) {
		safeLogger(options?.logger)?.warn(
			"Explicit Client Registration response aud does not match the RP Entity Identifier",
		);
		return err(
			federationError(FederationErrorCode.InvalidSubject, "Response aud does not match RP"),
		);
	}

	// iat and exp are REQUIRED in the registration response
	const responseExp = responsePayload.exp as number | undefined;
	if (responseExp === undefined) {
		safeLogger(options?.logger)?.warn("Explicit Client Registration response is missing exp");
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Registration response missing required 'exp' claim",
			),
		);
	}
	const responseNow = nowSeconds(options?.clock);
	if (responseNow >= responseExp) {
		safeLogger(options?.logger)?.warn("Explicit Client Registration response has expired");
		return err(federationError(InternalErrorCode.Expired, "Registration response has expired"));
	}

	const responseIat = responsePayload.iat as number | undefined;
	if (responseIat === undefined) {
		safeLogger(options?.logger)?.warn("Explicit Client Registration response is missing iat");
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
		safeLogger(options?.logger)?.warn(
			"Explicit Client Registration response trust_anchor is not a configured Trust Anchor",
		);
		return err(
			federationError(
				FederationErrorCode.InvalidTrustAnchor,
				"Response trust_anchor is not in configured trust anchors",
			),
		);
	}

	if (trustAnchor !== (selectedTrustAnchorId as string)) {
		safeLogger(options?.logger)?.warn(
			"Explicit Client Registration response trust_anchor does not match the selected Trust Anchor",
		);
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
		safeLogger(options?.logger)?.warn(
			"Explicit Client Registration response authority_hints MUST be a single-element array",
		);
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				"Response authority_hints MUST be a single-element array",
			),
		);
	}
	for (const hint of responseAuthorityHints) {
		if (typeof hint !== "string") {
			safeLogger(options?.logger)?.warn(
				"Explicit Client Registration response authority_hints contains a non-string value",
			);
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
		safeLogger(options?.logger)?.warn(
			"Explicit Client Registration response authority_hints does not match the selected RP Trust Chain",
		);
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				"Response authority_hints does not match selected RP trust chain",
			),
		);
	}

	if (responseExp > sharedChains.value.rpChain.expiresAt) {
		safeLogger(options?.logger)?.warn(
			"Explicit Client Registration response exp exceeds the selected RP Trust Chain expiry",
		);
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
		safeLogger(options?.logger)?.warn("Explicit Client Registration response is missing metadata");
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
			safeLogger(options?.logger)?.warn(
				"Explicit Client Registration response metadata is missing a requested Entity Type",
			);
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
			safeLogger(options?.logger)?.warn(
				"Explicit Client Registration response metadata contains an unrequested Entity Type",
			);
			return err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					"Response metadata contains unrequested entity type",
				),
			);
		}
	}

	if (responsePayload.client_secret !== undefined) {
		safeLogger(options?.logger)?.warn(
			`Explicit Client Registration response client_secret MUST be under metadata.${profile.clientType}`,
		);
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				`Registration response client_secret MUST be under metadata.${profile.clientType}`,
			),
		);
	}

	const registeredMetadata = responseMeta[profile.clientType];
	if (
		!registeredMetadata ||
		typeof registeredMetadata !== "object" ||
		Array.isArray(registeredMetadata)
	) {
		safeLogger(options?.logger)?.warn(
			`Explicit Client Registration response metadata MUST contain ${profile.clientType}`,
		);
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				`Registration response metadata MUST contain ${profile.clientType}`,
			),
		);
	}

	const registeredMetadataResult = profile.responseMetadataSchema.safeParse(registeredMetadata);
	if (!registeredMetadataResult.success) {
		const issuePaths = registeredMetadataResult.error.issues.map((issue) => issue.path.join("."));
		if (issuePaths.some((path) => path === "client_id")) {
			safeLogger(options?.logger)?.warn(
				`Explicit Client Registration response metadata.${profile.clientType}.client_id is required`,
			);
			return err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					`Registration response metadata.${profile.clientType}.client_id is required`,
				),
			);
		}
		if (issuePaths.some((path) => path === "client_secret")) {
			safeLogger(options?.logger)?.warn(
				`Explicit Client Registration response metadata.${profile.clientType}.client_secret MUST be a string`,
			);
			return err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					`Registration response metadata.${profile.clientType}.client_secret MUST be a string`,
				),
			);
		}
		safeLogger(options?.logger)?.warn(
			`Explicit Client Registration response metadata.${profile.clientType} is invalid`,
		);
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				`Registration response metadata.${profile.clientType} is invalid`,
			),
		);
	}

	const clientId = registeredMetadataResult.data.client_id;
	const clientSecret = registeredMetadataResult.data.client_secret;
	const clientSecretExpiresAt = registeredMetadataResult.data.client_secret_expires_at;
	if (clientSecret !== undefined && clientSecretExpiresAt !== undefined) {
		if (clientSecretExpiresAt !== 0 && clientSecretExpiresAt < responseExp) {
			safeLogger(options?.logger)?.warn(
				"Explicit Client Registration response client_secret_expires_at is earlier than exp",
			);
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
		safeLogger(options?.logger)?.warn(
			"Explicit Client Registration response jwks MUST be a verbatim copy of the RP Entity Configuration jwks",
		);
		return err(
			federationError(
				FederationErrorCode.InvalidMetadata,
				"Response jwks MUST be a verbatim copy of the request Entity Configuration jwks",
			),
		);
	}

	// RP must not use the registration past trust chain expiry
	const choiceCheck = profile.oidc
		? registrationResponseChoices(
				registeredMetadata,
				sharedChains.value.rpChain.resolvedMetadata[profile.clientType] ?? {},
			)
		: ok(undefined);
	if (!choiceCheck.ok) return choiceCheck;
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
		safeLogger(options?.logger)?.info("Explicit registration completed");
		return ok({ ...result, clientSecret });
	}
	safeLogger(options?.logger)?.info("Explicit registration completed");
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
