/** Provider-side explicit registration and shared-anchor client trust validation. */

import {
	createTrustChainOperation,
	decodeEntityStatement,
	type EntityId,
	err,
	type FederationError,
	FederationErrorCode,
	type FederationOptions,
	federationError,
	InternalErrorCode,
	JwtTyp,
	MediaType,
	ok,
	type Result,
	resolveTrustChains,
	safeLogger,
	selectTrustChain,
	shortestChain,
	type TrustAnchorSet,
	type ValidatedTrustChain,
	validateCriticalClaims,
	validateEntityStatementTimeClaims,
	validateTrustChain,
	verifyEntityStatement,
} from "@oidfed/core";
import { effectiveMetadata } from "../metadata-validation.js";
import {
	checkRegistrationAccreditation,
	type RegistrationAccreditationPolicy,
} from "./accreditation.js";
import type { ProcessedRegistration } from "./automatic-server.js";
import { registrationProfile } from "./profile.js";
import {
	parseTrustChainJsonBody,
	requireNonEmptyTrustAnchors,
	validateSuppliedTrustChain,
} from "./trust-chains.js";

export interface ProcessedExplicitRegistration extends ProcessedRegistration {
	readonly requestPayload: Record<string, unknown>;
	readonly peerResolvedOpMetadata?: Readonly<Record<string, unknown>>;
}

export interface ProcessExplicitRegistrationOptions
	extends FederationOptions,
		RegistrationAccreditationPolicy {
	/** The OP's Entity Identifier, REQUIRED for `aud` validation. */
	opEntityId: EntityId;
	/** Protocol role of the local server whose peer metadata is consumed. Defaults to OP. */
	providerMetadataType?: "openid_provider" | "oauth_authorization_server";
	/** Optional `trust_chain` JWS header value supplied with an entity-statement body. */
	trustChainHeader?: readonly string[];
}

/**
 * OP-side processing of an explicit registration request.
 *
 * Authenticates the submitted EC with its own keys and each candidate's
 * attested federation keys, then selects a path with valid resolved RP metadata.
 *
 * The caller caps registration expiry to `trustChain.expiresAt` (§12.2.2).
 */
export async function processExplicitRegistration(
	requestBody: string,
	contentType: string,
	trustAnchors: TrustAnchorSet | undefined,
	options: ProcessExplicitRegistrationOptions,
): Promise<Result<ProcessedExplicitRegistration, FederationError>> {
	const profile = registrationProfile(options.providerMetadataType);
	safeLogger(options?.logger)?.debug("Validating an Explicit Client Registration Request");

	const trustAnchorsResult = requireNonEmptyTrustAnchors(trustAnchors);
	if (!trustAnchorsResult.ok) return trustAnchorsResult;
	const configuredTrustAnchors = trustAnchorsResult.value;
	const operation = createTrustChainOperation(options);
	if (!operation.ok) return operation;
	options = { ...options, ...operation.value.options };

	if (contentType !== MediaType.EntityStatement && contentType !== MediaType.TrustChain) {
		safeLogger(options?.logger)?.warn(
			"Explicit Client Registration Request requires application/entity-statement+jwt or application/trust-chain+json",
		);
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Unsupported Content-Type. Expected '${MediaType.EntityStatement}' or '${MediaType.TrustChain}'`,
			),
		);
	}

	let rpEcJwt: string;
	let suppliedTrustChain: readonly string[] | undefined;
	let suppliedTrustChainLabel: "trust-chain+json" | "trust_chain" | undefined;

	if (contentType === MediaType.TrustChain) {
		const parseResult = parseTrustChainJsonBody(requestBody);
		if (!parseResult.ok) return parseResult;
		suppliedTrustChain = parseResult.value;
		suppliedTrustChainLabel = "trust-chain+json";
		rpEcJwt = suppliedTrustChain[0] as string;
	} else {
		suppliedTrustChain = options.trustChainHeader;
		suppliedTrustChainLabel = options.trustChainHeader !== undefined ? "trust_chain" : undefined;
		rpEcJwt = requestBody;
	}

	const decoded = decodeEntityStatement(rpEcJwt, options);
	if (!decoded.ok) {
		safeLogger(options?.logger)?.warn("Failed to decode the RP Entity Configuration");
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Failed to decode RP Entity Configuration",
			),
		);
	}

	const payload = decoded.value.payload as Record<string, unknown>;

	const rpEntityId = payload.iss as string as EntityId;
	if (!rpEntityId) {
		safeLogger(options?.logger)?.warn("RP Entity Configuration is missing iss");
		return err(federationError(FederationErrorCode.InvalidRequest, "RP EC missing 'iss' claim"));
	}

	const timeClaims = validateEntityStatementTimeClaims(payload, options);
	if (!timeClaims.ok)
		return err(federationError(FederationErrorCode.InvalidRequest, timeClaims.error.description));

	if (payload.sub !== payload.iss) {
		safeLogger(options?.logger)?.warn("RP Entity Configuration iss MUST equal sub");
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"RP EC 'iss' MUST equal 'sub' in Entity Configuration",
			),
		);
	}

	// aud is REQUIRED and MUST match OP Entity Identifier
	const aud = payload.aud;
	if (!aud) {
		safeLogger(options?.logger)?.warn("Explicit Client Registration Request is missing aud");
		return err(
			federationError(FederationErrorCode.InvalidRequest, "RP EC missing required 'aud' claim"),
		);
	}
	if (aud !== (options.opEntityId as string)) {
		safeLogger(options?.logger)?.warn(
			"Explicit Client Registration Request aud does not match the OP Entity Identifier",
		);
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"RP EC 'aud' does not match OP Entity Identifier",
			),
		);
	}

	// authority_hints is REQUIRED
	const authorityHints = payload.authority_hints;
	if (
		!Array.isArray(authorityHints) ||
		authorityHints.length === 0 ||
		!authorityHints.every((h) => typeof h === "string")
	) {
		safeLogger(options?.logger)?.warn(
			"Explicit Client Registration Request authority_hints MUST be a non-empty array of strings",
		);
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"RP EC 'authority_hints' MUST be a non-empty array of strings",
			),
		);
	}

	// The selected profile's client metadata is REQUIRED.
	const metadata = payload.metadata as Record<string, unknown> | undefined;
	if (!metadata || typeof metadata !== "object" || !metadata[profile.clientType]) {
		safeLogger(options?.logger)?.warn(
			`Explicit Client Registration Request MUST contain metadata.${profile.clientType}`,
		);
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Client EC MUST contain metadata.${profile.clientType}`,
			),
		);
	}

	const requestShape = profile.request.safeParse(payload);
	if (!requestShape.success) {
		safeLogger(options?.logger)?.warn(
			"Explicit Client Registration Request payload has invalid claims",
		);
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Invalid registration request payload: ${requestShape.error.issues.map((issue) => issue.path.join(".")).join(", ")}`,
			),
		);
	}
	const criticalClaims = validateCriticalClaims(payload, options.understoodCriticalClaims);
	if (!criticalClaims.ok) return criticalClaims;

	const header = decoded.value.header;
	if (contentType === MediaType.EntityStatement && header.trust_chain !== undefined) {
		if (
			options.trustChainHeader !== undefined &&
			JSON.stringify(options.trustChainHeader) !== JSON.stringify(header.trust_chain)
		) {
			safeLogger(options?.logger)?.warn(
				"Explicit Client Registration Request has conflicting trust_chain headers",
			);
			return err(
				federationError(FederationErrorCode.InvalidTrustChain, "Conflicting trust_chain headers"),
			);
		}
		suppliedTrustChain = header.trust_chain as readonly string[];
		suppliedTrustChainLabel = "trust_chain";
	}
	if (
		suppliedTrustChain !== undefined &&
		(!Array.isArray(suppliedTrustChain) ||
			suppliedTrustChain.length === 0 ||
			!suppliedTrustChain.every((s) => typeof s === "string"))
	) {
		safeLogger(options?.logger)?.warn("trust_chain must be a non-empty array of JWT strings");
		return err(
			federationError(
				FederationErrorCode.InvalidTrustChain,
				"trust_chain must be a non-empty array of JWT strings",
			),
		);
	}
	if (
		contentType === MediaType.TrustChain &&
		(header.peer_trust_chain !== undefined || header.trust_chain !== undefined)
	) {
		safeLogger(options?.logger)?.warn(
			"trust_chain and peer_trust_chain MUST NOT be used when the request body is a Trust Chain",
		);
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"trust_chain and peer_trust_chain MUST NOT be used when the request body is a Trust Chain",
			),
		);
	}
	if (header.peer_trust_chain !== undefined && suppliedTrustChain === undefined) {
		safeLogger(options?.logger)?.warn(
			"Explicit Client Registration peer_trust_chain requires trust_chain",
		);
		return err(
			federationError(FederationErrorCode.InvalidRequest, "peer_trust_chain requires trust_chain"),
		);
	}

	// Self-signature verification: the RP EC must be signed by a key in its own JWKS
	const rpJwks = payload.jwks as { keys: Array<Record<string, unknown>> } | undefined;
	if (!rpJwks) {
		safeLogger(options?.logger)?.warn(
			"RP Entity Configuration MUST contain jwks for self-signature verification",
		);
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"RP EC MUST contain 'jwks' for self-signature verification",
			),
		);
	}
	// Validate typ header matches entity-statement+jwt
	const selfVerify = await verifyEntityStatement(
		rpEcJwt,
		rpJwks as unknown as Parameters<typeof verifyEntityStatement>[1],
		{
			expectedTyp: JwtTyp.EntityStatement,
			...options,
			artifact: "entity-configuration",
			...(options.clock ? { clock: options.clock } : {}),
			...(options.clockSkewSeconds !== undefined
				? { clockSkewSeconds: options.clockSkewSeconds }
				: {}),
		},
	);
	if (!selfVerify.ok) {
		safeLogger(options?.logger)?.warn("RP Entity Configuration self-signature verification failed");
		return err(
			federationError(
				InternalErrorCode.SignatureInvalid,
				"RP EC self-signature verification failed",
			),
		);
	}

	const discovery =
		suppliedTrustChain !== undefined
			? undefined
			: await resolveTrustChains(rpEntityId, configuredTrustAnchors, {
					...options,
					entityConfigurationJwt: rpEcJwt,
					explicitRegistrationAudience: options.opEntityId,
				});
	const candidates =
		suppliedTrustChain !== undefined
			? [{ statements: suppliedTrustChain, entityConfigurations: options.entityConfigurations }]
			: (discovery?.chains ?? []);
	const validChains: ValidatedTrustChain[] = [];
	let reason = "No valid trust chains found for RP";
	let failureCode: FederationErrorCode = FederationErrorCode.InvalidTrustChain;
	for (const candidate of candidates) {
		if (operation.value.exhausted()) break;
		const validation = await validateTrustChain(candidate.statements, configuredTrustAnchors, {
			...options,
			entityConfigurations: candidate.entityConfigurations,
			verboseErrors: true,
			explicitRegistrationRequest: { jwt: rpEcJwt, audience: options.opEntityId },
		});
		if (validation.valid) {
			const metadata = validation.chain.resolvedMetadata;
			if (
				!profile.clientSchema(options).safeParse(metadata[profile.clientType]).success ||
				Object.keys(metadata).length !== Object.keys(payload.metadata as object).length ||
				Object.keys(payload.metadata as object).some((type) => !Object.hasOwn(metadata, type))
			) {
				failureCode = FederationErrorCode.InvalidMetadata;
				reason = `Resolved metadata must retain the requested entity types and comply with the ${profile.clientType} metadata schema`;
				continue;
			}
			validChains.push(validation.chain);
		} else reason = validation.errors[0]?.message ?? reason;
	}
	if (operation.value.exhausted() || (options.chainSelection && discovery?.incomplete))
		return err(
			federationError(
				FederationErrorCode.InvalidTrustChain,
				"Trust chain discovery was incomplete",
			),
		);
	if (!validChains.length) {
		safeLogger(options?.logger)?.warn(
			"No RP Trust Chain satisfies Explicit Client Registration validation",
		);
		return err(
			federationError(
				failureCode,
				`${suppliedTrustChainLabel ?? "Registration chain"} validation failed: ${reason}`,
			),
		);
	}
	const selection = selectTrustChain(validChains, options, shortestChain);
	if (!selection.ok) return selection;
	const bestChain = selection.value;
	const resolvedRpMetadata = bestChain.resolvedMetadata[profile.clientType];
	let peerResolvedOpMetadata: Readonly<Record<string, unknown>> | undefined;
	if (header.peer_trust_chain !== undefined) {
		const peer = await validateSuppliedTrustChain(
			header.peer_trust_chain as readonly string[],
			configuredTrustAnchors,
			{
				...options,
				expectedSubject: options.opEntityId,
				label: "peer_trust_chain",
			},
		);
		if (!peer.ok) return peer;
		if (peer.value.trustAnchorId !== bestChain.trustAnchorId) {
			safeLogger(options?.logger)?.warn(
				"peer_trust_chain Trust Anchor does not match the selected RP Trust Anchor",
			);
			return err(
				federationError(
					FederationErrorCode.InvalidTrustChain,
					"peer_trust_chain Trust Anchor does not match selected RP Trust Anchor",
				),
			);
		}
		const peerMetadata = effectiveMetadata(
			profile.providerType,
			peer.value.resolvedMetadata[profile.providerType],
			options.opEntityId,
			options,
		);
		if (!peerMetadata.ok) return peerMetadata;
		peerResolvedOpMetadata = peerMetadata.value;
	}
	if (operation.value.exhausted())
		return err(
			federationError(FederationErrorCode.InvalidTrustChain, "Trust chain operation exhausted"),
		);
	const accreditation = await checkRegistrationAccreditation(
		bestChain,
		"explicit",
		options,
		options,
	);
	if (!accreditation.ok) return accreditation;

	safeLogger(options?.logger)?.info("Explicit Client Registration Request validated");
	return ok({
		rpEntityId,
		resolvedRpMetadata: resolvedRpMetadata ?? {},
		trustChain: bestChain,
		requestPayload: payload,
		...(peerResolvedOpMetadata !== undefined ? { peerResolvedOpMetadata } : {}),
	});
}
