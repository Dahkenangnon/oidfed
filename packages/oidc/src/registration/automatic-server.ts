/** Provider-side automatic registration using authenticated client federation evidence. */

import {
	type ClientAttestationError,
	type Clock,
	DEFAULT_CLOCK_SKEW_SECONDS,
	type EntityId,
	err,
	FederationErrorCode,
	type FederationOptions,
	type FederationStorage,
	federationError,
	InternalErrorCode,
	nowSeconds,
	ok,
	type ReplayStore,
	type ResolvedEntityKeys,
	type Result,
	requireReplayStorage,
	resolveEntityKeys,
	runAsyncOperation,
	safeLogger,
	type TrustAnchorSet,
	type ValidatedTrustChain,
	verifyProtocolJwt,
} from "@oidfed/core";
import { effectiveMetadata } from "../metadata-validation.js";
import {
	checkRegistrationAccreditation,
	type RegistrationAccreditationPolicy,
} from "./accreditation.js";
import { registrationProfile } from "./profile.js";
import { validateAutomaticRegistrationRequest } from "./request-object.js";
import { requestObjectAlgorithms } from "./request-policy.js";
import {
	requireNonEmptyTrustAnchors,
	resolveAndValidateBestChain,
	validateSuppliedTrustChain,
} from "./trust-chains.js";

/** Context for OP-side automatic registration processing */
export interface AutomaticRegistrationContext {
	/** The OP's own Entity Identifier */
	readonly opEntityId: EntityId;
	/**
	 * strict requires an explicitly typed Request Object (default).
	 * compatible also permits generic JWT typing or an absent typ under RFC 9101 §10.8.
	 */
	readonly requestObjectTyping?: "strict" | "compatible";
	/** Maximum encoded size of the Request Object. */
	readonly maxCompactBytes?: number | undefined;
	/** Maximum allowed clock skew in seconds (default: 60) */
	readonly clockSkewSeconds?: number;
	/** NumericDate clock used for expiry validation. */
	readonly clock?: Clock;
}

export interface ProcessedRegistration {
	readonly rpEntityId: EntityId;
	readonly resolvedRpMetadata: Readonly<Record<string, unknown>>;
	readonly trustChain: ValidatedTrustChain;
	/**
	 * When the Request Object carried a `peer_trust_chain` JWS header, the
	 * OP's resolved metadata as derived from the RP-supplied peer chain.
	 * Integrators may use these RP-chosen values when creating the client
	 * registration; the library validates structural integrity but does not
	 * auto-apply the values.
	 */
	readonly peerResolvedOpMetadata?: Readonly<Record<string, unknown>>;
}

/** Automatic registration retains the protocol keys used to verify its Request Object. */
export interface ProcessedAutomaticRegistration extends ProcessedRegistration {
	readonly protocolKeys: ResolvedEntityKeys;
	/** Acceptance deadline, including JWT clock skew and unextended trust expiry. */
	readonly authenticationExpiresAt: number;
}

export interface AutomaticRegistrationProcessingInput
	extends FederationOptions,
		RegistrationAccreditationPolicy {
	/** The OP's Entity Identifier, REQUIRED for `aud` validation to prevent cross-OP replay. */
	opEntityId: EntityId;
	/** Atomic replay protection for one-time Request Objects. */
	readonly storage: FederationStorage & { readonly replay: ReplayStore };
	/** Request Object typing policy. Defaults to strict; compatible permits legacy JWT headers. */
	requestObjectTyping?: AutomaticRegistrationContext["requestObjectTyping"];
	/** Server role selecting the registration protocol. Defaults to OIDC. */
	providerMetadataType?: "openid_provider" | "oauth_authorization_server";
	/** Effective provider metadata when supplied by a role or host. */
	providerMetadata?: Readonly<Record<string, unknown>>;
}

/**
 * OP-side processing of an automatic registration Request Object.
 *
 * Validates the Request Object JWT claims, resolves the RP's trust chain,
 * verifies the JWT signature, and extracts resolved RP metadata.
 */
export async function processAutomaticRegistration(
	requestObjectJwt: string,
	trustAnchors: TrustAnchorSet | undefined,
	options: AutomaticRegistrationProcessingInput,
	beforeReplay?: (
		registration: ProcessedAutomaticRegistration,
	) => Promise<Result<void, ClientAttestationError>>,
): Promise<Result<ProcessedAutomaticRegistration, ClientAttestationError>> {
	let replay: ReplayStore;
	try {
		replay = requireReplayStorage(options.storage, "Automatic registration");
	} catch {
		return err(
			federationError(
				FederationErrorCode.ServerError,
				"Automatic registration requires replay storage",
			),
		);
	}
	const profile = registrationProfile(options.providerMetadataType);
	safeLogger(options?.logger)?.debug("Validating an Automatic Client Registration Request Object");

	const trustAnchorsResult = requireNonEmptyTrustAnchors(trustAnchors);
	if (!trustAnchorsResult.ok) return trustAnchorsResult;
	const configuredTrustAnchors = trustAnchorsResult.value;

	const validated = validateAutomaticRegistrationRequest(requestObjectJwt, {
		maxCompactBytes: options.maxCompactBytes,
		opEntityId: options.opEntityId,
		...(options.requestObjectTyping !== undefined
			? { requestObjectTyping: options.requestObjectTyping }
			: {}),
		...(options.clockSkewSeconds !== undefined
			? { clockSkewSeconds: options.clockSkewSeconds }
			: {}),
		...(options.clock ? { clock: options.clock } : {}),
	});
	if (!validated.ok) return validated;

	const rpEntityId = validated.value.rpEntityId;
	const bestChainResult =
		validated.value.trustChainHeader !== undefined
			? await validateSuppliedTrustChain(validated.value.trustChainHeader, configuredTrustAnchors, {
					...options,
					expectedSubject: rpEntityId,
					label: "trust_chain",
				})
			: await resolveAndValidateBestChain(rpEntityId, configuredTrustAnchors, options, profile);
	if (!bestChainResult.ok) return bestChainResult;
	const bestChain = bestChainResult.value;

	const client = await registrationClientFromChain(bestChain, options);
	if (!client.ok) return client;
	const { resolvedRpMetadata, protocolKeys } = client.value;

	const algorithms = requestObjectAlgorithms(
		resolvedRpMetadata,
		options.providerMetadata ?? {},
		options.allowedAlgorithms,
		options.algorithmRegistry,
	);
	if (!algorithms.ok) return algorithms;
	const authenticationExpiresAt = Math.min(
		bestChain.expiresAt,
		validated.value.exp + (options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS),
	);
	const registration: ProcessedAutomaticRegistration = { ...client.value, authenticationExpiresAt };
	const verifyResult = await verifyProtocolJwt(
		requestObjectJwt,
		{ keys: protocolKeys.keys },
		{
			// Bind verification to the policy-checked header on this same JWT. An undefined
			// expectation requires absence; it does not accept an arbitrary JWT type.
			...options,
			expectedTyp: validated.value.headerTyp,
			allowedAlgorithms: algorithms.value,
			keyIdPolicy: "single-key",
		},
	);
	if (!verifyResult.ok) {
		safeLogger(options?.logger)?.warn(
			"Automatic Client Registration Request Object signature verification failed",
		);
		return err(
			federationError(
				InternalErrorCode.SignatureInvalid,
				"Request Object signature verification failed",
			),
		);
	}

	let peerResolvedOpMetadata: Readonly<Record<string, unknown>> | undefined;
	const peerHeader = validated.value.peerTrustChainHeader;
	if (peerHeader !== undefined) {
		const peerValidation = await validateSuppliedTrustChain(peerHeader, configuredTrustAnchors, {
			...options,
			expectedSubject: options.opEntityId,
			label: "peer_trust_chain",
		});
		if (!peerValidation.ok) {
			safeLogger(options?.logger)?.warn(
				"Automatic Client Registration peer_trust_chain validation failed",
			);
			return err(peerValidation.error);
		}
		if (
			validated.value.trustChainHeader !== undefined &&
			peerValidation.value.trustAnchorId !== bestChain.trustAnchorId
		) {
			safeLogger(options?.logger)?.warn(
				"trust_chain and peer_trust_chain MUST select the same Trust Anchor",
			);
			return err(
				federationError(
					FederationErrorCode.InvalidTrustChain,
					`peer_trust_chain Trust Anchor ('${peerValidation.value.trustAnchorId}') does not match selected RP Trust Anchor ('${bestChain.trustAnchorId}')`,
				),
			);
		}
		const peerMetadata = effectiveMetadata(
			profile.providerType,
			peerValidation.value.resolvedMetadata[profile.providerType],
			options.opEntityId,
			options,
		);
		if (!peerMetadata.ok) return peerMetadata;
		peerResolvedOpMetadata = peerMetadata.value;
	}

	const accreditation = await checkRegistrationAccreditation(
		bestChain,
		"automatic",
		options,
		options,
	);
	if (!accreditation.ok) return accreditation;

	const current = checkRegistrationAuthentication(registration, options);
	if (!current.ok) return current;
	if (beforeReplay) {
		try {
			const additional = await runAsyncOperation(() => beforeReplay(registration), options);
			if (!additional.ok) return additional;
		} catch {
			return err(
				federationError(
					FederationErrorCode.ServerError,
					"Additional authentication failed or timed out",
				),
			);
		}
	}
	const beforeClaim = checkRegistrationAuthentication(registration, options);
	if (!beforeClaim.ok) return beforeClaim;
	try {
		const accepted = await runAsyncOperation(
			() =>
				replay.useJti({
					issuer: rpEntityId,
					audience: options.opEntityId,
					jti: validated.value.jti,
					expiresAt:
						validated.value.exp + (options?.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS),
				}),
			options,
		);
		if (accepted !== true) {
			safeLogger(options?.logger)?.warn(
				"Automatic Client Registration Request Object jti has already been used",
			);
			return err(
				federationError(
					FederationErrorCode.InvalidRequest,
					"Request Object JTI has already been used (replay detected)",
				),
			);
		}
	} catch {
		safeLogger(options.logger)?.error("Failed to claim Request Object JTI");
		return err(
			federationError(
				FederationErrorCode.ServerError,
				"Request Object replay protection is unavailable",
			),
		);
	}

	const afterClaim = checkRegistrationAuthentication(registration, options);
	if (!afterClaim.ok) return afterClaim;
	safeLogger(options?.logger)?.info("Automatic Client Registration Request validated");
	return ok({
		authenticationExpiresAt,
		protocolKeys,
		rpEntityId,
		resolvedRpMetadata,
		trustChain: bestChain,
		...(peerResolvedOpMetadata !== undefined ? { peerResolvedOpMetadata } : {}),
	});
}

/** Shared effective client metadata and protocol-key resolution for both PAR proof forms. */
export async function registrationClientFromChain(
	bestChain: ValidatedTrustChain,
	options: FederationOptions & Pick<AutomaticRegistrationProcessingInput, "providerMetadataType">,
): Promise<Result<ProcessedAutomaticRegistration>> {
	const profile = registrationProfile(options.providerMetadataType);
	const rpEntityId = bestChain.entityId;

	type LeafStatement = (typeof bestChain.statements)[0];
	type LeafFederationJwks = NonNullable<LeafStatement["payload"]["jwks"]>;
	const leafStatement = bestChain.statements[0] as LeafStatement & {
		payload: LeafStatement["payload"] & { jwks: LeafFederationJwks };
	};
	const federationJwks = leafStatement.payload.jwks;

	const resolvedRpMetadata = bestChain.resolvedMetadata[profile.clientType] ?? {};
	const clientMetadata = effectiveMetadata(
		profile.clientType,
		resolvedRpMetadata,
		undefined,
		options,
	);
	if (!clientMetadata.ok) return clientMetadata;
	const protocolKeysResult = await resolveEntityKeys(resolvedRpMetadata, federationJwks, {
		...options,
		expectedIssuer: rpEntityId,
		expectedOwner: rpEntityId,
	});
	if (!protocolKeysResult.ok) return protocolKeysResult;

	return ok({
		rpEntityId,
		resolvedRpMetadata,
		authenticationExpiresAt: bestChain.expiresAt,
		protocolKeys: protocolKeysResult.value,
		trustChain: bestChain,
	});
}

/** Recheck after asynchronous validation, immediately before the acceptance boundary. */
export function checkRegistrationAuthentication(
	registration: ProcessedAutomaticRegistration,
	options: FederationOptions,
): Result<void> {
	const now = nowSeconds(options.clock);
	return !options.signal?.aborted &&
		Number.isFinite(now) &&
		Number.isFinite(registration.authenticationExpiresAt) &&
		registration.authenticationExpiresAt > now &&
		registration.trustChain.expiresAt > now
		? ok(undefined)
		: err(
				federationError(
					FederationErrorCode.InvalidRequest,
					"Registration authentication expired or was cancelled",
				),
			);
}
