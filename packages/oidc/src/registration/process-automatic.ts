import {
	DEFAULT_CLOCK_SKEW_SECONDS,
	type EntityId,
	err,
	type FederationError,
	FederationErrorCode,
	type FederationOptions,
	federationError,
	InternalErrorCode,
	ok,
	type ReplayStore,
	type ResolvedEntityKeys,
	type Result,
	resolveEntityKeys,
	safeLogger,
	type TrustAnchorSet,
	type ValidatedTrustChain,
	verifyProtocolJwt,
} from "@oidfed/core";
import { RequestObjectTyp } from "../constants.js";
import { effectiveMetadata } from "../metadata.js";
import {
	checkRegistrationAccreditation,
	type RegistrationAccreditationPolicy,
} from "./accreditation.js";
import {
	requireNonEmptyTrustAnchors,
	resolveAndValidateBestChain,
	validateSuppliedTrustChain,
} from "./helpers.js";
import { registrationProfile } from "./profile.js";
import { validateAutomaticRegistrationRequest } from "./validate-request-object.js";

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
}

export interface ProcessAutomaticRegistrationOptions
	extends FederationOptions,
		RegistrationAccreditationPolicy {
	/** The OP's own Entity Identifier — REQUIRED to prevent cross-OP replay via `aud` validation. */
	opEntityId: EntityId;
	/** Server role selecting the registration protocol. Defaults to OIDC. */
	providerMetadataType?: "openid_provider" | "oauth_authorization_server";
	/** Atomic replay protection required for one-time Request Object processing. */
	replayStore: ReplayStore;
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
	options: ProcessAutomaticRegistrationOptions,
): Promise<Result<ProcessedAutomaticRegistration, FederationError>> {
	const profile = registrationProfile(options.providerMetadataType);
	safeLogger(options?.logger)?.debug("Validating an Automatic Client Registration Request Object");

	const trustAnchorsResult = requireNonEmptyTrustAnchors(trustAnchors);
	if (!trustAnchorsResult.ok) return trustAnchorsResult;
	const configuredTrustAnchors = trustAnchorsResult.value;

	const validated = validateAutomaticRegistrationRequest(requestObjectJwt, {
		opEntityId: options.opEntityId,
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

	type LeafStatement = (typeof bestChain.statements)[0];
	type LeafFederationJwks = NonNullable<LeafStatement["payload"]["jwks"]>;
	const leafStatement = bestChain.statements[0] as LeafStatement & {
		payload: LeafStatement["payload"] & { jwks: LeafFederationJwks };
	};
	const federationJwks = leafStatement.payload.jwks;

	const resolvedRpMetadata = bestChain.resolvedMetadata[profile.clientType] ?? {};
	const clientMetadata = effectiveMetadata(profile.clientType, resolvedRpMetadata);
	if (!clientMetadata.ok) return clientMetadata;
	const protocolKeysResult = await resolveEntityKeys(resolvedRpMetadata, federationJwks, {
		...options,
		expectedIssuer: rpEntityId,
		expectedOwner: rpEntityId,
	});
	if (!protocolKeysResult.ok) return protocolKeysResult;

	const verifyResult = await verifyProtocolJwt(
		requestObjectJwt,
		{ keys: protocolKeysResult.value.keys },
		{
			expectedTyp: RequestObjectTyp,
			keyIdPolicy: "single-key",
			...(options.clock ? { clock: options.clock } : {}),
			...(options.clockSkewSeconds !== undefined
				? { clockSkewSeconds: options.clockSkewSeconds }
				: {}),
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

	try {
		const accepted = await options.replayStore.useJti({
			issuer: rpEntityId,
			audience: options.opEntityId,
			jti: validated.value.jti,
			expiresAt: validated.value.exp + (options?.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS),
		});
		if (!accepted) {
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

	safeLogger(options?.logger)?.info("Automatic Client Registration Request validated");
	return ok({
		protocolKeys: protocolKeysResult.value,
		rpEntityId,
		resolvedRpMetadata,
		trustChain: bestChain,
		...(peerResolvedOpMetadata !== undefined ? { peerResolvedOpMetadata } : {}),
	});
}
