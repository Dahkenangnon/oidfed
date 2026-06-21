import {
	type EntityId,
	err,
	type FederationError,
	FederationErrorCode,
	type FederationOptions,
	federationError,
	InternalErrorCode,
	ok,
	type ReplayStore,
	type Result,
	resolveEntityKeys,
	type TrustAnchorSet,
	type ValidatedTrustChain,
	validateTrustChain,
	verifyEntityStatement,
} from "@oidfed/core";
import { RequestObjectTyp } from "../constants.js";
import { resolveAndValidateBestChain } from "./helpers.js";
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

export interface ProcessAutomaticRegistrationOptions extends FederationOptions {
	/** The OP's own Entity Identifier — REQUIRED to prevent cross-OP replay via `aud` validation. */
	opEntityId: EntityId;
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
	trustAnchors: TrustAnchorSet,
	options: ProcessAutomaticRegistrationOptions,
): Promise<Result<ProcessedRegistration, FederationError>> {
	const validated = validateAutomaticRegistrationRequest(requestObjectJwt, {
		opEntityId: options.opEntityId,
		...(options.clockSkewSeconds !== undefined
			? { clockSkewSeconds: options.clockSkewSeconds }
			: {}),
	});
	if (!validated.ok) return validated;

	const rpEntityId = validated.value.rpEntityId;
	const bestChainResult = await resolveAndValidateBestChain(rpEntityId, trustAnchors, options);
	if (!bestChainResult.ok) return bestChainResult;
	const bestChain = bestChainResult.value;

	const leafStatement = bestChain.statements[0] as (typeof bestChain.statements)[0];
	const federationJwks = leafStatement.payload.jwks;
	if (!federationJwks) {
		return err(
			federationError(
				InternalErrorCode.SignatureInvalid,
				"RP Entity Configuration has no federation jwks — cannot resolve OIDC protocol keys",
			),
		);
	}

	const resolvedRpMetadata = bestChain.resolvedMetadata.openid_relying_party ?? {};
	const protocolKeysResult = await resolveEntityKeys(resolvedRpMetadata, federationJwks, options);
	if (!protocolKeysResult.ok) return protocolKeysResult;

	const verifyResult = await verifyEntityStatement(
		requestObjectJwt,
		{ keys: protocolKeysResult.value.keys },
		{
			expectedTyp: RequestObjectTyp,
		},
	);
	if (!verifyResult.ok) {
		return err(
			federationError(
				InternalErrorCode.SignatureInvalid,
				"Request Object signature verification failed",
			),
		);
	}

	if (Object.keys(resolvedRpMetadata).length > 0) {
		const { OpenIDRelyingPartyMetadataSchema } = await import("../schemas/metadata.js");
		const metaParsed = OpenIDRelyingPartyMetadataSchema.safeParse(resolvedRpMetadata);
		if (!metaParsed.success) {
			return err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					"RP metadata does not comply with the OpenID Connect Relying Party metadata schema",
				),
			);
		}
	}

	let peerResolvedOpMetadata: Readonly<Record<string, unknown>> | undefined;
	const peerHeader = validated.value.peerTrustChainHeader;
	if (peerHeader && peerHeader.length > 0) {
		const peerValidation = await validateTrustChain([...peerHeader], trustAnchors, options);
		if (!peerValidation.valid) {
			return err(
				federationError(
					InternalErrorCode.TrustChainInvalid,
					`peer_trust_chain validation failed: ${
						peerValidation.errors[0]?.message ?? "unknown error"
					}`,
				),
			);
		}
		peerResolvedOpMetadata = peerValidation.chain.resolvedMetadata.openid_provider ?? {};
	}

	try {
		const accepted = await options.replayStore.useJti({
			issuer: rpEntityId,
			audience: options.opEntityId,
			jti: validated.value.jti,
			expiresAt: validated.value.exp,
		});
		if (!accepted) {
			return err(
				federationError(
					FederationErrorCode.InvalidRequest,
					"Request Object JTI has already been used (replay detected)",
				),
			);
		}
	} catch (error) {
		options.logger?.error("Failed to claim Request Object JTI", { error });
		return err(
			federationError(
				FederationErrorCode.ServerError,
				"Request Object replay protection is unavailable",
			),
		);
	}

	return ok({
		rpEntityId,
		resolvedRpMetadata,
		trustChain: bestChain,
		...(peerResolvedOpMetadata !== undefined ? { peerResolvedOpMetadata } : {}),
	});
}
