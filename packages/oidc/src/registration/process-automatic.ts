import {
	type EntityId,
	err,
	type FederationError,
	FederationErrorCode,
	type FederationOptions,
	federationError,
	InternalErrorCode,
	type JtiStore,
	ok,
	type Result,
	type TrustAnchorSet,
	type ValidatedTrustChain,
	verifyEntityStatement,
} from "@oidfed/core";
import { RequestObjectTyp } from "../constants.js";
import { resolveAndValidateBestChain } from "./helpers.js";
import { validateAutomaticRegistrationRequest } from "./validate-request-object.js";

export interface ProcessedRegistration {
	readonly rpEntityId: EntityId;
	readonly resolvedRpMetadata: Readonly<Record<string, unknown>>;
	readonly trustChain: ValidatedTrustChain;
}

export interface ProcessAutomaticRegistrationOptions extends FederationOptions {
	/** The OP's own Entity Identifier — REQUIRED to prevent cross-OP replay via `aud` validation. */
	opEntityId: EntityId;
	/** Optional JTI store for replay detection. */
	jtiStore?: JtiStore;
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

	if (!options.jtiStore) {
		// JTI replay protection is opt-in via the jtiStore parameter.
		// Callers who need replay protection should provide a JtiStore implementation.
	} else {
		const isReplay = await options.jtiStore.hasSeenAndRecord(
			validated.value.jti,
			validated.value.exp,
		);
		if (isReplay) {
			return err(
				federationError(
					FederationErrorCode.InvalidRequest,
					"Request Object JTI has already been used (replay detected)",
				),
			);
		}
	}

	const rpEntityId = validated.value.rpEntityId;
	const bestChainResult = await resolveAndValidateBestChain(rpEntityId, trustAnchors, options);
	if (!bestChainResult.ok) return bestChainResult;
	const bestChain = bestChainResult.value;

	const leafStatement = bestChain.statements[0] as (typeof bestChain.statements)[0];
	if (!leafStatement.payload.jwks) {
		return err(
			federationError(
				InternalErrorCode.SignatureInvalid,
				"RP Entity Configuration has no jwks — cannot verify signature",
			),
		);
	}
	const verifyResult = await verifyEntityStatement(requestObjectJwt, leafStatement.payload.jwks, {
		expectedTyp: RequestObjectTyp,
	});
	if (!verifyResult.ok) {
		return err(
			federationError(
				InternalErrorCode.SignatureInvalid,
				"Request Object signature verification failed",
			),
		);
	}

	const resolvedRpMetadata = bestChain.resolvedMetadata.openid_relying_party ?? {};

	if (Object.keys(resolvedRpMetadata).length > 0) {
		const { OpenIDRelyingPartyMetadataSchema } = await import("../schemas/metadata.js");
		const metaParsed = OpenIDRelyingPartyMetadataSchema.safeParse(resolvedRpMetadata);
		if (!metaParsed.success) {
			return err(
				federationError(
					FederationErrorCode.InvalidMetadata,
					"RP metadata does not comply with OIDC spec",
				),
			);
		}
	}

	return ok({
		rpEntityId,
		resolvedRpMetadata,
		trustChain: bestChain,
	});
}
