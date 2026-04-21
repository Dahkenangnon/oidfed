import {
	DEFAULT_CLOCK_SKEW_SECONDS,
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
	nowSeconds,
	ok,
	type Result,
	type TrustAnchorSet,
	verifyEntityStatement,
} from "@oidfed/core";
import { resolveAndValidateBestChain } from "./helpers.js";
import type { ProcessedRegistration } from "./process-automatic.js";

export interface ProcessExplicitRegistrationOptions extends FederationOptions {
	/** The OP's own Entity Identifier — REQUIRED for `aud` validation. */
	opEntityId: EntityId;
}

/**
 * OP-side processing of an explicit registration request.
 *
 * Validates the RP's Entity Configuration JWT, verifies its self-signature,
 * resolves trust chains, and extracts resolved `openid_relying_party` metadata.
 *
 * The caller MUST cap the registration `exp` to `trustChain.expiresAt` .
 */
export async function processExplicitRegistration(
	requestBody: string,
	contentType: string,
	trustAnchors: TrustAnchorSet,
	options: ProcessExplicitRegistrationOptions,
): Promise<Result<ProcessedRegistration, FederationError>> {
	if (contentType !== MediaType.EntityStatement && contentType !== MediaType.TrustChain) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Unsupported Content-Type. Expected '${MediaType.EntityStatement}' or '${MediaType.TrustChain}'`,
			),
		);
	}

	// O2: trust-chain+json body is a JSON array of JWTs; entity-statement+jwt is a single JWT
	let rpEcJwt: string;

	if (contentType === MediaType.TrustChain) {
		let chain: unknown;
		try {
			chain = JSON.parse(requestBody);
		} catch {
			return err(
				federationError(FederationErrorCode.InvalidRequest, "Invalid trust-chain+json body"),
			);
		}
		if (!Array.isArray(chain) || chain.length === 0 || !chain.every((s) => typeof s === "string")) {
			return err(
				federationError(
					FederationErrorCode.InvalidRequest,
					"trust-chain+json must be a non-empty array of JWT strings",
				),
			);
		}
		rpEcJwt = chain[0] as string;
		// Optimization: the OP MAY evaluate the supplied Trust Chain directly (not implemented)
	} else {
		rpEcJwt = requestBody;
	}

	const decoded = decodeEntityStatement(rpEcJwt);
	if (!decoded.ok) {
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
		return err(federationError(FederationErrorCode.InvalidRequest, "RP EC missing 'iss' claim"));
	}

	// iat and exp are REQUIRED in the RP Entity Configuration
	const clockSkew = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
	const now = nowSeconds();

	const iat = payload.iat as number | undefined;
	if (iat === undefined) {
		return err(
			federationError(FederationErrorCode.InvalidRequest, "RP EC missing required 'iat' claim"),
		);
	}
	if (iat > now + clockSkew) {
		return err(federationError(FederationErrorCode.InvalidRequest, "RP EC 'iat' is in the future"));
	}

	const exp = payload.exp as number | undefined;
	if (exp === undefined) {
		return err(
			federationError(FederationErrorCode.InvalidRequest, "RP EC missing required 'exp' claim"),
		);
	}
	if (now - clockSkew >= exp) {
		return err(federationError(FederationErrorCode.InvalidRequest, "RP EC has expired"));
	}

	if (payload.sub !== payload.iss) {
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
		return err(
			federationError(FederationErrorCode.InvalidRequest, "RP EC missing required 'aud' claim"),
		);
	}
	if (aud !== (options.opEntityId as string)) {
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
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"RP EC 'authority_hints' MUST be a non-empty array of strings",
			),
		);
	}

	// metadata containing openid_relying_party is REQUIRED
	const metadata = payload.metadata as Record<string, unknown> | undefined;
	if (!metadata || typeof metadata !== "object" || !metadata.openid_relying_party) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"RP EC MUST contain 'metadata' with 'openid_relying_party'",
			),
		);
	}

	// Self-signature verification: the RP EC must be signed by a key in its own JWKS
	const rpJwks = payload.jwks as { keys: Array<Record<string, unknown>> } | undefined;
	if (!rpJwks) {
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
		rpJwks as Parameters<typeof verifyEntityStatement>[1],
		{ expectedTyp: JwtTyp.EntityStatement },
	);
	if (!selfVerify.ok) {
		return err(
			federationError(
				InternalErrorCode.SignatureInvalid,
				"RP EC self-signature verification failed",
			),
		);
	}

	const bestChainResult = await resolveAndValidateBestChain(rpEntityId, trustAnchors, options);
	if (!bestChainResult.ok) return bestChainResult;
	const bestChain = bestChainResult.value;
	const resolvedRpMetadata = bestChain.resolvedMetadata.openid_relying_party ?? {};

	return ok({
		rpEntityId,
		resolvedRpMetadata,
		trustChain: bestChain,
	});
}
