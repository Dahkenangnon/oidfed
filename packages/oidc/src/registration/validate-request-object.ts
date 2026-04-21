/** OP-side pre-validation of automatic registration Request Objects (structure only, no signature check). */
import {
	DEFAULT_CLOCK_SKEW_SECONDS,
	decodeEntityStatement,
	type EntityId,
	err,
	FederationErrorCode,
	federationError,
	nowSeconds,
	ok,
} from "@oidfed/core";
import { RequestObjectTyp } from "../constants.js";
import type {
	AutomaticRegistrationContext,
	ValidatedRequestObject,
	ValidatedRequestObjectResult,
} from "./types.js";

/**
 * Validate an incoming Authorization Request Object JWT for automatic registration.
 *
 * Federation-layer validation:
 * - `typ` MUST be `oauth-authz-req+jwt`
 * - `sub` MUST NOT be present
 * - `client_id` REQUIRED and MUST equal `iss`
 * - `aud` MUST be the OP's Entity Identifier (single string)
 * - `exp` MUST be present and not expired
 * - `jti` MUST be present
 * - `registration` MUST NOT be present
 * - If `trust_chain` header present, first entry must be subject's EC
 *
 * Does NOT verify the JWT signature — that requires resolving the RP's trust chain
 * and is done separately by the OP after this validation step.
 */
export function validateAutomaticRegistrationRequest(
	requestObjectJwt: string,
	context: AutomaticRegistrationContext,
): ValidatedRequestObjectResult {
	const decoded = decodeEntityStatement(requestObjectJwt);
	if (!decoded.ok) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Failed to decode Request Object: ${decoded.error.description}`,
			),
		);
	}

	const { header, payload } = decoded.value;
	const claims = payload as Record<string, unknown>;

	if (header.typ !== RequestObjectTyp) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Invalid typ header: expected '${RequestObjectTyp}', got '${String(header.typ)}'`,
			),
		);
	}

	if (claims.sub !== undefined) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Request Object MUST NOT contain 'sub' claim",
			),
		);
	}

	const clientId = claims.client_id as string | undefined;
	if (!clientId) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Request Object missing required 'client_id' claim",
			),
		);
	}

	const iss = claims.iss as string | undefined;
	if (iss !== clientId) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Request Object 'iss' ('${String(iss)}') MUST equal 'client_id' ('${clientId}')`,
			),
		);
	}

	// aud must be a single string, not an array
	const aud = claims.aud;
	if (Array.isArray(aud)) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Request Object 'aud' MUST be a single string, not an array",
			),
		);
	}
	if (aud !== (context.opEntityId as string)) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Request Object 'aud' ('${String(aud)}') does not match OP Entity Identifier ('${context.opEntityId}')`,
			),
		);
	}

	const exp = claims.exp as number | undefined;
	if (exp === undefined) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Request Object missing required 'exp' claim",
			),
		);
	}
	const clockSkew = context.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
	const now = nowSeconds();
	if (now - clockSkew >= exp) {
		return err(federationError(FederationErrorCode.InvalidRequest, "Request Object has expired"));
	}

	const jti = claims.jti as string | undefined;
	if (!jti) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Request Object missing required 'jti' claim",
			),
		);
	}

	if (claims.registration !== undefined) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Request Object MUST NOT contain 'registration' claim",
			),
		);
	}

	const trustChainHeader = header.trust_chain as string[] | undefined;
	if (trustChainHeader && trustChainHeader.length > 0) {
		const firstEntry = trustChainHeader[0] as string;
		const firstDecoded = decodeEntityStatement(firstEntry);
		if (!firstDecoded.ok) {
			return err(
				federationError(
					FederationErrorCode.InvalidTrustChain,
					"Failed to decode first entry of trust_chain header",
				),
			);
		}
		const firstPayload = firstDecoded.value.payload as Record<string, unknown>;
		if (firstPayload.iss !== clientId || firstPayload.sub !== clientId) {
			return err(
				federationError(
					FederationErrorCode.InvalidTrustChain,
					"First entry of trust_chain header MUST be the subject's Entity Configuration",
				),
			);
		}
	}

	const validated: ValidatedRequestObject = {
		rpEntityId: clientId as EntityId,
		opEntityId: context.opEntityId as string,
		exp,
		jti,
		...(claims.iat !== undefined ? { iat: claims.iat as number } : {}),
		claims,
		...(trustChainHeader ? { trustChainHeader } : {}),
	};

	return ok(validated);
}
