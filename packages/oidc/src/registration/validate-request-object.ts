/**
 * OP-side pre-validation of automatic registration Request Objects (structure only, no signature
 * check).
 */

import {
	DEFAULT_CLOCK_SKEW_SECONDS,
	decodeEntityStatement,
	type EntityId,
	err,
	FederationErrorCode,
	federationError,
	isValidEntityId,
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
 * Check an incoming Authorization Request Object before automatic registration.
 *
 * Federation claim rules and oidfed's typing policy:
 * - `typ` follows the configured Request Object typing policy (strict by default).
 * - `sub` MUST NOT be present.
 * - `client_id` is REQUIRED and MUST equal `iss`.
 * - `aud` MUST be the OP's Entity Identifier as a single string.
 * - `exp` MUST be present and unexpired.
 * - `jti` MUST be present.
 * - `registration` MUST NOT be present.
 * - A `trust_chain` header starts with the subject's EC.
 *
 * The OP verifies the signature separately after resolving the RP's trust chain.
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
	if (Object.hasOwn(payload, "request") || Object.hasOwn(payload, "request_uri"))
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Request Objects MUST NOT contain request or request_uri",
			),
		);
	const claims = payload as Record<string, unknown>;

	const typing = context.requestObjectTyping ?? "strict";
	if (typing !== "strict" && typing !== "compatible")
		return err(
			federationError(FederationErrorCode.InvalidRequest, "Invalid Request Object typing policy"),
		);

	// Federation §12.1.1.1.1 illustrates this typ in a non-normative example.
	// RFC 9101 §10.8 permits explicit typing as a deployment policy and describes
	// compatibility with existing Request Objects. Keep legacy acceptance opt-in.
	// RFC 7515 §4.1.9 makes media types case-insensitive and permits application/.
	const typ =
		typeof header.typ === "string"
			? header.typ.toLowerCase().replace(/^application\//, "")
			: undefined;
	const explicitlyTyped = typ === RequestObjectTyp;
	const legacy = typing === "compatible" && (header.typ === undefined || typ === "jwt");
	if (!explicitlyTyped && !legacy) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Request Object typ does not satisfy the configured typing policy",
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
	if (!isValidEntityId(clientId)) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Request Object 'client_id' MUST be an Entity Identifier",
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
	if (typeof exp !== "number" || !Number.isFinite(exp)) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Request Object missing required 'exp' claim",
			),
		);
	}
	const clockSkew = context.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
	const now = nowSeconds(context.clock);
	if (now - clockSkew >= exp) {
		return err(federationError(FederationErrorCode.InvalidRequest, "Request Object has expired"));
	}

	const jti = claims.jti as string | undefined;
	if (typeof jti !== "string" || !jti) {
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

	for (const name of ["trust_chain", "peer_trust_chain"] as const) {
		const value = header[name];
		if (
			value !== undefined &&
			(!Array.isArray(value) ||
				value.length === 0 ||
				!value.every((entry) => typeof entry === "string" && entry.length > 0))
		) {
			return err(
				federationError(
					FederationErrorCode.InvalidTrustChain,
					`${name} must be a non-empty array of JWT strings`,
				),
			);
		}
	}

	const trustChainHeader = header.trust_chain as readonly string[] | undefined;
	if (trustChainHeader !== undefined) {
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

	const peerTrustChainHeader = header.peer_trust_chain as readonly string[] | undefined;
	if (peerTrustChainHeader !== undefined) {
		const peerFirstEntry = peerTrustChainHeader[0] as string;
		const peerFirstDecoded = decodeEntityStatement(peerFirstEntry);
		if (!peerFirstDecoded.ok) {
			return err(
				federationError(
					FederationErrorCode.InvalidTrustChain,
					"Failed to decode first entry of peer_trust_chain header",
				),
			);
		}
		const peerFirstPayload = peerFirstDecoded.value.payload as Record<string, unknown>;
		if (
			peerFirstPayload.iss !== context.opEntityId ||
			peerFirstPayload.sub !== context.opEntityId
		) {
			return err(
				federationError(
					FederationErrorCode.InvalidTrustChain,
					"First entry of peer_trust_chain header MUST be the OP's Entity Configuration",
				),
			);
		}

		// Same-Trust-Anchor invariant when both chains are present.
		if (trustChainHeader !== undefined) {
			const rpLastEntry = trustChainHeader[trustChainHeader.length - 1] as string;
			const peerLastEntry = peerTrustChainHeader[peerTrustChainHeader.length - 1] as string;
			const rpLastDecoded = decodeEntityStatement(rpLastEntry);
			const peerLastDecoded = decodeEntityStatement(peerLastEntry);
			if (!rpLastDecoded.ok || !peerLastDecoded.ok) {
				return err(
					federationError(
						FederationErrorCode.InvalidTrustChain,
						"Failed to decode last entry of trust_chain or peer_trust_chain header",
					),
				);
			}
			const rpTaId = trustChainTrailingAnchorId(rpLastDecoded.value.payload);
			const peerTaId = trustChainTrailingAnchorId(peerLastDecoded.value.payload);
			if (rpTaId !== peerTaId) {
				return err(
					federationError(
						FederationErrorCode.InvalidTrustChain,
						`peer_trust_chain Trust Anchor ('${peerTaId}') does not match trust_chain Trust Anchor ('${rpTaId}')`,
					),
				);
			}
		}
	}

	const validated: ValidatedRequestObject = {
		rpEntityId: clientId as EntityId,
		opEntityId: context.opEntityId as string,
		exp,
		jti,
		...(claims.iat !== undefined ? { iat: claims.iat as number } : {}),
		claims,
		...(typeof header.typ === "string" ? { headerTyp: header.typ } : {}),
		...(trustChainHeader !== undefined ? { trustChainHeader } : {}),
		...(peerTrustChainHeader !== undefined ? { peerTrustChainHeader } : {}),
	};

	return ok(validated);
}

/** Returns the Trust Anchor Entity Identifier from the trailing element of a Trust Chain. */
function trustChainTrailingAnchorId(payload: Record<string, unknown>): string | undefined {
	// Final element MAY be the TA's own EC (iss === sub) or a TA-signed Subordinate Statement
	// (iss is the TA, sub is the immediate subordinate).
	const iss = payload.iss as string | undefined;
	return iss;
}
