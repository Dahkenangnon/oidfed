/** Retrieval and verification of signed Subordinate Events responses. */

import { InternalErrorCode, JwtTyp, MediaType } from "../constants.js";
import { fetchFederationEndpoint } from "../endpoint-client.js";
import { ENDPOINT_OPERATION_PARAMETERS } from "../endpoint-parameters.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import { validateFetchUrl } from "../http/fetch-url.js";
import { verifyEntityStatement } from "../jose/verify.js";
import { safeLogger } from "../logging.js";
import type { JWKSet } from "../schemas/jwk.js";
import {
	type SubordinateEventsResponse,
	SubordinateEventsResponseSchema,
} from "../schemas/subordinate-events.js";
import { type EntityId, type FederationOptions, isValidEntityId } from "../types.js";

export interface VerifySubordinateEventsOptions extends FederationOptions {
	/** Expected authority Entity Identifier, independent of endpoint origin. */
	issuer: EntityId;
	subject: EntityId;
	clockSkewSeconds?: number;
}

/** Verify a history statement with independently trusted keys and expected identities. */
export async function verifySubordinateEventsResponse(
	jwt: string,
	issuerJwks: JWKSet,
	options: VerifySubordinateEventsOptions,
): Promise<Result<SubordinateEventsResponse, FederationError>> {
	const verified = await verifyEntityStatement(jwt, issuerJwks, {
		...options,
		expectedTyp: JwtTyp.EntityEventsStatement,
		...(options.clock ? { clock: options.clock } : {}),
		...(options.clockSkewSeconds !== undefined
			? { clockSkewSeconds: options.clockSkewSeconds }
			: {}),
	});
	if (!verified.ok) return verified;
	const parsed = SubordinateEventsResponseSchema.safeParse(verified.value.payload);
	if (!parsed.success)
		return err({
			code: InternalErrorCode.SignatureInvalid,
			description: `Invalid subordinate events response: ${parsed.error.message}`,
		});
	if (
		parsed.data.iss !== (options.issuer as string) ||
		parsed.data.sub !== (options.subject as string)
	) {
		return err({
			code: InternalErrorCode.SignatureInvalid,
			description: "Subordinate events issuer or subject does not match the request",
		});
	}
	return ok(parsed.data);
}

export interface FetchSubordinateEventsOptions extends FederationOptions {
	/** Independently trusted public Federation Entity Keys of the issuer. */
	issuerJwks: JWKSet;
	issuer: EntityId;
	/** A caller-created private_key_jwt assertion, with the issuer Entity Identifier as audience. */
	clientAssertion?: string;
}

/** Fetch and verify an authority's history about one Immediate Subordinate. */
export async function fetchSubordinateEvents(
	endpoint: string,
	subject: EntityId,
	options: FetchSubordinateEventsOptions,
): Promise<Result<SubordinateEventsResponse, FederationError>> {
	safeLogger(options?.logger)?.debug("Starting fetch subordinate events");

	const checked = validateFetchUrl(endpoint, options);
	if (!checked.ok) return checked;
	const url = checked.value;
	if (url.href.includes("#") || !isValidEntityId(subject) || !isValidEntityId(options.issuer)) {
		return err({
			code: InternalErrorCode.Network,
			description: "Invalid subordinate events endpoint, issuer, or subject",
		});
	}
	const form = new URLSearchParams({ sub: subject });
	const fetched = await fetchFederationEndpoint(
		url.toString(),
		form,
		{
			...options,
			method: "GET",
			accept: MediaType.EntityEventsStatement,
			expectedStatus: 200,
			federationErrors: true,
		},
		options.issuer,
		[],
		ENDPOINT_OPERATION_PARAMETERS.subordinateEvents,
	);
	if (!fetched.ok) return fetched;
	return verifySubordinateEventsResponse(fetched.value, options.issuerJwks, {
		...options,
		issuer: options.issuer,
		subject,
		...(options.clock ? { clock: options.clock } : {}),
		...(options.clockSkewSeconds !== undefined
			? { clockSkewSeconds: options.clockSkewSeconds }
			: {}),
	});
}
