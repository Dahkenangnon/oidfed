import {
	InternalErrorCode,
	JWT_BEARER_CLIENT_ASSERTION_TYPE,
	JwtTyp,
	MediaType,
} from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import { verifyEntityStatement } from "../jose/verify.js";
import type { JWKSet } from "../schemas/jwk.js";
import {
	type SubordinateEventsResponse,
	SubordinateEventsResponseSchema,
} from "../schemas/subordinate-events.js";
import { performFetch, validateFetchUrl } from "../trust-chain/fetch.js";
import { type EntityId, type FederationOptions, isValidEntityId } from "../types.js";

export interface VerifySubordinateEventsOptions {
	/** Expected authority Entity Identifier, independent of endpoint origin. */
	issuer: EntityId;
	subject: EntityId;
	clock?: FederationOptions["clock"];
	clockSkewSeconds?: number;
}

/** Verify a history statement with independently trusted keys and expected identities. */
export async function verifySubordinateEventsResponse(
	jwt: string,
	issuerJwks: JWKSet,
	options: VerifySubordinateEventsOptions,
): Promise<Result<SubordinateEventsResponse, FederationError>> {
	const verified = await verifyEntityStatement(jwt, issuerJwks, {
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
	if (options.clientAssertion !== undefined) {
		form.set("client_assertion", options.clientAssertion);
		form.set("client_assertion_type", JWT_BEARER_CLIENT_ASSERTION_TYPE);
	} else {
		url.searchParams.set("sub", subject);
	}
	const fetched = await performFetch(url.toString(), {
		...options,
		accept: MediaType.EntityEventsStatement,
		expectedStatus: 200,
		federationErrors: true,
		// Manual redirects plus exact status checking prevent forwarding assertions.
		// workerd supports "manual" but rejects Fetch's "error" redirect mode.
		redirect: "manual",
		...(options.clientAssertion !== undefined ? { method: "POST", body: form } : {}),
	});
	if (!fetched.ok) return fetched;
	return verifySubordinateEventsResponse(fetched.value, options.issuerJwks, {
		issuer: options.issuer,
		subject,
		...(options.clock ? { clock: options.clock } : {}),
		...(options.clockSkewSeconds !== undefined
			? { clockSkewSeconds: options.clockSkewSeconds }
			: {}),
	});
}
