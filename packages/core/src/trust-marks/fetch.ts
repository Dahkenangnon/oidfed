import { cloneData } from "../data-copy.js";
/** Trust Mark retrieval and signed status requests using standalone or trusted issuer context. */

import { freezeSnapshot } from "../callbacks.js";
import { FederationErrorCode, MediaType } from "../constants.js";
import { fetchFederationEndpoint } from "../endpoint-client.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import { validateExpectedIssuer, verifyTrustMarkStatusResponse } from "../federation-api/index.js";
import { decodeEntityStatement } from "../jose/verify.js";
import { safeLogger } from "./../logging.js";
import type { JWKSet } from "../schemas/jwk.js";
import { TrustMarkPayloadSchema } from "../schemas/trust-mark.js";
import {
	type Clock,
	type EntityId,
	entityId,
	type FederationOptions,
	nowSeconds,
} from "../types.js";
import { type TrustMarkIssuerContext, trustMarkIssuerContext } from "./evidence.js";
import { trustMarkOperation } from "./operation.js";
import { checkTrustMarkProfile } from "./profiles.js";

export interface FetchTrustMarkParams {
	trustMarkType: string;
	sub: EntityId;
}

/**
 * Fetch a Trust Mark JWT; validate it before relying on it.
 * Configure the endpoint and authentication together from trusted configuration or validated metadata.
 * This standalone client uses authentication.audience without an independent responder identity;
 * getEndpointAuthentication receives no responder. Authenticated requests use POST and never retry anonymously.
 * TrustMarkHolder.fetchAndAttachTrustMark supplies its verified issuer identity for an additional audience check.
 */
export async function fetchTrustMark(
	endpoint: string,
	params: FetchTrustMarkParams,
	options: FederationOptions,
): Promise<Result<string, FederationError>> {
	return requestTrustMark(endpoint, params, options);
}

/** Internal holder entry point carrying the verified issuer identity. */
export function fetchTrustMarkForIssuer(
	endpoint: string,
	params: FetchTrustMarkParams,
	issuer: string,
	options: FederationOptions,
): Promise<Result<string, FederationError>> {
	return requestTrustMark(endpoint, params, options, issuer);
}

async function requestTrustMark(
	endpoint: string,
	params: FetchTrustMarkParams,
	options: FederationOptions,
	issuer?: string,
): Promise<Result<string, FederationError>> {
	safeLogger(options?.logger)?.debug("Starting fetch trust mark");

	if (!params.trustMarkType) {
		return err(
			federationError(FederationErrorCode.InvalidRequest, "Missing trust_mark_type parameter"),
		);
	}
	if (!params.sub) {
		return err(federationError(FederationErrorCode.InvalidRequest, "Missing sub parameter"));
	}

	let parsed: URL;
	try {
		parsed = new URL(endpoint);
	} catch {
		return err(
			federationError(FederationErrorCode.InvalidRequest, `Invalid endpoint URL: ${endpoint}`),
		);
	}
	if (parsed.protocol !== "https:") {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Endpoint URL must use https scheme: ${endpoint}`,
			),
		);
	}
	if (parsed.href.includes("#")) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Endpoint URL must not contain a fragment: ${endpoint}`,
			),
		);
	}
	const selectors = new URLSearchParams({ trust_mark_type: params.trustMarkType, sub: params.sub });

	return fetchFederationEndpoint(
		parsed.toString(),
		selectors,
		{
			...options,
			expectedStatus: 200,
			accept: MediaType.TrustMark,
			expectedContentType: MediaType.TrustMark,
		},
		issuer,
	);
}

export interface FetchTrustMarkStatusOptions extends FederationOptions {
	expectedIssuer: string;
	clockSkewSeconds?: number;
	clock?: Clock;
}

export interface FetchTrustMarkStatusInput extends FederationOptions {
	jwt: string;
	issuerEvidence: TrustMarkIssuerContext;
	expectedSubject: string;
	expectedTrustMarkType: string;
	freshness?: { maxAgeSeconds: number };
}

export interface TrustMarkStatusResult {
	jwt: string;
	claims: Readonly<Record<string, unknown>>;
	verificationExpiresAt?: number;
	/** Additional status strings are permitted by Federation §8.4.2. */
	status: string;
	issuer: EntityId;
	issuedAt: number;
}

/** POST a Trust Mark JWT to a Trust Mark Status endpoint and verify the response. */
export function fetchTrustMarkStatus(
	input: FetchTrustMarkStatusInput,
): Promise<Result<TrustMarkStatusResult, FederationError>>;
export function fetchTrustMarkStatus(
	endpoint: string,
	trustMarkJwt: string,
	signerJwks: JWKSet,
	options: FetchTrustMarkStatusOptions,
): Promise<Result<TrustMarkStatusResult, FederationError>>;
export async function fetchTrustMarkStatus(
	endpointOrInput: string | FetchTrustMarkStatusInput,
	trustMarkJwt?: string,
	signerJwks?: JWKSet,
	suppliedOptions?: FetchTrustMarkStatusOptions,
): Promise<Result<TrustMarkStatusResult, FederationError>> {
	if (typeof endpointOrInput !== "string") return fetchTrustedStatus(endpointOrInput);
	if (!trustMarkJwt || !signerJwks || !suppliedOptions)
		return err(
			federationError(FederationErrorCode.InvalidRequest, "Missing status verification context"),
		);
	return fetchStatus(endpointOrInput, trustMarkJwt, signerJwks, suppliedOptions);
}

async function fetchTrustedStatus(
	input: FetchTrustMarkStatusInput,
): Promise<Result<TrustMarkStatusResult, FederationError>> {
	try {
		const options = trustMarkOperation(input);
		const trusted = trustMarkIssuerContext(
			input.issuerEvidence,
			input.expectedTrustMarkType,
			options,
		);
		if (!trusted.ok) return trusted;
		const decoded = decodeEntityStatement(input.jwt, options);
		if (!decoded.ok) return decoded;
		const mark = TrustMarkPayloadSchema.safeParse(decoded.value.payload);
		if (
			!mark.success ||
			mark.data.iss !== trusted.value.issuer ||
			mark.data.sub !== input.expectedSubject ||
			mark.data.trust_mark_type !== input.expectedTrustMarkType
		)
			return err(
				federationError(
					FederationErrorCode.InvalidRequest,
					"Trust Mark does not match the expected issuer, subject, and type",
				),
			);
		const profile = await checkTrustMarkProfile(
			decoded.value.header.typ,
			decoded.value.payload,
			input.trustMarkProfiles,
			false,
		);
		if (!profile.ok) return profile;
		const endpoint = trusted.value.metadata?.federation_trust_mark_status_endpoint;
		if (!endpoint)
			return err(
				federationError(
					FederationErrorCode.InvalidRequest,
					"Issuer does not publish a Trust Mark Status endpoint",
				),
			);
		const checked = await fetchStatus(
			endpoint,
			input.jwt,
			trusted.value.keys,
			{ ...options, expectedIssuer: trusted.value.issuer },
			input.freshness?.maxAgeSeconds,
			true,
		);
		if (!checked.ok) return checked;
		const claims = await checkTrustMarkProfile(
			decoded.value.header.typ,
			decoded.value.payload,
			input.trustMarkProfiles,
		);
		if (!claims.ok) return claims;
		const deadline = Math.min(
			trusted.value.expiresAt ?? Infinity,
			checked.value.verificationExpiresAt ?? Infinity,
		);
		if (deadline <= nowSeconds(options.clock) || options.signal?.aborted)
			return err(
				federationError(
					FederationErrorCode.InvalidRequest,
					"Trust Mark status evidence expired or was cancelled",
				),
			);
		return ok(
			freezeSnapshot({
				...checked.value,
				...(Number.isFinite(deadline) ? { verificationExpiresAt: deadline } : {}),
			}),
		);
	} catch {
		return err(
			federationError(FederationErrorCode.InvalidRequest, "Unable to verify Trust Mark status"),
		);
	}
}

async function fetchStatus(
	endpoint: string,
	trustMarkJwt: string,
	signerJwks: JWKSet,
	options: FetchTrustMarkStatusOptions,
	maxAgeSeconds?: number,
	checkIssuedAt = false,
): Promise<Result<TrustMarkStatusResult, FederationError>> {
	safeLogger(options?.logger)?.debug("Starting fetch trust mark status");

	const expectation = validateExpectedIssuer(options);
	if (!expectation.ok) return expectation;
	if (typeof trustMarkJwt !== "string" || !trustMarkJwt)
		return err(federationError(FederationErrorCode.InvalidRequest, "Missing trust_mark"));
	try {
		if (new URL(endpoint).href.includes("#"))
			return err(
				federationError(
					FederationErrorCode.InvalidRequest,
					"Endpoint URL must not contain a fragment",
				),
			);
	} catch {
		return err(federationError(FederationErrorCode.InvalidRequest, "Invalid endpoint URL"));
	}
	// Use the shared fetch boundary and keep the submitted JWT at its intended endpoint.
	const fetched = await fetchFederationEndpoint(
		endpoint,
		new URLSearchParams({ trust_mark: trustMarkJwt }),
		{
			...options,
			method: "POST",
			body: new URLSearchParams({ trust_mark: trustMarkJwt }),
			redirect: "manual",
			expectedStatus: 200,
			accept: MediaType.TrustMarkStatusResponse,
		},
		options.expectedIssuer,
	);
	if (!fetched.ok) return fetched;
	const verified = await verifyTrustMarkStatusResponse(fetched.value, signerJwks, {
		...options,
		expectedTrustMark: trustMarkJwt,
		checkIssuedAt,
		...(maxAgeSeconds !== undefined ? { maxAgeSeconds } : {}),
	});
	if (!verified.ok) return verified;
	const { status, iss, iat } = verified.value;
	const exp = verified.value.exp;
	const deadline = Math.min(
		typeof exp === "number" ? exp : Infinity,
		maxAgeSeconds === undefined ? Infinity : iat + maxAgeSeconds,
	);
	return ok(
		freezeSnapshot({
			status,
			issuer: entityId(iss),
			issuedAt: iat,
			jwt: fetched.value,
			claims: cloneData(verified.value),
			...(Number.isFinite(deadline) ? { verificationExpiresAt: deadline } : {}),
		}),
	);
}
