/**
 * Client-side helpers for the federation Trust Mark and Trust Mark Status
 * endpoints. The library already provides server-side handlers; these helpers
 * mirror the symmetry of the JWK-Set fetchers so integrators do not have to
 * re-implement HTTP / Content-Type discipline.
 */
import { FederationErrorCode, MediaType } from "../constants.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import { validateExpectedIssuer, verifyTrustMarkStatusResponse } from "../federation-api/index.js";
import { safeLogger } from "./../logging.js";
import type { JWKSet } from "../schemas/jwk.js";
import { performFetch } from "../trust-chain/fetch.js";
import type { Clock, EntityId, FederationOptions } from "../types.js";
import { entityId } from "../types.js";

export interface FetchTrustMarkParams {
	trustMarkType: string;
	sub: EntityId;
}

/** Fetch a Trust Mark JWT from a federation Trust Mark endpoint. */
export async function fetchTrustMark(
	endpoint: string,
	params: FetchTrustMarkParams,
	options?: FederationOptions,
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
	parsed.searchParams.set("trust_mark_type", params.trustMarkType);
	parsed.searchParams.set("sub", params.sub);

	return performFetch(parsed.toString(), {
		...options,
		accept: MediaType.TrustMark,
		expectedContentType: MediaType.TrustMark,
	});
}

export interface FetchTrustMarkStatusOptions extends FederationOptions {
	expectedIssuer: string;
	clockSkewSeconds?: number;
	clock?: Clock;
}

export interface TrustMarkStatusResult {
	/** Additional status strings are permitted by Federation §8.4.2. */
	status: string;
	issuer: EntityId;
	issuedAt: number;
}

/** POST a Trust Mark JWT to a Trust Mark Status endpoint and verify the response. */
export async function fetchTrustMarkStatus(
	endpoint: string,
	trustMarkJwt: string,
	signerJwks: JWKSet,
	options: FetchTrustMarkStatusOptions,
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
	const fetched = await performFetch(endpoint, {
		...options,
		method: "POST",
		body: new URLSearchParams({ trust_mark: trustMarkJwt }),
		redirect: "error",
		expectedStatus: 200,
		accept: MediaType.TrustMarkStatusResponse,
	});
	if (!fetched.ok) return fetched;
	const verified = await verifyTrustMarkStatusResponse(fetched.value, signerJwks, {
		...options,
		expectedTrustMark: trustMarkJwt,
	});
	if (!verified.ok) return verified;
	const { status, iss, iat } = verified.value;
	return ok({ status, issuer: entityId(iss), issuedAt: iat });
}
