/**
 * Client-side helpers for the federation Trust Mark and Trust Mark Status
 * endpoints. The library already provides server-side handlers; these helpers
 * mirror the symmetry of the JWK-Set fetchers so integrators do not have to
 * re-implement HTTP / Content-Type discipline.
 */
import { FederationErrorCode, JwtTyp, MediaType, type TrustMarkStatus } from "../constants.js";
import { err, type FederationError, federationError, ok, type Result } from "../errors.js";
import { verifyEntityStatement } from "../jose/verify.js";
import type { JWKSet } from "../schemas/jwk.js";
import { performFetch } from "../trust-chain/fetch.js";
import type { Clock, EntityId, FederationOptions } from "../types.js";

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
	if (parsed.hash) {
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
	clockSkewSeconds?: number;
	clock?: Clock;
}

export interface TrustMarkStatusResult {
	status: TrustMarkStatus;
	issuer: EntityId;
	issuedAt: number;
}

/** POST a Trust Mark JWT to a Trust Mark Status endpoint and verify the response. */
export async function fetchTrustMarkStatus(
	endpoint: string,
	trustMarkJwt: string,
	signerJwks: JWKSet,
	options?: FetchTrustMarkStatusOptions,
): Promise<Result<TrustMarkStatusResult, FederationError>> {
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
	if (parsed.hash) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Endpoint URL must not contain a fragment: ${endpoint}`,
			),
		);
	}

	const fetchFn = options?.httpClient ?? fetch;
	const body = new URLSearchParams({ trust_mark: trustMarkJwt }).toString();
	const response = await fetchFn(endpoint, {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			Accept: MediaType.TrustMarkStatusResponse,
		},
		body,
	});
	if (!response.ok) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`HTTP ${response.status} from trust mark status endpoint`,
			),
		);
	}
	const contentType = response.headers.get("content-type")?.split(";")[0]?.trim() ?? "";
	if (contentType !== MediaType.TrustMarkStatusResponse) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				`Unexpected Content-Type '${contentType}'`,
			),
		);
	}
	const jwt = await response.text();

	const verifyOpts: { expectedTyp: string; clockSkewSeconds?: number; clock?: Clock } = {
		expectedTyp: JwtTyp.TrustMarkStatusResponse,
	};
	if (options?.clockSkewSeconds !== undefined)
		verifyOpts.clockSkewSeconds = options.clockSkewSeconds;
	if (options?.clock !== undefined) verifyOpts.clock = options.clock;
	const verifyResult = await verifyEntityStatement(jwt, signerJwks, verifyOpts);
	if (!verifyResult.ok) return verifyResult;

	const payload = verifyResult.value.payload as Record<string, unknown>;
	const status = payload.status as TrustMarkStatus | undefined;
	const issuer = payload.iss as EntityId | undefined;
	const iat = payload.iat as number | undefined;

	if (!status || !issuer || iat === undefined) {
		return err(
			federationError(
				FederationErrorCode.InvalidRequest,
				"Trust mark status response missing required claims",
			),
		);
	}

	return ok({ status, issuer, issuedAt: iat });
}
