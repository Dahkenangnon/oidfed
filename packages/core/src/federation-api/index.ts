import { type EntityType, InternalErrorCode, JwtTyp, MediaType } from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import { verifyEntityStatement } from "../jose/verify.js";
import {
	type HistoricalKeysPayload,
	HistoricalKeysPayloadSchema,
	type ResolveResponsePayload,
	ResolveResponsePayloadSchema,
	type SignedJwkSetPayload,
	SignedJwkSetPayloadSchema,
	type TrustMarkStatusResponsePayload,
	TrustMarkStatusResponsePayloadSchema,
} from "../schemas/entity-statement.js";
import type { JWKSet } from "../schemas/jwk.js";
import { performFetch } from "../trust-chain/fetch.js";
import type { Clock, EntityId, FederationOptions } from "../types.js";

function apiError(description: string): FederationError {
	return { code: InternalErrorCode.SignatureInvalid, description };
}

interface VerifyOptions {
	clockSkewSeconds?: number;
	clock?: Clock;
}

function buildVerifyOpts(expectedTyp: string, options?: VerifyOptions) {
	const opts: { expectedTyp: string; clockSkewSeconds?: number; clock?: Clock } = { expectedTyp };
	if (options?.clockSkewSeconds !== undefined) opts.clockSkewSeconds = options.clockSkewSeconds;
	if (options?.clock !== undefined) opts.clock = options.clock;
	return opts;
}

/**
 * Verify and validate a Resolve Response JWT. Checks typ, signature, and claims.
 */
export async function verifyResolveResponse(
	jwt: string,
	issuerJwks: JWKSet,
	options?: VerifyOptions,
): Promise<Result<ResolveResponsePayload, FederationError>> {
	const result = await verifyEntityStatement(
		jwt,
		issuerJwks,
		buildVerifyOpts(JwtTyp.ResolveResponse, options),
	);
	if (!result.ok) return result;

	const parsed = ResolveResponsePayloadSchema.safeParse(result.value.payload);
	if (!parsed.success) {
		return err(apiError(`Invalid resolve response payload: ${parsed.error.message}`));
	}
	return { ok: true, value: parsed.data };
}

/**
 * Verify and validate a Trust Mark Status Response JWT.
 */
export async function verifyTrustMarkStatusResponse(
	jwt: string,
	issuerJwks: JWKSet,
	options?: VerifyOptions,
): Promise<Result<TrustMarkStatusResponsePayload, FederationError>> {
	const result = await verifyEntityStatement(
		jwt,
		issuerJwks,
		buildVerifyOpts(JwtTyp.TrustMarkStatusResponse, options),
	);
	if (!result.ok) return result;

	const parsed = TrustMarkStatusResponsePayloadSchema.safeParse(result.value.payload);
	if (!parsed.success) {
		return err(apiError(`Invalid trust mark status response payload: ${parsed.error.message}`));
	}
	return { ok: true, value: parsed.data };
}

/**
 * Verify and validate a Historical Keys Response JWT.
 */
export async function verifyHistoricalKeysResponse(
	jwt: string,
	issuerJwks: JWKSet,
	options?: VerifyOptions,
): Promise<Result<HistoricalKeysPayload, FederationError>> {
	const result = await verifyEntityStatement(
		jwt,
		issuerJwks,
		buildVerifyOpts(JwtTyp.JwkSet, options),
	);
	if (!result.ok) return result;

	const parsed = HistoricalKeysPayloadSchema.safeParse(result.value.payload);
	if (!parsed.success) {
		return err(apiError(`Invalid historical keys response payload: ${parsed.error.message}`));
	}
	return { ok: true, value: parsed.data };
}

/**
 * Verify and validate a Signed JWK Set JWT (returned by signed_jwks_uri).
 * Checks typ=jwk-set+jwt, signature, and required payload claims (iss, sub, keys).
 */
export async function verifySignedJwkSet(
	jwt: string,
	signerJwks: JWKSet,
	options?: VerifyOptions,
): Promise<Result<SignedJwkSetPayload, FederationError>> {
	const result = await verifyEntityStatement(
		jwt,
		signerJwks,
		buildVerifyOpts(JwtTyp.JwkSet, options),
	);
	if (!result.ok) return result;

	const parsed = SignedJwkSetPayloadSchema.safeParse(result.value.payload);
	if (!parsed.success) {
		return err(apiError(`Invalid signed JWK Set payload: ${parsed.error.message}`));
	}
	return { ok: true, value: parsed.data };
}

/** Optional filters accepted by the subordinate listing endpoint. */
export interface ListSubordinatesFilter {
	entityType?: EntityType | EntityType[];
	trustMarked?: boolean;
	trustMarkType?: string;
	intermediate?: boolean;
}

/** Fetch the subordinate-listing endpoint of an authority and return the array of Entity Identifiers. */
export async function fetchListSubordinates(
	listEndpoint: string,
	filter?: ListSubordinatesFilter,
	options?: FederationOptions,
): Promise<Result<EntityId[], FederationError>> {
	let url: URL;
	try {
		url = new URL(listEndpoint);
	} catch (cause) {
		return err({
			code: InternalErrorCode.Network,
			description: `Invalid list endpoint URL: ${listEndpoint}`,
			cause,
		});
	}

	if (filter?.entityType !== undefined) {
		const types = Array.isArray(filter.entityType) ? filter.entityType : [filter.entityType];
		for (const t of types) url.searchParams.append("entity_type", t);
	}
	if (filter?.trustMarked !== undefined) {
		url.searchParams.set("trust_marked", filter.trustMarked ? "true" : "false");
	}
	if (filter?.trustMarkType !== undefined) {
		url.searchParams.set("trust_mark_type", filter.trustMarkType);
	}
	if (filter?.intermediate !== undefined) {
		url.searchParams.set("intermediate", filter.intermediate ? "true" : "false");
	}

	const result = await performFetch(url.toString(), {
		...(options ?? {}),
		accept: MediaType.Json,
	});
	if (!result.ok) return result;

	let parsed: unknown;
	try {
		parsed = JSON.parse(result.value);
	} catch (cause) {
		return err({
			code: InternalErrorCode.Network,
			description: `List endpoint returned non-JSON body: ${listEndpoint}`,
			cause,
		});
	}
	if (!Array.isArray(parsed) || !parsed.every((v): v is string => typeof v === "string")) {
		return err({
			code: InternalErrorCode.Network,
			description: `List endpoint did not return a JSON array of strings: ${listEndpoint}`,
		});
	}
	return ok(parsed as EntityId[]);
}

/** Resolve-endpoint request parameters. `trustAnchor` and `entityType` may repeat. */
export interface ResolveRequestParams {
	sub: EntityId;
	trustAnchor: EntityId | EntityId[];
	entityType?: EntityType | EntityType[];
}

/** Fetch a Resolve Response JWT from a remote resolver. The verifier checks Content-Type and typ. */
export async function fetchResolveResponse(
	resolveEndpoint: string,
	params: ResolveRequestParams,
	options?: FederationOptions,
): Promise<Result<string, FederationError>> {
	let url: URL;
	try {
		url = new URL(resolveEndpoint);
	} catch (cause) {
		return err({
			code: InternalErrorCode.Network,
			description: `Invalid resolve endpoint URL: ${resolveEndpoint}`,
			cause,
		});
	}

	url.searchParams.set("sub", params.sub);

	const trustAnchors = Array.isArray(params.trustAnchor)
		? params.trustAnchor
		: [params.trustAnchor];
	if (trustAnchors.length === 0) {
		return err({
			code: InternalErrorCode.Network,
			description: "fetchResolveResponse requires at least one trustAnchor",
		});
	}
	for (const ta of trustAnchors) url.searchParams.append("trust_anchor", ta);

	if (params.entityType !== undefined) {
		const types = Array.isArray(params.entityType) ? params.entityType : [params.entityType];
		for (const t of types) url.searchParams.append("entity_type", t);
	}

	return performFetch(url.toString(), {
		...(options ?? {}),
		accept: MediaType.ResolveResponse,
		expectedContentType: null,
	});
}

export {
	type FetchHistoricalKeysOptions,
	fetchHistoricalKeys,
} from "./fetch-historical-keys.js";
export {
	type FetchTrustMarkListParams,
	fetchTrustMarkList,
} from "./fetch-trust-mark-list.js";
