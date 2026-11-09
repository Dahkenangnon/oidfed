import { type EntityTypeIdentifier, InternalErrorCode, JwtTyp, MediaType } from "../constants.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import { verifyEntityStatement } from "../jose/verify.js";
import { validateJwkSetUseRequirement } from "../jwks/use-requirement.js";
import { EntityIdSchema } from "../schemas/entity-id.js";
import {
	type HistoricalKeyEntry,
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

export interface VerifyOptions {
	/** Expected signer identity from trusted configuration or validated federation evidence. */
	expectedIssuer: string;
	clockSkewSeconds?: number;
	clock?: Clock;
}

export interface VerifyResolveResponseOptions extends VerifyOptions {
	expectedSubject: string;
	/** Requesting party's Entity Identifier; required to accept a response containing aud. */
	expectedAudience?: string;
}

export interface VerifyTrustMarkStatusOptions extends VerifyOptions {
	/** The exact JWT submitted to the status endpoint (Federation §8.4.2). */
	expectedTrustMark: string;
}

export interface VerifySignedJwkSetOptions extends VerifyOptions {
	/** Key owner from trusted context; §5.2.1 permits an owner distinct from the issuer. */
	expectedOwner: string;
}

/** Validate caller context before accepting any signed response (RFC 8725 §3.8). */
export function validateExpectedIssuer(
	options: VerifyOptions | undefined,
): Result<void, FederationError> {
	return EntityIdSchema.safeParse(options?.expectedIssuer).success
		? ok(undefined)
		: err(apiError("A valid expectedIssuer is required"));
}

function buildVerifyOpts(expectedTyp: string, options?: VerifyOptions) {
	const opts: { expectedTyp: string; clockSkewSeconds?: number; clock?: Clock } = { expectedTyp };
	if (options?.clockSkewSeconds !== undefined) opts.clockSkewSeconds = options.clockSkewSeconds;
	if (options?.clock !== undefined) opts.clock = options.clock;
	return opts;
}

/**
 * Verify a Resolve Response's typ, signature, claims, and recipient binding.
 * Federation §8.3.2 permits aud to be absent, including on authenticated responses.
 */
export async function verifyResolveResponse(
	jwt: string,
	issuerJwks: JWKSet,
	options: VerifyResolveResponseOptions,
): Promise<Result<ResolveResponsePayload, FederationError>> {
	const expectation = validateExpectedIssuer(options);
	if (!expectation.ok) return expectation;
	if (!EntityIdSchema.safeParse(options?.expectedSubject).success)
		return err(apiError("A valid expectedSubject is required"));
	const expectedAudience = options?.expectedAudience;
	if (expectedAudience !== undefined && !EntityIdSchema.safeParse(expectedAudience).success) {
		return err(apiError("Expected resolve response audience must be a valid Entity Identifier"));
	}
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
	const audience = parsed.data.aud;
	if (audience !== undefined) {
		if (expectedAudience === undefined) {
			return err(apiError("Resolve response audience requires an expectedAudience"));
		}
		const recipients = typeof audience === "string" ? [audience] : audience;
		if (!recipients.every((recipient) => recipient === expectedAudience)) {
			return err(apiError("Resolve response audience does not match the requesting party"));
		}
	}
	if (parsed.data.iss !== options.expectedIssuer)
		return err(apiError("Response issuer does not match expectedIssuer"));
	if (parsed.data.sub !== options.expectedSubject)
		return err(apiError("Resolve response subject does not match expectedSubject"));
	return { ok: true, value: parsed.data };
}

/**
 * Verify and validate a Trust Mark Status Response JWT.
 */
export async function verifyTrustMarkStatusResponse(
	jwt: string,
	issuerJwks: JWKSet,
	options: VerifyTrustMarkStatusOptions,
): Promise<Result<TrustMarkStatusResponsePayload, FederationError>> {
	const expectation = validateExpectedIssuer(options);
	if (!expectation.ok) return expectation;
	if (typeof options?.expectedTrustMark !== "string" || !options.expectedTrustMark)
		return err(apiError("A nonempty expectedTrustMark is required"));
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
	if (parsed.data.iss !== options.expectedIssuer)
		return err(apiError("Response issuer does not match expectedIssuer"));
	if (parsed.data.trust_mark !== options.expectedTrustMark)
		return err(apiError("Status response does not match the submitted Trust Mark"));
	return { ok: true, value: parsed.data };
}

/**
 * Verify and validate a Historical Keys Response JWT.
 */
export async function verifyHistoricalKeysResponse(
	jwt: string,
	issuerJwks: JWKSet,
	options: VerifyOptions,
): Promise<Result<HistoricalKeysPayload, FederationError>> {
	const expectation = validateExpectedIssuer(options);
	if (!expectation.ok) return expectation;
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
	if (parsed.data.iss !== options.expectedIssuer)
		return err(apiError("Response issuer does not match expectedIssuer"));
	return { ok: true, value: parsed.data };
}

const SECURITY_REVOCATION_REASONS = new Set(["compromised", "keyCompromise", "key_compromise"]);

export interface SelectHistoricalVerificationKeyOptions {
	readonly kid: string;
	readonly validAt: number;
	/** Additional security-revocation reasons defined by the federation (§8.7.3), matched exactly. */
	readonly securityRevocationReasons?: readonly string[];
}

/** Select a historical key usable for verifying material issued at the supplied NumericDate. */
export function selectHistoricalVerificationKey(
	keys: readonly HistoricalKeyEntry[],
	options: SelectHistoricalVerificationKeyOptions,
): Result<HistoricalKeyEntry, FederationError> {
	const matchingKeys = keys.filter((key) => key.kid === options.kid);
	if (matchingKeys.length === 0) {
		return err(apiError(`No historical key found for kid '${options.kid}'`));
	}

	for (const key of matchingKeys) {
		const revoked = key.revoked;
		// Additional reasons extend the existing protection, including pre-revocation signatures (§8.7).
		if (
			revoked?.reason &&
			(SECURITY_REVOCATION_REASONS.has(revoked.reason) ||
				options.securityRevocationReasons?.includes(revoked.reason))
		) {
			continue;
		}
		if (revoked?.revoked_at !== undefined && options.validAt >= revoked.revoked_at) {
			continue;
		}
		if (key.nbf !== undefined && options.validAt < key.nbf) {
			continue;
		}
		if (options.validAt >= key.exp) {
			continue;
		}
		return ok(key);
	}

	return err(apiError(`Historical key '${options.kid}' is not valid at ${options.validAt}`));
}

/**
 * Verify and validate a Signed JWK Set JWT (returned by signed_jwks_uri).
 * Checks typ=jwk-set+jwt, signature, and required payload claims (iss, sub, keys).
 */
export async function verifySignedJwkSet(
	jwt: string,
	signerJwks: JWKSet,
	options: VerifySignedJwkSetOptions,
): Promise<Result<SignedJwkSetPayload, FederationError>> {
	const expectation = validateExpectedIssuer(options);
	if (!expectation.ok) return expectation;
	if (!EntityIdSchema.safeParse(options?.expectedOwner).success)
		return err(apiError("A valid expectedOwner is required"));
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
	const useResult = validateJwkSetUseRequirement(parsed.data.keys);
	if (!useResult.ok) return useResult;
	if (parsed.data.iss !== options.expectedIssuer)
		return err(apiError("Response issuer does not match expectedIssuer"));
	if (parsed.data.sub !== options.expectedOwner)
		return err(apiError("Signed JWK Set owner does not match expectedOwner"));
	return { ok: true, value: parsed.data };
}

/** Optional filters accepted by the subordinate listing endpoint. */
export interface ListSubordinatesFilter {
	/** Open value space — Federation §5.1 permits identifiers beyond the published set. */
	entityType?: EntityTypeIdentifier | EntityTypeIdentifier[];
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
	if (!Array.isArray(parsed) || !parsed.every((v) => EntityIdSchema.safeParse(v).success)) {
		return err({
			code: InternalErrorCode.Network,
			description: `List endpoint did not return a JSON array of Entity Identifiers: ${listEndpoint}`,
		});
	}
	return ok(parsed as EntityId[]);
}

/** Resolve-endpoint request parameters. `trustAnchor` and `entityType` may repeat. */
export interface ResolveRequestParams {
	sub: EntityId;
	trustAnchor: EntityId | EntityId[];
	/** Open value space — Federation §5.1 permits identifiers beyond the published set. */
	entityType?: EntityTypeIdentifier | EntityTypeIdentifier[];
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
		expectedContentType: MediaType.ResolveResponse,
	});
}

export { fetchExtendedSubordinatesList } from "./extended-list.js";
export {
	type FetchHistoricalKeysOptions,
	fetchHistoricalKeys,
} from "./fetch-historical-keys.js";
export {
	type FetchTrustMarkListParams,
	fetchTrustMarkList,
} from "./fetch-trust-mark-list.js";

export {
	type FetchSubordinateEventsOptions,
	fetchSubordinateEvents,
	type VerifySubordinateEventsOptions,
	verifySubordinateEventsResponse,
} from "./subordinate-events.js";
