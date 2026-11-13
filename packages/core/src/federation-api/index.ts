import { setOwn } from "../callbacks.js";
import {
	DEFAULT_CLOCK_SKEW_SECONDS,
	type EntityTypeIdentifier,
	InternalErrorCode,
	JwtTyp,
	MediaType,
} from "../constants.js";
import { fetchFederationEndpoint } from "../endpoint-client.js";
import { LIST_UNORDERED_PARAMETERS, RESOLVE_UNORDERED_PARAMETERS } from "../endpoint-parameters.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import { verifyEntityStatement } from "../jose/verify.js";
import { validateJwkSetUseRequirement } from "../jwks/use-requirement.js";
import { safeLogger } from "./../logging.js";
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
import { type Clock, type EntityId, type FederationOptions, nowSeconds } from "../types.js";

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
	/** Host-selected maximum age; the specification supplies no universal limit. */
	maxAgeSeconds?: number;
	/** Enable future-iat rejection without selecting a maximum age. */
	checkIssuedAt?: boolean;
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
	for (const [name, value] of Object.entries(result.value.payload))
		if (!Object.hasOwn(parsed.data, name)) setOwn(parsed.data, name, value);
	if (parsed.data.iss !== options.expectedIssuer)
		return err(apiError("Response issuer does not match expectedIssuer"));
	if (parsed.data.trust_mark !== options.expectedTrustMark)
		return err(apiError("Status response does not match the submitted Trust Mark"));
	if (options.checkIssuedAt || options.maxAgeSeconds !== undefined) {
		const now = nowSeconds(options.clock);
		if (parsed.data.iat > now + (options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS))
			return err(apiError("Trust Mark Status Response was issued in the future"));
		if (
			options.maxAgeSeconds !== undefined &&
			(!Number.isFinite(options.maxAgeSeconds) ||
				options.maxAgeSeconds <= 0 ||
				now >= parsed.data.iat + options.maxAgeSeconds)
		)
			return err(apiError("Trust Mark Status Response exceeds the selected maximum age"));
	}
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
	/** Explicit non-security reasons allowing signatures strictly before revocation. Default rejects all revoked keys. */
	readonly allowedRevocationReasons?: readonly string[];
}

/** Select a historical key usable for verifying material issued at the supplied NumericDate. */
export function selectHistoricalVerificationKey(
	keys: readonly HistoricalKeyEntry[],
	options: SelectHistoricalVerificationKeyOptions,
): Result<HistoricalKeyEntry, FederationError> {
	if (!Number.isFinite(options.validAt) || !options.kid)
		return err(apiError("Historical key selection requires a finite time and kid"));
	const matchingKeys = keys.filter((key) => key.kid === options.kid);
	if (matchingKeys.length !== 1) return err(apiError("Historical key is missing or ambiguous"));
	const key = matchingKeys[0];
	if (!key) return err(apiError("Historical key is missing"));
	if (
		!Number.isFinite(key.exp) ||
		options.validAt >= key.exp ||
		(key.iat !== undefined && (!Number.isFinite(key.iat) || options.validAt < key.iat)) ||
		(key.nbf !== undefined && (!Number.isFinite(key.nbf) || options.validAt < key.nbf))
	)
		return err(apiError("Historical key was not eligible at signing time"));
	const revoked = key.revoked;
	if (revoked) {
		const reason = revoked.reason;
		if (
			!Number.isFinite(revoked.revoked_at) ||
			options.validAt >= revoked.revoked_at ||
			!reason ||
			reason === "unspecified" ||
			SECURITY_REVOCATION_REASONS.has(reason) ||
			options.securityRevocationReasons?.includes(reason) ||
			!options.allowedRevocationReasons?.includes(reason)
		)
			return err(apiError("Historical key is revoked"));
	}
	return ok(structuredClone(key));
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

/**
 * Fetch an authority's subordinate listing and return its Entity Identifiers.
 * Configure the endpoint and authentication together from trusted configuration or validated metadata.
 * This standalone client uses authentication.audience without an independent responder identity;
 * getEndpointAuthentication receives no responder. Authenticated requests use POST and never retry anonymously.
 * Collection traversal supplies its known authority identity for an additional audience check.
 */
export async function fetchListSubordinates(
	listEndpoint: string,
	filter?: ListSubordinatesFilter,
	options?: FederationOptions,
): Promise<Result<EntityId[], FederationError>> {
	return requestListSubordinates(listEndpoint, filter, options);
}

/** Internal traversal entry point with an independently known endpoint owner. */
export function fetchListSubordinatesForIssuer(
	listEndpoint: string,
	issuer: EntityId,
	options?: FederationOptions,
): Promise<Result<EntityId[], FederationError>> {
	return requestListSubordinates(listEndpoint, undefined, options, issuer);
}

async function requestListSubordinates(
	listEndpoint: string,
	filter?: ListSubordinatesFilter,
	options?: FederationOptions,
	issuer?: EntityId,
): Promise<Result<EntityId[], FederationError>> {
	safeLogger(options?.logger)?.debug("Starting fetch list subordinates");

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

	const selectors = new URLSearchParams();
	if (filter?.entityType !== undefined) {
		const types = Array.isArray(filter.entityType) ? filter.entityType : [filter.entityType];
		for (const t of types) selectors.append("entity_type", t);
	}
	if (filter?.trustMarked !== undefined) {
		selectors.set("trust_marked", filter.trustMarked ? "true" : "false");
	}
	if (filter?.trustMarkType !== undefined) {
		selectors.set("trust_mark_type", filter.trustMarkType);
	}
	if (filter?.intermediate !== undefined) {
		selectors.set("intermediate", filter.intermediate ? "true" : "false");
	}

	const result = await fetchFederationEndpoint(
		url.toString(),
		selectors,
		{
			...(options ?? {}),
			method: "GET",
			expectedStatus: 200,
			federationErrors: true,
			accept: MediaType.Json,
		},
		issuer,
		LIST_UNORDERED_PARAMETERS,
	);
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

/**
 * Fetch a Resolve Response JWT; use verifyResolveResponse to authenticate the returned statement.
 * Configure authentication.audience with the resolver's Entity Identifier. Neither the endpoint origin
 * nor a requested Trust Anchor establishes that identity. getEndpointAuthentication receives no responder.
 * Authenticated requests use POST and never retry anonymously after authentication failure.
 */
export async function fetchResolveResponse(
	resolveEndpoint: string,
	params: ResolveRequestParams,
	options?: FederationOptions,
): Promise<Result<string, FederationError>> {
	safeLogger(options?.logger)?.debug("Starting fetch resolve response");

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

	const selectors = new URLSearchParams({ sub: params.sub });

	const trustAnchors = Array.isArray(params.trustAnchor)
		? params.trustAnchor
		: [params.trustAnchor];
	if (trustAnchors.length === 0) {
		return err({
			code: InternalErrorCode.Network,
			description: "fetchResolveResponse requires at least one trustAnchor",
		});
	}
	for (const ta of trustAnchors) selectors.append("trust_anchor", ta);

	if (params.entityType !== undefined) {
		const types = Array.isArray(params.entityType) ? params.entityType : [params.entityType];
		for (const t of types) selectors.append("entity_type", t);
	}

	return fetchFederationEndpoint(
		url.toString(),
		selectors,
		{
			...(options ?? {}),
			method: "GET",
			expectedStatus: 200,
			federationErrors: true,
			accept: MediaType.ResolveResponse,
			expectedContentType: MediaType.ResolveResponse,
		},
		undefined,
		RESOLVE_UNORDERED_PARAMETERS,
	);
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
