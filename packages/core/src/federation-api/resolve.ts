import { type EntityTypeIdentifier, InternalErrorCode, JwtTyp, MediaType } from "../constants.js";
import { fetchFederationEndpoint } from "../endpoint-client.js";
import { RESOLVE_UNORDERED_PARAMETERS } from "../endpoint-parameters.js";
import { err, type FederationError, type Result } from "../errors.js";
import { verifyEntityStatement } from "../jose/verify.js";
import { safeLogger } from "../logging.js";
import { type ResolveResponsePayload, ResolveResponsePayloadSchema } from "../schemas/endpoints.js";
import { EntityIdSchema } from "../schemas/entity-id.js";
import type { JWKSet } from "../schemas/jwk.js";
import type { EntityId, FederationOptions } from "../types.js";
import {
	apiError,
	buildVerifyOpts,
	type VerifyOptions,
	validateExpectedIssuer,
} from "./verify-issuer.js";

export interface VerifyResolveResponseOptions extends VerifyOptions {
	expectedSubject: string;
	/** Requesting party's Entity Identifier; required to accept a response containing aud. */
	expectedAudience?: string;
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

/** Resolve-endpoint request parameters. `trustAnchor` and `entityType` may repeat. */
export interface ResolveRequestParams {
	sub: EntityId;
	trustAnchor: EntityId | EntityId[];
	/** Accept extension Entity Type Identifiers as permitted by Federation §5.1. */
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
	options: FederationOptions,
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
