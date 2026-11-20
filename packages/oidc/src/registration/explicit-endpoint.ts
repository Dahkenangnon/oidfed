/** OP-side explicit registration endpoint handler (self-contained, no authority dep). */

import {
	type CryptoContext,
	cloneData,
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	DEFAULT_MAX_REQUEST_BODY_BYTES,
	type EntityId,
	errorResponse,
	FederationErrorCode,
	type FederationOptions,
	federationEntry,
	federationSigningOptions,
	InternalErrorCode,
	isExactContentType,
	jwtResponse,
	MediaType,
	nowSeconds,
	readBodyWithLimit,
	requireMethod,
	safeLogger,
	signEntityStatement,
	type TrustAnchorSet,
	toPublicError,
} from "@oidfed/core";
import { registrationResponseChoices, withoutRegistrationChoices } from "../metadata-validation.js";
import type { RegistrationAccreditationPolicy } from "./accreditation.js";
import type { RegistrationProtocolAdapter } from "./adapter-types.js";
import {
	OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE,
	OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE,
} from "./constants.js";
import { processExplicitRegistration } from "./explicit-server.js";
import { validateRegistrationMetadataPolicy } from "./metadata-policy.js";
import { registrationProfile } from "./profile.js";
import { assertNonEmptyTrustAnchors } from "./trust-chains.js";

/** OIDC default values applied when the RP omits standard fields. */
const OIDC_METADATA_DEFAULTS: Record<string, unknown> = {
	response_types: ["code"],
	grant_types: ["authorization_code"],
	token_endpoint_auth_method: "client_secret_basic",
};
const REGISTRATION_MANAGEMENT_METADATA_FIELDS = [
	"registration_access_token",
	"registration_client_uri",
] as const;

export interface ExplicitRegistrationHandlerConfig extends RegistrationAccreditationPolicy {
	/** The OP's Entity Identifier, used for the aud check and as the response issuer. */
	readonly opEntityId: EntityId;
	/** Protocol role used to check the server's peer metadata. Defaults to OP. */
	readonly providerMetadataType?: "openid_provider" | "oauth_authorization_server";
	/** Federation-only signing key provider used for the signed registration response. */
	readonly crypto: CryptoContext;
	/** Non-empty trust anchors required for RP trust chain resolution. */
	readonly trustAnchors: TrustAnchorSet;
	/** TTL in seconds for the registration response JWT. Capped to chain expiry when a chain is resolved. */
	readonly registrationResponseTtlSeconds?: number;
	/** Optional protocol-specific adapter for metadata validation/enrichment. */
	readonly registrationProtocolAdapter?: RegistrationProtocolAdapter;
	/** Default disabled. In read-only mode the host MUST prevent the adapter-issued token from modifying registration. */
	readonly registrationManagement?: "disabled" | "read-only";
	/** Optional generator producing a client_secret embedded in the response. Returning undefined omits the field. */
	readonly generateClientSecret?: (sub: EntityId) => Promise<string | undefined>;
	/** Optional late pre-commit hook fired after response preparation and before `onRegistration`. */
	readonly onRegistrationInvalidation?: (sub: EntityId) => Promise<void>;
	/** Optional callback fired when dynamic registration completes successfully. */
	readonly onRegistration?: (
		sub: EntityId,
		clientMetadata: Record<string, unknown>,
		clientSecret?: string,
	) => Promise<void>;
	/** Federation-wide options (httpClient, clock, etc.). */
	readonly options: FederationOptions;
}

/**
 * Build the OP-side `/federation_registration` endpoint handler.
 *
 * The handler validates an Explicit Registration Request (signed Entity Configuration
 * JWT body OR JSON Trust Chain body), resolves the RP's trust chain, optionally runs
 * a protocol-specific adapter, and returns a signed Explicit Registration Response.
 */
export function createExplicitRegistrationHandler(
	config: ExplicitRegistrationHandlerConfig,
): (request: Request) => Promise<Response> {
	const profile = registrationProfile(config.providerMetadataType);
	const responseSchema = profile.responseFor(config.options);
	const trustAnchors = assertNonEmptyTrustAnchors(config.trustAnchors);
	const registrationManagement = config.registrationManagement ?? "disabled";
	if (registrationManagement !== "disabled" && registrationManagement !== "read-only")
		throw new TypeError("registrationManagement must be disabled or read-only");

	return async (request: Request) => {
		const logger = safeLogger(config.options?.logger);
		const methodError = requireMethod(request, "POST");
		if (methodError) return methodError;

		const contentType = request.headers.get("Content-Type");
		const isEntityStatementBody = isExactContentType(contentType, MediaType.EntityStatement);
		const isTrustChainBody = isExactContentType(contentType, MediaType.TrustChain);
		if (!isEntityStatementBody && !isTrustChainBody) {
			return errorResponse(
				400,
				"invalid_request",
				"Content-Type must be exactly application/entity-statement+jwt or application/trust-chain+json",
			);
		}

		const read = await readBodyWithLimit(request, DEFAULT_MAX_REQUEST_BODY_BYTES);
		if (!read.ok) return errorResponse(413, "invalid_request", "Request body too large");
		const body = read.text;
		if (!body) return errorResponse(400, "invalid_request", "Missing request body");

		const processed = await processExplicitRegistration(body, contentType as string, trustAnchors, {
			...config.options,
			...(config.trustMarkRequirements
				? { trustMarkRequirements: config.trustMarkRequirements }
				: {}),
			...(config.beforeRegistration ? { beforeRegistration: config.beforeRegistration } : {}),
			opEntityId: config.opEntityId,
			...(config.providerMetadataType ? { providerMetadataType: config.providerMetadataType } : {}),
		});
		if (!processed.ok) {
			// A bad request signature is a client error; retain 400 while using a public code.
			const error = toPublicError(
				processed.error.code === InternalErrorCode.SignatureInvalid
					? {
							code: FederationErrorCode.InvalidRequest,
							description: "RP Entity Configuration self-signature is invalid",
						}
					: processed.error,
			);
			return errorResponse(error.status, error.code, error.description);
		}
		const {
			requestPayload: reqPayload,
			rpEntityId,
			trustChain: bestChain,
			peerResolvedOpMetadata,
		} = processed.value;

		const policyChain = cloneData(bestChain);

		const adapterContext = {
			flow: "explicit",
			clientMetadataType: profile.clientType,
			signal: request.signal,
			...(peerResolvedOpMetadata !== undefined
				? { peerResolvedOpMetadata: cloneData(peerResolvedOpMetadata) }
				: {}),
		} as const;

		const adapter = config.registrationProtocolAdapter;
		if (adapter) {
			let accepted: ReturnType<RegistrationProtocolAdapter["validateClientMetadata"]>;
			try {
				accepted = adapter.validateClientMetadata(
					cloneData(bestChain.resolvedMetadata),
					adapterContext,
				);
			} catch (error) {
				logger?.error("RP metadata validation failed in registrationProtocolAdapter");
				throw error;
			}
			if (!accepted.ok) {
				logger?.warn("RP metadata was rejected by registrationProtocolAdapter");
				return errorResponse(400, accepted.error.code, accepted.error.description);
			}
		}

		const keySet = await federationEntry(config.crypto, {
			issuer: config.opEntityId,
			subject: rpEntityId,
		});
		const now = nowSeconds(config.options?.clock);

		const trustAnchorId = bestChain.trustAnchorId as string;

		const configuredTtl =
			config.registrationResponseTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS;
		let registrationExp = now + configuredTtl;
		if (bestChain) {
			const chainExp = bestChain.expiresAt;
			if (chainExp < registrationExp) {
				registrationExp = chainExp;
			}
		}

		if (registrationExp <= now) {
			return errorResponse(
				400,
				FederationErrorCode.InvalidTrustChain,
				"Registration chain has expired",
			);
		}

		let rpImmediateSuperior: string | undefined;
		if (bestChain && bestChain.statements.length > 1) {
			const superiorStmt = bestChain.statements[1] as (typeof bestChain.statements)[0];
			rpImmediateSuperior = superiorStmt.payload.iss as string;
		}

		const responsePayload: Record<string, unknown> = {
			iss: config.opEntityId,
			sub: reqPayload.sub,
			aud: reqPayload.sub,
			iat: now,
			exp: registrationExp,
			trust_anchor: trustAnchorId,
			authority_hints: [rpImmediateSuperior],
		};

		let responseMetadata = cloneData(bestChain.resolvedMetadata);
		if (adapter?.enrichResponseMetadata) {
			try {
				responseMetadata = cloneData(
					adapter.enrichResponseMetadata(responseMetadata, cloneData(bestChain), adapterContext),
				);
			} catch (error) {
				logger?.error(
					"Explicit Client Registration response metadata preparation failed in registrationProtocolAdapter",
				);
				throw error;
			}
		}
		const rpMeta = { ...responseMetadata[profile.clientType] };
		if (!rpMeta.client_id) rpMeta.client_id = reqPayload.sub;

		for (const [key, defaultValue] of Object.entries(OIDC_METADATA_DEFAULTS)) {
			if (!(key in rpMeta)) {
				const candidate = {
					...responseMetadata,
					[profile.clientType]: { ...rpMeta, [key]: defaultValue },
				};
				// Apply a recommended default only when federation policy permits it.
				if (validateRegistrationMetadataPolicy(candidate, policyChain, config.options).ok) {
					rpMeta[key] = defaultValue;
				}
			}
		}

		const outputMetadata = { ...responseMetadata, [profile.clientType]: rpMeta };
		responsePayload.metadata = outputMetadata;
		if (registrationManagement === "disabled")
			outputMetadata[profile.clientType] = stripRegistrationManagementFields(
				outputMetadata[profile.clientType] ?? {},
			);
		const choiceCheck = profile.oidc
			? registrationResponseChoices(
					outputMetadata[profile.clientType] ?? {},
					bestChain.resolvedMetadata[profile.clientType] ?? {},
				)
			: { ok: true as const };
		if (!choiceCheck.ok)
			return errorResponse(400, choiceCheck.error.code, choiceCheck.error.description);
		if (profile.oidc)
			outputMetadata[profile.clientType] = withoutRegistrationChoices(
				outputMetadata[profile.clientType] ?? {},
			);
		const policyCheck = validateRegistrationMetadataPolicy(
			responsePayload.metadata as Record<string, Record<string, unknown>>,
			policyChain,
			config.options,
		);
		if (!policyCheck.ok)
			return errorResponse(400, policyCheck.error.code, policyCheck.error.description);
		const preparedResponse = responseSchema.safeParse(responsePayload);
		if (!preparedResponse.success) {
			return errorResponse(
				500,
				FederationErrorCode.ServerError,
				"Registration response metadata preparation failed",
			);
		}

		if (config.generateClientSecret) {
			let clientSecret: string | undefined;
			try {
				clientSecret = await config.generateClientSecret(rpEntityId);
			} catch (error) {
				logger?.error(
					"Explicit Client Registration client_secret generation failed in generateClientSecret",
				);
				throw error;
			}
			if (clientSecret) {
				const metadataRecord = responsePayload.metadata as Record<string, unknown>;
				const rpMeta = (metadataRecord[profile.clientType] ?? {}) as Record<string, unknown>;
				rpMeta.client_secret = clientSecret;
				metadataRecord[profile.clientType] = rpMeta;
				responsePayload.metadata = metadataRecord;
			}
		}
		const responseValidation = responseSchema.safeParse(responsePayload);
		if (!responseValidation.success) {
			return errorResponse(
				500,
				FederationErrorCode.ServerError,
				"Registration response metadata preparation failed",
			);
		}

		const finalPolicy = validateRegistrationMetadataPolicy(
			responsePayload.metadata as Record<string, Record<string, unknown>>,
			policyChain,
			config.options,
		);
		if (!finalPolicy.ok)
			return errorResponse(400, finalPolicy.error.code, finalPolicy.error.description);

		const responseJwt = await signEntityStatement(responsePayload, keySet, {
			...federationSigningOptions(config.options),
			typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE,
		});

		if (config.onRegistrationInvalidation) {
			try {
				await config.onRegistrationInvalidation(rpEntityId);
			} catch {
				logger?.error(
					"Existing client registration invalidation failed in onRegistrationInvalidation",
				);
				return errorResponse(500, FederationErrorCode.ServerError, "Registration hook failed");
			}
		}

		if (config.onRegistration) {
			const metadataRecord = responsePayload.metadata as Record<string, unknown>;
			const clientMetadata = (metadataRecord?.[profile.clientType] ?? {}) as Record<
				string,
				unknown
			>;
			const clientSecret =
				typeof clientMetadata.client_secret === "string" ? clientMetadata.client_secret : undefined;
			try {
				await config.onRegistration(rpEntityId, clientMetadata, clientSecret);
			} catch {
				logger?.error("Explicit Client Registration failed in onRegistration");
				return errorResponse(500, FederationErrorCode.ServerError, "Registration hook failed");
			}
		}

		logger?.info("Explicit Client Registration completed");
		return jwtResponse(responseJwt, OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE);
	};
}

function stripRegistrationManagementFields(
	metadata: Record<string, unknown>,
): Record<string, unknown> {
	const scrubbed = { ...metadata };
	for (const field of REGISTRATION_MANAGEMENT_METADATA_FIELDS) {
		delete scrubbed[field];
	}
	return scrubbed;
}
