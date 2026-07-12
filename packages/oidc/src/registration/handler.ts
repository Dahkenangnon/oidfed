/** OP-side explicit registration endpoint handler (self-contained, no authority dep). */
import {
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	DEFAULT_MAX_REQUEST_BODY_BYTES,
	decodeEntityStatement,
	type EntityId,
	entityId,
	errorResponse,
	FederationErrorCode,
	type FederationKeyProvider,
	type FederationOptions,
	JwtTyp,
	jwtResponse,
	nowSeconds,
	readBodyWithLimit,
	requireMethod,
	signEntityStatement,
	type TrustAnchorSet,
	type ValidatedTrustChain,
	verifyEntityStatement,
} from "@oidfed/core";
import {
	OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE,
	OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE,
} from "../constants.js";
import { ExplicitRegistrationRequestPayloadSchema } from "../schemas/explicit-registration.js";
import type { RegistrationProtocolAdapter } from "./adapter-types.js";
import {
	assertNonEmptyTrustAnchors,
	parseTrustChainJsonBody,
	resolveAndValidateBestChain,
	validateSuppliedTrustChain,
} from "./helpers.js";

/** OIDC default values applied when the RP omits standard fields. */
const OIDC_METADATA_DEFAULTS: Record<string, unknown> = {
	response_types: ["code"],
	grant_types: ["authorization_code"],
	token_endpoint_auth_method: "client_secret_basic",
};

export interface ExplicitRegistrationHandlerConfig {
	/** The OP's Entity Identifier — used as the aud check target and as the issuer of the response. */
	readonly opEntityId: EntityId;
	/** Federation-only signing key provider used for the signed registration response. */
	readonly keyProvider: FederationKeyProvider;
	/** Non-empty trust anchors required for RP trust chain resolution. */
	readonly trustAnchors: TrustAnchorSet;
	/** TTL in seconds for the registration response JWT. Capped to chain expiry when a chain is resolved. */
	readonly registrationResponseTtlSeconds?: number;
	/** Optional protocol-specific adapter for metadata validation/enrichment. */
	readonly registrationProtocolAdapter?: RegistrationProtocolAdapter;
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
	readonly options?: FederationOptions;
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
	const trustAnchors = assertNonEmptyTrustAnchors(config.trustAnchors);

	return async (request: Request) => {
		const methodError = requireMethod(request, "POST");
		if (methodError) return methodError;

		const contentType = request.headers.get("Content-Type");
		if (
			!contentType ||
			(!contentType.includes("entity-statement+jwt") && !contentType.includes("trust-chain+json"))
		) {
			return errorResponse(
				400,
				"invalid_request",
				"Content-Type must be application/entity-statement+jwt or application/trust-chain+json",
			);
		}

		const read = await readBodyWithLimit(request, DEFAULT_MAX_REQUEST_BODY_BYTES);
		if (!read.ok) return errorResponse(413, "invalid_request", "Request body too large");
		const body = read.text;
		if (!body) return errorResponse(400, "invalid_request", "Missing request body");

		let ecJwt: string;
		let suppliedBodyTrustChain: readonly string[] | undefined;
		const isTrustChainBody = contentType.includes("trust-chain+json");
		if (isTrustChainBody) {
			const parseResult = parseTrustChainJsonBody(body);
			if (!parseResult.ok) {
				return errorResponse(400, parseResult.error.code, parseResult.error.description);
			}
			suppliedBodyTrustChain = parseResult.value;
			ecJwt = suppliedBodyTrustChain[0] as string;
		} else {
			ecJwt = body;
		}

		const decoded = decodeEntityStatement(ecJwt);
		if (!decoded.ok) {
			return errorResponse(400, "invalid_request", "Failed to decode request JWT");
		}

		const header = decoded.value.header;
		const payload = decoded.value.payload as Record<string, unknown>;

		if (header.typ !== JwtTyp.EntityStatement) {
			return errorResponse(
				400,
				"invalid_request",
				`Invalid typ header: expected '${JwtTyp.EntityStatement}'`,
			);
		}

		const parseResult = ExplicitRegistrationRequestPayloadSchema.safeParse(payload);
		if (!parseResult.success) {
			return errorResponse(400, "invalid_request", "Invalid registration request payload");
		}

		const reqPayload = parseResult.data;

		const aud = reqPayload.aud;
		if (aud !== config.opEntityId) {
			return errorResponse(400, "invalid_request", "aud MUST match the OP's Entity ID");
		}

		const selfVerify = await verifyEntityStatement(ecJwt, reqPayload.jwks, {
			...(config.options?.clock ? { clock: config.options.clock } : {}),
			...(config.options?.clockSkewSeconds !== undefined
				? { clockSkewSeconds: config.options.clockSkewSeconds }
				: {}),
		});
		if (!selfVerify.ok) {
			return errorResponse(
				400,
				"invalid_request",
				"Request JWT self-signature verification failed",
			);
		}

		if (reqPayload.sub !== reqPayload.iss) {
			return errorResponse(400, "invalid_request", "RP Entity Configuration iss MUST equal sub");
		}

		const trustChainHeader = header.trust_chain as string[] | undefined;
		if (trustChainHeader && trustChainHeader.length > 0) {
			const firstEntry = trustChainHeader[0] as string;
			const firstDecoded = decodeEntityStatement(firstEntry);
			if (!firstDecoded.ok) {
				return errorResponse(
					400,
					FederationErrorCode.InvalidTrustChain,
					"Failed to decode first entry of trust_chain header",
				);
			}
			const firstPayload = firstDecoded.value.payload as Record<string, unknown>;
			if (firstPayload.iss !== reqPayload.sub || firstPayload.sub !== reqPayload.sub) {
				return errorResponse(
					400,
					FederationErrorCode.InvalidTrustChain,
					"First entry of trust_chain header MUST be the subject's Entity Configuration",
				);
			}
		}

		const peerTrustChainHeader = header.peer_trust_chain as string[] | undefined;

		// peer_trust_chain MUST NOT appear when the request body is a Trust Chain.
		if (isTrustChainBody && peerTrustChainHeader !== undefined) {
			return errorResponse(
				400,
				"invalid_request",
				"peer_trust_chain MUST NOT be used when the request body is a Trust Chain",
			);
		}

		if (peerTrustChainHeader && peerTrustChainHeader.length > 0) {
			const peerFirstDecoded = decodeEntityStatement(peerTrustChainHeader[0] as string);
			if (!peerFirstDecoded.ok) {
				return errorResponse(
					400,
					FederationErrorCode.InvalidTrustChain,
					"Failed to decode first entry of peer_trust_chain header",
				);
			}
			const peerFirstPayload = peerFirstDecoded.value.payload as Record<string, unknown>;
			if (
				peerFirstPayload.iss !== config.opEntityId ||
				peerFirstPayload.sub !== config.opEntityId
			) {
				return errorResponse(
					400,
					FederationErrorCode.InvalidTrustChain,
					"First entry of peer_trust_chain header MUST be the OP's Entity Configuration",
				);
			}

			// When both headers are present, both Trust Chains MUST end at the same TA.
			// Compare the headers directly (independent of any validation fallback below).
			if (trustChainHeader && trustChainHeader.length > 0) {
				const rpHeaderLastDecoded = decodeEntityStatement(
					trustChainHeader[trustChainHeader.length - 1] as string,
				);
				const peerHeaderLastDecoded = decodeEntityStatement(
					peerTrustChainHeader[peerTrustChainHeader.length - 1] as string,
				);
				if (!rpHeaderLastDecoded.ok || !peerHeaderLastDecoded.ok) {
					return errorResponse(
						400,
						FederationErrorCode.InvalidTrustChain,
						"Failed to decode last entry of trust_chain or peer_trust_chain header",
					);
				}
				const rpHeaderTaId = (rpHeaderLastDecoded.value.payload as Record<string, unknown>).iss as
					| string
					| undefined;
				const peerHeaderTaId = (peerHeaderLastDecoded.value.payload as Record<string, unknown>)
					.iss as string | undefined;
				if (rpHeaderTaId !== peerHeaderTaId) {
					return errorResponse(
						400,
						FederationErrorCode.InvalidTrustChain,
						`peer_trust_chain Trust Anchor ('${peerHeaderTaId}') does not match trust_chain Trust Anchor ('${rpHeaderTaId}')`,
					);
				}
			}
		}

		const rpEntityId = entityId(reqPayload.sub);
		let bestChain: ValidatedTrustChain | undefined;

		if (suppliedBodyTrustChain !== undefined) {
			const bodyValidation = await validateSuppliedTrustChain(
				suppliedBodyTrustChain,
				trustAnchors,
				{
					...config.options,
					expectedSubject: rpEntityId,
					explicitRegistrationAudience: config.opEntityId,
					label: "trust-chain+json",
				},
			);
			if (!bodyValidation.ok) {
				return errorResponse(400, bodyValidation.error.code, bodyValidation.error.description);
			}
			bestChain = bodyValidation.value;
		} else if (trustChainHeader !== undefined) {
			const headerValidation = await validateSuppliedTrustChain(trustChainHeader, trustAnchors, {
				...config.options,
				expectedSubject: rpEntityId,
				explicitRegistrationAudience: config.opEntityId,
				label: "trust_chain",
			});
			if (!headerValidation.ok) {
				return errorResponse(400, headerValidation.error.code, headerValidation.error.description);
			}
			bestChain = headerValidation.value;
		} else {
			const chainResult = await resolveAndValidateBestChain(
				rpEntityId,
				trustAnchors,
				config.options ?? {},
			);
			if (!chainResult.ok) {
				return errorResponse(403, chainResult.error.code, chainResult.error.description);
			}
			bestChain = chainResult.value;
		}

		let peerResolvedOpMetadata: Readonly<Record<string, unknown>> | undefined;
		if (peerTrustChainHeader && peerTrustChainHeader.length > 0) {
			const peerValidation = await validateSuppliedTrustChain(peerTrustChainHeader, trustAnchors, {
				...config.options,
				expectedSubject: config.opEntityId,
				label: "peer_trust_chain",
			});
			if (!peerValidation.ok) {
				return errorResponse(
					400,
					FederationErrorCode.InvalidTrustChain,
					peerValidation.error.description,
				);
			}
			if (peerValidation.value.trustAnchorId !== bestChain.trustAnchorId) {
				return errorResponse(
					400,
					FederationErrorCode.InvalidTrustChain,
					`peer_trust_chain Trust Anchor ('${peerValidation.value.trustAnchorId}') does not match selected RP Trust Anchor ('${bestChain.trustAnchorId}')`,
				);
			}
			peerResolvedOpMetadata = peerValidation.value.resolvedMetadata.openid_provider ?? {};
		}

		const adapterContext =
			peerResolvedOpMetadata !== undefined ? { peerResolvedOpMetadata } : undefined;

		let validatedMetadata: Record<string, unknown> | undefined;
		if (config.registrationProtocolAdapter && reqPayload.metadata) {
			const metadataRecord = reqPayload.metadata as Record<string, unknown>;
			const adapterResult = config.registrationProtocolAdapter.validateClientMetadata(
				metadataRecord,
				adapterContext,
			);
			if (!adapterResult.ok) {
				return errorResponse(400, adapterResult.error.code, adapterResult.error.description);
			}
			validatedMetadata = adapterResult.value;
		}

		const keySet = await config.keyProvider.getFederationKeySet();
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
			authority_hints: rpImmediateSuperior ? [rpImmediateSuperior] : [trustAnchorId],
		};

		const metadataForResponse = validatedMetadata ?? reqPayload.metadata;
		if (metadataForResponse) {
			let enrichedMeta: Record<string, unknown>;
			if (config.registrationProtocolAdapter && bestChain) {
				enrichedMeta = config.registrationProtocolAdapter.enrichResponseMetadata(
					metadataForResponse as Record<string, unknown>,
					bestChain,
					adapterContext,
				);
			} else {
				enrichedMeta = metadataForResponse as Record<string, unknown>;
			}

			const rpMeta = (enrichedMeta.openid_relying_party ?? {}) as Record<string, unknown>;
			if (!rpMeta.client_id) {
				rpMeta.client_id = reqPayload.sub;
			}

			for (const [key, defaultValue] of Object.entries(OIDC_METADATA_DEFAULTS)) {
				if (!(key in rpMeta)) {
					rpMeta[key] = defaultValue;
				}
			}

			enrichedMeta.openid_relying_party = rpMeta;
			responsePayload.metadata = enrichedMeta;
		} else {
			responsePayload.metadata = {
				openid_relying_party: {
					client_id: reqPayload.sub,
					...OIDC_METADATA_DEFAULTS,
				},
			};
		}

		if (config.generateClientSecret) {
			const clientSecret = await config.generateClientSecret(rpEntityId);
			if (clientSecret) {
				const metadataRecord = responsePayload.metadata as Record<string, unknown>;
				const rpMeta = (metadataRecord.openid_relying_party ?? {}) as Record<string, unknown>;
				rpMeta.client_secret = clientSecret;
				metadataRecord.openid_relying_party = rpMeta;
				responsePayload.metadata = metadataRecord;
			}
		}

		const responseJwt = await signEntityStatement(responsePayload, keySet.signer, {
			typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE,
		});

		if (config.onRegistrationInvalidation) {
			try {
				await config.onRegistrationInvalidation(rpEntityId);
			} catch {
				return errorResponse(500, FederationErrorCode.ServerError, "Registration hook failed");
			}
		}

		if (config.onRegistration) {
			const metadataRecord = responsePayload.metadata as Record<string, unknown>;
			const clientMetadata = (metadataRecord?.openid_relying_party ?? {}) as Record<
				string,
				unknown
			>;
			const clientSecret =
				typeof clientMetadata.client_secret === "string" ? clientMetadata.client_secret : undefined;
			try {
				await config.onRegistration(rpEntityId, clientMetadata, clientSecret);
			} catch {
				return errorResponse(500, FederationErrorCode.ServerError, "Registration hook failed");
			}
		}

		return jwtResponse(responseJwt, OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE);
	};
}
