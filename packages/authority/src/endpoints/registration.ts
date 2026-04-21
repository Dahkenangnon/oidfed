import {
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	DEFAULT_MAX_REQUEST_BODY_BYTES,
	decodeEntityStatement,
	ExplicitRegistrationRequestPayloadSchema,
	entityId,
	FederationErrorCode,
	JwtTyp,
	MediaType,
	nowSeconds,
	resolveTrustChains,
	shortestChain,
	signEntityStatement,
	type ValidatedTrustChain,
	validateTrustChain,
	verifyEntityStatement,
} from "@oidfed/core";
import type { HandlerContext } from "./context.js";
import { errorResponse, jwtResponse, readBodyWithLimit, requireMethod } from "./helpers.js";

/** OIDC default values applied when the RP omits standard fields. */
const OIDC_METADATA_DEFAULTS: Record<string, unknown> = {
	response_types: ["code"],
	grant_types: ["authorization_code"],
	token_endpoint_auth_method: "client_secret_basic",
};

/** Handles explicit client registration requests. */
export function createRegistrationHandler(
	ctx: HandlerContext,
): (request: Request) => Promise<Response> {
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
		if (contentType.includes("trust-chain+json")) {
			try {
				const chain = JSON.parse(body) as string[];
				if (!Array.isArray(chain) || chain.length === 0) {
					return errorResponse(
						400,
						"invalid_request",
						"Trust chain must be a non-empty JSON array",
					);
				}
				ecJwt = chain[0] as string;
			} catch {
				return errorResponse(400, "invalid_request", "Invalid JSON in trust chain body");
			}
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
		if (aud !== ctx.entityId) {
			return errorResponse(400, "invalid_request", "aud MUST match the OP's Entity ID");
		}

		const selfVerify = await verifyEntityStatement(ecJwt, reqPayload.jwks);
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

		const rpEntityId = entityId(reqPayload.sub);
		let bestChain: ValidatedTrustChain | undefined;

		if (ctx.trustAnchors && ctx.trustAnchors.size > 0) {
			// Prefer the trust_chain provided in the header when present and valid
			if (trustChainHeader && trustChainHeader.length > 0) {
				const headerValidation = await validateTrustChain(
					trustChainHeader,
					ctx.trustAnchors,
					ctx.options,
				);
				if (headerValidation.valid) {
					bestChain = headerValidation.chain;
				}
			}

			// Fall back to independent resolution if the provided chain was absent or invalid
			if (!bestChain) {
				const chainResult = await resolveTrustChains(rpEntityId, ctx.trustAnchors, ctx.options);

				const validChains: ValidatedTrustChain[] = [];
				for (const chain of chainResult.chains) {
					const result = await validateTrustChain(
						chain.statements as string[],
						ctx.trustAnchors,
						ctx.options,
					);
					if (result.valid) {
						validChains.push(result.chain);
					}
				}

				if (validChains.length === 0) {
					return errorResponse(
						403,
						FederationErrorCode.InvalidTrustChain,
						"No valid trust chains found for RP",
					);
				}

				bestChain = shortestChain(validChains);
			}
		}

		// Always fire invalidation hook — even on first registration the OP may hold stale cached data
		if (ctx.registrationConfig?.onRegistrationInvalidation) {
			await ctx.registrationConfig.onRegistrationInvalidation(rpEntityId);
		}

		let validatedMetadata: Record<string, unknown> | undefined;
		if (ctx.registrationProtocolAdapter && reqPayload.metadata) {
			const metadataRecord = reqPayload.metadata as Record<string, unknown>;
			const adapterResult = ctx.registrationProtocolAdapter.validateClientMetadata(metadataRecord);
			if (!adapterResult.ok) {
				return errorResponse(400, adapterResult.error.code, adapterResult.error.description);
			}
			validatedMetadata = adapterResult.value;
		}

		const { key: signingKey, kid } = await ctx.getSigningKey();
		const now = nowSeconds(ctx.options?.clock);

		let trustAnchorId: string;
		if (bestChain) {
			trustAnchorId = bestChain.trustAnchorId as string;
		} else if (ctx.trustAnchors && ctx.trustAnchors.size > 0) {
			trustAnchorId = ctx.trustAnchors.keys().next().value as string;
		} else {
			trustAnchorId = ctx.entityId;
		}

		// Exp must not exceed trust chain lifetime
		const configuredTtl =
			ctx.registrationResponseTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS;
		let registrationExp = now + configuredTtl;
		if (bestChain) {
			const chainExp = bestChain.expiresAt;
			if (chainExp < registrationExp) {
				registrationExp = chainExp;
			}
		}

		// Index 1 in the chain is the subordinate statement from the RP's immediate superior
		let rpImmediateSuperior: string | undefined;
		if (bestChain && bestChain.statements.length > 1) {
			const superiorStmt = bestChain.statements[1] as (typeof bestChain.statements)[0];
			rpImmediateSuperior = superiorStmt.payload.iss as string;
		}

		const responsePayload: Record<string, unknown> = {
			iss: ctx.entityId,
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
			if (ctx.registrationProtocolAdapter && bestChain) {
				enrichedMeta = ctx.registrationProtocolAdapter.enrichResponseMetadata(
					metadataForResponse as Record<string, unknown>,
					bestChain,
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

		if (ctx.registrationConfig?.generateClientSecret) {
			const clientSecret = await ctx.registrationConfig.generateClientSecret(rpEntityId);
			if (clientSecret) {
				responsePayload.client_secret = clientSecret;
			}
		}

		const responseJwt = await signEntityStatement(responsePayload, signingKey, {
			kid,
			typ: JwtTyp.ExplicitRegistrationResponse,
		});

		return jwtResponse(responseJwt, MediaType.ExplicitRegistrationResponse);
	};
}
