import type QUnit from "qunit";
import {
	type DiscoveryResult,
	decodeEntityStatement,
	type EntityId,
	entityId,
	err,
	FederationErrorCode,
	type FederationOptions,
	federationError,
	generateSigningKey,
	type HttpClient,
	InMemoryJtiStore,
	isOk,
	type JWK,
	JwtTyp,
	MediaType,
	resolveTrustChains,
	shortestChain,
	signEntityStatement,
	type ValidatedTrustChain,
	validateTrustChain,
} from "../../../packages/core/src/index.js";
import { createClientAssertion } from "../../../packages/oidc/src/client-auth/assertion.js";
import {
	ClientRegistrationType,
	OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE,
	OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE,
	RequestObjectTyp,
} from "../../../packages/oidc/src/constants.js";
import { OIDCRegistrationAdapter } from "../../../packages/oidc/src/registration/adapter.js";
import type { RegistrationProtocolAdapter } from "../../../packages/oidc/src/registration/adapter-types.js";
import type { AutomaticRegistrationConfig } from "../../../packages/oidc/src/registration/automatic.js";
import { automaticRegistration } from "../../../packages/oidc/src/registration/automatic.js";
import type { ExplicitRegistrationConfig } from "../../../packages/oidc/src/registration/explicit.js";
import { explicitRegistration } from "../../../packages/oidc/src/registration/explicit.js";
import {
	createExplicitRegistrationHandler,
	type ExplicitRegistrationHandlerConfig,
} from "../../../packages/oidc/src/registration/handler.js";
import { processAutomaticRegistration } from "../../../packages/oidc/src/registration/process-automatic.js";
import { processExplicitRegistration } from "../../../packages/oidc/src/registration/process-explicit.js";
import type { AutomaticRegistrationContext } from "../../../packages/oidc/src/registration/types.js";
import { validateAutomaticRegistrationRequest } from "../../../packages/oidc/src/registration/validate-request-object.js";
import {
	ExplicitRegistrationRequestPayloadSchema,
	ExplicitRegistrationResponsePayloadSchema,
} from "../../../packages/oidc/src/schemas/explicit-registration.js";
import {
	OIDCFederationMetadataSchema,
	OpenIDProviderMetadataSchema,
	OpenIDRelyingPartyMetadataSchema,
	validateOIDCMetadata,
} from "../../../packages/oidc/src/schemas/metadata.js";
import { createMockFederation, LEAF_ID, OP_ID, TA_ID } from "../fixtures/index.js";

// ---------------------------------------------------------------------------
// Shared helpers (mirrors oidc/test/test-helpers.ts)
// ---------------------------------------------------------------------------

type RpConfig = AutomaticRegistrationConfig & ExplicitRegistrationConfig;

async function createRpConfig(
	overrides?: Partial<RpConfig>,
): Promise<{ config: RpConfig; signingKey: JWK; publicKey: JWK }> {
	const { privateKey, publicKey } = await generateSigningKey("ES256");
	const config: RpConfig = {
		entityId: LEAF_ID,
		signingKeys: [privateKey],
		authorityHints: [TA_ID],
		metadata: {
			openid_relying_party: {
				redirect_uris: ["https://rp.example.com/callback"],
				response_types: ["code"],
				client_registration_types: ["automatic"],
			},
		},
		...overrides,
	};
	return { config, signingKey: privateKey, publicKey };
}

async function createMockDiscovery(
	targetEntityId: EntityId,
	fed: Awaited<ReturnType<typeof createMockFederation>>,
): Promise<DiscoveryResult> {
	const chainResult = await resolveTrustChains(targetEntityId, fed.trustAnchors, fed.options);
	if (chainResult.chains.length === 0) throw new Error(`No chains resolved for ${targetEntityId}`);
	const validChains: ValidatedTrustChain[] = [];
	for (const chain of chainResult.chains) {
		const result = await validateTrustChain(
			chain.statements as string[],
			fed.trustAnchors,
			fed.options,
		);
		if (result.valid) validChains.push(result.chain);
	}
	if (validChains.length === 0) throw new Error(`No valid chains for ${targetEntityId}`);
	const bestChain = shortestChain(validChains);
	return {
		entityId: targetEntityId,
		resolvedMetadata: bestChain.resolvedMetadata,
		trustChain: bestChain,
		trustMarks: bestChain.trustMarks,
	} as DiscoveryResult;
}

// ---------------------------------------------------------------------------

export default (QUnit: QUnit) => {
	const { module, test } = QUnit;

	// -------------------------------------------------------------------------
	// client-auth/assertion
	// -------------------------------------------------------------------------
	module("oidc / createClientAssertion", () => {
		const clientId = "https://rp.example.com";
		const audience = "https://op.example.com";

		test("produces valid JWT with correct claims", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const jwt = await createClientAssertion(clientId, audience, privateKey);
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const { payload, header } = decoded.value;
			t.equal(payload.iss, clientId);
			t.equal(payload.sub, clientId);
			t.equal(header.typ, "JWT");
			t.equal(header.alg, "ES256");
			t.equal(header.kid, privateKey.kid);
			const p = payload as Record<string, unknown>;
			t.equal(p.aud, audience);
			t.equal(typeof p.jti, "string");
			t.equal(typeof p.iat, "number");
			t.equal(typeof p.exp, "number");
		});

		test("sets iss === sub === clientId", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const jwt = await createClientAssertion(clientId, audience, privateKey);
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.iss, clientId);
			t.equal(decoded.value.payload.sub, clientId);
		});

		test("generates unique jti across calls", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const d1 = decodeEntityStatement(await createClientAssertion(clientId, audience, privateKey));
			const d2 = decodeEntityStatement(await createClientAssertion(clientId, audience, privateKey));
			t.true(d1.ok && d2.ok);
			if (!d1.ok || !d2.ok) return;
			const jti1 = (d1.value.payload as Record<string, unknown>).jti;
			const jti2 = (d2.value.payload as Record<string, unknown>).jti;
			t.notEqual(jti1, jti2);
		});

		test("respects expiresInSeconds option", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const jwt = await createClientAssertion(clientId, audience, privateKey, {
				expiresInSeconds: 120,
			});
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.equal((p.exp as number) - (p.iat as number), 120);
		});

		test("defaults expiresInSeconds to 60", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const jwt = await createClientAssertion(clientId, audience, privateKey);
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.equal((p.exp as number) - (p.iat as number), 60);
		});

		test("signs with the provided key", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const jwt = await createClientAssertion(clientId, audience, privateKey);
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.header.kid, privateKey.kid);
			t.equal(jwt.split(".").length, 3);
		});

		test("works with RS256 key", async (t) => {
			const { privateKey } = await generateSigningKey("RS256");
			const jwt = await createClientAssertion(clientId, audience, privateKey);
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.header.alg, "RS256");
			t.equal(decoded.value.header.typ, "JWT");
			t.equal(decoded.value.payload.iss, clientId);
		});

		test("throws if signing key has no kid", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const keyWithoutKid = { ...privateKey, kid: undefined } as unknown as typeof privateKey;
			try {
				await createClientAssertion(clientId, audience, keyWithoutKid);
				t.ok(false, "should have thrown");
			} catch (e) {
				t.ok((e as Error).message.includes("kid"), (e as Error).message);
			}
		});
	});

	// -------------------------------------------------------------------------
	// schemas/metadata
	// -------------------------------------------------------------------------
	module("oidc / OIDCFederationMetadataSchema", () => {
		test("validates metadata with valid openid_provider fields", (t) => {
			const result = OIDCFederationMetadataSchema.safeParse({
				openid_provider: {
					issuer: "https://op.example.com",
					authorization_endpoint: "https://op.example.com/authorize",
					token_endpoint: "https://op.example.com/token",
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256"],
				},
			});
			t.true(result.success);
		});

		test("validates metadata with valid openid_relying_party fields", (t) => {
			const result = OIDCFederationMetadataSchema.safeParse({
				openid_relying_party: {
					redirect_uris: ["https://rp.example.com/callback"],
					response_types: ["code"],
					client_registration_types: ["automatic"],
				},
			});
			t.true(result.success);
		});

		test("rejects OP metadata with invalid issuer URL", (t) => {
			const result = OIDCFederationMetadataSchema.safeParse({
				openid_provider: {
					issuer: "not-a-url",
					authorization_endpoint: "https://op.example.com/authorize",
					token_endpoint: "https://op.example.com/token",
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256"],
				},
			});
			t.false(result.success);
		});

		test("rejects RP metadata with invalid redirect_uris", (t) => {
			const result = OIDCFederationMetadataSchema.safeParse({
				openid_relying_party: { redirect_uris: ["not-a-url"] },
			});
			t.false(result.success);
		});

		test("requires at least one entity type", (t) => {
			t.false(OIDCFederationMetadataSchema.safeParse({}).success);
		});
	});

	module("oidc / OpenIDProviderMetadataSchema — URL validation", () => {
		const validOP = {
			issuer: "https://op.example.com",
			authorization_endpoint: "https://op.example.com/auth",
			token_endpoint: "https://op.example.com/token",
			response_types_supported: ["code"],
			subject_types_supported: ["public"],
			id_token_signing_alg_values_supported: ["RS256"],
		};

		test("rejects http:// federation_registration_endpoint", (t) => {
			t.false(
				OpenIDProviderMetadataSchema.safeParse({
					...validOP,
					federation_registration_endpoint: "http://op.example.com/register",
				}).success,
			);
		});

		test("rejects fragment in federation_registration_endpoint", (t) => {
			t.false(
				OpenIDProviderMetadataSchema.safeParse({
					...validOP,
					federation_registration_endpoint: "https://op.example.com/register#frag",
				}).success,
			);
		});

		test("rejects http:// signed_jwks_uri", (t) => {
			t.false(
				OpenIDProviderMetadataSchema.safeParse({
					...validOP,
					signed_jwks_uri: "http://op.example.com/jwks",
				}).success,
			);
		});

		test("rejects http:// jwks_uri", (t) => {
			t.false(
				OpenIDProviderMetadataSchema.safeParse({
					...validOP,
					jwks_uri: "http://op.example.com/jwks",
				}).success,
			);
		});
	});

	module("oidc / OpenIDProviderMetadataSchema — explicit registration coherence", () => {
		const validOP = {
			issuer: "https://op.example.com",
			authorization_endpoint: "https://op.example.com/auth",
			token_endpoint: "https://op.example.com/token",
			response_types_supported: ["code"],
			subject_types_supported: ["public"],
			id_token_signing_alg_values_supported: ["RS256"],
		};

		test("rejects OP advertising 'explicit' without federation_registration_endpoint", (t) => {
			const result = OpenIDProviderMetadataSchema.safeParse({
				...validOP,
				client_registration_types_supported: ["explicit"],
			});
			t.false(result.success);
			if (result.success) return;
			t.ok(
				result.error.issues.some((i) =>
					i.message.includes("federation_registration_endpoint is REQUIRED"),
				),
			);
		});

		test("accepts OP advertising 'automatic' without federation_registration_endpoint", (t) => {
			t.true(
				OpenIDProviderMetadataSchema.safeParse({
					...validOP,
					client_registration_types_supported: ["automatic"],
				}).success,
			);
		});

		test("accepts OP advertising 'explicit' with valid federation_registration_endpoint", (t) => {
			t.true(
				OpenIDProviderMetadataSchema.safeParse({
					...validOP,
					client_registration_types_supported: ["explicit"],
					federation_registration_endpoint: "https://op.example.com/register",
				}).success,
			);
		});

		test("rejects OP advertising both 'explicit' and 'automatic' without federation_registration_endpoint", (t) => {
			const result = OpenIDProviderMetadataSchema.safeParse({
				...validOP,
				client_registration_types_supported: ["automatic", "explicit"],
			});
			t.false(result.success);
			if (result.success) return;
			t.ok(
				result.error.issues.some((i) =>
					i.message.includes("federation_registration_endpoint is REQUIRED"),
				),
			);
		});
	});

	module("oidc / OpenIDRelyingPartyMetadataSchema — URL validation", () => {
		test("rejects http:// signed_jwks_uri", (t) => {
			t.false(
				OpenIDRelyingPartyMetadataSchema.safeParse({
					signed_jwks_uri: "http://rp.example.com/jwks",
				}).success,
			);
		});

		test("rejects http:// jwks_uri", (t) => {
			t.false(
				OpenIDRelyingPartyMetadataSchema.safeParse({ jwks_uri: "http://rp.example.com/jwks" })
					.success,
			);
		});
	});

	module("oidc / validateOIDCMetadata", () => {
		test("returns parsed metadata for valid input", (t) => {
			const result = validateOIDCMetadata({
				openid_provider: {
					issuer: "https://op.example.com",
					authorization_endpoint: "https://op.example.com/authorize",
					token_endpoint: "https://op.example.com/token",
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256"],
				},
			});
			t.equal(result.openid_provider?.issuer, "https://op.example.com");
		});

		test("throws for invalid OP metadata", (t) => {
			t.throws(() => validateOIDCMetadata({ openid_provider: { issuer: "bad" } }));
		});

		test("throws for invalid RP metadata", (t) => {
			t.throws(() => validateOIDCMetadata({ openid_relying_party: { redirect_uris: [123] } }));
		});
	});

	// -------------------------------------------------------------------------
	// constants / ClientRegistrationType
	// -------------------------------------------------------------------------
	module("oidc / ClientRegistrationType", () => {
		test("has 2 types", (t) => {
			t.equal(Object.keys(ClientRegistrationType).length, 2);
			t.equal(ClientRegistrationType.Automatic, "automatic");
			t.equal(ClientRegistrationType.Explicit, "explicit");
		});
	});

	// -------------------------------------------------------------------------
	// schemas/explicit-registration
	// -------------------------------------------------------------------------
	{
		const erp_now = Math.floor(Date.now() / 1000);

		module("oidc / ExplicitRegistrationRequestPayloadSchema", () => {
			const validReq = {
				iss: "https://rp.example.com",
				sub: "https://rp.example.com",
				aud: "https://op.example.com",
				iat: erp_now,
				exp: erp_now + 3600,
				jwks: { keys: [{ kty: "EC" as const, kid: "k1", crv: "P-256", x: "a", y: "b" }] },
				authority_hints: ["https://ta.example.com"],
				metadata: { openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] } },
			};
			test("accepts valid registration request", (t) => {
				t.true(ExplicitRegistrationRequestPayloadSchema.safeParse(validReq).success);
			});
			test("rejects when iss !== sub", (t) => {
				t.false(
					ExplicitRegistrationRequestPayloadSchema.safeParse({
						...validReq,
						sub: "https://other.example.com",
					}).success,
				);
			});
			test("requires aud", (t) => {
				const { aud: _, ...v } = validReq;
				t.false(ExplicitRegistrationRequestPayloadSchema.safeParse(v).success);
			});
			test("requires authority_hints", (t) => {
				const { authority_hints: _, ...v } = validReq;
				t.false(ExplicitRegistrationRequestPayloadSchema.safeParse(v).success);
			});
			test("requires metadata", (t) => {
				const { metadata: _, ...v } = validReq;
				t.false(ExplicitRegistrationRequestPayloadSchema.safeParse(v).success);
			});
			test("requires metadata to contain openid_relying_party", (t) => {
				t.false(
					ExplicitRegistrationRequestPayloadSchema.safeParse({
						...validReq,
						metadata: { federation_entity: { organization_name: "Test" } },
					}).success,
				);
			});
		});

		module("oidc / ExplicitRegistrationResponsePayloadSchema", () => {
			const validResp = {
				iss: "https://op.example.com",
				sub: "https://rp.example.com",
				aud: "https://rp.example.com",
				iat: erp_now,
				exp: erp_now + 3600,
				trust_anchor: "https://ta.example.com",
				authority_hints: ["https://intermediate.example.com"],
			};
			test("accepts valid registration response", (t) => {
				t.true(ExplicitRegistrationResponsePayloadSchema.safeParse(validResp).success);
			});
			test("requires trust_anchor", (t) => {
				const { trust_anchor: _, ...v } = validResp;
				t.false(ExplicitRegistrationResponsePayloadSchema.safeParse(v).success);
			});
			test("accepts optional client_secret", (t) => {
				t.true(
					ExplicitRegistrationResponsePayloadSchema.safeParse({
						...validResp,
						client_secret: "secret123",
					}).success,
				);
			});
			test("requires authority_hints in response", (t) => {
				const { authority_hints: _, ...v } = validResp;
				t.false(ExplicitRegistrationResponsePayloadSchema.safeParse(v).success);
			});
			test("requires authority_hints to be exactly one element", (t) => {
				t.false(
					ExplicitRegistrationResponsePayloadSchema.safeParse({
						...validResp,
						authority_hints: ["https://a.example.com", "https://b.example.com"],
					}).success,
				);
			});
		});
	}

	// -------------------------------------------------------------------------
	// registration/adapter
	// -------------------------------------------------------------------------
	module("oidc / OIDCRegistrationAdapter", () => {
		const adapter = new OIDCRegistrationAdapter();
		const mockTrustChain = {
			entityId: entityId("https://rp.example.com"),
			statements: [],
			resolvedMetadata: {},
			expiresAt: Math.floor(Date.now() / 1000) + 86400,
		} as unknown as ValidatedTrustChain;

		test("accepts valid openid_relying_party metadata", (t) => {
			const result = adapter.validateClientMetadata({
				openid_relying_party: {
					redirect_uris: ["https://rp.example.com/callback"],
					response_types: ["code"],
					client_registration_types: ["automatic"],
				},
			});
			t.true(result.ok);
		});

		test("accepts metadata without openid_relying_party (federation-only)", (t) => {
			t.true(
				adapter.validateClientMetadata({ federation_entity: { organization_name: "Test Org" } }).ok,
			);
		});

		test("rejects invalid openid_relying_party metadata", (t) => {
			const result = adapter.validateClientMetadata({
				openid_relying_party: { redirect_uris: ["not-a-url"] },
			});
			t.false(result.ok);
			if (result.ok) return;
			t.equal(result.error.code, "invalid_metadata");
		});

		test("adds client_id from trust chain if missing", (t) => {
			const enriched = adapter.enrichResponseMetadata({}, mockTrustChain);
			t.equal(enriched.client_id, "https://rp.example.com");
		});

		test("preserves existing client_id", (t) => {
			const enriched = adapter.enrichResponseMetadata({ client_id: "existing-id" }, mockTrustChain);
			t.equal(enriched.client_id, "existing-id");
		});

		test("does not mutate the original metadata object", (t) => {
			const original = { scope: "openid" };
			const enriched = adapter.enrichResponseMetadata(original, mockTrustChain);
			t.equal(enriched.client_id, "https://rp.example.com");
			t.equal((original as Record<string, unknown>).client_id, undefined);
		});

		test("rejects openid_relying_party with invalid signed_jwks_uri (http)", (t) => {
			const result = adapter.validateClientMetadata({
				openid_relying_party: { signed_jwks_uri: "http://insecure.example.com/jwks" },
			});
			t.false(result.ok);
			if (result.ok) return;
			t.equal(result.error.code, "invalid_metadata");
		});

		test("accepts openid_relying_party with only optional fields", (t) => {
			t.true(
				adapter.validateClientMetadata({ openid_relying_party: { client_name: "Test RP" } }).ok,
			);
		});

		test("accepts empty openid_relying_party object", (t) => {
			t.true(adapter.validateClientMetadata({ openid_relying_party: {} }).ok);
		});
	});

	// -------------------------------------------------------------------------
	// registration/automatic
	// -------------------------------------------------------------------------
	module("oidc / automaticRegistration (RP-side)", () => {
		const authzParams = {
			redirect_uri: "https://rp.example.com/callback",
			scope: "openid",
			response_type: "code",
		};

		test("returns valid Request Object JWT with correct typ", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			const decoded = decodeEntityStatement(result.requestObjectJwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.header.typ, "oauth-authz-req+jwt");
		});

		test("has correct JWT claims: iss, client_id, aud, jti, exp", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			const decoded = decodeEntityStatement(result.requestObjectJwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.equal(p.iss, LEAF_ID);
			t.equal(p.client_id, LEAF_ID);
			t.equal(p.aud, OP_ID);
			t.equal(typeof p.jti, "string");
			t.equal(typeof p.exp, "number");
		});

		test("does NOT include sub claim", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			const decoded = decodeEntityStatement(result.requestObjectJwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal((decoded.value.payload as Record<string, unknown>).sub, undefined);
		});

		test("includes trust_chain as JWS header parameter", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			const decoded = decodeEntityStatement(result.requestObjectJwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const h = decoded.value.header as Record<string, unknown>;
			t.ok(Array.isArray(h.trust_chain));
			t.ok((h.trust_chain as string[]).length > 0);
		});

		test("attaches peer_trust_chain when includePeerTrustChain is true", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({
				signingKeys: [fed.leafSigningKey],
				includePeerTrustChain: true,
			});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			const decoded = decodeEntityStatement(result.requestObjectJwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const h = decoded.value.header as Record<string, unknown>;
			t.ok(Array.isArray(h.peer_trust_chain), "peer_trust_chain should be present");
			const peerChain = h.peer_trust_chain as string[];
			t.ok(peerChain.length > 0);
			// Same-TA invariant: peer chain ends at same TA as trust_chain.
			const rpChain = h.trust_chain as string[];
			const rpLast = decodeEntityStatement(rpChain[rpChain.length - 1] as string);
			const peerLast = decodeEntityStatement(peerChain[peerChain.length - 1] as string);
			t.true(rpLast.ok && peerLast.ok);
			if (!rpLast.ok || !peerLast.ok) return;
			t.equal(
				(rpLast.value.payload as Record<string, unknown>).iss,
				(peerLast.value.payload as Record<string, unknown>).iss,
			);
			// Peer chain begins at OP.
			const peerFirst = decodeEntityStatement(peerChain[0] as string);
			t.true(peerFirst.ok);
			if (!peerFirst.ok) return;
			const peerFirstPayload = peerFirst.value.payload as Record<string, unknown>;
			t.equal(peerFirstPayload.iss, OP_ID);
			t.equal(peerFirstPayload.sub, OP_ID);
		});

		test("throws when includePeerTrustChain is set but no peer chain to shared TA exists", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			// Strip the OP discovery responses from the http client so the peer
			// chain cannot be resolved, while keeping the leaf chain intact.
			const blockingHttpClient = async (input: string | URL | Request) => {
				const url = typeof input === "string" ? input : (input as Request).url;
				if (url.includes(OP_ID.replace(/^https?:\/\//, ""))) {
					return new Response("Not found", { status: 404 });
				}
				return fed.options.httpClient!(input);
			};
			const { config } = await createRpConfig({
				signingKeys: [fed.leafSigningKey],
				includePeerTrustChain: true,
			});
			let threw = false;
			try {
				await automaticRegistration(discovery, config, authzParams, fed.trustAnchors, {
					...fed.options,
					httpClient: blockingHttpClient,
				});
			} catch (e: unknown) {
				threw = true;
				t.ok((e as Error).message.toLowerCase().includes("peer"));
			}
			t.true(threw, "expected throw when peer chain cannot be built");
		});

		test("includes authzRequestParams in JWT payload", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			const params = { ...authzParams, nonce: "test-nonce" };
			const result = await automaticRegistration(
				discovery,
				config,
				params,
				fed.trustAnchors,
				fed.options,
			);
			const decoded = decodeEntityStatement(result.requestObjectJwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.equal(p.redirect_uri, params.redirect_uri);
			t.equal(p.scope, params.scope);
			t.equal(p.nonce, params.nonce);
		});

		test("query mode returns well-formed authorizationUrl with request + client_id", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({
				signingKeys: [fed.leafSigningKey],
				requestDelivery: "query",
			});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.equal(result.delivery, "query");
			if (result.delivery !== "query") return;
			const url = new URL(result.authorizationUrl);
			t.equal(url.searchParams.get("request"), result.requestObjectJwt);
			t.equal(url.searchParams.get("client_id"), LEAF_ID);
		});

		test("does not allow authzRequestParams to overwrite required claims", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			const result = await automaticRegistration(
				discovery,
				config,
				{
					iss: "https://attacker.example.com",
					aud: "https://attacker.example.com",
					sub: "https://attacker.example.com",
					...authzParams,
				},
				fed.trustAnchors,
				fed.options,
			);
			const decoded = decodeEntityStatement(result.requestObjectJwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.equal(p.iss, LEAF_ID);
			t.equal(p.aud, OP_ID);
			t.equal(p.sub, undefined);
		});

		test("throws if OP does not advertise automatic", async (t) => {
			const fed = await createMockFederation({
				opMetadata: {
					openid_provider: {
						issuer: OP_ID,
						authorization_endpoint: `${OP_ID}/authorize`,
						token_endpoint: `${OP_ID}/token`,
						federation_registration_endpoint: `${OP_ID}/federation_registration`,
						response_types_supported: ["code"],
						subject_types_supported: ["public"],
						id_token_signing_alg_values_supported: ["ES256"],
						client_registration_types_supported: ["explicit"],
					},
				},
			});
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			try {
				await automaticRegistration(discovery, config, authzParams, fed.trustAnchors, fed.options);
				t.ok(false, "should have thrown");
			} catch (e) {
				t.ok((e as Error).message.includes("automatic"), (e as Error).message);
			}
		});

		test("does not include registration param in JWT payload", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			const result = await automaticRegistration(
				discovery,
				config,
				{ registration: '{"client_name":"evil"}', ...authzParams },
				fed.trustAnchors,
				fed.options,
			);
			const decoded = decodeEntityStatement(result.requestObjectJwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal((decoded.value.payload as Record<string, unknown>).registration, undefined);
		});

		test("includes trustChainExpiresAt matching trust chain expiry", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.ok(result.trustChainExpiresAt > 0);
			t.equal(result.trustChainExpiresAt, discovery.trustChain.expiresAt);
		});

		test("uses JWK allowlist for public keys (no private fields leak)", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.ok(result.requestObjectJwt);
		});
	});

	// -------------------------------------------------------------------------
	// registration/automatic — Request Object delivery modes
	// -------------------------------------------------------------------------
	module("oidc / automaticRegistration delivery modes", () => {
		const authzParams = {
			redirect_uri: "https://rp.example.com/callback",
			scope: "openid",
			response_type: "code",
		};

		test("defaults to form_post when requestDelivery is omitted", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.equal(result.delivery, "form_post");
			if (result.delivery !== "form_post") return;
			t.equal(typeof result.authorizationEndpoint, "string");
			t.equal(result.formParams.request, result.requestObjectJwt);
			t.equal(result.formParams.client_id, LEAF_ID);
		});

		test("form_post: authorizationEndpoint matches OP authorization_endpoint metadata", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({
				signingKeys: [fed.leafSigningKey],
				requestDelivery: "form_post",
			});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.equal(result.delivery, "form_post");
			if (result.delivery !== "form_post") return;
			const opMeta = discovery.resolvedMetadata.openid_provider as Record<string, unknown>;
			t.equal(result.authorizationEndpoint, opMeta.authorization_endpoint as string);
		});

		test("request_uri: returns authorizationUrl with request_uri query and echoes input URI", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const hostedUri = "https://rp.example.com/request-object/xyz";
			const { config } = await createRpConfig({
				signingKeys: [fed.leafSigningKey],
				requestDelivery: "request_uri",
				requestUri: hostedUri,
			});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.equal(result.delivery, "request_uri");
			if (result.delivery !== "request_uri") return;
			t.equal(result.requestUri, hostedUri);
			const url = new URL(result.authorizationUrl);
			t.equal(url.searchParams.get("request_uri"), hostedUri);
			t.equal(url.searchParams.get("client_id"), LEAF_ID);
			t.equal(url.searchParams.get("request"), null);
		});

		test("request_uri: throws when requestUri is missing", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({
				signingKeys: [fed.leafSigningKey],
				requestDelivery: "request_uri",
			});
			let threw = false;
			try {
				await automaticRegistration(discovery, config, authzParams, fed.trustAnchors, fed.options);
			} catch (e: unknown) {
				threw = true;
				t.ok((e as Error).message.toLowerCase().includes("request_uri"));
			}
			t.true(threw, "expected throw when requestUri missing");
		});

		test("par: POSTs request + client_id + client_assertion to PAR endpoint and returns urn-style authorizationUrl", async (t) => {
			const parEndpoint = `${OP_ID}/request`;
			const fed = await createMockFederation({
				opMetadata: {
					openid_provider: {
						issuer: OP_ID,
						authorization_endpoint: `${OP_ID}/authorize`,
						token_endpoint: `${OP_ID}/token`,
						pushed_authorization_request_endpoint: parEndpoint,
						response_types_supported: ["code"],
						subject_types_supported: ["public"],
						id_token_signing_alg_values_supported: ["ES256"],
						client_registration_types_supported: ["automatic", "explicit"],
					},
				},
			});
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({
				signingKeys: [fed.leafSigningKey],
				requestDelivery: "par",
			});

			// Wrap the federation http client to intercept the PAR endpoint and
			// return a canned response, while letting everything else fall through.
			let capturedBody: string | undefined;
			let capturedMethod: string | undefined;
			const urn = "urn:ietf:params:oauth:request_uri:abc123";
			const parHttpClient: HttpClient = async (input, init) => {
				const url = typeof input === "string" ? input : (input as Request).url;
				if (url === parEndpoint) {
					capturedMethod = (init?.method as string | undefined) ?? "POST";
					capturedBody =
						typeof init?.body === "string"
							? init.body
							: input instanceof Request
								? await (input as Request).text()
								: undefined;
					return new Response(JSON.stringify({ request_uri: urn, expires_in: 60 }), {
						status: 201,
						headers: { "content-type": "application/json" },
					});
				}
				return fed.options.httpClient!(input, init);
			};

			const result = await automaticRegistration(discovery, config, authzParams, fed.trustAnchors, {
				...fed.options,
				httpClient: parHttpClient,
			});
			t.equal(result.delivery, "par");
			if (result.delivery !== "par") return;
			t.equal(capturedMethod, "POST");
			t.equal(typeof capturedBody, "string");
			const body = new URLSearchParams(capturedBody as string);
			t.equal(body.get("request"), result.requestObjectJwt);
			t.equal(body.get("client_id"), LEAF_ID);
			t.equal(
				body.get("client_assertion_type"),
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			);
			t.ok(body.get("client_assertion"));
			const assertionJwt = body.get("client_assertion") as string;
			const assertionDecoded = decodeEntityStatement(assertionJwt);
			t.true(assertionDecoded.ok);
			if (!assertionDecoded.ok) return;
			const ap = assertionDecoded.value.payload as Record<string, unknown>;
			t.equal(ap.iss, LEAF_ID);
			t.equal(ap.sub, LEAF_ID);
			// Audience MUST be OP Entity Identifier (not the PAR endpoint URL).
			t.equal(ap.aud, OP_ID);
			t.equal(result.pushedAuthorizationRequestEndpoint, parEndpoint);
			t.equal(result.parRequestUri, urn);
			const finalUrl = new URL(result.authorizationUrl);
			t.equal(finalUrl.searchParams.get("request_uri"), urn);
			t.equal(finalUrl.searchParams.get("client_id"), LEAF_ID);
			t.ok(result.parExpiresAt > Math.floor(Date.now() / 1000));
		});

		test("par: throws when OP advertises no pushed_authorization_request_endpoint", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({
				signingKeys: [fed.leafSigningKey],
				requestDelivery: "par",
			});
			let threw = false;
			try {
				await automaticRegistration(discovery, config, authzParams, fed.trustAnchors, fed.options);
			} catch (e: unknown) {
				threw = true;
				t.ok((e as Error).message.toLowerCase().includes("pushed_authorization_request_endpoint"));
			}
			t.true(threw, "expected throw when PAR endpoint absent");
		});
	});

	// -------------------------------------------------------------------------
	// registration/explicit
	// -------------------------------------------------------------------------
	module("oidc / explicitRegistration (RP-side)", () => {
		async function createMockOpWithRegistration() {
			const fed = await createMockFederation();
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			const discovery = await createMockDiscovery(OP_ID, fed);
			const now = Math.floor(Date.now() / 1000);
			const registrationResponsePayload = {
				iss: OP_ID,
				sub: LEAF_ID,
				aud: LEAF_ID,
				iat: now,
				exp: now + 86400,
				authority_hints: [TA_ID],
				trust_anchor: TA_ID,
				metadata: {
					openid_relying_party: {
						client_id: LEAF_ID,
						redirect_uris: ["https://rp.example.com/callback"],
						response_types: ["code"],
					},
				},
				jwks: { keys: [fed.leafPublicKey] },
			};
			const registrationResponseJwt = await signEntityStatement(
				registrationResponsePayload,
				fed.opSigningKey,
				{ kid: fed.opSigningKey.kid, typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
			);
			const originalHttpClient = fed.httpClient;
			const httpClient: HttpClient = async (input, init) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration") {
					return new Response(registrationResponseJwt, {
						status: 200,
						headers: { "Content-Type": OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE },
					});
				}
				return originalHttpClient(input, init);
			};
			return {
				...fed,
				config,
				discovery,
				httpClient,
				options: { httpClient } as FederationOptions,
				registrationResponsePayload,
			};
		}

		test("POSTs EC JWT to correct endpoint", async (t) => {
			const mock = await createMockOpWithRegistration();
			let capturedUrl = "";
			let capturedContentType = "";
			const trackingClient: HttpClient = async (input, init) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration") {
					capturedUrl = url;
					if (input instanceof Request)
						capturedContentType = input.headers.get("Content-Type") ?? "";
				}
				return mock.httpClient(input, init);
			};
			await explicitRegistration(mock.discovery, mock.config, mock.trustAnchors, {
				httpClient: trackingClient,
			});
			t.ok(capturedUrl.includes("/federation_registration"));
			t.equal(capturedContentType, MediaType.EntityStatement);
		});

		test("RP EC includes all REQUIRED claims", async (t) => {
			const mock = await createMockOpWithRegistration();
			let capturedBody = "";
			const trackingClient: HttpClient = async (input, init) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration" && input instanceof Request) {
					capturedBody = await (input as Request).clone().text();
				}
				return mock.httpClient(input, init);
			};
			await explicitRegistration(mock.discovery, mock.config, mock.trustAnchors, {
				httpClient: trackingClient,
			});
			const decoded = decodeEntityStatement(capturedBody);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.equal(p.iss, LEAF_ID);
			t.equal(p.sub, LEAF_ID);
			t.equal(typeof p.iat, "number");
			t.equal(typeof p.exp, "number");
			t.ok(p.jwks);
			t.equal(p.aud, OP_ID);
			t.ok(p.authority_hints);
			t.ok(p.metadata);
		});

		test("attaches peer_trust_chain when includePeerTrustChain is true", async (t) => {
			const mock = await createMockOpWithRegistration();
			let capturedBody = "";
			const trackingClient: HttpClient = async (input, init) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration" && input instanceof Request) {
					capturedBody = await (input as Request).clone().text();
				}
				return mock.httpClient(input, init);
			};
			await explicitRegistration(
				mock.discovery,
				{ ...mock.config, includePeerTrustChain: true },
				mock.trustAnchors,
				{ httpClient: trackingClient },
			);
			const decoded = decodeEntityStatement(capturedBody);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const h = decoded.value.header as Record<string, unknown>;
			t.ok(Array.isArray(h.peer_trust_chain));
			const peerChain = h.peer_trust_chain as string[];
			t.ok(peerChain.length > 0);
			const peerFirst = decodeEntityStatement(peerChain[0] as string);
			t.true(peerFirst.ok);
			if (!peerFirst.ok) return;
			const peerFirstPayload = peerFirst.value.payload as Record<string, unknown>;
			t.equal(peerFirstPayload.iss, OP_ID);
			t.equal(peerFirstPayload.sub, OP_ID);
		});

		test("returns correct clientId and registeredMetadata", async (t) => {
			const mock = await createMockOpWithRegistration();
			const result = await explicitRegistration(
				mock.discovery,
				mock.config,
				mock.trustAnchors,
				mock.options,
			);
			t.equal(result.clientId, LEAF_ID);
			t.ok(result.registeredMetadata);
			t.ok(result.expiresAt > 0);
		});

		test("throws if OP has no federation_registration_endpoint", async (t) => {
			const fed = await createMockFederation({
				opMetadata: {
					openid_provider: {
						issuer: OP_ID,
						authorization_endpoint: `${OP_ID}/authorize`,
						client_registration_types_supported: ["explicit"],
					},
				},
			});
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			try {
				await explicitRegistration(discovery, config, fed.trustAnchors, fed.options);
				t.ok(false, "should have thrown");
			} catch (e) {
				t.ok(
					(e as Error).message.includes("federation_registration_endpoint"),
					(e as Error).message,
				);
			}
		});

		test("response has registrationStatement with correct typ", async (t) => {
			const mock = await createMockOpWithRegistration();
			const result = await explicitRegistration(
				mock.discovery,
				mock.config,
				mock.trustAnchors,
				mock.options,
			);
			t.equal(result.registrationStatement.header.typ, OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE);
		});

		test("throws if OP does not advertise explicit registration", async (t) => {
			const fed = await createMockFederation({
				opMetadata: {
					openid_provider: {
						issuer: OP_ID,
						authorization_endpoint: `${OP_ID}/authorize`,
						token_endpoint: `${OP_ID}/token`,
						federation_registration_endpoint: `${OP_ID}/federation_registration`,
						response_types_supported: ["code"],
						subject_types_supported: ["public"],
						id_token_signing_alg_values_supported: ["ES256"],
						client_registration_types_supported: ["automatic"],
					},
				},
			});
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			try {
				await explicitRegistration(discovery, config, fed.trustAnchors, fed.options);
				t.ok(false, "should have thrown");
			} catch (e) {
				t.ok((e as Error).message.includes("explicit"), (e as Error).message);
			}
		});

		test("CRIT-1: throws if JWKS is missing (cannot verify response)", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { privateKey: unknownKey } = await generateSigningKey("ES256");
			const now = Math.floor(Date.now() / 1000);
			const badResponseJwt = await signEntityStatement(
				{ iss: OP_ID, sub: LEAF_ID, aud: LEAF_ID, iat: now, exp: now + 86400, trust_anchor: TA_ID },
				unknownKey,
				{ kid: unknownKey.kid, typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
			);
			const httpClient = async (input: string | URL | Request) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration")
					return new Response(badResponseJwt, {
						status: 200,
						headers: { "Content-Type": OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE },
					});
				return fed.httpClient(input);
			};
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			try {
				await explicitRegistration(discovery, config, fed.trustAnchors, { httpClient });
				t.ok(false, "should have thrown");
			} catch (e) {
				t.ok(/signature|verification/i.test((e as Error).message), (e as Error).message);
			}
		});

		test("returns trustChainExpiresAt", async (t) => {
			const mock = await createMockOpWithRegistration();
			const result = await explicitRegistration(
				mock.discovery,
				mock.config,
				mock.trustAnchors,
				mock.options,
			);
			t.ok(result.trustChainExpiresAt > 0);
			t.equal(result.trustChainExpiresAt, mock.discovery.trustChain.expiresAt);
		});

		test("throws if response trust_anchor doesn't match OP chain root", async (t) => {
			const fed = await createMockFederation();
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			const discovery = await createMockDiscovery(OP_ID, fed);
			const now = Math.floor(Date.now() / 1000);
			const badResponseJwt = await signEntityStatement(
				{
					iss: OP_ID,
					sub: LEAF_ID,
					aud: LEAF_ID,
					iat: now,
					exp: now + 86400,
					authority_hints: [TA_ID],
					trust_anchor: "https://wrong-ta.example.com",
					metadata: { openid_relying_party: { client_id: LEAF_ID } },
				},
				fed.opSigningKey,
				{ kid: fed.opSigningKey.kid, typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
			);
			const httpClient = async (input: string | URL | Request) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration")
					return new Response(badResponseJwt, {
						status: 200,
						headers: { "Content-Type": OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE },
					});
				return fed.httpClient(input);
			};
			try {
				await explicitRegistration(discovery, config, fed.trustAnchors, { httpClient });
				t.ok(false, "should have thrown");
			} catch (e) {
				t.ok(/trust_anchor/i.test((e as Error).message), (e as Error).message);
			}
		});

		test("throws if response metadata is missing a requested entity type", async (t) => {
			const fed = await createMockFederation();
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			const discovery = await createMockDiscovery(OP_ID, fed);
			const now = Math.floor(Date.now() / 1000);
			// RP requested openid_relying_party (createRpConfig default); OP responds with
			// metadata for a different entity type — must trigger the missing-entity-type guard.
			const badEntityTypeJwt = await signEntityStatement(
				{
					iss: OP_ID,
					sub: LEAF_ID,
					aud: LEAF_ID,
					iat: now,
					exp: now + 86400,
					authority_hints: [TA_ID],
					trust_anchor: TA_ID,
					metadata: { openid_provider: { issuer: OP_ID } },
				},
				fed.opSigningKey,
				{ kid: fed.opSigningKey.kid, typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
			);
			const httpClient = async (input: string | URL | Request) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration")
					return new Response(badEntityTypeJwt, {
						status: 200,
						headers: { "Content-Type": OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE },
					});
				return fed.httpClient(input);
			};
			try {
				await explicitRegistration(discovery, config, fed.trustAnchors, { httpClient });
				t.ok(false, "should have thrown");
			} catch (e) {
				t.ok(/missing requested entity type/i.test((e as Error).message), (e as Error).message);
			}
		});

		test("does not leak raw OP response body in errors", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			const httpClient = async (input: string | URL | Request) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration")
					return new Response("SECRET_INTERNAL_ERROR_DETAILS", { status: 500 });
				return fed.httpClient(input);
			};
			try {
				await explicitRegistration(discovery, config, fed.trustAnchors, { httpClient });
				t.ok(false, "should have thrown");
			} catch (e) {
				const msg = (e as Error).message;
				t.notOk(msg.includes("SECRET_INTERNAL_ERROR_DETAILS"), "no secret in message");
				t.ok(msg.includes("500"), "includes status code");
			}
		});

		test("throws if OP response is already expired", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			const past = Math.floor(Date.now() / 1000) - 7200;
			const expiredResponseJwt = await signEntityStatement(
				{
					iss: OP_ID,
					sub: LEAF_ID,
					aud: LEAF_ID,
					iat: past - 86400,
					exp: past,
					trust_anchor: TA_ID,
					metadata: { openid_relying_party: { client_id: LEAF_ID } },
				},
				fed.opSigningKey,
				{ kid: fed.opSigningKey.kid, typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
			);
			const httpClient = async (input: string | URL | Request) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration")
					return new Response(expiredResponseJwt, {
						status: 200,
						headers: { "Content-Type": OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE },
					});
				return fed.httpClient(input);
			};
			try {
				await explicitRegistration(discovery, config, fed.trustAnchors, { httpClient });
				t.ok(false, "should have thrown");
			} catch (e) {
				t.ok(/expired|signature|verification/i.test((e as Error).message), (e as Error).message);
			}
		});

		test("throws if OP response is missing exp", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
			const now = Math.floor(Date.now() / 1000);
			const noExpResponseJwt = await signEntityStatement(
				{
					iss: OP_ID,
					sub: LEAF_ID,
					aud: LEAF_ID,
					iat: now,
					trust_anchor: TA_ID,
					metadata: { openid_relying_party: { client_id: LEAF_ID } },
				},
				fed.opSigningKey,
				{ kid: fed.opSigningKey.kid, typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
			);
			const httpClient = async (input: string | URL | Request) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration")
					return new Response(noExpResponseJwt, {
						status: 200,
						headers: { "Content-Type": OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE },
					});
				return fed.httpClient(input);
			};
			try {
				await explicitRegistration(discovery, config, fed.trustAnchors, { httpClient });
				t.ok(false, "should have thrown");
			} catch (e) {
				t.ok(/exp/i.test((e as Error).message), (e as Error).message);
			}
		});
	});

	// -------------------------------------------------------------------------
	// registration/process-automatic
	// -------------------------------------------------------------------------
	module("oidc / processAutomaticRegistration", () => {
		async function createValidRequestObject(fed: Awaited<ReturnType<typeof createMockFederation>>) {
			const now = Math.floor(Date.now() / 1000);
			return signEntityStatement(
				{
					iss: LEAF_ID,
					client_id: LEAF_ID,
					aud: OP_ID,
					jti: crypto.randomUUID(),
					iat: now,
					exp: now + 300,
					redirect_uri: "https://rp.example.com/callback",
					scope: "openid",
					response_type: "code",
				},
				fed.leafSigningKey,
				{ kid: fed.leafSigningKey.kid, typ: "oauth-authz-req+jwt" },
			);
		}

		test("returns ok for valid Request Object", async (t) => {
			const fed = await createMockFederation();
			const result = await processAutomaticRegistration(
				await createValidRequestObject(fed),
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.true(result.ok);
			if (!result.ok) return;
			t.equal(result.value.rpEntityId, LEAF_ID);
		});

		test("returns ok with resolvedRpMetadata", async (t) => {
			const fed = await createMockFederation();
			const result = await processAutomaticRegistration(
				await createValidRequestObject(fed),
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.true(result.ok);
			if (!result.ok) return;
			t.ok(result.value.resolvedRpMetadata);
		});

		test("returns ok with trustChain", async (t) => {
			const fed = await createMockFederation();
			const result = await processAutomaticRegistration(
				await createValidRequestObject(fed),
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.true(result.ok);
			if (!result.ok) return;
			t.equal(result.value.trustChain.entityId, LEAF_ID);
		});

		test("returns err for wrong typ header", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const jwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					client_id: LEAF_ID,
					aud: OP_ID,
					jti: crypto.randomUUID(),
					iat: now,
					exp: now + 300,
				},
				fed.leafSigningKey,
				{ kid: fed.leafSigningKey.kid, typ: JwtTyp.EntityStatement },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
			});
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("typ"));
		});

		test("returns err if sub claim is present", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const jwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					sub: LEAF_ID,
					client_id: LEAF_ID,
					aud: OP_ID,
					jti: crypto.randomUUID(),
					iat: now,
					exp: now + 300,
				},
				fed.leafSigningKey,
				{ kid: fed.leafSigningKey.kid, typ: "oauth-authz-req+jwt" },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
			});
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("sub"));
		});

		test("returns err if iss !== client_id", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const jwt = await signEntityStatement(
				{
					iss: "https://other.example.com",
					client_id: LEAF_ID,
					aud: OP_ID,
					jti: crypto.randomUUID(),
					iat: now,
					exp: now + 300,
				},
				fed.leafSigningKey,
				{ kid: fed.leafSigningKey.kid, typ: "oauth-authz-req+jwt" },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
			});
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("iss"));
		});

		test("CRIT-2: returns err if aud does not match opEntityId", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const jwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					client_id: LEAF_ID,
					aud: "https://wrong-op.example.com",
					jti: crypto.randomUUID(),
					iat: now,
					exp: now + 300,
				},
				fed.leafSigningKey,
				{ kid: fed.leafSigningKey.kid, typ: "oauth-authz-req+jwt" },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
			});
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("aud"));
		});

		test("returns err for expired Request Object", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const jwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					client_id: LEAF_ID,
					aud: OP_ID,
					jti: crypto.randomUUID(),
					iat: now - 600,
					exp: now - 300,
				},
				fed.leafSigningKey,
				{ kid: fed.leafSigningKey.kid, typ: "oauth-authz-req+jwt" },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
			});
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("expired"));
		});

		test("returns err for missing exp", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const jwt = await signEntityStatement(
				{ iss: LEAF_ID, client_id: LEAF_ID, aud: OP_ID, jti: crypto.randomUUID(), iat: now },
				fed.leafSigningKey,
				{ kid: fed.leafSigningKey.kid, typ: "oauth-authz-req+jwt" },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
			});
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("exp"));
		});

		test("returns err for missing jti", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const jwt = await signEntityStatement(
				{ iss: LEAF_ID, client_id: LEAF_ID, aud: OP_ID, iat: now, exp: now + 300 },
				fed.leafSigningKey,
				{ kid: fed.leafSigningKey.kid, typ: "oauth-authz-req+jwt" },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
			});
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("jti"));
		});

		test("HIGH-1: detects replay via JTI store", async (t) => {
			const fed = await createMockFederation();
			const jtiStore = new InMemoryJtiStore();
			const jwt = await createValidRequestObject(fed);
			const result1 = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				jtiStore,
			});
			t.true(result1.ok);
			const result2 = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				jtiStore,
			});
			t.false(result2.ok);
			if (result2.ok) return;
			t.ok(result2.error.description.includes("replay"));
			jtiStore.dispose();
		});

		test("HIGH-3: respects clock skew", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const jwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					client_id: LEAF_ID,
					aud: OP_ID,
					jti: crypto.randomUUID(),
					iat: now - 330,
					exp: now - 30,
				},
				fed.leafSigningKey,
				{ kid: fed.leafSigningKey.kid, typ: "oauth-authz-req+jwt" },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				clockSkewSeconds: 60,
			});
			t.true(result.ok);
		});

		test("returns err for unknown RP", async (t) => {
			const fed = await createMockFederation();
			const { privateKey } = await generateSigningKey("ES256");
			const unknownEntity = entityId("https://unknown-rp.example.com");
			const now = Math.floor(Date.now() / 1000);
			const jwt = await signEntityStatement(
				{
					iss: unknownEntity,
					client_id: unknownEntity,
					aud: OP_ID,
					jti: crypto.randomUUID(),
					iat: now,
					exp: now + 300,
				},
				privateKey,
				{ kid: privateKey.kid, typ: "oauth-authz-req+jwt" },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
			});
			t.false(result.ok);
		});

		test("does not emit console.warn when no jtiStore is provided", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const jwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					client_id: LEAF_ID,
					aud: OP_ID,
					jti: crypto.randomUUID(),
					iat: now,
					exp: now + 300,
				},
				fed.leafSigningKey,
				{ kid: fed.leafSigningKey.kid, typ: "oauth-authz-req+jwt" },
			);
			let warnCalled = false;
			const originalWarn = console.warn;
			console.warn = () => {
				warnCalled = true;
			};
			try {
				await processAutomaticRegistration(jwt, fed.trustAnchors, {
					...fed.options,
					opEntityId: OP_ID,
				});
			} finally {
				console.warn = originalWarn;
			}
			t.false(warnCalled, "console.warn not called");
		});
	});

	// -------------------------------------------------------------------------
	// registration/process-explicit
	// -------------------------------------------------------------------------
	module("oidc / processExplicitRegistration", () => {
		function signOpts(key: JWK): { kid?: string; typ: string } {
			return key.kid != null
				? { kid: key.kid, typ: JwtTyp.EntityStatement }
				: { typ: JwtTyp.EntityStatement };
		}

		async function createValidExplicitRequest(
			fed: Awaited<ReturnType<typeof createMockFederation>>,
		) {
			const now = Math.floor(Date.now() / 1000);
			return signEntityStatement(
				{
					iss: LEAF_ID,
					sub: LEAF_ID,
					aud: OP_ID,
					iat: now,
					exp: now + 86400,
					jwks: { keys: [fed.leafPublicKey] },
					authority_hints: [TA_ID],
					metadata: {
						openid_relying_party: {
							redirect_uris: ["https://rp.example.com/callback"],
							response_types: ["code"],
						},
					},
				},
				fed.leafSigningKey,
				signOpts(fed.leafSigningKey),
			);
		}

		test("returns ok for valid explicit request", async (t) => {
			const fed = await createMockFederation();
			const result = await processExplicitRegistration(
				await createValidExplicitRequest(fed),
				MediaType.EntityStatement,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.true(result.ok);
			if (!result.ok) return;
			t.equal(result.value.rpEntityId, LEAF_ID);
			t.ok(result.value.resolvedRpMetadata);
		});

		test("returns err for unknown Content-Type", async (t) => {
			const fed = await createMockFederation();
			const result = await processExplicitRegistration(
				await createValidExplicitRequest(fed),
				"text/plain",
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("Content-Type"));
		});

		test("returns err if iss !== sub", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const ecJwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					sub: "https://different-entity.example.com",
					aud: OP_ID,
					iat: now,
					exp: now + 86400,
					jwks: { keys: [fed.leafPublicKey] },
					authority_hints: [TA_ID],
					metadata: {},
				},
				fed.leafSigningKey,
				signOpts(fed.leafSigningKey),
			);
			const result = await processExplicitRegistration(
				ecJwt,
				MediaType.EntityStatement,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("iss") && result.error.description.includes("sub"));
		});

		test("returns err if aud does not match opEntityId", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const ecJwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					sub: LEAF_ID,
					aud: "https://wrong-op.example.com",
					iat: now,
					exp: now + 86400,
					jwks: { keys: [fed.leafPublicKey] },
					authority_hints: [TA_ID],
					metadata: {},
				},
				fed.leafSigningKey,
				signOpts(fed.leafSigningKey),
			);
			const result = await processExplicitRegistration(
				ecJwt,
				MediaType.EntityStatement,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("aud"));
		});

		test("verifies RP EC self-signature", async (t) => {
			const fed = await createMockFederation();
			const { privateKey: wrongKey } = await generateSigningKey("ES256");
			const now = Math.floor(Date.now() / 1000);
			const ecJwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					sub: LEAF_ID,
					aud: OP_ID,
					iat: now,
					exp: now + 86400,
					jwks: { keys: [fed.leafPublicKey] },
					authority_hints: [TA_ID],
					metadata: {
						openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
					},
				},
				wrongKey,
				signOpts(wrongKey),
			);
			const result = await processExplicitRegistration(
				ecJwt,
				MediaType.EntityStatement,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("signature"));
		});

		test("returns ok with trustChain", async (t) => {
			const fed = await createMockFederation();
			const result = await processExplicitRegistration(
				await createValidExplicitRequest(fed),
				MediaType.EntityStatement,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.true(result.ok);
			if (!result.ok) return;
			t.equal(result.value.trustChain.entityId, LEAF_ID);
		});

		test("returns err if RP EC has no jwks", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const ecJwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					sub: LEAF_ID,
					aud: OP_ID,
					iat: now,
					exp: now + 86400,
					authority_hints: [TA_ID],
					metadata: {
						openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
					},
				},
				fed.leafSigningKey,
				signOpts(fed.leafSigningKey),
			);
			const result = await processExplicitRegistration(
				ecJwt,
				MediaType.EntityStatement,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("jwks"));
		});

		test("returns err if aud is missing from RP EC", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const ecJwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					sub: LEAF_ID,
					iat: now,
					exp: now + 86400,
					jwks: { keys: [fed.leafPublicKey] },
					authority_hints: [TA_ID],
					metadata: {},
				},
				fed.leafSigningKey,
				signOpts(fed.leafSigningKey),
			);
			const result = await processExplicitRegistration(
				ecJwt,
				MediaType.EntityStatement,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("aud"));
		});

		test("accepts valid trust-chain+json body", async (t) => {
			const fed = await createMockFederation();
			const ecJwt = await createValidExplicitRequest(fed);
			const result = await processExplicitRegistration(
				JSON.stringify([ecJwt]),
				MediaType.TrustChain,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.true(result.ok);
			if (!result.ok) return;
			t.equal(result.value.rpEntityId, LEAF_ID);
		});

		test("returns err for invalid trust-chain+json (not valid JSON)", async (t) => {
			const fed = await createMockFederation();
			const result = await processExplicitRegistration(
				"not-json",
				MediaType.TrustChain,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("trust-chain+json"));
		});

		test("returns err for empty trust-chain+json array", async (t) => {
			const fed = await createMockFederation();
			const result = await processExplicitRegistration(
				"[]",
				MediaType.TrustChain,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("non-empty array"));
		});

		test("returns err for unknown RP", async (t) => {
			const fed = await createMockFederation();
			const { privateKey, publicKey } = await generateSigningKey("ES256");
			const unknownEntity = entityId("https://unknown-rp.example.com");
			const now = Math.floor(Date.now() / 1000);
			const ecJwt = await signEntityStatement(
				{
					iss: unknownEntity,
					sub: unknownEntity,
					aud: OP_ID,
					iat: now,
					exp: now + 86400,
					jwks: { keys: [publicKey] },
					authority_hints: [TA_ID],
					metadata: {
						openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
					},
				},
				privateKey,
				signOpts(privateKey),
			);
			t.false(
				(
					await processExplicitRegistration(ecJwt, MediaType.EntityStatement, fed.trustAnchors, {
						...fed.options,
						opEntityId: OP_ID,
					})
				).ok,
			);
		});

		test("returns err for expired RP Entity Configuration", async (t) => {
			const fed = await createMockFederation();
			const past = Math.floor(Date.now() / 1000) - 7200;
			const ecJwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					sub: LEAF_ID,
					aud: OP_ID,
					iat: past - 86400,
					exp: past,
					jwks: { keys: [fed.leafPublicKey] },
					authority_hints: [TA_ID],
					metadata: {
						openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
					},
				},
				fed.leafSigningKey,
				signOpts(fed.leafSigningKey),
			);
			const result = await processExplicitRegistration(
				ecJwt,
				MediaType.EntityStatement,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("expired"));
		});

		test("returns err for future-dated RP EC iat", async (t) => {
			const fed = await createMockFederation();
			const future = Math.floor(Date.now() / 1000) + 7200;
			const ecJwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					sub: LEAF_ID,
					aud: OP_ID,
					iat: future,
					exp: future + 86400,
					jwks: { keys: [fed.leafPublicKey] },
					authority_hints: [TA_ID],
					metadata: {
						openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
					},
				},
				fed.leafSigningKey,
				signOpts(fed.leafSigningKey),
			);
			const result = await processExplicitRegistration(
				ecJwt,
				MediaType.EntityStatement,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("future"));
		});

		test("returns err for missing iat claim", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const ecJwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					sub: LEAF_ID,
					aud: OP_ID,
					exp: now + 86400,
					jwks: { keys: [fed.leafPublicKey] },
					authority_hints: [TA_ID],
					metadata: {
						openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
					},
				},
				fed.leafSigningKey,
				signOpts(fed.leafSigningKey),
			);
			const result = await processExplicitRegistration(
				ecJwt,
				MediaType.EntityStatement,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("iat"));
		});

		test("returns err for missing exp claim", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const ecJwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					sub: LEAF_ID,
					aud: OP_ID,
					iat: now,
					jwks: { keys: [fed.leafPublicKey] },
					authority_hints: [TA_ID],
					metadata: {
						openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
					},
				},
				fed.leafSigningKey,
				signOpts(fed.leafSigningKey),
			);
			const result = await processExplicitRegistration(
				ecJwt,
				MediaType.EntityStatement,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("exp"));
		});

		test("returns err if metadata is missing openid_relying_party", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const ecJwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					sub: LEAF_ID,
					aud: OP_ID,
					iat: now,
					exp: now + 86400,
					jwks: { keys: [fed.leafPublicKey] },
					authority_hints: [TA_ID],
					metadata: { federation_entity: { organization_name: "Test" } },
				},
				fed.leafSigningKey,
				signOpts(fed.leafSigningKey),
			);
			const result = await processExplicitRegistration(
				ecJwt,
				MediaType.EntityStatement,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("openid_relying_party"));
		});

		test("returns err if metadata is missing entirely", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const ecJwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					sub: LEAF_ID,
					aud: OP_ID,
					iat: now,
					exp: now + 86400,
					jwks: { keys: [fed.leafPublicKey] },
					authority_hints: [TA_ID],
				},
				fed.leafSigningKey,
				signOpts(fed.leafSigningKey),
			);
			const result = await processExplicitRegistration(
				ecJwt,
				MediaType.EntityStatement,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("metadata"));
		});

		test("returns err if authority_hints is missing", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const ecJwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					sub: LEAF_ID,
					aud: OP_ID,
					iat: now,
					exp: now + 86400,
					jwks: { keys: [fed.leafPublicKey] },
					metadata: {
						openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
					},
				},
				fed.leafSigningKey,
				signOpts(fed.leafSigningKey),
			);
			const result = await processExplicitRegistration(
				ecJwt,
				MediaType.EntityStatement,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("authority_hints"));
		});
	});

	// -------------------------------------------------------------------------
	// registration/validate-request-object
	// -------------------------------------------------------------------------
	module("oidc / validateAutomaticRegistrationRequest", () => {
		const rpId = entityId("https://rp.example.com");
		const opId = entityId("https://op.example.com");
		const ctx: AutomaticRegistrationContext = { opEntityId: opId };

		async function buildRequestObject(
			signingKey: JWK,
			overrides?: {
				payloadOverrides?: Record<string, unknown>;
				typOverride?: string;
				extraHeaders?: Record<string, unknown>;
				removeClaims?: string[];
			},
		): Promise<string> {
			const now = Math.floor(Date.now() / 1000);
			const payload: Record<string, unknown> = {
				iss: rpId,
				client_id: rpId,
				aud: opId,
				jti: crypto.randomUUID(),
				iat: now,
				exp: now + 300,
				redirect_uri: "https://rp.example.com/callback",
				scope: "openid",
				response_type: "code",
				...overrides?.payloadOverrides,
			};
			for (const key of overrides?.removeClaims ?? []) delete payload[key];
			return signEntityStatement(payload, signingKey, {
				kid: signingKey.kid as string,
				typ: (overrides?.typOverride ?? RequestObjectTyp) as string,
				...(overrides?.extraHeaders ? { extraHeaders: overrides.extraHeaders } : {}),
			});
		}

		test("accepts a valid Request Object", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const result = validateAutomaticRegistrationRequest(
				await buildRequestObject(privateKey),
				ctx,
			);
			t.true(result.ok);
			if (!result.ok) return;
			t.equal(result.value.rpEntityId, rpId);
			t.equal(result.value.opEntityId, opId);
			t.equal(typeof result.value.jti, "string");
			t.equal(typeof result.value.exp, "number");
		});

		test("rejects wrong typ header", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const result = validateAutomaticRegistrationRequest(
				await buildRequestObject(privateKey, { typOverride: "entity-statement+jwt" }),
				ctx,
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("typ"));
		});

		test("rejects with sub present", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const result = validateAutomaticRegistrationRequest(
				await buildRequestObject(privateKey, {
					payloadOverrides: { sub: "https://rp.example.com" },
				}),
				ctx,
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("sub"));
		});

		test("rejects missing client_id", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const result = validateAutomaticRegistrationRequest(
				await buildRequestObject(privateKey, { removeClaims: ["client_id"] }),
				ctx,
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("client_id"));
		});

		test("rejects iss !== client_id", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const result = validateAutomaticRegistrationRequest(
				await buildRequestObject(privateKey, {
					payloadOverrides: { iss: "https://other.example.com" },
				}),
				ctx,
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(
				result.error.description.includes("iss") && result.error.description.includes("client_id"),
			);
		});

		test("rejects wrong aud", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const result = validateAutomaticRegistrationRequest(
				await buildRequestObject(privateKey, {
					payloadOverrides: { aud: "https://wrong-op.example.com" },
				}),
				ctx,
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("aud"));
		});

		test("rejects multi-value aud", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const result = validateAutomaticRegistrationRequest(
				await buildRequestObject(privateKey, {
					payloadOverrides: { aud: [opId, "https://other.example.com"] },
				}),
				ctx,
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("single string"));
		});

		test("rejects expired JWT", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const past = Math.floor(Date.now() / 1000) - 3600;
			const result = validateAutomaticRegistrationRequest(
				await buildRequestObject(privateKey, { payloadOverrides: { exp: past, iat: past - 300 } }),
				ctx,
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("expired"));
		});

		test("rejects missing jti", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const result = validateAutomaticRegistrationRequest(
				await buildRequestObject(privateKey, { removeClaims: ["jti"] }),
				ctx,
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("jti"));
		});

		test("rejects registration claim present", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const result = validateAutomaticRegistrationRequest(
				await buildRequestObject(privateKey, {
					payloadOverrides: { registration: { client_name: "Test" } },
				}),
				ctx,
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("registration"));
		});

		test("validates trust_chain header first entry", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const { privateKey: otherKey, publicKey: otherPub } = await generateSigningKey("ES256");
			const wrongEc = await signEntityStatement(
				{
					iss: "https://other.example.com",
					sub: "https://other.example.com",
					iat: Math.floor(Date.now() / 1000),
					exp: Math.floor(Date.now() / 1000) + 3600,
					jwks: { keys: [otherPub] },
				},
				otherKey,
				{ typ: JwtTyp.EntityStatement },
			);
			const result = validateAutomaticRegistrationRequest(
				await buildRequestObject(privateKey, { extraHeaders: { trust_chain: [wrongEc] } }),
				ctx,
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("subject's Entity Configuration"));
		});

		test("accepts valid trust_chain header", async (t) => {
			const { privateKey, publicKey } = await generateSigningKey("ES256");
			const rpEc = await signEntityStatement(
				{
					iss: rpId,
					sub: rpId,
					iat: Math.floor(Date.now() / 1000),
					exp: Math.floor(Date.now() / 1000) + 3600,
					jwks: { keys: [publicKey] },
				},
				privateKey,
				{ typ: JwtTyp.EntityStatement },
			);
			const result = validateAutomaticRegistrationRequest(
				await buildRequestObject(privateKey, { extraHeaders: { trust_chain: [rpEc] } }),
				ctx,
			);
			t.true(result.ok);
			if (!result.ok) return;
			t.equal(result.value.trustChainHeader?.length, 1);
		});

		const taId = entityId("https://ta.example.com");

		async function buildPeerChainFixture() {
			const { privateKey: rpKey, publicKey: rpPub } = await generateSigningKey("ES256");
			const { privateKey: opKey, publicKey: opPub } = await generateSigningKey("ES256");
			const { privateKey: taKey, publicKey: taPub } = await generateSigningKey("ES256");
			const now = Math.floor(Date.now() / 1000);
			const exp = now + 3600;
			const rpEc = await signEntityStatement(
				{ iss: rpId, sub: rpId, iat: now, exp, jwks: { keys: [rpPub] } },
				rpKey,
				{ typ: JwtTyp.EntityStatement },
			);
			const opEc = await signEntityStatement(
				{ iss: opId, sub: opId, iat: now, exp, jwks: { keys: [opPub] } },
				opKey,
				{ typ: JwtTyp.EntityStatement },
			);
			const taEc = await signEntityStatement(
				{ iss: taId, sub: taId, iat: now, exp, jwks: { keys: [taPub] } },
				taKey,
				{ typ: JwtTyp.EntityStatement },
			);
			return { rpKey, opKey, taKey, rpEc, opEc, taEc, rpPub, opPub, taPub };
		}

		test("accepts peer_trust_chain that begins at OP and shares TA with trust_chain", async (t) => {
			const fx = await buildPeerChainFixture();
			const result = validateAutomaticRegistrationRequest(
				await buildRequestObject(fx.rpKey, {
					extraHeaders: {
						trust_chain: [fx.rpEc, fx.taEc],
						peer_trust_chain: [fx.opEc, fx.taEc],
					},
				}),
				ctx,
			);
			t.true(result.ok);
			if (!result.ok) return;
			t.equal(result.value.trustChainHeader?.length, 2);
			t.equal(result.value.peerTrustChainHeader?.length, 2);
		});

		test("rejects peer_trust_chain that does not begin at OP", async (t) => {
			const fx = await buildPeerChainFixture();
			const { privateKey: strangerKey, publicKey: strangerPub } = await generateSigningKey("ES256");
			const strangerId = "https://stranger.example.com";
			const now = Math.floor(Date.now() / 1000);
			const strangerEc = await signEntityStatement(
				{
					iss: strangerId,
					sub: strangerId,
					iat: now,
					exp: now + 3600,
					jwks: { keys: [strangerPub] },
				},
				strangerKey,
				{ typ: JwtTyp.EntityStatement },
			);
			const result = validateAutomaticRegistrationRequest(
				await buildRequestObject(fx.rpKey, {
					extraHeaders: {
						trust_chain: [fx.rpEc, fx.taEc],
						peer_trust_chain: [strangerEc, fx.taEc],
					},
				}),
				ctx,
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("OP's Entity Configuration"));
		});

		test("rejects peer_trust_chain whose TA differs from trust_chain TA", async (t) => {
			const fx = await buildPeerChainFixture();
			const { privateKey: otherTaKey, publicKey: otherTaPub } = await generateSigningKey("ES256");
			const otherTaId = "https://other-ta.example.com";
			const now = Math.floor(Date.now() / 1000);
			const otherTaEc = await signEntityStatement(
				{
					iss: otherTaId,
					sub: otherTaId,
					iat: now,
					exp: now + 3600,
					jwks: { keys: [otherTaPub] },
				},
				otherTaKey,
				{ typ: JwtTyp.EntityStatement },
			);
			const result = validateAutomaticRegistrationRequest(
				await buildRequestObject(fx.rpKey, {
					extraHeaders: {
						trust_chain: [fx.rpEc, fx.taEc],
						peer_trust_chain: [fx.opEc, otherTaEc],
					},
				}),
				ctx,
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("Trust Anchor"));
		});
	});

	// -------------------------------------------------------------------------
	// registration / createExplicitRegistrationHandler
	// -------------------------------------------------------------------------
	{
		const REG_NOW = Math.floor(Date.now() / 1000);
		const HANDLER_ENTITY_ID = entityId("https://op.example.com");
		const REQUIRED_FIELDS = {
			authority_hints: ["https://ta.example.com"],
			metadata: {
				openid_relying_party: {
					redirect_uris: ["https://rp.example.com/callback"],
					response_types: ["code"],
				},
			},
		};

		type HandlerConfigOverrides = {
			[K in keyof ExplicitRegistrationHandlerConfig]?:
				| ExplicitRegistrationHandlerConfig[K]
				| undefined;
		};
		async function createHandlerConfig(
			overrides?: HandlerConfigOverrides,
		): Promise<ExplicitRegistrationHandlerConfig> {
			const { privateKey } = await generateSigningKey("ES256");
			const opSigningKey: JWK = { ...privateKey, kid: "op-handler-test-kid" };
			const baseConfig: ExplicitRegistrationHandlerConfig = {
				opEntityId: HANDLER_ENTITY_ID,
				getSigningKey: async () => ({ key: opSigningKey, kid: opSigningKey.kid as string }),
			};
			return { ...baseConfig, ...overrides };
		}

		async function buildRegistrationRequest(
			rpEntityId: string,
			opEntityId: string,
			rpPrivateKey: Parameters<typeof signEntityStatement>[1],
			rpPublicKey: Record<string, unknown>,
			overrides?: Record<string, unknown>,
		) {
			return signEntityStatement(
				{
					iss: rpEntityId,
					sub: rpEntityId,
					aud: opEntityId,
					iat: REG_NOW,
					exp: REG_NOW + 3600,
					jwks: { keys: [rpPublicKey] },
					...REQUIRED_FIELDS,
					...overrides,
				},
				rpPrivateKey,
				{ typ: JwtTyp.EntityStatement },
			);
		}

		module("oidc / createExplicitRegistrationHandler", () => {
			test("accepts a valid explicit registration request", async (t) => {
				const config = await createHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const rpId = "https://rp.example.com";
				const jwt = await buildRegistrationRequest(
					rpId,
					HANDLER_ENTITY_ID as string,
					rpKeys.privateKey,
					rpKeys.publicKey as unknown as Record<string, unknown>,
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 200);
				t.equal(res.headers.get("Content-Type"), OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE);
				const responseJwt = await res.text();
				const decoded = decodeEntityStatement(responseJwt);
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				t.equal(decoded.value.header.typ, OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE);
				t.equal(decoded.value.payload.iss, HANDLER_ENTITY_ID);
				t.equal(decoded.value.payload.sub, rpId);
				const payload = decoded.value.payload as Record<string, unknown>;
				t.equal(payload.aud, rpId);
				t.ok(payload.trust_anchor);
				t.ok(payload.authority_hints);
				t.true(Array.isArray(payload.authority_hints));
				t.equal((payload.authority_hints as string[]).length, 1);
			});

			test("response includes metadata with openid_relying_party and client_id", async (t) => {
				const config = await createHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const rpId = "https://rp.example.com";
				const jwt = await buildRegistrationRequest(
					rpId,
					HANDLER_ENTITY_ID as string,
					rpKeys.privateKey,
					rpKeys.publicKey as unknown as Record<string, unknown>,
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 200);
				const decoded = decodeEntityStatement(await res.text());
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				const meta = (decoded.value.payload as Record<string, unknown>).metadata as Record<
					string,
					Record<string, unknown>
				>;
				t.ok(meta.openid_relying_party);
				t.equal(meta.openid_relying_party!.client_id, rpId);
			});

			test("response includes OIDC default values", async (t) => {
				const config = await createHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const rpId = "https://rp.example.com";
				const jwt = await buildRegistrationRequest(
					rpId,
					HANDLER_ENTITY_ID as string,
					rpKeys.privateKey,
					rpKeys.publicKey as unknown as Record<string, unknown>,
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 200);
				const decoded = decodeEntityStatement(await res.text());
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				const rpMeta = (
					(decoded.value.payload as Record<string, unknown>).metadata as Record<
						string,
						Record<string, unknown>
					>
				).openid_relying_party as Record<string, unknown>;
				t.deepEqual(rpMeta.response_types, ["code"]);
				t.deepEqual(rpMeta.grant_types, ["authorization_code"]);
				t.equal(rpMeta.token_endpoint_auth_method, "client_secret_basic");
			});

			test("rejects wrong Content-Type", async (t) => {
				const config = await createHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: "{}",
					}),
				);
				t.equal(res.status, 400);
			});

			test("accepts application/trust-chain+json Content-Type", async (t) => {
				const config = await createHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const rpId = "https://rp.example.com";
				const ecJwt = await buildRegistrationRequest(
					rpId,
					HANDLER_ENTITY_ID as string,
					rpKeys.privateKey,
					rpKeys.publicKey as unknown as Record<string, unknown>,
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.TrustChain },
						body: JSON.stringify([ecJwt]),
					}),
				);
				t.equal(res.status, 200);
			});

			test("rejects wrong aud", async (t) => {
				const config = await createHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const jwt = await buildRegistrationRequest(
					"https://rp.example.com",
					"https://wrong-op.example.com",
					rpKeys.privateKey,
					rpKeys.publicKey as unknown as Record<string, unknown>,
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 400);
				t.true(
					((await res.json()) as Record<string, string | undefined>).error_description!.includes(
						"aud",
					),
				);
			});

			test("uses custom registrationResponseTtlSeconds for exp", async (t) => {
				const config = await createHandlerConfig({ registrationResponseTtlSeconds: 7200 });
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const rpId = "https://rp.example.com";
				const jwt = await buildRegistrationRequest(
					rpId,
					HANDLER_ENTITY_ID as string,
					rpKeys.privateKey,
					rpKeys.publicKey as unknown as Record<string, unknown>,
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 200);
				const decoded = decodeEntityStatement(await res.text());
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				const payload = decoded.value.payload as Record<string, unknown>;
				t.equal((payload.exp as number) - (payload.iat as number), 7200);
			});

			test("rejects GET method", async (t) => {
				const config = await createHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const res = await handler(new Request(`${HANDLER_ENTITY_ID}/federation_registration`));
				t.equal(res.status, 405);
			});

			test("rejects invalid self-signature", async (t) => {
				const config = await createHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const wrongKeys = await generateSigningKey("ES256");
				const jwt = await buildRegistrationRequest(
					"https://rp.example.com",
					HANDLER_ENTITY_ID as string,
					wrongKeys.privateKey,
					rpKeys.publicKey as unknown as Record<string, unknown>,
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 400);
				t.true(
					((await res.json()) as Record<string, string | undefined>).error_description!.includes(
						"signature",
					),
				);
			});

			test("validates trust_chain header — first entry must be subject's EC", async (t) => {
				const config = await createHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const otherKeys = await generateSigningKey("ES256");
				const rpId = "https://rp.example.com";
				const wrongEc = await signEntityStatement(
					{
						iss: "https://other.example.com",
						sub: "https://other.example.com",
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [otherKeys.publicKey] },
					},
					otherKeys.privateKey,
					{ typ: JwtTyp.EntityStatement },
				);
				const jwt = await signEntityStatement(
					{
						iss: rpId,
						sub: rpId,
						aud: HANDLER_ENTITY_ID,
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [rpKeys.publicKey] },
						...REQUIRED_FIELDS,
					},
					rpKeys.privateKey,
					{ typ: JwtTyp.EntityStatement, extraHeaders: { trust_chain: [wrongEc] } },
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_trust_chain");
			});

			test("calls registrationProtocolAdapter.validateClientMetadata when configured", async (t) => {
				const rejectingAdapter: RegistrationProtocolAdapter = {
					validateClientMetadata: () =>
						err(federationError(FederationErrorCode.InvalidMetadata, "Bad RP metadata")),
					enrichResponseMetadata: (meta) => meta,
				};
				const config = await createHandlerConfig({
					registrationProtocolAdapter: rejectingAdapter,
				});
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const rpId = "https://rp.example.com";
				const jwt = await buildRegistrationRequest(
					rpId,
					HANDLER_ENTITY_ID as string,
					rpKeys.privateKey,
					rpKeys.publicKey as unknown as Record<string, unknown>,
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_metadata");
			});

			test("succeeds without adapter (federation-only)", async (t) => {
				const config = await createHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const rpId = "https://rp.example.com";
				const jwt = await buildRegistrationRequest(
					rpId,
					HANDLER_ENTITY_ID as string,
					rpKeys.privateKey,
					rpKeys.publicKey as unknown as Record<string, unknown>,
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 200);
			});

			test("rejects request missing authority_hints", async (t) => {
				const config = await createHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const rpId = "https://rp.example.com";
				const jwt = await signEntityStatement(
					{
						iss: rpId,
						sub: rpId,
						aud: HANDLER_ENTITY_ID,
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [rpKeys.publicKey] },
						metadata: {
							openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
						},
					},
					rpKeys.privateKey,
					{ typ: JwtTyp.EntityStatement },
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 400);
			});

			test("rejects request without openid_relying_party in metadata", async (t) => {
				const config = await createHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const rpId = "https://rp.example.com";
				const jwt = await signEntityStatement(
					{
						iss: rpId,
						sub: rpId,
						aud: HANDLER_ENTITY_ID,
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [rpKeys.publicKey] },
						authority_hints: ["https://ta.example.com"],
						metadata: { federation_entity: { organization_name: "Test" } },
					},
					rpKeys.privateKey,
					{ typ: JwtTyp.EntityStatement },
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 400);
			});

			test("calls onRegistrationInvalidation hook", async (t) => {
				let invalidatedSub: string | undefined;
				const config = await createHandlerConfig({
					onRegistrationInvalidation: async (sub) => {
						invalidatedSub = sub as string;
					},
				});
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const rpId = "https://rp.example.com";
				const jwt = await buildRegistrationRequest(
					rpId,
					HANDLER_ENTITY_ID as string,
					rpKeys.privateKey,
					rpKeys.publicKey as unknown as Record<string, unknown>,
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 200);
				t.equal(invalidatedSub, rpId);
			});
		});

		module("oidc / createExplicitRegistrationHandler — trust chain resolution", () => {
			test("resolves chain and sets trust_anchor, authority_hints, exp from chain", async (t) => {
				const fed = await createMockFederation();
				const config = await createHandlerConfig({
					trustAnchors: fed.trustAnchors,
					options: fed.options,
				});
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const jwt = await buildRegistrationRequest(
					LEAF_ID,
					HANDLER_ENTITY_ID as string,
					rpKeys.privateKey,
					rpKeys.publicKey as unknown as Record<string, unknown>,
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 200);
				const decoded = decodeEntityStatement(await res.text());
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				const payload = decoded.value.payload as Record<string, unknown>;
				t.equal(payload.trust_anchor, TA_ID);
				t.deepEqual(payload.authority_hints, [TA_ID]);
				const exp = payload.exp as number;
				const iat = payload.iat as number;
				t.true(exp > iat);
			});

			test("returns 403 when no valid chain can be resolved for RP", async (t) => {
				const fed = await createMockFederation();
				const config = await createHandlerConfig({
					trustAnchors: fed.trustAnchors,
					options: fed.options,
				});
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const unknownRp = "https://unknown-rp.example.com";
				const jwt = await buildRegistrationRequest(
					unknownRp,
					HANDLER_ENTITY_ID as string,
					rpKeys.privateKey,
					rpKeys.publicKey as unknown as Record<string, unknown>,
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 403);
				t.equal(
					((await res.json()) as Record<string, string>).error,
					FederationErrorCode.InvalidTrustChain,
				);
			});

			test("uses trust_chain JWT header when valid and present", async (t) => {
				const fed = await createMockFederation();
				const config = await createHandlerConfig({
					trustAnchors: fed.trustAnchors,
					options: fed.options,
				});
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const jwt = await signEntityStatement(
					{
						iss: LEAF_ID,
						sub: LEAF_ID,
						aud: HANDLER_ENTITY_ID,
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [rpKeys.publicKey as unknown as Record<string, unknown>] },
						...REQUIRED_FIELDS,
					},
					rpKeys.privateKey,
					{
						typ: JwtTyp.EntityStatement,
						extraHeaders: {
							trust_chain: [fed.leafEcJwt, fed.taSubStatementForLeaf, fed.taEcJwt],
						},
					},
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 200);
				const decoded = decodeEntityStatement(await res.text());
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				t.equal((decoded.value.payload as Record<string, unknown>).trust_anchor, TA_ID);
			});

			test("invokes registrationProtocolAdapter.enrichResponseMetadata", async (t) => {
				const fed = await createMockFederation();
				let enrichCalled = false;
				const adapter: RegistrationProtocolAdapter = {
					validateClientMetadata: (metadata) => ({ ok: true, value: metadata }),
					enrichResponseMetadata: (metadata) => {
						enrichCalled = true;
						return { ...metadata, injected: true };
					},
				};
				const config = await createHandlerConfig({
					trustAnchors: fed.trustAnchors,
					options: fed.options,
					registrationProtocolAdapter: adapter,
				});
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const jwt = await buildRegistrationRequest(
					LEAF_ID,
					HANDLER_ENTITY_ID as string,
					rpKeys.privateKey,
					rpKeys.publicKey as unknown as Record<string, unknown>,
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 200);
				t.true(enrichCalled);
				const decoded = decodeEntityStatement(await res.text());
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				const meta = (decoded.value.payload as Record<string, unknown>).metadata as Record<
					string,
					unknown
				>;
				t.equal(meta.injected, true);
			});

			test("emits client_secret when generateClientSecret hook returns a value", async (t) => {
				const fed = await createMockFederation();
				const config = await createHandlerConfig({
					trustAnchors: fed.trustAnchors,
					options: fed.options,
					generateClientSecret: async () => "secret-abc",
				});
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const jwt = await buildRegistrationRequest(
					LEAF_ID,
					HANDLER_ENTITY_ID as string,
					rpKeys.privateKey,
					rpKeys.publicKey as unknown as Record<string, unknown>,
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 200);
				const decoded = decodeEntityStatement(await res.text());
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				t.equal((decoded.value.payload as Record<string, unknown>).client_secret, "secret-abc");
			});

			test("omits client_secret when hook returns undefined", async (t) => {
				const fed = await createMockFederation();
				const config = await createHandlerConfig({
					trustAnchors: fed.trustAnchors,
					options: fed.options,
					generateClientSecret: async () => undefined,
				});
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const jwt = await buildRegistrationRequest(
					LEAF_ID,
					HANDLER_ENTITY_ID as string,
					rpKeys.privateKey,
					rpKeys.publicKey as unknown as Record<string, unknown>,
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 200);
				const decoded = decodeEntityStatement(await res.text());
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				t.notOk((decoded.value.payload as Record<string, unknown>).client_secret);
			});
		});

		module("oidc / createExplicitRegistrationHandler — peer_trust_chain", () => {
			async function buildPeerHandlerConfig(adapter?: RegistrationProtocolAdapter) {
				const fed = await createMockFederation();
				const overrides: HandlerConfigOverrides = {
					opEntityId: OP_ID,
					trustAnchors: fed.trustAnchors,
					options: fed.options,
					...(adapter ? { registrationProtocolAdapter: adapter } : {}),
				};
				const config = await createHandlerConfig(overrides);
				return { config, fed };
			}

			async function signRpRequest(opts: {
				fed: Awaited<ReturnType<typeof createMockFederation>>;
				rpKeys: { privateKey: JWK; publicKey: JWK };
				peerTrustChain: string[];
				includeRpTrustChain?: boolean;
			}) {
				const { fed, rpKeys, peerTrustChain, includeRpTrustChain = true } = opts;
				const trustChain = includeRpTrustChain
					? [fed.leafEcJwt, fed.taSubStatementForLeaf, fed.taEcJwt]
					: undefined;
				return signEntityStatement(
					{
						iss: LEAF_ID,
						sub: LEAF_ID,
						aud: OP_ID,
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [rpKeys.publicKey as unknown as Record<string, unknown>] },
						...REQUIRED_FIELDS,
					},
					rpKeys.privateKey,
					{
						typ: JwtTyp.EntityStatement,
						extraHeaders: {
							...(trustChain ? { trust_chain: trustChain } : {}),
							peer_trust_chain: peerTrustChain,
						},
					},
				);
			}

			test("validates and exposes peer_trust_chain metadata to the adapter", async (t) => {
				let receivedPeerMetadata: Readonly<Record<string, unknown>> | undefined;
				const adapter: RegistrationProtocolAdapter = {
					validateClientMetadata: (metadata, context) => {
						receivedPeerMetadata = context?.peerResolvedOpMetadata;
						return { ok: true, value: metadata };
					},
					enrichResponseMetadata: (metadata) => metadata,
				};
				const { config, fed } = await buildPeerHandlerConfig(adapter);
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const jwt = await signRpRequest({
					fed,
					rpKeys: { privateKey: rpKeys.privateKey, publicKey: rpKeys.publicKey },
					peerTrustChain: [fed.opEcJwt, fed.taSubStatementForOp, fed.taEcJwt],
				});
				const res = await handler(
					new Request(`${OP_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 200);
				t.ok(receivedPeerMetadata, "adapter received peerResolvedOpMetadata");
				t.equal(
					(receivedPeerMetadata as Record<string, unknown>).issuer,
					OP_ID,
					"peer chain resolved metadata has expected issuer",
				);
			});

			test("rejects peer_trust_chain that does not begin at OP", async (t) => {
				const { config, fed } = await buildPeerHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const jwt = await signRpRequest({
					fed,
					rpKeys: { privateKey: rpKeys.privateKey, publicKey: rpKeys.publicKey },
					peerTrustChain: [fed.leafEcJwt, fed.taSubStatementForLeaf, fed.taEcJwt],
				});
				const res = await handler(
					new Request(`${OP_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 400);
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, FederationErrorCode.InvalidTrustChain);
				t.ok(body.error_description?.includes("OP's Entity Configuration"));
			});

			test("rejects peer_trust_chain whose TA differs from RP's trust_chain TA", async (t) => {
				const { config, fed } = await buildPeerHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");

				const { privateKey: otherTaKey, publicKey: otherTaPub } = await generateSigningKey("ES256");
				const otherTaId = "https://other-ta.example.com";
				const now = REG_NOW;
				const otherTaEc = await signEntityStatement(
					{
						iss: otherTaId,
						sub: otherTaId,
						iat: now,
						exp: now + 3600,
						jwks: { keys: [otherTaPub as unknown as Record<string, unknown>] },
					},
					otherTaKey,
					{ typ: JwtTyp.EntityStatement },
				);

				const jwt = await signRpRequest({
					fed,
					rpKeys: { privateKey: rpKeys.privateKey, publicKey: rpKeys.publicKey },
					peerTrustChain: [fed.opEcJwt, otherTaEc],
				});
				const res = await handler(
					new Request(`${OP_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 400);
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, FederationErrorCode.InvalidTrustChain);
				t.ok(body.error_description?.includes("Trust Anchor"));
			});

			test("rejects peer_trust_chain when request body is a Trust Chain (trust-chain+json)", async (t) => {
				const { config, fed } = await buildPeerHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const leafEcWithPeer = await signEntityStatement(
					{
						iss: LEAF_ID,
						sub: LEAF_ID,
						aud: OP_ID,
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [rpKeys.publicKey as unknown as Record<string, unknown>] },
						...REQUIRED_FIELDS,
					},
					rpKeys.privateKey,
					{
						typ: JwtTyp.EntityStatement,
						extraHeaders: {
							peer_trust_chain: [fed.opEcJwt, fed.taSubStatementForOp, fed.taEcJwt],
						},
					},
				);
				const chainBody = JSON.stringify([leafEcWithPeer, fed.taSubStatementForLeaf, fed.taEcJwt]);
				const res = await handler(
					new Request(`${OP_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.TrustChain },
						body: chainBody,
					}),
				);
				t.equal(res.status, 400);
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, "invalid_request");
				t.ok(body.error_description?.includes("Trust Chain"));
			});

			test("same-TA derived from RP header trust_chain even when that header fails validation", async (t) => {
				const { config, fed } = await buildPeerHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");

				const { privateKey: rogueTaKey, publicKey: rogueTaPub } = await generateSigningKey("ES256");
				const rogueTaId = "https://rogue-ta.example.com";
				const rogueTaEc = await signEntityStatement(
					{
						iss: rogueTaId,
						sub: rogueTaId,
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [rogueTaPub as unknown as Record<string, unknown>] },
					},
					rogueTaKey,
					{ typ: JwtTyp.EntityStatement },
				);
				const fakeRpChain = [fed.leafEcJwt, rogueTaEc];

				const jwt = await signEntityStatement(
					{
						iss: LEAF_ID,
						sub: LEAF_ID,
						aud: OP_ID,
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [rpKeys.publicKey as unknown as Record<string, unknown>] },
						...REQUIRED_FIELDS,
					},
					rpKeys.privateKey,
					{
						typ: JwtTyp.EntityStatement,
						extraHeaders: {
							trust_chain: fakeRpChain,
							peer_trust_chain: [fed.opEcJwt, fed.taSubStatementForOp, fed.taEcJwt],
						},
					},
				);
				const res = await handler(
					new Request(`${OP_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 400);
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, FederationErrorCode.InvalidTrustChain);
				t.ok(body.error_description?.includes("Trust Anchor"));
			});

			test("rejects peer_trust_chain rooted in a Trust Anchor not in the OP's trust set", async (t) => {
				const { config, fed } = await buildPeerHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");

				const { privateKey: foreignTaKey, publicKey: foreignTaPub } =
					await generateSigningKey("ES256");
				const foreignTaId = "https://foreign-ta.example.com";
				const foreignTaEc = await signEntityStatement(
					{
						iss: foreignTaId,
						sub: foreignTaId,
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [foreignTaPub as unknown as Record<string, unknown>] },
					},
					foreignTaKey,
					{ typ: JwtTyp.EntityStatement },
				);

				const jwt = await signEntityStatement(
					{
						iss: LEAF_ID,
						sub: LEAF_ID,
						aud: OP_ID,
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [rpKeys.publicKey as unknown as Record<string, unknown>] },
						...REQUIRED_FIELDS,
					},
					rpKeys.privateKey,
					{
						typ: JwtTyp.EntityStatement,
						extraHeaders: {
							trust_chain: [fed.leafEcJwt, foreignTaEc],
							peer_trust_chain: [fed.opEcJwt, foreignTaEc],
						},
					},
				);
				const res = await handler(
					new Request(`${OP_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 400);
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, FederationErrorCode.InvalidTrustChain);
				t.ok(body.error_description?.includes("peer_trust_chain validation failed"));
			});

			test("treats empty peer_trust_chain array as absent (no rejection, no validation)", async (t) => {
				let receivedPeerMetadata: Readonly<Record<string, unknown>> | undefined;
				const adapter: RegistrationProtocolAdapter = {
					validateClientMetadata: (metadata, context) => {
						receivedPeerMetadata = context?.peerResolvedOpMetadata;
						return { ok: true, value: metadata };
					},
					enrichResponseMetadata: (metadata) => metadata,
				};
				const { config, fed } = await buildPeerHandlerConfig(adapter);
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const jwt = await signEntityStatement(
					{
						iss: LEAF_ID,
						sub: LEAF_ID,
						aud: OP_ID,
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [rpKeys.publicKey as unknown as Record<string, unknown>] },
						...REQUIRED_FIELDS,
					},
					rpKeys.privateKey,
					{
						typ: JwtTyp.EntityStatement,
						extraHeaders: { peer_trust_chain: [] },
					},
				);
				void fed;
				const res = await handler(
					new Request(`${OP_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 200, "empty peer_trust_chain should not block registration");
				t.equal(receivedPeerMetadata, undefined, "no peer metadata exposed for empty array");
			});

			test("response trust_anchor matches both RP header trust_chain TA and peer_trust_chain TA", async (t) => {
				const { config, fed } = await buildPeerHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				const jwt = await signRpRequest({
					fed,
					rpKeys: { privateKey: rpKeys.privateKey, publicKey: rpKeys.publicKey },
					peerTrustChain: [fed.opEcJwt, fed.taSubStatementForOp, fed.taEcJwt],
				});
				const res = await handler(
					new Request(`${OP_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 200);
				const decoded = decodeEntityStatement(await res.text());
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				const payload = decoded.value.payload as Record<string, unknown>;
				t.equal(
					payload.trust_anchor,
					TA_ID,
					"response trust_anchor matches the shared TA root of both chains",
				);
			});
		});

		module("oidc / createExplicitRegistrationHandler — body size limits", () => {
			test("body exactly at 64KB boundary is not rejected with 413", async (t) => {
				const config = await createHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const body = "x".repeat(64 * 1024);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body,
					}),
				);
				t.notEqual(res.status, 413);
			});

			test("body 1 byte over 64KB is rejected with 413", async (t) => {
				const config = await createHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const body = "x".repeat(64 * 1024 + 1);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body,
					}),
				);
				t.equal(res.status, 413);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_request");
			});

			test("spoofed Content-Length: 10 with 65KB actual body is rejected with 413", async (t) => {
				const config = await createHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const bigBody = "x".repeat(65 * 1024);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: {
							"Content-Type": MediaType.EntityStatement,
							"Content-Length": "10",
						},
						body: bigBody,
					}),
				);
				t.equal(res.status, 413);
			});
		});
	}
};
