import type QUnit from "qunit";
import {
	type DiscoveryResult,
	decodeEntityStatement,
	type EntityId,
	entityId,
	type FederationOptions,
	generateSigningKey,
	type HttpClient,
	InMemoryJtiStore,
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
import { RequestObjectTyp } from "../../../packages/oidc/src/constants.js";
import { OIDCRegistrationAdapter } from "../../../packages/oidc/src/registration/adapter.js";
import type { AutomaticRegistrationConfig } from "../../../packages/oidc/src/registration/automatic.js";
import { automaticRegistration } from "../../../packages/oidc/src/registration/automatic.js";
import type { ExplicitRegistrationConfig } from "../../../packages/oidc/src/registration/explicit.js";
import { explicitRegistration } from "../../../packages/oidc/src/registration/explicit.js";
import { processAutomaticRegistration } from "../../../packages/oidc/src/registration/process-automatic.js";
import { processExplicitRegistration } from "../../../packages/oidc/src/registration/process-explicit.js";
import type { AutomaticRegistrationContext } from "../../../packages/oidc/src/registration/types.js";
import { validateAutomaticRegistrationRequest } from "../../../packages/oidc/src/registration/validate-request-object.js";
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

		test("returns well-formed authorizationUrl", async (t) => {
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
						response_types_supported: ["code"],
						subject_types_supported: ["public"],
						id_token_signing_alg_values_supported: ["ES256"],
						client_registration_types_supported: ["explicit"],
					},
					federation_entity: {
						federation_registration_endpoint: `${OP_ID}/federation_registration`,
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
				{ kid: fed.opSigningKey.kid, typ: JwtTyp.ExplicitRegistrationResponse },
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
						headers: { "Content-Type": MediaType.ExplicitRegistrationResponse },
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
			t.equal(result.registrationStatement.header.typ, JwtTyp.ExplicitRegistrationResponse);
		});

		test("throws if OP does not advertise explicit registration", async (t) => {
			const fed = await createMockFederation({
				opMetadata: {
					openid_provider: {
						issuer: OP_ID,
						authorization_endpoint: `${OP_ID}/authorize`,
						token_endpoint: `${OP_ID}/token`,
						response_types_supported: ["code"],
						subject_types_supported: ["public"],
						id_token_signing_alg_values_supported: ["ES256"],
						client_registration_types_supported: ["automatic"],
					},
					federation_entity: {
						federation_registration_endpoint: `${OP_ID}/federation_registration`,
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
				{ kid: unknownKey.kid, typ: JwtTyp.ExplicitRegistrationResponse },
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
						headers: { "Content-Type": MediaType.ExplicitRegistrationResponse },
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
				{ kid: fed.opSigningKey.kid, typ: JwtTyp.ExplicitRegistrationResponse },
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
						headers: { "Content-Type": MediaType.ExplicitRegistrationResponse },
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
				{ kid: fed.opSigningKey.kid, typ: JwtTyp.ExplicitRegistrationResponse },
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
						headers: { "Content-Type": MediaType.ExplicitRegistrationResponse },
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
				{ kid: fed.opSigningKey.kid, typ: JwtTyp.ExplicitRegistrationResponse },
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
						headers: { "Content-Type": MediaType.ExplicitRegistrationResponse },
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
	});
};
