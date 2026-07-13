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
	isErr,
	isOk,
	type JWK,
	JwkSigner,
	JwtTyp,
	MediaType,
	MemoryFederationKeyProvider,
	MemoryReplayStore,
	type ReplayStore,
	resolveTrustChains,
	shortestChain,
	signEntityStatement,
	stripPrivateFields,
	type ValidatedTrustChain,
	validateTrustChain,
	WELL_KNOWN_OPENID_FEDERATION,
} from "../../../packages/core/src/index.js";
import { createClientAssertion } from "../../../packages/oidc/src/client-auth/assertion.js";
import {
	ClientRegistrationType,
	OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE,
	OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE,
	RequestObjectTyp,
} from "../../../packages/oidc/src/constants.js";
import * as OidcPublic from "../../../packages/oidc/src/index.js";
import {
	OAuthAuthorizationServerRole,
	OAuthClientRole,
	OAuthResourceRole,
	OidcProviderRole,
	OidcRelyingPartyRole,
} from "../../../packages/oidc/src/index.js";
import { StaticProtocolSigningKeyProvider } from "../../../packages/oidc/src/protocol-keys.js";
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
	OAuthAuthorizationServerMetadataSchema,
	OAuthClientMetadataSchema,
	OAuthResourceMetadataSchema,
	OIDCFederationMetadataSchema,
	OpenIDProviderMetadataSchema,
	OpenIDRelyingPartyMetadataSchema,
	OpenIDRelyingPartyRegistrationResponseMetadataSchema,
	validateOIDCMetadata,
} from "../../../packages/oidc/src/schemas/metadata.js";
import { createMockFederation, LEAF_ID, OP_ID, TA_ID } from "../fixtures/index.js";

// ---------------------------------------------------------------------------
// Shared helpers (mirrors oidc/test/test-helpers.ts)
// ---------------------------------------------------------------------------

type RpConfig = AutomaticRegistrationConfig & ExplicitRegistrationConfig;

function createFederationSigningKey(signingKey: JWK) {
	return { signer: new JwkSigner(signingKey), publicJwk: stripPrivateFields(signingKey) };
}

async function createRpConfig(
	overrides?: Partial<RpConfig>,
): Promise<{ config: RpConfig; signingKey: JWK; publicKey: JWK }> {
	const { privateKey, publicKey } = await generateSigningKey("ES256");
	const { privateKey: protocolPrivateKey, publicKey: protocolPublicKey } =
		await generateSigningKey("ES256");
	const config: RpConfig = {
		entityId: LEAF_ID,
		keyProvider: new MemoryFederationKeyProvider(createFederationSigningKey(privateKey)),
		protocolKeyProvider: new StaticProtocolSigningKeyProvider({
			requestObjectSigner: new JwkSigner(protocolPrivateKey),
		}),
		authorityHints: [TA_ID],
		metadata: {
			openid_relying_party: {
				redirect_uris: ["https://rp.example.com/callback"],
				response_types: ["code"],
				client_registration_types: ["automatic"],
				jwks: { keys: [protocolPublicKey] },
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

async function createDualAnchorRegistrationFixture() {
	const taA = entityId("https://ta-a.example.com");
	const taB = entityId("https://ta-b.example.com");
	const { privateKey: taASigningKey, publicKey: taAPublicKey } = await generateSigningKey("ES256");
	const { privateKey: taBSigningKey, publicKey: taBPublicKey } = await generateSigningKey("ES256");
	const { privateKey: opSigningKey, publicKey: opPublicKey } = await generateSigningKey("ES256");
	const { privateKey: leafSigningKey, publicKey: leafPublicKey } =
		await generateSigningKey("ES256");
	const { privateKey: leafProtocolSigningKey, publicKey: leafProtocolPublicKey } =
		await generateSigningKey("ES256");
	const now = Math.floor(Date.now() / 1000);
	const exp = now + 86400;
	const signStatement = (payload: Record<string, unknown>, key: JWK) =>
		signEntityStatement(payload, new JwkSigner(key), { typ: JwtTyp.EntityStatement });
	const taMetadata = (ta: EntityId) => ({
		federation_entity: {
			federation_fetch_endpoint: `${ta}/federation_fetch`,
		},
	});
	const opMetadata = {
		openid_provider: {
			issuer: OP_ID,
			authorization_endpoint: `${OP_ID}/authorize`,
			token_endpoint: `${OP_ID}/token`,
			federation_registration_endpoint: `${OP_ID}/federation_registration`,
			response_types_supported: ["code"],
			subject_types_supported: ["public"],
			client_registration_types_supported: ["automatic", "explicit"],
		},
	};
	const leafMetadata = {
		openid_relying_party: {
			redirect_uris: ["https://rp.example.com/callback"],
			response_types: ["code"],
			client_registration_types: ["automatic"],
			jwks: { keys: [leafProtocolPublicKey] },
		},
	};
	const taAEcJwt = await signStatement(
		{
			iss: taA,
			sub: taA,
			iat: now,
			exp,
			jwks: { keys: [taAPublicKey] },
			metadata: taMetadata(taA),
		},
		taASigningKey,
	);
	const taBEcJwt = await signStatement(
		{
			iss: taB,
			sub: taB,
			iat: now,
			exp,
			jwks: { keys: [taBPublicKey] },
			metadata: taMetadata(taB),
		},
		taBSigningKey,
	);
	const opEcJwt = await signStatement(
		{
			iss: OP_ID,
			sub: OP_ID,
			iat: now,
			exp,
			jwks: { keys: [opPublicKey] },
			authority_hints: [taA, taB],
			metadata: opMetadata,
		},
		opSigningKey,
	);
	const leafEcJwt = await signStatement(
		{
			iss: LEAF_ID,
			sub: LEAF_ID,
			iat: now,
			exp,
			jwks: { keys: [leafPublicKey] },
			authority_hints: [taB],
			metadata: leafMetadata,
		},
		leafSigningKey,
	);
	const taASubStatementForOp = await signStatement(
		{ iss: taA, sub: OP_ID, iat: now, exp, jwks: { keys: [opPublicKey] } },
		taASigningKey,
	);
	const taBSubStatementForOp = await signStatement(
		{ iss: taB, sub: OP_ID, iat: now, exp, jwks: { keys: [opPublicKey] } },
		taBSigningKey,
	);
	const taBSubStatementForLeaf = await signStatement(
		{ iss: taB, sub: LEAF_ID, iat: now, exp, jwks: { keys: [leafPublicKey] } },
		taBSigningKey,
	);
	const trustAnchors = new Map([
		[taA, { jwks: { keys: [taAPublicKey] } }],
		[taB, { jwks: { keys: [taBPublicKey] } }],
	]);
	const httpClient: HttpClient = async (input: string | URL | Request): Promise<Response> => {
		const url =
			typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
		const parsed = new URL(url);
		if (parsed.pathname === WELL_KNOWN_OPENID_FEDERATION) {
			const byOrigin: Record<string, string> = {
				[taA]: taAEcJwt,
				[taB]: taBEcJwt,
				[OP_ID]: opEcJwt,
				[LEAF_ID]: leafEcJwt,
			};
			const jwt = byOrigin[parsed.origin];
			if (jwt) {
				return new Response(jwt, {
					status: 200,
					headers: { "Content-Type": MediaType.EntityStatement },
				});
			}
		}
		if (parsed.pathname === "/federation_fetch") {
			const sub = parsed.searchParams.get("sub");
			let jwt: string | undefined;
			if (parsed.origin === taA && sub === OP_ID) jwt = taASubStatementForOp;
			if (parsed.origin === taB && sub === OP_ID) jwt = taBSubStatementForOp;
			if (parsed.origin === taB && sub === LEAF_ID) jwt = taBSubStatementForLeaf;
			if (jwt) {
				return new Response(jwt, {
					status: 200,
					headers: { "Content-Type": MediaType.EntityStatement },
				});
			}
		}
		return new Response("Not Found", { status: 404 });
	};
	const options: FederationOptions = { httpClient };
	const preferredOpChain = await validateTrustChain(
		[opEcJwt, taASubStatementForOp, taAEcJwt],
		trustAnchors,
		options,
	);
	if (!preferredOpChain.valid) {
		throw new Error("dual-anchor preferred OP chain is invalid");
	}
	const discovery = {
		entityId: OP_ID,
		resolvedMetadata: preferredOpChain.chain.resolvedMetadata,
		trustChain: preferredOpChain.chain,
		trustMarks: preferredOpChain.chain.trustMarks,
	} as DiscoveryResult;
	const rpConfig: RpConfig = {
		entityId: LEAF_ID,
		keyProvider: new MemoryFederationKeyProvider(createFederationSigningKey(leafSigningKey)),
		protocolKeyProvider: new StaticProtocolSigningKeyProvider({
			requestObjectSigner: new JwkSigner(leafProtocolSigningKey),
		}),
		authorityHints: [taB],
		metadata: leafMetadata,
	};
	return {
		discovery,
		httpClient,
		now,
		opSigningKey,
		rpConfig,
		taA,
		taB,
		trustAnchors,
	};
}

// ---------------------------------------------------------------------------

export default (QUnit: QUnit) => {
	const { module, test } = QUnit;

	module("oidc / public root exports", () => {
		test("keeps registration and client-auth helpers behind role classes", async (t) => {
			const runtimeExports = Object.keys(OidcPublic).sort();
			t.deepEqual(runtimeExports, [
				"OAuthAuthorizationServerRole",
				"OAuthClientRole",
				"OAuthResourceRole",
				"OIDCRegistrationAdapter",
				"OidcProviderRole",
				"OidcRelyingPartyRole",
				"StaticProtocolSigningKeyProvider",
			]);

			const hiddenRuntimeExports = [
				"automaticRegistration",
				"createClientAssertion",
				"createExplicitRegistrationHandler",
				"explicitRegistration",
				"processAutomaticRegistration",
				"processExplicitRegistration",
				"validateAutomaticRegistrationRequest",
				"validateOIDCMetadata",
				"ClientRegistrationType",
				"RequestObjectTyp",
				"OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE",
				"OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE",
				"OIDCRegistrationErrorCode",
				"ExplicitRegistrationRequestPayloadSchema",
				"ExplicitRegistrationResponsePayloadSchema",
				"OIDCFederationMetadataSchema",
				"OpenIDProviderMetadataSchema",
				"OpenIDRelyingPartyMetadataSchema",
			] as const;

			for (const exportName of hiddenRuntimeExports) {
				t.false(exportName in OidcPublic, `${exportName} is not a root runtime export`);
			}

			t.equal(typeof OidcPublic.OidcRelyingPartyRole.createClientAssertion, "function");
			t.equal(typeof OidcPublic.OidcRelyingPartyRole.prototype.createClientAssertion, "function");
			t.equal(typeof OidcPublic.OidcRelyingPartyRole.prototype.explicitlyRegister, "function");
			t.equal(
				typeof OidcPublic.OidcProviderRole.prototype.processAutomaticRegistration,
				"function",
			);
			t.equal(typeof OidcPublic.OidcProviderRole.prototype.processExplicitRegistration, "function");

			const { privateKey } = await generateSigningKey("ES256");
			const jwt = await OidcPublic.OidcRelyingPartyRole.createClientAssertion(
				"https://rp.example.com",
				"https://op.example.com/token",
				new JwkSigner(privateKey),
			);
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.iss, "https://rp.example.com");
			t.equal(decoded.value.payload.sub, "https://rp.example.com");
			t.equal(
				(decoded.value.payload as Record<string, unknown>).aud,
				"https://op.example.com/token",
			);
		});
	});

	// -------------------------------------------------------------------------
	// client-auth/assertion
	// -------------------------------------------------------------------------
	module("oidc / createClientAssertion", () => {
		const clientId = "https://rp.example.com";
		const audience = "https://op.example.com";

		test("produces valid JWT with correct claims", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const jwt = await createClientAssertion(clientId, audience, new JwkSigner(privateKey));
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
			const jwt = await createClientAssertion(clientId, audience, new JwkSigner(privateKey));
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.iss, clientId);
			t.equal(decoded.value.payload.sub, clientId);
		});

		test("generates unique jti across calls", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const signer = new JwkSigner(privateKey);
			const d1 = decodeEntityStatement(await createClientAssertion(clientId, audience, signer));
			const d2 = decodeEntityStatement(await createClientAssertion(clientId, audience, signer));
			t.true(d1.ok && d2.ok);
			if (!d1.ok || !d2.ok) return;
			const jti1 = (d1.value.payload as Record<string, unknown>).jti;
			const jti2 = (d2.value.payload as Record<string, unknown>).jti;
			t.notEqual(jti1, jti2);
		});

		test("respects expiresInSeconds option", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const jwt = await createClientAssertion(clientId, audience, new JwkSigner(privateKey), {
				expiresInSeconds: 120,
			});
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.equal((p.exp as number) - (p.iat as number), 120);
		});

		test("uses the injected NumericDate clock", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const jwt = await createClientAssertion(clientId, audience, new JwkSigner(privateKey), {
				expiresInSeconds: 120,
				clock: { now: () => 1_700_000_000 },
			});
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.iat, 1_700_000_000);
			t.equal(decoded.value.payload.exp, 1_700_000_120);
		});

		test("defaults expiresInSeconds to 60", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const jwt = await createClientAssertion(clientId, audience, new JwkSigner(privateKey));
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.equal((p.exp as number) - (p.iat as number), 60);
		});

		test("signs with the provided key", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const jwt = await createClientAssertion(clientId, audience, new JwkSigner(privateKey));
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.header.kid, privateKey.kid);
			t.equal(jwt.split(".").length, 3);
		});

		test("works with RS256 key", async (t) => {
			const { privateKey } = await generateSigningKey("RS256");
			const jwt = await createClientAssertion(clientId, audience, new JwkSigner(privateKey));
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
				await createClientAssertion(clientId, audience, new JwkSigner(keyWithoutKid));
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

		test("rejects registration response fields in openid_relying_party entity metadata", (t) => {
			const responseOnlyFields: Array<[string, unknown]> = [
				["client_id", "client-123"],
				["client_secret", "secret-123"],
				["client_id_issued_at", 1],
				["client_secret_expires_at", 2],
			];
			for (const [field, value] of responseOnlyFields) {
				t.false(
					OpenIDRelyingPartyMetadataSchema.safeParse({
						redirect_uris: ["https://rp.example.com/callback"],
						[field]: value,
					}).success,
					field,
				);
				t.false(
					OIDCFederationMetadataSchema.safeParse({
						openid_relying_party: {
							redirect_uris: ["https://rp.example.com/callback"],
							[field]: value,
						},
					}).success,
					field,
				);
			}
		});

		test("accepts registration response metadata credentials in the response schema", (t) => {
			const result = OpenIDRelyingPartyRegistrationResponseMetadataSchema.safeParse({
				client_id: "client-123",
				client_secret: "secret-123",
				client_id_issued_at: 1,
				client_secret_expires_at: 2,
				redirect_uris: ["https://rp.example.com/callback"],
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

	module("oidc / metadata common informational fields", () => {
		const commonFields = {
			organization_name: "Example Org",
			display_name: "Example Entity",
			description: "Identity service",
			keywords: ["identity", "federation"],
			contacts: ["Operations Desk", "+1 555 0100"],
			logo_uri: "https://example.com/logo.svg",
			policy_uri: "https://example.com/policy",
			information_uri: "https://example.com/info",
			organization_uri: "https://example.com",
		};

		const validProvider = {
			issuer: "https://op.example.com",
			authorization_endpoint: "https://op.example.com/auth",
			token_endpoint: "https://op.example.com/token",
			response_types_supported: ["code"],
			subject_types_supported: ["public"],
			id_token_signing_alg_values_supported: ["RS256"],
		};
		const validAuthorizationServer = {
			issuer: "https://as.example.com",
			response_types_supported: ["code"],
		};
		const metadataCases: Array<{
			name: string;
			parse: (metadata: Record<string, unknown>) => boolean;
		}> = [
			{
				name: "OpenID Provider metadata",
				parse: (metadata) =>
					OpenIDProviderMetadataSchema.safeParse({ ...validProvider, ...metadata }).success,
			},
			{
				name: "OpenID Relying Party metadata",
				parse: (metadata) =>
					OpenIDRelyingPartyMetadataSchema.safeParse({
						redirect_uris: ["https://rp.example.com/callback"],
						...metadata,
					}).success,
			},
			{
				name: "OAuth Authorization Server metadata",
				parse: (metadata) =>
					OAuthAuthorizationServerMetadataSchema.safeParse({
						...validAuthorizationServer,
						...metadata,
					}).success,
			},
			{
				name: "OAuth Client metadata",
				parse: (metadata) =>
					OAuthClientMetadataSchema.safeParse({
						redirect_uris: ["https://client.example.com/callback"],
						...metadata,
					}).success,
			},
			{
				name: "OAuth Resource metadata",
				parse: (metadata) =>
					OAuthResourceMetadataSchema.safeParse({
						resource: "https://resource.example.com",
						...metadata,
					}).success,
			},
		];

		for (const metadataCase of metadataCases) {
			test(`${metadataCase.name} accepts common informational fields`, (t) => {
				t.true(metadataCase.parse(commonFields));
			});

			test(`${metadataCase.name} rejects malformed common informational fields`, (t) => {
				const invalidCases: Array<{ name: string; metadata: Record<string, unknown> }> = [
					{ name: "empty keywords", metadata: { keywords: [] } },
					{ name: "empty contacts", metadata: { contacts: [] } },
					{ name: "non-string display name", metadata: { display_name: 123 } },
					{ name: "invalid information URL", metadata: { information_uri: "not-a-url" } },
				];
				for (const invalidCase of invalidCases) {
					t.false(metadataCase.parse(invalidCase.metadata), invalidCase.name);
				}
			});
		}
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

	module("oidc / OAuth metadata schemas", () => {
		const validAuthorizationServer = {
			issuer: "https://as.example.com",
			response_types_supported: ["code"],
		};

		test("OAuth Authorization Server validates issuer and registration endpoint", (t) => {
			const invalidIssuers = [
				"http://as.example.com",
				"https://as.example.com?tenant=1",
				"https://as.example.com#fragment",
			];
			for (const issuer of invalidIssuers) {
				t.false(
					OAuthAuthorizationServerMetadataSchema.safeParse({
						...validAuthorizationServer,
						issuer,
					}).success,
					issuer,
				);
			}

			t.false(
				OAuthAuthorizationServerMetadataSchema.safeParse({
					...validAuthorizationServer,
					client_registration_types_supported: ["explicit"],
				}).success,
			);
			t.false(
				OAuthAuthorizationServerMetadataSchema.safeParse({
					...validAuthorizationServer,
					client_registration_types_supported: ["explicit"],
					federation_registration_endpoint: "http://as.example.com/register",
				}).success,
			);
			t.true(
				OAuthAuthorizationServerMetadataSchema.safeParse({
					...validAuthorizationServer,
					client_registration_types_supported: ["explicit"],
					federation_registration_endpoint: "https://as.example.com/register",
				}).success,
			);
		});

		test("OAuth metadata schemas validate JWK Set URLs", (t) => {
			const urlCases: Array<{
				name: string;
				host: string;
				parse: (field: "jwks_uri" | "signed_jwks_uri", value: string) => boolean;
			}> = [
				{
					name: "authorization server",
					host: "as.example.com",
					parse: (field, value) =>
						OAuthAuthorizationServerMetadataSchema.safeParse({
							...validAuthorizationServer,
							[field]: value,
						}).success,
				},
				{
					name: "client",
					host: "client.example.com",
					parse: (field, value) => OAuthClientMetadataSchema.safeParse({ [field]: value }).success,
				},
				{
					name: "resource",
					host: "resource.example.com",
					parse: (field, value) =>
						OAuthResourceMetadataSchema.safeParse({
							resource: "https://resource.example.com",
							[field]: value,
						}).success,
				},
			];

			for (const urlCase of urlCases) {
				for (const field of ["jwks_uri", "signed_jwks_uri"] as const) {
					t.false(urlCase.parse(field, `http://${urlCase.host}/jwks`), urlCase.name);
					t.false(urlCase.parse(field, `https://${urlCase.host}/jwks#frag`), urlCase.name);
					t.true(urlCase.parse(field, `https://${urlCase.host}/jwks`), urlCase.name);
				}
			}
		});

		test("OAuth Resource requires a resource URL", (t) => {
			t.false(OAuthResourceMetadataSchema.safeParse({}).success);
			t.false(OAuthResourceMetadataSchema.safeParse({ resource: "not-a-url" }).success);
			t.true(
				OAuthResourceMetadataSchema.safeParse({
					resource: "https://resource.example.com",
					authorization_servers: ["https://as.example.com"],
				}).success,
			);
		});

		test("combined federation metadata validates OAuth entity metadata", (t) => {
			t.true(
				OIDCFederationMetadataSchema.safeParse({
					oauth_authorization_server: {
						...validAuthorizationServer,
						signed_jwks_uri: "https://as.example.com/jwks.jose",
					},
					oauth_client: {
						redirect_uris: ["https://client.example.com/callback"],
						contacts: ["Client Operations"],
					},
					oauth_resource: {
						resource: "https://resource.example.com",
						keywords: ["resource"],
					},
				}).success,
			);
			t.false(
				OIDCFederationMetadataSchema.safeParse({
					oauth_resource: { keywords: ["missing resource"] },
				}).success,
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
			test("rejects aud arrays", (t) => {
				t.false(
					ExplicitRegistrationRequestPayloadSchema.safeParse({
						...validReq,
						aud: ["https://op.example.com", "https://other-op.example.com"],
					}).success,
				);
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
				metadata: {
					openid_relying_party: {
						client_id: "client-123",
					},
				},
			};
			test("accepts valid registration response", (t) => {
				t.true(ExplicitRegistrationResponsePayloadSchema.safeParse(validResp).success);
			});
			test("rejects aud arrays", (t) => {
				t.false(
					ExplicitRegistrationResponsePayloadSchema.safeParse({
						...validResp,
						aud: ["https://rp.example.com", "https://other-rp.example.com"],
					}).success,
				);
			});
			test("requires trust_anchor", (t) => {
				const { trust_anchor: _, ...v } = validResp;
				t.false(ExplicitRegistrationResponsePayloadSchema.safeParse(v).success);
			});
			test("accepts nested client_secret", (t) => {
				t.true(
					ExplicitRegistrationResponsePayloadSchema.safeParse({
						...validResp,
						metadata: {
							openid_relying_party: {
								client_id: "client-123",
								client_secret: "secret123",
							},
						},
					}).success,
				);
			});
			test("rejects client_secret expiry before response expiry", (t) => {
				t.false(
					ExplicitRegistrationResponsePayloadSchema.safeParse({
						...validResp,
						metadata: {
							openid_relying_party: {
								client_id: "client-123",
								client_secret: "secret123",
								client_secret_expires_at: validResp.exp - 1,
							},
						},
					}).success,
				);
			});
			test("accepts response credential timestamps", (t) => {
				t.true(
					ExplicitRegistrationResponsePayloadSchema.safeParse({
						...validResp,
						metadata: {
							openid_relying_party: {
								client_id: "client-123",
								client_id_issued_at: 1,
								client_secret_expires_at: 2,
							},
						},
					}).success,
				);
			});
			test("rejects invalid response credential types", (t) => {
				const invalidMetadata = [
					{ openid_relying_party: { client_id: 123 } },
					{ openid_relying_party: { client_id: "client-123", client_secret: 123 } },
					{ openid_relying_party: { client_id: "client-123", client_id_issued_at: -1 } },
					{
						openid_relying_party: {
							client_id: "client-123",
							client_secret_expires_at: -1,
						},
					},
				];
				for (const metadata of invalidMetadata) {
					t.false(
						ExplicitRegistrationResponsePayloadSchema.safeParse({
							...validResp,
							metadata,
						}).success,
					);
				}
			});
			test("rejects top-level client_secret", (t) => {
				t.false(
					ExplicitRegistrationResponsePayloadSchema.safeParse({
						...validResp,
						client_secret: "secret123",
					}).success,
				);
			});
			test("requires response metadata", (t) => {
				const { metadata: _, ...v } = validResp;
				t.false(ExplicitRegistrationResponsePayloadSchema.safeParse(v).success);
			});
			test("requires openid_relying_party response metadata", (t) => {
				t.false(
					ExplicitRegistrationResponsePayloadSchema.safeParse({
						...validResp,
						metadata: { oauth_client: { client_id: "client-123" } },
					}).success,
				);
			});
			test("requires response metadata client_id", (t) => {
				t.false(
					ExplicitRegistrationResponsePayloadSchema.safeParse({
						...validResp,
						metadata: { openid_relying_party: { response_types: ["code"] } },
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

		test("rejects registration response fields in RP entity metadata", (t) => {
			const result = adapter.validateClientMetadata({
				openid_relying_party: {
					redirect_uris: ["https://rp.example.com/callback"],
					client_id: "client-123",
				},
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
			const { config } = await createRpConfig({});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.true(isOk(result));
			if (!isOk(result)) return;
			const decoded = decodeEntityStatement(result.value.requestObjectJwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.header.typ, "oauth-authz-req+jwt");
		});

		test("has correct JWT claims: iss, client_id, aud, jti, exp", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.true(isOk(result));
			if (!isOk(result)) return;
			const decoded = decodeEntityStatement(result.value.requestObjectJwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.equal(p.iss, LEAF_ID);
			t.equal(p.client_id, LEAF_ID);
			t.equal(p.aud, OP_ID);
			t.equal(typeof p.jti, "string");
			t.equal(typeof p.exp, "number");
		});

		test("uses options.clock for Request Object timestamps", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
			const fixedNow = Math.floor(Date.now() / 1000);
			const result = await automaticRegistration(discovery, config, authzParams, fed.trustAnchors, {
				...fed.options,
				clock: { now: () => fixedNow },
			});
			t.true(isOk(result));
			if (!isOk(result)) return;
			const decoded = decodeEntityStatement(result.value.requestObjectJwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.iat, fixedNow);
			t.equal(decoded.value.payload.exp, fixedNow + 300);
		});

		test("does NOT include sub claim", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.true(isOk(result));
			if (!isOk(result)) return;
			const decoded = decodeEntityStatement(result.value.requestObjectJwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal((decoded.value.payload as Record<string, unknown>).sub, undefined);
		});

		test("includes trust_chain as JWS header parameter", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.true(isOk(result));
			if (!isOk(result)) return;
			const decoded = decodeEntityStatement(result.value.requestObjectJwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const h = decoded.value.header as Record<string, unknown>;
			t.ok(Array.isArray(h.trust_chain));
			t.ok((h.trust_chain as string[]).length > 0);
		});

		test("selects a trust_chain rooted in a Trust Anchor shared with the OP", async (t) => {
			const fx = await createDualAnchorRegistrationFixture();
			const result = await automaticRegistration(
				fx.discovery,
				fx.rpConfig,
				authzParams,
				fx.trustAnchors,
				{ httpClient: fx.httpClient },
			);
			t.true(isOk(result), isErr(result) ? result.error.description : undefined);
			if (!isOk(result)) return;
			t.equal(result.value.trustChain.trustAnchorId, fx.taB);
			const decoded = decodeEntityStatement(result.value.requestObjectJwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const trustChain = (decoded.value.header as Record<string, unknown>).trust_chain;
			t.true(Array.isArray(trustChain));
			if (!Array.isArray(trustChain)) return;
			const root = decodeEntityStatement(trustChain[trustChain.length - 1] as string);
			t.true(root.ok);
			if (!root.ok) return;
			t.equal(root.value.payload.iss, fx.taB);
			t.equal(root.value.payload.sub, fx.taB);
		});

		test("attaches peer_trust_chain when includePeerTrustChain is true", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({
				includePeerTrustChain: true,
			});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.true(isOk(result));
			if (!isOk(result)) return;
			const decoded = decodeEntityStatement(result.value.requestObjectJwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const h = decoded.value.header as Record<string, unknown>;
			t.ok(Array.isArray(h.peer_trust_chain), "peer_trust_chain should be present");
			const peerChain = h.peer_trust_chain as string[];
			t.ok(peerChain.length > 0);
			// Same-Trust-Anchor invariant: peer chain ends at the same anchor as trust_chain.
			const rpChain = h.trust_chain as string[];
			const rpLast = decodeEntityStatement(rpChain[rpChain.length - 1] as string);
			const peerLast = decodeEntityStatement(peerChain[peerChain.length - 1] as string);
			t.true(rpLast.ok && peerLast.ok);
			if (!rpLast.ok || !peerLast.ok) return;
			t.equal(
				(rpLast.value.payload as Record<string, unknown>).iss,
				(peerLast.value.payload as Record<string, unknown>).iss,
			);
			// The peer chain starts with the OpenID Provider Entity Configuration.
			const peerFirst = decodeEntityStatement(peerChain[0] as string);
			t.true(peerFirst.ok);
			if (!peerFirst.ok) return;
			const peerFirstPayload = peerFirst.value.payload as Record<string, unknown>;
			t.equal(peerFirstPayload.iss, OP_ID);
			t.equal(peerFirstPayload.sub, OP_ID);
		});

		test("fails when includePeerTrustChain is set but no peer chain to shared TA exists", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			// Exclude OP discovery responses so peer-chain resolution fails while
			// preserving the RP leaf chain used by the main request.
			const blockingHttpClient = async (input: string | URL | Request) => {
				const url = typeof input === "string" ? input : (input as Request).url;
				if (url.includes(OP_ID.replace(/^https?:\/\//, ""))) {
					return new Response("Not found", { status: 404 });
				}
				return fed.options.httpClient!(input);
			};
			const { config } = await createRpConfig({
				includePeerTrustChain: true,
			});
			const result = await automaticRegistration(discovery, config, authzParams, fed.trustAnchors, {
				...fed.options,
				httpClient: blockingHttpClient,
			});
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(result.error.description.toLowerCase().includes("peer"));
			}
		});

		test("includes authzRequestParams in JWT payload", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
			const params = { ...authzParams, nonce: "test-nonce" };
			const result = await automaticRegistration(
				discovery,
				config,
				params,
				fed.trustAnchors,
				fed.options,
			);
			t.true(isOk(result));
			if (!isOk(result)) return;
			const decoded = decodeEntityStatement(result.value.requestObjectJwt);
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
				requestDelivery: "query",
			});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.true(isOk(result));
			if (!isOk(result)) return;
			t.equal(result.value.delivery, "query");
			if (result.value.delivery !== "query") return;
			const url = new URL(result.value.authorizationUrl);
			t.equal(url.searchParams.get("request"), result.value.requestObjectJwt);
			t.equal(url.searchParams.get("client_id"), LEAF_ID);
		});

		test("does not allow authzRequestParams to overwrite required claims", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
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
			t.true(isOk(result));
			if (!isOk(result)) return;
			const decoded = decodeEntityStatement(result.value.requestObjectJwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.equal(p.iss, LEAF_ID);
			t.equal(p.aud, OP_ID);
			t.equal(p.sub, undefined);
		});

		test("fails if OP does not advertise automatic", async (t) => {
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
			const { config } = await createRpConfig({});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(result.error.description.includes("automatic"), result.error.description);
			}
		});

		test("does not include registration param in JWT payload", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
			const result = await automaticRegistration(
				discovery,
				config,
				{ registration: '{"client_name":"evil"}', ...authzParams },
				fed.trustAnchors,
				fed.options,
			);
			t.true(isOk(result));
			if (!isOk(result)) return;
			const decoded = decodeEntityStatement(result.value.requestObjectJwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal((decoded.value.payload as Record<string, unknown>).registration, undefined);
		});

		test("includes trustChainExpiresAt matching trust chain expiry", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.true(isOk(result));
			if (!isOk(result)) return;
			t.ok(result.value.trustChainExpiresAt > 0);
			t.equal(result.value.trustChainExpiresAt, discovery.trustChain.expiresAt);
		});

		test("uses JWK allowlist for public keys (no private fields leak)", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.true(isOk(result));
			if (!isOk(result)) return;
			t.ok(result.value.requestObjectJwt);
		});

		test("fails when openid_relying_party and oauth_client are missing", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({
				metadata: {},
			});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.true(result.error.description.includes("is required for automatic registration"));
			}
		});

		test("fails when jwks is not a JWK Set", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({
				metadata: {
					openid_relying_party: {
						// biome-ignore lint/suspicious/noExplicitAny: test
						jwks: "not-a-jwk-set" as any,
					},
				},
			});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.true(result.error.description.includes("must be a JWK Set"));
			}
		});

		test("fails when signer kid is not published in jwks", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({
				metadata: {
					openid_relying_party: {
						jwks: { keys: [] },
					},
				},
			});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.true(result.error.description.includes("is not published in metadata"));
			}
		});

		test("fails when OIDC protocol keys are not published", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({
				metadata: {
					openid_relying_party: {
						client_name: "test",
					},
				},
			});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.true(result.error.description.includes("must publish OIDC protocol keys"));
			}
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
			const { config } = await createRpConfig({});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.true(isOk(result));
			if (!isOk(result)) return;
			t.equal(result.value.delivery, "form_post");
			if (result.value.delivery !== "form_post") return;
			t.equal(typeof result.value.authorizationEndpoint, "string");
			t.equal(result.value.formParams.request, result.value.requestObjectJwt);
			t.equal(result.value.formParams.client_id, LEAF_ID);
		});

		test("form_post: authorizationEndpoint matches OP authorization_endpoint metadata", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({
				requestDelivery: "form_post",
			});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.true(isOk(result));
			if (!isOk(result)) return;
			t.equal(result.value.delivery, "form_post");
			if (result.value.delivery !== "form_post") return;
			const opMeta = discovery.resolvedMetadata.openid_provider as Record<string, unknown>;
			t.equal(result.value.authorizationEndpoint, opMeta.authorization_endpoint as string);
		});

		test("request_uri: returns authorizationUrl with request_uri query and echoes input URI", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const hostedUri = "https://rp.example.com/request-object/xyz";
			const { config } = await createRpConfig({
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
			t.true(isOk(result));
			if (!isOk(result)) return;
			t.equal(result.value.delivery, "request_uri");
			if (result.value.delivery !== "request_uri") return;
			t.equal(result.value.requestUri, hostedUri);
			const url = new URL(result.value.authorizationUrl);
			t.equal(url.searchParams.get("request_uri"), hostedUri);
			t.equal(url.searchParams.get("client_id"), LEAF_ID);
			t.equal(url.searchParams.get("request"), null);
		});

		test("request_uri: fails when requestUri is missing", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({
				requestDelivery: "request_uri",
			});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(result.error.description.toLowerCase().includes("request_uri"));
			}
		});

		test("par: POSTs request + client_id + client_assertion to PAR endpoint and returns urn-style authorizationUrl", async (t) => {
			const now = Math.floor(Date.now() / 1000) + 30;
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
				requestDelivery: "par",
			});

			// Intercept only the PAR endpoint; all federation discovery requests
			// continue through the regular mock HTTP client.
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
				clock: { now: () => now },
				httpClient: parHttpClient,
			});
			t.true(isOk(result));
			if (!isOk(result)) return;
			t.equal(result.value.delivery, "par");
			if (result.value.delivery !== "par") return;
			t.equal(capturedMethod, "POST");
			t.equal(typeof capturedBody, "string");
			const body = new URLSearchParams(capturedBody as string);
			t.equal(body.get("request"), result.value.requestObjectJwt);
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
			t.equal(ap.iat, now);
			t.equal(ap.exp, now + 60);
			t.equal(result.value.pushedAuthorizationRequestEndpoint, parEndpoint);
			t.equal(result.value.parRequestUri, urn);
			const finalUrl = new URL(result.value.authorizationUrl);
			t.equal(finalUrl.searchParams.get("request_uri"), urn);
			t.equal(finalUrl.searchParams.get("client_id"), LEAF_ID);
			t.equal(result.value.parExpiresAt, now + 60);
		});

		test("par: rejects unpublished client assertion signer before POST", async (t) => {
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
			const requestKeys = await generateSigningKey("ES256");
			const assertionKeys = await generateSigningKey("ES256");
			const { config } = await createRpConfig({
				requestDelivery: "par",
				protocolKeyProvider: new StaticProtocolSigningKeyProvider({
					requestObjectSigner: new JwkSigner(requestKeys.privateKey),
					clientAssertionSigner: new JwkSigner(assertionKeys.privateKey),
				}),
				metadata: {
					openid_relying_party: {
						redirect_uris: ["https://rp.example.com/callback"],
						response_types: ["code"],
						client_registration_types: ["automatic"],
						jwks: { keys: [requestKeys.publicKey] },
					},
				},
			});

			let parPosts = 0;
			const httpClient: HttpClient = async (input, init) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (url === parEndpoint) {
					parPosts += 1;
					return new Response(JSON.stringify({ request_uri: "urn:test", expires_in: 60 }), {
						status: 201,
						headers: { "content-type": "application/json" },
					});
				}
				return fed.options.httpClient!(input, init);
			};

			const result = await automaticRegistration(discovery, config, authzParams, fed.trustAnchors, {
				...fed.options,
				httpClient,
			});
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(result.error.description.includes("client assertion"), result.error.description);
			}
			t.equal(parPosts, 0);
		});

		test("par: fails when OP advertises no pushed_authorization_request_endpoint", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({
				requestDelivery: "par",
			});
			const result = await automaticRegistration(
				discovery,
				config,
				authzParams,
				fed.trustAnchors,
				fed.options,
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(
					result.error.description.toLowerCase().includes("pushed_authorization_request_endpoint"),
				);
			}
		});
	});

	// -------------------------------------------------------------------------
	// registration/explicit
	// -------------------------------------------------------------------------
	module("oidc / explicitRegistration (RP-side)", () => {
		async function createMockOpWithRegistration() {
			const fed = await createMockFederation();
			const { config } = await createRpConfig({});
			const discovery = await createMockDiscovery(OP_ID, fed);
			const now = Math.floor(Date.now() / 1000);
			const registrationResponsePayload = {
				iss: OP_ID,
				sub: LEAF_ID,
				aud: LEAF_ID,
				iat: now,
				exp: now + 3600,
				authority_hints: [TA_ID],
				trust_anchor: TA_ID,
				metadata: {
					openid_relying_party: {
						client_id: LEAF_ID,
						redirect_uris: ["https://rp.example.com/callback"],
						response_types: ["code"],
					},
				},
			};
			const originalHttpClient = fed.httpClient;
			const httpClient: HttpClient = async (input, init) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration") {
					const requestBody = input instanceof Request ? await input.clone().text() : "";
					const requestPayload = decodeEntityStatement(requestBody);
					const responsePayload = {
						...registrationResponsePayload,
						...(requestPayload.ok
							? { jwks: (requestPayload.value.payload as Record<string, unknown>).jwks }
							: {}),
					};
					const registrationResponseJwt = await signEntityStatement(
						responsePayload,
						new JwkSigner(fed.opSigningKey),
						{ typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
					);
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

		async function explicitRegistrationWithResponse(
			responsePayload: Record<string, unknown>,
			configOverrides?: Partial<RpConfig>,
			responseOptions?: {
				readonly status?: number;
				readonly contentType?: string | null;
			},
		) {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig(configOverrides);
			const responseJwt = await signEntityStatement(
				responsePayload,
				new JwkSigner(fed.opSigningKey),
				{ typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
			);
			const httpClient = async (input: string | URL | Request) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration") {
					const headers = new Headers();
					if (responseOptions?.contentType !== null) {
						headers.set(
							"Content-Type",
							responseOptions?.contentType ?? OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE,
						);
					}
					return new Response(responseJwt, {
						status: responseOptions?.status ?? 200,
						headers,
					});
				}
				return fed.httpClient(input);
			};
			return explicitRegistration(discovery, config, fed.trustAnchors, { httpClient });
		}

		function explicitRegistrationResponseBase(overrides?: Record<string, unknown>) {
			const now = Math.floor(Date.now() / 1000);
			return {
				iss: OP_ID,
				sub: LEAF_ID,
				aud: LEAF_ID,
				iat: now,
				exp: now + 3600,
				authority_hints: [TA_ID],
				trust_anchor: TA_ID,
				metadata: { openid_relying_party: { client_id: LEAF_ID } },
				...overrides,
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
			const result = await explicitRegistration(mock.discovery, mock.config, mock.trustAnchors, {
				httpClient: trackingClient,
			});
			t.true(isOk(result), isErr(result) ? result.error.description : undefined);
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
			const result = await explicitRegistration(mock.discovery, mock.config, mock.trustAnchors, {
				httpClient: trackingClient,
			});
			t.true(isOk(result));
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

		test("uses options.clock for the RP Entity Configuration", async (t) => {
			const mock = await createMockOpWithRegistration();
			const now = Math.floor(Date.now() / 1000) + 30;
			let capturedBody = "";
			const trackingClient: HttpClient = async (input, init) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration" && input instanceof Request) {
					capturedBody = await input.clone().text();
				}
				return mock.httpClient(input, init);
			};
			const result = await explicitRegistration(mock.discovery, mock.config, mock.trustAnchors, {
				clock: { now: () => now },
				httpClient: trackingClient,
			});
			t.true(isOk(result));
			const decoded = decodeEntityStatement(capturedBody);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.iat, now);
			t.equal(decoded.value.payload.exp, now + 86400);
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
			const result = await explicitRegistration(
				mock.discovery,
				{ ...mock.config, includePeerTrustChain: true },
				mock.trustAnchors,
				{ httpClient: trackingClient },
			);
			t.true(isOk(result));
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

		test("selects a trust_chain rooted in a Trust Anchor shared with the OP", async (t) => {
			const fx = await createDualAnchorRegistrationFixture();
			let capturedBody = "";
			const httpClient: HttpClient = async (input, init) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration" && input instanceof Request) {
					capturedBody = await input.clone().text();
					const responseJwt = await signEntityStatement(
						{
							iss: OP_ID,
							sub: LEAF_ID,
							aud: LEAF_ID,
							iat: fx.now,
							exp: fx.now + 3600,
							authority_hints: [fx.taB],
							trust_anchor: fx.taB,
							metadata: { openid_relying_party: { client_id: LEAF_ID } },
						},
						new JwkSigner(fx.opSigningKey),
						{ typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
					);
					return new Response(responseJwt, {
						status: 200,
						headers: { "Content-Type": OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE },
					});
				}
				return fx.httpClient(input, init);
			};
			const result = await explicitRegistration(fx.discovery, fx.rpConfig, fx.trustAnchors, {
				httpClient,
			});
			t.true(isOk(result), isErr(result) ? result.error.description : undefined);
			if (!isOk(result)) return;
			t.equal(
				(result.value.registrationStatement.payload as Record<string, unknown>).trust_anchor,
				fx.taB,
			);
			const decoded = decodeEntityStatement(capturedBody);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const trustChain = (decoded.value.header as Record<string, unknown>).trust_chain;
			t.true(Array.isArray(trustChain));
			if (!Array.isArray(trustChain)) return;
			const root = decodeEntityStatement(trustChain[trustChain.length - 1] as string);
			t.true(root.ok);
			if (!root.ok) return;
			t.equal(root.value.payload.iss, fx.taB);
			t.equal(root.value.payload.sub, fx.taB);
		});

		test("returns correct clientId and registeredMetadata", async (t) => {
			const mock = await createMockOpWithRegistration();
			const result = await explicitRegistration(
				mock.discovery,
				mock.config,
				mock.trustAnchors,
				mock.options,
			);
			t.true(isOk(result));
			if (isOk(result)) {
				t.equal(result.value.clientId, LEAF_ID);
				t.ok(result.value.registeredMetadata);
				t.ok(result.value.expiresAt > 0);
			}
		});

		test("returns clientId from response metadata instead of response sub", async (t) => {
			const result = await explicitRegistrationWithResponse(
				explicitRegistrationResponseBase({
					metadata: {
						openid_relying_party: {
							client_id: "op-issued-client-id",
							redirect_uris: ["https://rp.example.com/callback"],
						},
					},
				}),
			);
			t.true(isOk(result), isErr(result) ? result.error.description : undefined);
			if (isOk(result)) {
				t.equal(result.value.clientId, "op-issued-client-id");
				t.equal(result.value.registeredMetadata.client_id, "op-issued-client-id");
			}
		});

		test("fails if explicit registration response status is not exactly 200", async (t) => {
			const result = await explicitRegistrationWithResponse(
				explicitRegistrationResponseBase(),
				undefined,
				{ status: 201 },
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/HTTP 201/.test(result.error.description), result.error.description);
			}
		});

		test("fails if explicit registration response Content-Type is missing", async (t) => {
			const result = await explicitRegistrationWithResponse(
				explicitRegistrationResponseBase(),
				undefined,
				{ contentType: null },
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/Content-Type/.test(result.error.description), result.error.description);
			}
		});

		test("fails if explicit registration response Content-Type is wrong", async (t) => {
			const result = await explicitRegistrationWithResponse(
				explicitRegistrationResponseBase(),
				undefined,
				{ contentType: "application/entity-statement+jwt" },
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/Content-Type/.test(result.error.description), result.error.description);
			}
		});

		test("fails if explicit registration response Content-Type has parameters", async (t) => {
			const result = await explicitRegistrationWithResponse(
				explicitRegistrationResponseBase(),
				undefined,
				{ contentType: `${OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE}; charset=utf-8` },
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/Content-Type/.test(result.error.description), result.error.description);
			}
		});

		test("fails if OP has no federation_registration_endpoint", async (t) => {
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
			const { config } = await createRpConfig({});
			const result = await explicitRegistration(discovery, config, fed.trustAnchors, fed.options);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(
					result.error.description.includes("federation_registration_endpoint"),
					result.error.description,
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
			t.true(isOk(result));
			if (isOk(result)) {
				t.equal(
					result.value.registrationStatement.header.typ,
					OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE,
				);
			}
		});

		test("fails if OP does not advertise explicit registration", async (t) => {
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
			const { config } = await createRpConfig({});
			const result = await explicitRegistration(discovery, config, fed.trustAnchors, fed.options);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(result.error.description.includes("explicit"), result.error.description);
			}
		});

		test("CRIT-1: fails if JWKS is missing (cannot verify response)", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { privateKey: unknownKey } = await generateSigningKey("ES256");
			const now = Math.floor(Date.now() / 1000);
			const badResponseJwt = await signEntityStatement(
				{ iss: OP_ID, sub: LEAF_ID, aud: LEAF_ID, iat: now, exp: now + 86400, trust_anchor: TA_ID },
				new JwkSigner(unknownKey),
				{ typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
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
			const { config } = await createRpConfig({});
			const result = await explicitRegistration(discovery, config, fed.trustAnchors, {
				httpClient,
			});
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/signature|verification/i.test(result.error.description), result.error.description);
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
			t.true(isOk(result));
			if (isOk(result)) {
				t.ok(result.value.trustChainExpiresAt > 0);
				t.equal(result.value.trustChainExpiresAt, mock.discovery.trustChain.expiresAt);
			}
		});

		test("fails if response trust_anchor doesn't match OP chain root", async (t) => {
			const fed = await createMockFederation();
			const { config } = await createRpConfig({});
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
				new JwkSigner(fed.opSigningKey),
				{ typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
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
			const result = await explicitRegistration(discovery, config, fed.trustAnchors, {
				httpClient,
			});
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/trust_anchor/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if response metadata is missing a requested entity type", async (t) => {
			const fed = await createMockFederation();
			const { config } = await createRpConfig({});
			const discovery = await createMockDiscovery(OP_ID, fed);
			const now = Math.floor(Date.now() / 1000);
			// The RP requested openid_relying_party metadata, while the OP responds
			// with a different entity type. This must hit the missing-entity-type guard.
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
				new JwkSigner(fed.opSigningKey),
				{ typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
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
			const result = await explicitRegistration(discovery, config, fed.trustAnchors, {
				httpClient,
			});
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(
					/missing requested entity type/i.test(result.error.description),
					result.error.description,
				);
			}
		});

		test("fails if response metadata is missing", async (t) => {
			const { metadata: _, ...payload } = explicitRegistrationResponseBase();
			const result = await explicitRegistrationWithResponse(payload);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/metadata/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if response metadata.openid_relying_party.client_id is missing", async (t) => {
			const result = await explicitRegistrationWithResponse(
				explicitRegistrationResponseBase({
					metadata: { openid_relying_party: { response_types: ["code"] } },
				}),
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/client_id/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if response authority_hints is missing", async (t) => {
			const { authority_hints: _, ...payload } = explicitRegistrationResponseBase();
			const result = await explicitRegistrationWithResponse(payload);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/authority_hints/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if response authority_hints has multiple elements", async (t) => {
			const result = await explicitRegistrationWithResponse(
				explicitRegistrationResponseBase({
					authority_hints: [TA_ID, "https://other.example.com"],
				}),
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/single-element/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if response authority_hints does not match selected RP trust chain", async (t) => {
			const result = await explicitRegistrationWithResponse(
				explicitRegistrationResponseBase({
					authority_hints: ["https://unrelated.example.com"],
				}),
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/authority_hints/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if response expires after selected RP trust chain", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
			const now = Math.floor(Date.now() / 1000);
			const responseJwt = await signEntityStatement(
				{
					iss: OP_ID,
					sub: LEAF_ID,
					aud: LEAF_ID,
					iat: now,
					exp: discovery.trustChain.expiresAt + 1,
					authority_hints: [TA_ID],
					trust_anchor: TA_ID,
					metadata: { openid_relying_party: { client_id: LEAF_ID } },
				},
				new JwkSigner(fed.opSigningKey),
				{ typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
			);
			const httpClient: HttpClient = async (input) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration") {
					return new Response(responseJwt, {
						status: 200,
						headers: { "Content-Type": OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE },
					});
				}
				return fed.httpClient(input);
			};
			const result = await explicitRegistration(discovery, config, fed.trustAnchors, {
				httpClient,
			});
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/trust chain expiry/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if response metadata contains an unrequested entity type", async (t) => {
			const result = await explicitRegistrationWithResponse(
				explicitRegistrationResponseBase({
					metadata: {
						openid_relying_party: { client_id: LEAF_ID },
						oauth_client: { client_id: LEAF_ID },
					},
				}),
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/unrequested entity type/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if response jwks is not a verbatim copy of request EC jwks", async (t) => {
			const otherKey = await generateSigningKey("ES256");
			const result = await explicitRegistrationWithResponse(
				explicitRegistrationResponseBase({ jwks: { keys: [otherKey.publicKey] } }),
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/jwks/i.test(result.error.description), result.error.description);
			}
		});

		test("does not leak raw OP response body in errors", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
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
			const result = await explicitRegistration(discovery, config, fed.trustAnchors, {
				httpClient,
			});
			t.true(isErr(result));
			if (isErr(result)) {
				const msg = result.error.description;
				t.notOk(msg.includes("SECRET_INTERNAL_ERROR_DETAILS"), "no secret in message");
				t.ok(msg.includes("500"), "includes status code");
			}
		});

		test("fails if OP response is already expired", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
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
				new JwkSigner(fed.opSigningKey),
				{ typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
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
			const result = await explicitRegistration(discovery, config, fed.trustAnchors, {
				httpClient,
			});
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(
					/expired|signature|verification/i.test(result.error.description),
					result.error.description,
				);
			}
		});

		test("fails if OP response is missing exp", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
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
				new JwkSigner(fed.opSigningKey),
				{ typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
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
			const result = await explicitRegistration(discovery, config, fed.trustAnchors, {
				httpClient,
			});
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/exp/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if response cannot be decoded", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
			const httpClient = async (input: string | URL | Request) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration")
					return new Response("not-a-jwt", {
						status: 200,
						headers: { "Content-Type": OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE },
					});
				return fed.httpClient(input);
			};
			const result = await explicitRegistration(discovery, config, fed.trustAnchors, {
				httpClient,
			});
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(
					/signature verification failed/i.test(result.error.description),
					result.error.description,
				);
			}
		});

		test("fails if response has wrong typ header", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
			const now = Math.floor(Date.now() / 1000);
			const wrongTypResponseJwt = await signEntityStatement(
				{
					iss: OP_ID,
					sub: LEAF_ID,
					aud: LEAF_ID,
					iat: now,
					exp: now + 86400,
					trust_anchor: TA_ID,
					metadata: { openid_relying_party: { client_id: LEAF_ID } },
				},
				new JwkSigner(fed.opSigningKey),
				{ typ: "invalid-typ" },
			);
			const httpClient = async (input: string | URL | Request) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration")
					return new Response(wrongTypResponseJwt, {
						status: 200,
						headers: { "Content-Type": OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE },
					});
				return fed.httpClient(input);
			};
			const result = await explicitRegistration(discovery, config, fed.trustAnchors, {
				httpClient,
			});
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(
					/signature verification failed/i.test(result.error.description),
					result.error.description,
				);
			}
		});

		test("fails if response iss does not match OP", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
			const now = Math.floor(Date.now() / 1000);
			const wrongIssResponseJwt = await signEntityStatement(
				{
					iss: "https://wrong-op.example.com",
					sub: LEAF_ID,
					aud: LEAF_ID,
					iat: now,
					exp: now + 86400,
					trust_anchor: TA_ID,
					metadata: { openid_relying_party: { client_id: LEAF_ID } },
				},
				new JwkSigner(fed.opSigningKey),
				{ typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
			);
			const httpClient = async (input: string | URL | Request) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration")
					return new Response(wrongIssResponseJwt, {
						status: 200,
						headers: { "Content-Type": OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE },
					});
				return fed.httpClient(input);
			};
			const result = await explicitRegistration(discovery, config, fed.trustAnchors, {
				httpClient,
			});
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/iss/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if response sub is missing", async (t) => {
			const { sub: _, ...payload } = explicitRegistrationResponseBase();
			const result = await explicitRegistrationWithResponse(payload);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/sub/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if response sub does not match RP", async (t) => {
			const result = await explicitRegistrationWithResponse(
				explicitRegistrationResponseBase({ sub: "https://other-rp.example.com" }),
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/sub/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if response aud does not match RP", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
			const now = Math.floor(Date.now() / 1000);
			const wrongAudResponseJwt = await signEntityStatement(
				{
					iss: OP_ID,
					sub: LEAF_ID,
					aud: "https://wrong-rp.example.com",
					iat: now,
					exp: now + 86400,
					trust_anchor: TA_ID,
					metadata: { openid_relying_party: { client_id: LEAF_ID } },
				},
				new JwkSigner(fed.opSigningKey),
				{ typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
			);
			const httpClient = async (input: string | URL | Request) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration")
					return new Response(wrongAudResponseJwt, {
						status: 200,
						headers: { "Content-Type": OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE },
					});
				return fed.httpClient(input);
			};
			const result = await explicitRegistration(discovery, config, fed.trustAnchors, {
				httpClient,
			});
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/aud/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if response aud has multiple values", async (t) => {
			const result = await explicitRegistrationWithResponse(
				explicitRegistrationResponseBase({
					aud: [LEAF_ID, "https://other-rp.example.com"],
				}),
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/aud/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if response is missing iat", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
			const now = Math.floor(Date.now() / 1000);
			const noIatResponseJwt = await signEntityStatement(
				{
					iss: OP_ID,
					sub: LEAF_ID,
					aud: LEAF_ID,
					exp: now + 86400,
					trust_anchor: TA_ID,
					metadata: { openid_relying_party: { client_id: LEAF_ID } },
				},
				new JwkSigner(fed.opSigningKey),
				{ typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
			);
			const httpClient = async (input: string | URL | Request) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration")
					return new Response(noIatResponseJwt, {
						status: 200,
						headers: { "Content-Type": OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE },
					});
				return fed.httpClient(input);
			};
			const result = await explicitRegistration(discovery, config, fed.trustAnchors, {
				httpClient,
			});
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/iat/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if response trust_anchor is unknown", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
			const now = Math.floor(Date.now() / 1000);
			const unknownTaResponseJwt = await signEntityStatement(
				{
					iss: OP_ID,
					sub: LEAF_ID,
					aud: LEAF_ID,
					iat: now,
					exp: now + 86400,
					trust_anchor: "https://unknown-ta.example.com",
					metadata: { openid_relying_party: { client_id: LEAF_ID } },
				},
				new JwkSigner(fed.opSigningKey),
				{ typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
			);
			const httpClient = async (input: string | URL | Request) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration")
					return new Response(unknownTaResponseJwt, {
						status: 200,
						headers: { "Content-Type": OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE },
					});
				return fed.httpClient(input);
			};
			const result = await explicitRegistration(discovery, config, fed.trustAnchors, {
				httpClient,
			});
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/trust_anchor.*configured/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if response authority_hints is invalid", async (t) => {
			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);
			const { config } = await createRpConfig({});
			const now = Math.floor(Date.now() / 1000);
			const invalidHintsResponseJwt = await signEntityStatement(
				{
					iss: OP_ID,
					sub: LEAF_ID,
					aud: LEAF_ID,
					iat: now,
					exp: now + 86400,
					trust_anchor: TA_ID,
					authority_hints: ["not-a-string-hint", 123],
					metadata: { openid_relying_party: { client_id: LEAF_ID } },
				},
				new JwkSigner(fed.opSigningKey),
				{ typ: OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE },
			);
			const httpClient = async (input: string | URL | Request) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				if (new URL(url).pathname === "/federation_registration")
					return new Response(invalidHintsResponseJwt, {
						status: 200,
						headers: { "Content-Type": OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE },
					});
				return fed.httpClient(input);
			};
			const result = await explicitRegistration(discovery, config, fed.trustAnchors, {
				httpClient,
			});
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/authority_hints/i.test(result.error.description), result.error.description);
			}
		});

		test("returns clientSecret from nested response metadata", async (t) => {
			const result = await explicitRegistrationWithResponse(
				explicitRegistrationResponseBase({
					metadata: {
						openid_relying_party: {
							client_id: LEAF_ID,
							client_secret: "super-secret-123",
						},
					},
				}),
			);
			t.true(isOk(result));
			if (isOk(result)) {
				t.equal(result.value.clientSecret, "super-secret-123");
			}
		});

		test("fails if nested client_secret expires before the response", async (t) => {
			const now = Math.floor(Date.now() / 1000);
			const result = await explicitRegistrationWithResponse(
				explicitRegistrationResponseBase({
					iat: now,
					exp: now + 3600,
					metadata: {
						openid_relying_party: {
							client_id: LEAF_ID,
							client_secret: "super-secret-123",
							client_secret_expires_at: now + 3599,
						},
					},
				}),
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/client_secret_expires_at/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if nested response client_secret is not a string", async (t) => {
			const result = await explicitRegistrationWithResponse(
				explicitRegistrationResponseBase({
					metadata: {
						openid_relying_party: {
							client_id: LEAF_ID,
							client_secret: 123,
						},
					},
				}),
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/client_secret/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if response credential timestamps are invalid", async (t) => {
			const result = await explicitRegistrationWithResponse(
				explicitRegistrationResponseBase({
					metadata: {
						openid_relying_party: {
							client_id: LEAF_ID,
							client_id_issued_at: -1,
						},
					},
				}),
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/invalid/i.test(result.error.description), result.error.description);
			}
		});

		test("fails if response uses top-level client_secret", async (t) => {
			const result = await explicitRegistrationWithResponse(
				explicitRegistrationResponseBase({ client_secret: "super-secret-123" }),
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(/client_secret/i.test(result.error.description), result.error.description);
			}
		});
	});

	// -------------------------------------------------------------------------
	// registration/process-automatic
	// -------------------------------------------------------------------------
	module("oidc / processAutomaticRegistration", () => {
		const replayStore = () => new MemoryReplayStore();

		async function createValidRequestObject(
			fed: Awaited<ReturnType<typeof createMockFederation>>,
			extraHeaders?: Record<string, unknown>,
		) {
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
				new JwkSigner(fed.leafProtocolSigningKey),
				{
					typ: RequestObjectTyp,
					...(extraHeaders ? { extraHeaders } : {}),
				},
			);
		}

		test("returns err when trust anchors are empty", async (t) => {
			const result = await processAutomaticRegistration("not-a-request-object", new Map(), {
				opEntityId: OP_ID,
				replayStore: replayStore(),
			});
			t.false(result.ok);
			if (result.ok) return;
			t.equal(result.error.code, FederationErrorCode.InvalidTrustChain);
			t.ok(result.error.description.includes("Trust Anchor"));
		});

		test("returns err when trust anchor IDs are invalid", async (t) => {
			const result = await processAutomaticRegistration(
				"not-a-request-object",
				new Map([["http://ta.example.com", { jwks: { keys: [] } }]]),
				{
					opEntityId: OP_ID,
					replayStore: replayStore(),
				},
			);
			t.false(result.ok);
			if (result.ok) return;
			t.equal(result.error.code, FederationErrorCode.InvalidTrustChain);
			t.ok(/Invalid Trust Anchor entity ID/.test(result.error.description));
		});

		test("returns ok for valid Request Object", async (t) => {
			const fed = await createMockFederation();
			const result = await processAutomaticRegistration(
				await createValidRequestObject(fed),
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID, replayStore: replayStore() },
			);
			t.true(result.ok);
			if (!result.ok) return;
			t.equal(result.value.rpEntityId, LEAF_ID);
		});

		test("returns err when RP entity metadata includes registration response fields", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const leafEcJwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					sub: LEAF_ID,
					iat: now,
					exp: now + 86400,
					jwks: { keys: [fed.leafPublicKey] },
					authority_hints: [TA_ID],
					metadata: {
						openid_relying_party: {
							redirect_uris: ["https://rp.example.com/callback"],
							response_types: ["code"],
							jwks: { keys: [fed.leafProtocolPublicKey] },
							client_id: "client-123",
						},
					},
				},
				new JwkSigner(fed.leafSigningKey),
				{ typ: JwtTyp.EntityStatement },
			);
			const jwt = await createValidRequestObject(fed, {
				trust_chain: [leafEcJwt, fed.taSubStatementForLeaf, fed.taEcJwt],
			});
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				replayStore: replayStore(),
			});
			t.false(result.ok);
			if (result.ok) return;
			t.equal(result.error.code, FederationErrorCode.InvalidMetadata);
			t.ok(result.error.description.includes("Relying Party metadata"));
		});

		test("uses valid trust_chain header without discovery fetch", async (t) => {
			const fed = await createMockFederation();
			const httpClient: HttpClient = async () => {
				throw new Error("discovery fetch should not run for supplied trust_chain");
			};
			const jwt = await createValidRequestObject(fed, {
				trust_chain: [fed.leafEcJwt, fed.taSubStatementForLeaf, fed.taEcJwt],
			});
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				httpClient,
				opEntityId: OP_ID,
				replayStore: replayStore(),
			});
			t.true(result.ok);
			if (!result.ok) return;
			t.equal(result.value.trustChain.trustAnchorId, TA_ID);
		});

		test("rejects invalid trust_chain header instead of falling back to discovery", async (t) => {
			const fed = await createMockFederation();
			const jwt = await createValidRequestObject(fed, { trust_chain: [fed.leafEcJwt] });
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				replayStore: replayStore(),
			});
			t.false(result.ok);
			if (result.ok) return;
			t.equal(result.error.code, FederationErrorCode.InvalidTrustChain);
			t.ok(result.error.description.includes("trust_chain validation failed"));
		});

		test("verifies Request Objects with RP protocol keys, not federation keys", async (t) => {
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
				new JwkSigner(fed.leafSigningKey),
				{ typ: RequestObjectTyp },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				replayStore: replayStore(),
			});
			t.false(result.ok);
			if (result.ok) return;
			t.equal(result.error.code, "ERR_SIGNATURE_INVALID");
		});

		test("does not consume a JTI before Request Object signature validation", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const jwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					client_id: LEAF_ID,
					aud: OP_ID,
					jti: "must-not-be-consumed",
					iat: now,
					exp: now + 300,
				},
				new JwkSigner(fed.leafSigningKey),
				{ typ: RequestObjectTyp },
			);
			let claims = 0;
			const store: ReplayStore = {
				async useJti() {
					claims += 1;
					return true;
				},
			};
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				replayStore: store,
			});
			t.false(result.ok);
			t.equal(claims, 0);
		});

		test("returns ok with resolvedRpMetadata", async (t) => {
			const fed = await createMockFederation();
			const result = await processAutomaticRegistration(
				await createValidRequestObject(fed),
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID, replayStore: replayStore() },
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
				{ ...fed.options, opEntityId: OP_ID, replayStore: replayStore() },
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
				new JwkSigner(fed.leafProtocolSigningKey),
				{ typ: JwtTyp.EntityStatement },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				replayStore: replayStore(),
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
				new JwkSigner(fed.leafProtocolSigningKey),
				{ typ: "oauth-authz-req+jwt" },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				replayStore: replayStore(),
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
				new JwkSigner(fed.leafProtocolSigningKey),
				{ typ: "oauth-authz-req+jwt" },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				replayStore: replayStore(),
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
				new JwkSigner(fed.leafProtocolSigningKey),
				{ typ: "oauth-authz-req+jwt" },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				replayStore: replayStore(),
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
				new JwkSigner(fed.leafProtocolSigningKey),
				{ typ: "oauth-authz-req+jwt" },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				replayStore: replayStore(),
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
				new JwkSigner(fed.leafProtocolSigningKey),
				{ typ: "oauth-authz-req+jwt" },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				replayStore: replayStore(),
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
				new JwkSigner(fed.leafProtocolSigningKey),
				{ typ: "oauth-authz-req+jwt" },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				replayStore: replayStore(),
			});
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("jti"));
		});

		test("HIGH-1: detects replay via replay store", async (t) => {
			const fed = await createMockFederation();
			const store = replayStore();
			const jwt = await createValidRequestObject(fed);
			const result1 = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				replayStore: store,
			});
			t.true(result1.ok);
			const result2 = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				replayStore: store,
			});
			t.false(result2.ok);
			if (result2.ok) return;
			t.ok(result2.error.description.includes("replay"));
		});

		test("returns server_error when replay storage is unavailable", async (t) => {
			const fed = await createMockFederation();
			const result = await processAutomaticRegistration(
				await createValidRequestObject(fed),
				fed.trustAnchors,
				{
					...fed.options,
					opEntityId: OP_ID,
					replayStore: {
						async useJti() {
							throw new Error("database unavailable");
						},
					},
				},
			);
			t.false(result.ok);
			if (result.ok) return;
			t.equal(result.error.code, FederationErrorCode.ServerError);
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
				new JwkSigner(fed.leafProtocolSigningKey),
				{ typ: "oauth-authz-req+jwt" },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				replayStore: replayStore(),
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
				new JwkSigner(privateKey),
				{ typ: "oauth-authz-req+jwt" },
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				replayStore: replayStore(),
			});
			t.false(result.ok);
		});

		test("returns err during trust-chain validation if RP EC has no federation jwks", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const badLeafEcPayload = {
				iss: LEAF_ID,
				sub: LEAF_ID,
				iat: now,
				exp: now + 86400,
				authority_hints: [TA_ID],
				metadata: {
					openid_relying_party: {
						redirect_uris: ["https://rp.example.com/callback"],
						response_types: ["code"],
						client_registration_types: ["automatic"],
						jwks: { keys: [fed.leafProtocolPublicKey] },
					},
				},
			};
			const badLeafEcJwt = await signEntityStatement(
				badLeafEcPayload,
				new JwkSigner(fed.leafSigningKey),
				{ typ: JwtTyp.EntityStatement },
			);
			const httpClient: HttpClient = async (input, init) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				const parsed = new URL(url);
				if (parsed.pathname === "/.well-known/openid-federation" && parsed.origin === LEAF_ID) {
					return new Response(badLeafEcJwt, {
						status: 200,
						headers: { "Content-Type": "application/entity-statement+jwt" },
					});
				}
				return fed.httpClient(input, init);
			};
			const result = await processAutomaticRegistration(
				await createValidRequestObject(fed),
				fed.trustAnchors,
				{ ...fed.options, httpClient, opEntityId: OP_ID, replayStore: replayStore() },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.equal(result.error.code, FederationErrorCode.InvalidTrustChain);
			t.ok(result.error.description.includes("No valid trust chains found for RP"));
		});

		test("returns err if RP metadata does not comply with schema", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const badLeafEcPayload = {
				iss: LEAF_ID,
				sub: LEAF_ID,
				iat: now,
				exp: now + 86400,
				jwks: { keys: [fed.leafPublicKey] },
				authority_hints: [TA_ID],
				metadata: {
					openid_relying_party: {
						redirect_uris: "not-an-array-of-uris",
						response_types: ["code"],
						client_registration_types: ["automatic"],
						jwks: { keys: [fed.leafProtocolPublicKey] },
					},
				},
			};
			const badLeafEcJwt = await signEntityStatement(
				badLeafEcPayload,
				new JwkSigner(fed.leafSigningKey),
				{ typ: JwtTyp.EntityStatement },
			);
			const httpClient: HttpClient = async (input, init) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				const parsed = new URL(url);
				if (parsed.pathname === "/.well-known/openid-federation" && parsed.origin === LEAF_ID) {
					return new Response(badLeafEcJwt, {
						status: 200,
						headers: { "Content-Type": "application/entity-statement+jwt" },
					});
				}
				return fed.httpClient(input, init);
			};
			const result = await processAutomaticRegistration(
				await createValidRequestObject(fed),
				fed.trustAnchors,
				{ ...fed.options, httpClient, opEntityId: OP_ID, replayStore: replayStore() },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(
				result.error.description.includes("Relying Party metadata schema"),
				result.error.description,
			);
		});

		test("returns err if peer_trust_chain header fails validation", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const invalidOpEcJwt = await signEntityStatement(
				{
					iss: OP_ID,
					sub: OP_ID,
					iat: now,
					exp: now + 86400,
					jwks: { keys: [fed.opPublicKey] },
					metadata: {},
				},
				new JwkSigner(fed.leafSigningKey),
				{ typ: JwtTyp.EntityStatement },
			);
			const jwt = await signEntityStatement(
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
				new JwkSigner(fed.leafProtocolSigningKey),
				{
					typ: "oauth-authz-req+jwt",
					extraHeaders: {
						trust_chain: [fed.leafEcJwt, fed.taSubStatementForLeaf, fed.taEcJwt],
						peer_trust_chain: [invalidOpEcJwt, fed.taSubStatementForOp, fed.taEcJwt],
					},
				},
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				replayStore: replayStore(),
			});
			t.false(result.ok);
			if (result.ok) return;
			t.ok(
				result.error.description.includes("peer_trust_chain validation failed"),
				result.error.description,
			);
		});

		test("succeeds with valid peer_trust_chain header", async (t) => {
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
					redirect_uri: "https://rp.example.com/callback",
					scope: "openid",
					response_type: "code",
				},
				new JwkSigner(fed.leafProtocolSigningKey),
				{
					typ: "oauth-authz-req+jwt",
					extraHeaders: {
						trust_chain: [fed.leafEcJwt, fed.taSubStatementForLeaf, fed.taEcJwt],
						peer_trust_chain: [fed.opEcJwt, fed.taSubStatementForOp, fed.taEcJwt],
					},
				},
			);
			const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				replayStore: replayStore(),
			});
			t.true(result.ok);
		});

		test("rejects peer_trust_chain whose Trust Anchor differs from selected RP chain", async (t) => {
			const fed = await createMockFederation();
			const { privateKey: otherTaKey, publicKey: otherTaPublicKey } =
				await generateSigningKey("ES256");
			const otherTaId = entityId("https://other-ta.example.com");
			const now = Math.floor(Date.now() / 1000);
			const otherOpEcJwt = await signEntityStatement(
				{
					iss: OP_ID,
					sub: OP_ID,
					iat: now,
					exp: now + 86400,
					jwks: { keys: [fed.opPublicKey] },
					authority_hints: [otherTaId],
					metadata: {
						openid_provider: {
							issuer: OP_ID,
							authorization_endpoint: `${OP_ID}/authorize`,
							token_endpoint: `${OP_ID}/token`,
							response_types_supported: ["code"],
							subject_types_supported: ["public"],
						},
					},
				},
				new JwkSigner(fed.opSigningKey),
				{ typ: JwtTyp.EntityStatement },
			);
			const otherTaSubStatementForOp = await signEntityStatement(
				{
					iss: otherTaId,
					sub: OP_ID,
					iat: now,
					exp: now + 86400,
					jwks: { keys: [fed.opPublicKey] },
				},
				new JwkSigner(otherTaKey),
				{ typ: JwtTyp.EntityStatement },
			);
			const otherTaEcJwt = await signEntityStatement(
				{
					iss: otherTaId,
					sub: otherTaId,
					iat: now,
					exp: now + 86400,
					jwks: { keys: [otherTaPublicKey] },
				},
				new JwkSigner(otherTaKey),
				{ typ: JwtTyp.EntityStatement },
			);
			const trustAnchors = new Map(fed.trustAnchors);
			trustAnchors.set(otherTaId, { jwks: { keys: [otherTaPublicKey] } });
			const jwt = await createValidRequestObject(fed, {
				peer_trust_chain: [otherOpEcJwt, otherTaSubStatementForOp, otherTaEcJwt],
			});
			const result = await processAutomaticRegistration(jwt, trustAnchors, {
				...fed.options,
				opEntityId: OP_ID,
				replayStore: replayStore(),
			});
			t.false(result.ok);
			if (result.ok) return;
			t.equal(result.error.code, FederationErrorCode.InvalidTrustChain);
			t.ok(result.error.description.includes("does not match selected RP Trust Anchor"));
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
				new JwkSigner(fed.leafSigningKey),
				signOpts(fed.leafSigningKey),
			);
		}

		test("returns err when trust anchors are empty", async (t) => {
			const result = await processExplicitRegistration(
				"not-an-entity-statement",
				MediaType.EntityStatement,
				new Map(),
				{ opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.equal(result.error.code, FederationErrorCode.InvalidTrustChain);
			t.ok(result.error.description.includes("Trust Anchor"));
		});

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

		test("returns err when explicit request RP metadata includes registration response fields", async (t) => {
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
					metadata: {
						openid_relying_party: {
							redirect_uris: ["https://rp.example.com/callback"],
							client_secret: "response-secret",
						},
					},
				},
				new JwkSigner(fed.leafSigningKey),
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
			t.equal(result.error.code, FederationErrorCode.InvalidMetadata);
			t.ok(result.error.description.includes("Relying Party metadata"));
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
				new JwkSigner(fed.leafSigningKey),
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
				new JwkSigner(fed.leafSigningKey),
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

		test("returns err if aud has multiple values", async (t) => {
			const fed = await createMockFederation();
			const now = Math.floor(Date.now() / 1000);
			const ecJwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					sub: LEAF_ID,
					aud: [OP_ID, "https://other-op.example.com"],
					iat: now,
					exp: now + 86400,
					jwks: { keys: [fed.leafPublicKey] },
					authority_hints: [TA_ID],
					metadata: {},
				},
				new JwkSigner(fed.leafSigningKey),
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
				new JwkSigner(wrongKey),
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

		test("uses valid trust_chain header without discovery fetch", async (t) => {
			const fed = await createMockFederation();
			const httpClient: HttpClient = async () => {
				throw new Error("discovery fetch should not run for supplied trust_chain");
			};
			const result = await processExplicitRegistration(
				await createValidExplicitRequest(fed),
				MediaType.EntityStatement,
				fed.trustAnchors,
				{
					...fed.options,
					httpClient,
					opEntityId: OP_ID,
					trustChainHeader: [fed.leafEcJwt, fed.taSubStatementForLeaf, fed.taEcJwt],
				},
			);
			t.true(result.ok);
			if (!result.ok) return;
			t.equal(result.value.trustChain.trustAnchorId, TA_ID);
		});

		test("rejects invalid trust_chain header instead of falling back to discovery", async (t) => {
			const fed = await createMockFederation();
			const result = await processExplicitRegistration(
				await createValidExplicitRequest(fed),
				MediaType.EntityStatement,
				fed.trustAnchors,
				{
					...fed.options,
					opEntityId: OP_ID,
					trustChainHeader: [fed.leafEcJwt],
				},
			);
			t.false(result.ok);
			if (result.ok) return;
			t.equal(result.error.code, FederationErrorCode.InvalidTrustChain);
			t.ok(result.error.description.includes("trust_chain validation failed"));
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
				new JwkSigner(fed.leafSigningKey),
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
				new JwkSigner(fed.leafSigningKey),
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
			const httpClient: HttpClient = async () => {
				throw new Error("discovery fetch should not run for supplied trust-chain+json");
			};
			const result = await processExplicitRegistration(
				JSON.stringify([ecJwt, fed.taSubStatementForLeaf, fed.taEcJwt]),
				MediaType.TrustChain,
				fed.trustAnchors,
				{ ...fed.options, httpClient, opEntityId: OP_ID },
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

		test("returns err for trust-chain+json body that is not an array", async (t) => {
			const fed = await createMockFederation();
			for (const requestBody of ["{}", JSON.stringify("jwt")]) {
				const result = await processExplicitRegistration(
					requestBody,
					MediaType.TrustChain,
					fed.trustAnchors,
					{ ...fed.options, opEntityId: OP_ID },
				);
				t.false(result.ok);
				if (result.ok) continue;
				t.ok(result.error.description.includes("non-empty array"));
			}
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

		test("returns err for trust-chain+json with non-string array members", async (t) => {
			const fed = await createMockFederation();
			const result = await processExplicitRegistration(
				JSON.stringify([{}]),
				MediaType.TrustChain,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("non-empty array"));
		});

		test("rejects one-entry trust-chain+json body instead of falling back to discovery", async (t) => {
			const fed = await createMockFederation();
			const ecJwt = await createValidExplicitRequest(fed);
			const result = await processExplicitRegistration(
				JSON.stringify([ecJwt]),
				MediaType.TrustChain,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.equal(result.error.code, FederationErrorCode.InvalidTrustChain);
			t.ok(result.error.description.includes("trust-chain+json validation failed"));
		});

		test("rejects malformed trust-chain+json body instead of falling back to discovery", async (t) => {
			const fed = await createMockFederation();
			const ecJwt = await createValidExplicitRequest(fed);
			const result = await processExplicitRegistration(
				JSON.stringify([ecJwt, fed.taEcJwt]),
				MediaType.TrustChain,
				fed.trustAnchors,
				{ ...fed.options, opEntityId: OP_ID },
			);
			t.false(result.ok);
			if (result.ok) return;
			t.equal(result.error.code, FederationErrorCode.InvalidTrustChain);
			t.ok(result.error.description.includes("trust-chain+json validation failed"));
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
				new JwkSigner(privateKey),
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
				new JwkSigner(fed.leafSigningKey),
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
				new JwkSigner(fed.leafSigningKey),
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
				new JwkSigner(fed.leafSigningKey),
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
				new JwkSigner(fed.leafSigningKey),
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
				new JwkSigner(fed.leafSigningKey),
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
				new JwkSigner(fed.leafSigningKey),
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
				new JwkSigner(fed.leafSigningKey),
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
			return signEntityStatement(payload, new JwkSigner(signingKey), {
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

		test("rejects client_id that is not an Entity Identifier", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const result = validateAutomaticRegistrationRequest(
				await buildRequestObject(privateKey, {
					payloadOverrides: { iss: "relative-client", client_id: "relative-client" },
				}),
				ctx,
			);
			t.false(result.ok);
			if (result.ok) return;
			t.ok(result.error.description.includes("Entity Identifier"));
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

		test("does not normalize aud or client_id before comparison", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const precomposedOpId = entityId("https://op.example.com/caf\u00e9");
			const decomposedOpId = entityId("https://op.example.com/cafe\u0301");
			t.notEqual(precomposedOpId, decomposedOpId);
			t.equal(precomposedOpId.normalize("NFC"), decomposedOpId.normalize("NFC"));
			const wrongAud = validateAutomaticRegistrationRequest(
				await buildRequestObject(privateKey, {
					payloadOverrides: { aud: precomposedOpId },
				}),
				{ opEntityId: decomposedOpId },
			);
			t.false(wrongAud.ok);
			if (!wrongAud.ok) {
				t.ok(wrongAud.error.description.includes("aud"));
			}
			const precomposedRpId = "https://rp.example.com/caf\u00e9";
			const decomposedRpId = "https://rp.example.com/cafe\u0301";
			t.notEqual(precomposedRpId, decomposedRpId);
			t.equal(precomposedRpId.normalize("NFC"), decomposedRpId.normalize("NFC"));
			const wrongClientId = validateAutomaticRegistrationRequest(
				await buildRequestObject(privateKey, {
					payloadOverrides: { iss: precomposedRpId, client_id: decomposedRpId },
				}),
				ctx,
			);
			t.false(wrongClientId.ok);
			if (!wrongClientId.ok) {
				t.ok(wrongClientId.error.description.includes("client_id"));
			}
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

		test("uses the context clock for expiry validation", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const result = validateAutomaticRegistrationRequest(
				await buildRequestObject(privateKey, {
					payloadOverrides: { iat: 1_000, exp: 1_100 },
				}),
				{ ...ctx, clock: { now: () => 1_050 }, clockSkewSeconds: 0 },
			);
			t.true(result.ok);
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
				new JwkSigner(otherKey),
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
				new JwkSigner(privateKey),
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
				new JwkSigner(rpKey),
				{ typ: JwtTyp.EntityStatement },
			);
			const opEc = await signEntityStatement(
				{ iss: opId, sub: opId, iat: now, exp, jwks: { keys: [opPub] } },
				new JwkSigner(opKey),
				{ typ: JwtTyp.EntityStatement },
			);
			const taEc = await signEntityStatement(
				{ iss: taId, sub: taId, iat: now, exp, jwks: { keys: [taPub] } },
				new JwkSigner(taKey),
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
				new JwkSigner(strangerKey),
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
				new JwkSigner(otherTaKey),
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
				keyProvider: new MemoryFederationKeyProvider(createFederationSigningKey(opSigningKey)),
				trustAnchors: new Map([[TA_ID, { jwks: { keys: [] } }]]),
			};
			return { ...baseConfig, ...overrides };
		}

		async function createFederatedHandlerFixture(overrides?: HandlerConfigOverrides) {
			const fed = await createMockFederation();
			const config = await createHandlerConfig({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
				...overrides,
			});
			return { config, fed };
		}

		async function buildRegistrationRequest(
			rpEntityId: string,
			opEntityId: string,
			rpPrivateKey: JWK,
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
				new JwkSigner(rpPrivateKey),
				{ typ: JwtTyp.EntityStatement },
			);
		}

		module("oidc / createExplicitRegistrationHandler", () => {
			test("requires non-empty trust anchors when constructed", async (t) => {
				const missingTrustAnchors = await createHandlerConfig({ trustAnchors: undefined });
				t.throws(() => createExplicitRegistrationHandler(missingTrustAnchors), /Trust Anchor/);

				const emptyTrustAnchors = await createHandlerConfig({ trustAnchors: new Map() });
				t.throws(() => createExplicitRegistrationHandler(emptyTrustAnchors), /Trust Anchor/);
			});

			test("accepts a valid explicit registration request", async (t) => {
				const { config } = await createFederatedHandlerFixture();
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
				t.equal(res.headers.get("Content-Type"), OIDC_MEDIA_TYPE_EXPLICIT_REGISTRATION_RESPONSE);
				const responseJwt = await res.text();
				const decoded = decodeEntityStatement(responseJwt);
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				t.equal(decoded.value.header.typ, OIDC_JWT_TYP_EXPLICIT_REGISTRATION_RESPONSE);
				t.equal(decoded.value.payload.iss, HANDLER_ENTITY_ID);
				t.equal(decoded.value.payload.sub, LEAF_ID);
				const payload = decoded.value.payload as Record<string, unknown>;
				t.equal(payload.aud, LEAF_ID);
				t.equal(payload.trust_anchor, TA_ID);
				t.notEqual(payload.trust_anchor, HANDLER_ENTITY_ID);
				t.ok(payload.authority_hints);
				t.true(Array.isArray(payload.authority_hints));
				t.equal((payload.authority_hints as string[]).length, 1);
			});

			test("rejects request RP metadata with registration response fields", async (t) => {
				const { config, fed } = await createFederatedHandlerFixture();
				const handler = createExplicitRegistrationHandler(config);
				const jwt = await buildRegistrationRequest(
					LEAF_ID,
					HANDLER_ENTITY_ID as string,
					fed.leafSigningKey,
					fed.leafPublicKey as unknown as Record<string, unknown>,
					{
						metadata: {
							openid_relying_party: {
								redirect_uris: ["https://rp.example.com/callback"],
								client_id_issued_at: 1,
							},
						},
					},
				);
				const res = await handler(
					new Request(`${String(HANDLER_ENTITY_ID)}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 400);
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, FederationErrorCode.InvalidMetadata);
			});

			test("response includes metadata with openid_relying_party and client_id", async (t) => {
				const { config } = await createFederatedHandlerFixture();
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
				const meta = (decoded.value.payload as Record<string, unknown>).metadata as Record<
					string,
					Record<string, unknown>
				>;
				t.ok(meta.openid_relying_party);
				t.equal(meta.openid_relying_party!.client_id, LEAF_ID);
			});

			test("response includes OIDC default values", async (t) => {
				const { config } = await createFederatedHandlerFixture();
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

			test("removes registration management fields from response metadata", async (t) => {
				let committedMetadata: Record<string, unknown> | undefined;
				const adapter: RegistrationProtocolAdapter = {
					validateClientMetadata: (metadata) => ({ ok: true, value: metadata }),
					enrichResponseMetadata: (metadata) => ({
						...metadata,
						registration_access_token: "token-123",
						registration_client_uri: `${HANDLER_ENTITY_ID}/registration/client-123`,
					}),
				};
				const { config } = await createFederatedHandlerFixture({
					registrationProtocolAdapter: adapter,
					onRegistration: async (_sub, clientMetadata) => {
						committedMetadata = clientMetadata;
					},
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
				const responseMetadata = (decoded.value.payload as Record<string, unknown>)
					.metadata as Record<string, Record<string, unknown>>;
				const rpMeta = responseMetadata.openid_relying_party as Record<string, unknown>;
				t.false("registration_access_token" in rpMeta);
				t.false("registration_client_uri" in rpMeta);
				t.ok(committedMetadata);
				t.false("registration_access_token" in (committedMetadata ?? {}));
				t.false("registration_client_uri" in (committedMetadata ?? {}));
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

			test("rejects parameterized or substring Content-Type", async (t) => {
				const config = await createHandlerConfig();
				const handler = createExplicitRegistrationHandler(config);
				const cases = [
					`${MediaType.EntityStatement}; charset=utf-8`,
					"text/plain; note=application/entity-statement+jwt",
					`${MediaType.TrustChain}; charset=utf-8`,
				];

				for (const contentType of cases) {
					const res = await handler(
						new Request(`${String(HANDLER_ENTITY_ID)}/federation_registration`, {
							method: "POST",
							headers: { "Content-Type": contentType },
							body: "ignored",
						}),
					);
					t.equal(res.status, 400, contentType);
					const body = (await res.json()) as Record<string, string>;
					t.equal(body.error, FederationErrorCode.InvalidRequest, contentType);
				}
			});

			test("accepts application/trust-chain+json Content-Type", async (t) => {
				const { config, fed } = await createFederatedHandlerFixture({
					options: {
						httpClient: async () => {
							throw new Error("discovery fetch should not run for supplied trust-chain+json");
						},
					},
				});
				const handler = createExplicitRegistrationHandler(config);
				const ecJwt = await buildRegistrationRequest(
					LEAF_ID,
					HANDLER_ENTITY_ID as string,
					fed.leafSigningKey,
					fed.leafPublicKey as unknown as Record<string, unknown>,
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.TrustChain },
						body: JSON.stringify([ecJwt, fed.taSubStatementForLeaf, fed.taEcJwt]),
					}),
				);
				t.equal(res.status, 200);
			});

			test("rejects one-entry application/trust-chain+json body", async (t) => {
				const { config, fed } = await createFederatedHandlerFixture();
				const handler = createExplicitRegistrationHandler(config);
				const ecJwt = await buildRegistrationRequest(
					LEAF_ID,
					HANDLER_ENTITY_ID as string,
					fed.leafSigningKey,
					fed.leafPublicKey as unknown as Record<string, unknown>,
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.TrustChain },
						body: JSON.stringify([ecJwt]),
					}),
				);
				t.equal(res.status, 400);
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, FederationErrorCode.InvalidTrustChain);
			});

			test("rejects application/trust-chain+json body that is not an array", async (t) => {
				const { config } = await createFederatedHandlerFixture();
				const handler = createExplicitRegistrationHandler(config);
				const res = await handler(
					new Request(`${String(HANDLER_ENTITY_ID)}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.TrustChain },
						body: JSON.stringify({ trust_chain: [] }),
					}),
				);
				t.equal(res.status, 400);
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, FederationErrorCode.InvalidRequest);
			});

			test("rejects application/trust-chain+json body with non-string members", async (t) => {
				const { config } = await createFederatedHandlerFixture();
				const handler = createExplicitRegistrationHandler(config);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.TrustChain },
						body: JSON.stringify([{}]),
					}),
				);
				t.equal(res.status, 400);
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, FederationErrorCode.InvalidRequest);
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
				const { config } = await createFederatedHandlerFixture({
					registrationResponseTtlSeconds: 7200,
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
					new JwkSigner(otherKeys.privateKey),
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
					new JwkSigner(rpKeys.privateKey),
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
				const { config } = await createFederatedHandlerFixture({
					registrationProtocolAdapter: rejectingAdapter,
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
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_metadata");
			});

			test("returns server_error when response metadata preparation is invalid", async (t) => {
				const invalidResponseAdapter: RegistrationProtocolAdapter = {
					validateClientMetadata: (raw) => ({ ok: true, value: raw }),
					enrichResponseMetadata: (meta) => ({
						...meta,
						client_id: 123,
					}),
				};
				const { config } = await createFederatedHandlerFixture({
					registrationProtocolAdapter: invalidResponseAdapter,
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
					new Request(`${String(HANDLER_ENTITY_ID)}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 500);
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, FederationErrorCode.ServerError);
				t.false((body.error_description ?? "").includes("client_id"));
			});

			test("does not invalidate registration when adapter validation rejects metadata", async (t) => {
				let invalidated = false;
				const rejectingAdapter: RegistrationProtocolAdapter = {
					validateClientMetadata: () =>
						err(federationError(FederationErrorCode.InvalidMetadata, "Bad RP metadata")),
					enrichResponseMetadata: (meta) => meta,
				};
				const { config } = await createFederatedHandlerFixture({
					registrationProtocolAdapter: rejectingAdapter,
					onRegistrationInvalidation: async () => {
						invalidated = true;
					},
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
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_metadata");
				t.false(invalidated);
			});

			test("succeeds without adapter (federation-only)", async (t) => {
				const { config } = await createFederatedHandlerFixture();
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
					new JwkSigner(rpKeys.privateKey),
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
					new JwkSigner(rpKeys.privateKey),
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

			test("calls onRegistrationInvalidation before onRegistration on success", async (t) => {
				const events: string[] = [];
				const { config } = await createFederatedHandlerFixture({
					onRegistrationInvalidation: async (sub) => {
						events.push(`invalidate:${sub}`);
					},
					onRegistration: async (sub) => {
						events.push(`register:${sub}`);
					},
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
				t.deepEqual(events, [`invalidate:${LEAF_ID}`, `register:${LEAF_ID}`]);
			});

			test("replaces existing registration state on repeated success", async (t) => {
				const events: string[] = [];
				const registrations = new Map<string, Record<string, unknown>>();
				let secretCounter = 0;
				const { config } = await createFederatedHandlerFixture({
					generateClientSecret: async () => `secret-${++secretCounter}`,
					onRegistrationInvalidation: async (sub) => {
						events.push(`invalidate:${sub}`);
						registrations.delete(sub);
					},
					onRegistration: async (sub, clientMetadata, clientSecret) => {
						events.push(`register:${sub}:${clientSecret ?? "public"}`);
						registrations.set(sub, { ...clientMetadata, clientSecret });
					},
				});
				const handler = createExplicitRegistrationHandler(config);
				const rpKeys = await generateSigningKey("ES256");
				for (const suffix of ["one", "two"]) {
					const jwt = await buildRegistrationRequest(
						LEAF_ID,
						HANDLER_ENTITY_ID as string,
						rpKeys.privateKey,
						rpKeys.publicKey as unknown as Record<string, unknown>,
						{
							metadata: {
								openid_relying_party: {
									redirect_uris: [`https://rp.example.com/${suffix}/callback`],
								},
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
					t.equal(res.status, 200, suffix);
				}

				t.deepEqual(events, [
					`invalidate:${LEAF_ID}`,
					`register:${LEAF_ID}:secret-1`,
					`invalidate:${LEAF_ID}`,
					`register:${LEAF_ID}:secret-2`,
				]);
				const current = registrations.get(LEAF_ID);
				t.ok(current);
				t.equal(current?.clientSecret, "secret-2");
				t.deepEqual(current?.redirect_uris, ["https://rp.example.com/two/callback"]);
			});

			test("does not call onRegistration when invalidation hook fails", async (t) => {
				let registered = false;
				const { config } = await createFederatedHandlerFixture({
					onRegistrationInvalidation: async () => {
						throw new Error("secret invalidation failure");
					},
					onRegistration: async () => {
						registered = true;
					},
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
				t.equal(res.status, 500);
				t.false(registered);
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, FederationErrorCode.ServerError);
				t.false((body.error_description ?? "").includes("secret invalidation failure"));
			});

			test("returns sanitized server_error when registration hook fails", async (t) => {
				const { config } = await createFederatedHandlerFixture({
					onRegistration: async () => {
						throw new Error("secret registration failure");
					},
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
				t.equal(res.status, 500);
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, FederationErrorCode.ServerError);
				t.false((body.error_description ?? "").includes("secret registration failure"));
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
					options: {
						httpClient: async () => {
							throw new Error("discovery fetch should not run for supplied trust_chain");
						},
					},
				});
				const handler = createExplicitRegistrationHandler(config);
				const jwt = await signEntityStatement(
					{
						iss: LEAF_ID,
						sub: LEAF_ID,
						aud: HANDLER_ENTITY_ID,
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [fed.leafPublicKey as unknown as Record<string, unknown>] },
						...REQUIRED_FIELDS,
					},
					new JwkSigner(fed.leafSigningKey),
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

			test("rejects invalid trust_chain JWT header instead of falling back to discovery", async (t) => {
				const fed = await createMockFederation();
				const config = await createHandlerConfig({
					trustAnchors: fed.trustAnchors,
					options: fed.options,
				});
				const handler = createExplicitRegistrationHandler(config);
				const jwt = await signEntityStatement(
					{
						iss: LEAF_ID,
						sub: LEAF_ID,
						aud: HANDLER_ENTITY_ID,
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [fed.leafPublicKey as unknown as Record<string, unknown>] },
						...REQUIRED_FIELDS,
					},
					new JwkSigner(fed.leafSigningKey),
					{
						typ: JwtTyp.EntityStatement,
						extraHeaders: { trust_chain: [fed.leafEcJwt] },
					},
				);
				const res = await handler(
					new Request(`${HANDLER_ENTITY_ID}/federation_registration`, {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 400);
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, FederationErrorCode.InvalidTrustChain);
				t.ok(body.error_description?.includes("trust_chain validation failed"));
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
					Record<string, unknown>
				>;
				t.equal(meta.openid_relying_party?.injected, true);
			});

			test("emits client_secret when generateClientSecret hook returns a value", async (t) => {
				const fed = await createMockFederation();
				let capturedClientSecret: string | undefined;
				const config = await createHandlerConfig({
					trustAnchors: fed.trustAnchors,
					options: fed.options,
					generateClientSecret: async () => "secret-abc",
					onRegistration: async (_sub, _metadata, clientSecret) => {
						capturedClientSecret = clientSecret;
					},
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
				const metadata = payload.metadata as Record<string, unknown>;
				const rpMeta = metadata.openid_relying_party as Record<string, unknown>;
				t.equal(payload.client_secret, undefined);
				t.equal(rpMeta.client_secret, "secret-abc");
				t.equal(capturedClientSecret, "secret-abc");
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
				const payload = decoded.value.payload as Record<string, unknown>;
				const metadata = payload.metadata as Record<string, unknown>;
				const rpMeta = metadata.openid_relying_party as Record<string, unknown>;
				t.equal(payload.client_secret, undefined);
				t.equal(rpMeta.client_secret, undefined);
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
					new JwkSigner(rpKeys.privateKey),
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
					new JwkSigner(otherTaKey),
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
					new JwkSigner(rpKeys.privateKey),
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
					new JwkSigner(rogueTaKey),
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
					new JwkSigner(rpKeys.privateKey),
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
					new JwkSigner(foreignTaKey),
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
					new JwkSigner(rpKeys.privateKey),
					{
						typ: JwtTyp.EntityStatement,
						extraHeaders: { peer_trust_chain: [fed.opEcJwt, foreignTaEc] },
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
					new JwkSigner(rpKeys.privateKey),
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

	module("oidc / role composition", () => {
		test("OidcRelyingPartyRole role composition metadata and type", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const protocolKeyProvider = new StaticProtocolSigningKeyProvider({
				requestObjectSigner: new JwkSigner(privateKey),
			});
			const role = new OidcRelyingPartyRole({
				protocolKeyProvider,
				metadata: { client_name: "My OIDC RP" },
			});
			role.initialize({
				entityId: "https://rp.example.com",
				// biome-ignore lint/suspicious/noExplicitAny: test
				keyProvider: {} as any,
			});
			t.equal(role.type, "openid_relying_party");
			t.equal(role.metadata.client_name, "My OIDC RP");
		});

		test("OidcProviderRole role composition metadata and type", async (t) => {
			const role = new OidcProviderRole({
				registrationPath: "/my-reg",
				metadata: { op_name: "My OIDC OP" },
				registrationProtocolAdapter: new OIDCRegistrationAdapter(),
			});
			t.throws(
				() =>
					role.initialize({
						entityId: "https://op.example.com",
						// biome-ignore lint/suspicious/noExplicitAny: test
						keyProvider: {} as any,
					}),
				/Trust Anchor/,
			);
		});

		test("OidcProviderRole role composition works with configured trust anchors", async (t) => {
			const fed = await createMockFederation();
			const trustAnchorConfig = fed.trustAnchors.get(TA_ID);
			t.ok(trustAnchorConfig, "fixture exposes TA config");
			if (!trustAnchorConfig) return;
			const trustAnchors = new Map([[TA_ID as string, trustAnchorConfig]]);
			const role = new OidcProviderRole({
				registrationPath: "/my-reg",
				metadata: { op_name: "My OIDC OP" },
			});
			role.initialize({
				entityId: OP_ID,
				// biome-ignore lint/suspicious/noExplicitAny: test
				keyProvider: {} as any,
				trustAnchors,
				options: fed.options,
			});
			t.equal(role.type, "openid_provider");
			t.equal(role.metadata.op_name, "My OIDC OP");
			t.ok(role.routes?.has("/my-reg"), "routes must map custom registration path");
		});

		test("OAuthClientRole role composition metadata and type", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const protocolKeyProvider = new StaticProtocolSigningKeyProvider({
				requestObjectSigner: new JwkSigner(privateKey),
			});
			const role = new OAuthClientRole({
				protocolKeyProvider,
				metadata: { client_name: "My OAuth Client" },
			});
			role.initialize({
				entityId: "https://rp.example.com",
				// biome-ignore lint/suspicious/noExplicitAny: test
				keyProvider: {} as any,
			});
			t.equal(role.type, "oauth_client");
			t.equal(role.metadata.client_name, "My OAuth Client");
		});

		test("OAuthAuthorizationServerRole role composition metadata and type", async (t) => {
			const role = new OAuthAuthorizationServerRole({
				registrationPath: "/oauth-reg",
				metadata: { auth_server_name: "My AS" },
			});
			t.throws(
				() =>
					role.initialize({
						entityId: "https://op.example.com",
						// biome-ignore lint/suspicious/noExplicitAny: test
						keyProvider: {} as any,
					}),
				/Trust Anchor/,
			);
		});

		test("OAuthAuthorizationServerRole role composition with all config options", async (t) => {
			const fed = await createMockFederation();
			const adapter: RegistrationProtocolAdapter = {
				validateClientMetadata: (metadata) => ({ ok: true, value: metadata }),
				enrichResponseMetadata: (metadata) => metadata,
			};
			const role = new OAuthAuthorizationServerRole({
				registrationPath: "/oauth-reg",
				metadata: { auth_server_name: "My AS" },
				trustAnchors: fed.trustAnchors,
				registrationResponseTtlSeconds: 3600,
				registrationProtocolAdapter: adapter,
				generateClientSecret: async () => "secret",
				onRegistrationInvalidation: async () => {},
			});
			role.initialize({
				entityId: OP_ID,
				// biome-ignore lint/suspicious/noExplicitAny: test
				keyProvider: {} as any,
				options: fed.options,
			});
			t.equal(role.type, "oauth_authorization_server");
			t.equal(role.metadata.auth_server_name, "My AS");
			t.ok(role.routes?.has("/oauth-reg"));
		});

		test("OAuthResourceRole role composition metadata and type", async (t) => {
			const { publicKey } = await generateSigningKey("ES256");
			const jwks = { keys: [publicKey] };
			const role = new OAuthResourceRole({
				metadata: { resource_name: "My Resource" },
				jwks,
			});
			role.initialize({
				entityId: "https://rs.example.com",
				// biome-ignore lint/suspicious/noExplicitAny: test
				keyProvider: {} as any,
			});
			t.equal(role.type, "oauth_resource");
			t.equal(role.metadata.resource_name, "My Resource");
			t.deepEqual(role.metadata.jwks, jwks);
		});

		test("OidcRelyingPartyRole and OAuthClientRole createAuthorizationRequest", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const protocolKeyProvider = new StaticProtocolSigningKeyProvider({
				requestObjectSigner: new JwkSigner(privateKey),
			});
			const role = new OidcRelyingPartyRole({
				protocolKeyProvider,
				metadata: {
					client_name: "My OIDC RP",
					redirect_uris: ["https://rp.example.com/callback"],
					response_types: ["code"],
					client_registration_types: ["automatic"],
					jwks: { keys: [stripPrivateFields(privateKey)] },
				},
			});
			const oauthRole = new OAuthClientRole({
				protocolKeyProvider,
				metadata: {
					client_name: "My OAuth Client",
					redirect_uris: ["https://rp.example.com/callback"],
					response_types: ["code"],
					client_registration_types: ["automatic"],
					jwks: { keys: [stripPrivateFields(privateKey)] },
				},
			});

			const fed = await createMockFederation();
			const discovery = await createMockDiscovery(OP_ID, fed);

			const context = {
				entityId: LEAF_ID,
				// biome-ignore lint/suspicious/noExplicitAny: test
				keyProvider: {} as any,
				options: fed.options,
				authorityHints: [TA_ID],
			};

			role.initialize(context);
			oauthRole.initialize(context);

			const authzParams = {
				redirect_uri: "https://rp.example.com/callback",
				scope: "openid",
				response_type: "code",
			};

			const result1 = await role.createAuthorizationRequest(
				discovery,
				authzParams,
				fed.trustAnchors,
			);
			t.true(isOk(result1));

			const result2 = await oauthRole.createAuthorizationRequest(
				discovery,
				authzParams,
				fed.trustAnchors,
			);
			t.true(isOk(result2));
		});

		test("OidcRelyingPartyRole stops automatic registration when discovery fails", async (t) => {
			const { privateKey, publicKey } = await generateSigningKey("ES256");
			const federationKey = await generateSigningKey("ES256");
			const protocolKeyProvider = new StaticProtocolSigningKeyProvider({
				requestObjectSigner: new JwkSigner(privateKey),
			});
			const role = new OidcRelyingPartyRole({
				protocolKeyProvider,
				metadata: {
					redirect_uris: ["https://rp.example.com/callback"],
					response_types: ["code"],
					client_registration_types: ["automatic"],
					jwks: { keys: [publicKey] },
				},
			});

			const attemptedUrls: string[] = [];
			const httpClient: HttpClient = async (input) => {
				const url =
					typeof input === "string"
						? input
						: input instanceof URL
							? input.toString()
							: (input as Request).url;
				attemptedUrls.push(url);
				return new Response("Not Found", { status: 404 });
			};
			const fed = await createMockFederation();
			role.initialize({
				entityId: LEAF_ID,
				keyProvider: new MemoryFederationKeyProvider(
					createFederationSigningKey(federationKey.privateKey),
				),
				authorityHints: [TA_ID],
				trustAnchors: fed.trustAnchors,
				options: { httpClient },
			});

			const result = await role.automaticallyRegister({
				opEntityId: OP_ID,
				redirect_uri: "https://rp.example.com/callback",
				scope: "openid",
				requestDelivery: "par",
			});
			t.true(isErr(result));
			t.false(attemptedUrls.some((url) => url === `${OP_ID}/request`));
		});
	});
};
