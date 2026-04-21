import {
	decodeEntityStatement,
	type FederationOptions,
	type HttpClient,
	JwtTyp,
	MediaType,
	signEntityStatement,
} from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { explicitRegistration } from "../../src/registration/explicit.js";
import {
	createMockDiscovery,
	createMockFederation,
	createRpConfig,
	LEAF_ID,
	OP_ID,
	TA_ID,
} from "../test-helpers.js";

describe("explicitRegistration (RP-side)", () => {
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
			{
				kid: fed.opSigningKey.kid,
				typ: JwtTyp.ExplicitRegistrationResponse,
			},
		);

		const originalHttpClient = fed.httpClient;
		const httpClient: HttpClient = async (input, init) => {
			const url =
				typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
			const parsed = new URL(url);

			if (parsed.origin === OP_ID && parsed.pathname === "/federation_registration") {
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

	it("POSTs EC JWT to correct endpoint", async () => {
		const mock = await createMockOpWithRegistration();
		let capturedUrl = "";
		let capturedContentType = "";

		const trackingClient: HttpClient = async (input, init) => {
			const url =
				typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
			const parsed = new URL(url);
			if (parsed.pathname === "/federation_registration") {
				capturedUrl = url;
				if (input instanceof Request) {
					capturedContentType = input.headers.get("Content-Type") ?? "";
				}
			}
			return mock.httpClient(input, init);
		};

		await explicitRegistration(mock.discovery, mock.config, mock.trustAnchors, {
			httpClient: trackingClient,
		});

		expect(capturedUrl).toContain("/federation_registration");
		expect(capturedContentType).toBe(MediaType.EntityStatement);
	});

	it("RP EC includes all REQUIRED claims", async () => {
		const mock = await createMockOpWithRegistration();
		let capturedBody = "";

		const trackingClient: HttpClient = async (input, init) => {
			const url =
				typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
			const parsed = new URL(url);
			if (parsed.pathname === "/federation_registration") {
				if (input instanceof Request) {
					capturedBody = await input.clone().text();
				}
			}
			return mock.httpClient(input, init);
		};

		await explicitRegistration(mock.discovery, mock.config, mock.trustAnchors, {
			httpClient: trackingClient,
		});

		const decoded = decodeEntityStatement(capturedBody);
		expect(decoded.ok).toBe(true);
		if (!decoded.ok) return;

		const p = decoded.value.payload as Record<string, unknown>;
		expect(p.iss).toBe(LEAF_ID);
		expect(p.sub).toBe(LEAF_ID);
		expect(typeof p.iat).toBe("number");
		expect(typeof p.exp).toBe("number");
		expect(p.jwks).toBeDefined();
		expect(p.aud).toBe(OP_ID);
		expect(p.authority_hints).toBeDefined();
		expect(p.metadata).toBeDefined();
	});

	it("returns correct clientId and registeredMetadata", async () => {
		const mock = await createMockOpWithRegistration();

		const result = await explicitRegistration(
			mock.discovery,
			mock.config,
			mock.trustAnchors,
			mock.options,
		);

		expect(result.clientId).toBe(LEAF_ID);
		expect(result.registeredMetadata).toBeDefined();
		expect(result.expiresAt).toBeGreaterThan(0);
	});

	it("throws if OP has no federation_registration_endpoint", async () => {
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

		await expect(
			explicitRegistration(discovery, config, fed.trustAnchors, fed.options),
		).rejects.toThrow("federation_registration_endpoint");
	});

	it("response has registrationStatement with correct typ", async () => {
		const mock = await createMockOpWithRegistration();

		const result = await explicitRegistration(
			mock.discovery,
			mock.config,
			mock.trustAnchors,
			mock.options,
		);

		expect(result.registrationStatement.header.typ).toBe(JwtTyp.ExplicitRegistrationResponse);
	});

	it("throws if OP does not advertise explicit registration", async () => {
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

		await expect(
			explicitRegistration(discovery, config, fed.trustAnchors, fed.options),
		).rejects.toThrow("explicit");
	});

	it("CRIT-1: throws if JWKS is missing (cannot verify response)", async () => {
		// This tests that signature verification is mandatory, not optional
		const fed = await createMockFederation();
		const discovery = await createMockDiscovery(OP_ID, fed);

		// Create a response signed with an unknown key
		const { privateKey: unknownKey } = await (await import("@oidfed/core")).generateSigningKey(
			"ES256",
		);
		const now = Math.floor(Date.now() / 1000);

		const badResponseJwt = await signEntityStatement(
			{
				iss: OP_ID,
				sub: LEAF_ID,
				aud: LEAF_ID,
				iat: now,
				exp: now + 86400,
				trust_anchor: TA_ID,
			},
			unknownKey,
			{ kid: unknownKey.kid, typ: JwtTyp.ExplicitRegistrationResponse },
		);

		const httpClient = async (input: string | URL | Request) => {
			const url =
				typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
			const parsed = new URL(url);
			if (parsed.pathname === "/federation_registration") {
				return new Response(badResponseJwt, {
					status: 200,
					headers: { "Content-Type": MediaType.ExplicitRegistrationResponse },
				});
			}
			return fed.httpClient(input);
		};

		const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });

		await expect(
			explicitRegistration(discovery, config, fed.trustAnchors, { httpClient }),
		).rejects.toThrow(/signature|verification/i);
	});

	it("returns trustChainExpiresAt", async () => {
		const mock = await createMockOpWithRegistration();

		const result = await explicitRegistration(
			mock.discovery,
			mock.config,
			mock.trustAnchors,
			mock.options,
		);

		expect(result.trustChainExpiresAt).toBeGreaterThan(0);
		expect(result.trustChainExpiresAt).toBe(mock.discovery.trustChain.expiresAt);
	});

	it("throws if response trust_anchor doesn't match OP chain root", async () => {
		const fed = await createMockFederation();
		const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });
		const discovery = await createMockDiscovery(OP_ID, fed);

		const now = Math.floor(Date.now() / 1000);

		// Response with wrong trust_anchor
		const badResponseJwt = await signEntityStatement(
			{
				iss: OP_ID,
				sub: LEAF_ID,
				aud: LEAF_ID,
				iat: now,
				exp: now + 86400,
				authority_hints: [TA_ID],
				trust_anchor: "https://wrong-ta.example.com",
				metadata: {
					openid_relying_party: { client_id: LEAF_ID },
				},
			},
			fed.opSigningKey,
			{ kid: fed.opSigningKey.kid, typ: JwtTyp.ExplicitRegistrationResponse },
		);

		const httpClient = async (input: string | URL | Request) => {
			const url =
				typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
			const parsed = new URL(url);
			if (parsed.pathname === "/federation_registration") {
				return new Response(badResponseJwt, {
					status: 200,
					headers: { "Content-Type": MediaType.ExplicitRegistrationResponse },
				});
			}
			return fed.httpClient(input);
		};

		await expect(
			explicitRegistration(discovery, config, fed.trustAnchors, { httpClient }),
		).rejects.toThrow(/trust_anchor/i);
	});

	it("does not leak raw OP response body in errors (MED-5)", async () => {
		const fed = await createMockFederation();
		const discovery = await createMockDiscovery(OP_ID, fed);
		const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });

		const httpClient = async (input: string | URL | Request) => {
			const url =
				typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
			const parsed = new URL(url);
			if (parsed.pathname === "/federation_registration") {
				return new Response("SECRET_INTERNAL_ERROR_DETAILS", { status: 500 });
			}
			return fed.httpClient(input);
		};

		try {
			await explicitRegistration(discovery, config, fed.trustAnchors, { httpClient });
			expect.unreachable("should have thrown");
		} catch (e) {
			const msg = (e as Error).message;
			expect(msg).not.toContain("SECRET_INTERNAL_ERROR_DETAILS");
			expect(msg).toContain("500");
		}
	});

	it("throws if OP response is already expired (SEC-3)", async () => {
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
				typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
			const parsed = new URL(url);
			if (parsed.pathname === "/federation_registration") {
				return new Response(expiredResponseJwt, {
					status: 200,
					headers: { "Content-Type": MediaType.ExplicitRegistrationResponse },
				});
			}
			return fed.httpClient(input);
		};

		// Expired JWTs are rejected — either by jose's jwtVerify (signature layer)
		// or by our explicit exp check (defense-in-depth)
		await expect(
			explicitRegistration(discovery, config, fed.trustAnchors, { httpClient }),
		).rejects.toThrow(/expired|signature|verification/i);
	});

	it("throws if OP response is missing exp (SEC-3)", async () => {
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
				typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
			const parsed = new URL(url);
			if (parsed.pathname === "/federation_registration") {
				return new Response(noExpResponseJwt, {
					status: 200,
					headers: { "Content-Type": MediaType.ExplicitRegistrationResponse },
				});
			}
			return fed.httpClient(input);
		};

		await expect(
			explicitRegistration(discovery, config, fed.trustAnchors, { httpClient }),
		).rejects.toThrow(/exp/i);
	});
});
