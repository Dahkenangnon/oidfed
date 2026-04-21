import {
	decodeEntityStatement,
	type EntityId,
	entityId,
	FederationEndpoint,
	generateSigningKey,
	isOk,
	signEntityStatement,
	type TrustAnchorSet,
	WELL_KNOWN_OPENID_FEDERATION,
} from "@oidfed/core";
import { beforeEach, describe, expect, it } from "vitest";
import { type AuthorityConfig, createAuthorityServer } from "../src/server.js";
import {
	MemoryKeyStore,
	MemorySubordinateStore,
	MemoryTrustMarkStore,
} from "../src/storage/memory.js";
import type { SubordinateRecord } from "../src/storage/types.js";

const AUTHORITY_ID = entityId("https://authority.example.com");
const SUB1 = entityId("https://sub1.example.com");
const MARK_TYPE = "https://trust.example.com/mark-a";

function makeRecord(
	id: ReturnType<typeof entityId>,
	overrides?: Partial<SubordinateRecord>,
): SubordinateRecord {
	return {
		entityId: id,
		jwks: { keys: [{ kty: "EC", crv: "P-256", x: "abc", y: "def" }] },
		createdAt: Date.now(),
		updatedAt: Date.now(),
		...overrides,
	};
}

describe("createAuthorityServer", () => {
	let keyStore: MemoryKeyStore;
	let subordinateStore: MemorySubordinateStore;
	let trustMarkStore: MemoryTrustMarkStore;
	let config: AuthorityConfig;

	beforeEach(async () => {
		keyStore = new MemoryKeyStore();
		subordinateStore = new MemorySubordinateStore();
		trustMarkStore = new MemoryTrustMarkStore();

		const { privateKey } = await generateSigningKey("ES256");
		const signingKey = { ...privateKey, kid: "server-key-1" };
		await keyStore.addKey(signingKey);
		await keyStore.activateKey("server-key-1");

		config = {
			entityId: AUTHORITY_ID,

			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${AUTHORITY_ID}/federation_fetch`,
					federation_list_endpoint: `${AUTHORITY_ID}/federation_list`,
				},
			},
			subordinateStore,
			keyStore,
			trustMarkStore,
			trustMarkIssuers: { [MARK_TYPE]: [AUTHORITY_ID] },
		};
	});

	describe("programmatic API", () => {
		it("getEntityConfiguration returns signed JWT", async () => {
			const server = createAuthorityServer(config);
			const jwt = await server.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			expect(isOk(decoded)).toBe(true);
			if (!isOk(decoded)) return;
			expect(decoded.value.payload.iss).toBe(AUTHORITY_ID);
			expect(decoded.value.payload.sub).toBe(AUTHORITY_ID);
		});

		it("getSubordinateStatement returns signed JWT", async () => {
			await subordinateStore.add(makeRecord(SUB1));
			const server = createAuthorityServer(config);
			const jwt = await server.getSubordinateStatement(SUB1);
			const decoded = decodeEntityStatement(jwt);
			expect(isOk(decoded)).toBe(true);
			if (!isOk(decoded)) return;
			expect(decoded.value.payload.iss).toBe(AUTHORITY_ID);
			expect(decoded.value.payload.sub).toBe(SUB1);
		});

		it("getSubordinateStatement throws for unknown entity", async () => {
			const server = createAuthorityServer(config);
			await expect(server.getSubordinateStatement(SUB1)).rejects.toThrow("not found");
		});

		it("listSubordinates returns entity IDs", async () => {
			await subordinateStore.add(makeRecord(SUB1));
			const server = createAuthorityServer(config);
			const list = await server.listSubordinates();
			expect(list).toEqual([SUB1]);
		});

		it("issueTrustMark returns signed JWT", async () => {
			const server = createAuthorityServer(config);
			const jwt = await server.issueTrustMark(SUB1, MARK_TYPE);
			const decoded = decodeEntityStatement(jwt);
			expect(isOk(decoded)).toBe(true);
			if (!isOk(decoded)) return;
			const payload = decoded.value.payload as Record<string, unknown>;
			expect(payload.trust_mark_type).toBe(MARK_TYPE);
			expect(payload.sub).toBe(SUB1);
		});

		it("listTrustMarkedEntities returns entity IDs", async () => {
			const server = createAuthorityServer(config);
			await server.issueTrustMark(SUB1, MARK_TYPE);
			const list = await server.listTrustMarkedEntities(MARK_TYPE);
			expect(list).toContain(SUB1);
		});

		it("getHistoricalKeys returns signed JWT", async () => {
			const server = createAuthorityServer(config);
			const jwt = await server.getHistoricalKeys();
			expect(jwt).toBeTruthy();
			const decoded = decodeEntityStatement(jwt);
			expect(isOk(decoded)).toBe(true);
		});

		it("rotateSigningKey rotates the key", async () => {
			const server = createAuthorityServer(config);
			const { privateKey: newKey } = await generateSigningKey("ES256");
			const key = { ...newKey, kid: "server-key-2" };
			await server.rotateSigningKey(key);

			const signing = await keyStore.getSigningKey();
			expect(signing.key.kid).toBe("server-key-2");
		});
	});

	describe("HTTP handler", () => {
		it("routes to entity configuration", async () => {
			const server = createAuthorityServer(config);
			const handler = server.handler();
			const res = await handler(new Request(`${AUTHORITY_ID}${WELL_KNOWN_OPENID_FEDERATION}`));

			expect(res.status).toBe(200);
			expect(res.headers.get("Content-Type")).toBe("application/entity-statement+jwt");
		});

		it("routes to fetch endpoint", async () => {
			await subordinateStore.add(makeRecord(SUB1));
			const server = createAuthorityServer(config);
			const handler = server.handler();
			const res = await handler(
				new Request(`${AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(SUB1)}`),
			);

			expect(res.status).toBe(200);
		});

		it("routes to list endpoint", async () => {
			const server = createAuthorityServer(config);
			const handler = server.handler();
			const res = await handler(new Request(`${AUTHORITY_ID}${FederationEndpoint.List}`));

			expect(res.status).toBe(200);
			expect(res.headers.get("Content-Type")).toBe("application/json");
		});

		it("routes to historical keys endpoint", async () => {
			const server = createAuthorityServer(config);
			const handler = server.handler();
			const res = await handler(new Request(`${AUTHORITY_ID}${FederationEndpoint.HistoricalKeys}`));

			expect(res.status).toBe(200);
			expect(res.headers.get("Content-Type")).toBe("application/jwk-set+jwt");
		});

		it("routes to trust mark status endpoint", async () => {
			const server = createAuthorityServer(config);
			const handler = server.handler();
			const res = await handler(
				new Request(`${AUTHORITY_ID}${FederationEndpoint.TrustMarkStatus}`, {
					method: "POST",
					headers: { "Content-Type": "application/x-www-form-urlencoded" },
					body: "trust_mark=invalid",
				}),
			);

			expect(res.status).toBe(200);
		});

		it("routes to trust mark list endpoint", async () => {
			const server = createAuthorityServer(config);
			const handler = server.handler();
			const res = await handler(
				new Request(
					`${AUTHORITY_ID}${FederationEndpoint.TrustMarkList}?trust_mark_type=${encodeURIComponent(MARK_TYPE)}`,
				),
			);

			expect(res.status).toBe(200);
		});

		it("routes to trust mark endpoint — returns 404 when no trust mark exists", async () => {
			const server = createAuthorityServer(config);
			const handler = server.handler();
			const res = await handler(
				new Request(
					`${AUTHORITY_ID}${FederationEndpoint.TrustMark}?trust_mark_type=${encodeURIComponent(MARK_TYPE)}&sub=${encodeURIComponent(SUB1)}`,
				),
			);

			expect(res.status).toBe(404);
		});

		it("routes to trust mark endpoint — returns 200 when trust mark exists", async () => {
			const server = createAuthorityServer(config);
			// Pre-issue a trust mark via the server method
			await server.issueTrustMark(SUB1, MARK_TYPE);

			const handler = server.handler();
			const res = await handler(
				new Request(
					`${AUTHORITY_ID}${FederationEndpoint.TrustMark}?trust_mark_type=${encodeURIComponent(MARK_TYPE)}&sub=${encodeURIComponent(SUB1)}`,
				),
			);

			expect(res.status).toBe(200);
		});

		it("routes to resolve endpoint", async () => {
			const server = createAuthorityServer(config);
			const handler = server.handler();
			const res = await handler(
				new Request(`${AUTHORITY_ID}${FederationEndpoint.Resolve}?sub=${encodeURIComponent(SUB1)}`),
			);

			expect(res.status).toBe(400);
		});

		it("strips X-Authenticated-Entity header from incoming requests", async () => {
			await subordinateStore.add(makeRecord(SUB1));
			const server = createAuthorityServer(config);
			const handler = server.handler();
			const res = await handler(
				new Request(`${AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(SUB1)}`, {
					headers: { "X-Authenticated-Entity": "https://spoofed.example.com" },
				}),
			);

			// Should succeed (200) and the spoofed header should not affect processing
			expect(res.status).toBe(200);
		});

		it("returns 404 for unknown paths", async () => {
			const server = createAuthorityServer(config);
			const handler = server.handler();
			const res = await handler(new Request(`${AUTHORITY_ID}/unknown-endpoint`));

			expect(res.status).toBe(404);
			expect(res.headers.get("Cache-Control")).toBe("no-store");
			const body = await res.json();
			expect(body.error).toBe("not_found");
		});

		it("all responses include security headers", async () => {
			const server = createAuthorityServer(config);
			const handler = server.handler();
			const res = await handler(new Request(`${AUTHORITY_ID}${WELL_KNOWN_OPENID_FEDERATION}`));

			expect(res.headers.get("Cache-Control")).toBe("no-store");
			expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
			expect(res.headers.get("Strict-Transport-Security")).toBeTruthy();
		});
	});

	describe("input validation", () => {
		it("rejects non-HTTPS entityId", () => {
			expect(() =>
				createAuthorityServer({
					...config,
					entityId: "http://insecure.example.com" as EntityId,
				}),
			).toThrow("entityId MUST be a valid HTTPS URL");
		});

		it("rejects entityId with query parameter", () => {
			expect(() =>
				createAuthorityServer({
					...config,
					entityId: "https://example.com?foo=bar" as EntityId,
				}),
			).toThrow("entityId MUST be a valid HTTPS URL");
		});

		it("rejects entityId with fragment", () => {
			expect(() =>
				createAuthorityServer({
					...config,
					entityId: "https://example.com#frag" as EntityId,
				}),
			).toThrow("entityId MUST be a valid HTTPS URL");
		});

		it("rejects zero entityConfigurationTtlSeconds", () => {
			expect(() =>
				createAuthorityServer({
					...config,
					entityConfigurationTtlSeconds: 0,
				}),
			).toThrow("entityConfigurationTtlSeconds must be positive");
		});

		it("rejects negative subordinateStatementTtlSeconds", () => {
			expect(() =>
				createAuthorityServer({
					...config,
					subordinateStatementTtlSeconds: -1,
				}),
			).toThrow("subordinateStatementTtlSeconds must be positive");
		});

		it("rejects zero registrationResponseTtlSeconds", () => {
			expect(() =>
				createAuthorityServer({
					...config,
					registrationResponseTtlSeconds: 0,
				}),
			).toThrow("registrationResponseTtlSeconds must be positive");
		});

		it("rejects negative trustMarkTtlSeconds", () => {
			expect(() =>
				createAuthorityServer({
					...config,
					trustMarkTtlSeconds: -5,
				}),
			).toThrow("trustMarkTtlSeconds must be positive");
		});

		it("accepts undefined TTL fields (uses defaults)", () => {
			expect(() => createAuthorityServer(config)).not.toThrow();
		});

		it("accepts positive TTL values", () => {
			expect(() =>
				createAuthorityServer({
					...config,
					entityConfigurationTtlSeconds: 3600,
					subordinateStatementTtlSeconds: 1800,
				}),
			).not.toThrow();
		});
	});

	describe("client authentication wiring", () => {
		const CLIENT_ID = entityId("https://client.example.com");
		const JWT_BEARER_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

		async function setupAuthenticatedServer(authMethods: string[]) {
			const taKeyStore = new MemoryKeyStore();
			const taSubStore = new MemorySubordinateStore();
			const { privateKey: taPrivKey, publicKey: taPubKey } = await generateSigningKey("ES256");
			const taSigningKey = { ...taPrivKey, kid: "ta-key-1" };
			const taPublicKey = { ...taPubKey, kid: "ta-key-1" };
			await taKeyStore.addKey(taSigningKey);
			await taKeyStore.activateKey("ta-key-1");

			const { privateKey: clientPrivKey, publicKey: clientPubKey } =
				await generateSigningKey("ES256");
			const clientSigningKey = { ...clientPrivKey, kid: "client-key-1" };
			const clientPublicKey = { ...clientPubKey, kid: "client-key-1" };

			const trustAnchors: TrustAnchorSet = new Map([
				[AUTHORITY_ID, { jwks: { keys: [taPublicKey] } }],
			]);

			// httpClient that serves entity configurations and subordinate statements
			const httpClient = async (input: string | URL | Request): Promise<Response> => {
				const url =
					typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
				const now = Math.floor(Date.now() / 1000);

				if (url === `${CLIENT_ID}${WELL_KNOWN_OPENID_FEDERATION}`) {
					const jwt = await signEntityStatement(
						{
							iss: CLIENT_ID,
							sub: CLIENT_ID,
							iat: now,
							exp: now + 3600,
							jwks: { keys: [clientPublicKey] },
							authority_hints: [AUTHORITY_ID],
						},
						clientSigningKey,
						{ kid: clientSigningKey.kid },
					);
					return new Response(jwt, {
						status: 200,
						headers: { "Content-Type": "application/entity-statement+jwt" },
					});
				}
				if (url === `${AUTHORITY_ID}${WELL_KNOWN_OPENID_FEDERATION}`) {
					const jwt = await signEntityStatement(
						{
							iss: AUTHORITY_ID,
							sub: AUTHORITY_ID,
							iat: now,
							exp: now + 3600,
							jwks: { keys: [taPublicKey] },
							metadata: {
								federation_entity: {
									federation_fetch_endpoint: `${AUTHORITY_ID}${FederationEndpoint.Fetch}`,
								},
							},
						},
						taSigningKey,
						{ kid: taSigningKey.kid },
					);
					return new Response(jwt, {
						status: 200,
						headers: { "Content-Type": "application/entity-statement+jwt" },
					});
				}
				if (url.startsWith(`${AUTHORITY_ID}${FederationEndpoint.Fetch}`)) {
					const parsedUrl = new URL(url);
					if (parsedUrl.searchParams.get("sub") === CLIENT_ID) {
						const jwt = await signEntityStatement(
							{
								iss: AUTHORITY_ID,
								sub: CLIENT_ID,
								iat: now,
								exp: now + 3600,
								jwks: { keys: [clientPublicKey] },
							},
							taSigningKey,
							{ kid: taSigningKey.kid },
						);
						return new Response(jwt, {
							status: 200,
							headers: { "Content-Type": "application/entity-statement+jwt" },
						});
					}
				}
				return new Response("Not found", { status: 404 });
			};

			await taSubStore.add(makeRecord(SUB1));

			const authConfig: AuthorityConfig = {
				entityId: AUTHORITY_ID,
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${AUTHORITY_ID}${FederationEndpoint.Fetch}`,
						federation_list_endpoint: `${AUTHORITY_ID}${FederationEndpoint.List}`,
						federation_fetch_endpoint_auth_methods: authMethods,
					},
				},
				subordinateStore: taSubStore,
				keyStore: taKeyStore,
				trustAnchors,
				options: { httpClient },
			};

			const createAssertion = async () => {
				const now = Math.floor(Date.now() / 1000);
				return signEntityStatement(
					{
						iss: CLIENT_ID,
						sub: CLIENT_ID,
						aud: AUTHORITY_ID,
						jti: crypto.randomUUID(),
						iat: now,
						exp: now + 60,
					},
					clientSigningKey,
					{ kid: clientSigningKey.kid, typ: "JWT" },
				);
			};

			return { config: authConfig, createAssertion };
		}

		it("server with private_key_jwt rejects unauthenticated GET on fetch", async () => {
			const { config: authConfig } = await setupAuthenticatedServer(["private_key_jwt"]);
			const server = createAuthorityServer(authConfig);
			const handler = server.handler();
			const res = await handler(
				new Request(`${AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(SUB1)}`),
			);
			expect(res.status).toBe(405);
		});

		it("server with private_key_jwt accepts authenticated POST on fetch", async () => {
			const { config: authConfig, createAssertion } = await setupAuthenticatedServer([
				"private_key_jwt",
			]);
			const server = createAuthorityServer(authConfig);
			const handler = server.handler();
			const assertion = await createAssertion();
			const res = await handler(
				new Request(`${AUTHORITY_ID}${FederationEndpoint.Fetch}`, {
					method: "POST",
					headers: { "Content-Type": "application/x-www-form-urlencoded" },
					body: `sub=${encodeURIComponent(SUB1)}&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
				}),
			);
			expect(res.status).toBe(200);
		});

		it("server without auth methods accepts unauthenticated GET", async () => {
			// Use default config (no auth methods set)
			await subordinateStore.add(makeRecord(SUB1));
			const server = createAuthorityServer(config);
			const handler = server.handler();
			const res = await handler(
				new Request(`${AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(SUB1)}`),
			);
			expect(res.status).toBe(200);
		});

		it("server with ['none', 'private_key_jwt'] accepts both unauthenticated GET and authenticated POST", async () => {
			const { config: authConfig, createAssertion } = await setupAuthenticatedServer([
				"none",
				"private_key_jwt",
			]);
			const server = createAuthorityServer(authConfig);
			const handler = server.handler();

			// GET should work without auth
			const getRes = await handler(
				new Request(`${AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(SUB1)}`),
			);
			expect(getRes.status).toBe(200);

			// POST with auth should also work
			const assertion = await createAssertion();
			const postRes = await handler(
				new Request(`${AUTHORITY_ID}${FederationEndpoint.Fetch}`, {
					method: "POST",
					headers: { "Content-Type": "application/x-www-form-urlencoded" },
					body: `sub=${encodeURIComponent(SUB1)}&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
				}),
			);
			expect(postRes.status).toBe(200);
		});
	});
});
