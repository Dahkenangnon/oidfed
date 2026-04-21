import {
	entityId,
	FederationEndpoint,
	FederationErrorCode,
	generateSigningKey,
	type JWK,
	signEntityStatement,
	type TrustAnchorSet,
	WELL_KNOWN_OPENID_FEDERATION,
} from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { createAuthenticatedHandler } from "../../src/endpoints/client-auth.js";
import type { HandlerContext } from "../../src/endpoints/context.js";
import { jsonResponse } from "../../src/endpoints/helpers.js";
import {
	MemoryKeyStore,
	MemorySubordinateStore,
	MemoryTrustMarkStore,
} from "../../src/storage/memory.js";

const AUTHORITY_ID = entityId("https://authority.example.com");
const CLIENT_ID = entityId("https://client.example.com");
const JWT_BEARER_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

// A simple inner handler that echoes back the `sub` param
async function echoHandler(request: Request): Promise<Response> {
	const url = new URL(request.url);
	const sub = url.searchParams.get("sub");
	return jsonResponse({ sub, method: request.method });
}

// A POST-native inner handler that reads from body
async function postEchoHandler(request: Request): Promise<Response> {
	const text = await request.text();
	const params = new URLSearchParams(text);
	return jsonResponse({ trust_mark: params.get("trust_mark"), method: request.method });
}

async function setupContext(overrides?: Partial<HandlerContext>): Promise<{
	ctx: HandlerContext;
	taSigningKey: JWK;
	taPublicKey: JWK;
	clientSigningKey: JWK;
	clientPublicKey: JWK;
	trustAnchors: TrustAnchorSet;
	createClientAssertionJwt: (overrides?: {
		iss?: string;
		sub?: string;
		aud?: string | string[];
		exp?: number;
	}) => Promise<string>;
	makeHttpClient: () => (input: string | URL | Request) => Promise<Response>;
}> {
	// Generate TA keys
	const taKeys = await generateSigningKey("ES256");
	const taSigningKey = { ...taKeys.privateKey, kid: "ta-key-1" };
	const taPublicKey = { ...taKeys.publicKey, kid: "ta-key-1" };

	// Generate client keys
	const clientKeys = await generateSigningKey("ES256");
	const clientSigningKey = { ...clientKeys.privateKey, kid: "client-key-1" };
	const clientPublicKey = { ...clientKeys.publicKey, kid: "client-key-1" };

	const trustAnchors: TrustAnchorSet = new Map([[AUTHORITY_ID, { jwks: { keys: [taPublicKey] } }]]);

	const keyStore = new MemoryKeyStore();
	await keyStore.addKey(taSigningKey);
	await keyStore.activateKey("ta-key-1");

	const ctx: HandlerContext = {
		entityId: AUTHORITY_ID,
		keyStore,
		subordinateStore: new MemorySubordinateStore(),
		trustMarkStore: new MemoryTrustMarkStore(),
		metadata: {
			federation_entity: {
				federation_fetch_endpoint: `${AUTHORITY_ID}${FederationEndpoint.Fetch}`,
			},
		},
		getSigningKey: async () => ({ key: taSigningKey, kid: "ta-key-1" }),
		trustAnchors,
		...overrides,
	};

	const createClientAssertionJwt = async (assertionOverrides?: {
		iss?: string;
		sub?: string;
		aud?: string | string[];
		exp?: number;
	}): Promise<string> => {
		const now = Math.floor(Date.now() / 1000);
		const payload: Record<string, unknown> = {
			iss: assertionOverrides?.iss ?? CLIENT_ID,
			sub: assertionOverrides?.sub ?? CLIENT_ID,
			aud: assertionOverrides?.aud ?? AUTHORITY_ID,
			jti: crypto.randomUUID(),
			iat: now,
			exp: assertionOverrides?.exp ?? now + 60,
		};
		return signEntityStatement(payload, clientSigningKey, {
			kid: clientSigningKey.kid,
			typ: "JWT",
		});
	};

	// Create an httpClient that serves Entity Configurations and Subordinate Statements
	const makeHttpClient = () => {
		return async (input: string | URL | Request): Promise<Response> => {
			const url =
				typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

			// Client Entity Configuration
			if (url === `${CLIENT_ID}${WELL_KNOWN_OPENID_FEDERATION}`) {
				const now = Math.floor(Date.now() / 1000);
				const ecPayload: Record<string, unknown> = {
					iss: CLIENT_ID,
					sub: CLIENT_ID,
					iat: now,
					exp: now + 3600,
					jwks: { keys: [clientPublicKey] },
					authority_hints: [AUTHORITY_ID],
				};
				const ecJwt = await signEntityStatement(ecPayload, clientSigningKey, {
					kid: clientSigningKey.kid,
				});
				return new Response(ecJwt, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}

			// TA Entity Configuration
			if (url === `${AUTHORITY_ID}${WELL_KNOWN_OPENID_FEDERATION}`) {
				const now = Math.floor(Date.now() / 1000);
				const ecPayload: Record<string, unknown> = {
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
				};
				const ecJwt = await signEntityStatement(ecPayload, taSigningKey, {
					kid: taSigningKey.kid,
				});
				return new Response(ecJwt, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}

			// Subordinate statement fetch (TA fetching client's subordinate statement)
			if (url.startsWith(`${AUTHORITY_ID}${FederationEndpoint.Fetch}`)) {
				const parsedUrl = new URL(url);
				const sub = parsedUrl.searchParams.get("sub");
				if (sub === CLIENT_ID) {
					const now = Math.floor(Date.now() / 1000);
					const ssPayload: Record<string, unknown> = {
						iss: AUTHORITY_ID,
						sub: CLIENT_ID,
						iat: now,
						exp: now + 3600,
						jwks: { keys: [clientPublicKey] },
					};
					const ssJwt = await signEntityStatement(ssPayload, taSigningKey, {
						kid: taSigningKey.kid,
					});
					return new Response(ssJwt, {
						status: 200,
						headers: { "Content-Type": "application/entity-statement+jwt" },
					});
				}
			}

			return new Response("Not found", { status: 404 });
		};
	};

	return {
		ctx,
		taSigningKey,
		taPublicKey,
		clientSigningKey,
		clientPublicKey,
		trustAnchors,
		createClientAssertionJwt,
		makeHttpClient,
	};
}

describe("createAuthenticatedHandler", () => {
	describe("no auth required (passthrough)", () => {
		it("returns inner handler unchanged when authMethods is undefined", async () => {
			const { ctx } = await setupContext();
			const handler = createAuthenticatedHandler(ctx, echoHandler, undefined);
			expect(handler).toBe(echoHandler);
		});

		it("returns inner handler unchanged when authMethods is ['none']", async () => {
			const { ctx } = await setupContext();
			const handler = createAuthenticatedHandler(ctx, echoHandler, ["none"]);
			expect(handler).toBe(echoHandler);
		});

		it("returns inner handler unchanged when authMethods is empty []", async () => {
			const { ctx } = await setupContext();
			const handler = createAuthenticatedHandler(ctx, echoHandler, []);
			expect(handler).toBe(echoHandler);
		});
	});

	describe("private_key_jwt enforcement", () => {
		it("rejects GET when only 'private_key_jwt' configured", async () => {
			const { ctx } = await setupContext();
			const handler = createAuthenticatedHandler(ctx, echoHandler, ["private_key_jwt"]);
			const req = new Request(`${AUTHORITY_ID}/test?sub=test`);
			const res = await handler(req);
			expect(res.status).toBe(405);
		});

		it("accepts GET when both 'none' and 'private_key_jwt' configured", async () => {
			const { ctx } = await setupContext();
			const handler = createAuthenticatedHandler(ctx, echoHandler, ["none", "private_key_jwt"]);
			const req = new Request(`${AUTHORITY_ID}/test?sub=test`);
			const res = await handler(req);
			expect(res.status).toBe(200);
			const body = (await res.json()) as Record<string, unknown>;
			expect(body.sub).toBe("test");
		});

		it("rejects POST without client_assertion", async () => {
			const { ctx } = await setupContext();
			const handler = createAuthenticatedHandler(ctx, echoHandler, ["private_key_jwt"]);
			const req = new Request(`${AUTHORITY_ID}/test`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: "sub=https%3A%2F%2Ffoo.com",
			});
			const res = await handler(req);
			expect(res.status).toBe(401);
			const body = (await res.json()) as Record<string, unknown>;
			expect(body.error).toBe(FederationErrorCode.InvalidClient);
		});

		it("rejects POST with wrong client_assertion_type", async () => {
			const { ctx, createClientAssertionJwt } = await setupContext();
			const handler = createAuthenticatedHandler(ctx, echoHandler, ["private_key_jwt"]);
			const assertion = await createClientAssertionJwt();
			const req = new Request(`${AUTHORITY_ID}/test`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=wrong`,
			});
			const res = await handler(req);
			expect(res.status).toBe(401);
			const body = (await res.json()) as Record<string, unknown>;
			expect(body.error).toBe(FederationErrorCode.InvalidClient);
			expect(body.error_description).toContain("client_assertion_type");
		});

		it("accepts valid POST with correct client_assertion", async () => {
			const { ctx, createClientAssertionJwt, makeHttpClient } = await setupContext();
			const ctxWithHttp: HandlerContext = {
				...ctx,
				options: { httpClient: makeHttpClient() },
			};
			const handler = createAuthenticatedHandler(ctxWithHttp, echoHandler, ["private_key_jwt"]);
			const assertion = await createClientAssertionJwt();
			const req = new Request(`${AUTHORITY_ID}/test`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: `sub=test_value&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
			});
			const res = await handler(req);
			expect(res.status).toBe(200);
			const body = (await res.json()) as Record<string, unknown>;
			expect(body.sub).toBe("test_value");
			expect(body.method).toBe("GET");
		});

		it("forwards endpoint params correctly from POST body", async () => {
			const { ctx, createClientAssertionJwt, makeHttpClient } = await setupContext();
			const ctxWithHttp: HandlerContext = {
				...ctx,
				options: { httpClient: makeHttpClient() },
			};
			const handler = createAuthenticatedHandler(ctxWithHttp, echoHandler, ["private_key_jwt"]);
			const subValue = "https://sub.example.com";
			const assertion = await createClientAssertionJwt();
			const req = new Request(`${AUTHORITY_ID}/test`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: `sub=${encodeURIComponent(subValue)}&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
			});
			const res = await handler(req);
			expect(res.status).toBe(200);
			const body = (await res.json()) as Record<string, unknown>;
			expect(body.sub).toBe(subValue);
		});

		it("rejects POST with expired client_assertion", async () => {
			const { ctx, createClientAssertionJwt, makeHttpClient } = await setupContext();
			const ctxWithHttp: HandlerContext = {
				...ctx,
				options: { httpClient: makeHttpClient(), clockSkewSeconds: 0 },
			};
			const handler = createAuthenticatedHandler(ctxWithHttp, echoHandler, ["private_key_jwt"]);
			const now = Math.floor(Date.now() / 1000);
			const assertion = await createClientAssertionJwt({ exp: now - 120 });
			const req = new Request(`${AUTHORITY_ID}/test`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
			});
			const res = await handler(req);
			expect(res.status).toBe(401);
		});

		it("rejects POST with wrong aud in assertion", async () => {
			const { ctx, createClientAssertionJwt, makeHttpClient } = await setupContext();
			const ctxWithHttp: HandlerContext = {
				...ctx,
				options: { httpClient: makeHttpClient() },
			};
			const handler = createAuthenticatedHandler(ctxWithHttp, echoHandler, ["private_key_jwt"]);
			const assertion = await createClientAssertionJwt({
				aud: "https://wrong.example.com",
			});
			const req = new Request(`${AUTHORITY_ID}/test`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
			});
			const res = await handler(req);
			expect(res.status).toBe(401);
		});

		it("rejects POST when trust chain resolution fails", async () => {
			const { ctx, createClientAssertionJwt } = await setupContext();
			// httpClient that always returns 404 — no trust chain can be built
			const ctxWithBrokenHttp: HandlerContext = {
				...ctx,
				options: {
					httpClient: async () => new Response("Not found", { status: 404 }),
				},
			};
			const handler = createAuthenticatedHandler(ctxWithBrokenHttp, echoHandler, [
				"private_key_jwt",
			]);
			const assertion = await createClientAssertionJwt();
			const req = new Request(`${AUTHORITY_ID}/test`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
			});
			const res = await handler(req);
			expect(res.status).toBe(401);
		});

		it("rejects POST with invalid signature", async () => {
			const { ctx, makeHttpClient } = await setupContext();
			const ctxWithHttp: HandlerContext = {
				...ctx,
				options: { httpClient: makeHttpClient() },
			};
			const handler = createAuthenticatedHandler(ctxWithHttp, echoHandler, ["private_key_jwt"]);
			// Create assertion with a DIFFERENT key (not the client's registered key)
			const otherKeys = await generateSigningKey("ES256");
			const now = Math.floor(Date.now() / 1000);
			const payload: Record<string, unknown> = {
				iss: CLIENT_ID,
				sub: CLIENT_ID,
				aud: AUTHORITY_ID,
				jti: crypto.randomUUID(),
				iat: now,
				exp: now + 60,
			};
			const badAssertion = await signEntityStatement(payload, otherKeys.privateKey, {
				kid: otherKeys.privateKey.kid,
				typ: "JWT",
			});
			const req = new Request(`${AUTHORITY_ID}/test`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: `sub=test&client_assertion=${encodeURIComponent(badAssertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
			});
			const res = await handler(req);
			expect(res.status).toBe(401);
		});

		it("returns 500 when trust anchors not configured", async () => {
			const { ctx, createClientAssertionJwt } = await setupContext();
			// Remove trust anchors from context
			const ctxNoTa: HandlerContext = {
				entityId: ctx.entityId,
				keyStore: ctx.keyStore,
				subordinateStore: ctx.subordinateStore,
				metadata: ctx.metadata,
				getSigningKey: ctx.getSigningKey,
				// no trustAnchors
			};
			const handler = createAuthenticatedHandler(ctxNoTa, echoHandler, ["private_key_jwt"]);
			const assertion = await createClientAssertionJwt();
			const req = new Request(`${AUTHORITY_ID}/test`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
			});
			const res = await handler(req);
			expect(res.status).toBe(500);
		});

		it("iss !== sub in assertion returns 401", async () => {
			const { ctx, createClientAssertionJwt, makeHttpClient } = await setupContext();
			const ctxWithHttp: HandlerContext = {
				...ctx,
				options: { httpClient: makeHttpClient() },
			};
			const handler = createAuthenticatedHandler(ctxWithHttp, echoHandler, ["private_key_jwt"]);
			const assertion = await createClientAssertionJwt({
				iss: CLIENT_ID,
				sub: "https://other.example.com",
			});
			const req = new Request(`${AUTHORITY_ID}/test`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
			});
			const res = await handler(req);
			expect(res.status).toBe(401);
		});
	});

	describe("nativeMethod: POST", () => {
		it("forwards remaining POST body for POST-native endpoints", async () => {
			const { ctx, createClientAssertionJwt, makeHttpClient } = await setupContext();
			const ctxWithHttp: HandlerContext = {
				...ctx,
				options: { httpClient: makeHttpClient() },
			};
			const handler = createAuthenticatedHandler(
				ctxWithHttp,
				postEchoHandler,
				["private_key_jwt"],
				{ nativeMethod: "POST" },
			);
			const assertion = await createClientAssertionJwt();
			const req = new Request(`${AUTHORITY_ID}/test`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: `trust_mark=some_trust_mark_jwt&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
			});
			const res = await handler(req);
			expect(res.status).toBe(200);
			const body = (await res.json()) as Record<string, unknown>;
			expect(body.trust_mark).toBe("some_trust_mark_jwt");
			expect(body.method).toBe("POST");
		});
	});
});
