import { describe, expect, it, vi } from "vitest";
import { JwtTyp } from "../../src/constants.js";
import { generateSigningKey } from "../../src/jose/keys.js";
import { signEntityStatement } from "../../src/jose/sign.js";
import type { JWK } from "../../src/schemas/jwk.js";
import { createConcurrencyLimiter, resolveTrustChains } from "../../src/trust-chain/resolve.js";
import type { EntityId, TrustAnchorSet } from "../../src/types.js";

const now = Math.floor(Date.now() / 1000);

async function signEC(entityId: string, privateKey: JWK, overrides?: Record<string, unknown>) {
	return signEntityStatement(
		{
			iss: entityId,
			sub: entityId,
			iat: now,
			exp: now + 3600,
			jwks: { keys: [privateKey] },
			...overrides,
		},
		privateKey,
		{ typ: JwtTyp.EntityStatement },
	);
}

async function signSS(
	issuer: string,
	subject: string,
	privateKey: JWK,
	overrides?: Record<string, unknown>,
) {
	return signEntityStatement(
		{
			iss: issuer,
			sub: subject,
			iat: now,
			exp: now + 3600,
			jwks: { keys: [privateKey] },
			...overrides,
		},
		privateKey,
		{ typ: JwtTyp.EntityStatement },
	);
}

describe("createConcurrencyLimiter", () => {
	it("limits concurrent executions", async () => {
		const limiter = createConcurrencyLimiter(2);
		let active = 0;
		let maxActive = 0;

		const task = async () => {
			active++;
			maxActive = Math.max(maxActive, active);
			await new Promise((r) => setTimeout(r, 50));
			active--;
			return "done";
		};

		const results = await Promise.all([limiter(task), limiter(task), limiter(task), limiter(task)]);

		expect(maxActive).toBeLessThanOrEqual(2);
		expect(results).toEqual(["done", "done", "done", "done"]);
	});

	it("queues excess requests and releases on completion", async () => {
		const limiter = createConcurrencyLimiter(1);
		const order: number[] = [];

		const task = (id: number) => async () => {
			order.push(id);
			await new Promise((r) => setTimeout(r, 10));
			return id;
		};

		const results = await Promise.all([limiter(task(1)), limiter(task(2)), limiter(task(3))]);

		expect(results).toEqual([1, 2, 3]);
		expect(order).toEqual([1, 2, 3]);
	});
});

describe("resolveTrustChains", () => {
	it("resolves single path: leaf → TA", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, {
			jwks: { keys: [taKeys.publicKey] },
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ta.example.com/federation_fetch",
				},
			},
		});
		const leafEc = await signEC("https://leaf.example.com", leafKeys.privateKey, {
			jwks: { keys: [leafKeys.publicKey] },
			authority_hints: ["https://ta.example.com"],
			metadata: {
				federation_entity: { organization_name: "Leaf" },
			},
		});
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			{
				jwks: { keys: [leafKeys.publicKey] },
			},
		);

		const responses: Record<string, string> = {
			"https://leaf.example.com/.well-known/openid-federation": leafEc,
			"https://ta.example.com/.well-known/openid-federation": taEc,
		};
		const fetchResponses: Record<string, string> = {
			"https://ta.example.com/federation_fetch?sub=https%3A%2F%2Fleaf.example.com": ss,
		};

		const mockFetch = vi.fn(async (url: string | URL | Request) => {
			const urlStr = url.toString();
			const body = responses[urlStr] ?? fetchResponses[urlStr];
			if (body) {
				return new Response(body, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			return new Response("Not found", { status: 404 });
		});

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await resolveTrustChains("https://leaf.example.com" as EntityId, taSet, {
			httpClient: mockFetch,
			// TA has a fetch endpoint
		});

		expect(result.chains.length).toBeGreaterThanOrEqual(1);
		expect(result.chains[0]?.entityId).toBe("https://leaf.example.com");
		expect(result.chains[0]?.trustAnchorId).toBe("https://ta.example.com");
		// Chain should be [leafEC, SS, taEC]
		expect(result.chains[0]?.statements).toHaveLength(3);
	});

	it("resolves two paths: leaf → int1 → TA and leaf → int2 → TA", async () => {
		const taKeys = await generateSigningKey("ES256");
		const int1Keys = await generateSigningKey("ES256");
		const int2Keys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, {
			jwks: { keys: [taKeys.publicKey] },
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ta.example.com/federation_fetch",
				},
			},
		});
		const int1Ec = await signEC("https://int1.example.com", int1Keys.privateKey, {
			jwks: { keys: [int1Keys.publicKey] },
			authority_hints: ["https://ta.example.com"],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://int1.example.com/federation_fetch",
				},
			},
		});
		const int2Ec = await signEC("https://int2.example.com", int2Keys.privateKey, {
			jwks: { keys: [int2Keys.publicKey] },
			authority_hints: ["https://ta.example.com"],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://int2.example.com/federation_fetch",
				},
			},
		});
		const leafEc = await signEC("https://leaf.example.com", leafKeys.privateKey, {
			jwks: { keys: [leafKeys.publicKey] },
			authority_hints: ["https://int1.example.com", "https://int2.example.com"],
		});

		const ssInt1Leaf = await signSS(
			"https://int1.example.com",
			"https://leaf.example.com",
			int1Keys.privateKey,
			{
				jwks: { keys: [leafKeys.publicKey] },
			},
		);
		const ssInt2Leaf = await signSS(
			"https://int2.example.com",
			"https://leaf.example.com",
			int2Keys.privateKey,
			{
				jwks: { keys: [leafKeys.publicKey] },
			},
		);
		const ssTaInt1 = await signSS(
			"https://ta.example.com",
			"https://int1.example.com",
			taKeys.privateKey,
			{
				jwks: { keys: [int1Keys.publicKey] },
			},
		);
		const ssTaInt2 = await signSS(
			"https://ta.example.com",
			"https://int2.example.com",
			taKeys.privateKey,
			{
				jwks: { keys: [int2Keys.publicKey] },
			},
		);

		const responses: Record<string, string> = {
			"https://leaf.example.com/.well-known/openid-federation": leafEc,
			"https://int1.example.com/.well-known/openid-federation": int1Ec,
			"https://int2.example.com/.well-known/openid-federation": int2Ec,
			"https://ta.example.com/.well-known/openid-federation": taEc,
			"https://int1.example.com/federation_fetch?sub=https%3A%2F%2Fleaf.example.com": ssInt1Leaf,
			"https://int2.example.com/federation_fetch?sub=https%3A%2F%2Fleaf.example.com": ssInt2Leaf,
			"https://ta.example.com/federation_fetch?sub=https%3A%2F%2Fint1.example.com": ssTaInt1,
			"https://ta.example.com/federation_fetch?sub=https%3A%2F%2Fint2.example.com": ssTaInt2,
		};

		const mockFetch = vi.fn(async (url: string | URL | Request) => {
			const body = responses[url.toString()];
			if (body) {
				return new Response(body, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			return new Response("Not found", { status: 404 });
		});

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await resolveTrustChains("https://leaf.example.com" as EntityId, taSet, {
			httpClient: mockFetch,
		});

		expect(result.chains.length).toBe(2);
	});

	it("detects loop: A → B → A", async () => {
		const aKeys = await generateSigningKey("ES256");
		const bKeys = await generateSigningKey("ES256");

		const aEc = await signEC("https://a.example.com", aKeys.privateKey, {
			jwks: { keys: [aKeys.publicKey] },
			authority_hints: ["https://b.example.com"],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://a.example.com/federation_fetch",
				},
			},
		});
		const bEc = await signEC("https://b.example.com", bKeys.privateKey, {
			jwks: { keys: [bKeys.publicKey] },
			authority_hints: ["https://a.example.com"],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://b.example.com/federation_fetch",
				},
			},
		});

		const ssBA = await signSS("https://b.example.com", "https://a.example.com", bKeys.privateKey, {
			jwks: { keys: [aKeys.publicKey] },
		});
		const ssAB = await signSS("https://a.example.com", "https://b.example.com", aKeys.privateKey, {
			jwks: { keys: [bKeys.publicKey] },
		});

		const responses: Record<string, string> = {
			"https://a.example.com/.well-known/openid-federation": aEc,
			"https://b.example.com/.well-known/openid-federation": bEc,
			"https://b.example.com/federation_fetch?sub=https%3A%2F%2Fa.example.com": ssBA,
			"https://a.example.com/federation_fetch?sub=https%3A%2F%2Fb.example.com": ssAB,
		};

		const mockFetch = vi.fn(async (url: string | URL | Request) => {
			const body = responses[url.toString()];
			if (body) {
				return new Response(body, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			return new Response("Not found", { status: 404 });
		});

		const taSet: TrustAnchorSet = new Map(); // No TA configured

		const result = await resolveTrustChains("https://a.example.com" as EntityId, taSet, {
			httpClient: mockFetch,
			maxChainDepth: 5,
		});

		expect(result.chains).toHaveLength(0);
		expect(result.errors.length).toBeGreaterThan(0);
	});

	it("respects maxChainDepth", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, {
			jwks: { keys: [taKeys.publicKey] },
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ta.example.com/federation_fetch",
				},
			},
		});
		const leafEc = await signEC("https://leaf.example.com", leafKeys.privateKey, {
			jwks: { keys: [leafKeys.publicKey] },
			authority_hints: ["https://ta.example.com"],
		});
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			{
				jwks: { keys: [leafKeys.publicKey] },
			},
		);

		const responses: Record<string, string> = {
			"https://leaf.example.com/.well-known/openid-federation": leafEc,
			"https://ta.example.com/.well-known/openid-federation": taEc,
			"https://ta.example.com/federation_fetch?sub=https%3A%2F%2Fleaf.example.com": ss,
		};

		const mockFetch = vi.fn(async (url: string | URL | Request) => {
			const body = responses[url.toString()];
			if (body) {
				return new Response(body, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			return new Response("Not found", { status: 404 });
		});

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		// maxChainDepth=0 should prevent any resolution beyond leaf
		const result = await resolveTrustChains("https://leaf.example.com" as EntityId, taSet, {
			httpClient: mockFetch,
			maxChainDepth: 0,
		});

		expect(result.chains).toHaveLength(0);
	});

	it("rejects leaf EC where iss/sub don't match entityId", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		// Leaf EC has iss=sub but they differ from requested entityId
		const fakeLeafEc = await signEC("https://imposter.example.com", leafKeys.privateKey, {
			jwks: { keys: [leafKeys.publicKey] },
			authority_hints: ["https://ta.example.com"],
		});

		const mockFetch = vi.fn(async (url: string | URL | Request) => {
			const urlStr = url.toString();
			if (urlStr.includes("leaf.example.com/.well-known")) {
				return new Response(fakeLeafEc, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			return new Response("Not found", { status: 404 });
		});

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await resolveTrustChains("https://leaf.example.com" as EntityId, taSet, {
			httpClient: mockFetch,
		});

		expect(result.chains).toHaveLength(0);
		expect(result.errors.length).toBeGreaterThan(0);
		expect(result.errors[0]?.code).toBe("ERR_TRUST_CHAIN_INVALID");
		expect(result.errors[0]?.description).toContain("identity mismatch");
	});

	it("errors when authority hint entity has no federation_fetch_endpoint", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		// TA EC without federation_fetch_endpoint
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, {
			jwks: { keys: [taKeys.publicKey] },
			// No metadata.federation_entity.federation_fetch_endpoint
		});
		const leafEc = await signEC("https://leaf.example.com", leafKeys.privateKey, {
			jwks: { keys: [leafKeys.publicKey] },
			authority_hints: ["https://ta.example.com"],
		});

		const responses: Record<string, string> = {
			"https://leaf.example.com/.well-known/openid-federation": leafEc,
			"https://ta.example.com/.well-known/openid-federation": taEc,
		};

		const mockFetch = vi.fn(async (url: string | URL | Request) => {
			const body = responses[url.toString()];
			if (body) {
				return new Response(body, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			return new Response("Not found", { status: 404 });
		});

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await resolveTrustChains("https://leaf.example.com" as EntityId, taSet, {
			httpClient: mockFetch,
		});

		expect(result.chains).toHaveLength(0);
		expect(result.errors.length).toBeGreaterThan(0);
		expect(result.errors.some((e) => e.description?.includes("federation_fetch_endpoint"))).toBe(
			true,
		);
	});

	it("handles HTTP failure on one path without aborting others", async () => {
		const taKeys = await generateSigningKey("ES256");
		const intKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, {
			jwks: { keys: [taKeys.publicKey] },
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ta.example.com/federation_fetch",
				},
			},
		});
		const intEc = await signEC("https://int.example.com", intKeys.privateKey, {
			jwks: { keys: [intKeys.publicKey] },
			authority_hints: ["https://ta.example.com"],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://int.example.com/federation_fetch",
				},
			},
		});
		const leafEc = await signEC("https://leaf.example.com", leafKeys.privateKey, {
			jwks: { keys: [leafKeys.publicKey] },
			authority_hints: ["https://broken.example.com", "https://int.example.com"],
		});
		const ssIntLeaf = await signSS(
			"https://int.example.com",
			"https://leaf.example.com",
			intKeys.privateKey,
			{
				jwks: { keys: [leafKeys.publicKey] },
			},
		);
		const ssTaInt = await signSS(
			"https://ta.example.com",
			"https://int.example.com",
			taKeys.privateKey,
			{
				jwks: { keys: [intKeys.publicKey] },
			},
		);

		const responses: Record<string, string> = {
			"https://leaf.example.com/.well-known/openid-federation": leafEc,
			"https://int.example.com/.well-known/openid-federation": intEc,
			"https://ta.example.com/.well-known/openid-federation": taEc,
			"https://int.example.com/federation_fetch?sub=https%3A%2F%2Fleaf.example.com": ssIntLeaf,
			"https://ta.example.com/federation_fetch?sub=https%3A%2F%2Fint.example.com": ssTaInt,
		};

		const mockFetch = vi.fn(async (url: string | URL | Request) => {
			const body = responses[url.toString()];
			if (body) {
				return new Response(body, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			return new Response("Not found", { status: 404 });
		});

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await resolveTrustChains("https://leaf.example.com" as EntityId, taSet, {
			httpClient: mockFetch,
		});

		// One path fails, but the other should succeed
		expect(result.chains.length).toBeGreaterThanOrEqual(1);
		expect(result.errors.length).toBeGreaterThanOrEqual(1);
	});

	it("exhausts fetch budget when maxTotalFetches: 1", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, {
			jwks: { keys: [taKeys.publicKey] },
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ta.example.com/federation_fetch",
				},
			},
		});
		const leafEc = await signEC("https://leaf.example.com", leafKeys.privateKey, {
			jwks: { keys: [leafKeys.publicKey] },
			authority_hints: ["https://ta.example.com"],
		});
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
		);

		const mockFetch = vi.fn(async (input: string | URL | Request) => {
			const url = typeof input === "string" ? input : input.toString();
			if (url.includes(".well-known/openid-federation")) {
				if (url.includes("leaf"))
					return new Response(leafEc, {
						status: 200,
						headers: { "Content-Type": "application/entity-statement+jwt" },
					});
				if (url.includes("ta"))
					return new Response(taEc, {
						status: 200,
						headers: { "Content-Type": "application/entity-statement+jwt" },
					});
			}
			if (url.includes("federation_fetch"))
				return new Response(ss, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			return new Response("Not found", { status: 404 });
		});

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		// maxTotalFetches: 1 means only the leaf EC fetch is allowed; TA EC fetch is blocked
		const result = await resolveTrustChains("https://leaf.example.com" as EntityId, taSet, {
			httpClient: mockFetch,
			maxTotalFetches: 1,
		});

		expect(result.chains).toHaveLength(0);
		expect(result.errors.some((e) => e.description.includes("budget"))).toBe(true);
	});

	it("exhausts fetch budget on subordinate statement fetch when maxTotalFetches: 2", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, {
			jwks: { keys: [taKeys.publicKey] },
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ta.example.com/federation_fetch",
				},
			},
		});
		const leafEc = await signEC("https://leaf.example.com", leafKeys.privateKey, {
			jwks: { keys: [leafKeys.publicKey] },
			authority_hints: ["https://ta.example.com"],
		});
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
		);

		const mockFetch = vi.fn(async (input: string | URL | Request) => {
			const url = typeof input === "string" ? input : input.toString();
			if (url.includes(".well-known/openid-federation")) {
				if (url.includes("leaf"))
					return new Response(leafEc, {
						status: 200,
						headers: { "Content-Type": "application/entity-statement+jwt" },
					});
				if (url.includes("ta"))
					return new Response(taEc, {
						status: 200,
						headers: { "Content-Type": "application/entity-statement+jwt" },
					});
			}
			if (url.includes("federation_fetch"))
				return new Response(ss, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			return new Response("Not found", { status: 404 });
		});

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		// maxTotalFetches: 2 allows leaf EC + TA EC but blocks the subordinate statement fetch
		const result = await resolveTrustChains("https://leaf.example.com" as EntityId, taSet, {
			httpClient: mockFetch,
			maxTotalFetches: 2,
		});

		expect(result.chains).toHaveLength(0);
		expect(result.errors.some((e) => e.description.includes("budget"))).toBe(true);
	});
});
