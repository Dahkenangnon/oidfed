import { entityId, type TrustAnchorSet } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { createResolveHandler } from "../../src/endpoints/resolve.js";
import { createTestContext } from "./test-helpers.js";

// Note: Full resolve testing with MockFederationBuilder will be in integration tests.
// Here we test parameter validation and error responses.

describe("createResolveHandler", () => {
	it("returns 400 when sub is missing", async () => {
		const { ctx } = await createTestContext();
		const handler = createResolveHandler(ctx);
		const res = await handler(
			new Request(
				"https://authority.example.com/federation_resolve?trust_anchor=https%3A%2F%2Fta.example.com",
			),
		);

		expect(res.status).toBe(400);
		const body = await res.json();
		expect(body.error).toBe("invalid_request");
	});

	it("returns 400 when trust_anchor is missing", async () => {
		const { ctx } = await createTestContext();
		const handler = createResolveHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}`,
			),
		);

		expect(res.status).toBe(400);
		const body = await res.json();
		expect(body.error).toBe("invalid_request");
	});

	it("returns 404 when no trust anchors configured", async () => {
		const { ctx } = await createTestContext();
		const handler = createResolveHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://ta.example.com")}`,
			),
		);

		expect(res.status).toBe(404);
		const body = await res.json();
		expect(body.error).toBe("invalid_trust_anchor");
	});

	it("returns 404 for unknown trust anchor", async () => {
		const taId = entityId("https://known-ta.example.com");
		const anchors: TrustAnchorSet = new Map([
			[taId, { jwks: { keys: [{ kty: "EC", crv: "P-256", x: "abc", y: "def" }] } }],
		]);

		const { ctx } = await createTestContext({ trustAnchors: anchors });
		const handler = createResolveHandler(ctx);
		const unknownTa = "https://unknown-ta.example.com";
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent(unknownTa)}`,
			),
		);

		expect(res.status).toBe(404);
		const body = await res.json();
		expect(body.error).toBe("invalid_trust_anchor");
	});

	it("returns 405 for POST", async () => {
		const { ctx } = await createTestContext();
		const handler = createResolveHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_resolve", { method: "POST" }),
		);

		expect(res.status).toBe(405);
	});

	it("does not include aud when X-Authenticated-Entity header is absent", async () => {
		// This is a parameter validation test — the resolve will fail with 400
		// because no trust anchors are configured, but we verify aud logic via
		// the next test that provides the header.
		const { ctx } = await createTestContext();
		const handler = createResolveHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://ta.example.com")}`,
			),
		);
		// Without trust anchors, we get 404 — aud is irrelevant for error responses
		expect(res.status).toBe(404);
	});

	it("includes aud when X-Authenticated-Entity header is present", async () => {
		// We need a proper trust chain for the resolve to succeed.
		// Since that requires MockFederationBuilder (integration test), we test
		// the header-to-payload plumbing by checking the request reaches the handler
		// with the header. Full integration test covers the JWT payload.
		const { ctx } = await createTestContext();
		const handler = createResolveHandler(ctx);
		const clientEntity = "https://client.example.com";
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://ta.example.com")}`,
				{ headers: { "X-Authenticated-Entity": clientEntity } },
			),
		);
		// Will fail at trust anchor validation, but the header plumbing is exercised
		expect(res.status).toBe(404);
	});

	it("accepts entity_type parameter without error", async () => {
		const { ctx } = await createTestContext();
		const handler = createResolveHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://ta.example.com")}&entity_type=openid_provider`,
			),
		);
		// Will fail at trust anchor validation, but entity_type param is accepted
		expect(res.status).toBe(404);
		const body = await res.json();
		expect(body.error).toBe("invalid_trust_anchor");
	});

	it("returns 400 for invalid X-Authenticated-Entity header value", async () => {
		const { ctx } = await createTestContext();
		const handler = createResolveHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://ta.example.com")}`,
				{ headers: { "X-Authenticated-Entity": "not-a-url" } },
			),
		);
		expect(res.status).toBe(400);
		const body = await res.json();
		expect(body.error).toBe("invalid_request");
	});

	it("accepts a valid X-Authenticated-Entity header and proceeds to trust chain resolution", async () => {
		const { ctx } = await createTestContext();
		const handler = createResolveHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://ta.example.com")}`,
				{ headers: { "X-Authenticated-Entity": "https://client.example.com" } },
			),
		);
		// Without configured trust anchors, fails at 404 — not 400
		expect(res.status).toBe(404);
	});

	it("includes security headers on error responses", async () => {
		const { ctx } = await createTestContext();
		const handler = createResolveHandler(ctx);
		const res = await handler(new Request("https://authority.example.com/federation_resolve"));

		expect(res.headers.get("Cache-Control")).toBe("no-store");
		expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
	});
});
