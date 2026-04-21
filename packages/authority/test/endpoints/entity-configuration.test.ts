import { decodeEntityStatement, entityId, isOk, verifyEntityStatement } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { createEntityConfigurationHandler } from "../../src/endpoints/entity-configuration.js";
import { createTestContext, ENTITY_ID } from "./test-helpers.js";

describe("createEntityConfigurationHandler", () => {
	it("returns a signed JWT with entity-statement+jwt content type", async () => {
		const { ctx } = await createTestContext();
		const handler = createEntityConfigurationHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/.well-known/openid-federation"),
		);

		expect(res.status).toBe(200);
		expect(res.headers.get("Content-Type")).toBe("application/entity-statement+jwt");
	});

	it("includes security headers", async () => {
		const { ctx } = await createTestContext();
		const handler = createEntityConfigurationHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/.well-known/openid-federation"),
		);

		expect(res.headers.get("Cache-Control")).toBe("no-store");
		expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
	});

	it("JWT has iss === sub === entityId", async () => {
		const { ctx } = await createTestContext();
		const handler = createEntityConfigurationHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/.well-known/openid-federation"),
		);

		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		expect(decoded.value.payload.iss).toBe(ENTITY_ID);
		expect(decoded.value.payload.sub).toBe(ENTITY_ID);
	});

	it("JWT contains jwks", async () => {
		const { ctx } = await createTestContext();
		const handler = createEntityConfigurationHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/.well-known/openid-federation"),
		);

		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		expect(payload.jwks).toBeDefined();
		const jwks = payload.jwks as { keys: unknown[] };
		expect(jwks.keys.length).toBeGreaterThan(0);
	});

	it("JWT contains metadata", async () => {
		const { ctx } = await createTestContext();
		const handler = createEntityConfigurationHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/.well-known/openid-federation"),
		);

		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		expect(payload.metadata).toBeDefined();
	});

	it("includes authority_hints for intermediates", async () => {
		const superiorId = entityId("https://ta.example.com");
		const { ctx } = await createTestContext({
			authorityHints: [superiorId],
		});
		const handler = createEntityConfigurationHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/.well-known/openid-federation"),
		);

		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		expect(payload.authority_hints).toEqual([superiorId]);
	});

	it("includes trust_mark_issuers when configured", async () => {
		const issuers = { "https://trust.example.com/mark-a": ["https://issuer.example.com"] };
		const { ctx } = await createTestContext({ trustMarkIssuers: issuers });
		const handler = createEntityConfigurationHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/.well-known/openid-federation"),
		);

		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		expect(payload.trust_mark_issuers).toEqual(issuers);
	});

	it("includes trust_mark_owners when configured", async () => {
		const owners = {
			"https://trust.example.com/mark-a": {
				iss: entityId("https://owner.example.com"),
				sub: entityId("https://delegate.example.com"),
			},
		};
		const { ctx } = await createTestContext({ trustMarkOwners: owners });
		const handler = createEntityConfigurationHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/.well-known/openid-federation"),
		);

		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		expect(payload.trust_mark_owners).toEqual(owners);
	});

	it("uses custom entityConfigurationTtlSeconds for exp", async () => {
		const { ctx } = await createTestContext({ entityConfigurationTtlSeconds: 3600 });
		const handler = createEntityConfigurationHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/.well-known/openid-federation"),
		);

		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		const iat = payload.iat as number;
		const exp = payload.exp as number;
		expect(exp - iat).toBe(3600);
	});

	it("defaults to 86400s TTL when entityConfigurationTtlSeconds is not set", async () => {
		const { ctx } = await createTestContext();
		const handler = createEntityConfigurationHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/.well-known/openid-federation"),
		);

		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		const iat = payload.iat as number;
		const exp = payload.exp as number;
		expect(exp - iat).toBe(86400);
	});

	it("returns 500 when no active keys are available", async () => {
		const { ctx, keyStore } = await createTestContext();
		// Revoke the only active key to simulate empty JWKS
		await keyStore.revokeKey("test-key-1", "test");

		const handler = createEntityConfigurationHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/.well-known/openid-federation"),
		);

		expect(res.status).toBe(500);
	});

	it("returns 405 for POST", async () => {
		const { ctx } = await createTestContext();
		const handler = createEntityConfigurationHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/.well-known/openid-federation", {
				method: "POST",
			}),
		);

		expect(res.status).toBe(405);
		expect(res.headers.get("Allow")).toBe("GET");
	});

	it("JWT can be verified with the active keys", async () => {
		const { ctx } = await createTestContext();
		const handler = createEntityConfigurationHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/.well-known/openid-federation"),
		);

		const jwt = await res.text();
		const activeKeys = await ctx.keyStore.getActiveKeys();
		const result = await verifyEntityStatement(jwt, activeKeys);
		expect(isOk(result)).toBe(true);
	});
});
