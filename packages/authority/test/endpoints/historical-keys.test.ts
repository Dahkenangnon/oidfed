import { decodeEntityStatement, generateSigningKey, isOk } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { createHistoricalKeysHandler } from "../../src/endpoints/historical-keys.js";
import { createTestContext } from "./test-helpers.js";

describe("createHistoricalKeysHandler", () => {
	it("returns signed JWT with jwk-set+jwt content type", async () => {
		const { ctx } = await createTestContext();
		const handler = createHistoricalKeysHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_historical_keys"),
		);

		expect(res.status).toBe(200);
		expect(res.headers.get("Content-Type")).toBe("application/jwk-set+jwt");
	});

	it("includes all key states", async () => {
		const { ctx, keyStore } = await createTestContext();

		const { privateKey: pk2 } = await generateSigningKey("ES256");
		await keyStore.addKey({ ...pk2, kid: "pending-key" });

		const { privateKey: pk3 } = await generateSigningKey("ES256");
		await keyStore.addKey({ ...pk3, kid: "retiring-key" });
		await keyStore.activateKey("retiring-key");
		await keyStore.retireKey("retiring-key", Date.now() + 86400000);

		const handler = createHistoricalKeysHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_historical_keys"),
		);
		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		const keys = payload.keys as Array<Record<string, unknown>>;
		expect(keys.length).toBe(3);
	});

	it("revoked keys have revoked metadata", async () => {
		const { ctx, keyStore } = await createTestContext();
		await keyStore.revokeKey("test-key-1", "keyCompromise");

		const { privateKey: pk2 } = await generateSigningKey("ES256");
		await keyStore.addKey({ ...pk2, kid: "new-active" });
		await keyStore.activateKey("new-active");

		const newCtx = {
			...ctx,
			getSigningKey: async () => ({ key: { ...pk2, kid: "new-active" }, kid: "new-active" }),
		};
		const handler = createHistoricalKeysHandler(newCtx);
		const res = await handler(
			new Request("https://authority.example.com/federation_historical_keys"),
		);
		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		const keys = payload.keys as Array<Record<string, unknown>>;
		const revokedKey = keys.find((k) => k.kid === "test-key-1");
		expect(revokedKey).toBeDefined();
		expect(revokedKey?.revoked).toBeDefined();
		const revoked = revokedKey?.revoked as Record<string, unknown>;
		expect(revoked.revoked_at).toBeGreaterThan(0);
		expect(revoked.reason).toBe("keyCompromise");
	});

	it("active keys do not have revoked field", async () => {
		const { ctx } = await createTestContext();
		const handler = createHistoricalKeysHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_historical_keys"),
		);
		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		const keys = payload.keys as Array<Record<string, unknown>>;
		const activeKey = keys.find((k) => k.kid === "test-key-1");
		expect(activeKey).toBeDefined();
		expect(activeKey?.revoked).toBeUndefined();
	});

	it("includes nbf for keys with activatedAt", async () => {
		const { ctx } = await createTestContext();
		const handler = createHistoricalKeysHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_historical_keys"),
		);
		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		const keys = payload.keys as Array<Record<string, unknown>>;
		// test-key-1 was activated in createTestContext
		const activeKey = keys.find((k) => k.kid === "test-key-1");
		expect(activeKey).toBeDefined();
		expect(activeKey?.nbf).toBeTypeOf("number");
		expect(activeKey?.nbf).toBeGreaterThan(0);
	});

	it("omits nbf for keys without activatedAt", async () => {
		const { ctx, keyStore } = await createTestContext();

		const { privateKey: pk2 } = await generateSigningKey("ES256");
		await keyStore.addKey({ ...pk2, kid: "pending-key" });

		const handler = createHistoricalKeysHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_historical_keys"),
		);
		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		const keys = payload.keys as Array<Record<string, unknown>>;
		const pendingKey = keys.find((k) => k.kid === "pending-key");
		expect(pendingKey).toBeDefined();
		expect(pendingKey?.nbf).toBeUndefined();
	});

	it("strips private key fields", async () => {
		const { ctx } = await createTestContext();
		const handler = createHistoricalKeysHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_historical_keys"),
		);
		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		const keys = payload.keys as Array<Record<string, unknown>>;
		for (const key of keys) {
			expect(key).not.toHaveProperty("d");
		}
	});

	it("includes security headers", async () => {
		const { ctx } = await createTestContext();
		const handler = createHistoricalKeysHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_historical_keys"),
		);

		expect(res.headers.get("Cache-Control")).toBe("no-store");
		expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
	});

	it("returns 405 for POST", async () => {
		const { ctx } = await createTestContext();
		const handler = createHistoricalKeysHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_historical_keys", { method: "POST" }),
		);

		expect(res.status).toBe(405);
	});
});
