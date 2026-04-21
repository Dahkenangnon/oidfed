import { decodeEntityStatement, entityId, isOk } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { createFetchHandler } from "../../src/endpoints/fetch.js";
import type { SubordinateRecord } from "../../src/storage/types.js";
import { createTestContext, ENTITY_ID } from "./test-helpers.js";

const SUB1 = entityId("https://sub1.example.com");

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

describe("createFetchHandler", () => {
	it("returns 400 when sub is missing", async () => {
		const { ctx } = await createTestContext();
		const handler = createFetchHandler(ctx);
		const res = await handler(new Request("https://authority.example.com/federation_fetch"));

		expect(res.status).toBe(400);
		const body = await res.json();
		expect(body.error).toBe("invalid_request");
	});

	it("returns 400 when sub is invalid", async () => {
		const { ctx } = await createTestContext();
		const handler = createFetchHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_fetch?sub=not-a-url"),
		);

		expect(res.status).toBe(400);
	});

	it("returns 404 when sub is unknown", async () => {
		const { ctx } = await createTestContext();
		const handler = createFetchHandler(ctx);
		const res = await handler(
			new Request(`https://authority.example.com/federation_fetch?sub=${encodeURIComponent(SUB1)}`),
		);

		expect(res.status).toBe(404);
		const body = await res.json();
		expect(body.error).toBe("not_found");
	});

	it("returns 400 when sub === entityId", async () => {
		const { ctx } = await createTestContext();
		const handler = createFetchHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_fetch?sub=${encodeURIComponent(ENTITY_ID)}`,
			),
		);

		expect(res.status).toBe(400);
		const body = await res.json();
		expect(body.error).toBe("invalid_request");
	});

	it("returns signed subordinate statement for known sub", async () => {
		const { ctx, subordinateStore } = await createTestContext();
		await subordinateStore.add(
			makeRecord(SUB1, {
				metadata: { openid_provider: { issuer: "https://sub1.example.com" } },
				sourceEndpoint: "https://sub1.example.com/federation_fetch",
			}),
		);

		const handler = createFetchHandler(ctx);
		const res = await handler(
			new Request(`https://authority.example.com/federation_fetch?sub=${encodeURIComponent(SUB1)}`),
		);

		expect(res.status).toBe(200);
		expect(res.headers.get("Content-Type")).toBe("application/entity-statement+jwt");

		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		expect(decoded.value.payload.iss).toBe(ENTITY_ID);
		expect(decoded.value.payload.sub).toBe(SUB1);

		const payload = decoded.value.payload as Record<string, unknown>;
		expect(payload.metadata).toBeDefined();
		expect(payload.source_endpoint).toBe("https://sub1.example.com/federation_fetch");
	});

	it("includes security headers", async () => {
		const { ctx, subordinateStore } = await createTestContext();
		await subordinateStore.add(makeRecord(SUB1));
		const handler = createFetchHandler(ctx);
		const res = await handler(
			new Request(`https://authority.example.com/federation_fetch?sub=${encodeURIComponent(SUB1)}`),
		);

		expect(res.headers.get("Cache-Control")).toBe("no-store");
		expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
	});

	it("uses custom subordinateStatementTtlSeconds for exp", async () => {
		const { ctx, subordinateStore } = await createTestContext({
			subordinateStatementTtlSeconds: 1800,
		});
		await subordinateStore.add(makeRecord(SUB1));

		const handler = createFetchHandler(ctx);
		const res = await handler(
			new Request(`https://authority.example.com/federation_fetch?sub=${encodeURIComponent(SUB1)}`),
		);

		expect(res.status).toBe(200);
		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		const iat = payload.iat as number;
		const exp = payload.exp as number;
		expect(exp - iat).toBe(1800);
	});

	it("returns 405 for POST", async () => {
		const { ctx } = await createTestContext();
		const handler = createFetchHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_fetch?sub=https%3A%2F%2Ffoo.com", {
				method: "POST",
			}),
		);

		expect(res.status).toBe(405);
	});
});
