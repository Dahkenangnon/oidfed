import { entityId } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { createTrustMarkListHandler } from "../../src/endpoints/trust-mark-list.js";
import { createTestContext } from "./test-helpers.js";

const SUB1 = entityId("https://sub1.example.com");
const SUB2 = entityId("https://sub2.example.com");
const MARK_TYPE = "https://trust.example.com/mark-a";

describe("createTrustMarkListHandler", () => {
	it("returns entity IDs of active trust marks", async () => {
		const { ctx, trustMarkStore } = await createTestContext();
		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB1,
			jwt: "jwt1",
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});
		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB2,
			jwt: "jwt2",
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});

		const handler = createTrustMarkListHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(MARK_TYPE)}`,
			),
		);

		expect(res.status).toBe(200);
		expect(res.headers.get("Content-Type")).toBe("application/json");
		const body = await res.json();
		expect(body).toContain(SUB1);
		expect(body).toContain(SUB2);
	});

	it("filters by sub", async () => {
		const { ctx, trustMarkStore } = await createTestContext();
		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB1,
			jwt: "jwt1",
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});
		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB2,
			jwt: "jwt2",
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});

		const handler = createTrustMarkListHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(MARK_TYPE)}&sub=${encodeURIComponent(SUB1)}`,
			),
		);

		const body = await res.json();
		expect(body).toEqual([SUB1]);
	});

	it("excludes revoked trust marks", async () => {
		const { ctx, trustMarkStore } = await createTestContext();
		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB1,
			jwt: "jwt1",
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});
		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB2,
			jwt: "jwt2",
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});
		await trustMarkStore.revoke(MARK_TYPE, SUB2);

		const handler = createTrustMarkListHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(MARK_TYPE)}`,
			),
		);

		const body = await res.json();
		expect(body).toEqual([SUB1]);
	});

	it("returns 400 when trust_mark_type is missing", async () => {
		const { ctx } = await createTestContext();
		const handler = createTrustMarkListHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_trust_mark_list"),
		);

		expect(res.status).toBe(400);
		const body = await res.json();
		expect(body.error).toBe("invalid_request");
	});

	it("returns 501 when no trust mark store", async () => {
		const { ctx } = await createTestContext({ trustMarkStore: undefined });
		const handler = createTrustMarkListHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(MARK_TYPE)}`,
			),
		);

		expect(res.status).toBe(501);
	});

	it("includes security headers", async () => {
		const { ctx } = await createTestContext();
		const handler = createTrustMarkListHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(MARK_TYPE)}`,
			),
		);

		expect(res.headers.get("Cache-Control")).toBe("no-store");
		expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
	});

	it("returns 400 for invalid sub parameter", async () => {
		const { ctx } = await createTestContext();
		const handler = createTrustMarkListHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(MARK_TYPE)}&sub=not-a-valid-url`,
			),
		);

		expect(res.status).toBe(400);
		const body = await res.json();
		expect(body.error).toBe("invalid_request");
	});

	it("returns 405 for POST", async () => {
		const { ctx } = await createTestContext();
		const handler = createTrustMarkListHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_trust_mark_list", { method: "POST" }),
		);

		expect(res.status).toBe(405);
	});
});
