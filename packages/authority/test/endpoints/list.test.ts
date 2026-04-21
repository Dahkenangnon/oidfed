import { EntityType, entityId } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { createListHandler } from "../../src/endpoints/list.js";
import type { SubordinateRecord } from "../../src/storage/types.js";
import { createTestContext } from "./test-helpers.js";

const SUB1 = entityId("https://sub1.example.com");
const SUB2 = entityId("https://sub2.example.com");
const _SUB3 = entityId("https://sub3.example.com");

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

describe("createListHandler", () => {
	it("returns all entity IDs with no filter", async () => {
		const { ctx, subordinateStore } = await createTestContext();
		await subordinateStore.add(makeRecord(SUB1));
		await subordinateStore.add(makeRecord(SUB2));

		const handler = createListHandler(ctx);
		const res = await handler(new Request("https://authority.example.com/federation_list"));

		expect(res.status).toBe(200);
		expect(res.headers.get("Content-Type")).toBe("application/json");

		const body = await res.json();
		expect(body).toHaveLength(2);
		expect(body).toContain(SUB1);
		expect(body).toContain(SUB2);
	});

	it("returns empty array when no subordinates", async () => {
		const { ctx } = await createTestContext();
		const handler = createListHandler(ctx);
		const res = await handler(new Request("https://authority.example.com/federation_list"));

		const body = await res.json();
		expect(body).toEqual([]);
	});

	it("filters by entity_type", async () => {
		const { ctx, subordinateStore } = await createTestContext();
		await subordinateStore.add(
			makeRecord(SUB1, {
				entityTypes: [EntityType.OpenIDProvider],
			}),
		);
		await subordinateStore.add(
			makeRecord(SUB2, {
				entityTypes: [EntityType.OpenIDRelyingParty],
			}),
		);

		const handler = createListHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_list?entity_type=openid_provider"),
		);

		const body = await res.json();
		expect(body).toEqual([SUB1]);
	});

	it("filters by intermediate", async () => {
		const { ctx, subordinateStore } = await createTestContext();
		await subordinateStore.add(makeRecord(SUB1, { isIntermediate: true }));
		await subordinateStore.add(makeRecord(SUB2, { isIntermediate: false }));

		const handler = createListHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_list?intermediate=true"),
		);

		const body = await res.json();
		expect(body).toEqual([SUB1]);
	});

	it("filters by trust_marked when trust mark store is available", async () => {
		const { ctx, subordinateStore, trustMarkStore } = await createTestContext();
		await subordinateStore.add(makeRecord(SUB1));
		await subordinateStore.add(makeRecord(SUB2));

		await trustMarkStore.issue({
			trustMarkType: "https://trust.example.com/mark",
			subject: SUB1,
			jwt: "test.jwt",
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});

		const handler = createListHandler(ctx);
		const res = await handler(
			new Request(
				"https://authority.example.com/federation_list?trust_marked=true&trust_mark_type=https%3A%2F%2Ftrust.example.com%2Fmark",
			),
		);

		const body = await res.json();
		expect(body).toEqual([SUB1]);
	});

	it("ignores unknown parameters", async () => {
		const { ctx, subordinateStore } = await createTestContext();
		await subordinateStore.add(makeRecord(SUB1));
		const handler = createListHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_list?unknown_param=foo"),
		);

		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body).toEqual([SUB1]);
	});

	it("returns 400 with unsupported_parameter when trust_marked used but no trust mark store", async () => {
		const { ctx } = await createTestContext({ trustMarkStore: undefined });
		const handler = createListHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_list?trust_marked=true"),
		);

		expect(res.status).toBe(400);
		const body = await res.json();
		expect(body.error).toBe("unsupported_parameter");
		expect(body.error_description).toBeDefined();
	});

	it("returns 400 with unsupported_parameter when trust_mark_type used but no trust mark store", async () => {
		const { ctx } = await createTestContext({ trustMarkStore: undefined });
		const handler = createListHandler(ctx);
		const res = await handler(
			new Request(
				"https://authority.example.com/federation_list?trust_mark_type=https%3A%2F%2Fexample.com%2Ftm",
			),
		);

		expect(res.status).toBe(400);
		const body = await res.json();
		expect(body.error).toBe("unsupported_parameter");
	});

	it("filters by multiple entity_type values with OR logic", async () => {
		const { ctx, subordinateStore } = await createTestContext();
		await subordinateStore.add(makeRecord(SUB1, { entityTypes: [EntityType.OpenIDProvider] }));
		await subordinateStore.add(makeRecord(SUB2, { entityTypes: [EntityType.OpenIDRelyingParty] }));
		const sub3 = entityId("https://sub3.example.com");
		await subordinateStore.add(makeRecord(sub3, { entityTypes: [EntityType.OAuthClient] }));

		const handler = createListHandler(ctx);
		const res = await handler(
			new Request(
				"https://authority.example.com/federation_list?entity_type=openid_provider&entity_type=openid_relying_party",
			),
		);

		const body = await res.json();
		expect(body).toHaveLength(2);
		expect(body).toContain(SUB1);
		expect(body).toContain(SUB2);
	});

	it("filters trust_marked=true without trust_mark_type to entities with any active trust mark", async () => {
		const { ctx, subordinateStore, trustMarkStore } = await createTestContext();
		await subordinateStore.add(makeRecord(SUB1));
		await subordinateStore.add(makeRecord(SUB2));

		await trustMarkStore.issue({
			trustMarkType: "https://trust.example.com/mark",
			subject: SUB1,
			jwt: "test.jwt",
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});

		const handler = createListHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_list?trust_marked=true"),
		);

		const body = await res.json();
		expect(body).toEqual([SUB1]);
	});

	it("filters by trust_mark_type alone without trust_marked", async () => {
		const { ctx, subordinateStore, trustMarkStore } = await createTestContext();
		await subordinateStore.add(makeRecord(SUB1));
		await subordinateStore.add(makeRecord(SUB2));

		await trustMarkStore.issue({
			trustMarkType: "https://trust.example.com/mark",
			subject: SUB1,
			jwt: "test.jwt",
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});

		const handler = createListHandler(ctx);
		const res = await handler(
			new Request(
				"https://authority.example.com/federation_list?trust_mark_type=https%3A%2F%2Ftrust.example.com%2Fmark",
			),
		);

		const body = await res.json();
		expect(body).toEqual([SUB1]);
	});

	it("filters trust_marked=false without trust_mark_type to entities with no active trust marks", async () => {
		const { ctx, subordinateStore, trustMarkStore } = await createTestContext();
		await subordinateStore.add(makeRecord(SUB1));
		await subordinateStore.add(makeRecord(SUB2));

		await trustMarkStore.issue({
			trustMarkType: "https://trust.example.com/mark",
			subject: SUB1,
			jwt: "test.jwt",
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});

		const handler = createListHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_list?trust_marked=false"),
		);

		const body = await res.json();
		expect(body).toEqual([SUB2]);
	});

	it("includes security headers", async () => {
		const { ctx } = await createTestContext();
		const handler = createListHandler(ctx);
		const res = await handler(new Request("https://authority.example.com/federation_list"));

		expect(res.headers.get("Cache-Control")).toBe("no-store");
		expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
	});

	it("returns 405 for POST", async () => {
		const { ctx } = await createTestContext();
		const handler = createListHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_list", { method: "POST" }),
		);

		expect(res.status).toBe(405);
	});
});
