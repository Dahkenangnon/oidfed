import { entityId } from "@oidfed/core";
import { beforeEach, describe, expect, it } from "vitest";
import { MemoryTrustMarkStore } from "../../src/storage/memory.js";
import type { TrustMarkRecord } from "../../src/storage/types.js";

const SUB1 = entityId("https://sub1.example.com");
const SUB2 = entityId("https://sub2.example.com");
const TYPE_A = "https://trust.example.com/mark-a";
const TYPE_B = "https://trust.example.com/mark-b";

function makeRecord(
	type: string,
	subject: ReturnType<typeof entityId>,
	overrides?: Partial<TrustMarkRecord>,
): TrustMarkRecord {
	return {
		trustMarkType: type,
		subject,
		jwt: `jwt.for.${type}.${subject}`,
		issuedAt: Math.floor(Date.now() / 1000),
		active: true,
		...overrides,
	};
}

describe("MemoryTrustMarkStore", () => {
	let store: MemoryTrustMarkStore;

	beforeEach(() => {
		store = new MemoryTrustMarkStore();
	});

	describe("issue & get", () => {
		it("issues and retrieves a trust mark", async () => {
			const record = makeRecord(TYPE_A, SUB1);
			await store.issue(record);
			const result = await store.get(TYPE_A, SUB1);
			expect(result).toEqual(record);
		});

		it("returns undefined for unknown trust mark", async () => {
			const result = await store.get(TYPE_A, SUB1);
			expect(result).toBeUndefined();
		});

		it("upserts on re-issue (overwrites)", async () => {
			const first = makeRecord(TYPE_A, SUB1, { jwt: "first.jwt" });
			await store.issue(first);
			const second = makeRecord(TYPE_A, SUB1, { jwt: "second.jwt" });
			await store.issue(second);
			const result = await store.get(TYPE_A, SUB1);
			expect(result?.jwt).toBe("second.jwt");
		});
	});

	describe("list", () => {
		it("lists records by type", async () => {
			await store.issue(makeRecord(TYPE_A, SUB1));
			await store.issue(makeRecord(TYPE_A, SUB2));
			await store.issue(makeRecord(TYPE_B, SUB1));
			const result = await store.list(TYPE_A);
			expect(result.items).toHaveLength(2);
		});

		it("filters by sub", async () => {
			await store.issue(makeRecord(TYPE_A, SUB1));
			await store.issue(makeRecord(TYPE_A, SUB2));
			const result = await store.list(TYPE_A, { sub: SUB1 });
			expect(result.items).toHaveLength(1);
			expect(result.items[0].subject).toBe(SUB1);
		});

		it("paginates with cursor and limit", async () => {
			for (let i = 0; i < 5; i++) {
				await store.issue(makeRecord(TYPE_A, entityId(`https://sub${i}.example.com`)));
			}
			const page1 = await store.list(TYPE_A, { limit: 2 });
			expect(page1.items).toHaveLength(2);
			expect(page1.nextCursor).toBeDefined();

			const page2 = await store.list(TYPE_A, {
				limit: 2,
				cursor: page1.nextCursor,
			});
			expect(page2.items).toHaveLength(2);
			expect(page2.nextCursor).toBeDefined();

			const page3 = await store.list(TYPE_A, {
				limit: 2,
				cursor: page2.nextCursor,
			});
			expect(page3.items).toHaveLength(1);
			expect(page3.nextCursor).toBeUndefined();
		});

		it("returns empty for unknown type", async () => {
			const result = await store.list("https://unknown.example.com/mark");
			expect(result.items).toEqual([]);
		});
	});

	describe("revoke", () => {
		it("sets active to false", async () => {
			await store.issue(makeRecord(TYPE_A, SUB1));
			await store.revoke(TYPE_A, SUB1);
			const result = await store.get(TYPE_A, SUB1);
			expect(result?.active).toBe(false);
		});

		it("throws for unknown trust mark", async () => {
			await expect(store.revoke(TYPE_A, SUB1)).rejects.toThrow("not found");
		});
	});

	describe("isActive", () => {
		it("returns true for active trust mark", async () => {
			await store.issue(makeRecord(TYPE_A, SUB1));
			expect(await store.isActive(TYPE_A, SUB1)).toBe(true);
		});

		it("returns false for revoked trust mark", async () => {
			await store.issue(makeRecord(TYPE_A, SUB1));
			await store.revoke(TYPE_A, SUB1);
			expect(await store.isActive(TYPE_A, SUB1)).toBe(false);
		});

		it("returns false for nonexistent trust mark", async () => {
			expect(await store.isActive(TYPE_A, SUB1)).toBe(false);
		});
	});
});
