import { EntityType, entityId } from "@oidfed/core";
import { beforeEach, describe, expect, it } from "vitest";
import { MemorySubordinateStore } from "../../src/storage/memory.js";
import type { SubordinateRecord } from "../../src/storage/types.js";

const SUB1 = entityId("https://sub1.example.com");
const SUB2 = entityId("https://sub2.example.com");
const SUB3 = entityId("https://sub3.example.com");

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

describe("MemorySubordinateStore", () => {
	let store: MemorySubordinateStore;

	beforeEach(() => {
		store = new MemorySubordinateStore();
	});

	describe("add & get", () => {
		it("adds and retrieves a record", async () => {
			const record = makeRecord(SUB1);
			await store.add(record);
			const result = await store.get(SUB1);
			expect(result).toEqual(record);
		});

		it("returns undefined for unknown entity", async () => {
			const result = await store.get(SUB1);
			expect(result).toBeUndefined();
		});

		it("rejects duplicate entityId", async () => {
			await store.add(makeRecord(SUB1));
			await expect(store.add(makeRecord(SUB1))).rejects.toThrow("already exists");
		});
	});

	describe("list", () => {
		it("returns all records with no filter", async () => {
			await store.add(makeRecord(SUB1));
			await store.add(makeRecord(SUB2));
			const results = await store.list();
			expect(results).toHaveLength(2);
		});

		it("returns empty array for empty store", async () => {
			const results = await store.list();
			expect(results).toEqual([]);
		});

		it("filters by entityType", async () => {
			await store.add(
				makeRecord(SUB1, {
					entityTypes: [EntityType.OpenIDProvider],
				}),
			);
			await store.add(
				makeRecord(SUB2, {
					entityTypes: [EntityType.OpenIDRelyingParty],
				}),
			);
			const results = await store.list({
				entityTypes: [EntityType.OpenIDProvider],
			});
			expect(results).toHaveLength(1);
			expect(results[0].entityId).toBe(SUB1);
		});

		it("filters by intermediate", async () => {
			await store.add(makeRecord(SUB1, { isIntermediate: true }));
			await store.add(makeRecord(SUB2, { isIntermediate: false }));
			await store.add(makeRecord(SUB3));
			const results = await store.list({ intermediate: true });
			expect(results).toHaveLength(1);
			expect(results[0].entityId).toBe(SUB1);
		});

		it("filters intermediate=false includes records without flag", async () => {
			await store.add(makeRecord(SUB1, { isIntermediate: false }));
			await store.add(makeRecord(SUB2));
			const results = await store.list({ intermediate: false });
			expect(results).toHaveLength(2);
		});
	});

	describe("update", () => {
		it("updates a record", async () => {
			await store.add(makeRecord(SUB1));
			await store.update(SUB1, { isIntermediate: true });
			const result = await store.get(SUB1);
			expect(result?.isIntermediate).toBe(true);
		});

		it("preserves entityId on update", async () => {
			await store.add(makeRecord(SUB1));
			await store.update(SUB1, {
				entityId: SUB2,
			} as Partial<SubordinateRecord>);
			const result = await store.get(SUB1);
			expect(result?.entityId).toBe(SUB1);
		});

		it("updates updatedAt timestamp", async () => {
			const original = makeRecord(SUB1);
			await store.add(original);
			await new Promise((r) => setTimeout(r, 5));
			await store.update(SUB1, { isIntermediate: true });
			const result = await store.get(SUB1);
			expect(result?.updatedAt).toBeGreaterThan(original.updatedAt);
		});

		it("throws for unknown entity", async () => {
			await expect(store.update(SUB1, { isIntermediate: true })).rejects.toThrow("not found");
		});
	});

	describe("remove", () => {
		it("removes a record", async () => {
			await store.add(makeRecord(SUB1));
			await store.remove(SUB1);
			const result = await store.get(SUB1);
			expect(result).toBeUndefined();
		});

		it("throws for unknown entity", async () => {
			await expect(store.remove(SUB1)).rejects.toThrow("not found");
		});
	});
});
