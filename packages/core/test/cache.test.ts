import { describe, expect, it, vi } from "vitest";
import { chainCacheKey, ecCacheKey, esCacheKey, MemoryCache } from "../src/cache/index.js";
import type { EntityId } from "../src/types.js";

describe("MemoryCache", () => {
	it("stores and retrieves a value", async () => {
		const cache = new MemoryCache();
		await cache.set("key1", { data: "test" }, 60);
		const result = await cache.get<{ data: string }>("key1");
		expect(result).toEqual({ data: "test" });
	});

	it("returns undefined for missing key", async () => {
		const cache = new MemoryCache();
		const result = await cache.get("nonexistent");
		expect(result).toBeUndefined();
	});

	it("expires entries after TTL", async () => {
		const cache = new MemoryCache();
		vi.useFakeTimers();
		try {
			await cache.set("key1", "value", 1);
			expect(await cache.get("key1")).toBe("value");

			vi.advanceTimersByTime(1500);
			expect(await cache.get("key1")).toBeUndefined();
		} finally {
			vi.useRealTimers();
		}
	});

	it("deletes a key", async () => {
		const cache = new MemoryCache();
		await cache.set("key1", "value", 60);
		await cache.delete("key1");
		expect(await cache.get("key1")).toBeUndefined();
	});

	it("clears all entries", async () => {
		const cache = new MemoryCache();
		await cache.set("a", 1, 60);
		await cache.set("b", 2, 60);
		await cache.clear();
		expect(await cache.get("a")).toBeUndefined();
		expect(await cache.get("b")).toBeUndefined();
	});

	it("evicts oldest entry when maxEntries reached", async () => {
		const cache = new MemoryCache({ maxEntries: 2 });
		await cache.set("a", 1, 60);
		await cache.set("b", 2, 60);
		await cache.set("c", 3, 60);

		expect(await cache.get("a")).toBeUndefined();
		expect(await cache.get("b")).toBe(2);
		expect(await cache.get("c")).toBe(3);
	});

	it("LRU: accessing a key moves it to the end", async () => {
		const cache = new MemoryCache({ maxEntries: 2 });
		await cache.set("a", 1, 60);
		await cache.set("b", 2, 60);

		// Access 'a' to make it recently used
		await cache.get("a");

		// Now 'b' should be evicted when adding 'c'
		await cache.set("c", 3, 60);

		expect(await cache.get("a")).toBe(1);
		expect(await cache.get("b")).toBeUndefined();
		expect(await cache.get("c")).toBe(3);
	});
});

describe("cache key generation", () => {
	const entityId = "https://example.com" as EntityId;
	const entityId2 = "https://other.example.com" as EntityId;

	it("ecCacheKey produces prefixed key", async () => {
		const key = await ecCacheKey(entityId);
		expect(key).toMatch(/^ec:[0-9a-f]{32}$/);
	});

	it("esCacheKey produces prefixed key", async () => {
		const key = await esCacheKey(entityId, entityId2);
		expect(key).toMatch(/^es:[0-9a-f]{32}$/);
	});

	it("chainCacheKey produces prefixed key", async () => {
		const key = await chainCacheKey(entityId, entityId2);
		expect(key).toMatch(/^chain:[0-9a-f]{32}$/);
	});

	it("different inputs produce different keys", async () => {
		const key1 = await ecCacheKey(entityId);
		const key2 = await ecCacheKey(entityId2);
		expect(key1).not.toBe(key2);
	});

	it("same inputs produce same keys", async () => {
		const key1 = await ecCacheKey(entityId);
		const key2 = await ecCacheKey(entityId);
		expect(key1).toBe(key2);
	});
});
