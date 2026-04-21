import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { InMemoryJtiStore } from "../src/in-memory-jti-store.js";

describe("InMemoryJtiStore", () => {
	let store: InMemoryJtiStore;

	beforeEach(() => {
		store = new InMemoryJtiStore(0); // no periodic cleanup timer
	});

	afterEach(() => {
		store.dispose();
	});

	it("returns false on first record, true on replay", async () => {
		const future = Math.floor(Date.now() / 1000) + 3600;
		expect(await store.hasSeenAndRecord("jti-1", future)).toBe(false);
		expect(await store.hasSeenAndRecord("jti-1", future)).toBe(true);
	});

	it("returns false for distinct JTIs", async () => {
		const future = Math.floor(Date.now() / 1000) + 3600;
		expect(await store.hasSeenAndRecord("jti-a", future)).toBe(false);
		expect(await store.hasSeenAndRecord("jti-b", future)).toBe(false);
	});

	it("TTL cleanup removes expired entries", () => {
		const past = Math.floor(Date.now() / 1000) - 1;
		// Access private method via cast for whitebox testing
		const s = store as unknown as { seen: Map<string, number>; cleanup(): void };
		s.seen.set("expired-jti", past);
		s.cleanup();
		expect(s.seen.has("expired-jti")).toBe(false);
	});

	it("does not remove non-expired entries during cleanup", () => {
		const future = Math.floor(Date.now() / 1000) + 3600;
		const s = store as unknown as { seen: Map<string, number>; cleanup(): void };
		s.seen.set("live-jti", future);
		s.cleanup();
		expect(s.seen.has("live-jti")).toBe(true);
	});

	it("evicts oldest entry when maxEntries is reached", async () => {
		const maxEntries = 3;
		const capped = new InMemoryJtiStore(0, maxEntries);
		const future = Math.floor(Date.now() / 1000) + 3600;

		await capped.hasSeenAndRecord("jti-1", future);
		await capped.hasSeenAndRecord("jti-2", future);
		await capped.hasSeenAndRecord("jti-3", future);
		// At limit — inserting a 4th should evict "jti-1"
		await capped.hasSeenAndRecord("jti-4", future);

		const s = capped as unknown as { seen: Map<string, number> };
		expect(s.seen.size).toBe(maxEntries);
		expect(s.seen.has("jti-1")).toBe(false);
		expect(s.seen.has("jti-4")).toBe(true);

		capped.dispose();
	});

	it("default constructor uses maxEntries=10_000", () => {
		const s = new InMemoryJtiStore() as unknown as { maxEntries: number };
		expect(s.maxEntries).toBe(10_000);
		(s as unknown as InMemoryJtiStore).dispose();
	});

	it("custom maxEntries constructor is respected", () => {
		const s = new InMemoryJtiStore(0, 500) as unknown as { maxEntries: number };
		expect(s.maxEntries).toBe(500);
		(s as unknown as InMemoryJtiStore).dispose();
	});

	it("dispose clears all entries and stops timer", async () => {
		const future = Math.floor(Date.now() / 1000) + 3600;
		await store.hasSeenAndRecord("jti-x", future);
		store.dispose();
		const s = store as unknown as { seen: Map<string, number> };
		expect(s.seen.size).toBe(0);
	});
});
