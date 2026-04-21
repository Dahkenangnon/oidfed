import { generateSigningKey, type JWK } from "@oidfed/core";
import { beforeEach, describe, expect, it } from "vitest";
import { MemoryKeyStore } from "../../src/storage/memory.js";

describe("MemoryKeyStore", () => {
	let store: MemoryKeyStore;

	beforeEach(() => {
		store = new MemoryKeyStore();
	});

	describe("constructor", () => {
		it("creates an empty store with no arguments", async () => {
			const s = new MemoryKeyStore();
			const keys = await s.getHistoricalKeys();
			expect(keys).toHaveLength(0);
		});

		it("accepts a single key and activates it", async () => {
			const { privateKey } = await generateSigningKey("ES256");
			const key = { ...privateKey, kid: "init-1" };
			const s = new MemoryKeyStore(key);

			const signing = await s.getSigningKey();
			expect(signing.key.kid).toBe("init-1");
			expect(signing.state).toBe("active");
			expect(signing.key).toHaveProperty("d");
		});

		it("accepts an array of keys and activates all", async () => {
			const k1 = { ...(await generateSigningKey("ES256")).privateKey, kid: "a" };
			const k2 = { ...(await generateSigningKey("ES256")).privateKey, kid: "b" };
			const s = new MemoryKeyStore([k1, k2]);

			const active = await s.getActiveKeys();
			expect(active.keys).toHaveLength(2);

			// Last key is the signing key (most recently activated)
			const signing = await s.getSigningKey();
			expect(signing.key.kid).toBe("b");
		});

		it("strips private fields from getActiveKeys", async () => {
			const { privateKey } = await generateSigningKey("ES256");
			const s = new MemoryKeyStore({ ...privateKey, kid: "x" });
			const active = await s.getActiveKeys();
			expect(active.keys[0]).not.toHaveProperty("d");
		});

		it("throws if initial key has no kid", () => {
			expect(() => new MemoryKeyStore({ kty: "EC" } as JWK)).toThrow("kid");
		});

		it("throws on duplicate kid in initial keys", async () => {
			const { privateKey } = await generateSigningKey("ES256");
			const key = { ...privateKey, kid: "dup" };
			expect(() => new MemoryKeyStore([key, key])).toThrow("Duplicate kid");
		});

		it("still allows addKey after constructor initialization", async () => {
			const k1 = { ...(await generateSigningKey("ES256")).privateKey, kid: "init" };
			const s = new MemoryKeyStore(k1);

			const k2 = { ...(await generateSigningKey("ES256")).privateKey, kid: "added" };
			await s.addKey(k2);
			await s.activateKey("added");

			const history = await s.getHistoricalKeys();
			expect(history).toHaveLength(2);
		});
	});

	async function addAndActivateKey(kid?: string) {
		const { privateKey } = await generateSigningKey("ES256");
		const keyKid = kid ?? privateKey.kid ?? crypto.randomUUID();
		const key = { ...privateKey, kid: keyKid };
		await store.addKey(key);
		await store.activateKey(keyKid);
		return key;
	}

	describe("addKey", () => {
		it("adds a key in pending state", async () => {
			const { privateKey } = await generateSigningKey("ES256");
			const key = { ...privateKey, kid: "k1" };
			await store.addKey(key);
			const history = await store.getHistoricalKeys();
			expect(history).toHaveLength(1);
			expect(history[0].state).toBe("pending");
		});

		it("requires kid", async () => {
			const { privateKey } = await generateSigningKey("ES256");
			const key = { ...privateKey };
			delete (key as Record<string, unknown>).kid;
			await expect(store.addKey(key)).rejects.toThrow("kid");
		});

		it("rejects duplicate kid", async () => {
			const { privateKey } = await generateSigningKey("ES256");
			const key = { ...privateKey, kid: "k1" };
			await store.addKey(key);
			await expect(store.addKey(key)).rejects.toThrow("already exists");
		});
	});

	describe("activateKey", () => {
		it("transitions pending to active", async () => {
			const { privateKey } = await generateSigningKey("ES256");
			const key = { ...privateKey, kid: "k1" };
			await store.addKey(key);
			await store.activateKey("k1");
			const managed = (await store.getHistoricalKeys()).find((k) => k.key.kid === "k1");
			expect(managed?.state).toBe("active");
			expect(managed?.activatedAt).toBeGreaterThan(0);
		});

		it("rejects non-pending key", async () => {
			const _key = await addAndActivateKey("k1");
			await expect(store.activateKey("k1")).rejects.toThrow("active");
		});

		it("throws for unknown kid", async () => {
			await expect(store.activateKey("unknown")).rejects.toThrow("not found");
		});
	});

	describe("getActiveKeys", () => {
		it("returns active and retiring keys", async () => {
			const _k1 = await addAndActivateKey("k1");
			const _k2 = await addAndActivateKey("k2");
			await store.retireKey("k1", Date.now() + 86400000);
			const result = await store.getActiveKeys();
			expect(result.keys).toHaveLength(2);
		});

		it("strips private key fields", async () => {
			await addAndActivateKey("k1");
			const result = await store.getActiveKeys();
			const key = result.keys[0];
			expect(key).not.toHaveProperty("d");
			expect(key).not.toHaveProperty("p");
			expect(key).not.toHaveProperty("q");
			expect(key).not.toHaveProperty("dp");
			expect(key).not.toHaveProperty("dq");
			expect(key).not.toHaveProperty("qi");
		});

		it("does not include pending keys", async () => {
			const { privateKey } = await generateSigningKey("ES256");
			await store.addKey({ ...privateKey, kid: "pending-key" });
			const result = await store.getActiveKeys();
			expect(result.keys).toHaveLength(0);
		});

		it("does not include revoked keys", async () => {
			await addAndActivateKey("k1");
			await store.revokeKey("k1", "compromise");
			const result = await store.getActiveKeys();
			expect(result.keys).toHaveLength(0);
		});
	});

	describe("getSigningKey", () => {
		it("returns the most recently activated active key", async () => {
			await addAndActivateKey("k1");
			await new Promise((r) => setTimeout(r, 5));
			await addAndActivateKey("k2");
			const signing = await store.getSigningKey();
			expect(signing.key.kid).toBe("k2");
		});

		it("returns private key material", async () => {
			await addAndActivateKey("k1");
			const signing = await store.getSigningKey();
			expect(signing.key).toHaveProperty("d");
		});

		it("throws when no active key", async () => {
			await expect(store.getSigningKey()).rejects.toThrow("No active signing key");
		});

		it("does not return retiring keys", async () => {
			await addAndActivateKey("k1");
			await store.retireKey("k1", Date.now() + 86400000);
			await expect(store.getSigningKey()).rejects.toThrow("No active signing key");
		});
	});

	describe("retireKey", () => {
		it("transitions active to retiring", async () => {
			await addAndActivateKey("k1");
			const removeAfter = Date.now() + 86400000;
			await store.retireKey("k1", removeAfter);
			const managed = (await store.getHistoricalKeys()).find((k) => k.key.kid === "k1");
			expect(managed?.state).toBe("retiring");
			expect(managed?.scheduledRemovalAt).toBe(removeAfter);
		});

		it("rejects non-active key", async () => {
			const { privateKey } = await generateSigningKey("ES256");
			await store.addKey({ ...privateKey, kid: "k1" });
			await expect(store.retireKey("k1", Date.now())).rejects.toThrow("pending");
		});
	});

	describe("revokeKey", () => {
		it("revokes an active key", async () => {
			await addAndActivateKey("k1");
			await store.revokeKey("k1", "keyCompromise");
			const managed = (await store.getHistoricalKeys()).find((k) => k.key.kid === "k1");
			expect(managed?.state).toBe("revoked");
			expect(managed?.revokedAt).toBeGreaterThan(0);
			expect(managed?.revocationReason).toBe("keyCompromise");
		});

		it("can revoke a pending key (emergency)", async () => {
			const { privateKey } = await generateSigningKey("ES256");
			await store.addKey({ ...privateKey, kid: "k1" });
			await store.revokeKey("k1", "keyCompromise");
			const managed = (await store.getHistoricalKeys()).find((k) => k.key.kid === "k1");
			expect(managed?.state).toBe("revoked");
		});

		it("can revoke a retiring key", async () => {
			await addAndActivateKey("k1");
			await store.retireKey("k1", Date.now() + 86400000);
			await store.revokeKey("k1", "keyCompromise");
			const managed = (await store.getHistoricalKeys()).find((k) => k.key.kid === "k1");
			expect(managed?.state).toBe("revoked");
		});

		it("throws for unknown kid", async () => {
			await expect(store.revokeKey("unknown", "test")).rejects.toThrow("not found");
		});
	});

	describe("getHistoricalKeys", () => {
		it("returns all keys regardless of state", async () => {
			const { privateKey: pk1 } = await generateSigningKey("ES256");
			await store.addKey({ ...pk1, kid: "k1" });
			await addAndActivateKey("k2");
			await addAndActivateKey("k3");
			await store.retireKey("k3", Date.now() + 86400000);
			const history = await store.getHistoricalKeys();
			expect(history).toHaveLength(3);
			const states = history.map((k) => k.state);
			expect(states).toContain("pending");
			expect(states).toContain("active");
			expect(states).toContain("retiring");
		});
	});
});
