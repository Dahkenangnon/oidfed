import { generateSigningKey } from "@oidfed/core";
import { beforeEach, describe, expect, it } from "vitest";
import { rotateKey, rotateKeyCompromise } from "../../src/keys/index.js";
import { MemoryKeyStore } from "../../src/storage/memory.js";

describe("rotateKey", () => {
	let store: MemoryKeyStore;

	beforeEach(async () => {
		store = new MemoryKeyStore();
		const { privateKey } = await generateSigningKey("ES256");
		await store.addKey({ ...privateKey, kid: "old-key" });
		await store.activateKey("old-key");
	});

	it("activates new key and retires old key", async () => {
		const { privateKey: newKey } = await generateSigningKey("ES256");
		const key = { ...newKey, kid: "new-key" };
		await rotateKey(store, key);

		const signing = await store.getSigningKey();
		expect(signing.key.kid).toBe("new-key");

		const history = await store.getHistoricalKeys();
		const oldManaged = history.find((k) => k.key.kid === "old-key");
		expect(oldManaged?.state).toBe("retiring");
		expect(oldManaged?.scheduledRemovalAt).toBeGreaterThan(Date.now());
	});

	it("old key is still in active keys (retiring)", async () => {
		const { privateKey: newKey } = await generateSigningKey("ES256");
		await rotateKey(store, { ...newKey, kid: "new-key" });
		const activeKeys = await store.getActiveKeys();
		expect(activeKeys.keys).toHaveLength(2);
	});
});

describe("rotateKeyCompromise", () => {
	let store: MemoryKeyStore;

	beforeEach(async () => {
		store = new MemoryKeyStore();
		const { privateKey } = await generateSigningKey("ES256");
		await store.addKey({ ...privateKey, kid: "compromised-key" });
		await store.activateKey("compromised-key");
	});

	it("immediately revokes old key and activates new", async () => {
		const { privateKey: newKey } = await generateSigningKey("ES256");
		const key = { ...newKey, kid: "new-key" };
		await rotateKeyCompromise(store, key, "compromised-key");

		const signing = await store.getSigningKey();
		expect(signing.key.kid).toBe("new-key");

		const history = await store.getHistoricalKeys();
		const oldManaged = history.find((k) => k.key.kid === "compromised-key");
		expect(oldManaged?.state).toBe("revoked");
		expect(oldManaged?.revocationReason).toBe("keyCompromise");
	});

	it("revoked key is not in active keys", async () => {
		const { privateKey: newKey } = await generateSigningKey("ES256");
		await rotateKeyCompromise(store, { ...newKey, kid: "new-key" }, "compromised-key");
		const activeKeys = await store.getActiveKeys();
		expect(activeKeys.keys).toHaveLength(1);
		expect(activeKeys.keys[0].kid).toBe("new-key");
	});
});
