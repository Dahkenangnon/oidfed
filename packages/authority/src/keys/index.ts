import { DEFAULT_KEY_RETIRE_AFTER_MS, type JWK } from "@oidfed/core";
import type { KeyStore } from "../storage/types.js";

/** Rotates the signing key by activating a new key and retiring the current one. */
export async function rotateKey(
	keyStore: KeyStore,
	newKey: JWK,
	options?: { removeAfterMs?: number },
): Promise<void> {
	const current = await keyStore.getSigningKey();
	const newKid = newKey.kid;
	const oldKid = current.key.kid;
	if (!newKid) throw new Error("New key must have a kid");
	if (!oldKid) throw new Error("Current key must have a kid");
	await keyStore.addKey(newKey);
	await keyStore.activateKey(newKid);
	const removeAfter = Date.now() + (options?.removeAfterMs ?? DEFAULT_KEY_RETIRE_AFTER_MS);
	await keyStore.retireKey(oldKid, removeAfter);
}

/** Rotates the signing key due to compromise, revoking the old key immediately. */
export async function rotateKeyCompromise(
	keyStore: KeyStore,
	newKey: JWK,
	oldKid: string,
): Promise<void> {
	const newKid = newKey.kid;
	if (!newKid) throw new Error("New key must have a kid");
	await keyStore.addKey(newKey);
	await keyStore.activateKey(newKid);
	await keyStore.revokeKey(oldKid, "keyCompromise");
}
