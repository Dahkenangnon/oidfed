import {
	DEFAULT_KEY_RETIRE_AFTER_MS,
	type FederationSigningKey,
	type ManagedFederationKeyProvider,
} from "@oidfed/core";

/** Rotates the signing key by activating a new key and retiring the current one. */
export async function rotateKey(
	keyProvider: ManagedFederationKeyProvider,
	newKey: FederationSigningKey,
	options?: { removeAfterMs?: number },
): Promise<void> {
	const current = await keyProvider.getFederationKeySet();
	const newKid = newKey.signer.kid;
	const oldKid = current.signer.kid;
	if (!newKid) throw new Error("New signer must have a kid");
	if (!oldKid) throw new Error("Current signer must have a kid");
	await keyProvider.addKey(newKey);
	await keyProvider.activateKey(newKid);
	const removeAfter = Date.now() + (options?.removeAfterMs ?? DEFAULT_KEY_RETIRE_AFTER_MS);
	await keyProvider.retireKey(oldKid, removeAfter);
}

/** Rotates the signing key due to compromise, revoking the old key immediately. */
export async function rotateKeyCompromise(
	keyProvider: ManagedFederationKeyProvider,
	newKey: FederationSigningKey,
	oldKid: string,
): Promise<void> {
	const newKid = newKey.signer.kid;
	if (!newKid) throw new Error("New signer must have a kid");
	await keyProvider.addKey(newKey);
	await keyProvider.activateKey(newKid);
	await keyProvider.revokeKey(oldKid, "keyCompromise");
}
