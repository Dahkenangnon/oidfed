import {
	type FederationSigningKey,
	type ManagedFederationKeyProvider,
	rotateFederationKey,
} from "@oidfed/core";

/** Rotates the signing key by activating a new key and retiring the current one. */
export async function rotateKey(
	keyProvider: ManagedFederationKeyProvider,
	newKey: FederationSigningKey,
	options?: { removeAfterMs?: number; nowMs?: () => number },
): Promise<void> {
	await rotateFederationKey(keyProvider, newKey, options);
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
