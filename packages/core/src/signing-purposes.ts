/** Explicit signing-purpose selection and public role key publication. */
import {
	type KeyPurpose,
	type KeyringEntry,
	type KeySelectionContext,
	toPublicJwk,
} from "@oidfed/crypto";
import { captureKeyringEntry, validateFederationKeySet } from "./federation-keys.js";
import type { CryptoContext, EntityContext } from "./types.js";

/** Operation names belong to the role; hosts map each enabled operation to a purpose. */
export type SigningPurposes = Readonly<Record<string, KeyPurpose | undefined>>;

/** Select and validate a stable binding. An omitted purpose has no implicit fallback. */
export async function selectSigningEntry(
	crypto: CryptoContext,
	purpose: KeyPurpose | undefined,
	context?: KeySelectionContext,
): Promise<KeyringEntry> {
	if (!purpose) throw new TypeError("A signing purpose must be configured for this operation");
	const entry = await crypto.keyring.entry(purpose, context);
	return captureKeyringEntry(entry, crypto.algorithmRegistry);
}

/** Read managed signing snapshots and merge public keys, rejecting conflicting identifiers. */
export async function signingPublication(
	context: EntityContext,
	purposes: SigningPurposes | undefined,
	pinned?: ReadonlyMap<string, KeyringEntry>,
): Promise<Record<string, unknown>> {
	if (!purposes) return {};
	const keys = new Map<string, ReturnType<typeof toPublicJwk>>();
	const snapshots = new Map<string, KeyringEntry>();
	for (const purpose of Object.values(purposes)) {
		if (purpose === undefined || snapshots.has(purpose)) continue;
		const entry =
			pinned?.get(purpose) ??
			(await selectSigningEntry(context.crypto, purpose, { issuer: context.entityId }));
		validateFederationKeySet(entry, context.crypto.algorithmRegistry);
		snapshots.set(purpose, entry);
		for (const source of entry.publishedJwks.keys) {
			const key = toPublicJwk(source, context.crypto.algorithmRegistry);
			if (!key.kid) throw new TypeError("Managed signing keys require kid");
			const previous = keys.get(key.kid);
			const canonical = (value: object) =>
				JSON.stringify(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)));
			if (previous && canonical(previous) !== canonical(key))
				throw new TypeError(`Conflicting managed signing keys for '${key.kid}'`);
			keys.set(key.kid, key);
		}
	}
	return { jwks: { keys: [...keys.values()] } };
}

export { isSignerPublished as isProtocolSignerPublished } from "./federation-keys.js";

/** Check the operation names configured for a built-in role. */
export function validateSigningPurposes(
	purposes: SigningPurposes | undefined,
	names: readonly string[],
): void {
	for (const [name, purpose] of Object.entries(purposes ?? {})) {
		if (!names.includes(name)) throw new TypeError(`Unknown signing operation '${name}'`);
		if (purpose !== undefined && (typeof purpose !== "string" || !purpose))
			throw new TypeError(`Signing operation '${name}' requires a nonempty purpose`);
	}
}
