/** Federation key snapshots and historical-key protocol conversion. */
import {
	assertSigningPublicJwk,
	DEFAULT_JWS_REGISTRY,
	type KeyPurpose,
	type KeyringEntry,
	type KeySelectionContext,
	type RotatingKeyring,
	samePublicKey,
	toPublicJwk,
} from "@oidfed/crypto";
import { freezeSnapshot } from "./callbacks.js";
import { registryFor } from "./crypto-context.js";
import { cloneData } from "./data-copy.js";
import { preparePublicJwkSet } from "./jwks/public-material.js";
import { type HistoricalKeyEntry, HistoricalKeyEntrySchema } from "./schemas/entity-statement.js";
import type { CryptoContext } from "./types.js";

/** Explicit source for recorded Federation historical-key wire objects. */
export interface FederationKeyHistorySource {
	getHistoricalKeys(): Promise<readonly HistoricalKeyEntry[]>;
}
/** Convert withdrawn records only. Publication and activation are not key issuance. */
export function historicalKeysFromKeyring(
	keyring: Pick<RotatingKeyring, "history">,
	purpose: KeyPurpose = "federation",
	registry = DEFAULT_JWS_REGISTRY,
): FederationKeyHistorySource {
	return {
		async getHistoricalKeys() {
			const output: HistoricalKeyEntry[] = [];
			for (const record of await keyring.history(purpose)) {
				if (record.retiredAt === undefined && record.revokedAt === undefined) continue;
				const ends = [record.retiredAt, record.revokedAt].filter(
					(value): value is number => value !== undefined,
				);
				if (!ends.every(Number.isFinite))
					throw new TypeError("Historical withdrawal times must be finite");
				output.push(
					HistoricalKeyEntrySchema.parse({
						...toPublicJwk(record.publicJwk, registry),
						exp: Math.min(...ends),
						...(record.revokedAt === undefined
							? {}
							: {
									revoked: {
										revoked_at: record.revokedAt,
										...(record.revocationReason === undefined
											? {}
											: { reason: record.revocationReason }),
									},
								}),
					}),
				);
			}
			return output;
		},
	};
}
/** Validate public publication and the selected signer's matching key identity. */
export function captureKeyringEntry(
	entry: KeyringEntry,
	registry = DEFAULT_JWS_REGISTRY,
): KeyringEntry {
	const identity = assertSigningPublicJwk({ ...entry.signer.publicJwk }, registry);
	const prepared = preparePublicJwkSet(
		{
			keys: entry.publishedJwks.keys.map((key) => ({
				...key,
				...(key.key_ops ? { key_ops: [...key.key_ops] } : {}),
			})),
		},
		registry,
	);
	if (!prepared.ok) throw new TypeError(prepared.error.description);
	const matches = prepared.value.keys.filter((key) => key.kid === identity.kid);
	if (matches.length !== 1)
		throw new TypeError("Federation keys must publish exactly one key for the selected signer");
	const key = matches[0];
	if (!key || !samePublicKey(key, identity, registry))
		throw new TypeError("Published key material must match the selected signer");
	if (
		(key?.alg !== undefined && key.alg !== identity.alg) ||
		(key?.use !== undefined && key.use !== "sig") ||
		(key?.key_ops !== undefined && !key.key_ops.includes("verify"))
	)
		throw new TypeError("Published key must allow the selected signature algorithm");
	const sign = entry.signer.sign;
	if (typeof sign !== "function") throw new TypeError("Signer must implement sign");
	return Object.freeze({
		signer: Object.freeze({
			publicJwk: freezeSnapshot(cloneData(identity)),
			sign: sign.bind(entry.signer),
		}),
		publishedJwks: freezeSnapshot(prepared.value),
	});
}
/** Validate the selected binding and all advertised public key material. */
export function validateFederationKeySet(
	entry: KeyringEntry,
	registry = DEFAULT_JWS_REGISTRY,
): void {
	captureKeyringEntry(entry, registry);
}

/** Read one federation snapshot with framework-neutral selection facts. */
export async function federationEntry(
	crypto: CryptoContext,
	context?: KeySelectionContext,
): Promise<KeyringEntry> {
	const entry = await crypto.keyring.entry(crypto.federationPurpose ?? "federation", context);
	return captureKeyringEntry(entry, registryFor(crypto));
}
