import { DEFAULT_KEY_RETIRE_AFTER_MS } from "./constants.js";
import type { JwtSigner } from "./jose/signer.js";
import { validateSigner } from "./jose/signer.js";
import type { HistoricalKeyEntry } from "./schemas/entity-statement.js";
import type { JWK, JWKSet } from "./schemas/jwk.js";
import { JWKSetSchema } from "./schemas/jwk.js";

export interface FederationKeySet {
	readonly signer: JwtSigner;
	readonly jwks: JWKSet;
}

export interface FederationKeyProvider {
	getFederationKeySet(): Promise<FederationKeySet>;
}

export interface FederationSigningKey {
	readonly signer: JwtSigner;
	readonly publicJwk: JWK;
}

export interface ManagedFederationKeyProvider extends FederationKeyProvider {
	getHistoricalFederationKeys(): Promise<HistoricalKeyEntry[]>;
	addKey(key: FederationSigningKey): Promise<void>;
	activateKey(kid: string): Promise<void>;
	retireKey(kid: string, removeAfter: number): Promise<void>;
	revokeKey(kid: string, reason: string): Promise<void>;
}

export type FederationKeyState = "pending" | "active" | "retiring" | "revoked";

export interface ManagedFederationKeyEntry {
	readonly signer: JwtSigner;
	readonly publicJwk: JWK;
	readonly state: FederationKeyState;
	readonly createdAt?: number;
	readonly activatedAt?: number;
	readonly expiresAt?: number;
	readonly scheduledRemovalAt?: number;
	readonly revokedAt?: number;
	readonly revocationReason?: string;
}

export class StaticFederationKeyProvider implements FederationKeyProvider {
	private readonly keySet: FederationKeySet;

	constructor(keySet: FederationKeySet) {
		validateFederationKeySet(keySet);
		this.keySet = keySet;
	}

	async getFederationKeySet(): Promise<FederationKeySet> {
		return this.keySet;
	}
}

export interface MemoryFederationKeyProviderOptions {
	readonly now?: () => number;
}

export class MemoryFederationKeyProvider implements ManagedFederationKeyProvider {
	private readonly keys = new Map<string, ManagedFederationKeyEntry>();
	private readonly now: () => number;

	constructor(
		initial?: FederationSigningKey | ReadonlyArray<FederationSigningKey>,
		options?: MemoryFederationKeyProviderOptions,
	) {
		this.now = options?.now ?? Date.now;
		if (initial) {
			const keys = Array.isArray(initial) ? initial : [initial];
			const now = this.now();
			for (let i = 0; i < keys.length; i++) {
				const { signer, publicJwk } = this.validateNewKey(keys[i] as FederationSigningKey);
				this.keys.set(signer.kid, {
					signer,
					publicJwk,
					state: "active",
					createdAt: now,
					activatedAt: now + i,
				});
			}
		}
	}

	async getFederationKeySet(): Promise<FederationKeySet> {
		let selected: ManagedFederationKeyEntry | undefined;
		const keys: JWK[] = [];
		for (const entry of this.keys.values()) {
			if (entry.state === "active" || entry.state === "retiring") {
				keys.push(entry.publicJwk);
			}
			if (entry.state === "active") {
				if (!selected || (entry.activatedAt ?? 0) > (selected.activatedAt ?? 0)) {
					selected = entry;
				}
			}
		}
		if (!selected) {
			throw new Error("No active federation signing key available");
		}
		const jwks = { keys };
		validateFederationKeySet({ signer: selected.signer, jwks });
		return { signer: selected.signer, jwks };
	}

	async getHistoricalFederationKeys(): Promise<HistoricalKeyEntry[]> {
		const nowSeconds = Math.floor(this.now() / 1000);
		return Array.from(this.keys.values()).map((entry) => mapHistoricalEntry(entry, nowSeconds));
	}

	async addKey(key: FederationSigningKey): Promise<void> {
		const { signer, publicJwk } = this.validateNewKey(key);
		this.keys.set(signer.kid, {
			signer,
			publicJwk,
			state: "pending",
			createdAt: this.now(),
		});
	}

	async activateKey(kid: string): Promise<void> {
		const entry = this.getEntry(kid);
		if (entry.state !== "pending") {
			throw new Error(`Federation key '${kid}' is in state '${entry.state}', expected 'pending'`);
		}
		this.keys.set(kid, { ...entry, state: "active", activatedAt: this.now() });
	}

	async retireKey(kid: string, removeAfter: number): Promise<void> {
		const entry = this.getEntry(kid);
		if (entry.state !== "active") {
			throw new Error(`Federation key '${kid}' is in state '${entry.state}', expected 'active'`);
		}
		this.keys.set(kid, { ...entry, state: "retiring", scheduledRemovalAt: removeAfter });
	}

	async revokeKey(kid: string, reason: string): Promise<void> {
		const entry = this.getEntry(kid);
		this.keys.set(kid, {
			...entry,
			state: "revoked",
			revokedAt: this.now(),
			revocationReason: reason,
		});
	}

	private validateNewKey(key: FederationSigningKey): FederationSigningKey {
		const { signer } = key;
		validateSigner(signer);
		if (this.keys.has(signer.kid)) {
			throw new Error(`Federation key '${signer.kid}' already exists`);
		}
		return { signer, publicJwk: validateFederationPublicJwk(key.publicJwk, signer) };
	}

	private getEntry(kid: string): ManagedFederationKeyEntry {
		const entry = this.keys.get(kid);
		if (!entry) {
			throw new Error(`Federation key '${kid}' not found`);
		}
		return entry;
	}
}

export async function rotateFederationKey(
	provider: ManagedFederationKeyProvider,
	newKey: FederationSigningKey,
	options?: { removeAfterMs?: number; now?: () => number },
): Promise<void> {
	const current = await provider.getFederationKeySet();
	await provider.addKey(newKey);
	await provider.activateKey(newKey.signer.kid);
	const now = options?.now?.() ?? Date.now();
	await provider.retireKey(
		current.signer.kid,
		now + (options?.removeAfterMs ?? DEFAULT_KEY_RETIRE_AFTER_MS),
	);
}

export function validateFederationKeySet(keySet: FederationKeySet): void {
	validateSigner(keySet.signer);
	const parsed = JWKSetSchema.safeParse(keySet.jwks);
	if (!parsed.success) {
		throw new Error("Federation JWKS MUST be a public JWK Set with unique non-empty kids");
	}
	let signerKeyCount = 0;
	for (const key of parsed.data.keys) {
		if (key.kid === keySet.signer.kid) {
			signerKeyCount++;
			if (key.alg && key.alg !== keySet.signer.alg) {
				throw new Error(
					`Federation signer alg '${keySet.signer.alg}' does not match published key alg '${key.alg}'`,
				);
			}
		}
	}
	if (signerKeyCount !== 1) {
		throw new Error(
			"Federation JWKS MUST publish exactly one public key for the active signer kid",
		);
	}
}

function validateFederationPublicJwk(publicJwk: JWK, signer: JwtSigner): JWK {
	const parsed = JWKSetSchema.safeParse({ keys: [publicJwk] });
	if (!parsed.success) {
		throw new Error("Federation public JWK MUST contain only asymmetric public key material");
	}
	const jwk = parsed.data.keys[0] as JWK;
	if (jwk.kid !== signer.kid) {
		throw new Error("Federation public JWK kid MUST match signer kid");
	}
	if (jwk.alg && jwk.alg !== signer.alg) {
		throw new Error("Federation public JWK alg MUST match signer alg");
	}
	return jwk;
}

function mapHistoricalEntry(
	entry: ManagedFederationKeyEntry,
	nowSeconds: number,
): HistoricalKeyEntry {
	const historical = { ...entry.publicJwk } as HistoricalKeyEntry;
	if (entry.expiresAt !== undefined) {
		historical.exp = Math.floor(entry.expiresAt / 1000);
	} else if (entry.scheduledRemovalAt !== undefined) {
		historical.exp = Math.floor(entry.scheduledRemovalAt / 1000);
	} else if (entry.revokedAt !== undefined) {
		historical.exp = Math.floor(entry.revokedAt / 1000);
	} else {
		historical.exp = nowSeconds;
	}
	if (entry.createdAt !== undefined) {
		historical.iat = Math.floor(entry.createdAt / 1000);
	}
	if (entry.activatedAt !== undefined) {
		historical.nbf = Math.floor(entry.activatedAt / 1000);
	}
	if (entry.state === "revoked") {
		historical.revoked = {
			revoked_at: entry.revokedAt ? Math.floor(entry.revokedAt / 1000) : nowSeconds,
			...(entry.revocationReason ? { reason: entry.revocationReason } : {}),
		};
	}
	return historical;
}
