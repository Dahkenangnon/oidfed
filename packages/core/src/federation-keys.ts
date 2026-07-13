import { DEFAULT_KEY_RETIRE_AFTER_MS } from "./constants.js";
import { stripPrivateFields } from "./jose/keys.js";
import type { JwtSigner } from "./jose/signer.js";
import { JwkSigner, validateSigner } from "./jose/signer.js";
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
	publishKey(key: FederationSigningKey): Promise<void>;
	switchActiveKey(kid: string, options?: SwitchActiveFederationKeyOptions): Promise<void>;
	revokeKey(kid: string, reason: string): Promise<void>;
}

export interface SwitchActiveFederationKeyOptions {
	readonly retirePreviousAfterMs?: number;
}

type FederationKeyState = "published" | "active" | "retiring" | "revoked";

interface ManagedFederationKeyEntry {
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
	/** Current Unix time in milliseconds for key-lifecycle scheduling. */
	readonly nowMs?: () => number;
}

export class MemoryFederationKeyProvider implements ManagedFederationKeyProvider {
	static fromJWK(
		jwk: JWK,
		options?: MemoryFederationKeyProviderOptions,
	): MemoryFederationKeyProvider {
		return new MemoryFederationKeyProvider(
			{
				signer: new JwkSigner(jwk),
				publicJwk: stripPrivateFields(jwk),
			},
			options,
		);
	}

	private readonly keys = new Map<string, ManagedFederationKeyEntry>();
	private readonly nowMs: () => number;

	constructor(
		initial: FederationSigningKey | readonly [FederationSigningKey, ...FederationSigningKey[]],
		options?: MemoryFederationKeyProviderOptions,
	) {
		this.nowMs = options?.nowMs ?? Date.now;
		const keys = Array.isArray(initial) ? initial : [initial];
		if (keys.length === 0) {
			throw new Error("MemoryFederationKeyProvider requires at least one initial federation key");
		}
		const now = this.nowMs();
		let activationOrder = 0;
		for (const key of keys) {
			const { signer, publicJwk } = this.validateNewKey(key);
			this.keys.set(signer.kid, {
				signer,
				publicJwk,
				state: "active",
				createdAt: now,
				activatedAt: now + activationOrder,
			});
			activationOrder++;
		}
	}

	async getFederationKeySet(): Promise<FederationKeySet> {
		let selected: ManagedFederationKeyEntry | undefined;
		const keys: JWK[] = [];
		const now = this.nowMs();
		for (const entry of this.keys.values()) {
			if (
				entry.state === "active" ||
				entry.state === "published" ||
				(entry.state === "retiring" &&
					(entry.scheduledRemovalAt === undefined || entry.scheduledRemovalAt > now))
			) {
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
		const nowSeconds = Math.floor(this.nowMs() / 1000);
		return Array.from(this.keys.values()).map((entry) => mapHistoricalEntry(entry, nowSeconds));
	}

	async publishKey(key: FederationSigningKey): Promise<void> {
		const { signer, publicJwk } = this.validateNewKey(key);
		this.keys.set(signer.kid, {
			signer,
			publicJwk,
			state: "published",
			createdAt: this.nowMs(),
		});
	}

	async switchActiveKey(
		kid: string,
		options: SwitchActiveFederationKeyOptions = {},
	): Promise<void> {
		const entry = this.getEntry(kid);
		if (entry.state !== "published") {
			throw new Error(`Federation key '${kid}' is in state '${entry.state}', expected 'published'`);
		}

		const current = await this.getFederationKeySet();
		const previousKid = current.signer.kid;
		const now = this.nowMs();
		this.keys.set(kid, { ...entry, state: "active", activatedAt: now });

		if (previousKid !== kid) {
			const previous = this.getEntry(previousKid);
			if (previous.state === "active") {
				this.keys.set(previousKid, {
					...previous,
					state: "retiring",
					scheduledRemovalAt: now + (options.retirePreviousAfterMs ?? DEFAULT_KEY_RETIRE_AFTER_MS),
				});
			}
		}
	}

	async revokeKey(kid: string, reason: string): Promise<void> {
		const entry = this.getEntry(kid);
		this.keys.set(kid, {
			...entry,
			state: "revoked",
			revokedAt: this.nowMs(),
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

export function federationKey(jwk: JWK): FederationSigningKey {
	return {
		signer: new JwkSigner(jwk),
		publicJwk: stripPrivateFields(jwk),
	};
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
