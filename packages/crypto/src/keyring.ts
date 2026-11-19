/** Purpose-addressed signing snapshots and an in-memory publication lifecycle. */
import { assertPublicJwk, assertSigningPublicJwk, assertVerificationKey } from "./jwk.js";
import { DEFAULT_JWS_REGISTRY, type JwsAlgorithmRegistry } from "./registry.js";
import {
	CryptoError,
	type HistoricalKeyRecord,
	type Jwk,
	type KeyPurpose,
	type Keyring,
	type KeyringEntry,
	type KeySelectionContext,
	type RotatingKeyring,
	type Signer,
	type SigningPublicJwk,
} from "./types.js";

function freeze<T>(value: T): T {
	if (value !== null && typeof value === "object") {
		for (const child of Object.values(value)) freeze(child);
		Object.freeze(value);
	}
	return value;
}

function capture(signer: Signer, registry: JwsAlgorithmRegistry): Signer {
	if (!signer || typeof signer.sign !== "function")
		throw new CryptoError("SIGNER_CONTRACT_VIOLATION", "Expected a signing callback");
	const publicJwk = { ...signer.publicJwk };
	const identity = freeze(assertSigningPublicJwk(publicJwk, registry));
	const operation = signer.sign.bind(signer);
	return Object.freeze({ publicJwk: identity, sign: (input: Uint8Array) => operation(input) });
}

function publication(key: Jwk, registry: JwsAlgorithmRegistry): Jwk {
	if (!key || typeof key.kid !== "string" || !key.kid)
		throw new CryptoError("MALFORMED_KEY", "Published keys require a kid");
	return freeze(
		key.alg === undefined
			? assertPublicJwk(key, registry)
			: assertVerificationKey(key, key.alg, registry),
	);
}

function entry(
	signer: Signer,
	additional: readonly Jwk[],
	registry: JwsAlgorithmRegistry,
): KeyringEntry {
	const keys = [signer.publicJwk, ...additional.map((key) => publication(key, registry))];
	const ids = keys.map((key) => key.kid);
	if (new Set(ids).size !== ids.length)
		throw new CryptoError("MALFORMED_KEY", "Published key identifiers must be unique");
	return freeze({ signer, publishedJwks: { keys } });
}

/** Named signers and explicit publication/alias configuration. Empty maps are valid. */
export interface StaticKeyringConfig {
	/** Registry used to validate and publish application key formats. */
	readonly algorithmRegistry?: JwsAlgorithmRegistry;
	/** Each signer owns a stable private-key operation for its purpose. */
	readonly signers: Readonly<Partial<Record<KeyPurpose, Signer>>>;
	/** One-hop aliases to configured signers; sharing never happens implicitly. */
	readonly aliases?: Readonly<Partial<Record<KeyPurpose, KeyPurpose>>>;
	/** Other public keys to advertise alongside a purpose's selected signer; kids must be unique. */
	readonly additionalPublishedKeys?: Readonly<Partial<Record<KeyPurpose, readonly Jwk[]>>>;
}

/** Capture configured signers and public metadata once, then reuse frozen entries. */
export class StaticKeyring implements Keyring {
	readonly #entries = new Map<KeyPurpose, KeyringEntry>();
	readonly #aliases = new Map<KeyPurpose, KeyPurpose>();
	/** Validate signers, unique published kids and one-hop aliases without invoking signing.
	 * @throws {CryptoError} For invalid keys, bindings or alias targets.
	 */
	constructor(config: StaticKeyringConfig) {
		const registry = config.algorithmRegistry ?? DEFAULT_JWS_REGISTRY;
		for (const [purpose, signer] of Object.entries(config.signers)) {
			if (signer !== undefined)
				this.#entries.set(
					purpose,
					entry(
						capture(signer, registry),
						Object.hasOwn(config.additionalPublishedKeys ?? {}, purpose)
							? (config.additionalPublishedKeys?.[purpose] ?? [])
							: [],
						registry,
					),
				);
		}
		for (const [purpose, target] of Object.entries(config.aliases ?? {})) {
			if (target === undefined) continue;
			if (this.#entries.has(purpose) || !this.#entries.has(target))
				throw new CryptoError(
					"KEY_NOT_FOUND",
					"Alias must reference a configured signer without shadowing one",
				);
			this.#aliases.set(purpose, target);
		}
		for (const purpose of Object.keys(config.additionalPublishedKeys ?? {})) {
			if (!this.#entries.has(purpose))
				throw new CryptoError("KEY_NOT_FOUND", "Additional keys require a configured signer");
		}
	}

	/** Read the cached snapshot. Context is accepted for compatibility with custom keyrings.
	 * @throws {CryptoError} KEY_NOT_FOUND if the purpose is not configured or aliased.
	 */
	async entry(purpose: KeyPurpose, _context?: KeySelectionContext): Promise<KeyringEntry> {
		const value = this.#entries.get(this.#aliases.get(purpose) ?? purpose);
		if (!value)
			throw new CryptoError("KEY_NOT_FOUND", `No signer configured for purpose ${purpose}`);
		return value;
	}
}

type State = "published" | "active" | "retiring" | "retired" | "revoked";
interface Managed {
	readonly publicJwk: SigningPublicJwk;
	signer: Signer | undefined;
	state: State;
	readonly publishedAt: number;
	activatedAt?: number;
	retiredAt?: number;
	revokedAt?: number;
	revocationReason?: string;
}
/** Clock configuration for the in-memory lifecycle. */
export interface MemoryRotatingKeyringOptions {
	/** Registry used to validate and publish application key formats. */
	readonly algorithmRegistry?: JwsAlgorithmRegistry;
	/** Unix seconds. Must be finite and must not move backwards between mutations. */
	readonly nowSeconds?: () => number;
}

/** In-memory state; applications control propagation delays and retirement scheduling. */
export class MemoryRotatingKeyring implements RotatingKeyring {
	readonly #purposes = new Map<KeyPurpose, Map<string, Managed>>();
	readonly #clock: () => number;
	readonly #registry: JwsAlgorithmRegistry;
	#lastTime: number;
	/** Introduce initial keys as active at the first clock reading. An empty keyring is valid.
	 * @throws {CryptoError} For invalid bindings or a non-finite clock.
	 */
	constructor(
		initial: Readonly<Partial<Record<KeyPurpose, Signer>>> = {},
		options?: MemoryRotatingKeyringOptions,
	) {
		this.#registry = options?.algorithmRegistry ?? DEFAULT_JWS_REGISTRY;
		this.#clock = options?.nowSeconds ?? (() => Date.now() / 1000);
		this.#lastTime = this.#time();
		for (const [purpose, source] of Object.entries(initial)) {
			if (source === undefined) continue;
			const signer = capture(source, this.#registry);
			this.#purposes.set(
				purpose,
				new Map([
					[
						signer.publicJwk.kid,
						{
							signer,
							publicJwk: signer.publicJwk,
							state: "active",
							publishedAt: this.#lastTime,
							activatedAt: this.#lastTime,
						},
					],
				]),
			);
		}
	}

	#time(): number {
		const now = this.#clock();
		if (!Number.isFinite(now) || (this.#lastTime !== undefined && now < this.#lastTime))
			throw new CryptoError(
				"SIGNER_CONTRACT_VIOLATION",
				"Lifecycle clock must be finite and nondecreasing",
			);
		return now;
	}
	#keys(purpose: KeyPurpose): Map<string, Managed> {
		const keys = this.#purposes.get(purpose);
		if (!keys) throw new CryptoError("KEY_NOT_FOUND", `No keys for purpose ${purpose}`);
		return keys;
	}
	#key(purpose: KeyPurpose, kid: string): Managed {
		const key = this.#keys(purpose).get(kid);
		if (!key) throw new CryptoError("KEY_NOT_FOUND", `No managed key ${kid}`);
		return key;
	}

	/** Capture the active binding and keys in publication or overlap. Context is not interpreted.
	 * @throws {CryptoError} KEY_NOT_FOUND if the purpose has no active signer.
	 */
	async entry(purpose: KeyPurpose, _context?: KeySelectionContext): Promise<KeyringEntry> {
		const keys = [...this.#keys(purpose).values()];
		const active = keys.find((key) => key.state === "active");
		if (!active?.signer)
			throw new CryptoError("KEY_NOT_FOUND", `No active signer for purpose ${purpose}`);
		return entry(
			active.signer,
			keys
				.filter((key) => key.state === "published" || key.state === "retiring")
				.map((key) => key.publicJwk),
			this.#registry,
		);
	}
	/** Introduce a key without activating it. Identifiers cannot be reused, even after withdrawal.
	 * @throws {CryptoError} For invalid keys, duplicate kids or a failed lifecycle clock check.
	 */
	async publish(purpose: KeyPurpose, source: Signer): Promise<void> {
		const signer = capture(source, this.#registry);
		const keys = this.#purposes.get(purpose) ?? new Map<string, Managed>();
		if (keys.has(signer.publicJwk.kid))
			throw new CryptoError("MALFORMED_KEY", "Managed key identifiers cannot be reused");
		const now = this.#time();
		keys.set(signer.publicJwk.kid, {
			signer,
			publicJwk: signer.publicJwk,
			state: "published",
			publishedAt: now,
		});
		this.#purposes.set(purpose, keys);
		this.#lastTime = now;
	}
	/** Activate a published key and move the current signer into overlap.
	 * @throws {CryptoError} KEY_NOT_FOUND for ineligible keys; SIGNER_CONTRACT_VIOLATION for clock errors.
	 */
	async activate(purpose: KeyPurpose, kid: string): Promise<void> {
		const next = this.#key(purpose, kid);
		if (next.state !== "published")
			throw new CryptoError("KEY_NOT_FOUND", "Only a published key can be activated");
		const now = this.#time();
		for (const key of this.#keys(purpose).values())
			if (key.state === "active") key.state = "retiring";
		next.state = "active";
		next.activatedAt = now;
		this.#lastTime = now;
	}
	/** Withdraw a published or overlap key. Repeating this operation is a no-op.
	 * @throws {CryptoError} KEY_NOT_FOUND for missing/ineligible keys or a typed clock failure.
	 */
	async retire(purpose: KeyPurpose, kid: string): Promise<void> {
		const key = this.#key(purpose, kid);
		if (key.state === "retired") return;
		if (key.state !== "published" && key.state !== "retiring")
			throw new CryptoError("KEY_NOT_FOUND", "Only published or retiring keys can retire");
		const now = this.#time();
		key.state = "retired";
		key.signer = undefined;
		key.retiredAt = now;
		this.#lastTime = now;
	}
	/** Withdraw a managed key, preserving the first revocation time and reason on repeat calls.
	 * Existing snapshots still hold their custody callback; the host controls backend revocation.
	 * @throws {CryptoError} KEY_NOT_FOUND for a missing key or a typed clock failure.
	 */
	async revoke(purpose: KeyPurpose, kid: string, reason: string): Promise<void> {
		const key = this.#key(purpose, kid);
		if (key.state === "revoked") return;
		const now = this.#time();
		key.state = "revoked";
		key.signer = undefined;
		key.revokedAt = now;
		key.revocationReason = reason;
		this.#lastTime = now;
	}
	/** Return detached, frozen facts for keys that were activated, retired or revoked.
	 * Pending, never-activated keys are omitted. Unix-second timestamps may be fractional.
	 * @throws {CryptoError} KEY_NOT_FOUND for an unknown purpose.
	 */
	async history(purpose: KeyPurpose): Promise<readonly HistoricalKeyRecord[]> {
		return freeze(
			[...this.#keys(purpose).values()]
				.filter(
					(key) =>
						key.activatedAt !== undefined || key.state === "retired" || key.state === "revoked",
				)
				.map((key) => ({
					publicJwk: key.publicJwk,
					publishedAt: key.publishedAt,
					...(key.activatedAt !== undefined ? { activatedAt: key.activatedAt } : {}),
					...(key.retiredAt !== undefined ? { retiredAt: key.retiredAt } : {}),
					...(key.revokedAt !== undefined ? { revokedAt: key.revokedAt } : {}),
					...(key.revocationReason !== undefined ? { revocationReason: key.revocationReason } : {}),
				})),
		);
	}
}
