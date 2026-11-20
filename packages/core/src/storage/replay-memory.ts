import type { CryptoEngine } from "@oidfed/crypto";
import { sha256Hex } from "../crypto-runtime.js";

/** In-memory replay claims scoped by issuer, audience, and JWT identifier. */

import { type Clock, nowSeconds } from "../types.js";
import { JtiReplayClaimSchema, parseStorageRecord } from "./record-schemas.js";
import type { JtiReplayClaim, ReplayStore } from "./replay-store.js";

export interface MemoryReplayStoreOptions {
	readonly engine?: CryptoEngine;
	readonly clock?: Clock;
	readonly maxEntries?: number;
}

/** Raised when accepting another claim would require evicting a live replay record. */
export class ReplayStoreCapacityError extends Error {
	constructor(maxEntries: number) {
		super(`Replay store capacity of ${maxEntries} unexpired entries has been reached`);
		this.name = "ReplayStoreCapacityError";
	}
}

/** Development-only in-memory replay store with fail-closed capacity handling. */
export class MemoryReplayStore implements ReplayStore {
	// Budget for raw tuple keys when the application does not supply a digest engine.
	private static readonly maxKeyUnits = 16 * 1024 * 1024;
	private keyUnits = 0;
	private readonly entries = new Map<string, number>();
	private readonly clock: Clock | undefined;
	private readonly maxEntries: number;

	/**
	 * Create a process-local replay store with a default capacity of 10,000 live claims.
	 * A non-positive or unsafe-integer capacity throws RangeError.
	 */
	constructor(private readonly options: MemoryReplayStoreOptions = {}) {
		this.clock = options?.clock;
		this.maxEntries = options?.maxEntries ?? 10_000;
		if (!Number.isSafeInteger(this.maxEntries) || this.maxEntries <= 0) {
			throw new RangeError("maxEntries must be a positive safe integer");
		}
	}

	/**
	 * Atomically claim an issuer/audience/JTI tuple.
	 * Return false for replayed or expired claims; malformed claims throw, and a full store
	 * throws ReplayStoreCapacityError rather than evicting a live replay record.
	 */
	async useJti(claim: JtiReplayClaim): Promise<boolean> {
		const { expiresAt, issuer, audience, jti } = parseStorageRecord(
			JtiReplayClaimSchema,
			claim,
			"replay",
			"claim",
		);
		// Hash the complete tuple before the atomic lookup/insert. Long protocol IDs
		// retain their identity without consuming proportional persistent memory.
		const tuple = JSON.stringify([issuer, audience, jti]);
		const key = this.options.engine ? await sha256Hex(tuple, this.options.engine) : tuple;
		const now = nowSeconds(this.clock);
		this.removeExpired(now);
		// Hashing can cross the deadline. Expired claims cannot acquire a replay slot.
		if (expiresAt <= now) return false;

		if (this.entries.has(key)) return false;
		if (
			this.entries.size >= this.maxEntries ||
			this.keyUnits + key.length > MemoryReplayStore.maxKeyUnits
		) {
			throw new ReplayStoreCapacityError(this.maxEntries);
		}

		this.entries.set(key, expiresAt);
		this.keyUnits += key.length;
		return true;
	}

	private removeExpired(now: number): void {
		for (const [key, expiresAt] of this.entries) {
			if (expiresAt <= now) {
				this.entries.delete(key);
				this.keyUnits -= key.length;
			}
		}
	}
}
