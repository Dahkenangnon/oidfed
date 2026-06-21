import type { JtiReplayClaim, ReplayStore } from "./replay-store.js";
import type { Clock } from "./types.js";
import { nowSeconds } from "./types.js";

export interface MemoryReplayStoreOptions {
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
	private readonly entries = new Map<string, number>();
	private readonly clock: Clock | undefined;
	private readonly maxEntries: number;

	constructor(options?: MemoryReplayStoreOptions) {
		this.clock = options?.clock;
		this.maxEntries = options?.maxEntries ?? 10_000;
		if (!Number.isSafeInteger(this.maxEntries) || this.maxEntries <= 0) {
			throw new RangeError("maxEntries must be a positive safe integer");
		}
	}

	async useJti(claim: JtiReplayClaim): Promise<boolean> {
		this.validateClaim(claim);
		const now = nowSeconds(this.clock);
		this.removeExpired(now);

		const key = JSON.stringify([claim.issuer, claim.audience, claim.jti]);
		if (this.entries.has(key)) return false;
		if (this.entries.size >= this.maxEntries) {
			throw new ReplayStoreCapacityError(this.maxEntries);
		}

		this.entries.set(key, claim.expiresAt);
		return true;
	}

	private removeExpired(now: number): void {
		for (const [key, expiresAt] of this.entries) {
			if (expiresAt <= now) this.entries.delete(key);
		}
	}

	private validateClaim(claim: JtiReplayClaim): void {
		if (!claim.issuer || !claim.audience || !claim.jti) {
			throw new TypeError("issuer, audience, and jti must be non-empty strings");
		}
		if (!Number.isFinite(claim.expiresAt)) {
			throw new TypeError("expiresAt must be a finite NumericDate");
		}
	}
}
