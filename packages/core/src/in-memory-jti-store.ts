import type { JtiStore } from "./jti-store.js";
import { nowSeconds } from "./types.js";

/**
 * In-memory JTI store with TTL-based cleanup.
 *
 * **WARNING: Development and testing only.** Recorded JTIs are lost on process
 * restart, re-enabling replay attacks for any unexpired JWTs. Not suitable for
 * multi-process deployments where processes don't share memory.
 *
 * For production, implement {@link JtiStore} with a shared store (Redis, database)
 * that supports atomic check-and-set. See `docs/storage-guide.md`.
 */
export class InMemoryJtiStore implements JtiStore {
	private readonly seen = new Map<string, number>();
	private cleanupTimer: ReturnType<typeof setInterval> | null = null;

	constructor(
		cleanupIntervalMs = 60_000,
		private readonly maxEntries = 10_000,
	) {
		this.cleanupTimer = setInterval(() => this.cleanup(), cleanupIntervalMs);
		// Allow the process to exit even if the timer is running
		if (typeof this.cleanupTimer === "object" && "unref" in this.cleanupTimer) {
			this.cleanupTimer.unref();
		}
	}

	async hasSeenAndRecord(jti: string, expiresAt: number): Promise<boolean> {
		if (this.seen.has(jti)) {
			return true;
		}
		if (this.seen.size >= this.maxEntries) {
			const oldest = this.seen.keys().next().value;
			if (oldest !== undefined) this.seen.delete(oldest);
		}
		this.seen.set(jti, expiresAt);
		return false;
	}

	private cleanup(): void {
		const now = nowSeconds();
		for (const [jti, expiresAt] of this.seen) {
			if (now > expiresAt) {
				this.seen.delete(jti);
			}
		}
	}

	/** Stop the cleanup timer and clear all recorded JTIs. */
	dispose(): void {
		if (this.cleanupTimer !== null) {
			clearInterval(this.cleanupTimer);
			this.cleanupTimer = null;
		}
		this.seen.clear();
	}
}
