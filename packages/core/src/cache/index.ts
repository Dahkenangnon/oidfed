import { CachePrefix } from "../constants.js";
import type { CacheProvider, Clock, EntityId } from "../types.js";

interface CacheEntry<T> {
	value: T;
	expiresAt: number;
}

/**
 * LRU in-memory cache with TTL-based expiry and configurable max entries.
 *
 * **WARNING: Development and testing only.** Cache is not shared across processes
 * and is lost on restart. For production with multiple processes or containers,
 * implement {@link CacheProvider} with Redis or similar. See `docs/storage-guide.md`.
 */
export class MemoryCache implements CacheProvider {
	private readonly store = new Map<string, CacheEntry<unknown>>();
	private readonly maxEntries: number;
	private readonly clock: Clock;

	constructor(options?: { maxEntries?: number; clock?: Clock }) {
		this.maxEntries = options?.maxEntries ?? 1000;
		this.clock = options?.clock ?? { now: () => Date.now() };
	}

	async get<T>(key: string): Promise<T | undefined> {
		const entry = this.store.get(key);
		if (!entry) return undefined;

		if (this.clock.now() >= entry.expiresAt) {
			this.store.delete(key);
			return undefined;
		}

		// LRU: move to end by re-inserting
		this.store.delete(key);
		this.store.set(key, entry);

		return entry.value as T;
	}

	async set<T>(key: string, value: T, ttlSeconds: number): Promise<void> {
		if (this.store.size >= this.maxEntries && !this.store.has(key)) {
			const firstKey = this.store.keys().next().value;
			if (firstKey !== undefined) {
				this.store.delete(firstKey);
			}
		}

		this.store.set(key, {
			value,
			expiresAt: this.clock.now() + ttlSeconds * 1000,
		});
	}

	async delete(key: string): Promise<void> {
		this.store.delete(key);
	}

	async clear(): Promise<void> {
		this.store.clear();
	}
}

async function sha256Hex(input: string): Promise<string> {
	const encoded = new TextEncoder().encode(input);
	const hashBuffer = await crypto.subtle.digest("SHA-256", encoded);
	const hashArray = new Uint8Array(hashBuffer);
	return Array.from(hashArray)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

export async function ecCacheKey(entityId: EntityId): Promise<string> {
	const hash = await sha256Hex(entityId);
	return CachePrefix.EntityConfiguration + hash.slice(0, 32);
}

export async function esCacheKey(issuer: EntityId, subject: EntityId): Promise<string> {
	const hash = await sha256Hex(`${issuer}:${subject}`);
	return CachePrefix.EntityStatement + hash.slice(0, 32);
}

export async function chainCacheKey(entityId: EntityId, trustAnchorId: EntityId): Promise<string> {
	const hash = await sha256Hex(`${entityId}:${trustAnchorId}`);
	return CachePrefix.TrustChain + hash.slice(0, 32);
}
