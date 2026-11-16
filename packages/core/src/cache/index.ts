/** In-memory TTL caching and deterministic cache keys for federation evidence. */

import { CachePrefix } from "../constants.js";
import type { CacheProvider, Clock, EntityId } from "../types.js";

interface CacheEntry<T> {
	value: T;
	expiresAt: number;
}

export interface MemoryCacheOptions {
	readonly maxEntries?: number;
	/** NumericDate clock in seconds. */
	readonly clock?: Clock;
}

/**
 * LRU in-memory cache with TTL-based expiry and configurable max entries.
 *
 * **WARNING: Development and testing only.** Cache is not shared across processes
 * and is lost on restart. For production with multiple processes or containers,
 * implement {@link CacheProvider} with Redis or similar. See `docs/features/11.6.storage-adapters.md`.
 */
export class MemoryCache implements CacheProvider {
	private readonly store = new Map<string, CacheEntry<unknown>>();
	private readonly maxEntries: number;
	private readonly clock: Clock;

	/** Create a process-local cache with an optional clock and a default capacity of 1,000 entries. */
	constructor(options?: MemoryCacheOptions) {
		this.maxEntries = options?.maxEntries ?? 1000;
		this.clock = options?.clock ?? { now: () => Math.floor(Date.now() / 1000) };
	}

	/** Read a live entry and update its LRU position. Values are returned by reference. */
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

	/**
	 * Retain a value by reference until its TTL expires; evict the least-recently-used entry at
	 * capacity.
	 */
	async set<T>(key: string, value: T, ttlSeconds: number): Promise<void> {
		if (this.store.size >= this.maxEntries && !this.store.has(key)) {
			const firstKey = this.store.keys().next().value;
			if (firstKey !== undefined) {
				this.store.delete(firstKey);
			}
		}

		this.store.set(key, {
			value,
			expiresAt: this.clock.now() + ttlSeconds,
		});
	}

	async delete(key: string): Promise<void> {
		this.store.delete(key);
	}

	/** Remove all entries owned by this cache instance. */
	async clear(): Promise<void> {
		this.store.clear();
	}

	/** Dispose of this instance by clearing its entries. */
	async [Symbol.asyncDispose](): Promise<void> {
		await this.clear();
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

/** Derive a namespaced cache key from the exact Entity Identifier. */
export async function ecCacheKey(entityId: EntityId): Promise<string> {
	const hash = await sha256Hex(entityId);
	return CachePrefix.EntityConfiguration + hash.slice(0, 32);
}

/** Derive a namespaced Subordinate Statement cache key from its issuer and subject. */
export async function esCacheKey(issuer: EntityId, subject: EntityId): Promise<string> {
	const hash = await sha256Hex(`${issuer}:${subject}`);
	return CachePrefix.EntityStatement + hash.slice(0, 32);
}

/** Derive a namespaced trust chain cache key from its subject and selected anchor. */
export async function chainCacheKey(entityId: EntityId, trustAnchorId: EntityId): Promise<string> {
	const hash = await sha256Hex(`${entityId}:${trustAnchorId}`);
	return CachePrefix.TrustChain + hash.slice(0, 32);
}
