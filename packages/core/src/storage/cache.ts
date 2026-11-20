import type { CryptoEngine } from "@oidfed/crypto";
import { sha256Hex } from "../crypto-runtime.js";
import type { CacheStore } from "./contracts.js";
import { StorageJsonSchema } from "./record-schemas.js";

/** In-memory TTL caching and deterministic cache keys for federation evidence. */

import { CachePrefix } from "../constants.js";
import { assertPositiveTtlSeconds } from "../ttl.js";
import { type Clock, type EntityId, nowSeconds } from "../types.js";

interface CacheEntry {
	json: string;
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
 * supply a shared {@link CacheStore}. See `docs/features/11.6.storage-adapters.md`.
 */
export class MemoryCache implements CacheStore {
	private readonly store = new Map<string, CacheEntry>();
	private readonly maxEntries: number;
	private readonly clock: Clock;

	/** Create a process-local cache with an optional clock and a default capacity of 1,000 entries. */
	constructor(options?: MemoryCacheOptions) {
		this.maxEntries = options?.maxEntries ?? 1000;
		if (!Number.isSafeInteger(this.maxEntries) || this.maxEntries <= 0)
			throw new RangeError("maxEntries must be a positive safe integer");
		this.clock = options?.clock ?? { now: () => Math.floor(Date.now() / 1000) };
	}

	/** Read a detached live entry and update its LRU position. */
	async get<T>(key: string): Promise<T | undefined> {
		const entry = this.store.get(key);
		if (!entry) return undefined;

		if (nowSeconds(this.clock) >= entry.expiresAt) {
			this.store.delete(key);
			return undefined;
		}

		// LRU: move to end by re-inserting
		this.store.delete(key);
		this.store.set(key, entry);

		return JSON.parse(entry.json) as T;
	}

	/**
	 * Retain a detached JSON value until its TTL expires; evict the least-recently-used entry at
	 * capacity.
	 */
	async set<T>(key: string, value: T, ttlSeconds: number): Promise<void> {
		assertPositiveTtlSeconds(ttlSeconds, "Cache TTL", "finite");
		if (typeof key !== "string" || !StorageJsonSchema.safeParse(value).success)
			throw new TypeError("Cache keys must be strings and values must be JSON data");
		const json = JSON.stringify(value);
		const expiresAt = nowSeconds(this.clock) + ttlSeconds;
		if (!Number.isFinite(expiresAt)) throw new RangeError("Cache expiry must be finite");
		if (this.store.size >= this.maxEntries && !this.store.has(key)) {
			const firstKey = this.store.keys().next().value;
			if (firstKey !== undefined) {
				this.store.delete(firstKey);
			}
		}

		this.store.set(key, {
			json,
			expiresAt,
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

/** Derive a namespaced cache key from the exact Entity Identifier. */
export async function ecCacheKey(entityId: EntityId, engine: CryptoEngine): Promise<string> {
	const hash = await sha256Hex(entityId, engine);
	return CachePrefix.EntityConfiguration + hash.slice(0, 32);
}

/** Derive a namespaced Subordinate Statement cache key from its issuer and subject. */
export async function esCacheKey(
	issuer: EntityId,
	subject: EntityId,
	engine: CryptoEngine,
): Promise<string> {
	const hash = await sha256Hex(`${issuer}:${subject}`, engine);
	return CachePrefix.EntityStatement + hash.slice(0, 32);
}

/** Derive a namespaced trust chain cache key from its subject and selected anchor. */
export async function chainCacheKey(
	entityId: EntityId,
	trustAnchorId: EntityId,
	engine: CryptoEngine,
): Promise<string> {
	const hash = await sha256Hex(`${entityId}:${trustAnchorId}`, engine);
	return CachePrefix.TrustChain + hash.slice(0, 32);
}
