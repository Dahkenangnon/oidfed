/** Retrieval and caching for Entity Configurations and Subordinate Statements. */

import {
	DEFAULT_CACHE_TTL_SECONDS,
	FederationErrorCode,
	InternalErrorCode,
	WELL_KNOWN_OPENID_FEDERATION,
} from "../constants.js";
import { fetchFederationEndpoint } from "../endpoint-client.js";
import { err, type FederationError, ok, type Result } from "../errors.js";
import { performFetch } from "../http/fetch.js";
import { fetchFailure, httpFailureStatus } from "../http/fetch-failure.js";
import { decodeEntityStatement } from "../jose/verify.js";
import { safeLogger } from "../logging.js";
import { ecCacheKey, esCacheKey } from "../storage/cache.js";
import { StatementCacheValueSchema } from "../storage/cache-records.js";
import { getCacheStorage } from "../storage/capabilities.js";
import type { CacheStore } from "../storage/contracts.js";
import { type EntityId, type FederationOptions, isValidEntityId, nowSeconds } from "../types.js";

/** Validate Entity Identifier syntax without normalizing the identifier used in comparisons. */
export function validateEntityId(value: string): Result<EntityId, FederationError> {
	if (isValidEntityId(value)) {
		return ok(value);
	}
	return err({
		code: InternalErrorCode.Network,
		description: `Invalid entity ID: ${value}`,
	});
}

/** Decode only for cache lifetime (§10.2); callers still validate signatures and claims. */
function statementCacheTtl(jwt: string, options: FederationOptions): number {
	const decoded = decodeEntityStatement(jwt, options);
	const exp = decoded.ok ? decoded.value.payload.exp : undefined;
	if (typeof exp !== "number" || !Number.isFinite(exp)) return 0;
	const remaining = exp - nowSeconds(options?.clock);
	const ttl = Math.min(remaining, options?.cacheMaxTtlSeconds ?? DEFAULT_CACHE_TTL_SECONDS);
	return Number.isFinite(ttl) && ttl > 0 ? ttl : 0;
}

async function cachedStatement(
	cache: CacheStore,
	key: string,
	options: FederationOptions,
): Promise<string | undefined> {
	let cached: string | undefined;
	try {
		cached = await cache.get<string>(key);
	} catch (error) {
		safeLogger(options.logger)?.error("Failed to read the federation cache");
		throw error;
	}
	if (cached === undefined) return undefined;
	if (StatementCacheValueSchema.safeParse(cached).success && statementCacheTtl(cached, options) > 0)
		return cached;
	try {
		await cache.delete(key);
	} catch (error) {
		safeLogger(options.logger)?.error("Failed to delete an expired federation cache entry");
		throw error;
	}
	return undefined;
}

/** Cache only unexpired statements, propagating storage failures to the caller. */
async function cacheStatement(
	cache: CacheStore,
	key: string,
	jwt: string,
	options: FederationOptions,
): Promise<void> {
	const ttl = statementCacheTtl(jwt, options);
	if (ttl <= 0) return;
	try {
		await cache.set(key, jwt, ttl);
	} catch (error) {
		safeLogger(options.logger)?.error("Failed to write the federation cache");
		throw error;
	}
}

/** Construct the discovery URL from the exact Entity Identifier (Federation §9). */
export function entityConfigurationUrl(entityId: EntityId): string {
	const base = entityId.endsWith("/") ? entityId.slice(0, -1) : entityId;
	return `${base}${WELL_KNOWN_OPENID_FEDERATION}`;
}

/** Fetch an Entity Configuration using §9.1 GET discovery, without a Federation client assertion. */
export async function fetchEntityConfiguration(
	entityId: EntityId,
	options: FederationOptions,
): Promise<Result<string, FederationError>> {
	const url = entityConfigurationUrl(entityId);

	const cache = getCacheStorage(options?.storage);
	if (cache) {
		const cacheKey = await ecCacheKey(entityId, options.engine);
		const cached = await cachedStatement(cache, cacheKey, options);
		if (cached !== undefined) {
			safeLogger(options?.logger)?.debug("Cache hit for entity configuration");
			return ok(cached);
		}
	}

	safeLogger(options?.logger)?.debug("Fetching entity configuration");
	const result = await performFetch(url, {
		...options,
		method: "GET",
		expectedStatus: 200,
		federationErrors: true,
	});

	if (
		!result.ok &&
		result.error.code === InternalErrorCode.Network &&
		httpFailureStatus(result.error) === 404
	)
		return err(
			fetchFailure(
				{ code: FederationErrorCode.NotFound, description: "Entity Configuration not found" },
				{ kind: "http", status: 404 },
			),
		);

	if (result.ok && cache) {
		const cacheKey = await ecCacheKey(entityId, options.engine);
		await cacheStatement(cache, cacheKey, result.value, options);
	}

	return result;
}

export interface FetchSubordinateStatementOptions extends FederationOptions {
	/** Actual issuer identifier for isolating cached attestations when it is known. */
	issuer?: EntityId;
}

/** Fetch a Subordinate Statement about a subject from a superior's fetch endpoint. */
export async function fetchSubordinateStatement(
	fetchEndpoint: string,
	subject: EntityId,
	options: FetchSubordinateStatementOptions,
): Promise<Result<string, FederationError>> {
	let url: URL;
	try {
		url = new URL(fetchEndpoint);
	} catch (cause) {
		return err({
			code: InternalErrorCode.Network,
			description: `Invalid URL: ${fetchEndpoint}`,
			cause,
		});
	}

	const cache = getCacheStorage(options?.storage);
	if (cache) {
		const issuer = options.issuer ?? (url.origin as EntityId);
		const cacheKey = await esCacheKey(issuer, subject, options.engine);
		const cached = await cachedStatement(cache, cacheKey, options);
		if (cached !== undefined) {
			safeLogger(options?.logger)?.debug("Cache hit for subordinate statement");
			return ok(cached);
		}
	}

	safeLogger(options?.logger)?.debug("Fetching subordinate statement");
	const result = await fetchFederationEndpoint(
		url.toString(),
		new URLSearchParams({ sub: subject }),
		{
			...options,
			method: "GET",
			expectedStatus: 200,
			federationErrors: true,
		},
		options?.issuer,
	);

	if (
		!result.ok &&
		result.error.code === InternalErrorCode.Network &&
		httpFailureStatus(result.error) === 404
	)
		return err(
			fetchFailure(
				{ code: FederationErrorCode.NotFound, description: "Subordinate Statement not found" },
				{ kind: "http", status: 404 },
			),
		);

	if (result.ok && cache) {
		const issuer = options.issuer ?? (url.origin as EntityId);
		const cacheKey = await esCacheKey(issuer, subject, options.engine);
		await cacheStatement(cache, cacheKey, result.value, options);
	}

	return result;
}
