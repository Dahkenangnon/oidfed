import { z } from "zod";
import { DEFAULT_MAX_CHAIN_DEPTH, FederationErrorCode } from "../constants.js";
import { err, ok, type Result } from "../errors.js";
import { fetchListSubordinates } from "../federation-api/index.js";
import { decodeEntityConfiguration } from "../jose/verify.js";
import {
	COLLECTION_INFO_CLAIMS,
	EntityCollectionEntitySchema,
	type EntityTypeInfo,
} from "../schemas/entity-collection.js";
import type { EntityConfigurationPayload } from "../schemas/entity-statement.js";
import { fetchEntityConfiguration, fetchSubordinateStatement } from "../trust-chain/fetch.js";
import { createConcurrencyLimiter } from "../trust-chain/resolve.js";
import { validateTrustMarkReferenceSyntax } from "../trust-chain/validate.js";
import {
	type CacheProvider,
	type EntityId,
	type FederationOptions,
	type HttpClient,
	isValidEntityId,
	nowSeconds,
} from "../types.js";
import { createCollectionEvidence } from "./evidence.js";
import type {
	CollectionEntry,
	EntityCollectionCollectorContext,
	EntityCollectionConfig,
	EntityCollectionSnapshot,
} from "./types.js";

const MAX_OPEN_ISSUER_FETCHES = 50;
const MAX_OPEN_ISSUER_TOTAL_FETCHES = 100;

function informationalMetadata(
	metadata: Record<string, Record<string, unknown>>,
): Record<string, EntityTypeInfo> {
	return Object.fromEntries(
		Object.entries(metadata).map(([type, values]) => {
			const info: Record<string, unknown> = Object.fromEntries(
				Object.entries(values).filter(([name]) =>
					(COLLECTION_INFO_CLAIMS as readonly string[]).includes(name.split("#")[0] ?? ""),
				),
			);
			const fallback =
				type === "openid_relying_party" || type === "oauth_client"
					? "client_name"
					: type === "oauth_resource"
						? "resource_name"
						: undefined;
			if (fallback)
				for (const [name, value] of Object.entries(values)) {
					if (name !== fallback && !name.startsWith(`${fallback}#`)) continue;
					const target = `display_name${name.slice(fallback.length)}`;
					if (!Object.hasOwn(info, target)) info[target] = value;
				}
			return [type, info];
		}),
	);
}

function freeze<T>(value: T): T {
	if (value && typeof value === "object") {
		for (const child of Object.values(value)) freeze(child);
		Object.freeze(value);
	}
	return value;
}

/** Settle cancellation independently of application callbacks that ignore their signal. */
function callback<T>(run: () => T | Promise<T>, signal: AbortSignal): Promise<T> {
	return new Promise((resolve, reject) => {
		const abort = () => {
			signal.removeEventListener("abort", abort);
			reject(new DOMException("Refresh aborted", "AbortError"));
		};
		if (signal.aborted) return abort();
		signal.addEventListener("abort", abort, { once: true });
		Promise.resolve()
			.then(() => {
				if (signal.aborted) throw new DOMException("Refresh aborted", "AbortError");
				return run();
			})
			.then(
				(value) => {
					signal.removeEventListener("abort", abort);
					resolve(value);
				},
				(error) => {
					signal.removeEventListener("abort", abort);
					reject(error);
				},
			);
	});
}

const candidateSchema = z.strictObject({
	entity: EntityCollectionEntitySchema,
	expiresAt: z.number().finite(),
});

/** Build outside storage, then let the caller publish the complete result atomically. */
export async function buildCollectionSnapshot(
	anchor: EntityId,
	config: EntityCollectionConfig,
	signal?: AbortSignal,
): Promise<Result<EntityCollectionSnapshot>> {
	const pinned = config.trustAnchors.get(anchor);
	if (!pinned)
		return err({
			code: FederationErrorCode.InvalidTrustAnchor,
			description: "Unsupported collection Trust Anchor",
		});
	const anchors = new Map([[anchor, pinned]]);
	let exhausted = false;
	let fetches = 0;
	let openIssuerFetches = 0;
	const maxFetches = config.options?.maxTotalFetches ?? 1000;
	const http = config.options?.httpClient ?? fetch;
	const controller = new AbortController();
	const limit = createConcurrencyLimiter(
		config.options?.maxConcurrentFetches ?? 6,
		controller.signal,
	);
	const abort = () => controller.abort();
	for (const source of [signal, config.options?.signal]) {
		if (source?.aborted) controller.abort();
		source?.addEventListener("abort", abort, { once: true });
	}
	// Freeze the first cache value seen during this refresh, including shared-cache hits.
	const frozen = new Map<string, unknown>();
	const cache: CacheProvider = {
		async get<T>(key: string): Promise<T | undefined> {
			if (frozen.has(key)) return frozen.get(key) as T;
			const value = await config.options?.cache?.get<T>(key);
			if (value !== undefined) frozen.set(key, value);
			return value;
		},
		async set<T>(key: string, value: T, ttl: number): Promise<void> {
			if (!frozen.has(key)) frozen.set(key, value);
			await config.options?.cache?.set(key, value, ttl);
		},
		async delete(key) {
			frozen.delete(key);
		},
		async clear() {
			frozen.clear();
		},
		async [Symbol.asyncDispose]() {
			frozen.clear();
		},
	};
	function createHttpClient(openIssuer = false): HttpClient {
		let issuerFetches = 0;
		return async (url, init) =>
			limit(async () => {
				if (controller.signal.aborted || init?.signal?.aborted)
					throw new DOMException("Refresh aborted", "AbortError");
				// Optional proofs stop before they can abort the refresh-wide controller.
				if (openIssuer) {
					if (
						issuerFetches >= MAX_OPEN_ISSUER_FETCHES ||
						openIssuerFetches >= MAX_OPEN_ISSUER_TOTAL_FETCHES ||
						fetches >= maxFetches
					)
						throw new Error("Open Trust Mark issuer fetch allowance exhausted");
					issuerFetches++;
					openIssuerFetches++;
				}
				if (++fetches > maxFetches) {
					exhausted = true;
					controller.abort();
					throw new Error("Collection fetch budget exhausted");
				}
				return http(url, {
					...init,
					signal: init?.signal ?? controller.signal,
					redirect: "manual",
				});
			});
	}
	const options: FederationOptions = {
		...config.options,
		maxTotalFetches: maxFetches,
		cache,
		signal: controller.signal,
		httpClient: createHttpClient(),
	};
	const configurations = new Map<EntityId, ReturnType<typeof fetchEntityConfiguration>>();
	const statements = new Map<string, ReturnType<typeof fetchSubordinateStatement>>();
	const listings = new Map<string, ReturnType<typeof fetchListSubordinates>>();
	function configuration(id: EntityId) {
		let pending = configurations.get(id);
		if (!pending) {
			pending = fetchEntityConfiguration(id, options);
			configurations.set(id, pending);
		}
		return pending;
	}
	function statement(issuer: EntityId, endpoint: string, subject: EntityId) {
		const key = JSON.stringify([issuer, endpoint, subject]);
		let pending = statements.get(key);
		if (!pending) {
			pending = fetchSubordinateStatement(endpoint, subject, { ...options, issuer });
			statements.set(key, pending);
		}
		return pending;
	}
	function listing(issuer: EntityId, endpoint: string) {
		const key = JSON.stringify([issuer, endpoint]);
		let pending = listings.get(key);
		if (!pending) {
			pending = fetchListSubordinates(endpoint, undefined, options);
			listings.set(key, pending);
		}
		return pending;
	}
	const evidence = createCollectionEvidence(anchor, anchors, options, configuration, () => ({
		...options,
		maxTotalFetches: MAX_OPEN_ISSUER_FETCHES,
		httpClient: createHttpClient(true),
	}));
	const context: EntityCollectionCollectorContext = Object.freeze({
		trustAnchor: anchor,
		trustAnchorJwks: freeze(structuredClone(pinned.jwks)),
		options: Object.freeze({ ...options }),
		signal: controller.signal,
	});
	try {
		const entries = new Map<string, CollectionEntry>();
		const publications = new Map<string, EntityConfigurationPayload>();
		const collector = config.collector;
		if (collector) {
			const supplied = await callback(() => collector(context), controller.signal);
			if (!supplied.ok) return supplied;
			if (!Array.isArray(supplied.value) || supplied.value.length > (config.maxEntities ?? 10000))
				throw new Error("Invalid or oversized collection candidate set");
			for (const input of supplied.value) {
				const candidate = candidateSchema.parse(input);
				JSON.stringify(candidate.entity);
				const errors: Parameters<typeof validateTrustMarkReferenceSyntax>[0] = [];
				validateTrustMarkReferenceSyntax(errors, candidate.entity.trust_marks, 0);
				if (errors.length || entries.has(candidate.entity.entity_id))
					throw new Error("Invalid or duplicate collection candidate");
				entries.set(candidate.entity.entity_id, {
					...structuredClone(candidate),
					verifiedMarks: [],
				});
			}
		} else {
			const root = await evidence.root();
			if (!root.ok) return root;
			const queue = [{ id: anchor, chain: [root.value.jwt], depth: 0, path: [anchor] }];
			const traversed = new Set<string>();
			let examined = 0;
			for (let index = 0; index < queue.length; index++) {
				if (controller.signal.aborted) throw new DOMException("Refresh aborted", "AbortError");
				const node = queue[index];
				if (!node) continue;
				const pathKey = JSON.stringify(node.path);
				if (traversed.has(pathKey)) continue;
				traversed.add(pathKey);
				const decoded = decodeEntityConfiguration(node.chain[0] ?? "");
				if (!decoded.ok) throw new Error("Invalid authority configuration");
				const meta = decoded.value.payload.metadata?.federation_entity;
				if (!meta?.federation_list_endpoint) continue;
				if (!meta.federation_fetch_endpoint)
					throw new Error("Authority does not publish a fetch endpoint");
				const list = await listing(node.id, meta.federation_list_endpoint);
				if (!list.ok) return list;
				for (const id of new Set(list.value)) {
					if (!isValidEntityId(id)) throw new Error("Invalid subordinate identifier in listing");
					if (node.path.includes(id)) continue;
					if (++examined > (config.maxEntities ?? 10000))
						throw new Error("Collection entity budget exhausted");
					if (node.depth >= (options.maxChainDepth ?? DEFAULT_MAX_CHAIN_DEPTH))
						throw new Error("Collection traversal depth exceeded");
					const childEc = await configuration(id);
					if (!childEc.ok) return childEc;
					const ss = await statement(node.id, meta.federation_fetch_endpoint, id);
					if (!ss.ok) return ss;
					const chain = [
						childEc.value,
						ss.value,
						...(node.id === anchor ? node.chain : node.chain.slice(1)),
					];
					const verified = await evidence.validatePath(chain);
					if (!verified) continue;
					const child = decodeEntityConfiguration(childEc.value);
					if (!child.ok || (child.value.payload.sub as string) !== (id as string)) continue;
					const payload = child.value.payload;
					const metadata = (payload.metadata ?? {}) as Record<string, Record<string, unknown>>;
					const entity = EntityCollectionEntitySchema.safeParse({
						entity_id: id,
						entity_types: Object.keys(metadata),
						entity_infos: informationalMetadata(metadata),
						...(payload.trust_marks ? { trust_marks: payload.trust_marks } : {}),
					});
					if (!entity.success) {
						options.logger?.debug(
							"Excluded collection entity with invalid informational metadata",
							{
								entityId: id,
							},
						);
						continue;
					}
					const previous = entries.get(id);
					entries.set(id, {
						entity: entity.data,
						expiresAt: Math.max(previous?.expiresAt ?? -Infinity, verified.expiresAt),
						chainExpiresAt: Math.max(previous?.chainExpiresAt ?? -Infinity, verified.expiresAt),
						verifiedMarks: [],
					});
					publications.set(id, payload);
					queue.push({ id, chain, depth: node.depth + 1, path: [...node.path, id] });
				}
			}
		}
		for (const [id, entry] of entries) {
			if (entry.expiresAt <= nowSeconds(options.clock)) {
				entries.delete(id);
				continue;
			}
			await evidence.verifyMarks(entry, publications.get(id));
		}
		// Finish mandatory publication and explicit issuer checks before optional discovery.
		for (const [id, entry] of entries) {
			await evidence.verifyMarks(entry, publications.get(id), true);
			const filter = config.filter;
			if (filter) {
				const decision = await callback(
					() => filter(freeze(structuredClone(entry)), context),
					controller.signal,
				);
				if (decision === false) {
					entries.delete(id);
					continue;
				}
				if (decision !== true) {
					const parsed = z.strictObject({ expiresAt: z.number().finite() }).parse(decision);
					entry.expiresAt = Math.min(entry.expiresAt, parsed.expiresAt);
					entry.verifiedMarks = entry.verifiedMarks.map((mark) => ({
						...mark,
						expiresAt: Math.min(mark.expiresAt, entry.expiresAt),
					}));
				}
			}
			if (entry.expiresAt <= nowSeconds(options.clock)) entries.delete(id);
		}
		if (exhausted || controller.signal.aborted) throw new Error("Collection refresh incomplete");
		return ok({
			id: crypto.randomUUID(),
			trustAnchor: anchor,
			lastUpdated: nowSeconds(options.clock),
			entries: [...entries.values()].sort((a, b) =>
				a.entity.entity_id < b.entity.entity_id
					? -1
					: a.entity.entity_id > b.entity.entity_id
						? 1
						: 0,
			),
		});
	} catch (cause) {
		return err({
			code: FederationErrorCode.TemporarilyUnavailable,
			description: "Collection refresh could not be completed",
			cause,
		});
	} finally {
		for (const source of [signal, config.options?.signal])
			source?.removeEventListener("abort", abort);
	}
}
