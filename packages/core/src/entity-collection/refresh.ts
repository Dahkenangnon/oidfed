import { DEFAULT_MAX_CHAIN_DEPTH, FederationErrorCode, InternalErrorCode } from "../constants.js";
import { err, ok, type Result } from "../errors.js";
import { fetchListSubordinates } from "../federation-api/index.js";
import { decodeEntityConfiguration, decodeEntityStatement } from "../jose/verify.js";
import {
	COLLECTION_INFO_CLAIMS,
	EntityCollectionEntitySchema,
	type EntityTypeInfo,
} from "../schemas/entity-collection.js";
import type { JWKSet } from "../schemas/jwk.js";
import { fetchEntityConfiguration, fetchSubordinateStatement } from "../trust-chain/fetch.js";
import { createConcurrencyLimiter, resolveTrustChains } from "../trust-chain/resolve.js";
import { validateTrustChain } from "../trust-chain/validate.js";
import {
	type CacheProvider,
	type EntityId,
	type FederationOptions,
	isValidEntityId,
	nowSeconds,
	type ValidatedTrustChain,
	type ValidatedTrustMark,
} from "../types.js";
import type { CollectionEntry, EntityCollectionConfig, EntityCollectionSnapshot } from "./types.js";

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
	const options: FederationOptions = {
		...config.options,
		maxTotalFetches: config.options?.maxTotalFetches ?? 1000,
		cache,
		signal: controller.signal,
		httpClient: async (url, init) =>
			limit(async () => {
				if (controller.signal.aborted || init?.signal?.aborted)
					throw new DOMException("Refresh aborted", "AbortError");
				if (++fetches > (config.options?.maxTotalFetches ?? 1000)) {
					exhausted = true;
					throw new Error("Collection fetch budget exhausted");
				}
				return http(url, { ...init, redirect: "manual" });
			}),
	};
	const configurations = new Map<EntityId, ReturnType<typeof fetchEntityConfiguration>>();
	const statements = new Map<string, ReturnType<typeof fetchSubordinateStatement>>();
	const listings = new Map<string, ReturnType<typeof fetchListSubordinates>>();
	const resolutions = new Map<EntityId, ReturnType<typeof resolveTrustChains>>();
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
	const issuerProofs = new Map<string, { keys: JWKSet; expiresAt: number }>();
	issuerProofs.set(anchor, { keys: pinned.jwks, expiresAt: Infinity });
	async function verifyPath(
		chain: readonly string[],
		resolving = new Set<string>(),
	): Promise<ValidatedTrustChain | undefined> {
		const decoded = decodeEntityConfiguration(chain[0] ?? "");
		if (!decoded.ok) return undefined;
		const subject = decoded.value.payload.sub;
		if (resolving.has(subject)) return undefined;
		const nextResolving = new Set(resolving).add(subject);
		const keys = new Map<string, JWKSet>();
		// These key bindings are trusted only if the entire path validates below.
		for (const jwt of chain) {
			const statement = decodeEntityStatement(jwt);
			if (statement.ok && statement.value.payload.jwks)
				keys.set(statement.value.payload.sub, statement.value.payload.jwks);
		}
		keys.set(anchor, pinned?.jwks as JWKSet);
		for (const ref of decoded.value.payload.trust_marks ?? []) {
			const mark = decodeEntityStatement(ref.trust_mark);
			if (!mark.ok || !isValidEntityId(mark.value.payload.iss)) continue;
			const issuer = mark.value.payload.iss;
			if (keys.has(issuer)) continue;
			let proof = issuerProofs.get(issuer);
			if (!proof && !nextResolving.has(issuer)) {
				let resolution = resolutions.get(issuer);
				if (!resolution) {
					resolution = resolveTrustChains(issuer, anchors, options);
					resolutions.set(issuer, resolution);
				}
				const paths = await resolution;
				if (
					paths.incomplete ||
					paths.errors.some(
						(error) =>
							error.code === InternalErrorCode.Network || error.code === InternalErrorCode.Timeout,
					)
				)
					throw new Error("Unable to resolve Trust Mark issuer");
				for (const candidate of paths.chains) {
					const verified = await verifyPath(candidate.statements, nextResolving);
					if (!verified) continue;
					const ec = decodeEntityConfiguration(candidate.statements[0] ?? "");
					if (ec.ok) {
						proof = {
							keys: ec.value.payload.jwks,
							expiresAt: Math.max(
								issuerProofs.get(issuer)?.expiresAt ?? -Infinity,
								verified.expiresAt,
							),
						};
						issuerProofs.set(issuer, proof);
					}
				}
			}
			if (proof) keys.set(issuer, proof.keys);
		}
		const checked = await validateTrustChain(chain, anchors, {
			...options,
			verboseErrors: true,
			trustMarkIssuerKeys: keys,
		});
		if (!checked.valid)
			options.logger?.debug("Excluded collection entity with an invalid chain", {
				subject,
				errors: checked.errors,
			});
		return checked.valid ? checked.chain : undefined;
	}
	try {
		const root = await configuration(anchor);
		if (!root.ok) return root;
		const rootChain = await verifyPath([root.value]);
		if (!rootChain)
			return err({
				code: FederationErrorCode.InvalidTrustChain,
				description: "Invalid collection Trust Anchor configuration",
			});
		const rootEc = decodeEntityConfiguration(root.value);
		if (!rootEc.ok) return rootEc;
		issuerProofs.set(anchor, { keys: pinned.jwks, expiresAt: rootChain.expiresAt });
		const queue = [{ id: anchor, chain: [root.value], depth: 0, path: [anchor] }];
		const traversed = new Set<string>();
		const entries = new Map<string, CollectionEntry>();
		const markEvidence = new Map<string, readonly ValidatedTrustMark[]>();
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
				const verified = await verifyPath(chain);
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
					options.logger?.debug("Excluded collection entity with invalid informational metadata", {
						entityId: id,
					});
					continue;
				}
				const previous = entries.get(id);
				entries.set(id, {
					entity: entity.data,
					chainExpiresAt: Math.max(previous?.chainExpiresAt ?? -Infinity, verified.expiresAt),
					verifiedMarks: [],
				});
				markEvidence.set(id, verified.trustMarks);
				issuerProofs.set(id, {
					keys: payload.jwks,
					expiresAt: Math.max(issuerProofs.get(id)?.expiresAt ?? -Infinity, verified.expiresAt),
				});
				queue.push({ id, chain, depth: node.depth + 1, path: [...node.path, id] });
			}
		}
		if (exhausted || controller.signal.aborted) throw new Error("Collection refresh incomplete");
		for (const [id, entry] of entries)
			entry.verifiedMarks = (markEvidence.get(id) ?? []).map((mark) => ({
				type: mark.trustMarkType,
				expiresAt: Math.min(
					mark.expiresAt ?? Infinity,
					mark.delegation?.expiresAt ?? Infinity,
					issuerProofs.get(mark.issuer)?.expiresAt ?? entry.chainExpiresAt,
					entry.chainExpiresAt,
				),
			}));
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
