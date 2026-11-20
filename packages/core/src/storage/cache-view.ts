import type { CacheStore, FederationStorage } from "./contracts.js";

/** Borrow the host repositories and replace only the cache for this operation. */
export function withOperationCache(
	storage: FederationStorage | undefined,
	cache: CacheStore,
): FederationStorage {
	if (!storage) return { namespace: "operation", capabilities: ["cache"], cache };
	const has = (capability: FederationStorage["capabilities"][number]) =>
		storage.capabilities.includes(capability);
	const capabilities = has("cache")
		? storage.capabilities
		: Object.freeze([...storage.capabilities, "cache"] as const);
	return Object.freeze({
		namespace: storage.namespace,
		capabilities,
		cache,
		...(storage.isolation ? { isolation: storage.isolation } : {}),
		...(has("subordinate:read") && storage.subordinate ? { subordinate: storage.subordinate } : {}),
		...(has("trustMark:read") && storage.trustMark ? { trustMark: storage.trustMark } : {}),
		...(has("subordinateEvent:read") && storage.subordinateEvent
			? { subordinateEvent: storage.subordinateEvent }
			: {}),
		...(has("entityCollection") && storage.entityCollection
			? { entityCollection: storage.entityCollection }
			: {}),
		...(has("replay") && storage.replay ? { replay: storage.replay } : {}),
		...(has("transaction") && storage.transaction
			? { transaction: storage.transaction.bind(storage) }
			: {}),
		...(has("snapshot") && storage.readSnapshot
			? { readSnapshot: storage.readSnapshot.bind(storage) }
			: {}),
		...(has("namespace") && storage.withNamespace
			? { withNamespace: storage.withNamespace.bind(storage) }
			: {}),
	});
}
