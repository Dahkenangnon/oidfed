import { assertStorageCapabilities } from "./capabilities.js";
import type { FederationStorage, StorageCapability } from "./contracts.js";

export interface FederationStorageParts {
	readonly base: FederationStorage;
	readonly entityCollection?: FederationStorage;
	readonly replay?: FederationStorage;
	readonly cache?: FederationStorage;
}

/**
 * Join repositories owned by separate backends in one logical namespace.
 * Transactional repositories and their snapshot boundary all come from the base.
 * The result borrows every client and never disposes any component.
 */
export function composeFederationStorage(parts: FederationStorageParts): FederationStorage {
	const { base } = parts;
	assertStorageCapabilities(base, [], "Storage composition base");
	const additions = {} as {
		[K in "entityCollection" | "replay" | "cache"]?: NonNullable<FederationStorage[K]>;
	};
	const capabilities: StorageCapability[] = base.capabilities.filter((cap) => cap !== "namespace");
	const bind = new Set([base]);
	function add<K extends keyof typeof additions>(
		key: K,
		part: FederationStorage | undefined,
	): void {
		if (!part) return;
		assertStorageCapabilities(part, [key], "Storage composition");
		if (part === base) return;
		if (part.namespace !== base.namespace)
			throw new TypeError(`Storage namespaces differ for ${key}`);
		if (capabilities.includes(key)) throw new TypeError(`More than one storage part owns ${key}`);
		additions[key] = part[key] as NonNullable<FederationStorage[K]>;
		capabilities.push(key);
		bind.add(part);
	}
	add("entityCollection", parts.entityCollection);
	add("replay", parts.replay);
	add("cache", parts.cache);

	const withNamespace = [...bind].every((part) => part.capabilities.includes("namespace"))
		? (namespace: string) => {
				const rebound = new Map<FederationStorage, FederationStorage>();
				for (const part of bind) {
					assertStorageCapabilities(part, ["namespace"], "Storage rebind");
					const selected = part.withNamespace(namespace);
					if (selected.namespace !== namespace)
						throw new TypeError("Rebound storage has the wrong namespace");
					rebound.set(part, selected);
				}
				const selectedBase = rebound.get(base);
				if (!selectedBase) throw new TypeError("Missing rebound base storage");
				const extra: Partial<FederationStorageParts> = {};
				for (const key of ["entityCollection", "replay", "cache"] as const) {
					const part = parts[key];
					if (!part) continue;
					const selected = rebound.get(part);
					if (!selected) throw new TypeError(`Missing rebound storage for ${key}`);
					Object.assign(extra, { [key]: selected });
				}
				return composeFederationStorage({ ...extra, base: selectedBase });
			}
		: undefined;
	if (withNamespace) capabilities.push("namespace");
	const declared = (capability: StorageCapability) => base.capabilities.includes(capability);
	const subordinate = declared("subordinate:read") ? base.subordinate : undefined;
	const trustMark = declared("trustMark:read") ? base.trustMark : undefined;
	const subordinateEvent = declared("subordinateEvent:read") ? base.subordinateEvent : undefined;
	return Object.freeze({
		namespace: base.namespace,
		capabilities: Object.freeze(capabilities),
		...(base.isolation ? { isolation: base.isolation } : {}),
		...(subordinate
			? {
					subordinate: declared("subordinate:write")
						? subordinate
						: {
								fetch: subordinate.fetch.bind(subordinate),
								list: subordinate.list.bind(subordinate),
							},
				}
			: {}),
		...(trustMark
			? {
					trustMark: declared("trustMark:write")
						? trustMark
						: {
								revision: trustMark.revision.bind(trustMark),
								candidates: trustMark.candidates.bind(trustMark),
								valid: trustMark.valid.bind(trustMark),
								status: trustMark.status.bind(trustMark),
								listSubjects: trustMark.listSubjects.bind(trustMark),
								forSubject: trustMark.forSubject.bind(trustMark),
								hasAny: trustMark.hasAny.bind(trustMark),
							},
				}
			: {}),
		...(subordinateEvent
			? {
					subordinateEvent: declared("subordinateEvent:write")
						? subordinateEvent
						: {
								history: subordinateEvent.history.bind(subordinateEvent),
							},
				}
			: {}),
		...(declared("entityCollection") && base.entityCollection
			? { entityCollection: base.entityCollection }
			: {}),
		...(declared("replay") && base.replay ? { replay: base.replay } : {}),
		...(declared("cache") && base.cache ? { cache: base.cache } : {}),
		...(declared("transaction") && base.transaction
			? { transaction: base.transaction.bind(base) }
			: {}),
		...(declared("snapshot") && base.readSnapshot
			? { readSnapshot: base.readSnapshot.bind(base) }
			: {}),
		...(withNamespace ? { withNamespace } : {}),
		...additions,
	});
}
