import type { CryptoEngine } from "@oidfed/crypto";
import { createConcurrencyLimiter } from "../async-operation.js";
import { cloneData } from "../data-copy.js";
import type { Clock } from "../types.js";
import { MemoryCache } from "./cache.js";
import { assertStorageCapabilities, runScoped } from "./capabilities.js";
import type { EntityCollectionStore, MemoryEntityCollectionStoreOptions } from "./collection.js";
import { MemoryEntityCollectionStore } from "./collection-memory.js";
import type {
	CacheStore,
	FederationStorage,
	ReadSnapshotView,
	StorageCapability,
	TransactionView,
} from "./contracts.js";
import {
	MemorySubordinateEventStore,
	MemorySubordinateStore,
	type RecordState,
	type StateMutation,
	type StateReader,
	trustMarkRecords,
} from "./record-memory.js";
import type { StorageValidationOptions } from "./record-schemas.js";
import { MemoryReplayStore } from "./replay-memory.js";
import type { ReplayStore } from "./replay-store.js";
import type { TrustMarkStore } from "./trust-mark.js";
import { MemoryTrustMarkStorage } from "./trust-mark-memory.js";

export interface MemoryFederationStorageOptions extends StorageValidationOptions {
	readonly namespace: string;
	/** Select explicit capabilities. Omission enables every in-memory repository. */
	readonly capabilities?: readonly StorageCapability[];
	readonly clock?: Clock;
	/** Optional digest engine for bounded-size in-memory replay keys. */
	readonly engine?: CryptoEngine;
	readonly maxReplayEntries?: number;
	readonly maxCacheEntries?: number;
	readonly maxCompactBytes?: number;
	readonly collection?: Omit<MemoryEntityCollectionStoreOptions, "clock">;
}

const defaultCapabilities: readonly StorageCapability[] = Object.freeze([
	"subordinate:read",
	"subordinate:write",
	"trustMark:read",
	"trustMark:write",
	"subordinateEvent:read",
	"subordinateEvent:write",
	"entityCollection",
	"replay",
	"cache",
	"transaction",
	"snapshot",
	"namespace",
]);

function trustMarkRepository(
	read: StateReader,
	mutate: StateMutation,
	options: StorageValidationOptions,
): TrustMarkStore {
	const records = new MemoryTrustMarkStorage(
		() => trustMarkRecords(read()),
		(op) =>
			mutate((state) => {
				if (op(trustMarkRecords(state))) state.trustMarkRevision++;
			}),
		options,
	);
	return {
		candidates: records.candidates.bind(records),
		status: records.status.bind(records),
		valid: records.valid.bind(records),
		listSubjects: records.listSubjects.bind(records),
		forSubject: records.forSubject.bind(records),
		hasAny: records.hasAny.bind(records),
		issue: records.issue.bind(records),
		revoke: records.revoke.bind(records),
		revokeExact: records.revokeExact.bind(records),
		revision: async () => read().trustMarkRevision.toString(),
	};
}

function collectionRepository(options: MemoryFederationStorageOptions): EntityCollectionStore {
	return new MemoryEntityCollectionStore({
		...options.collection,
		...(options.clock ? { clock: options.clock } : {}),
	});
}

/**
 * Process-local implementation for development, tests, and single-instance deployments
 * that can tolerate data loss on restart. Rebound handles share only matching namespaces.
 */
export class MemoryFederationStorage implements FederationStorage {
	readonly namespace: string;
	readonly capabilities: readonly StorageCapability[];
	readonly isolation?: "serializable";
	readonly subordinate?: NonNullable<FederationStorage["subordinate"]>;
	readonly trustMark?: NonNullable<FederationStorage["trustMark"]>;
	readonly subordinateEvent?: NonNullable<FederationStorage["subordinateEvent"]>;
	readonly entityCollection?: EntityCollectionStore;
	readonly replay?: ReplayStore;
	readonly cache?: CacheStore;
	readonly transaction?: NonNullable<FederationStorage["transaction"]>;
	readonly readSnapshot?: NonNullable<FederationStorage["readSnapshot"]>;
	readonly withNamespace?: NonNullable<FederationStorage["withNamespace"]>;

	constructor(options: MemoryFederationStorageOptions) {
		this.namespace = options.namespace;
		this.capabilities = Object.freeze([...(options.capabilities ?? defaultCapabilities)]);
		const has = (capability: StorageCapability) => this.capabilities.includes(capability);
		const exclusive = createConcurrencyLimiter(1);
		let state: RecordState = {
			subordinates: new Map(),
			trustMarkRevision: 0n,
			...(has("trustMark:read") ? { trustMarks: new Map() } : {}),
			...(has("subordinateEvent:read") ? { subordinateEvents: new Map() } : {}),
		};
		const repositories = (
			read: StateReader,
			mutate: StateMutation,
			writable: boolean,
			transaction = false,
		): TransactionView => {
			const view: { -readonly [K in keyof TransactionView]: TransactionView[K] } = {};
			if (has("subordinate:read")) {
				const records = new MemorySubordinateStore(read, mutate, options);
				view.subordinate = {
					fetch: records.fetch.bind(records),
					list: records.list.bind(records),
					...(writable && has("subordinate:write")
						? {
								register: records.register.bind(records),
								update: records.update.bind(records),
								remove: records.remove.bind(records),
							}
						: {}),
				};
			}
			if (has("trustMark:read")) {
				const { issue, revoke, revokeExact, ...queries } = trustMarkRepository(
					read,
					mutate,
					options,
				);
				view.trustMark = {
					...queries,
					...(writable && has("trustMark:write")
						? {
								issue,
								revoke,
								...(revokeExact ? { revokeExact } : {}),
								...(transaction
									? {
											checkRevision: async (expected: string) =>
												(await queries.revision()) === expected,
										}
									: {}),
							}
						: {}),
				};
			}
			if (has("subordinateEvent:read")) {
				const events = new MemorySubordinateEventStore(read, mutate);
				view.subordinateEvent = {
					history: events.history.bind(events),
					...(writable && has("subordinateEvent:write")
						? { append: events.append.bind(events) }
						: {}),
				};
			}
			return view;
		};
		Object.assign(
			this,
			repositories(
				() => state,
				(op) => exclusive(async () => op(state)),
				true,
			),
		);
		if (has("cache"))
			this.cache = new MemoryCache({
				...(options.clock ? { clock: options.clock } : {}),
				...(options.maxCacheEntries !== undefined ? { maxEntries: options.maxCacheEntries } : {}),
			});
		if (has("replay"))
			this.replay = new MemoryReplayStore({
				...(options.engine ? { engine: options.engine } : {}),
				...(options.clock ? { clock: options.clock } : {}),
				...(options.maxReplayEntries !== undefined ? { maxEntries: options.maxReplayEntries } : {}),
			});
		if (has("entityCollection")) this.entityCollection = collectionRepository(options);
		if (has("transaction")) {
			this.isolation = "serializable";
			this.transaction = <T>(operation: (view: TransactionView) => Promise<T>): Promise<T> =>
				exclusive(async () => {
					const draft = cloneData(state);
					const view = repositories(
						() => draft,
						async (op) => op(draft),
						true,
						true,
					);
					const result = await runScoped(this, view, true, operation, undefined, false);
					state = draft;
					return result;
				});
		}
		if (has("snapshot")) {
			this.readSnapshot = async <T>(
				operation: (view: ReadSnapshotView) => Promise<T>,
			): Promise<T> => {
				const snapshot = await exclusive(async () => cloneData(state));
				const view = repositories(
					() => snapshot,
					async () => {
						throw new Error("Storage snapshot is read-only");
					},
					false,
				);
				return runScoped(this, view, false, operation, undefined, false);
			};
		}
		if (has("namespace")) {
			const namespaces = new Map<string, FederationStorage>([[this.namespace, this]]);
			const withNamespace = (namespace: string): FederationStorage => {
				const existing = namespaces.get(namespace);
				if (existing) return existing;
				const handle = new MemoryFederationStorage({
					...options,
					capabilities: this.capabilities,
					namespace,
				});
				const bound = Object.assign(handle, { withNamespace });
				namespaces.set(namespace, bound);
				return bound;
			};
			this.withNamespace = withNamespace;
		}
		assertStorageCapabilities(this, []);
	}
}
