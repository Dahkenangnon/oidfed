import type { EntityCollectionStore } from "./collection.js";
import type { ReplayStore } from "./replay-store.js";
import type {
	SubordinateEventReadStore,
	SubordinateEventStore,
	SubordinateReadStore,
	SubordinateStore,
} from "./subordinates.js";
import type {
	TrustMarkReadStore,
	TrustMarkStore,
	TrustMarkTransactionStore,
} from "./trust-mark.js";

/** Cache values are detached JSON data. TTLs are durations in seconds. */
export interface CacheStore {
	get<T>(key: string): Promise<T | undefined>;
	set<T>(key: string, value: T, ttlSeconds: number): Promise<void>;
	delete(key: string): Promise<void>;
	clear(): Promise<void>;
}

export type StorageCapability =
	| "subordinate:read"
	| "subordinate:write"
	| "trustMark:read"
	| "trustMark:write"
	| "subordinateEvent:read"
	| "subordinateEvent:write"
	| "entityCollection"
	| "replay"
	| "cache"
	| "transaction"
	| "snapshot"
	| "namespace";

/** Detached, read-only repositories valid for one consistent read callback. */
export interface ReadSnapshotView {
	readonly subordinate?: SubordinateReadStore;
	readonly trustMark?: TrustMarkReadStore;
	readonly subordinateEvent?: SubordinateEventReadStore;
}

/** Namespace-local repositories valid for one serializable write attempt. */
export interface TransactionView extends ReadSnapshotView {
	readonly subordinate?: SubordinateReadStore | SubordinateStore;
	readonly trustMark?: TrustMarkReadStore | TrustMarkTransactionStore;
	readonly subordinateEvent?: SubordinateEventReadStore | SubordinateEventStore;
}

/**
 * Storage supplied by a host. Transaction callbacks may run again after a known abort.
 * Callbacks use only their scoped repositories and keep external effects outside the transaction.
 */
export interface FederationStorage {
	/** Stable logical scope. All replicas serving one entity use the same scope. */
	readonly namespace: string;
	/** Declare only implemented repositories and guarantees. */
	readonly capabilities: readonly StorageCapability[];
	readonly isolation?: "serializable";
	readonly subordinate?: SubordinateReadStore | SubordinateStore;
	readonly trustMark?: TrustMarkReadStore | TrustMarkStore;
	readonly subordinateEvent?: SubordinateEventReadStore | SubordinateEventStore;
	readonly entityCollection?: EntityCollectionStore;
	readonly replay?: ReplayStore;
	readonly cache?: CacheStore;
	/** Rebind using borrowed resources and separate state for the requested namespace. */
	withNamespace?(namespace: string): FederationStorage;
	/** Commit all awaited callback writes, or roll them back when the callback rejects. */
	transaction?<T>(operation: (view: TransactionView) => Promise<T>): Promise<T>;
	/** Borrow a coherent snapshot spanning the declared record repositories. */
	readSnapshot?<T>(operation: (view: ReadSnapshotView) => Promise<T>): Promise<T>;
	/** Release resources owned by this handle. Do not close supplied clients. */
	[Symbol.asyncDispose]?(): Promise<void>;
}
