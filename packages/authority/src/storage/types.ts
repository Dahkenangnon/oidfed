/** Unified authority persistence contracts. */
import type {
	CacheProvider,
	EntityCollectionStore,
	EntityId,
	EntityStatementExtensions,
	EntityTypeIdentifier,
	JWKSet,
	ReplayStore,
	SubordinateEvent,
	TrustChainConstraints,
	TrustMarkStorage,
} from "@oidfed/core";

export interface StorageAdapter {
	readonly collections?: EntityCollectionStore;
	readonly subordinateEvents?: SubordinateEventStorage;
	readonly subordinates: SubordinateStorage;
	readonly trustMarks?: TrustMarkStorage;
	readonly replay?: ReplayStore;
	readonly cache?: CacheProvider;
	/** Commit callback writes atomically, or roll them back on failure. Use only tx repositories: awaiting a parent queued mutation inside the callback can deadlock. */
	transaction<T>(operation: (tx: StorageTransaction) => Promise<T>): Promise<T>;
	/** Read one consistent, detached view. Use only supplied repositories; do not await parent writes from inside the callback. */
	readSnapshot?<T>(operation: (snapshot: StorageReadSnapshot) => Promise<T>): Promise<T>;
}

/** Read-only views return detached records and expose no mutation methods. */
export interface StorageReadSnapshot {
	readonly trustMarks?: Pick<TrustMarkStorage, "listCandidates" | "getByJwt">;
	readonly subordinates: Pick<SubordinateStorage, "get" | "list">;
	readonly subordinateEvents?: Pick<SubordinateEventStorage, "list">;
}

export interface StorageTransaction {
	readonly subordinateEvents?: SubordinateEventStorage;
	readonly subordinates: SubordinateStorage;
	readonly trustMarks?: TrustMarkStorage;
}

export interface SubordinateStorage {
	/** Return a detached record; changing it does not update storage. */
	get(entityId: EntityId): Promise<SubordinateRecord | undefined>;
	/**
	 * Return matching records ordered lexicographically by entityId; cursors are inclusive.
	 * A filtered page may be empty with a continuation. Without options, return all matches.
	 */
	list(filter?: ListFilter, options?: ListPageOptions): Promise<ListPage>;
	/** Capture and validate input before queuing. Reject duplicate identifiers. */
	add(record: SubordinateRecord): Promise<void>;
	/** Capture changes before queuing, then merge and validate against the current record inside the write transaction. Reject unknown identifiers. */
	update(entityId: EntityId, updates: SubordinateRecordUpdate): Promise<void>;
	remove(entityId: EntityId): Promise<void>;
}

export interface ListPageOptions {
	/** EntityId of the first record to return. */
	cursor?: EntityId;
	limit?: number;
	updatedAfter?: number;
	updatedBefore?: number;
}

export interface ListPage {
	readonly items: SubordinateRecord[];
	/**
	 * First unreturned position, strictly after the incoming cursor and returned records.
	 * May accompany an empty page. Omission means the scan is exhausted.
	 */
	readonly nextCursor?: EntityId;
}

export interface SubordinateRecord extends EntityStatementExtensions {
	/** Immutable entity identifier. */
	readonly entityId: EntityId;
	readonly jwks: JWKSet;
	readonly metadata?: Readonly<Record<string, unknown>>;
	readonly metadataPolicy?: Readonly<Record<string, unknown>>;
	readonly constraints?: Readonly<TrustChainConstraints>;
	/** Entity Types published by the subordinate. Open value space — Federation §5.1 permits identifiers beyond the published set. */
	readonly entityTypes?: ReadonlyArray<EntityTypeIdentifier>;
	readonly isIntermediate?: boolean;
	readonly sourceEndpoint?: string;
	readonly metadataPolicyCrit?: ReadonlyArray<string>;
	/** Adapter-managed creation NumericDate. */
	readonly createdAt: number;
	/** Adapter-managed update NumericDate. */
	readonly updatedAt: number;
}

/** Annotations applied to each event captured by one lifecycle operation. */
export interface SubordinateEventAnnotations {
	readonly eventDescription?: string;
	readonly informationUri?: string;
}

export type SubordinateRecordUpdate = Partial<
	Omit<SubordinateRecord, "entityId" | "createdAt" | "updatedAt">
>;

export interface ListFilter {
	/**
	 * Matches records having ANY of the listed types (union semantics).
	 * Federation §8.2.1's "include all specified Entity Types" condenses
	 * explicitly-OR drafting (openid/federation ee7a372f → 49d194e3), and
	 * Entity Collection Draft 01 clarifies the same sentence to "any of".
	 * Values are open-ended identifiers (Federation §5.1, no registry):
	 * custom adapters must not reject unknown values — filter and report no
	 * matches instead.
	 */
	entityTypes?: EntityTypeIdentifier[];
	/** When true, require a valid issued mark. False adds no restriction. */
	trustMarked?: boolean;
	/** Match any of the supplied Trust Mark types. */
	trustMarkType?: string | ReadonlyArray<string>;
	/** True selects intermediates; false selects non-intermediates; omission selects both. */
	intermediate?: boolean;
	/** Required when trustMarked is true or trustMarkType is provided. */
	validAt?: number;
}

export type {
	TrustMarkListOptions,
	TrustMarkListPage,
	TrustMarkRecord,
	TrustMarkStorage,
} from "@oidfed/core";

/**
 * Scope history by issuer and subject. Preserve append order, including equal
 * timestamps and duplicate events; imported timestamps need not be increasing.
 * Clone values on append and list. Removing a registration retains its history.
 * Transaction-bound repositories commit registration changes and events together.
 */
export interface SubordinateEventStorage {
	append(issuer: EntityId, subject: EntityId, events: readonly SubordinateEvent[]): Promise<void>;
	list(issuer: EntityId, subject: EntityId): Promise<readonly SubordinateEvent[]>;
}
