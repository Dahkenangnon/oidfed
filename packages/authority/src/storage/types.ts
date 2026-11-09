/** Unified authority persistence contracts. */
import type {
	CacheProvider,
	EntityCollectionStore,
	EntityId,
	EntityTypeIdentifier,
	JWKSet,
	ReplayStore,
	SubordinateEvent,
	TrustChainConstraints,
} from "@oidfed/core";

export interface StorageAdapter {
	readonly collections?: EntityCollectionStore;
	readonly subordinateEvents?: SubordinateEventStorage;
	readonly subordinates: SubordinateStorage;
	readonly trustMarks?: TrustMarkStorage;
	readonly replay?: ReplayStore;
	readonly cache?: CacheProvider;
	transaction<T>(operation: (tx: StorageTransaction) => Promise<T>): Promise<T>;
	/** Read one consistent view. Use only the supplied repositories inside the callback. */
	readSnapshot?<T>(operation: (snapshot: StorageReadSnapshot) => Promise<T>): Promise<T>;
}

/** Read-only views return detached records and expose no mutation methods. */
export interface StorageReadSnapshot {
	readonly subordinates: Pick<SubordinateStorage, "get" | "list">;
	readonly subordinateEvents?: Pick<SubordinateEventStorage, "list">;
}

export interface StorageTransaction {
	readonly subordinateEvents?: SubordinateEventStorage;
	readonly subordinates: SubordinateStorage;
	readonly trustMarks?: TrustMarkStorage;
}

export interface SubordinateStorage {
	get(entityId: EntityId): Promise<SubordinateRecord | undefined>;
	/**
	 * Return matching records ordered lexicographically by entityId; cursors are inclusive.
	 * A filtered page may be empty with a continuation. Without options, return all matches.
	 */
	list(filter?: ListFilter, options?: ListPageOptions): Promise<ListPage>;
	add(record: SubordinateRecord): Promise<void>;
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

export interface SubordinateRecord {
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
	readonly crit?: ReadonlyArray<string>;
	readonly metadataPolicyCrit?: ReadonlyArray<string>;
	/** Adapter-managed creation NumericDate. */
	readonly createdAt: number;
	/** Adapter-managed update NumericDate. */
	readonly updatedAt: number;
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
	intermediate?: boolean;
	/** Required when trustMarked is true or trustMarkType is provided. */
	validAt?: number;
}

export interface TrustMarkListOptions {
	readonly subject?: EntityId;
	/** Subject of the first unreturned record; inclusive. */
	readonly cursor?: EntityId;
	readonly limit: number;
}

export interface TrustMarkListPage {
	readonly items: TrustMarkRecord[];
	readonly nextCursor?: EntityId;
}

/**
 * Current-validity queries require active marks with finite issuedAt <= validAt
 * and either no expiration or expiresAt > validAt. Apply this eligibility before
 * selecting the newest mark, using exact authority time without added clock leeway.
 */
export interface TrustMarkStorage {
	getValid(
		trustMarkType: string,
		subject: EntityId,
		validAt: number,
	): Promise<TrustMarkRecord | undefined>;
	getByJwt(jwt: string): Promise<TrustMarkRecord | undefined>;
	listValid(
		trustMarkType: string,
		validAt: number,
		options: TrustMarkListOptions,
	): Promise<TrustMarkListPage>;
	listValidForSubject(subject: EntityId, validAt: number): Promise<TrustMarkRecord[]>;
	hasAnyValid(subject: EntityId, validAt: number): Promise<boolean>;
	issue(record: TrustMarkRecord): Promise<void>;
	revoke(trustMarkType: string, subject: EntityId, revokedAt: number): Promise<void>;
}

/**
 * Stored fields mirror the signed JWT's type, subject, iat, and optional exp.
 * Ingestion establishes the JWT's signature and issuer trust before storing it.
 */
export interface TrustMarkRecord {
	readonly trustMarkType: string;
	readonly subject: EntityId;
	readonly jwt: string;
	readonly issuedAt: number;
	readonly expiresAt?: number;
	readonly active: boolean;
	readonly revokedAt?: number;
}

/** History remains independent of the current registration record. */
export interface SubordinateEventStorage {
	append(issuer: EntityId, subject: EntityId, events: readonly SubordinateEvent[]): Promise<void>;
	list(issuer: EntityId, subject: EntityId): Promise<readonly SubordinateEvent[]>;
}
