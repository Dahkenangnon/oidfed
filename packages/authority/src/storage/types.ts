/** Unified authority persistence contracts. */
import type {
	CacheProvider,
	EntityId,
	EntityType,
	JWKSet,
	ReplayStore,
	TrustChainConstraints,
} from "@oidfed/core";

export interface StorageAdapter {
	readonly subordinates: SubordinateStorage;
	readonly trustMarks?: TrustMarkStorage;
	readonly replay?: ReplayStore;
	readonly cache?: CacheProvider;
	transaction<T>(operation: (tx: StorageTransaction) => Promise<T>): Promise<T>;
}

export interface StorageTransaction {
	readonly subordinates: SubordinateStorage;
	readonly trustMarks?: TrustMarkStorage;
}

export interface SubordinateStorage {
	get(entityId: EntityId): Promise<SubordinateRecord | undefined>;
	/** Records are ordered lexicographically by entityId; cursors are inclusive. */
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
	readonly nextCursor?: EntityId;
}

export interface SubordinateRecord {
	readonly entityId: EntityId;
	readonly jwks: JWKSet;
	readonly metadata?: Readonly<Record<string, unknown>>;
	readonly metadataPolicy?: Readonly<Record<string, unknown>>;
	readonly constraints?: Readonly<TrustChainConstraints>;
	readonly entityTypes?: ReadonlyArray<EntityType>;
	readonly isIntermediate?: boolean;
	readonly sourceEndpoint?: string;
	readonly crit?: ReadonlyArray<string>;
	readonly metadataPolicyCrit?: ReadonlyArray<string>;
	/** NumericDate. */
	readonly createdAt: number;
	/** NumericDate. */
	readonly updatedAt: number;
}

export type SubordinateRecordUpdate = Partial<
	Omit<SubordinateRecord, "entityId" | "createdAt" | "updatedAt">
>;

export interface ListFilter {
	entityTypes?: EntityType[];
	trustMarked?: boolean;
	trustMarkType?: string;
	intermediate?: boolean;
	/** Required when trustMarked or trustMarkType is provided. */
	validAt?: number;
}

export interface TrustMarkListOptions {
	readonly subject?: EntityId;
	readonly cursor?: EntityId;
	readonly limit: number;
}

export interface TrustMarkListPage {
	readonly items: TrustMarkRecord[];
	readonly nextCursor?: EntityId;
}

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

export interface TrustMarkRecord {
	readonly trustMarkType: string;
	readonly subject: EntityId;
	readonly jwt: string;
	readonly issuedAt: number;
	readonly expiresAt?: number;
	readonly active: boolean;
	readonly revokedAt?: number;
}
