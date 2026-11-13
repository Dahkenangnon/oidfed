import type { EntityId } from "../types.js";

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
	/** Return every candidate, including revoked records, before service-level eligibility and newest-record selection. Return detached records from one consistent view. */
	listCandidates(filter: {
		readonly issuer: string;
		readonly trustMarkType?: string;
		readonly subject?: EntityId;
	}): Promise<TrustMarkRecord[]>;
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
	revoke(
		trustMarkType: string,
		subject: EntityId,
		revokedAt: number,
		issuer?: string,
	): Promise<void>;
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

/** Atomic write and consistent read boundary shared by Leaf and Authority issuers. */
export interface TrustMarkStore {
	readonly trustMarks: TrustMarkStorage;
	transaction<T>(
		operation: (tx: { readonly trustMarks: TrustMarkStorage }) => Promise<T>,
	): Promise<T>;
	readSnapshot<T>(
		operation: (snapshot: {
			readonly trustMarks: Pick<TrustMarkStorage, "listCandidates" | "getByJwt">;
		}) => Promise<T>,
	): Promise<T>;
}
