/** Trust Mark persistence and transactional store contracts. */

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
 * Validity queries require an active mark with finite issuedAt <= validAt and either
 * no expiration or expiresAt > validAt. An embedded delegation must be decodable,
 * have finite iat <= validAt, and have no exp or exp > validAt.
 * Apply these checks before choosing the newest mark, using exact issuer time with
 * no added clock leeway. See isStoredTrustMarkEligible for the shared predicate.
 * Verify the signature and establish issuer trust before storing the record.
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
	/** Return a detached record, including revoked or expired records when present. */
	getByJwt(jwt: string): Promise<TrustMarkRecord | undefined>;
	listValid(
		trustMarkType: string,
		validAt: number,
		options: TrustMarkListOptions,
	): Promise<TrustMarkListPage>;
	listValidForSubject(subject: EntityId, validAt: number): Promise<TrustMarkRecord[]>;
	hasAnyValid(subject: EntityId, validAt: number): Promise<boolean>;
	/** Capture input before asynchronous work. Reissuing the same JWT must not replace its record. */
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
	/** Commit all callback writes together, or roll them back on failure. Use tx repositories only; awaiting parent queued writes inside the callback can deadlock. */
	transaction<T>(
		operation: (tx: { readonly trustMarks: TrustMarkStorage }) => Promise<T>,
	): Promise<T>;
	readSnapshot<T>(
		operation: (snapshot: {
			readonly trustMarks: Pick<TrustMarkStorage, "listCandidates" | "getByJwt">;
		}) => Promise<T>,
	): Promise<T>;
}
