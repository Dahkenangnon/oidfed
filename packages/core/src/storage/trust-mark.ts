/** Trust Mark persistence and transactional store contracts. */

import type { z } from "zod";
import type { EntityId } from "../types.js";
import type { TrustMarkRecordSchema } from "./record-schemas.js";

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
export interface TrustMarkReadStore {
	/** Revision of this namespace, including an empty dataset. Changes with every effective mutation. */
	revision(): Promise<string>;
	/** Return every candidate, including revoked records, before service-level eligibility and newest-record selection. Return detached records from one consistent view. */
	candidates(filter: {
		readonly issuer: string;
		readonly trustMarkType?: string;
		readonly subject?: EntityId;
	}): Promise<TrustMarkRecord[]>;
	valid(
		trustMarkType: string,
		subject: EntityId,
		validAt: number,
	): Promise<TrustMarkRecord | undefined>;
	/** Return a detached record, including revoked or expired records when present. */
	status(jwt: string): Promise<TrustMarkRecord | undefined>;
	listSubjects(
		trustMarkType: string,
		validAt: number,
		options: TrustMarkListOptions,
	): Promise<TrustMarkListPage>;
	forSubject(subject: EntityId, validAt: number): Promise<TrustMarkRecord[]>;
	hasAny(subject: EntityId, validAt: number): Promise<boolean>;
}

export interface TrustMarkStore extends TrustMarkReadStore {
	/** Capture input before asynchronous work. Reissuing the same JWT must not replace its record. */
	issue(record: TrustMarkRecord): Promise<void>;
	revoke(
		trustMarkType: string,
		subject: EntityId,
		revokedAt: number,
		issuer?: string,
	): Promise<void>;
	/** Withdraw precisely this issuer's JWT. Repeating a withdrawal is a no-op. */
	revokeExact?(jwt: string, revokedAt: number, issuer: string): Promise<void>;
}

/** Writable Trust Mark repository bound to one serializable transaction. */
export interface TrustMarkTransactionStore extends TrustMarkStore {
	/** Compare the opaque revision within the same serialization boundary as writes. */
	checkRevision(expected: string): Promise<boolean>;
}

/**
 * Stored fields mirror the signed JWT's type, subject, iat, and optional exp.
 * Ingestion establishes the JWT's signature and issuer trust before storing it.
 */
export type TrustMarkRecord = Readonly<z.infer<typeof TrustMarkRecordSchema>>;
