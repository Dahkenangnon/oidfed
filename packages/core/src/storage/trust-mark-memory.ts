/** Detached in-memory Trust Mark records with serialized store transactions. */

import { cloneData } from "../data-copy.js";
import { decodeEntityStatement } from "../jose/verify.js";
import type { EntityId } from "../types.js";
import { parseStoredTrustMark, type StorageValidationOptions } from "./record-schemas.js";
import type {
	TrustMarkListOptions,
	TrustMarkListPage,
	TrustMarkRecord,
	TrustMarkStore,
} from "./trust-mark.js";
import { isStoredTrustMarkEligible } from "./trust-mark-eligibility.js";

const detached = <T>(value: T): T => cloneData(value);

function compareStrings(left: string, right: string): number {
	return left < right ? -1 : left > right ? 1 : 0;
}

function isNewerTrustMark(candidate: TrustMarkRecord, current: TrustMarkRecord): boolean {
	return (
		candidate.issuedAt > current.issuedAt ||
		(candidate.issuedAt === current.issuedAt && compareStrings(candidate.jwt, current.jwt) > 0)
	);
}

function latestBySubject(records: TrustMarkRecord[]): TrustMarkRecord[] {
	const latest = new Map<string, TrustMarkRecord>();
	for (const record of records) {
		const existing = latest.get(record.subject);
		if (!existing || isNewerTrustMark(record, existing)) latest.set(record.subject, record);
	}
	return [...latest.values()];
}

/**
 * Detached storage operations over a host-supplied record map and mutation boundary.
 * Storage eligibility uses local flags and lifetimes; the issuer service performs cryptographic
 * checks.
 */
export class MemoryTrustMarkStorage implements Omit<TrustMarkStore, "revision"> {
	constructor(
		private readonly read: () => Map<string, TrustMarkRecord>,
		private readonly mutate: (
			operation: (records: Map<string, TrustMarkRecord>) => boolean,
		) => Promise<void>,
		private readonly options: StorageValidationOptions,
	) {}

	private records(): Map<string, TrustMarkRecord> {
		const records = this.read();
		if (!records) throw new Error("Trust mark storage is not enabled");
		return records;
	}

	/**
	 * Return detached records matching the decoded issuer and optional selectors, without verifying
	 * JWT signatures.
	 */
	async candidates(filter: {
		issuer: string;
		trustMarkType?: string;
		subject?: EntityId;
	}): Promise<TrustMarkRecord[]> {
		return detached(
			[...this.records().values()].filter((record) => {
				const parsed = decodeEntityStatement(record.jwt, this.options);
				return (
					parsed.ok &&
					parsed.value.payload.iss === filter.issuer &&
					(filter.trustMarkType === undefined || record.trustMarkType === filter.trustMarkType) &&
					(filter.subject === undefined || record.subject === filter.subject)
				);
			}),
		);
	}

	/**
	 * Return the newest locally eligible record for a subject and type, without cryptographic
	 * revalidation.
	 */
	async valid(
		trustMarkType: string,
		subject: EntityId,
		validAt: number,
	): Promise<TrustMarkRecord | undefined> {
		const records = [...this.records().values()]
			.filter(
				(record) =>
					record.trustMarkType === trustMarkType &&
					record.subject === subject &&
					isStoredTrustMarkEligible(record, validAt, this.options),
			)
			.sort((a, b) =>
				a.issuedAt === b.issuedAt ? compareStrings(b.jwt, a.jwt) : b.issuedAt - a.issuedAt,
			);
		return records[0] ? detached(records[0]) : undefined;
	}

	/** Look up the exact JWT and return a detached record, including inactive records. */
	async status(jwt: string): Promise<TrustMarkRecord | undefined> {
		const record = this.records().get(jwt);
		return record ? detached(record) : undefined;
	}

	/** Page locally eligible subjects in identifier order, returning one latest record per subject. */
	async listSubjects(
		trustMarkType: string,
		validAt: number,
		options: TrustMarkListOptions,
	): Promise<TrustMarkListPage> {
		if (!Number.isSafeInteger(options.limit) || options.limit <= 0) {
			throw new RangeError("limit must be a positive safe integer");
		}
		let records = latestBySubject(
			[...this.records().values()].filter(
				(record) =>
					record.trustMarkType === trustMarkType &&
					(options.subject === undefined || record.subject === options.subject) &&
					isStoredTrustMarkEligible(record, validAt, this.options),
			),
		).sort((a, b) => compareStrings(a.subject, b.subject));
		if (options.cursor !== undefined) {
			records = records.filter((record) => record.subject >= (options.cursor as EntityId));
		}
		if (records.length > options.limit) {
			const next = records[options.limit];
			return next
				? { items: detached(records.slice(0, options.limit)), nextCursor: next.subject }
				: { items: detached(records.slice(0, options.limit)) };
		}
		return { items: detached(records) };
	}

	/** Return the latest locally eligible record for each type held by the subject. */
	async forSubject(subject: EntityId, validAt: number): Promise<TrustMarkRecord[]> {
		const records = [...this.records().values()].filter(
			(record) =>
				record.subject === subject && isStoredTrustMarkEligible(record, validAt, this.options),
		);
		const latest = new Map<string, TrustMarkRecord>();
		for (const record of records) {
			const existing = latest.get(record.trustMarkType);
			if (!existing || isNewerTrustMark(record, existing)) {
				latest.set(record.trustMarkType, record);
			}
		}
		return detached(
			[...latest.values()].sort((a, b) => compareStrings(a.trustMarkType, b.trustMarkType)),
		);
	}

	/** Check local issuance flags and lifetimes; this does not authenticate the stored JWT. */
	async hasAny(subject: EntityId, validAt: number): Promise<boolean> {
		return [...this.records().values()].some(
			(record) =>
				record.subject === subject && isStoredTrustMarkEligible(record, validAt, this.options),
		);
	}

	/** Detach the issuance record before its write can wait behind another operation. */
	async issue(record: TrustMarkRecord): Promise<void> {
		// The caller may reuse its input while this write waits for a transaction.
		const captured = parseStoredTrustMark(record, this.options, "issue");
		await this.mutate((records) => {
			if (!records) throw new Error("Trust mark storage is not enabled");
			if (records.has(captured.jwt)) return false;
			records.set(captured.jwt, captured);
			return true;
		});
	}

	/**
	 * Deactivate all matching active records, optionally limited to an issuer. Reject when none match.
	 */
	async revoke(
		trustMarkType: string,
		subject: EntityId,
		revokedAt: number,
		issuer?: string,
	): Promise<void> {
		if (!Number.isFinite(revokedAt))
			throw new TypeError("Trust Mark revocation date must be finite");
		await this.mutate((records) => {
			if (!records) throw new Error("Trust mark storage is not enabled");
			let found = false;
			for (const [jwt, record] of records) {
				const parsed = decodeEntityStatement(jwt, this.options);
				if (issuer !== undefined && (!parsed.ok || parsed.value.payload.iss !== issuer)) continue;
				if (record.trustMarkType === trustMarkType && record.subject === subject && record.active) {
					records.set(jwt, { ...record, active: false, revokedAt });
					found = true;
				}
			}
			if (!found) throw new Error(`Trust mark '${trustMarkType}' for '${subject}' not found`);
			return true;
		});
	}

	/** Deactivate one issuer-owned record and preserve its first withdrawal time. */
	async revokeExact(jwt: string, revokedAt: number, issuer: string): Promise<void> {
		if (!Number.isFinite(revokedAt))
			throw new TypeError("Trust Mark revocation date must be finite");
		await this.mutate((records) => {
			const record = records.get(jwt);
			const decoded = record && decodeEntityStatement(jwt, this.options);
			if (!record || !decoded?.ok || decoded.value.payload.iss !== issuer)
				throw new Error("Trust Mark not found");
			if (!record.active) return false;
			records.set(jwt, { ...record, active: false, revokedAt });
			return true;
		});
	}
}
