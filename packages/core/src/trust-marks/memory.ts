import { cloneData } from "../data-copy.js";
/** Detached in-memory Trust Mark records with serialized store transactions. */

import { createConcurrencyLimiter } from "../async-operation.js";
import { decodeEntityStatement } from "../jose/verify.js";
import type { EntityId } from "../types.js";
import { isStoredTrustMarkEligible } from "./eligibility.js";
import type {
	TrustMarkListOptions,
	TrustMarkListPage,
	TrustMarkRecord,
	TrustMarkStorage,
	TrustMarkStore,
} from "./storage.js";

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
export class MemoryTrustMarkStorage implements TrustMarkStorage {
	constructor(
		private readonly read: () => Map<string, TrustMarkRecord>,
		private readonly mutate: <T>(
			operation: (records: Map<string, TrustMarkRecord>) => T | Promise<T>,
		) => Promise<T>,
		private readonly maxCompactBytes?: number,
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
	async listCandidates(filter: {
		issuer: string;
		trustMarkType?: string;
		subject?: EntityId;
	}): Promise<TrustMarkRecord[]> {
		return detached(
			[...this.records().values()].filter((record) => {
				const parsed = decodeEntityStatement(record.jwt, { maxCompactBytes: this.maxCompactBytes });
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
	async getValid(
		trustMarkType: string,
		subject: EntityId,
		validAt: number,
	): Promise<TrustMarkRecord | undefined> {
		const records = [...this.records().values()]
			.filter(
				(record) =>
					record.trustMarkType === trustMarkType &&
					record.subject === subject &&
					isStoredTrustMarkEligible(record, validAt, this.maxCompactBytes),
			)
			.sort((a, b) =>
				a.issuedAt === b.issuedAt ? compareStrings(b.jwt, a.jwt) : b.issuedAt - a.issuedAt,
			);
		return records[0] ? detached(records[0]) : undefined;
	}

	/** Look up the exact JWT and return a detached record, including inactive records. */
	async getByJwt(jwt: string): Promise<TrustMarkRecord | undefined> {
		const record = this.records().get(jwt);
		return record ? detached(record) : undefined;
	}

	/** Page locally eligible subjects in identifier order, returning one latest record per subject. */
	async listValid(
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
					isStoredTrustMarkEligible(record, validAt, this.maxCompactBytes),
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
	async listValidForSubject(subject: EntityId, validAt: number): Promise<TrustMarkRecord[]> {
		const records = [...this.records().values()].filter(
			(record) =>
				record.subject === subject &&
				isStoredTrustMarkEligible(record, validAt, this.maxCompactBytes),
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
	async hasAnyValid(subject: EntityId, validAt: number): Promise<boolean> {
		return [...this.records().values()].some(
			(record) =>
				record.subject === subject &&
				isStoredTrustMarkEligible(record, validAt, this.maxCompactBytes),
		);
	}

	/** Detach the issuance record before its write can wait behind another operation. */
	async issue(record: TrustMarkRecord): Promise<void> {
		// The caller may reuse its input while this write waits for a transaction.
		const captured = detached(record);
		await this.mutate((records) => {
			if (!records) throw new Error("Trust mark storage is not enabled");
			if (!records.has(captured.jwt)) records.set(captured.jwt, captured);
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
		await this.mutate((records) => {
			if (!records) throw new Error("Trust mark storage is not enabled");
			let found = false;
			for (const [jwt, record] of records) {
				const parsed = decodeEntityStatement(jwt, { maxCompactBytes: this.maxCompactBytes });
				if (issuer !== undefined && (!parsed.ok || parsed.value.payload.iss !== issuer)) continue;
				if (record.trustMarkType === trustMarkType && record.subject === subject && record.active) {
					records.set(jwt, { ...record, active: false, revokedAt });
					found = true;
				}
			}
			if (!found) throw new Error(`Trust mark '${trustMarkType}' for '${subject}' not found`);
		});
	}
}

/** In-memory, process-local transaction adapter. Production hosts supply durable storage. */
export class MemoryTrustMarkStore implements TrustMarkStore {
	private records = new Map<string, TrustMarkRecord>();
	private readonly serialize = createConcurrencyLimiter(1);
	readonly trustMarks: MemoryTrustMarkStorage;
	private readonly maxCompactBytes: number | undefined;
	/** Set the same compact size limit used by the issuing host. */
	constructor(options?: { readonly maxCompactBytes?: number }) {
		this.maxCompactBytes = options?.maxCompactBytes;
		this.trustMarks = new MemoryTrustMarkStorage(
			() => this.records,
			(op) => this.exclusive(() => op(this.records)),
			this.maxCompactBytes,
		);
	}
	private async exclusive<T>(operation: () => Promise<T> | T): Promise<T> {
		return this.serialize(async () => operation());
	}
	/** Serialize writes against a cloned record map; commit only after the callback succeeds. */
	async transaction<T>(
		operation: (tx: { trustMarks: TrustMarkStorage }) => Promise<T>,
	): Promise<T> {
		return this.exclusive(async () => {
			const records = cloneData(this.records);
			const result = await operation({
				trustMarks: new MemoryTrustMarkStorage(
					() => records,
					async (op) => op(records),
					this.maxCompactBytes,
				),
			});
			this.records = records;
			return result;
		});
	}
	/** Capture a detached read-only view before invoking the callback outside the write queue. */
	async readSnapshot<T>(
		operation: (snapshot: {
			trustMarks: Pick<TrustMarkStorage, "listCandidates" | "getByJwt">;
		}) => Promise<T>,
	): Promise<T> {
		const records = await this.exclusive(() => cloneData(this.records));
		const view = new MemoryTrustMarkStorage(
			() => records,
			async () => {
				throw new Error("Read-only snapshot");
			},
			this.maxCompactBytes,
		);
		return operation({
			trustMarks: {
				listCandidates: view.listCandidates.bind(view),
				getByJwt: view.getByJwt.bind(view),
			},
		});
	}
}
