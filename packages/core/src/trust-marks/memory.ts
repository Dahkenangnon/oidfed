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

const detached = <T>(value: T): T => structuredClone(value);

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

export class MemoryTrustMarkStorage implements TrustMarkStorage {
	constructor(
		private readonly read: () => Map<string, TrustMarkRecord>,
		private readonly mutate: <T>(
			operation: (records: Map<string, TrustMarkRecord>) => T | Promise<T>,
		) => Promise<T>,
	) {}

	private records(): Map<string, TrustMarkRecord> {
		const records = this.read();
		if (!records) throw new Error("Trust mark storage is not enabled");
		return records;
	}

	async listCandidates(filter: {
		issuer: string;
		trustMarkType?: string;
		subject?: EntityId;
	}): Promise<TrustMarkRecord[]> {
		return detached(
			[...this.records().values()].filter((record) => {
				const parsed = decodeEntityStatement(record.jwt);
				return (
					parsed.ok &&
					parsed.value.payload.iss === filter.issuer &&
					(filter.trustMarkType === undefined || record.trustMarkType === filter.trustMarkType) &&
					(filter.subject === undefined || record.subject === filter.subject)
				);
			}),
		);
	}

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
					isStoredTrustMarkEligible(record, validAt),
			)
			.sort((a, b) =>
				a.issuedAt === b.issuedAt ? compareStrings(b.jwt, a.jwt) : b.issuedAt - a.issuedAt,
			);
		return records[0] ? detached(records[0]) : undefined;
	}

	async getByJwt(jwt: string): Promise<TrustMarkRecord | undefined> {
		const record = this.records().get(jwt);
		return record ? detached(record) : undefined;
	}

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
					isStoredTrustMarkEligible(record, validAt),
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

	async listValidForSubject(subject: EntityId, validAt: number): Promise<TrustMarkRecord[]> {
		const records = [...this.records().values()].filter(
			(record) => record.subject === subject && isStoredTrustMarkEligible(record, validAt),
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

	async hasAnyValid(subject: EntityId, validAt: number): Promise<boolean> {
		return [...this.records().values()].some(
			(record) => record.subject === subject && isStoredTrustMarkEligible(record, validAt),
		);
	}

	async issue(record: TrustMarkRecord): Promise<void> {
		// The caller may reuse its input while this write waits for a transaction.
		const captured = detached(record);
		await this.mutate((records) => {
			if (!records) throw new Error("Trust mark storage is not enabled");
			if (!records.has(captured.jwt)) records.set(captured.jwt, captured);
		});
	}

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
				const parsed = decodeEntityStatement(jwt);
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
	private tail: Promise<void> = Promise.resolve();
	readonly trustMarks = new MemoryTrustMarkStorage(
		() => this.records,
		(op) => this.exclusive(() => op(this.records)),
	);
	private async exclusive<T>(operation: () => Promise<T> | T): Promise<T> {
		const prior = this.tail;
		let release!: () => void;
		this.tail = new Promise<void>((resolve) => {
			release = resolve;
		});
		await prior;
		try {
			return await operation();
		} finally {
			release();
		}
	}
	async transaction<T>(
		operation: (tx: { trustMarks: TrustMarkStorage }) => Promise<T>,
	): Promise<T> {
		return this.exclusive(async () => {
			const records = structuredClone(this.records);
			const result = await operation({
				trustMarks: new MemoryTrustMarkStorage(
					() => records,
					async (op) => op(records),
				),
			});
			this.records = records;
			return result;
		});
	}
	async readSnapshot<T>(
		operation: (snapshot: {
			trustMarks: Pick<TrustMarkStorage, "listCandidates" | "getByJwt">;
		}) => Promise<T>,
	): Promise<T> {
		const records = await this.exclusive(() => structuredClone(this.records));
		const view = new MemoryTrustMarkStorage(
			() => records,
			async () => {
				throw new Error("Read-only snapshot");
			},
		);
		return operation({
			trustMarks: {
				listCandidates: view.listCandidates.bind(view),
				getByJwt: view.getByJwt.bind(view),
			},
		});
	}
}
