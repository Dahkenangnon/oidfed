import { cloneData } from "../data-copy.js";
import type { SubordinateEvent } from "../schemas/subordinate-events.js";
import type { EntityId } from "../types.js";
import {
	parseStorageRecord,
	parseStoredSubordinateEvents,
	parseSubordinateRecord,
	parseSubordinateUpdate,
	StorageEntityIdSchema,
	type StorageValidationOptions,
} from "./record-schemas.js";
import type {
	ListFilter,
	ListPage,
	ListPageOptions,
	SubordinateEventStore,
	SubordinateRecord,
	SubordinateRecordUpdate,
	SubordinateStore,
} from "./subordinates.js";
import type { TrustMarkRecord } from "./trust-mark.js";
import { isStoredTrustMarkEligible } from "./trust-mark-eligibility.js";

export interface RecordState {
	subordinateEvents?: Map<string, Map<string, SubordinateEvent[]>>;
	subordinates: Map<string, SubordinateRecord>;
	trustMarks?: Map<string, TrustMarkRecord>;
	trustMarkRevision: bigint;
}

export type StateReader = () => RecordState;
export type StateMutation = <T>(operation: (state: RecordState) => T | Promise<T>) => Promise<T>;

const detached = <T>(value: T): T => cloneData(value);

function compareStrings(left: string, right: string): number {
	return left < right ? -1 : left > right ? 1 : 0;
}

export function trustMarkRecords(state: RecordState): Map<string, TrustMarkRecord> {
	if (!state.trustMarks) throw new Error("Trust mark storage is not configured");
	return state.trustMarks;
}

export class MemorySubordinateStore implements SubordinateStore {
	constructor(
		private readonly read: StateReader,
		private readonly mutate: StateMutation,
		private readonly options: StorageValidationOptions,
	) {}

	async fetch(entityId: EntityId): Promise<SubordinateRecord | undefined> {
		const record = this.read().subordinates.get(entityId);
		return record ? detached(record) : undefined;
	}

	async list(filter?: ListFilter, options?: ListPageOptions): Promise<ListPage> {
		let results = [...this.read().subordinates.values()];
		if (filter?.entityTypes?.length) {
			results = results.filter(
				(record) => record.entityTypes?.some((type) => filter.entityTypes?.includes(type)) ?? false,
			);
		}
		if (filter?.intermediate !== undefined) {
			results = results.filter(
				(record) => (record.isIntermediate ?? false) === filter.intermediate,
			);
		}
		// Federation §8.2.1 defines true; false is unspecified.
		// Here false adds no restriction; supplied mark types still filter.
		if (filter?.trustMarked === true || filter?.trustMarkType !== undefined) {
			if (filter.validAt === undefined || !Number.isFinite(filter.validAt)) {
				throw new TypeError("validAt is required for trust mark filters");
			}
			const marks = this.read().trustMarks;
			if (!marks) throw new Error("Trust mark filtering is not supported by this adapter");
			const requestedTypes =
				typeof filter.trustMarkType === "string" ? [filter.trustMarkType] : filter.trustMarkType;
			results = results.filter((record) => {
				const valid = [...marks.values()].some(
					(mark) =>
						mark.subject === record.entityId &&
						(requestedTypes === undefined || requestedTypes.includes(mark.trustMarkType)) &&
						isStoredTrustMarkEligible(mark, filter.validAt as number, this.options),
				);
				return valid;
			});
		}
		if (options?.updatedAfter !== undefined) {
			results = results.filter((record) => record.updatedAt >= (options.updatedAfter as number));
		}
		if (options?.updatedBefore !== undefined) {
			results = results.filter((record) => record.updatedAt <= (options.updatedBefore as number));
		}
		results.sort((a, b) => compareStrings(a.entityId, b.entityId));
		if (options?.cursor !== undefined) {
			results = results.filter((record) => record.entityId >= (options.cursor as EntityId));
		}
		const limit = options?.limit;
		if (limit !== undefined && results.length > limit) {
			const next = results[limit];
			return next
				? { items: detached(results.slice(0, limit)), nextCursor: next.entityId }
				: { items: detached(results.slice(0, limit)) };
		}
		return { items: detached(results) };
	}

	async register(record: SubordinateRecord): Promise<void> {
		// Capture before waiting for a preceding transaction; validate what is stored.
		const captured = parseSubordinateRecord(record, this.options, "register");
		await this.mutate((state) => {
			if (state.subordinates.has(captured.entityId)) {
				throw new Error(`Subordinate '${captured.entityId}' already exists`);
			}
			state.subordinates.set(captured.entityId, captured);
		});
	}

	async update(
		entityId: EntityId,
		updates: SubordinateRecordUpdate,
		updatedAt: number,
	): Promise<void> {
		const captured = parseSubordinateUpdate(updates, this.options);
		await this.mutate((state) => {
			const existing = state.subordinates.get(entityId);
			if (!existing) throw new Error(`Subordinate '${entityId}' not found`);
			const updated = {
				...existing,
				...captured,
				entityId: existing.entityId,
				createdAt: existing.createdAt,
				updatedAt,
			};
			state.subordinates.set(entityId, parseSubordinateRecord(updated, this.options, "update"));
		});
	}

	async remove(entityId: EntityId): Promise<void> {
		await this.mutate((state) => {
			if (!state.subordinates.delete(entityId)) {
				throw new Error(`Subordinate '${entityId}' not found`);
			}
		});
	}
}

export class MemorySubordinateEventStore implements SubordinateEventStore {
	constructor(
		private readonly read: StateReader,
		private readonly mutate: StateMutation,
	) {}
	async append(
		issuer: EntityId,
		subject: EntityId,
		events: readonly SubordinateEvent[],
	): Promise<void> {
		parseStorageRecord(StorageEntityIdSchema, issuer, "subordinateEvent", "append issuer");
		parseStorageRecord(StorageEntityIdSchema, subject, "subordinateEvent", "append subject");
		const parsed = parseStoredSubordinateEvents(events, "append");
		await this.mutate((state) => {
			const history = state.subordinateEvents;
			if (!history) throw new Error("Subordinate event storage is not enabled");
			let subjects = history.get(issuer);
			if (!subjects) {
				subjects = new Map();
				history.set(issuer, subjects);
			}
			subjects.set(subject, [...(subjects.get(subject) ?? []), ...detached(parsed)]);
		});
	}
	async history(issuer: EntityId, subject: EntityId): Promise<readonly SubordinateEvent[]> {
		return detached(this.read().subordinateEvents?.get(issuer)?.get(subject) ?? []);
	}
}
