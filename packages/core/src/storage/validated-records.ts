import { z } from "zod";
import type { EntityId } from "../types.js";
import { InvalidStorageRecordError } from "./errors.js";
import {
	isStorageJson,
	parseStorageRecord,
	parseStoredSubordinateEvents,
	parseStoredTrustMark,
	parseSubordinateRecord,
	parseSubordinateUpdate,
	StorageEntityIdSchema,
	type StorageValidationOptions,
	SubordinateRecordSchema,
	TrustMarkRevisionSchema,
	trustMarkFields,
} from "./record-schemas.js";
import type {
	ListFilter,
	ListPage,
	ListPageOptions,
	SubordinateReadStore,
	SubordinateRecord,
} from "./subordinates.js";
import type { TrustMarkListOptions, TrustMarkReadStore, TrustMarkRecord } from "./trust-mark.js";
import { isStoredTrustMarkEligible } from "./trust-mark-eligibility.js";

function fetched(
	value: unknown,
	id: EntityId,
	options?: StorageValidationOptions,
): SubordinateRecord | undefined {
	if (value === undefined) return;
	const record = subordinate(value, "fetch", options);
	if (record.entityId !== id)
		throw new InvalidStorageRecordError(
			"subordinate",
			"fetch",
			"Record identity does not match the requested subject",
		);
	return record;
}

function subordinate(value: unknown, method: string, options?: StorageValidationOptions) {
	return options
		? parseSubordinateRecord(value, options, method)
		: parseStorageRecord(SubordinateRecordSchema, value, "subordinate", method);
}

const pageEnvelope = z.strictObject({
	items: z.array(z.unknown()),
	nextCursor: StorageEntityIdSchema.optional(),
});

function pageData(value: unknown, kind: string, method: string) {
	if (!isStorageJson(value, true))
		throw new InvalidStorageRecordError(kind, method, "Expected JSON page data");
	const page = pageEnvelope.safeParse(value);
	if (!page.success) throw new InvalidStorageRecordError(kind, method, "Invalid page");
	return page.data;
}

function checkedArray(value: unknown, kind: string, method: string): unknown[] {
	if (!Array.isArray(value) || !isStorageJson(value, true))
		throw new InvalidStorageRecordError(kind, method, "Expected a dense JSON array");
	return value;
}

function listed(
	value: unknown,
	paging: ListPageOptions | undefined,
	options?: StorageValidationOptions,
): ListPage {
	const page = pageData(value, "subordinate", "list");
	if (paging?.limit !== undefined && page.items.length > paging.limit)
		throw new InvalidStorageRecordError("subordinate", "list", "Page exceeds the requested limit");
	let previous: EntityId | undefined;
	const items = page.items.map((raw) => {
		const item = subordinate(raw, "list", options);
		if (
			(previous !== undefined && item.entityId <= previous) ||
			(paging?.cursor !== undefined && item.entityId < paging.cursor)
		)
			throw new InvalidStorageRecordError(
				"subordinate",
				"list",
				"Records are outside the requested order or cursor",
			);
		previous = item.entityId;
		return item;
	});
	if (
		page.nextCursor !== undefined &&
		((previous !== undefined && page.nextCursor <= previous) ||
			(paging?.cursor !== undefined && page.nextCursor <= paging.cursor))
	)
		throw new InvalidStorageRecordError("subordinate", "list", "Continuation does not advance");
	return {
		items,
		...(page.nextCursor !== undefined ? { nextCursor: page.nextCursor } : {}),
	};
}

export async function fetchStoredSubordinate(
	store: SubordinateReadStore,
	id: EntityId,
	options: StorageValidationOptions = {},
): Promise<SubordinateRecord | undefined> {
	return fetched(await store.fetch(id), id, options);
}

export async function listStoredSubordinates(
	store: SubordinateReadStore,
	filter?: ListFilter,
	paging?: ListPageOptions,
	options: StorageValidationOptions = {},
): Promise<ListPage> {
	return listed(await store.list(filter, paging), paging, options);
}

/** Check scoped operations inside their transaction, before the view can commit. */
export async function callValidatedRepository(
	repository: "subordinate" | "trustMark" | "subordinateEvent",
	method: string,
	target: object,
	args: unknown[],
	options?: StorageValidationOptions,
): Promise<unknown> {
	const candidate: unknown = Reflect.get(target, method);
	if (typeof candidate !== "function")
		throw new InvalidStorageRecordError(repository, method, "Missing repository method");
	const call = (...values: unknown[]): unknown =>
		Reflect.apply(candidate as (...args: unknown[]) => unknown, target, values);
	const invalid = (detail: string) => new InvalidStorageRecordError(repository, method, detail);
	if (repository === "subordinate") {
		const [subject, changes, updatedAt] = args;
		switch (method) {
			case "fetch": {
				const id = parseStorageRecord(StorageEntityIdSchema, subject, repository, method);
				return fetched(await call(id), id, options);
			}
			case "list":
				return listed(await call(...args), changes as ListPageOptions | undefined, options);
			case "register":
				return call(subordinate(subject, method, options));
			case "remove":
				return call(parseStorageRecord(StorageEntityIdSchema, subject, repository, method));
			case "update": {
				const id = parseStorageRecord(StorageEntityIdSchema, subject, repository, method);
				const captured = parseSubordinateUpdate(changes, options);
				if (typeof updatedAt !== "number" || !Number.isFinite(updatedAt))
					throw invalid("Invalid update timestamp");
				return call(id, captured, updatedAt);
			}
			default:
				return call(...args);
		}
	}
	if (repository === "subordinateEvent") {
		const [issuer, subject, events] = args;
		const issuerId = parseStorageRecord(StorageEntityIdSchema, issuer, repository, method);
		const subjectId = parseStorageRecord(StorageEntityIdSchema, subject, repository, method);
		const value = method === "history" ? await call(issuerId, subjectId) : events;
		const records = parseStoredSubordinateEvents(value, method);
		return method === "history" ? records : call(issuerId, subjectId, records);
	}
	const [arg, subject] = args;
	const parse = (value: unknown, expected?: Parameters<typeof parseStoredTrustMark>[3]) => {
		if (options) return parseStoredTrustMark(value, options, method, expected);
		const record = parseStorageRecord(trustMarkFields, value, repository, method);
		if (
			(expected?.jwt !== undefined && record.jwt !== expected.jwt) ||
			(expected?.subject !== undefined && record.subject !== expected.subject) ||
			(expected?.trustMarkType !== undefined && record.trustMarkType !== expected.trustMarkType)
		)
			throw invalid("Inconsistent Trust Mark identity");
		return record;
	};
	const eligible = (record: TrustMarkRecord, at: unknown) => {
		if (
			typeof at !== "number" ||
			!Number.isFinite(at) ||
			!record.active ||
			record.issuedAt > at ||
			(record.expiresAt !== undefined && record.expiresAt <= at) ||
			(options && !isStoredTrustMarkEligible(record, at, options))
		)
			throw invalid("Ineligible Trust Mark");
		return record;
	};
	switch (method) {
		case "issue":
			return call(parse(arg));
		case "revision":
			return parseStorageRecord(TrustMarkRevisionSchema, await call(), repository, method);
		case "checkRevision":
		case "hasAny": {
			const result = await call(...args);
			if (typeof result !== "boolean") throw invalid("Expected a boolean result");
			return result;
		}
		case "status":
		case "valid": {
			const result = await call(...args);
			if (result === undefined) return;
			return method === "status"
				? parse(result, { jwt: arg as string })
				: eligible(
						parse(result, { trustMarkType: arg as string, subject: subject as EntityId }),
						args[2],
					);
		}
		case "candidates":
		case "forSubject": {
			const result = checkedArray(await call(...args), repository, method);
			const expected =
				method === "candidates"
					? (arg as Parameters<TrustMarkReadStore["candidates"]>[0])
					: { subject: arg as EntityId };
			return result.map((raw) => {
				const record = parse(raw, expected);
				return method === "forSubject" ? eligible(record, subject) : record;
			});
		}
		case "listSubjects": {
			const page = pageData(await call(...args), repository, method);
			const { subject: selected, cursor, limit } = args[2] as TrustMarkListOptions;
			if (page.items.length > limit) throw invalid("Page exceeds the requested limit");
			let previous: EntityId | undefined;
			const items = page.items.map((raw) => {
				const record = eligible(
					parse(raw, { trustMarkType: arg as string, ...(selected ? { subject: selected } : {}) }),
					subject,
				);
				if ((previous && record.subject <= previous) || (cursor && record.subject < cursor))
					throw invalid("Records are outside the requested order or cursor");
				previous = record.subject;
				return record;
			});
			const next = page.nextCursor;
			if (
				next &&
				((previous && next <= previous) ||
					(cursor && next <= cursor) ||
					(selected && next !== selected))
			)
				throw invalid("Continuation does not advance");
			return { items, ...(next !== undefined ? { nextCursor: next } : {}) };
		}
		default:
			return call(...args);
	}
}
