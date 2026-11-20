import { z } from "zod";
import { InvalidStorageRecordError } from "./errors.js";
import {
	EntityCollectionCursorSchema,
	EntityCollectionSnapshotSchema,
	isStorageJson,
	JtiReplayClaimSchema,
	parseStorageRecord,
	parseStoredTrustMark,
	parseSubordinateRecord,
	StorageEntityIdSchema,
	type StorageValidationOptions,
	SubordinateEventHistorySchema,
	SubordinateRecordSchema,
	TrustMarkRecordSchema,
} from "./record-schemas.js";

const keyId = z.string().min(1);
const sha256 = z.string().regex(/^[a-f0-9]{64}$/);
const sequence = z.string().regex(/^(0|[1-9][0-9]*)$/);
const date = z.number().finite();
const schemas = {
	subordinate: SubordinateRecordSchema,
	event: SubordinateEventHistorySchema,
	mark: z.array(TrustMarkRecordSchema).min(1),
	markRevision: sequence,
	replay: z.strictObject({
		key: sha256,
		expiresAt: date,
		extensions: JtiReplayClaimSchema.shape.extensions,
	}),
	collectionSnapshot: z.strictObject({
		value: EntityCollectionSnapshotSchema,
		order: z.string().regex(/^[1-9][0-9]*$/),
		retainUntil: date.optional(),
	}),
	collectionCurrent: keyId,
	collectionCursor: z.strictObject({ id: keyId, value: EntityCollectionCursorSchema }),
	collectionSequence: sequence,
};

/** Optional record layout used by the single-file database examples. */
export type StoragePayloadByKind = { [K in keyof typeof schemas]: z.infer<(typeof schemas)[K]> };

/** Validate an example record before writing or after decoding a read. */
export function parseStoragePayload<K extends keyof StoragePayloadByKind>(
	kind: K,
	id: string,
	value: unknown,
	operation: "read" | "write",
	options: StorageValidationOptions = {},
): StoragePayloadByKind[K] {
	const badKey = () => new InvalidStorageRecordError(kind, operation, "Invalid record identity");
	switch (kind) {
		case "subordinate": {
			const record = parseSubordinateRecord(value, options, operation);
			if (record.entityId !== id) throw badKey();
			return record as StoragePayloadByKind[K];
		}
		case "event": {
			let pair: unknown;
			try {
				pair = JSON.parse(id);
			} catch {
				throw badKey();
			}
			if (
				!Array.isArray(pair) ||
				pair.length !== 2 ||
				!pair.every((item: unknown) => StorageEntityIdSchema.safeParse(item).success) ||
				JSON.stringify(pair) !== id
			)
				throw badKey();
			break;
		}
		case "mark": {
			if (
				!sha256.safeParse(id).success ||
				!Array.isArray(value) ||
				value.length === 0 ||
				!isStorageJson(value, true)
			)
				throw badKey();
			const records = value.map((record: unknown) =>
				parseStoredTrustMark(record, options, operation),
			);
			if (new Set(records.map((record) => record.jwt)).size !== records.length) throw badKey();
			return records as StoragePayloadByKind[K];
		}
		case "markRevision":
		case "collectionSequence":
			if (id !== "") throw badKey();
			break;
		case "collectionCurrent":
			if (!StorageEntityIdSchema.safeParse(id).success) throw badKey();
			break;
		case "collectionSnapshot": {
			const row = parseStorageRecord(schemas.collectionSnapshot, value, kind, operation);
			if (row.value.id !== id) throw badKey();
			return row as StoragePayloadByKind[K];
		}
		case "collectionCursor": {
			const row = parseStorageRecord(schemas.collectionCursor, value, kind, operation);
			if (row.id !== id) throw badKey();
			return row as StoragePayloadByKind[K];
		}
		case "replay": {
			const row = parseStorageRecord(schemas.replay, value, kind, operation);
			if (row.key !== id) throw badKey();
			return row as StoragePayloadByKind[K];
		}
	}
	return parseStorageRecord<unknown>(
		schemas[kind],
		value,
		kind,
		operation,
	) as StoragePayloadByKind[K];
}
