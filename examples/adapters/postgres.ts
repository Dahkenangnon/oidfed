import { createHash } from "node:crypto";
import {
	cloneData,
	decodeEntityStatement,
	EntityCollectionCursorCapacityError,
	EntityCollectionCursorSchema,
	EntityCollectionSnapshotSchema,
	type EntityCollectionStore,
	type EntityId,
	type FederationStorage,
	InvalidStorageRecordError,
	isStoredTrustMarkEligible,
	type JtiReplayClaim,
	JtiReplayClaimSchema,
	type ListFilter,
	type ListPageOptions,
	parseStoragePayload,
	parseStorageRecord,
	parseStoredSubordinateEvents,
	parseStoredTrustMark,
	parseSubordinateRecord,
	parseSubordinateUpdate,
	type ReadSnapshotView,
	type ReplayStore,
	ReplayStoreCapacityError,
	type StorageCapability,
	type StoragePayloadByKind,
	type StorageValidationOptions,
	type SubordinateEventStore,
	type SubordinateStore,
	type TransactionView,
	type TrustMarkRecord,
	type TrustMarkStore,
} from "@oidfed/core";
import { DatabaseError, type Pool, type PoolClient } from "pg";

/** Provision an empty, dedicated schema with a migration connection. */
export async function provisionPostgresStorage(pool: Pool): Promise<void> {
	await pool.query(`
		CREATE SCHEMA IF NOT EXISTS oidfed;
		DO $$
		BEGIN
			IF EXISTS (
				SELECT 1 FROM pg_catalog.pg_class AS relation
				JOIN pg_catalog.pg_namespace AS schema ON schema.oid = relation.relnamespace
				WHERE schema.nspname = 'oidfed'
				  AND relation.relname IN ('oidfed_storage_record', 'oidfed_storage_guard', 'mark_lookup')
				  AND NOT EXISTS (
				    SELECT 1 FROM pg_catalog.pg_attribute
				    WHERE attrelid = relation.oid AND attname = 'namespace_key' AND NOT attisdropped
				  )
			) THEN
				RAISE EXCEPTION 'Existing oidfed storage layout requires migration to a fresh schema or database';
			END IF;
		END $$;
		CREATE TABLE IF NOT EXISTS oidfed.oidfed_storage_guard (
			namespace text COLLATE "C" NOT NULL,
			namespace_key bytea PRIMARY KEY CHECK (namespace_key = sha256(convert_to(namespace, 'UTF8'))),
			epoch bigint NOT NULL DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS oidfed.oidfed_storage_record (
			namespace text COLLATE "C" NOT NULL,
			namespace_key bytea NOT NULL CHECK (namespace_key = sha256(convert_to(namespace, 'UTF8'))),
			kind text COLLATE "C" NOT NULL,
			id text COLLATE "C" NOT NULL,
			id_key bytea NOT NULL CHECK (id_key = sha256(convert_to(id, 'UTF8'))),
			payload jsonb NOT NULL,
			entity_order bytea,
			replay_expiry double precision GENERATED ALWAYS AS (
				CASE WHEN kind = 'replay' THEN (payload->>'expiresAt')::double precision END
			) STORED,
			PRIMARY KEY (namespace_key, kind, id_key),
			CHECK ((kind = 'subordinate') = (entity_order IS NOT NULL)),
			CHECK (kind <> 'replay' OR (
				jsonb_typeof(payload) = 'object'
				AND jsonb_typeof(payload->'key') = 'string'
				AND payload->>'key' = id
				AND id ~ '^[a-f0-9]{64}$'
				AND jsonb_typeof(payload->'expiresAt') = 'number'
				AND (NOT payload ? 'extensions' OR jsonb_typeof(payload->'extensions') = 'object')
				AND (payload - ARRAY['key', 'expiresAt', 'extensions']) = '{}'::jsonb
			) IS TRUE)
		);
		CREATE INDEX IF NOT EXISTS oidfed_replay_expiry
			ON oidfed.oidfed_storage_record (namespace_key, replay_expiry) WHERE kind = 'replay';
		CREATE INDEX IF NOT EXISTS oidfed_subordinate_order
			ON oidfed.oidfed_storage_record (namespace_key, (substring(entity_order FROM 1 FOR 128)))
			WHERE kind = 'subordinate';
		CREATE INDEX IF NOT EXISTS oidfed_subordinate_updated
			ON oidfed.oidfed_storage_record (namespace_key, (((payload->>'updatedAt')::double precision)))
			WHERE kind = 'subordinate';
		CREATE INDEX IF NOT EXISTS oidfed_subordinate_types
			ON oidfed.oidfed_storage_record USING gin ((payload->'entityTypes'))
			WHERE kind = 'subordinate';

		CREATE TABLE IF NOT EXISTS oidfed.mark_lookup (
			namespace text COLLATE "C" NOT NULL,
			namespace_key bytea NOT NULL CHECK (namespace_key = sha256(convert_to(namespace, 'UTF8'))),
			kind text COLLATE "C" GENERATED ALWAYS AS ('mark'::text) STORED,
			mark_id text COLLATE "C" NOT NULL,
			mark_id_key bytea NOT NULL CHECK (mark_id_key = sha256(convert_to(mark_id, 'UTF8'))),
			member_position integer NOT NULL,
			issuer text COLLATE "C" NOT NULL,
			subject text COLLATE "C" NOT NULL,
			mark_type text COLLATE "C" NOT NULL,
			subject_order bytea NOT NULL,
			PRIMARY KEY (namespace_key, mark_id_key, member_position),
			FOREIGN KEY (namespace_key, kind, mark_id_key)
				REFERENCES oidfed.oidfed_storage_record (namespace_key, kind, id_key) ON DELETE CASCADE
		);
		-- Hash indexes keep long selector strings out of B-tree index keys.
		CREATE INDEX IF NOT EXISTS oidfed_mark_issuer ON oidfed.mark_lookup USING hash (issuer);
		CREATE INDEX IF NOT EXISTS oidfed_mark_subject ON oidfed.mark_lookup USING hash (subject);
		CREATE INDEX IF NOT EXISTS oidfed_mark_type ON oidfed.mark_lookup USING hash (mark_type);
		CREATE INDEX IF NOT EXISTS oidfed_mark_subject_order
			ON oidfed.mark_lookup (namespace_key, (substring(subject_order FROM 1 FOR 128)));
	`);
}

// PostgreSQL text cannot preserve NUL or unpaired surrogates. Reject them before hashing.
function storageKey(value: string): Buffer {
	if (value.includes("\0") || /[\uD800-\uDFFF]/u.test(value))
		throw new TypeError("PostgreSQL storage keys must be well-formed text without NUL");
	return createHash("sha256").update(value, "utf8").digest();
}

function operations(
	client: PoolClient,
	namespace: string,
	namespaceKey: Buffer,
	options: StorageValidationOptions,
): Records {
	return {
		async now() {
			return (
				(
					await client.query<{ now: number }>(
						"SELECT EXTRACT(EPOCH FROM clock_timestamp())::float8 AS now",
					)
				).rows[0]?.now ?? NaN
			);
		},
		async get(kind, id) {
			const result = await client.query<{ id: string; payload: unknown }>(
				"SELECT id, payload FROM oidfed.oidfed_storage_record WHERE namespace_key = $4 AND kind = $2 AND id_key = $5 AND namespace = $1 AND id = $3",
				[namespace, kind, id, namespaceKey, storageKey(id)],
			);
			const row = result.rows[0];
			return row && storedPayload(kind, id, row.payload, "read", options);
		},
		async list(kind) {
			const result = await client.query<{ id: string; payload: unknown }>(
				"SELECT id, payload FROM oidfed.oidfed_storage_record WHERE namespace_key = $3 AND kind = $2 AND namespace = $1",
				[namespace, kind, namespaceKey],
			);
			return result.rows.map((row) => storedPayload(kind, row.id, row.payload, "read", options));
		},
		async selectSubordinates(filter, paging, cursor, after) {
			const types = filter?.entityTypes?.length ? filter.entityTypes : null;
			const result = await client.query<PayloadRow>(
				`SELECT id, payload FROM oidfed.oidfed_storage_record
				 WHERE namespace_key = $8 AND namespace = $1 AND kind = 'subordinate'
				   AND ($2::text[] IS NULL OR (payload->'entityTypes') ?| $2)
				   AND ($3::boolean IS NULL OR COALESCE((payload->>'isIntermediate')::boolean, false) = $3)
				   AND ($4::float8 IS NULL OR (payload->>'updatedAt')::float8 >= $4)
				   AND ($5::float8 IS NULL OR (payload->>'updatedAt')::float8 <= $5)
				   AND ($6::bytea IS NULL OR
				        (substring(entity_order FROM 1 FOR 128), entity_order) >
				        (substring($6 FROM 1 FOR 128), $6)
				        OR (NOT $7::boolean AND entity_order = $6))
				 ORDER BY substring(entity_order FROM 1 FOR 128), entity_order
				 LIMIT ${listingBatchSize}`,
				[
					namespace,
					types,
					filter?.intermediate ?? null,
					paging?.updatedAfter ?? null,
					paging?.updatedBefore ?? null,
					cursor === undefined ? null : entityOrder(cursor),
					after,
					namespaceKey,
				],
			);
			return result.rows.map(({ id, payload }) =>
				storedPayload("subordinate", id, payload, "read", options),
			);
		},
		async selectMarkSubjects(type, subject, cursor, after) {
			const result = await client.query<{ subject: EntityId }>(
				`SELECT DISTINCT subject, subject_order, substring(subject_order FROM 1 FOR 128) AS prefix
				 FROM oidfed.mark_lookup
				 WHERE namespace_key = $6 AND namespace = $1 AND mark_type = $2 AND ($3::text IS NULL OR subject = $3)
				   AND ($4::bytea IS NULL OR
				        (substring(subject_order FROM 1 FOR 128), subject_order) >
				        (substring($4 FROM 1 FOR 128), $4)
				        OR (NOT $5::boolean AND subject_order = $4))
				 ORDER BY prefix, subject_order
				 LIMIT ${listingBatchSize}`,
				[
					namespace,
					type,
					subject ?? null,
					cursor === undefined ? null : entityOrder(cursor),
					after,
					namespaceKey,
				],
			);
			return result.rows.map((row) => row.subject);
		},
		async selectMarks({ issuer, subjects, types }) {
			const result = await client.query<PayloadRow>(
				`SELECT record.id, record.payload
				 FROM oidfed.oidfed_storage_record AS record
				 JOIN (
				   SELECT DISTINCT mark_id, mark_id_key FROM oidfed.mark_lookup
				   WHERE namespace_key = $5 AND namespace = $1 AND ($2::text IS NULL OR issuer = $2)
				     AND ($3::text[] IS NULL OR subject = ANY($3))
				     AND ($4::text[] IS NULL OR mark_type = ANY($4))
				 ) AS selected ON selected.mark_id_key = record.id_key AND selected.mark_id = record.id
				 WHERE record.namespace_key = $5 AND record.namespace = $1 AND record.kind = 'mark'`,
				[namespace, issuer ?? null, subjects ?? null, types ?? null, namespaceKey],
			);
			return result.rows.map(({ id, payload }) =>
				storedPayload("mark", id, payload, "read", options),
			);
		},
		async set(kind, id, payload) {
			const saved = storedPayload(kind, id, payload, "write", options);
			const idKey = storageKey(id);
			const result = await client.query(
				`INSERT INTO oidfed.oidfed_storage_record AS record
				   (namespace, kind, id, payload, entity_order, namespace_key, id_key)
				 VALUES ($1, $2, $3, $4, $5, $6, $7)
				 ON CONFLICT (namespace_key, kind, id_key)
				 DO UPDATE SET payload = EXCLUDED.payload, entity_order = EXCLUDED.entity_order
				 WHERE record.namespace = EXCLUDED.namespace AND record.id = EXCLUDED.id`,
				[
					namespace,
					kind,
					id,
					JSON.stringify(saved),
					kind === "subordinate" ? entityOrder(id) : null,
					namespaceKey,
					idKey,
				],
			);
			if (result.rowCount !== 1) throw new Error("PostgreSQL storage key conflict");
			if (kind === "mark") {
				const selectors = (saved as StoragePayloadByKind["mark"]).map((mark, position) => {
					const decoded = decodeEntityStatement(mark.jwt, options);
					if (!decoded.ok)
						throw new InvalidStorageRecordError("mark", "write", "Invalid Trust Mark issuer");
					return {
						position,
						issuer: decoded.value.payload.iss,
						subject: mark.subject,
						mark_type: mark.trustMarkType,
						subject_order: entityOrder(mark.subject).toString("hex"),
					};
				});
				await client.query(
					"DELETE FROM oidfed.mark_lookup WHERE namespace_key = $3 AND mark_id_key = $4 AND namespace = $1 AND mark_id = $2",
					[namespace, id, namespaceKey, idKey],
				);
				await client.query(
					`INSERT INTO oidfed.mark_lookup (namespace, mark_id, member_position, issuer, subject, mark_type, subject_order, namespace_key, mark_id_key)
					 SELECT $1, $2, position, issuer, subject, mark_type, decode(subject_order, 'hex'), $4, $5
					 FROM jsonb_to_recordset($3::jsonb) AS item
					   (position int, issuer text, subject text, mark_type text, subject_order text)`,
					[namespace, id, JSON.stringify(selectors), namespaceKey, idKey],
				);
			}
		},
		async claimReplay(key, claim, capacity, clock) {
			const time = clock ? clock() : await this.now();
			if (!Number.isFinite(time)) throw new TypeError("Invalid replay clock");
			if (claim.expiresAt <= time) return false;
			await client.query(
				`DELETE FROM oidfed.oidfed_storage_record
				 WHERE namespace_key = $3 AND namespace = $1 AND kind = 'replay' AND replay_expiry <= $2`,
				[namespace, time, namespaceKey],
			);
			const override = clock ? clock() : null;
			if (clock && !Number.isFinite(override)) throw new TypeError("Invalid replay clock");
			const payload = storedPayload(
				"replay",
				key,
				{
					key,
					expiresAt: claim.expiresAt,
					...(claim.extensions ? { extensions: claim.extensions } : {}),
				},
				"write",
				options,
			);
			const result = await client.query<{ claimed: boolean; full: boolean }>(
				`WITH tick AS MATERIALIZED (
				   SELECT COALESCE($5::float8, EXTRACT(EPOCH FROM clock_timestamp())::float8) AS now
				 ), decision AS MATERIALIZED (
				   SELECT now, CASE
				     WHEN $4::float8 <= now THEN 'expired'
				     WHEN EXISTS (
				       SELECT 1 FROM oidfed.oidfed_storage_record
				       WHERE namespace_key = $7 AND id_key = $8 AND namespace = $1 AND kind = 'replay' AND id = $2 AND replay_expiry > now
				     ) THEN 'duplicate'
				     WHEN (
				       SELECT count(*) FROM oidfed.oidfed_storage_record
				       WHERE namespace_key = $7 AND namespace = $1 AND kind = 'replay' AND replay_expiry > now
				     ) >= $6 THEN 'full'
				     ELSE 'claim'
				   END AS outcome FROM tick
				 ), written AS (
				   INSERT INTO oidfed.oidfed_storage_record AS record (namespace, kind, id, payload, namespace_key, id_key)
				   SELECT $1, 'replay', $2, $3::jsonb, $7, $8 FROM decision
				   WHERE outcome = 'claim'
				     AND $4::float8 > COALESCE($5::float8, EXTRACT(EPOCH FROM clock_timestamp())::float8)
				   ON CONFLICT (namespace_key, kind, id_key) DO UPDATE SET payload = EXCLUDED.payload
				   WHERE record.namespace = EXCLUDED.namespace AND record.id = EXCLUDED.id
				     AND record.replay_expiry <= (SELECT now FROM decision)
				   RETURNING id
				 )
				 SELECT EXISTS (SELECT 1 FROM written) AS claimed,
				   outcome = 'full' AND $4::float8 > COALESCE($5::float8, EXTRACT(EPOCH FROM clock_timestamp())::float8) AS full
				 FROM decision`,
				[
					namespace,
					key,
					JSON.stringify(payload),
					claim.expiresAt,
					override,
					capacity,
					namespaceKey,
					storageKey(key),
				],
			);
			const decision = result.rows[0];
			if (!decision) throw new Error("Missing replay claim result");
			if (decision.full) throw new ReplayStoreCapacityError(capacity);
			return decision.claimed;
		},
		async delete(kind, id) {
			const result = await client.query(
				"DELETE FROM oidfed.oidfed_storage_record WHERE namespace_key = $4 AND kind = $2 AND id_key = $5 AND namespace = $1 AND id = $3",
				[namespace, kind, id, namespaceKey, storageKey(id)],
			);
			return result.rowCount === 1;
		},
	};
}

export type PostgresStorageOptions = DatabaseStorageOptions & { pool: Pool; namespace: string };
export function postgresStorage(
	options: PostgresStorageOptions & { replay?: true | undefined },
): ReturnType<typeof createStorage> & { replay: ReplayStore };
export function postgresStorage(options: PostgresStorageOptions): ReturnType<typeof createStorage>;
export function postgresStorage({
	pool,
	namespace,
	...options
}: PostgresStorageOptions): ReturnType<typeof createStorage> {
	const namespaceKey = storageKey(namespace);
	async function run<T>(write: boolean, operation: (records: Records) => Promise<T>): Promise<T> {
		for (let attempt = 0; ; attempt++) {
			const client = await pool.connect();
			let discard = false;
			try {
				await client.query(
					write
						? "BEGIN ISOLATION LEVEL SERIALIZABLE"
						: "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
				);
				if (write) {
					const guard = await client.query(
						`INSERT INTO oidfed.oidfed_storage_guard AS guard (namespace, namespace_key)
						 VALUES ($1, $2)
						 ON CONFLICT (namespace_key) DO UPDATE SET epoch = guard.epoch + 1
						 WHERE guard.namespace = EXCLUDED.namespace`,
						[namespace, namespaceKey],
					);
					if (guard.rowCount !== 1) throw new Error("PostgreSQL storage namespace conflict");
				}
				const result = await operation(operations(client, namespace, namespaceKey, options));
				const commit = await client.query("COMMIT");
				if (commit.command !== "COMMIT")
					throw new Error("PostgreSQL rolled back the storage transaction");
				return result;
			} catch (error) {
				try {
					await client.query("ROLLBACK");
				} catch {
					discard = true;
				}
				// Only server-confirmed transaction aborts are retryable. A connection failure at
				// COMMIT has an unknown outcome and is propagated.
				const code = error instanceof DatabaseError ? error.code : undefined;
				if (discard || attempt >= 4 || (code !== "40001" && code !== "40P01")) throw error;
			} finally {
				client.release(discard);
			}
		}
	}
	const database: Database = {
		read: (operation) => run(false, operation),
		write: (operation) => run(true, operation),
	};
	return createStorage(
		namespace,
		database,
		options.now,
		(name) => postgresStorage({ ...options, pool, namespace: name }),
		options,
	);
}

type RecordKind = keyof StoragePayloadByKind;

interface PayloadRow {
	id: string;
	payload: unknown;
}

interface MarkSelectors {
	issuer?: string;
	subjects?: readonly EntityId[];
	types?: readonly string[];
}

const listingBatchSize = 128;

/** Compare UTF-16 code units in PostgreSQL in the same order as JavaScript strings. */
const entityOrder = (id: string): Buffer => Buffer.from(id, "utf16le").swap16();

interface Records {
	now(): Promise<number>;
	selectSubordinates(
		filter: ListFilter | undefined,
		paging: ListPageOptions | undefined,
		cursor: EntityId | undefined,
		after: boolean,
	): Promise<StoragePayloadByKind["subordinate"][]>;
	selectMarkSubjects(
		type: string,
		subject: EntityId | undefined,
		cursor: EntityId | undefined,
		after: boolean,
	): Promise<EntityId[]>;
	selectMarks(selectors: MarkSelectors): Promise<TrustMarkRecord[][]>;
	claimReplay(
		key: string,
		claim: JtiReplayClaim,
		capacity: number,
		clock?: () => number,
	): Promise<boolean>;
	get<K extends RecordKind>(kind: K, id: string): Promise<StoragePayloadByKind[K] | undefined>;
	list<K extends RecordKind>(kind: K): Promise<StoragePayloadByKind[K][]>;
	set<K extends RecordKind>(kind: K, id: string, payload: StoragePayloadByKind[K]): Promise<void>;
	delete(kind: RecordKind, id: string): Promise<boolean>;
}

function storedPayload<K extends RecordKind>(
	kind: K,
	id: string,
	value: unknown,
	operation: "read" | "write",
	options: StorageValidationOptions,
): StoragePayloadByKind[K] {
	const payload = parseStoragePayload(kind, id, value, operation, options);
	if (
		kind === "mark" &&
		(payload as StoragePayloadByKind["mark"]).some((mark) => digest(mark.jwt) !== id)
	)
		throw new InvalidStorageRecordError(
			kind,
			operation,
			"Trust Mark digest does not match the record key",
		);
	return payload;
}

interface Database {
	read<T>(operation: (records: Records) => Promise<T>): Promise<T>;
	write<T>(operation: (records: Records) => Promise<T>): Promise<T>;
}

const digest = (s: string): string => createHash("sha256").update(s).digest("hex");
const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
function latest(a: TrustMarkRecord, b: TrustMarkRecord): number {
	return b.issuedAt - a.issuedAt || compare(b.jwt, a.jwt);
}
/** Scan keyset batches inside one snapshot until we find the first unreturned match. */
async function readPage<T>(
	cursor: EntityId | undefined,
	limit: number | undefined,
	batch: (
		cursor: EntityId | undefined,
		after: boolean,
	) => Promise<{
		subjects: readonly EntityId[];
		matches: ReadonlyMap<EntityId, T>;
	}>,
) {
	if (limit !== undefined && (!Number.isSafeInteger(limit) || limit < 1))
		throw new RangeError("Invalid page limit");
	const items: T[] = [];
	let after = false;
	for (;;) {
		const { subjects, matches } = await batch(cursor, after);
		for (const id of subjects) {
			const item = matches.get(id);
			if (item === undefined) continue;
			if (items.length === limit) return { items, nextCursor: id };
			items.push(item);
		}
		if (subjects.length < listingBatchSize) return { items };
		cursor = subjects[subjects.length - 1];
		after = true;
	}
}

function repositories(db: Database, options: StorageValidationOptions) {
	const belongs = (mark: TrustMarkRecord, issuer?: string) => {
		if (issuer === undefined) return true;
		const decoded = decodeEntityStatement(mark.jwt, options);
		return decoded.ok && decoded.value.payload.iss === issuer;
	};
	const revision = () => db.read(async (records) => (await records.get("markRevision", "")) ?? "0");
	const bump = async (records: Records) => {
		const current = (await records.get("markRevision", "")) ?? "0";
		await records.set("markRevision", "", (BigInt(current) + 1n).toString());
	};

	const subordinate: SubordinateStore = {
		fetch: (id) => db.read((records) => records.get("subordinate", id)),
		list(filter?: ListFilter, pagingOptions?: ListPageOptions) {
			const selected = cloneData(filter);
			const paging = cloneData(pagingOptions);
			const filterByMark = selected?.trustMarked === true || selected?.trustMarkType !== undefined;
			const validAt = selected?.validAt;
			if (filterByMark && (validAt === undefined || !Number.isFinite(validAt)))
				return Promise.reject(new TypeError("Invalid validAt"));
			const types =
				typeof selected?.trustMarkType === "string"
					? [selected.trustMarkType]
					: selected?.trustMarkType;
			return db.read((records) =>
				readPage(paging?.cursor, paging?.limit, async (cursor, after) => {
					const candidates = await records.selectSubordinates(selected, paging, cursor, after);
					const subjects = candidates.map((record) => record.entityId);
					const eligible =
						filterByMark && validAt !== undefined && subjects.length > 0
							? new Set(
									(await records.selectMarks({ subjects, ...(types ? { types } : {}) }))
										.flat()
										.filter(
											(mark) =>
												(!types || types.includes(mark.trustMarkType)) &&
												isStoredTrustMarkEligible(mark, validAt, options),
										)
										.map((mark) => mark.subject),
								)
							: undefined;
					const matches = new Map(
						candidates
							.filter((record) => !eligible || eligible.has(record.entityId))
							.map((record) => [record.entityId, record]),
					);
					return { subjects, matches };
				}),
			);
		},
		async register(record) {
			const captured = parseSubordinateRecord(record, options, "register");
			await db.write(async (records) => {
				if (await records.get("subordinate", captured.entityId))
					throw new Error("Subordinate already exists");
				await records.set("subordinate", captured.entityId, captured);
			});
		},
		async update(id, changes, updatedAt) {
			const captured = parseSubordinateUpdate(changes, options);
			await db.write(async (records) => {
				const existing = await records.get("subordinate", id);
				if (!existing) throw new Error("Subordinate not found");
				const record = {
					...existing,
					...captured,
					entityId: id,
					createdAt: existing.createdAt,
					updatedAt,
				};
				await records.set("subordinate", id, parseSubordinateRecord(record, options, "update"));
			});
		},
		async remove(id) {
			if (!(await db.write((records) => records.delete("subordinate", id))))
				throw new Error("Subordinate not found");
		},
	};
	const subordinateEvent: SubordinateEventStore = {
		async append(issuer, subject, events) {
			const captured = parseStoredSubordinateEvents(events, "append");
			const key = JSON.stringify([issuer, subject]);
			await db.write(async (records) => {
				const existing = await records.get("event", key);
				await records.set("event", key, {
					...existing,
					events: [...(existing?.events ?? []), ...captured],
				});
			});
		},
		history: (issuer, subject) =>
			db.read(
				async (records) =>
					(await records.get("event", JSON.stringify([issuer, subject])))?.events ?? [],
			),
	};
	const selects = (record: TrustMarkRecord, type?: string, subject?: EntityId) =>
		(type === undefined || record.trustMarkType === type) &&
		(subject === undefined || record.subject === subject);
	const selectors = (type?: string, subject?: EntityId): MarkSelectors => ({
		...(type !== undefined ? { types: [type] } : {}),
		...(subject !== undefined ? { subjects: [subject] } : {}),
	});
	const eligible = (at: number, type?: string, subject?: EntityId) =>
		db.read(async (records) =>
			(await records.selectMarks(selectors(type, subject)))
				.flat()
				.filter(
					(record) =>
						selects(record, type, subject) && isStoredTrustMarkEligible(record, at, options),
				)
				.sort(latest),
		);
	function firstBy(
		records: TrustMarkRecord[],
		key: "subject" | "trustMarkType",
	): TrustMarkRecord[] {
		const values = new Map<string, TrustMarkRecord>();
		for (const row of records) if (!values.has(row[key])) values.set(row[key], row);
		return [...values.values()].sort((a, b) => compare(a[key], b[key]));
	}
	const trustMark: TrustMarkStore = {
		revision,
		candidates({ issuer, trustMarkType, subject }) {
			return db.read(async (records) =>
				(await records.selectMarks({ issuer, ...selectors(trustMarkType, subject) }))
					.flat()
					.filter((record) => belongs(record, issuer) && selects(record, trustMarkType, subject)),
			);
		},
		status: (jwt) =>
			db.read(async (records) =>
				(await records.get("mark", digest(jwt)))?.find((mark) => mark.jwt === jwt),
			),
		async valid(type, subject, at) {
			return (await eligible(at, type, subject))[0];
		},
		listSubjects(type, at, { subject, cursor, limit }) {
			return db.read((records) =>
				readPage(cursor, limit, async (position, after) => {
					const subjects = await records.selectMarkSubjects(type, subject, position, after);
					const matches = new Map<EntityId, TrustMarkRecord>();
					if (subjects.length > 0) {
						const ordered = (await records.selectMarks({ types: [type], subjects }))
							.flat()
							.filter(
								(mark) =>
									mark.trustMarkType === type && isStoredTrustMarkEligible(mark, at, options),
							)
							.sort(latest);
						for (const mark of ordered)
							if (!matches.has(mark.subject)) matches.set(mark.subject, mark);
					}
					return { subjects, matches };
				}),
			);
		},
		async forSubject(subject, at) {
			return firstBy(await eligible(at, undefined, subject), "trustMarkType");
		},
		async hasAny(subject, at) {
			return (await eligible(at, undefined, subject)).length > 0;
		},
		async issue(record) {
			const captured = parseStoredTrustMark(record, options, "issue");
			await db.write(async (records) => {
				const key = digest(captured.jwt);
				const bucket = (await records.get("mark", key)) ?? [];
				if (bucket.some((existing) => existing.jwt === captured.jwt)) return;
				await records.set("mark", key, [...bucket, captured]);
				await bump(records);
			});
		},
		async revoke(type, subject, revokedAt, issuer) {
			if (!Number.isFinite(revokedAt)) throw new TypeError("Invalid revocation date");
			await db.write(async (records) => {
				let changed = false;
				for (const bucket of await records.selectMarks({
					...selectors(type, subject),
					...(issuer === undefined ? {} : { issuer }),
				})) {
					const affected = bucket.filter(
						(mark) => mark.active && belongs(mark, issuer) && selects(mark, type, subject),
					);
					const first = affected[0];
					if (!first) continue;
					await records.set(
						"mark",
						digest(first.jwt),
						bucket.map((mark) =>
							affected.includes(mark) ? { ...mark, active: false, revokedAt } : mark,
						),
					);
					changed = true;
				}
				if (!changed) throw new Error("Trust Mark not found");
				await bump(records);
			});
		},
	};
	return { subordinate, subordinateEvent, trustMark };
}

const recordCapabilities = [
	"subordinate:read",
	"subordinate:write",
	"subordinateEvent:read",
	"subordinateEvent:write",
	"trustMark:read",
	"trustMark:write",
	"transaction",
	"snapshot",
	"replay",
	"entityCollection",
	"namespace",
] as const satisfies readonly StorageCapability[];

function createStorage(
	namespace: string,
	db: Database,
	now: (() => number) | undefined,
	withNamespace: (name: string) => FederationStorage,
	options: DatabaseStorageOptions,
) {
	const { maxReplayEntries = 10_000, replay: replayEnabled = true, collection } = options;
	if (replayEnabled && (!Number.isSafeInteger(maxReplayEntries) || maxReplayEntries < 1))
		throw new RangeError("Invalid replay capacity");
	async function scoped<T>(
		records: Records,
		operation: (view: ReturnType<typeof repositories>) => Promise<T>,
		writable: boolean,
	): Promise<T> {
		let open = true;
		let pending = 0;
		let tail = Promise.resolve();
		const read: Database["read"] = (work) => {
			if (!open) return Promise.reject(new Error("Storage view has closed"));
			pending++;
			const next = tail.then(() => {
				if (!open) throw new Error("Storage view has closed");
				return work(records);
			});
			const settled = () => {
				pending--;
			};
			tail = next.then(settled, settled);
			return next;
		};
		try {
			const result = await operation(
				repositories(
					{
						read,
						write: (work) =>
							writable ? read(work) : Promise.reject(new Error("Read-only snapshot")),
					},
					options,
				),
			);
			if (pending > 0) throw new Error("Storage callback must await its repository operations");
			return result;
		} finally {
			open = false;
			await tail;
		}
	}
	const { subordinate, trustMark, subordinateEvent } = repositories(db, options);
	return {
		subordinate,
		trustMark,
		subordinateEvent,
		namespace,
		capabilities: replayEnabled
			? recordCapabilities
			: recordCapabilities.filter((capability) => capability !== "replay"),
		entityCollection: durableCollection(db, collection, now),
		isolation: "serializable",
		withNamespace,
		transaction<T>(operation: (view: TransactionView) => Promise<T>) {
			return db.write((records) =>
				scoped(
					records,
					(view) =>
						operation({
							...view,
							trustMark: {
								...view.trustMark,
								checkRevision: async (expected) => (await view.trustMark.revision()) === expected,
							},
						}),
					true,
				),
			);
		},
		readSnapshot<T>(operation: (view: ReadSnapshotView) => Promise<T>) {
			return db.read((records) =>
				scoped(
					records,
					({ subordinate, subordinateEvent, trustMark }) => {
						const { issue: _issue, revoke: _revoke, ...queries } = trustMark;
						return operation({
							subordinate: { fetch: subordinate.fetch, list: subordinate.list },
							subordinateEvent: { history: subordinateEvent.history },
							trustMark: queries,
						});
					},
					false,
				),
			);
		},
		...(replayEnabled
			? {
					replay: {
						async useJti(input: JtiReplayClaim) {
							const claim = parseStorageRecord(JtiReplayClaimSchema, input, "replay", "claim");
							const key = digest(JSON.stringify([claim.issuer, claim.audience, claim.jti]));
							return db.write((records) => records.claimReplay(key, claim, maxReplayEntries, now));
						},
					},
				}
			: {}),
	} satisfies FederationStorage;
}

interface DatabaseStorageOptions extends StorageValidationOptions {
	readonly now?: () => number;
	readonly maxReplayEntries?: number;
	readonly replay?: boolean;
	readonly collection?: CollectionStorageOptions;
}

interface CollectionStorageOptions {
	readonly retentionSeconds?: number;
	readonly maxSnapshots?: number;
	readonly maxCursors?: number;
}

/** Publish and retain Collection snapshots in PostgreSQL. */
function durableCollection(
	database: Database,
	options?: CollectionStorageOptions,
	clock?: () => number,
): EntityCollectionStore {
	const retention = options?.retentionSeconds ?? 900;
	const maxSnapshots = options?.maxSnapshots ?? 100;
	const maxCursors = options?.maxCursors ?? 10000;
	if (![retention, maxSnapshots, maxCursors].every((n) => Number.isSafeInteger(n) && n > 0))
		throw new RangeError("Collection store limits must be positive safe integers");

	async function now(records: Records): Promise<number> {
		const time = clock ? clock() : await records.now();
		if (!Number.isFinite(time)) throw new RangeError("Invalid Collection storage clock");
		return time;
	}

	async function currentRow(records: Records, anchor: EntityId) {
		const pointer = await records.get("collectionCurrent", anchor);
		if (pointer === undefined) return undefined;
		const snapshot = await records.get("collectionSnapshot", pointer);
		if (!snapshot || snapshot.value.trustAnchor !== anchor || snapshot.retainUntil !== undefined)
			throw new InvalidStorageRecordError(
				"collectionCurrent",
				"read",
				"Invalid current snapshot reference",
			);
		return snapshot;
	}

	return {
		async publish(input) {
			const snapshot = parseStorageRecord(
				EntityCollectionSnapshotSchema,
				input,
				"collectionSnapshot",
				"publish",
			);
			await database.write(async (records) => {
				const time = await now(records);
				const previous = await currentRow(records, snapshot.trustAnchor);
				const snapshots = await records.list("collectionSnapshot");
				const retained = [];
				for (const item of snapshots) {
					if (item.retainUntil !== undefined && item.retainUntil <= time)
						await records.delete("collectionSnapshot", item.value.id);
					else retained.push(item);
				}
				if (
					retained.some((item) => item.value.id === snapshot.id) ||
					(await records.list("collectionCursor")).some(
						({ value }) => value.snapshotId === snapshot.id && value.expiresAt > time,
					)
				)
					throw new Error("Snapshot identifiers must be unique");

				const previousId = previous?.value.id;
				const historical = retained
					.filter((item) => item.retainUntil !== undefined)
					.sort((a, b) => {
						const difference = BigInt(a.order) - BigInt(b.order);
						return difference < 0n ? -1 : difference > 0n ? 1 : 0;
					});
				const needed = retained.length - maxSnapshots + 1;
				const evicted = historical.slice(0, Math.max(0, needed));
				const replacePrevious = needed > evicted.length;
				if (needed > evicted.length + (previousId === undefined ? 0 : 1))
					throw new Error(
						`Collection snapshot capacity ${maxSnapshots} is occupied by current anchors`,
					);

				for (const item of evicted) await records.delete("collectionSnapshot", item.value.id);
				if (previous) {
					if (replacePrevious) await records.delete("collectionSnapshot", previous.value.id);
					else {
						const retainUntil = time + retention;
						if (!Number.isFinite(retainUntil)) throw new RangeError("Invalid snapshot deadline");
						await records.set("collectionSnapshot", previous.value.id, {
							...previous,
							retainUntil,
						});
					}
				}
				const counter = (await records.get("collectionSequence", "")) ?? "0";
				const order = (BigInt(counter) + 1n).toString();
				await records.set("collectionSequence", "", order);
				await records.set("collectionSnapshot", snapshot.id, { value: snapshot, order });
				await records.set("collectionCurrent", snapshot.trustAnchor, snapshot.id);
			});
		},
		current(anchor) {
			return database.read(async (records) => (await currentRow(records, anchor))?.value);
		},
		snapshot(id) {
			return database.read(async (records) => {
				const item = await records.get("collectionSnapshot", id);
				if (!item) return undefined;
				if (item.retainUntil !== undefined && item.retainUntil <= (await now(records)))
					return undefined;
				return item.value;
			});
		},
		async saveCursor(id, input) {
			const value = parseStorageRecord(
				EntityCollectionCursorSchema,
				input,
				"collectionCursor",
				"save",
			);
			await database.write(async (records) => {
				const time = await now(records);
				let live = 0;
				let existing = false;
				for (const item of await records.list("collectionCursor")) {
					if (item.value.expiresAt <= time) await records.delete("collectionCursor", item.id);
					else {
						live++;
						existing ||= item.id === id;
					}
				}
				if (!existing && live >= maxCursors)
					throw new EntityCollectionCursorCapacityError(maxCursors);
				await records.set("collectionCursor", id, { id, value });
			});
		},
		cursor(id) {
			return database.read(async (records) => {
				const item = await records.get("collectionCursor", id);
				if (!item || item.value.expiresAt <= (await now(records))) return undefined;
				return item.value;
			});
		},
	};
}
