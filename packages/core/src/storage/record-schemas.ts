import type { JwsAlgorithmRegistry } from "@oidfed/crypto";
import { z } from "zod";
import { cloneData } from "../data-copy.js";
import { preparePublicJwkSet } from "../jwks/public-material.js";
import type { MetadataPolicyOptions } from "../metadata-policy/index.js";
import { TrustChainConstraintsSchema } from "../schemas/constraints.js";
import {
	createCollectionSchemas,
	type EntityCollectionEntity,
	EntityCollectionEntitySchema,
	EntityTypeInfoSchema,
} from "../schemas/entity-collection.js";
import { EntityIdSchema } from "../schemas/entity-id.js";
import { SubordinateStatementSchema } from "../schemas/entity-statement.js";
import { type JWKSet, JWKSetSchema, validatePublishedMetadataKeys } from "../schemas/jwk.js";
import { SubordinateEventSchema } from "../schemas/subordinate-events.js";
import { TrustMarkPayloadSchema } from "../schemas/trust-mark.js";
import { matchTrustMarkProfile, type TrustMarkProfile } from "../trust-marks/profiles.js";
import type { EntityId } from "../types.js";
import { InvalidStorageRecordError, InvalidSubordinateRecord } from "./errors.js";
import { assertSubordinatePublicationClaims } from "./subordinate-publication.js";
import {
	assertMetadataValuesNotNull,
	isFederationEntityOperationalField,
} from "./subordinate-statement-shape.js";
import { readStoredDelegation, readStoredSignedJwt } from "./trust-mark-eligibility.js";

export type JsonValue = string | boolean | number | null | readonly JsonValue[] | JsonObject;
export interface JsonObject {
	readonly [name: string]: JsonValue;
}

/** Validate data that can round-trip without invoking accessors or changing JSON values. */
export function isStorageJson(value: unknown, allowOptionalFields = false): boolean {
	const ancestors = new Set<object>();
	const pending: ({ value: unknown } | { leave: object })[] = [{ value }];
	while (pending.length) {
		const entry = pending.pop();
		if (!entry) break;
		if ("leave" in entry) {
			ancestors.delete(entry.leave);
			continue;
		}
		const current = entry.value;
		if (current === null || typeof current === "string" || typeof current === "boolean") continue;
		if (typeof current === "number") {
			if (!Number.isFinite(current)) return false;
			continue;
		}
		if (typeof current !== "object" || !current || ancestors.has(current)) return false;
		const array = Array.isArray(current);
		const prototype: unknown = Object.getPrototypeOf(current);
		if (
			array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null
		)
			return false;
		const keys = Reflect.ownKeys(current);
		if (array && keys.length !== current.length + 1) return false;
		ancestors.add(current);
		pending.push({ leave: current });
		for (const key of keys) {
			if (array && key === "length") continue;
			if (typeof key !== "string") return false;
			if (array && (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= current.length)) return false;
			const descriptor = Object.getOwnPropertyDescriptor(current, key);
			if (!descriptor?.enumerable || !("value" in descriptor)) return false;
			const nested: unknown = descriptor.value;
			if (!(allowOptionalFields && !array && nested === undefined)) pending.push({ value: nested });
		}
	}
	return true;
}

function jsonObject(value: unknown): value is JsonObject {
	return (
		value !== null && typeof value === "object" && !Array.isArray(value) && isStorageJson(value)
	);
}

const extensions = z.custom<JsonObject>(jsonObject, "Expected a JSON object").optional();
export const StorageEntityIdSchema = EntityIdSchema;
const numericDate = z.number().finite();
const nonEmpty = z.string().min(1);
const readonlyNames = z.array(nonEmpty).readonly();
const protocolObject = z.custom<Readonly<Record<string, unknown>>>(
	jsonObject,
	"Expected a JSON object",
);

/** JSON accepted by the generic cache contract. */
export const StorageJsonSchema = z.custom<JsonValue>(
	(value) => isStorageJson(value),
	"Expected JSON data",
);
export const CacheWriteSchema = z.strictObject({
	key: z.string(),
	value: StorageJsonSchema,
	ttlSeconds: z.number().finite().positive(),
});

export const SubordinateRecordSchema = z.strictObject({
	entityId: StorageEntityIdSchema,
	jwks: z.custom<JWKSet>(
		(value) => isStorageJson(value) && JWKSetSchema.safeParse(value).success,
		"Expected public Federation JWKS",
	),
	createdAt: numericDate,
	updatedAt: numericDate,
	metadata: protocolObject.optional(),
	metadataPolicy: protocolObject.optional(),
	constraints: z
		.custom<z.infer<typeof TrustChainConstraintsSchema>>(
			(value) => jsonObject(value) && TrustChainConstraintsSchema.safeParse(value).success,
			"Expected JSON Trust Chain constraints",
		)
		.optional(),
	entityTypes: readonlyNames.optional(),
	isIntermediate: z.boolean().optional(),
	sourceEndpoint: SubordinateStatementSchema.shape.source_endpoint,
	metadataPolicyCrit: readonlyNames.optional(),
	additionalClaims: protocolObject.optional(),
	crit: readonlyNames.optional(),
	extensions,
});

function checkSubordinateClaims(
	record: z.infer<typeof SubordinateRecordSchema>,
	options?: MetadataPolicyOptions,
): void {
	const federation = record.metadata?.federation_entity;
	if (federation && typeof federation === "object") {
		const fields = Object.keys(federation).filter(isFederationEntityOperationalField);
		if (fields.length)
			throw new Error(`Operational fields belong in Entity Configuration: ${fields.join(", ")}`);
	}
	assertMetadataValuesNotNull(record.metadata);
	assertSubordinatePublicationClaims(record, options);
}

/** Context used to validate deployment-specific key material and policy operators. */
export interface StorageValidationOptions extends MetadataPolicyOptions {
	readonly customPolicyOperators?: MetadataPolicyOptions["customOperators"];
	readonly algorithmRegistry?: JwsAlgorithmRegistry | undefined;
	readonly maxCompactBytes?: number | undefined;
	readonly trustMarkProfiles?: readonly TrustMarkProfile[] | undefined;
}

export function parseSubordinateRecord(
	value: unknown,
	options: StorageValidationOptions = {},
	operation = "validate",
): z.infer<typeof SubordinateRecordSchema> {
	try {
		const checked = isStorageJson(value, true)
			? SubordinateRecordSchema.safeParse(value)
			: undefined;
		if (!checked?.success) {
			const issue = checked?.error.issues[0];
			const field = issue?.path[0];
			throw new InvalidSubordinateRecord(
				field === "entityId"
					? "Subordinate entityId must be a valid Entity Identifier"
					: `Invalid Subordinate Statement storage shape${field ? `: ${String(field)}` : ""}`,
				operation,
			);
		}
		const record = detachedStorageValue(checked.data);
		checkSubordinateClaims(record, {
			customOperators: options.customPolicyOperators ?? options.customOperators,
		});
		if (record.metadata) validatePublishedMetadataKeys(record.metadata, options.algorithmRegistry);
		const keys = preparePublicJwkSet(record.jwks, options.algorithmRegistry);
		if (!keys.ok) throw new Error(keys.error.description);
		return { ...record, jwks: keys.value };
	} catch (error) {
		if (error instanceof InvalidSubordinateRecord) throw error;
		throw new InvalidSubordinateRecord(
			error instanceof InvalidStorageRecordError
				? "Invalid Subordinate Statement storage shape"
				: error instanceof Error
					? error.message
					: "Invalid subordinate publication claims",
			operation,
		);
	}
}

export const SubordinateRecordUpdateSchema = SubordinateRecordSchema.omit({
	entityId: true,
	createdAt: true,
	updatedAt: true,
}).partial();

/** Capture an update without dropping explicit undefined used to clear optional fields. */
export function parseSubordinateUpdate(
	value: unknown,
	options?: StorageValidationOptions,
): z.infer<typeof SubordinateRecordUpdateSchema> {
	const parsed = isStorageJson(value, true)
		? SubordinateRecordUpdateSchema.safeParse(value)
		: undefined;
	if (!parsed?.success) {
		const field = parsed?.error.issues[0]?.path[0];
		throw new InvalidSubordinateRecord(
			`Invalid Subordinate Statement update${field ? `: ${String(field)}` : ""}`,
			"update",
		);
	}
	const patch = cloneData(parsed.data);
	if (options && patch.jwks !== undefined) {
		const keys = preparePublicJwkSet(patch.jwks, options.algorithmRegistry);
		if (!keys.ok) throw new InvalidSubordinateRecord(keys.error.description, "update");
		patch.jwks = keys.value;
	}
	if (options && patch.metadata) {
		try {
			validatePublishedMetadataKeys(patch.metadata, options.algorithmRegistry);
		} catch (error) {
			throw new InvalidSubordinateRecord(
				error instanceof Error ? error.message : "Invalid inline protocol keys",
				"update",
			);
		}
	}
	return patch;
}

export const SubordinatePageSchema = z.strictObject({
	items: z.array(SubordinateRecordSchema),
	nextCursor: StorageEntityIdSchema.optional(),
});

export const trustMarkFields = z
	.strictObject({
		trustMarkType: nonEmpty,
		subject: StorageEntityIdSchema,
		jwt: nonEmpty,
		issuedAt: numericDate,
		expiresAt: numericDate.optional(),
		active: z.boolean(),
		revokedAt: numericDate.optional(),
		extensions,
	})
	.refine(
		(record) => !record.active || record.revokedAt === undefined,
		"Active marks cannot be revoked",
	);

function trustMarkClaims(
	record: z.infer<typeof trustMarkFields>,
	options: StorageValidationOptions,
) {
	const token = readStoredSignedJwt(record.jwt, options);
	if (!token) return undefined;
	const claims = TrustMarkPayloadSchema.safeParse(token.payload);
	if (
		!claims.success ||
		String(claims.data.sub) !== record.subject ||
		claims.data.trust_mark_type !== record.trustMarkType ||
		claims.data.iat !== record.issuedAt ||
		claims.data.exp !== record.expiresAt ||
		!matchTrustMarkProfile(token.header.typ, record.trustMarkType, options.trustMarkProfiles).ok
	)
		return undefined;
	if (claims.data.delegation !== undefined) {
		const delegation = readStoredDelegation(claims.data.delegation, options);
		if (
			!delegation ||
			delegation.sub !== claims.data.iss ||
			delegation.trust_mark_type !== record.trustMarkType
		)
			return undefined;
	}
	return claims.data;
}

/** Validate a stored mark with the base Trust Mark profile, registry, and compact size limit. */
export const TrustMarkRecordSchema = trustMarkFields.refine(
	(record) => !!trustMarkClaims(record, {}),
	{
		message: "Invalid or inconsistent Trust Mark claims",
	},
);

/** Check stored claims and their configured profile. Ingestion establishes signature trust. */
export function parseStoredTrustMark(
	value: unknown,
	options: StorageValidationOptions = {},
	operation = "validate",
	expected?: {
		readonly issuer?: string;
		readonly subject?: EntityId;
		readonly trustMarkType?: string;
		readonly jwt?: string;
	},
): z.infer<typeof TrustMarkRecordSchema> {
	const record = parseStorageRecord(trustMarkFields, value, "trustMark", operation);
	const claims = trustMarkClaims(record, options);
	if (
		!claims ||
		(expected?.issuer !== undefined && claims.iss !== expected.issuer) ||
		(expected?.subject !== undefined && record.subject !== expected.subject) ||
		(expected?.trustMarkType !== undefined && record.trustMarkType !== expected.trustMarkType) ||
		(expected?.jwt !== undefined && record.jwt !== expected.jwt)
	)
		throw new InvalidStorageRecordError(
			"trustMark",
			operation,
			"Inconsistent Trust Mark claims or identity",
		);
	return record;
}

export const TrustMarkRevisionSchema = nonEmpty;
export const StoredSubordinateEventSchema = z.preprocess(
	(value) => {
		if (!isStorageJson(value, true) || !value || typeof value !== "object" || Array.isArray(value))
			return undefined;
		const captured = { ...value } as Record<string, unknown>;
		for (const field of ["event_description", "information_uri"])
			if (captured[field] === undefined) delete captured[field];
		return isStorageJson(captured) ? captured : undefined;
	},
	SubordinateEventSchema.extend({
		iat: numericDate,
		event: z.string().min(1, "Event name must not be empty"),
	}),
);

export const SubordinateEventHistorySchema = z.strictObject({
	events: z.array(StoredSubordinateEventSchema),
	extensions,
});

const eventArray = z.array(StoredSubordinateEventSchema);

/** Capture a dense event batch before opening a write or returning history. */
export function parseStoredSubordinateEvents(value: unknown, operation: string) {
	return parseStorageRecord(eventArray, value, "subordinateEvent", operation);
}

// Host-declared informational names can contain hashes. Persist their values intact and
// validate contextual language suffixes through the Collection service's configured schema.
const storedCollectionEntity = EntityCollectionEntitySchema.extend({
	entity_infos: z.record(z.string(), z.record(z.string(), StorageJsonSchema)).optional(),
})
	.transform((entity): EntityCollectionEntity => {
		for (const field of ["entity_types", "entity_infos", "trust_marks"] as const)
			if (entity[field] === undefined) delete entity[field];
		return entity;
	})
	.refine(
		(entity) =>
			isStorageJson(entity) &&
			Object.values(entity.entity_infos ?? {}).every(
				(info) =>
					EntityTypeInfoSchema.safeParse(
						Object.fromEntries(Object.entries(info).filter(([name]) => !name.includes("#"))),
					).success,
			),
		"Invalid stored Collection entity",
	);

function collectionEntrySchema(entity: z.ZodType<EntityCollectionEntity>) {
	return z
		.strictObject({
			entity,
			expiresAt: numericDate,
			chainExpiresAt: numericDate.optional(),
			verifiedMarks: z
				.array(
					z.strictObject({
						type: nonEmpty,
						jwt: nonEmpty,
						expiresAt: numericDate,
					}),
				)
				.readonly(),
			extensions,
		})
		.refine(
			({ entity, verifiedMarks }) => {
				const refs = new Map(
					(entity.trust_marks ?? []).map((ref) => [ref.trust_mark, ref.trust_mark_type]),
				);
				return verifiedMarks.every((mark) => refs.get(mark.jwt) === mark.type);
			},
			{ path: ["verifiedMarks"], message: "Trust Mark evidence must match a published reference" },
		);
}

export const CollectionEntrySchema = collectionEntrySchema(storedCollectionEntity);

function collectionSnapshotSchema(entry: typeof CollectionEntrySchema) {
	return z
		.strictObject({
			id: nonEmpty,
			trustAnchor: StorageEntityIdSchema,
			lastUpdated: numericDate,
			entries: z.array(entry),
			extensions,
		})
		.refine(
			(snapshot) =>
				new Set(snapshot.entries.map((item) => item.entity.entity_id)).size ===
				snapshot.entries.length,
			{ path: ["entries"], message: "Collection Entity Identifiers must be unique" },
		)
		.transform(({ entries, ...snapshot }) => ({
			...snapshot,
			entries: Object.freeze(
				entries.sort((a, b) => {
					const left = a.entity.entity_id;
					const right = b.entity.entity_id;
					return left < right ? -1 : left > right ? 1 : 0;
				}),
			),
		}));
}

export const EntityCollectionSnapshotSchema = collectionSnapshotSchema(CollectionEntrySchema);

/** Validate the configured entity shape and its stored evidence in one snapshot pass. */
export function collectionReadSchema(
	infoClaims: Parameters<typeof createCollectionSchemas>[0],
	options: StorageValidationOptions,
) {
	const entity = createCollectionSchemas(infoClaims).entity.transform(
		(value): EntityCollectionEntity => {
			for (const field of ["entity_types", "entity_infos", "trust_marks"] as const)
				if (value[field] === undefined) delete value[field];
			return value;
		},
	);
	return collectionSnapshotSchema(
		collectionEntrySchema(entity).refine(
			(entry) =>
				entry.verifiedMarks.every((mark) => {
					const signed = readStoredSignedJwt(mark.jwt, options);
					if (
						!signed ||
						!matchTrustMarkProfile(signed.header.typ, mark.type, options.trustMarkProfiles).ok
					)
						return false;
					const claims = TrustMarkPayloadSchema.safeParse(signed.payload);
					if (
						!claims.success ||
						claims.data.sub !== entry.entity.entity_id ||
						claims.data.trust_mark_type !== mark.type ||
						(claims.data.exp !== undefined && mark.expiresAt > claims.data.exp)
					)
						return false;
					if (!claims.data.delegation) return true;
					const delegation = readStoredDelegation(claims.data.delegation, options);
					return (
						!!delegation &&
						delegation.sub === claims.data.iss &&
						delegation.trust_mark_type === mark.type &&
						(delegation.exp === undefined || mark.expiresAt <= delegation.exp)
					);
				}),
			{ path: ["verifiedMarks"], message: "Trust Mark evidence must match the Collection entity" },
		),
	);
}

export const EntityCollectionCursorSchema = z.strictObject({
	snapshotId: nonEmpty,
	trustAnchor: StorageEntityIdSchema,
	context: nonEmpty,
	index: z.int().nonnegative(),
	expiresAt: numericDate,
	extensions,
});

export const JtiReplayClaimSchema = z.strictObject({
	issuer: nonEmpty,
	audience: nonEmpty,
	jti: nonEmpty,
	expiresAt: numericDate,
	extensions,
});

/** Parse and detach a record using an operation-specific error without embedding the record. */
export function parseStorageRecord<T>(
	schema: z.ZodType<T>,
	value: unknown,
	kind: string,
	operation: string,
): T {
	if (!isStorageJson(value, true))
		throw new InvalidStorageRecordError(
			kind,
			operation,
			kind === "trustMark"
				? "Expected JSON record data with finite NumericDates"
				: "Expected JSON record data",
		);
	const parsed = schema.safeParse(value);
	if (!parsed.success) {
		const field = parsed.error.issues[0]?.path.join(".");
		throw new InvalidStorageRecordError(
			kind,
			operation,
			kind === "subordinateEvent" && (field === "event" || field?.endsWith(".event"))
				? "Invalid event field or empty event name"
				: ["issuedAt", "expiresAt", "revokedAt"].includes(field ?? "") && kind === "trustMark"
					? "Trust Mark timestamps must be finite NumericDates"
					: field
						? `Invalid field ${field}`
						: "Invalid record shape",
		);
	}
	// Zod can retain an explicitly undefined optional property. Omit it before storing.
	return detachedStorageValue(parsed.data);
}

function detachedStorageValue<T>(data: T): T {
	const output = cloneData(data);
	if (output && typeof output === "object" && !Array.isArray(output))
		for (const key of Object.keys(output))
			if (Reflect.get(output, key) === undefined) Reflect.deleteProperty(output, key);
	return output;
}

export type CacheWrite = z.infer<typeof CacheWriteSchema>;
export type SubordinateEventHistory = z.infer<typeof SubordinateEventHistorySchema>;
export type TrustMarkRevision = z.infer<typeof TrustMarkRevisionSchema>;
