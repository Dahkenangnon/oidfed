import {
	type EntityId,
	nowSeconds,
	preparePublicJwkSet,
	type SubordinateEvent,
	SubordinateEventType,
} from "@oidfed/core";
import type { HandlerContext } from "./endpoints/context.js";
import type {
	StorageTransaction,
	SubordinateEventAnnotations,
	SubordinateRecord,
	SubordinateRecordUpdate,
} from "./storage/types.js";
import { parsePublishedSubordinateEvent } from "./utils/subordinate-event.js";
import { sanitizeSubordinateMetadata } from "./utils/subordinate-statement-shape.js";

function canonical(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
	if (value && typeof value === "object") {
		return `{${Object.entries(value)
			.filter(([, v]) => v !== undefined)
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
			.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`)
			.join(",")}}`;
	}
	return JSON.stringify(value) ?? "undefined";
}

function publicKeys(record: SubordinateRecord): string {
	const prepared = preparePublicJwkSet(record.jwks);
	if (!prepared.ok) throw new Error(prepared.error.description);
	// Compare the published JSON, including lifecycle and extension members. Only
	// key order is immaterial; Federation §8.7 dates can change without new key material.
	return canonical({ ...prepared.value, keys: prepared.value.keys.map(canonical).sort() });
}

function sanitize<T extends SubordinateRecordUpdate>(record: T): T {
	if (!("metadata" in record)) return record;
	const { metadata, ...rest } = record;
	const cleaned = sanitizeSubordinateMetadata(metadata);
	return { ...rest, metadata: cleaned } as T;
}

/** One capture boundary for both authority classes; raw adapter writes remain untracked. */
export function createSubordinateLifecycle(ctx: HandlerContext) {
	function annotationFields(
		annotations?: SubordinateEventAnnotations,
	): Pick<SubordinateEvent, "event_description" | "information_uri"> {
		if (annotations === undefined) return {};
		if (!ctx.storage.subordinateEvents)
			throw new Error("Event annotations require subordinate event storage");
		if (
			!annotations ||
			typeof annotations !== "object" ||
			Array.isArray(annotations) ||
			Object.keys(annotations).some((key) => key !== "eventDescription" && key !== "informationUri")
		)
			throw new TypeError("Invalid event annotations");
		const event = parsePublishedSubordinateEvent({
			iat: 0,
			event: "registration",
			...(annotations.eventDescription !== undefined
				? { event_description: annotations.eventDescription }
				: {}),
			...(annotations.informationUri !== undefined
				? { information_uri: annotations.informationUri }
				: {}),
		});
		const { iat: _iat, event: _event, ...fields } = event;
		return fields;
	}
	function requireTransactionEvents(tx: StorageTransaction): void {
		if (ctx.storage.subordinateEvents && !tx.subordinateEvents) {
			throw new Error("Event-enabled storage requires transaction-bound subordinateEvents");
		}
	}
	async function append(
		tx: StorageTransaction,
		subject: EntityId,
		events: SubordinateEvent[],
	): Promise<void> {
		if (ctx.storage.subordinateEvents) {
			if (!tx.subordinateEvents)
				throw new Error("Transaction-bound subordinateEvents is unavailable");
			await tx.subordinateEvents.append(ctx.entityId, subject, events);
		}
	}
	return {
		async registerSubordinate(
			record: Omit<SubordinateRecord, "createdAt" | "updatedAt">,
			annotations?: SubordinateEventAnnotations,
		): Promise<void> {
			const fields = annotationFields(annotations);
			const normalized = sanitize(structuredClone(record));
			await ctx.storage.transaction(async (tx) => {
				requireTransactionEvents(tx);
				const iat = nowSeconds(ctx.options?.clock);
				await tx.subordinates.add({ ...normalized, createdAt: iat, updatedAt: iat });
				// Draft 01 §2.3.3: registration covers the operation's initial metadata and keys.
				// Later operations remain distinct even when their NumericDates are equal.
				await append(tx, normalized.entityId, [
					{ ...fields, iat, event: SubordinateEventType.Registration },
				]);
			});
		},
		async updateSubordinate(
			subject: EntityId,
			updates: SubordinateRecordUpdate,
			annotations?: SubordinateEventAnnotations,
		): Promise<void> {
			const fields = annotationFields(annotations);
			const normalized = sanitize(structuredClone(updates));
			await ctx.storage.transaction(async (tx) => {
				requireTransactionEvents(tx);
				const before = await tx.subordinates.get(subject);
				if (!before) throw new Error(`Subordinate '${subject}' not found`);
				let beforeKeys: string | undefined;
				if (normalized.jwks !== undefined) {
					// Reject invalid replacements within the transaction, while allowing repair
					// of a legacy record whose keys could not have been published.
					publicKeys({ ...before, jwks: normalized.jwks });
					try {
						beforeKeys = publicKeys(before);
					} catch {
						/* Legacy invalid keys count as changed. */
					}
				}
				await tx.subordinates.update(subject, normalized);
				const after = await tx.subordinates.get(subject);
				if (!after) throw new Error(`Subordinate '${subject}' disappeared during update`);
				const eventTypes: string[] = [];
				if (
					canonical(sanitizeSubordinateMetadata(before.metadata)) !==
					canonical(sanitizeSubordinateMetadata(after.metadata))
				)
					eventTypes.push(SubordinateEventType.MetadataUpdate);
				if (canonical(before.metadataPolicy) !== canonical(after.metadataPolicy))
					eventTypes.push(SubordinateEventType.MetadataPolicyUpdate);
				if (normalized.jwks !== undefined && beforeKeys !== publicKeys(after))
					eventTypes.push(SubordinateEventType.JwksUpdate);
				const iat = nowSeconds(ctx.options?.clock);
				if (eventTypes.length)
					await append(
						tx,
						subject,
						eventTypes.map((event) => ({ ...fields, iat, event })),
					);
			});
		},
		async revokeSubordinate(
			subject: EntityId,
			annotations?: SubordinateEventAnnotations,
		): Promise<void> {
			const fields = annotationFields(annotations);
			await ctx.storage.transaction(async (tx) => {
				requireTransactionEvents(tx);
				await tx.subordinates.remove(subject);
				await append(tx, subject, [
					{
						...fields,
						iat: nowSeconds(ctx.options?.clock),
						event: SubordinateEventType.Revocation,
					},
				]);
			});
		},
		async recordSubordinateEvents(
			subject: EntityId,
			events: readonly SubordinateEvent[],
		): Promise<void> {
			if (!ctx.storage.subordinateEvents)
				throw new Error("Subordinate event storage is not configured");
			const parsed = events.map(parsePublishedSubordinateEvent);
			await ctx.storage.transaction(async (tx) => {
				requireTransactionEvents(tx);
				await append(tx, subject, parsed);
			});
		},
	};
}
