import { cloneData } from "@oidfed/core";
/** Subordinate registration, updates, revocation, and transactional lifecycle events. */

import {
	type EntityId,
	entityId,
	nowSeconds,
	preparePublicJwkSet,
	type SubordinateEvent,
	SubordinateEventType,
	safeLogger,
} from "@oidfed/core";
import type { HandlerContext } from "./endpoints/context.js";
import type {
	StorageTransaction,
	SubordinateEventAnnotations,
	SubordinateRecord,
	SubordinateRecordUpdate,
} from "./storage/types.js";
import { parsePublishedSubordinateEvent } from "./utils/subordinate-event.js";
import { assertSubordinatePublicationClaims } from "./utils/subordinate-publication.js";
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

function publicKeys(
	record: SubordinateRecord,
	registry: HandlerContext["options"]["algorithmRegistry"],
): string {
	const prepared = preparePublicJwkSet(record.jwks, registry);
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
	function noteEventInformationUris(uris: readonly (string | undefined)[]): void {
		if (uris.some((uri) => uri !== undefined && new URL(uri).protocol !== "https:"))
			safeLogger(ctx.options?.logger)?.info(
				"HTTPS is RECOMMENDED for Subordinate Event information_uri",
			);
	}
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
			entityId(record.entityId);
			const fields = annotationFields(annotations);
			const normalized = sanitize(cloneData(record));
			try {
				await ctx.storage.transaction(async (tx) => {
					requireTransactionEvents(tx);
					const iat = nowSeconds(ctx.options?.clock);
					assertSubordinatePublicationClaims(normalized, {
						customOperators: ctx.options?.customPolicyOperators,
					});
					await tx.subordinates.add({ ...normalized, createdAt: iat, updatedAt: iat });
					// Draft 01 §2.3.3: registration covers the operation's initial metadata and keys.
					// Later operations remain distinct even when their NumericDates are equal.
					await append(tx, normalized.entityId, [
						{ ...fields, iat, event: SubordinateEventType.Registration },
					]);
				});
			} catch (error) {
				safeLogger(ctx.options?.logger)?.error("Immediate Subordinate registration failed");
				throw error;
			}
			safeLogger(ctx.options?.logger)?.info("Immediate Subordinate registration completed");
			if (ctx.storage.subordinateEvents) noteEventInformationUris([fields.information_uri]);
		},
		async updateSubordinate(
			subject: EntityId,
			updates: SubordinateRecordUpdate,
			annotations?: SubordinateEventAnnotations,
		): Promise<void> {
			const fields = annotationFields(annotations);
			const normalized = sanitize(cloneData(updates));
			let recordedEvents = false;
			try {
				await ctx.storage.transaction(async (tx) => {
					requireTransactionEvents(tx);
					const before = await tx.subordinates.get(subject);
					if (!before) throw new Error(`Subordinate '${subject}' not found`);
					assertSubordinatePublicationClaims(
						{ ...before, ...normalized },
						{ customOperators: ctx.options?.customPolicyOperators },
					);
					let beforeKeys: string | undefined;
					if (normalized.jwks !== undefined) {
						// Validate replacement keys inside the transaction. An invalid stored key set
						// can be repaired by a valid replacement.
						publicKeys({ ...before, jwks: normalized.jwks }, ctx.options.algorithmRegistry);
						try {
							beforeKeys = publicKeys(before, ctx.options.algorithmRegistry);
						} catch {
							/* Treat an invalid stored key set as changed. */
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
					if (
						normalized.jwks !== undefined &&
						beforeKeys !== publicKeys(after, ctx.options.algorithmRegistry)
					)
						eventTypes.push(SubordinateEventType.JwksUpdate);
					const iat = nowSeconds(ctx.options?.clock);
					if (eventTypes.length) {
						await append(
							tx,
							subject,
							eventTypes.map((event) => ({ ...fields, iat, event })),
						);
						recordedEvents = !!ctx.storage.subordinateEvents;
					}
				});
			} catch (error) {
				safeLogger(ctx.options?.logger)?.error("Immediate Subordinate update failed");
				throw error;
			}
			safeLogger(ctx.options?.logger)?.info("Immediate Subordinate update completed");
			if (recordedEvents) noteEventInformationUris([fields.information_uri]);
		},
		async revokeSubordinate(
			subject: EntityId,
			annotations?: SubordinateEventAnnotations,
		): Promise<void> {
			const fields = annotationFields(annotations);
			try {
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
			} catch (error) {
				safeLogger(ctx.options?.logger)?.error("Immediate Subordinate revocation failed");
				throw error;
			}
			safeLogger(ctx.options?.logger)?.info("Immediate Subordinate revocation completed");
			if (ctx.storage.subordinateEvents) noteEventInformationUris([fields.information_uri]);
		},
		async recordSubordinateEvents(
			subject: EntityId,
			events: readonly SubordinateEvent[],
		): Promise<void> {
			if (!ctx.storage.subordinateEvents)
				throw new Error("Subordinate event storage is not configured");
			const parsed = events.map(parsePublishedSubordinateEvent);
			try {
				await ctx.storage.transaction(async (tx) => {
					requireTransactionEvents(tx);
					await append(tx, subject, parsed);
				});
			} catch (error) {
				safeLogger(ctx.options?.logger)?.error("Subordinate Event recording failed");
				throw error;
			}
			safeLogger(ctx.options?.logger)?.info("Subordinate Event recording completed");
			noteEventInformationUris(parsed.map((event) => event.information_uri));
		},
	};
}
