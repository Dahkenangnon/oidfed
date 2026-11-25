import {
	assertStorageCapabilities,
	assertStorageView,
	cloneData,
	describeStorageRequirements,
	storageTransaction,
} from "@oidfed/core";

/** Subordinate registration, updates, revocation, and transactional lifecycle events. */

import type {
	SubordinateEventAnnotations,
	SubordinateRecord,
	SubordinateRecordUpdate,
	TransactionView,
} from "@oidfed/core";
import {
	assertSubordinatePublicationClaims,
	type EntityId,
	entityId,
	nowSeconds,
	parsePublishedSubordinateEvent,
	preparePublicJwkSet,
	type SubordinateEvent,
	SubordinateEventType,
	safeLogger,
	sanitizeSubordinateMetadata,
} from "@oidfed/core";
import type { HandlerContext } from "./endpoints/context.js";
import { canonicalSubordinateJson as canonical } from "./endpoints/subordinate-claims.js";

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
		if (!ctx.storage.capabilities.includes("subordinateEvent:write"))
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
	async function append(
		tx: TransactionView,
		subject: EntityId,
		events: SubordinateEvent[],
	): Promise<void> {
		if (ctx.storage.capabilities.includes("subordinateEvent:write")) {
			assertStorageView(tx, ["subordinateEvent:write"], "Append Subordinate Events");
			await tx.subordinateEvent.append(ctx.entityId, subject, events);
		}
	}
	return {
		async registerSubordinate(
			record: Omit<SubordinateRecord, "createdAt" | "updatedAt">,
			annotations?: SubordinateEventAnnotations,
		): Promise<void> {
			assertStorageCapabilities(
				ctx.storage,
				describeStorageRequirements("subordinateLifecycle"),
				"registerSubordinate",
			);
			entityId(record.entityId);
			const fields = annotationFields(annotations);
			const normalized = sanitize(cloneData(record));
			try {
				await storageTransaction(
					ctx.storage,
					async (tx) => {
						assertStorageView(tx, ["subordinate:write"], "Register Subordinate");
						const iat = nowSeconds(ctx.options?.clock);
						assertSubordinatePublicationClaims(normalized, {
							customOperators: ctx.options?.customPolicyOperators,
						});
						await tx.subordinate.register({ ...normalized, createdAt: iat, updatedAt: iat });
						// Draft 01 §2.3.3: registration covers the operation's initial metadata and keys.
						// Later operations remain distinct even when their NumericDates are equal.
						await append(tx, normalized.entityId, [
							{ ...fields, iat, event: SubordinateEventType.Registration },
						]);
					},
					ctx.options,
				);
			} catch (error) {
				safeLogger(ctx.options?.logger)?.error("Immediate Subordinate registration failed");
				throw error;
			}
			safeLogger(ctx.options?.logger)?.info("Immediate Subordinate registration completed");
			if (ctx.storage.capabilities.includes("subordinateEvent:write"))
				noteEventInformationUris([fields.information_uri]);
		},
		async updateSubordinate(
			subject: EntityId,
			updates: SubordinateRecordUpdate,
			annotations?: SubordinateEventAnnotations,
		): Promise<void> {
			assertStorageCapabilities(
				ctx.storage,
				describeStorageRequirements("subordinateLifecycle"),
				"updateSubordinate",
			);
			const fields = annotationFields(annotations);
			const normalized = sanitize(cloneData(updates));
			let recordedEvents: boolean;
			try {
				recordedEvents = await storageTransaction(
					ctx.storage,
					async (tx) => {
						assertStorageView(tx, ["subordinate:write"], "Update Subordinate");
						const before = await tx.subordinate.fetch(subject);
						if (!before) throw new Error(`Subordinate '${subject}' not found`);
						assertSubordinatePublicationClaims(
							{ ...before, ...normalized },
							{ customOperators: ctx.options?.customPolicyOperators },
						);
						const beforeKeys =
							normalized.jwks === undefined
								? undefined
								: publicKeys(before, ctx.options.algorithmRegistry);
						const iat = nowSeconds(ctx.options.clock);
						await tx.subordinate.update(subject, normalized, iat);
						const after = await tx.subordinate.fetch(subject);
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
						if (eventTypes.length) {
							await append(
								tx,
								subject,
								eventTypes.map((event) => ({ ...fields, iat, event })),
							);
						}
						return (
							eventTypes.length > 0 && ctx.storage.capabilities.includes("subordinateEvent:write")
						);
					},
					ctx.options,
				);
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
			assertStorageCapabilities(
				ctx.storage,
				describeStorageRequirements("subordinateLifecycle"),
				"revokeSubordinate",
			);
			const fields = annotationFields(annotations);
			try {
				await storageTransaction(
					ctx.storage,
					async (tx) => {
						assertStorageView(tx, ["subordinate:write"], "Revoke Subordinate");
						await tx.subordinate.remove(subject);
						await append(tx, subject, [
							{
								...fields,
								iat: nowSeconds(ctx.options?.clock),
								event: SubordinateEventType.Revocation,
							},
						]);
					},
					ctx.options,
				);
			} catch (error) {
				safeLogger(ctx.options?.logger)?.error("Immediate Subordinate revocation failed");
				throw error;
			}
			safeLogger(ctx.options?.logger)?.info("Immediate Subordinate revocation completed");
			if (ctx.storage.capabilities.includes("subordinateEvent:write"))
				noteEventInformationUris([fields.information_uri]);
		},
		async recordSubordinateEvents(
			subject: EntityId,
			events: readonly SubordinateEvent[],
		): Promise<void> {
			assertStorageCapabilities(
				ctx.storage,
				describeStorageRequirements("eventCapture"),
				"recordSubordinateEvents",
			);
			if (!ctx.storage.capabilities.includes("subordinateEvent:write"))
				throw new Error("Subordinate event storage is not configured");
			const parsed = events.map(parsePublishedSubordinateEvent);
			try {
				await storageTransaction(
					ctx.storage,
					async (tx) => {
						await append(tx, subject, parsed);
					},
					ctx.options,
				);
			} catch (error) {
				safeLogger(ctx.options?.logger)?.error("Subordinate Event recording failed");
				throw error;
			}
			safeLogger(ctx.options?.logger)?.info("Subordinate Event recording completed");
			noteEventInformationUris(parsed.map((event) => event.information_uri));
		},
	};
}
