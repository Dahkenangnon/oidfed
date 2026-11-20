import type { z } from "zod";
import type { EntityTypeIdentifier } from "../constants.js";
import type { SubordinateEvent } from "../schemas/subordinate-events.js";
import type { EntityId } from "../types.js";
import type { SubordinateRecordSchema } from "./record-schemas.js";

export interface SubordinateReadStore {
	/** Return a detached record; changing it does not update storage. */
	fetch(entityId: EntityId): Promise<SubordinateRecord | undefined>;
	/**
	 * Return matching records ordered lexicographically by entityId; cursors are inclusive.
	 * A filtered page may be empty with a continuation. Without options, return all matches.
	 */
	list(filter?: ListFilter, options?: ListPageOptions): Promise<ListPage>;
}

export interface SubordinateStore extends SubordinateReadStore {
	/** Capture and validate input before queuing. Reject duplicate identifiers. */
	register(record: SubordinateRecord): Promise<void>;
	/** Capture changes before queuing, then merge and validate against the current record inside the write transaction. Reject unknown identifiers. */
	update(entityId: EntityId, updates: SubordinateRecordUpdate, updatedAt: number): Promise<void>;
	remove(entityId: EntityId): Promise<void>;
}

export interface ListPageOptions {
	/** EntityId of the first record to return. */
	cursor?: EntityId;
	limit?: number;
	updatedAfter?: number;
	updatedBefore?: number;
}

export interface ListPage {
	readonly items: SubordinateRecord[];
	/**
	 * First unreturned position, strictly after the incoming cursor and returned records.
	 * May accompany an empty page. Omission means the scan is exhausted.
	 */
	readonly nextCursor?: EntityId;
}

export type SubordinateRecord = Readonly<z.infer<typeof SubordinateRecordSchema>>;

/** Annotations applied to each event captured by one lifecycle operation. */
export interface SubordinateEventAnnotations {
	readonly eventDescription?: string;
	readonly informationUri?: string;
}

export type SubordinateRecordUpdate = Partial<
	Omit<SubordinateRecord, "entityId" | "createdAt" | "updatedAt">
>;

export interface ListFilter {
	/**
	 * Match records having any requested Entity Type (union semantics). These are listing
	 * filters from Federation §8.2.1 and Entity Collection Draft 01. Entity Type Identifiers
	 * are open-ended (Federation §5.1, no registry). Custom adapters filter unknown values
	 * and return no matches for them instead of rejecting the request.
	 */
	entityTypes?: EntityTypeIdentifier[];
	/** When true, require a valid issued mark. False adds no restriction. */
	trustMarked?: boolean;
	/** Match any of the supplied Trust Mark types. */
	trustMarkType?: string | ReadonlyArray<string>;
	/** True selects intermediates; false selects non-intermediates; omission selects both. */
	intermediate?: boolean;
	/** Required when trustMarked is true or trustMarkType is provided. */
	validAt?: number;
}

/**
 * Scope history by issuer and subject. Preserve append order, including equal
 * timestamps and duplicate events; imported timestamps need not be increasing.
 * Clone values on append and list. Removing a registration retains its history.
 * Transaction-bound repositories commit registration changes and events together.
 */
export interface SubordinateEventReadStore {
	history(issuer: EntityId, subject: EntityId): Promise<readonly SubordinateEvent[]>;
}

export interface SubordinateEventStore extends SubordinateEventReadStore {
	append(issuer: EntityId, subject: EntityId, events: readonly SubordinateEvent[]): Promise<void>;
}
