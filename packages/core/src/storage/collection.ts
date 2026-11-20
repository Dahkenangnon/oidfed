import type { z } from "zod";
import type { Clock, EntityId } from "../types.js";
import type {
	CollectionEntrySchema,
	EntityCollectionCursorSchema,
	EntityCollectionSnapshotSchema,
} from "./record-schemas.js";

/** Evidence is local server state; it is never returned as collection data. */
export type CollectionEntry = z.infer<typeof CollectionEntrySchema>;
export type EntityCollectionSnapshot = z.infer<typeof EntityCollectionSnapshotSchema>;
export type EntityCollectionCursor = z.infer<typeof EntityCollectionCursorSchema>;
/**
 * Atomically publish snapshots and return detached values. Keep entries in their
 * published Entity Identifier order (§3.1.1). Snapshot identifiers name immutable
 * contents and publishers must generate a fresh identifier for each snapshot.
 * Current is isolated by anchor. A cursor retains its snapshot identity
 * and position. Expired or unavailable snapshots must not resolve to newer contents.
 */
export interface EntityCollectionStore {
	publish(snapshot: EntityCollectionSnapshot): Promise<void>;
	current(trustAnchor: EntityId): Promise<EntityCollectionSnapshot | undefined>;
	snapshot(id: string): Promise<EntityCollectionSnapshot | undefined>;
	/** May throw EntityCollectionCursorCapacityError to report temporary capacity exhaustion. */
	saveCursor(id: string, cursor: EntityCollectionCursor): Promise<void>;
	cursor(id: string): Promise<EntityCollectionCursor | undefined>;
}
export interface MemoryEntityCollectionStoreOptions {
	clock?: Clock;
	retentionSeconds?: number;
	maxSnapshots?: number;
	maxCursors?: number;
}
