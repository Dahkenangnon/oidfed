import { parseStorageRecord, StoredSubordinateEventSchema } from "./record-schemas.js";
/** Detached validation of manually published subordinate events. */

import type { SubordinateEvent } from "../schemas/subordinate-events.js";

/** Local publication requires an event name; Draft 01 leaves custom names open. */
export function parsePublishedSubordinateEvent(event: SubordinateEvent): SubordinateEvent {
	return parseStorageRecord(StoredSubordinateEventSchema, event, "subordinateEvent", "publish");
}
