import { cloneData } from "@oidfed/core";
/** Detached validation of manually published subordinate events. */

import { type SubordinateEvent, SubordinateEventSchema } from "@oidfed/core";

/** Local publication requires an event name; Draft 01 leaves custom names open. */
export function parsePublishedSubordinateEvent(event: SubordinateEvent): SubordinateEvent {
	const parsed = SubordinateEventSchema.parse(event);
	if (parsed.event.length === 0) throw new TypeError("Published event names must not be empty");
	// Capture nested extension claims before a queued storage operation can yield.
	return cloneData(parsed);
}
