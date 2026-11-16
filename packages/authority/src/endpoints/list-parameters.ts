/** Parameter rules shared by base and Extended Subordinate Listing. */

import { FederationErrorCode } from "@oidfed/core";
import { errorResponse } from "./helpers.js";

/** Distinguish absence from an invalid boolean value. */
export function parseBooleanQuery(value: string | null): boolean | null | undefined {
	if (value === null) return null;
	if (value === "true") return true;
	if (value === "false") return false;
	return undefined;
}

/** Extension Entity Type names are allowed, but empty selectors are invalid. */
export function validateEntityTypes(entityTypes: readonly string[]): Response | undefined {
	if (entityTypes.some((type) => type.length === 0))
		return errorResponse(400, FederationErrorCode.InvalidRequest, "entity_type must not be empty");
	return undefined;
}
