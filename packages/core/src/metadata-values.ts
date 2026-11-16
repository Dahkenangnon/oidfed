/** Metadata null-value checks shared by publication and trust chain validation. */

import { isObject } from "./callbacks.js";

/** Find nulls in positions requiring objects or non-null metadata parameters. */
export function findInvalidMetadataNullPaths(
	metadata: unknown,
): readonly (readonly (string | number)[])[] {
	if (metadata === null) return [[]];
	if (!isObject(metadata)) return [];

	const invalid: (string | number)[][] = [];
	for (const [entityType, parameters] of Object.entries(metadata)) {
		if (parameters === null) {
			invalid.push([entityType]);
			continue;
		}
		if (!isObject(parameters)) continue;
		for (const [parameter, value] of Object.entries(parameters)) {
			if (value === null) invalid.push([entityType, parameter]);
		}
	}
	return invalid;
}
