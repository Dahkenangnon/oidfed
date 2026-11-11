/** Find nulls in positions requiring objects or non-null metadata parameters. */
export function findInvalidMetadataNullPaths(
	metadata: unknown,
): readonly (readonly (string | number)[])[] {
	if (metadata === null) return [[]];
	if (typeof metadata !== "object" || Array.isArray(metadata)) return [];

	const invalid: (string | number)[][] = [];
	for (const [entityType, parameters] of Object.entries(metadata)) {
		if (parameters === null) {
			invalid.push([entityType]);
			continue;
		}
		if (typeof parameters !== "object" || Array.isArray(parameters)) continue;
		for (const [parameter, value] of Object.entries(parameters)) {
			if (value === null) invalid.push([entityType, parameter]);
		}
	}
	return invalid;
}
