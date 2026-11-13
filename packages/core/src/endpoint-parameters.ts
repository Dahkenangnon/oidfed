/** Compare repeated endpoint parameters; unknown parameters retain exact ordering. */
export function endpointParameterValuesMatch(
	name: string,
	fixed: readonly string[],
	supplied: readonly string[],
	unorderedParameters: readonly string[],
): boolean {
	if (!unorderedParameters.includes(name))
		return fixed.length === supplied.length && fixed.every((value, i) => value === supplied[i]);
	const expected = new Set(fixed),
		actual = new Set(supplied);
	return expected.size === actual.size && [...expected].every((value) => actual.has(value));
}

/** Federation §8.2.1 filters by membership in the requested Entity Types. */
export const LIST_UNORDERED_PARAMETERS = Object.freeze(["entity_type"] as const);
export const EXTENDED_LIST_UNORDERED_PARAMETERS = Object.freeze([
	"entity_type",
	"trust_mark_type",
] as const);
export const RESOLVE_UNORDERED_PARAMETERS = Object.freeze(["trust_anchor", "entity_type"] as const);

/** Collection §3.3.1 defines these repeated selectors by membership. */
export const COLLECTION_UNORDERED_PARAMETERS = Object.freeze([
	"entity_type",
	"trust_mark_type",
	"entity_claims",
	"info_claims",
	"locale",
] as const);
