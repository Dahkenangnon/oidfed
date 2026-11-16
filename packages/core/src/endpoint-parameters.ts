/** Fixed-selector comparison and extension-parameter handling for federation endpoints. */

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

export type EndpointAdditionalParameters = Readonly<Record<string, string | readonly string[]>>;
const reserved = new Set([
	"entity_type",
	"trust_anchor",
	"trust_marked",
	"intermediate",
	"from",
	"limit",
	"updated_after",
	"updated_before",
	"audit_timestamps",
	"claims",
	"query",
	"entity_claims",
	"info_claims",
	"locale",
	"trust_mark_type",
	"sub",
	"trust_mark",
	"client_id",
	"client_assertion",
	"client_assertion_type",
	"client_secret",
]);

/** Names owned by federation protocols or their standard authentication fields. */
export function isReservedEndpointParameter(name: string): boolean {
	return reserved.has(name);
}

/** Copy selectors and add extension parameters without overriding selectors or fixed URL values. */
export function prepareEndpointParameters(
	selectors: URLSearchParams,
	additional?: EndpointAdditionalParameters,
	fixed: URLSearchParams = new URLSearchParams(),
): URLSearchParams {
	const result = new URLSearchParams(selectors);
	for (const [name, value] of Object.entries(additional ?? {})) {
		if (reserved.has(name) || result.has(name) || fixed.has(name))
			throw new Error("Additional parameters cannot replace protocol selectors or credentials");
		const values = typeof value === "string" ? [value] : value;
		if (!Array.isArray(values) || values.some((v) => typeof v !== "string"))
			throw new Error("Invalid additional parameter values");
		for (const item of values) result.append(name, item);
	}
	return result;
}
