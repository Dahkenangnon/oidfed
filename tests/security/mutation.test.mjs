/** Execute the mutable source directly; packed dist files cannot satisfy these tests. */

import assert from "node:assert/strict";
import {
	endpointParameterValuesMatch,
	isReservedEndpointParameter,
	prepareEndpointParameters,
} from "../../packages/core/src/endpoint-parameters.ts";

assert.equal(
	endpointParameterValuesMatch("entity_type", ["a", "b"], ["b", "a", "a"], ["entity_type"]),
	true,
);
assert.equal(
	endpointParameterValuesMatch("entity_type", ["a", "b"], ["b"], ["entity_type"]),
	false,
);
assert.equal(
	endpointParameterValuesMatch("custom", ["a", "b"], ["b", "a"], ["entity_type"]),
	false,
);
assert.equal(endpointParameterValuesMatch("custom", ["a"], ["a", "a"], []), false);
assert.equal(endpointParameterValuesMatch("custom", ["a"], ["a"], []), true);
assert.equal(endpointParameterValuesMatch("custom", ["a", "b"], ["a", "wrong"], []), false);
assert.equal(
	endpointParameterValuesMatch("entity_type", ["a", "b"], ["a", "wrong"], ["entity_type"]),
	false,
);
assert.equal(
	endpointParameterValuesMatch("entity_type", ["a"], ["a", "extra"], ["entity_type"]),
	false,
);
assert.equal(endpointParameterValuesMatch("entity_type", [], [], ["entity_type"]), true);
for (const name of [
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
]) {
	assert.equal(isReservedEndpointParameter(name), true);
	assert.throws(() => prepareEndpointParameters(new URLSearchParams(), { [name]: "value" }));
}
assert.equal(isReservedEndpointParameter("custom"), false);
assert.throws(() =>
	prepareEndpointParameters(new URLSearchParams("custom=fixed"), { custom: "value" }),
);
assert.throws(() =>
	prepareEndpointParameters(
		new URLSearchParams(),
		{ custom: "value" },
		new URLSearchParams("custom=fixed"),
	),
);
assert.throws(() => prepareEndpointParameters(new URLSearchParams(), { custom: ["valid", 123] }));
assert.throws(() => prepareEndpointParameters(new URLSearchParams(), { custom: 123 }));
const before = new URLSearchParams("entity_type=one");
const extended = prepareEndpointParameters(before, { custom: ["two", "three"], single: "four" });
assert.equal(before.toString(), "entity_type=one");
assert.deepEqual(extended.getAll("custom"), ["two", "three"]);
assert.equal(extended.get("single"), "four");
assert.equal(extended.get("entity_type"), "one");
const structural = prepareEndpointParameters(
	new URLSearchParams(),
	JSON.parse('{"__proto__":"extension"}'),
);
assert.equal(structural.get("__proto__"), "extension");
