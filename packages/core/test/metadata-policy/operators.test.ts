import { describe, expect, it } from "vitest";
import { PolicyOperator } from "../../src/constants.js";
import { operators } from "../../src/metadata-policy/operators.js";
import type { PolicyOperatorDefinition } from "../../src/types.js";

function getOp(name: string): PolicyOperatorDefinition {
	const op = operators[name];
	if (!op) throw new Error(`Operator '${name}' not found`);
	return op;
}

describe("operators registry", () => {
	it("has all 7 operators", () => {
		expect(Object.keys(operators)).toHaveLength(7);
		for (const op of Object.values(PolicyOperator)) {
			expect(operators).toHaveProperty(op);
		}
	});

	it("operators are in correct order", () => {
		expect(operators[PolicyOperator.Value]?.order).toBe(1);
		expect(operators[PolicyOperator.Add]?.order).toBe(2);
		expect(operators[PolicyOperator.Default]?.order).toBe(3);
		expect(operators[PolicyOperator.OneOf]?.order).toBe(4);
		expect(operators[PolicyOperator.SubsetOf]?.order).toBe(5);
		expect(operators[PolicyOperator.SupersetOf]?.order).toBe(6);
		expect(operators[PolicyOperator.Essential]?.order).toBe(7);
	});
});

describe("value operator", () => {
	const op = getOp(PolicyOperator.Value);

	describe("apply", () => {
		it("returns the operator value when param is present", () => {
			const result = op.apply("existing", "forced");
			expect(result).toEqual({ ok: true, value: "forced" });
		});

		it("returns removed when operator value is null", () => {
			const result = op.apply("existing", null);
			expect(result).toEqual({ ok: true, value: null, removed: true });
		});

		it("sets value even when param is absent (undefined)", () => {
			const result = op.apply(undefined, "forced");
			expect(result).toEqual({ ok: true, value: "forced" });
		});

		it("removes when param is absent and value is null", () => {
			const result = op.apply(undefined, null);
			expect(result).toEqual({ ok: true, value: null, removed: true });
		});
	});

	describe("merge", () => {
		it("succeeds when values are equal", () => {
			expect(op.merge("same", "same")).toEqual({ ok: true, value: "same" });
		});

		it("succeeds when arrays are equal", () => {
			expect(op.merge(["a", "b"], ["a", "b"])).toEqual({ ok: true, value: ["a", "b"] });
		});

		it("fails when values differ", () => {
			const result = op.merge("one", "two");
			expect(result.ok).toBe(false);
		});
	});
});

describe("add operator", () => {
	const op = getOp(PolicyOperator.Add);

	describe("apply", () => {
		it("sets value when param is absent", () => {
			const result = op.apply(undefined, ["x", "y"]);
			expect(result).toEqual({ ok: true, value: ["x", "y"] });
		});

		it("unions with existing array without duplicates", () => {
			const result = op.apply(["a", "b"], ["b", "c"]);
			expect(result).toEqual({ ok: true, value: ["a", "b", "c"] });
		});

		it("unions with existing when param already has all values", () => {
			const result = op.apply(["a", "b"], ["a"]);
			expect(result).toEqual({ ok: true, value: ["a", "b"] });
		});
	});

	describe("merge", () => {
		it("returns union of arrays", () => {
			const result = op.merge(["a"], ["b"]);
			expect(result).toEqual({ ok: true, value: ["a", "b"] });
		});

		it("deduplicates", () => {
			const result = op.merge(["a", "b"], ["b", "c"]);
			expect(result).toEqual({ ok: true, value: ["a", "b", "c"] });
		});
	});
});

describe("default operator", () => {
	const op = getOp(PolicyOperator.Default);

	describe("apply", () => {
		it("sets value when param is absent", () => {
			const result = op.apply(undefined, "fallback");
			expect(result).toEqual({ ok: true, value: "fallback" });
		});

		it("keeps existing value when param is present", () => {
			const result = op.apply("existing", "fallback");
			expect(result).toEqual({ ok: true, value: "existing" });
		});
	});

	describe("merge", () => {
		it("succeeds when values are equal", () => {
			expect(op.merge("same", "same")).toEqual({ ok: true, value: "same" });
		});

		it("fails when values differ", () => {
			const result = op.merge("a", "b");
			expect(result.ok).toBe(false);
		});
	});
});

describe("one_of operator", () => {
	const op = getOp(PolicyOperator.OneOf);

	describe("apply", () => {
		it("passes when value is in allowed set", () => {
			const result = op.apply("a", ["a", "b", "c"]);
			expect(result).toEqual({ ok: true, value: "a" });
		});

		it("fails when value is not in allowed set", () => {
			const result = op.apply("z", ["a", "b", "c"]);
			expect(result.ok).toBe(false);
		});

		it("passes when param is absent", () => {
			const result = op.apply(undefined, ["a", "b"]);
			expect(result).toEqual({ ok: true, value: undefined });
		});
	});

	describe("merge", () => {
		it("returns intersection", () => {
			const result = op.merge(["a", "b", "c"], ["b", "c", "d"]);
			expect(result).toEqual({ ok: true, value: ["b", "c"] });
		});

		it("fails when intersection is empty", () => {
			const result = op.merge(["a", "b"], ["c", "d"]);
			expect(result.ok).toBe(false);
		});
	});
});

describe("subset_of operator", () => {
	const op = getOp(PolicyOperator.SubsetOf);

	describe("apply", () => {
		it("intersects param with allowed set", () => {
			const result = op.apply(["a", "b", "c"], ["b", "c", "d"]);
			expect(result).toEqual({ ok: true, value: ["b", "c"] });
		});

		it("passes when param is absent", () => {
			const result = op.apply(undefined, ["a", "b"]);
			expect(result).toEqual({ ok: true, value: undefined });
		});

		it("returns empty array when no overlap", () => {
			const result = op.apply(["x"], ["a", "b"]);
			expect(result).toEqual({ ok: true, value: [] });
		});
	});

	describe("merge", () => {
		it("returns intersection of ceilings", () => {
			const result = op.merge(["a", "b", "c"], ["b", "c", "d"]);
			expect(result).toEqual({ ok: true, value: ["b", "c"] });
		});

		it("allows empty intersection (restrictive)", () => {
			const result = op.merge(["a"], ["b"]);
			expect(result).toEqual({ ok: true, value: [] });
		});
	});
});

describe("superset_of operator", () => {
	const op = getOp(PolicyOperator.SupersetOf);

	describe("apply", () => {
		it("passes when param contains all required values", () => {
			const result = op.apply(["a", "b", "c"], ["a", "b"]);
			expect(result).toEqual({ ok: true, value: ["a", "b", "c"] });
		});

		it("fails when param is missing required values", () => {
			const result = op.apply(["a"], ["a", "b"]);
			expect(result.ok).toBe(false);
		});

		it("passes when param is absent", () => {
			const result = op.apply(undefined, ["a"]);
			expect(result).toEqual({ ok: true, value: undefined });
		});
	});

	describe("merge", () => {
		it("returns union of floors", () => {
			const result = op.merge(["a", "b"], ["b", "c"]);
			expect(result).toEqual({ ok: true, value: ["a", "b", "c"] });
		});
	});
});

describe("essential operator", () => {
	const op = getOp(PolicyOperator.Essential);

	describe("apply", () => {
		it("fails when essential=true and value is absent", () => {
			const result = op.apply(undefined, true);
			expect(result.ok).toBe(false);
		});

		it("passes when essential=true and value is present", () => {
			const result = op.apply("exists", true);
			expect(result).toEqual({ ok: true, value: "exists" });
		});

		it("passes when essential=false and value is absent", () => {
			const result = op.apply(undefined, false);
			expect(result).toEqual({ ok: true, value: undefined });
		});
	});

	describe("merge", () => {
		it("returns logical OR (true wins)", () => {
			expect(op.merge(false, true)).toEqual({ ok: true, value: true });
			expect(op.merge(true, false)).toEqual({ ok: true, value: true });
			expect(op.merge(true, true)).toEqual({ ok: true, value: true });
			expect(op.merge(false, false)).toEqual({ ok: true, value: false });
		});
	});
});

describe("canCombineWith — full 7×7 matrix", () => {
	const ops = [
		PolicyOperator.Value,
		PolicyOperator.Add,
		PolicyOperator.Default,
		PolicyOperator.OneOf,
		PolicyOperator.SubsetOf,
		PolicyOperator.SupersetOf,
		PolicyOperator.Essential,
	] as const;

	// Y = always allowed, C = conditional, C* = special, - = never
	// value, add, default, one_of, subset_of, superset_of, essential
	const matrix: Record<string, Record<string, "Y" | "C" | "C*" | "-">> = {
		value: {
			value: "-",
			add: "C",
			default: "C",
			one_of: "C",
			subset_of: "C",
			superset_of: "C",
			essential: "C*",
		},
		add: {
			value: "C",
			add: "-",
			default: "Y",
			one_of: "-",
			subset_of: "C",
			superset_of: "Y",
			essential: "Y",
		},
		default: {
			value: "C",
			add: "Y",
			default: "-",
			one_of: "Y",
			subset_of: "Y",
			superset_of: "Y",
			essential: "Y",
		},
		one_of: {
			value: "C",
			add: "-",
			default: "Y",
			one_of: "-",
			subset_of: "-",
			superset_of: "-",
			essential: "Y",
		},
		subset_of: {
			value: "C",
			add: "C",
			default: "Y",
			one_of: "-",
			subset_of: "-",
			superset_of: "C",
			essential: "Y",
		},
		superset_of: {
			value: "C",
			add: "Y",
			default: "Y",
			one_of: "-",
			subset_of: "C",
			superset_of: "-",
			essential: "Y",
		},
		essential: {
			value: "C*",
			add: "Y",
			default: "Y",
			one_of: "Y",
			subset_of: "Y",
			superset_of: "Y",
			essential: "-",
		},
	};

	// Test all "Y" (always allowed) cells
	describe("always allowed (Y) combinations", () => {
		const yCases: [string, string][] = [];
		for (const a of ops) {
			for (const b of ops) {
				if (matrix[a]?.[b] === "Y") {
					yCases.push([a, b]);
				}
			}
		}

		it.each(yCases)("%s + %s is always allowed", (a, b) => {
			const opA = getOp(a);
			// Use minimal compatible values
			const thisVal =
				a === "essential" ? true : a === "add" ? ["x"] : a === "superset_of" ? ["x"] : "x";
			const otherVal =
				b === "essential" ? true : b === "add" ? ["x"] : b === "superset_of" ? ["x"] : "x";
			expect(opA.canCombineWith(b, thisVal, otherVal)).toBe(true);
		});
	});

	// Test all "-" (never allowed) cells
	describe("never allowed (-) combinations", () => {
		const neverCases: [string, string][] = [];
		for (const a of ops) {
			for (const b of ops) {
				if (matrix[a]?.[b] === "-") {
					neverCases.push([a, b]);
				}
			}
		}

		it.each(neverCases)("%s + %s is never allowed", (a, b) => {
			const opA = getOp(a);
			const thisVal =
				a === "essential" ? true : a === "add" ? ["x"] : a === "superset_of" ? ["x"] : ["x"];
			const otherVal =
				b === "essential" ? true : b === "add" ? ["x"] : b === "superset_of" ? ["x"] : ["x"];
			expect(opA.canCombineWith(b, thisVal, otherVal)).toBe(false);
		});
	});

	// Test conditional (C) cells — must test both compatible and incompatible values
	describe("conditional (C) combinations", () => {
		// value + add: compatible when add values are subset of value (array)
		it("value + add: allowed when add subset of value array", () => {
			expect(operators.value?.canCombineWith("add", ["a", "b"], ["a"])).toBe(true);
		});
		it("value + add: rejected when add not subset of value", () => {
			expect(operators.value?.canCombineWith("add", ["a"], ["b"])).toBe(false);
		});
		it("add + value: allowed when add subset of value array", () => {
			expect(operators.add?.canCombineWith("value", ["a"], ["a", "b"])).toBe(true);
		});

		// value + default: compatible when default equals value
		it("value + default: allowed when equal", () => {
			expect(operators.value?.canCombineWith("default", "x", "x")).toBe(true);
		});
		it("value + default: rejected when different", () => {
			expect(operators.value?.canCombineWith("default", "x", "y")).toBe(false);
		});

		// value + one_of: compatible when value is member of one_of
		it("value + one_of: allowed when value in one_of set", () => {
			expect(operators.value?.canCombineWith("one_of", "a", ["a", "b"])).toBe(true);
		});
		it("value + one_of: rejected when value not in one_of set", () => {
			expect(operators.value?.canCombineWith("one_of", "c", ["a", "b"])).toBe(false);
		});

		// value + subset_of: compatible when value array is subset of subset_of
		it("value + subset_of: allowed when value array subset of subset_of", () => {
			expect(operators.value?.canCombineWith("subset_of", ["a", "b"], ["a", "b", "c"])).toBe(true);
		});
		it("value + subset_of: rejected when value not subset", () => {
			expect(operators.value?.canCombineWith("subset_of", ["a", "d"], ["a", "b", "c"])).toBe(false);
		});
		it("value + subset_of: scalar in subset_of", () => {
			expect(operators.value?.canCombineWith("subset_of", "a", ["a", "b"])).toBe(true);
		});
		it("value + subset_of: scalar not in subset_of", () => {
			expect(operators.value?.canCombineWith("subset_of", "z", ["a", "b"])).toBe(false);
		});

		// value + superset_of: compatible when value array is superset of superset_of
		it("value + superset_of: allowed when value superset", () => {
			expect(operators.value?.canCombineWith("superset_of", ["a", "b", "c"], ["a", "b"])).toBe(
				true,
			);
		});
		it("value + superset_of: rejected when value not superset", () => {
			expect(operators.value?.canCombineWith("superset_of", ["a"], ["a", "b"])).toBe(false);
		});

		// add + subset_of: compatible when add subset of subset_of
		it("add + subset_of: allowed when add subset of ceiling", () => {
			expect(operators.add?.canCombineWith("subset_of", ["a"], ["a", "b", "c"])).toBe(true);
		});
		it("add + subset_of: rejected when add exceeds ceiling", () => {
			expect(operators.add?.canCombineWith("subset_of", ["a", "d"], ["a", "b"])).toBe(false);
		});
		it("subset_of + add: allowed when add subset of ceiling", () => {
			expect(operators.subset_of?.canCombineWith("add", ["a", "b", "c"], ["a"])).toBe(true);
		});

		// subset_of + superset_of: compatible when superset_of subset of subset_of
		it("subset_of + superset_of: allowed when floor ⊆ ceiling", () => {
			expect(operators.subset_of?.canCombineWith("superset_of", ["a", "b", "c"], ["a", "b"])).toBe(
				true,
			);
		});
		it("subset_of + superset_of: rejected when floor ⊄ ceiling", () => {
			expect(operators.subset_of?.canCombineWith("superset_of", ["a", "b"], ["a", "b", "c"])).toBe(
				false,
			);
		});
		it("superset_of + subset_of: allowed when floor ⊆ ceiling", () => {
			expect(operators.superset_of?.canCombineWith("subset_of", ["a", "b"], ["a", "b", "c"])).toBe(
				true,
			);
		});
	});

	// Test C* (value + essential special rule)
	describe("special conditional (C*) combinations", () => {
		it("value + essential: allowed normally", () => {
			expect(operators.value?.canCombineWith("essential", "x", true)).toBe(true);
		});

		it("value + essential: rejected when value=null AND essential=true", () => {
			expect(operators.value?.canCombineWith("essential", null, true)).toBe(false);
		});

		it("value + essential: allowed when value=null AND essential=false", () => {
			expect(operators.value?.canCombineWith("essential", null, false)).toBe(true);
		});

		it("essential + value: rejected when value=null AND essential=true", () => {
			expect(operators.essential?.canCombineWith("value", true, null)).toBe(false);
		});

		it("essential + value: allowed when essential=false AND value=null", () => {
			expect(operators.essential?.canCombineWith("value", false, null)).toBe(true);
		});
	});
});

describe("operator non-array robustness", () => {
	const addOp = getOp(PolicyOperator.Add);
	const subsetOfOp = getOp(PolicyOperator.SubsetOf);
	const supersetOfOp = getOp(PolicyOperator.SupersetOf);

	describe("add operator", () => {
		it("apply: wraps scalar parameterValue in array before union", () => {
			// Scalar param + array operator
			const result = addOp.apply("existing", ["new1", "new2"]);
			expect(result.ok).toBe(true);
			if (result.ok) {
				expect(result.value).toEqual(["existing", "new1", "new2"]);
			}
		});

		it("apply: handles scalar operatorValue", () => {
			const result = addOp.apply(["a"], "b");
			expect(result.ok).toBe(true);
			if (result.ok) {
				expect(result.value).toEqual(["a", "b"]);
			}
		});

		it("merge: handles scalar values by wrapping in arrays", () => {
			const result = addOp.merge("a", "b");
			expect(result.ok).toBe(true);
			if (result.ok) {
				expect(result.value).toEqual(["a", "b"]);
			}
		});
	});

	describe("subset_of operator", () => {
		it("apply: handles scalar parameterValue against array constraint", () => {
			// Scalar value that IS in the subset
			const okResult = subsetOfOp.apply("a", ["a", "b"]);
			expect(okResult.ok).toBe(true);
			if (okResult.ok) expect(okResult.value).toBe("a");

			// Scalar value NOT in the subset
			const failResult = subsetOfOp.apply("c", ["a", "b"]);
			expect(failResult.ok).toBe(false);
		});

		it("merge: handles scalar values by wrapping in arrays", () => {
			const result = subsetOfOp.merge("a", "b");
			expect(result.ok).toBe(true);
			// Intersection of ["a"] and ["b"] = []
			if (result.ok) expect(result.value).toEqual([]);
		});
	});

	describe("superset_of operator", () => {
		it("apply: handles scalar parameterValue against array constraint", () => {
			// Scalar param that IS a superset of [scalar]
			const okResult = supersetOfOp.apply("a", ["a"]);
			expect(okResult.ok).toBe(true);
			if (okResult.ok) expect(okResult.value).toBe("a");

			// Scalar param that is NOT a superset of [a, b]
			const failResult = supersetOfOp.apply("a", ["a", "b"]);
			expect(failResult.ok).toBe(false);
		});

		it("merge: handles scalar values by wrapping in arrays", () => {
			const result = supersetOfOp.merge("a", "b");
			expect(result.ok).toBe(true);
			// Union of ["a"] and ["b"] = ["a", "b"]
			if (result.ok) expect(result.value).toEqual(["a", "b"]);
		});
	});
});
