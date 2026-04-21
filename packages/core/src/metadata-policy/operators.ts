/** Metadata policy operators (add, default, one_of, subset_of, superset_of, essential, value). */
import { PolicyOperator } from "../constants.js";
import type {
	PolicyMergeResult,
	PolicyOperatorDefinition,
	PolicyOperatorResult,
} from "../types.js";

/** Deep structural equality for policy values (arrays, objects, primitives). */
function deepEqual(a: unknown, b: unknown): boolean {
	if (a === b) return true;
	if (a === null || b === null) return false;
	if (typeof a !== typeof b) return false;

	if (Array.isArray(a) && Array.isArray(b)) {
		if (a.length !== b.length) return false;
		return a.every((item, i) => deepEqual(item, b[i]));
	}

	if (typeof a === "object" && typeof b === "object") {
		const keysA = Object.keys(a as Record<string, unknown>);
		const keysB = Object.keys(b as Record<string, unknown>);
		if (keysA.length !== keysB.length) return false;
		return keysA.every((key) =>
			deepEqual((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key]),
		);
	}

	return false;
}

/** Check if every element in `subset` exists in `superset` (deep equality). */
function isSubset(subset: unknown[], superset: unknown[]): boolean {
	return subset.every((item) => superset.some((s) => deepEqual(item, s)));
}

/** Merge two arrays, deduplicating via deep equality. */
function arrayUnion(a: unknown[], b: unknown[]): unknown[] {
	const result = [...a];
	for (const item of b) {
		if (!result.some((r) => deepEqual(r, item))) {
			result.push(item);
		}
	}
	return result;
}

function arrayIntersection(a: unknown[], b: unknown[]): unknown[] {
	return a.filter((item) => b.some((bi) => deepEqual(item, bi)));
}

function containsElement(arr: unknown[], element: unknown): boolean {
	return arr.some((item) => deepEqual(item, element));
}

const NEVER_ALLOWED = new Set([
	"add:one_of",
	"one_of:add",
	"one_of:subset_of",
	"subset_of:one_of",
	"one_of:superset_of",
	"superset_of:one_of",
]);

function checkValueCombination(otherOp: string, valueVal: unknown, otherVal: unknown): boolean {
	switch (otherOp) {
		case PolicyOperator.Add: {
			const addArr = otherVal as unknown[];
			if (Array.isArray(valueVal)) {
				return isSubset(addArr, valueVal);
			}
			return addArr.length === 1 && deepEqual(addArr[0], valueVal);
		}
		case PolicyOperator.Default:
			return deepEqual(valueVal, otherVal);
		case PolicyOperator.OneOf:
			return containsElement(otherVal as unknown[], valueVal);
		case PolicyOperator.SubsetOf: {
			const subsetOfArr = otherVal as unknown[];
			if (Array.isArray(valueVal)) {
				return isSubset(valueVal, subsetOfArr);
			}
			return containsElement(subsetOfArr, valueVal);
		}
		case PolicyOperator.SupersetOf: {
			const supersetOfArr = otherVal as unknown[];
			if (Array.isArray(valueVal)) {
				return isSubset(supersetOfArr, valueVal);
			}
			return supersetOfArr.length === 1 && deepEqual(supersetOfArr[0], valueVal);
		}
		case PolicyOperator.Essential: {
			if (valueVal === null && otherVal === true) return false;
			return true;
		}
		default:
			return false;
	}
}

const valueOperator: PolicyOperatorDefinition = {
	name: PolicyOperator.Value,
	order: 1,
	action: "modify",
	apply(_parameterValue: unknown, operatorValue: unknown): PolicyOperatorResult {
		if (operatorValue === null) {
			return { ok: true, value: null, removed: true };
		}
		return { ok: true, value: operatorValue };
	},
	merge(existingValue: unknown, newValue: unknown): PolicyMergeResult {
		if (deepEqual(existingValue, newValue)) {
			return { ok: true, value: existingValue };
		}
		return { ok: false, error: `Conflicting 'value' operators: cannot merge different values` };
	},
	canCombineWith(otherOperator: string, thisValue: unknown, otherValue: unknown): boolean {
		if (otherOperator === PolicyOperator.Value) return false;
		if (NEVER_ALLOWED.has(`value:${otherOperator}`)) return false;
		return checkValueCombination(otherOperator, thisValue, otherValue);
	},
};

const addOperator: PolicyOperatorDefinition = {
	name: PolicyOperator.Add,
	order: 2,
	action: "modify",
	apply(parameterValue: unknown, operatorValue: unknown): PolicyOperatorResult {
		if (parameterValue === undefined) {
			return { ok: true, value: operatorValue };
		}
		const opArr = Array.isArray(operatorValue) ? operatorValue : [operatorValue];
		const paramArr = Array.isArray(parameterValue) ? parameterValue : [parameterValue];
		return { ok: true, value: arrayUnion(paramArr, opArr) };
	},
	merge(existingValue: unknown, newValue: unknown): PolicyMergeResult {
		const existArr = Array.isArray(existingValue) ? existingValue : [existingValue];
		const newArr = Array.isArray(newValue) ? newValue : [newValue];
		return { ok: true, value: arrayUnion(existArr, newArr) };
	},
	canCombineWith(otherOperator: string, thisValue: unknown, otherValue: unknown): boolean {
		if (otherOperator === PolicyOperator.Add) return false;
		if (NEVER_ALLOWED.has(`add:${otherOperator}`)) return false;

		if (otherOperator === PolicyOperator.Value) {
			return checkValueCombination(PolicyOperator.Add, otherValue, thisValue);
		}
		if (otherOperator === PolicyOperator.SubsetOf) {
			const thisArr = Array.isArray(thisValue) ? thisValue : [thisValue];
			const otherArr = Array.isArray(otherValue) ? otherValue : [otherValue];
			return isSubset(thisArr, otherArr);
		}
		return true;
	},
};

const defaultOperator: PolicyOperatorDefinition = {
	name: PolicyOperator.Default,
	order: 3,
	action: "modify",
	apply(parameterValue: unknown, operatorValue: unknown): PolicyOperatorResult {
		if (parameterValue === undefined) {
			return { ok: true, value: operatorValue };
		}
		return { ok: true, value: parameterValue };
	},
	merge(existingValue: unknown, newValue: unknown): PolicyMergeResult {
		if (deepEqual(existingValue, newValue)) {
			return { ok: true, value: existingValue };
		}
		return { ok: false, error: `Conflicting 'default' operators: cannot merge different values` };
	},
	canCombineWith(otherOperator: string, thisValue: unknown, otherValue: unknown): boolean {
		if (otherOperator === PolicyOperator.Default) return false;

		if (otherOperator === PolicyOperator.Value) {
			return checkValueCombination(PolicyOperator.Default, otherValue, thisValue);
		}
		return true;
	},
};

const oneOfOperator: PolicyOperatorDefinition = {
	name: PolicyOperator.OneOf,
	order: 4,
	action: "check",
	apply(parameterValue: unknown, operatorValue: unknown): PolicyOperatorResult {
		if (parameterValue === undefined) {
			return { ok: true, value: undefined };
		}
		const allowed = operatorValue as unknown[];
		if (containsElement(allowed, parameterValue)) {
			return { ok: true, value: parameterValue };
		}
		return { ok: false, error: `Value not in one_of set` };
	},
	merge(existingValue: unknown, newValue: unknown): PolicyMergeResult {
		const intersection = arrayIntersection(existingValue as unknown[], newValue as unknown[]);
		if (intersection.length === 0) {
			return { ok: false, error: `one_of merge resulted in empty intersection` };
		}
		return { ok: true, value: intersection };
	},
	canCombineWith(otherOperator: string, _thisValue: unknown, otherValue: unknown): boolean {
		if (otherOperator === PolicyOperator.OneOf) return false;
		if (NEVER_ALLOWED.has(`one_of:${otherOperator}`)) return false;

		if (otherOperator === PolicyOperator.Value) {
			return checkValueCombination(PolicyOperator.OneOf, otherValue, _thisValue);
		}
		return true;
	},
};

const subsetOfOperator: PolicyOperatorDefinition = {
	name: PolicyOperator.SubsetOf,
	order: 5,
	action: "both",
	apply(parameterValue: unknown, operatorValue: unknown): PolicyOperatorResult {
		if (parameterValue === undefined) {
			return { ok: true, value: undefined };
		}
		const opArr = Array.isArray(operatorValue) ? operatorValue : [operatorValue];
		if (Array.isArray(parameterValue)) {
			return { ok: true, value: arrayIntersection(parameterValue, opArr) };
		}
		if (containsElement(opArr, parameterValue)) {
			return { ok: true, value: parameterValue };
		}
		return { ok: false, error: `Value not in subset_of set` };
	},
	merge(existingValue: unknown, newValue: unknown): PolicyMergeResult {
		const existArr = Array.isArray(existingValue) ? existingValue : [existingValue];
		const newArr = Array.isArray(newValue) ? newValue : [newValue];
		return { ok: true, value: arrayIntersection(existArr, newArr) };
	},
	canCombineWith(otherOperator: string, thisValue: unknown, otherValue: unknown): boolean {
		if (otherOperator === PolicyOperator.SubsetOf) return false;
		if (NEVER_ALLOWED.has(`subset_of:${otherOperator}`)) return false;

		if (otherOperator === PolicyOperator.Value) {
			return checkValueCombination(PolicyOperator.SubsetOf, otherValue, thisValue);
		}
		if (otherOperator === PolicyOperator.Add) {
			const otherArr = Array.isArray(otherValue) ? otherValue : [otherValue];
			const thisArr = Array.isArray(thisValue) ? thisValue : [thisValue];
			return isSubset(otherArr, thisArr);
		}
		if (otherOperator === PolicyOperator.SupersetOf) {
			// Floor must be subset of ceiling
			const otherArr = Array.isArray(otherValue) ? otherValue : [otherValue];
			const thisArr = Array.isArray(thisValue) ? thisValue : [thisValue];
			return isSubset(otherArr, thisArr);
		}
		return true;
	},
};

const supersetOfOperator: PolicyOperatorDefinition = {
	name: PolicyOperator.SupersetOf,
	order: 6,
	action: "check",
	apply(parameterValue: unknown, operatorValue: unknown): PolicyOperatorResult {
		if (parameterValue === undefined) {
			return { ok: true, value: undefined };
		}
		const opArr = Array.isArray(operatorValue) ? operatorValue : [operatorValue];
		const paramArr = Array.isArray(parameterValue) ? parameterValue : [parameterValue];
		if (isSubset(opArr, paramArr)) {
			return { ok: true, value: parameterValue };
		}
		return { ok: false, error: `Value does not contain all required elements from superset_of` };
	},
	merge(existingValue: unknown, newValue: unknown): PolicyMergeResult {
		const existArr = Array.isArray(existingValue) ? existingValue : [existingValue];
		const newArr = Array.isArray(newValue) ? newValue : [newValue];
		return { ok: true, value: arrayUnion(existArr, newArr) };
	},
	canCombineWith(otherOperator: string, thisValue: unknown, otherValue: unknown): boolean {
		if (otherOperator === PolicyOperator.SupersetOf) return false;
		if (NEVER_ALLOWED.has(`superset_of:${otherOperator}`)) return false;

		if (otherOperator === PolicyOperator.Value) {
			return checkValueCombination(PolicyOperator.SupersetOf, otherValue, thisValue);
		}
		if (otherOperator === PolicyOperator.SubsetOf) {
			// Floor (this) must be subset of ceiling (other)
			const thisArr = Array.isArray(thisValue) ? thisValue : [thisValue];
			const otherArr = Array.isArray(otherValue) ? otherValue : [otherValue];
			return isSubset(thisArr, otherArr);
		}
		return true;
	},
};

const essentialOperator: PolicyOperatorDefinition = {
	name: PolicyOperator.Essential,
	order: 7,
	action: "check",
	apply(parameterValue: unknown, operatorValue: unknown): PolicyOperatorResult {
		if (operatorValue === true && parameterValue === undefined) {
			return { ok: false, error: `Essential parameter is missing` };
		}
		return { ok: true, value: parameterValue };
	},
	merge(existingValue: unknown, newValue: unknown): PolicyMergeResult {
		return { ok: true, value: (existingValue as boolean) || (newValue as boolean) };
	},
	canCombineWith(otherOperator: string, thisValue: unknown, otherValue: unknown): boolean {
		if (otherOperator === PolicyOperator.Essential) return false;

		if (otherOperator === PolicyOperator.Value) {
			if (otherValue === null && thisValue === true) return false;
			return true;
		}
		return true;
	},
};

export const operators: Record<string, PolicyOperatorDefinition> = {
	[PolicyOperator.Value]: valueOperator,
	[PolicyOperator.Add]: addOperator,
	[PolicyOperator.Default]: defaultOperator,
	[PolicyOperator.OneOf]: oneOfOperator,
	[PolicyOperator.SubsetOf]: subsetOfOperator,
	[PolicyOperator.SupersetOf]: supersetOfOperator,
	[PolicyOperator.Essential]: essentialOperator,
};
