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

function isJsonObject(value: unknown): value is Record<string, unknown> {
	return !!value && typeof value === "object" && !Array.isArray(value);
}

function valueType(value: unknown): string {
	if (value === null) return "null";
	if (Array.isArray(value)) return "array";
	return typeof value;
}

function isScalar(value: unknown): value is string | number | boolean {
	return typeof value === "string" || typeof value === "number" || typeof value === "boolean";
}

function isValueOrDefaultMetadataValue(value: unknown): boolean {
	return isScalar(value) || Array.isArray(value);
}

function isComparableElement(value: unknown): boolean {
	return typeof value === "string" || typeof value === "number" || isJsonObject(value);
}

function isComparableArray(value: unknown): value is unknown[] {
	return Array.isArray(value) && value.every(isComparableElement);
}

function isOneOfMetadataValue(value: unknown): boolean {
	return typeof value === "string" || typeof value === "number" || isJsonObject(value);
}

function isEssentialMetadataValue(value: unknown): boolean {
	return value !== null && value !== undefined;
}

function invalidOperatorValue(name: string, expected: string, value: unknown): string {
	return `'${name}' operator value must be ${expected}; got ${valueType(value)}`;
}

function invalidMetadataValue(name: string, expected: string, value: unknown): string {
	return `'${name}' operator does not support metadata value type ${valueType(value)}; expected ${expected}`;
}

export function validateStandardPolicyOperatorConfiguration(
	operatorName: string,
	operatorValue: unknown,
): string | undefined {
	switch (operatorName) {
		case PolicyOperator.Value:
			return operatorValue === null || isValueOrDefaultMetadataValue(operatorValue)
				? undefined
				: invalidOperatorValue(
						operatorName,
						"a string, number, boolean, array, or null",
						operatorValue,
					);
		case PolicyOperator.Default:
			return isValueOrDefaultMetadataValue(operatorValue)
				? undefined
				: invalidOperatorValue(operatorName, "a string, number, boolean, or array", operatorValue);
		case PolicyOperator.Add:
		case PolicyOperator.SubsetOf:
		case PolicyOperator.SupersetOf:
			return isComparableArray(operatorValue)
				? undefined
				: invalidOperatorValue(
						operatorName,
						"an array of strings, numbers, or objects",
						operatorValue,
					);
		case PolicyOperator.OneOf:
			return isComparableArray(operatorValue)
				? undefined
				: invalidOperatorValue(
						operatorName,
						"an array of strings, numbers, or objects",
						operatorValue,
					);
		case PolicyOperator.Essential:
			return typeof operatorValue === "boolean"
				? undefined
				: invalidOperatorValue(operatorName, "a boolean", operatorValue);
		default:
			return undefined;
	}
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
			if (!Array.isArray(valueVal)) return false;
			return isSubset(addArr, valueVal);
		}
		case PolicyOperator.Default:
			if (valueVal === null) return false;
			return deepEqual(valueVal, otherVal);
		case PolicyOperator.OneOf:
			if (Array.isArray(valueVal)) return false;
			return containsElement(otherVal as unknown[], valueVal);
		case PolicyOperator.SubsetOf: {
			const subsetOfArr = otherVal as unknown[];
			if (!Array.isArray(valueVal)) return false;
			return isSubset(valueVal, subsetOfArr);
		}
		case PolicyOperator.SupersetOf: {
			const supersetOfArr = otherVal as unknown[];
			if (!Array.isArray(valueVal)) return false;
			return isSubset(supersetOfArr, valueVal);
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
	apply(parameterValue: unknown, operatorValue: unknown): PolicyOperatorResult {
		const configError = validateStandardPolicyOperatorConfiguration(
			PolicyOperator.Value,
			operatorValue,
		);
		if (configError) return { ok: false, error: configError };
		if (parameterValue !== undefined && !isValueOrDefaultMetadataValue(parameterValue)) {
			return {
				ok: false,
				error: invalidMetadataValue(
					PolicyOperator.Value,
					"a string, number, boolean, or array",
					parameterValue,
				),
			};
		}
		if (operatorValue === null) {
			return { ok: true, value: null, removed: true };
		}
		return { ok: true, value: operatorValue };
	},
	merge(existingValue: unknown, newValue: unknown): PolicyMergeResult {
		const existingError = validateStandardPolicyOperatorConfiguration(
			PolicyOperator.Value,
			existingValue,
		);
		if (existingError) return { ok: false, error: existingError };
		const newError = validateStandardPolicyOperatorConfiguration(PolicyOperator.Value, newValue);
		if (newError) return { ok: false, error: newError };
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
		const configError = validateStandardPolicyOperatorConfiguration(
			PolicyOperator.Add,
			operatorValue,
		);
		if (configError) return { ok: false, error: configError };
		if (parameterValue === undefined) {
			return { ok: true, value: operatorValue };
		}
		if (!isComparableArray(parameterValue)) {
			return {
				ok: false,
				error: invalidMetadataValue(
					PolicyOperator.Add,
					"an array of strings, numbers, or objects",
					parameterValue,
				),
			};
		}
		const operatorArray = operatorValue as unknown[];
		return { ok: true, value: arrayUnion(parameterValue, operatorArray) };
	},
	merge(existingValue: unknown, newValue: unknown): PolicyMergeResult {
		const existingError = validateStandardPolicyOperatorConfiguration(
			PolicyOperator.Add,
			existingValue,
		);
		if (existingError) return { ok: false, error: existingError };
		const newError = validateStandardPolicyOperatorConfiguration(PolicyOperator.Add, newValue);
		if (newError) return { ok: false, error: newError };
		return { ok: true, value: arrayUnion(existingValue as unknown[], newValue as unknown[]) };
	},
	canCombineWith(otherOperator: string, thisValue: unknown, otherValue: unknown): boolean {
		if (otherOperator === PolicyOperator.Add) return false;
		if (NEVER_ALLOWED.has(`add:${otherOperator}`)) return false;

		if (otherOperator === PolicyOperator.Value) {
			return checkValueCombination(PolicyOperator.Add, otherValue, thisValue);
		}
		if (otherOperator === PolicyOperator.SubsetOf) {
			if (!isComparableArray(thisValue) || !isComparableArray(otherValue)) return false;
			return isSubset(thisValue, otherValue);
		}
		return true;
	},
};

const defaultOperator: PolicyOperatorDefinition = {
	name: PolicyOperator.Default,
	order: 3,
	action: "modify",
	apply(parameterValue: unknown, operatorValue: unknown): PolicyOperatorResult {
		const configError = validateStandardPolicyOperatorConfiguration(
			PolicyOperator.Default,
			operatorValue,
		);
		if (configError) return { ok: false, error: configError };
		if (parameterValue === undefined) {
			return { ok: true, value: operatorValue };
		}
		if (!isValueOrDefaultMetadataValue(parameterValue)) {
			return {
				ok: false,
				error: invalidMetadataValue(
					PolicyOperator.Default,
					"a string, number, boolean, or array",
					parameterValue,
				),
			};
		}
		return { ok: true, value: parameterValue };
	},
	merge(existingValue: unknown, newValue: unknown): PolicyMergeResult {
		const existingError = validateStandardPolicyOperatorConfiguration(
			PolicyOperator.Default,
			existingValue,
		);
		if (existingError) return { ok: false, error: existingError };
		const newError = validateStandardPolicyOperatorConfiguration(PolicyOperator.Default, newValue);
		if (newError) return { ok: false, error: newError };
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
		const configError = validateStandardPolicyOperatorConfiguration(
			PolicyOperator.OneOf,
			operatorValue,
		);
		if (configError) return { ok: false, error: configError };
		if (parameterValue === undefined) {
			return { ok: true, value: undefined };
		}
		if (!isOneOfMetadataValue(parameterValue)) {
			return {
				ok: false,
				error: invalidMetadataValue(
					PolicyOperator.OneOf,
					"a string, number, or object",
					parameterValue,
				),
			};
		}
		const operatorArray = operatorValue as unknown[];
		if (containsElement(operatorArray, parameterValue)) {
			return { ok: true, value: parameterValue };
		}
		return { ok: false, error: `Value not in one_of set` };
	},
	merge(existingValue: unknown, newValue: unknown): PolicyMergeResult {
		const existingError = validateStandardPolicyOperatorConfiguration(
			PolicyOperator.OneOf,
			existingValue,
		);
		if (existingError) return { ok: false, error: existingError };
		const newError = validateStandardPolicyOperatorConfiguration(PolicyOperator.OneOf, newValue);
		if (newError) return { ok: false, error: newError };
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
		const configError = validateStandardPolicyOperatorConfiguration(
			PolicyOperator.SubsetOf,
			operatorValue,
		);
		if (configError) return { ok: false, error: configError };
		if (parameterValue === undefined) {
			return { ok: true, value: undefined };
		}
		if (!isComparableArray(parameterValue)) {
			return {
				ok: false,
				error: invalidMetadataValue(
					PolicyOperator.SubsetOf,
					"an array of strings, numbers, or objects",
					parameterValue,
				),
			};
		}
		const operatorArray = operatorValue as unknown[];
		return { ok: true, value: arrayIntersection(parameterValue, operatorArray) };
	},
	merge(existingValue: unknown, newValue: unknown): PolicyMergeResult {
		const existingError = validateStandardPolicyOperatorConfiguration(
			PolicyOperator.SubsetOf,
			existingValue,
		);
		if (existingError) return { ok: false, error: existingError };
		const newError = validateStandardPolicyOperatorConfiguration(PolicyOperator.SubsetOf, newValue);
		if (newError) return { ok: false, error: newError };
		return {
			ok: true,
			value: arrayIntersection(existingValue as unknown[], newValue as unknown[]),
		};
	},
	canCombineWith(otherOperator: string, thisValue: unknown, otherValue: unknown): boolean {
		if (otherOperator === PolicyOperator.SubsetOf) return false;
		if (NEVER_ALLOWED.has(`subset_of:${otherOperator}`)) return false;

		if (otherOperator === PolicyOperator.Value) {
			return checkValueCombination(PolicyOperator.SubsetOf, otherValue, thisValue);
		}
		if (otherOperator === PolicyOperator.Add) {
			if (!isComparableArray(thisValue) || !isComparableArray(otherValue)) return false;
			return isSubset(otherValue, thisValue);
		}
		if (otherOperator === PolicyOperator.SupersetOf) {
			// Floor must be subset of ceiling
			if (!isComparableArray(thisValue) || !isComparableArray(otherValue)) return false;
			return isSubset(otherValue, thisValue);
		}
		return true;
	},
};

const supersetOfOperator: PolicyOperatorDefinition = {
	name: PolicyOperator.SupersetOf,
	order: 6,
	action: "check",
	apply(parameterValue: unknown, operatorValue: unknown): PolicyOperatorResult {
		const configError = validateStandardPolicyOperatorConfiguration(
			PolicyOperator.SupersetOf,
			operatorValue,
		);
		if (configError) return { ok: false, error: configError };
		if (parameterValue === undefined) {
			return { ok: true, value: undefined };
		}
		if (!isComparableArray(parameterValue)) {
			return {
				ok: false,
				error: invalidMetadataValue(
					PolicyOperator.SupersetOf,
					"an array of strings, numbers, or objects",
					parameterValue,
				),
			};
		}
		const operatorArray = operatorValue as unknown[];
		if (isSubset(operatorArray, parameterValue)) {
			return { ok: true, value: parameterValue };
		}
		return { ok: false, error: `Value does not contain all required elements from superset_of` };
	},
	merge(existingValue: unknown, newValue: unknown): PolicyMergeResult {
		const existingError = validateStandardPolicyOperatorConfiguration(
			PolicyOperator.SupersetOf,
			existingValue,
		);
		if (existingError) return { ok: false, error: existingError };
		const newError = validateStandardPolicyOperatorConfiguration(
			PolicyOperator.SupersetOf,
			newValue,
		);
		if (newError) return { ok: false, error: newError };
		return { ok: true, value: arrayUnion(existingValue as unknown[], newValue as unknown[]) };
	},
	canCombineWith(otherOperator: string, thisValue: unknown, otherValue: unknown): boolean {
		if (otherOperator === PolicyOperator.SupersetOf) return false;
		if (NEVER_ALLOWED.has(`superset_of:${otherOperator}`)) return false;

		if (otherOperator === PolicyOperator.Value) {
			return checkValueCombination(PolicyOperator.SupersetOf, otherValue, thisValue);
		}
		if (otherOperator === PolicyOperator.SubsetOf) {
			// Floor (this) must be subset of ceiling (other)
			if (!isComparableArray(thisValue) || !isComparableArray(otherValue)) return false;
			return isSubset(thisValue, otherValue);
		}
		return true;
	},
};

const essentialOperator: PolicyOperatorDefinition = {
	name: PolicyOperator.Essential,
	order: 7,
	action: "check",
	apply(parameterValue: unknown, operatorValue: unknown): PolicyOperatorResult {
		const configError = validateStandardPolicyOperatorConfiguration(
			PolicyOperator.Essential,
			operatorValue,
		);
		if (configError) return { ok: false, error: configError };
		if (operatorValue === true && parameterValue === undefined) {
			return { ok: false, error: `Essential parameter is missing` };
		}
		if (parameterValue !== undefined && !isEssentialMetadataValue(parameterValue)) {
			return {
				ok: false,
				error: invalidMetadataValue(
					PolicyOperator.Essential,
					"a string, number, boolean, object, or array",
					parameterValue,
				),
			};
		}
		return { ok: true, value: parameterValue };
	},
	merge(existingValue: unknown, newValue: unknown): PolicyMergeResult {
		const existingError = validateStandardPolicyOperatorConfiguration(
			PolicyOperator.Essential,
			existingValue,
		);
		if (existingError) return { ok: false, error: existingError };
		const newError = validateStandardPolicyOperatorConfiguration(
			PolicyOperator.Essential,
			newValue,
		);
		if (newError) return { ok: false, error: newError };
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
