import { describe, expect, it } from "vitest";
import { parseJsonOrError } from "../../src/util/parse.js";

describe("parseJsonOrError", () => {
	it("returns ok for valid JSON", () => {
		const result = parseJsonOrError('{"key":"value"}');
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value).toEqual({ key: "value" });
		}
	});

	it("returns error for invalid JSON", () => {
		const result = parseJsonOrError("not json");
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("not valid JSON");
		}
	});

	it("uses custom error message", () => {
		const result = parseJsonOrError("bad", "Custom parse error");
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toBe("Custom parse error");
		}
	});

	it("handles arrays", () => {
		const result = parseJsonOrError("[1,2,3]");
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value).toEqual([1, 2, 3]);
		}
	});
});
