import { describe, expect, it } from "vitest";
import { JsonFormatter } from "../../src/output/json.js";

describe("JsonFormatter", () => {
	const fmt = new JsonFormatter();

	it("formats objects as plain JSON", () => {
		const result = fmt.format({ foo: "bar" });
		expect(result).toBe('{\n  "foo": "bar"\n}');
		expect(JSON.parse(result)).toEqual({ foo: "bar" });
	});

	it("formats arrays", () => {
		const result = fmt.format([1, 2, 3]);
		expect(JSON.parse(result)).toEqual([1, 2, 3]);
	});

	it("formats primitives", () => {
		expect(fmt.format("hello")).toBe('"hello"');
		expect(fmt.format(42)).toBe("42");
		expect(fmt.format(null)).toBe("null");
		expect(fmt.format(true)).toBe("true");
	});

	it("does not colorize JWT strings", () => {
		const jwt = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.c2lnbmF0dXJl";
		const result = fmt.format(jwt);
		// Should be plain JSON string with no ANSI codes
		expect(result).toBe(`"${jwt}"`);
		expect(JSON.parse(result)).toBe(jwt);
	});

	it("roundtrips complex objects", () => {
		const data = { items: [{ id: 1, active: true }], total: 1 };
		expect(JSON.parse(fmt.format(data))).toEqual(data);
	});
});
