import { describe, expect, it } from "vitest";
import { HumanFormatter } from "../../src/output/human.js";

describe("HumanFormatter", () => {
	const fmt = new HumanFormatter();

	it("formats array of objects as table", () => {
		const data = [
			{ name: "Alice", age: 30 },
			{ name: "Bob", age: 25 },
		];
		const result = fmt.format(data);
		expect(result).toContain("name");
		expect(result).toContain("age");
		expect(result).toContain("Alice");
		expect(result).toContain("Bob");
		expect(result).toContain("─");
	});

	it("formats single object as key-value", () => {
		const result = fmt.format({ iss: "https://ta.example.com", sub: "https://leaf.example.com" });
		expect(result).toContain("iss");
		expect(result).toContain("sub");
		expect(result).toContain("https://ta.example.com");
	});

	it("formats primitives as colorized JSON", () => {
		expect(fmt.format("hello")).toContain("hello");
		expect(fmt.format(42)).toContain("42");
		expect(fmt.format(null)).toContain("null");
	});

	it("handles nested objects in values", () => {
		const result = fmt.format({ key: { nested: true } });
		expect(result).toContain("nested");
	});

	it("renders boolean values as ✓/✗", () => {
		const data = [
			{ name: "check1", valid: true },
			{ name: "check2", valid: false },
		];
		const result = fmt.format(data);
		expect(result).toContain("✓");
		expect(result).toContain("✗");
	});

	it("renders nested array as sub-table in key-value format", () => {
		const data = {
			entity: "https://ta.example.com",
			checks: [
				{ name: "jwks", status: "ok" },
				{ name: "metadata", status: "error" },
			],
		};
		const result = fmt.format(data);
		expect(result).toContain("checks");
		expect(result).toContain("jwks");
		expect(result).toContain("metadata");
		expect(result).toContain("name");
		expect(result).toContain("status");
	});

	it("detects compact JWT and returns colored 3-segment string", () => {
		const jwt = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.c2lnbmF0dXJl";
		const result = fmt.format(jwt);
		expect(result).toContain("eyJhbGciOiJSUzI1NiJ9");
		expect(result).toContain("eyJpc3MiOiJ0ZXN0In0");
		expect(result).toContain("c2lnbmF0dXJl");
		const dots = result.match(/\./g);
		expect(dots).toHaveLength(2);
	});

	it("does not treat non-JWT strings as JWT", () => {
		const result = fmt.format("not.a.jwt.token");
		// 4 dot-separated parts — not a JWT, rendered as JSON string
		expect(result).toContain("not.a.jwt.token");
	});
});
