import { describe, expect, it } from "vitest";
import { EntityIdSchema } from "../../src/schemas/entity-id.js";

describe("EntityIdSchema", () => {
	it("accepts valid HTTPS entity ID", () => {
		const result = EntityIdSchema.safeParse("https://example.com");
		expect(result.success).toBe(true);
	});

	it("accepts HTTPS entity ID with path", () => {
		const result = EntityIdSchema.safeParse("https://example.com/oidc");
		expect(result.success).toBe(true);
	});

	it("rejects HTTP URLs", () => {
		const result = EntityIdSchema.safeParse("http://example.com");
		expect(result.success).toBe(false);
	});

	it("rejects non-URL strings", () => {
		const result = EntityIdSchema.safeParse("not-a-url");
		expect(result.success).toBe(false);
	});

	it("rejects URLs exceeding 2048 characters", () => {
		const longUrl = `https://example.com/${"a".repeat(2048)}`;
		const result = EntityIdSchema.safeParse(longUrl);
		expect(result.success).toBe(false);
	});

	it("accepts URL at exactly 2048 characters", () => {
		const base = "https://example.com/";
		const url = base + "a".repeat(2048 - base.length);
		expect(url.length).toBe(2048);
		const result = EntityIdSchema.safeParse(url);
		expect(result.success).toBe(true);
	});

	it("rejects URLs with credentials", () => {
		const result = EntityIdSchema.safeParse("https://user:pass@example.com");
		expect(result.success).toBe(false);
	});

	it("rejects URLs with query parameters", () => {
		const result = EntityIdSchema.safeParse("https://example.com?foo=bar");
		expect(result.success).toBe(false);
	});

	it("rejects URLs with fragments", () => {
		const result = EntityIdSchema.safeParse("https://example.com#section");
		expect(result.success).toBe(false);
	});

	it("rejects empty string", () => {
		const result = EntityIdSchema.safeParse("");
		expect(result.success).toBe(false);
	});
});
