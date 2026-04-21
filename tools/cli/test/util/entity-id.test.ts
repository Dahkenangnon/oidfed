import { describe, expect, it } from "vitest";
import {
	extractJwks,
	isEntityId,
	normalizeEntityId,
	parseEntityIdOrError,
} from "../../src/util/entity-id.js";

describe("parseEntityIdOrError", () => {
	it("returns ok for valid HTTPS entity ID", () => {
		const result = parseEntityIdOrError("https://example.com");
		expect(result.ok).toBe(true);
	});

	it("returns error for invalid entity ID", () => {
		const result = parseEntityIdOrError("not-a-url");
		expect(result.ok).toBe(false);
	});

	it("returns error for HTTP entity ID", () => {
		const result = parseEntityIdOrError("http://example.com");
		expect(result.ok).toBe(false);
	});
});

describe("normalizeEntityId", () => {
	it("strips trailing slash", () => {
		expect(normalizeEntityId("https://example.com/")).toBe("https://example.com");
	});

	it("returns unchanged when no trailing slash", () => {
		expect(normalizeEntityId("https://example.com")).toBe("https://example.com");
	});
});

describe("isEntityId", () => {
	it("recognizes https URLs", () => {
		expect(isEntityId("https://example.com")).toBe(true);
	});

	it("recognizes http URLs", () => {
		expect(isEntityId("http://example.com")).toBe(true);
	});

	it("rejects JWT-like strings", () => {
		expect(isEntityId("eyJhbGciOiJFUzI1NiJ9.payload.sig")).toBe(false);
	});
});

describe("extractJwks", () => {
	it("returns ok when payload has jwks with keys", () => {
		const payload = { jwks: { keys: [{ kty: "EC" }] } };
		const result = extractJwks(payload);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.keys).toHaveLength(1);
		}
	});

	it("returns error when jwks is missing", () => {
		const result = extractJwks({ iss: "https://example.com" });
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("missing required jwks");
		}
	});

	it("returns error when jwks has no keys property", () => {
		const result = extractJwks({ jwks: {} });
		expect(result.ok).toBe(false);
	});
});
