import type { HttpClient } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { createHttpClient, fetchTextOrError } from "../../src/util/http.js";

describe("createHttpClient", () => {
	it("aborts requests that exceed timeout", async () => {
		const client = createHttpClient(1);
		await expect(client("https://httpbin.org/delay/10")).rejects.toThrow();
	});
});

describe("fetchTextOrError", () => {
	it("returns ok with body text on success", async () => {
		const mockClient: HttpClient = async () => new Response("hello", { status: 200 });
		const result = await fetchTextOrError(mockClient, "https://example.com", "Fetch failed");
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value).toBe("hello");
		}
	});

	it("returns error on non-ok HTTP status", async () => {
		const mockClient: HttpClient = async () => new Response("Not Found", { status: 404 });
		const result = await fetchTextOrError(mockClient, "https://example.com", "Fetch failed");
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("Fetch failed");
			expect(result.error.description).toContain("404");
		}
	});
});
