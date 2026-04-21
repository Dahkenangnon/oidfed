import { generateSigningKey, type HttpClient, signEntityStatement } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/fetch.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const logger = createLogger({ quiet: true, verbose: false });

function mockClient(body: string, ok = true): HttpClient {
	return async () => new Response(body, { status: ok ? 200 : 404 });
}

describe("fetch handler", () => {
	it("fetches subordinate statement raw", async () => {
		const result = await handler(
			{ issuer: "https://ta.example.com", subject: "https://leaf.example.com", decode: false },
			{ httpClient: mockClient("eyJhbGciOi..."), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(true);
	});

	it("decodes subordinate statement", async () => {
		const key = await generateSigningKey("ES256");
		const jwt = await signEntityStatement(
			{
				iss: "https://ta.example.com",
				sub: "https://leaf.example.com",
				iat: 1000,
				exp: 9999999999,
			},
			key.privateKey,
		);

		const result = await handler(
			{ issuer: "https://ta.example.com", subject: "https://leaf.example.com", decode: true },
			{ httpClient: mockClient(jwt), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(parsed.iss).toBe("https://ta.example.com");
		}
	});

	it("returns error for invalid issuer", async () => {
		const result = await handler(
			{ issuer: "not-a-url", subject: "https://leaf.example.com", decode: false },
			{ httpClient: mockClient(""), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
	});

	it("returns error on HTTP failure", async () => {
		const result = await handler(
			{ issuer: "https://ta.example.com", subject: "https://leaf.example.com", decode: false },
			{ httpClient: mockClient("", false), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
	});
});
