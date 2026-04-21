import { generateSigningKey, type HttpClient, signEntityStatement } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/entity.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

function makeHttpClient(responseBody: string, ok = true): HttpClient {
	return async () =>
		new Response(ok ? responseBody : "Not Found", {
			status: ok ? 200 : 404,
			headers: { "Content-Type": "application/entity-statement+jwt" },
		}) as unknown as Response;
}

const logger = createLogger({ quiet: true, verbose: false });

describe("entity handler", () => {
	it("verifies JWT signature when verify=true", async () => {
		const key = await generateSigningKey("ES256");
		const jwt = await signEntityStatement(
			{
				iss: "https://ta.example.com",
				sub: "https://ta.example.com",
				iat: 1000,
				exp: 9999999999,
				jwks: { keys: [key.publicKey] },
			},
			key.privateKey,
		);

		const result = await handler(
			{ entityId: "https://ta.example.com", decode: false, verify: true },
			{ httpClient: makeHttpClient(jwt), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(parsed.iss).toBe("https://ta.example.com");
		}
	});

	it("fetches and returns raw JWT when decode=false", async () => {
		const key = await generateSigningKey("ES256");
		const jwt = await signEntityStatement(
			{
				iss: "https://ta.example.com",
				sub: "https://ta.example.com",
				iat: 1000,
				exp: 9999999999,
				jwks: { keys: [key.publicKey] },
			},
			key.privateKey,
		);

		const result = await handler(
			{ entityId: "https://ta.example.com", decode: false, verify: false },
			{ httpClient: makeHttpClient(jwt), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(true);
	});

	it("fetches and decodes JWT when decode=true", async () => {
		const key = await generateSigningKey("ES256");
		const jwt = await signEntityStatement(
			{
				iss: "https://ta.example.com",
				sub: "https://ta.example.com",
				iat: 1000,
				exp: 9999999999,
				jwks: { keys: [key.publicKey] },
			},
			key.privateKey,
		);

		const result = await handler(
			{ entityId: "https://ta.example.com", decode: true, verify: false },
			{ httpClient: makeHttpClient(jwt), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(parsed.iss).toBe("https://ta.example.com");
		}
	});

	it("returns error when fetch fails", async () => {
		const result = await handler(
			{ entityId: "https://ta.example.com", decode: false, verify: false },
			{ httpClient: makeHttpClient("Not Found", false), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
	});
});
