import { generateSigningKey, type HttpClient, signEntityStatement } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/health.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const logger = createLogger({ quiet: true, verbose: false });

describe("health handler", () => {
	it("returns error for invalid entity ID", async () => {
		const client: HttpClient = async () => new Response("", { status: 404 });
		const result = await handler(
			{ entityId: "bad" },
			{ httpClient: client, formatter: new JsonFormatter(), logger, readFile: async () => "" },
		);
		expect(result.ok).toBe(false);
	});

	it("includes key comparison when --ta-jwks provided", async () => {
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

		const client: HttpClient = async () =>
			new Response(jwt, {
				status: 200,
				headers: { "Content-Type": "application/entity-statement+jwt" },
			});
		const taJwks = JSON.stringify({ keys: [key.publicKey] });
		const result = await handler(
			{ entityId: "https://ta.example.com", taJwks: "/tmp/ta.jwks" },
			{ httpClient: client, formatter: new JsonFormatter(), logger, readFile: async () => taJwks },
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(parsed.key_comparison).toBeDefined();
			expect(parsed.key_comparison.match).toBe(true);
		}
	});

	it("checks health of entity endpoints", async () => {
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

		const client: HttpClient = async () => new Response(jwt, { status: 200 });
		const result = await handler(
			{ entityId: "https://ta.example.com" },
			{ httpClient: client, formatter: new JsonFormatter(), logger, readFile: async () => "" },
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(parsed.checks).toBeInstanceOf(Array);
			expect(parsed.checks.length).toBeGreaterThanOrEqual(1);
		}
	});
});
