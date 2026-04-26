import { generateSigningKey, type HttpClient, signEntityStatement } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/validate.js";
import { DEFAULT_CONFIG } from "../../src/config.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const failingClient: HttpClient = async () => new Response("Not Found", { status: 404 });

const deps = {
	httpClient: failingClient,
	formatter: new JsonFormatter(),
	logger: createLogger({ quiet: true, verbose: false }),
	config: DEFAULT_CONFIG,
};

describe("validate handler", () => {
	it("returns error when no JWTs provided", async () => {
		const result = await handler({ jwts: [], trustAnchors: ["https://ta.example.com"] }, deps);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("At least one JWT");
		}
	});

	it("returns error when no trust anchors specified", async () => {
		const result = await handler({ jwts: ["some-jwt"], trustAnchors: [] }, deps);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("No trust anchors");
		}
	});

	it("validates a self-signed trust anchor EC", async () => {
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

		const taClient: HttpClient = async () =>
			new Response(jwt, {
				status: 200,
				headers: { "content-type": "application/entity-statement+jwt" },
			});

		const result = await handler(
			{ jwts: [jwt], trustAnchors: ["https://ta.example.com"] },
			{ ...deps, httpClient: taClient },
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(typeof parsed.valid).toBe("boolean");
		}
	});

	it("auto-detects entity-id mode for HTTP URLs", async () => {
		const result = await handler({ jwts: ["https://entity.example.com"], trustAnchors: [] }, deps);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("No trust anchors");
		}
	});

	it("entity-id mode returns error when TA is unreachable", async () => {
		const result = await handler(
			{ jwts: ["https://leaf.example.com"], trustAnchors: ["https://ta.example.com"] },
			deps,
		);
		expect(result.ok).toBe(false);
	});

	it("entity-id mode returns error for invalid entity URL", async () => {
		// Need a TA that can be fetched so buildTrustAnchors doesn't fail first
		const key = await generateSigningKey("ES256");
		const taJwt = await signEntityStatement(
			{
				iss: "https://ta.example.com",
				sub: "https://ta.example.com",
				iat: 1000,
				exp: 9999999999,
				jwks: { keys: [key.publicKey] },
			},
			key.privateKey,
		);
		const client: HttpClient = async (input) => {
			const parsed = new URL(typeof input === "string" ? input : input.toString());
			if (parsed.hostname === "ta.example.com") {
				return new Response(taJwt, {
					status: 200,
					headers: { "content-type": "application/entity-statement+jwt" },
				});
			}
			return new Response("Not Found", { status: 404 });
		};

		const result = await handler(
			{ jwts: ["https://nonexistent.example.com"], trustAnchors: ["https://ta.example.com"] },
			{ ...deps, httpClient: client },
		);
		// Resolution will fail because leaf is unreachable
		expect(result.ok).toBe(false);
	});
});
