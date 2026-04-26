import { generateSigningKey, type HttpClient, signEntityStatement } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handleJwt, handler } from "../../src/commands/expiry.js";
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

async function makeJwt(exp: number) {
	const key = await generateSigningKey("ES256");
	return signEntityStatement(
		{ iss: "https://ta.example.com", sub: "https://ta.example.com", iat: 1000, exp },
		key.privateKey,
	);
}

describe("expiry handler — JWT mode", () => {
	it("shows expiry details for a valid JWT", async () => {
		const jwt = await makeJwt(9999999999);
		const result = await handler({ jwt }, deps);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(parsed.expired).toBe(false);
			expect(parsed.remaining_seconds).toBeGreaterThan(0);
			expect(parsed.issuer).toBe("https://ta.example.com");
		}
	});

	it("shows expired status for past expiry", async () => {
		const jwt = await makeJwt(1000);
		const result = await handler({ jwt }, deps);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(parsed.expired).toBe(true);
			expect(parsed.remaining_seconds).toBe(0);
		}
	});

	it("returns error for invalid JWT", async () => {
		const result = await handler({ jwt: "not-a-jwt" }, deps);
		expect(result.ok).toBe(false);
	});
});

describe("handleJwt", () => {
	it("returns expiry info synchronously", async () => {
		const jwt = await makeJwt(9999999999);
		const result = handleJwt(jwt, deps);
		expect(result.ok).toBe(true);
	});
});

describe("expiry handler — entity-id mode", () => {
	it("returns error when no trust anchors for entity-id mode", async () => {
		const result = await handler({ jwt: "https://entity.example.com", trustAnchors: [] }, deps);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("No trust anchors");
		}
	});

	it("returns error when TA is unreachable in entity-id mode", async () => {
		const result = await handler(
			{ jwt: "https://leaf.example.com", trustAnchors: ["https://ta.example.com"] },
			deps,
		);
		expect(result.ok).toBe(false);
	});

	it("auto-detects entity-id from https URL", async () => {
		// Verifies that handler routes to entity-id mode for https URLs
		const result = await handler({ jwt: "https://leaf.example.com", trustAnchors: [] }, deps);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			// Should fail asking for trust anchors, not "invalid JWT"
			expect(result.error.description).toContain("No trust anchors");
		}
	});

	it("does not auto-detect http URLs as entity IDs (Entity IDs MUST use https)", async () => {
		// http://… is not a valid Entity Identifier per the spec, so the handler
		// falls back to JWT decoding, which fails with a JWT-shape error.
		const result = await handler({ jwt: "http://leaf.example.com", trustAnchors: [] }, deps);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).not.toContain("No trust anchors");
		}
	});
});
