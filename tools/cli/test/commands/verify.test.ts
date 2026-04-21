import { generateSigningKey, type HttpClient, signEntityStatement } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/verify.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const logger = createLogger({ quiet: true, verbose: false });
const formatter = new JsonFormatter();

async function makeSignedJwt(claims?: Record<string, unknown>) {
	const key = await generateSigningKey("ES256");
	const jwt = await signEntityStatement(
		{
			iss: "https://ta.example.com",
			sub: "https://ta.example.com",
			iat: 1000,
			exp: 9999999999,
			jwks: { keys: [key.publicKey] },
			...claims,
		},
		key.privateKey,
	);
	return { jwt, key };
}

describe("verify handler", () => {
	it("verifies JWT with inline JWKS file", async () => {
		const { jwt, key } = await makeSignedJwt();
		const jwks = JSON.stringify({ keys: [key.publicKey] });

		const result = await handler(
			{ jwt, jwksFile: "/tmp/jwks.json" },
			{
				httpClient: async () => new Response("", { status: 404 }),
				formatter,
				logger,
				readFile: async () => jwks,
			},
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(parsed.payload.iss).toBe("https://ta.example.com");
		}
	});

	it("verifies JWT by fetching JWKS from entity ID", async () => {
		const { jwt, key } = await makeSignedJwt();
		const ecJwt = await signEntityStatement(
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
			new Response(ecJwt, {
				status: 200,
				headers: { "Content-Type": "application/entity-statement+jwt" },
			});

		const result = await handler(
			{ jwt, entityId: "https://ta.example.com" },
			{ httpClient: client, formatter, logger, readFile: async () => "" },
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(parsed.payload.iss).toBe("https://ta.example.com");
		}
	});

	it("auto-fetches JWKS from iss when no source specified", async () => {
		const { jwt, key } = await makeSignedJwt();
		const ecJwt = await signEntityStatement(
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
			new Response(ecJwt, {
				status: 200,
				headers: { "Content-Type": "application/entity-statement+jwt" },
			});

		const result = await handler(
			{ jwt },
			{ httpClient: client, formatter, logger, readFile: async () => "" },
		);
		expect(result.ok).toBe(true);
	});

	it("returns error for invalid JWKS file", async () => {
		const { jwt } = await makeSignedJwt();
		const result = await handler(
			{ jwt, jwksFile: "/nonexistent" },
			{
				httpClient: async () => new Response("", { status: 404 }),
				formatter,
				logger,
				readFile: async () => {
					throw new Error("ENOENT");
				},
			},
		);
		expect(result.ok).toBe(false);
	});

	it("returns error when verification fails (wrong key)", async () => {
		const { jwt } = await makeSignedJwt();
		const otherKey = await generateSigningKey("ES256");
		const jwks = JSON.stringify({ keys: [otherKey.publicKey] });

		const result = await handler(
			{ jwt, jwksFile: "/tmp/jwks.json" },
			{
				httpClient: async () => new Response("", { status: 404 }),
				formatter,
				logger,
				readFile: async () => jwks,
			},
		);
		expect(result.ok).toBe(false);
	});
});
