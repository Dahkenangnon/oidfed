import { generateSigningKey, type HttpClient, signEntityStatement } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/trust-mark-status.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const logger = createLogger({ quiet: true, verbose: false });

function mockClient(body: string, ok = true): HttpClient {
	return async (_url, init) => {
		expect(init?.method).toBe("POST");
		expect(init?.headers).toEqual(
			expect.objectContaining({ "Content-Type": "application/x-www-form-urlencoded" }),
		);
		return new Response(body, { status: ok ? 200 : 404 });
	};
}

describe("trust-mark-status handler", () => {
	it("verifies response JWT when verify=true", async () => {
		const key = await generateSigningKey("ES256");
		const statusJwt = await signEntityStatement(
			{
				iss: "https://ta.example.com",
				sub: "https://ta.example.com",
				iat: 1000,
				exp: 9999999999,
				trust_mark: "eyJ.test.jwt",
				status: "valid",
			},
			key.privateKey,
			{ typ: "trust-mark-status-response+jwt" },
		);
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

		const client: HttpClient = async (url, _init) => {
			if (url.includes(".well-known")) {
				return new Response(ecJwt, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			return new Response(statusJwt, { status: 200 });
		};

		const result = await handler(
			{ entityId: "https://ta.example.com", verify: true, trustMark: "eyJ.abc.def" },
			{ httpClient: client, formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(true);
	});

	it("decodes a JWT response and returns payload", async () => {
		const key = await generateSigningKey("ES256");
		const jwt = await signEntityStatement(
			{
				iss: "https://ta.example.com",
				sub: "https://ta.example.com",
				iat: 1000,
				exp: 9999999999,
				active: true,
				jwks: { keys: [key.publicKey] },
			},
			key.privateKey,
		);
		const result = await handler(
			{ entityId: "https://ta.example.com", verify: false, trustMark: "eyJ.abc.def" },
			{ httpClient: mockClient(jwt), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(parsed.active).toBe(true);
			expect(parsed.iss).toBe("https://ta.example.com");
		}
	});

	it("falls back to JSON.parse for plain JSON responses", async () => {
		const result = await handler(
			{ entityId: "https://ta.example.com", verify: false, trustMark: "eyJ.abc.def" },
			{
				httpClient: mockClient(JSON.stringify({ active: true })),
				formatter: new JsonFormatter(),
				logger,
			},
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(JSON.parse(result.value).active).toBe(true);
		}
	});

	it("sends trust_mark in form body", async () => {
		const trustMarkJwt = "eyJ.payload.sig";
		const result = await handler(
			{ entityId: "https://ta.example.com", trustMark: trustMarkJwt, verify: false },
			{
				httpClient: async (_url, init) => {
					const bodyStr = init?.body as string;
					const params = new URLSearchParams(bodyStr);
					expect(params.get("trust_mark")).toBe(trustMarkJwt);
					return new Response(JSON.stringify({ active: true }), { status: 200 });
				},
				formatter: new JsonFormatter(),
				logger,
			},
		);
		expect(result.ok).toBe(true);
	});

	it("returns error for invalid entity ID", async () => {
		const result = await handler(
			{ entityId: "bad", trustMark: "jwt", verify: false },
			{ httpClient: mockClient(""), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
	});

	it("returns error on HTTP failure", async () => {
		const result = await handler(
			{ entityId: "https://ta.example.com", verify: false, trustMark: "jwt" },
			{ httpClient: mockClient("", false), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
	});

	it("wraps non-JWT non-JSON response as raw", async () => {
		const result = await handler(
			{ entityId: "https://ta.example.com", verify: false, trustMark: "jwt" },
			{ httpClient: mockClient("plain text response"), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(JSON.parse(result.value).response).toBe("plain text response");
		}
	});

	it("sends sub and id in form body for subject+id mode", async () => {
		const result = await handler(
			{
				entityId: "https://ta.example.com",
				subject: "https://rp.example.com",
				trustMarkId: "https://trust.example/mark/1",
				verify: false,
			},
			{
				httpClient: async (_url, init) => {
					const bodyStr = init?.body as string;
					const params = new URLSearchParams(bodyStr);
					expect(params.get("sub")).toBe("https://rp.example.com");
					expect(params.get("id")).toBe("https://trust.example/mark/1");
					expect(params.has("trust_mark")).toBe(false);
					return new Response(JSON.stringify({ active: true }), { status: 200 });
				},
				formatter: new JsonFormatter(),
				logger,
			},
		);
		expect(result.ok).toBe(true);
	});

	it("returns error when neither trust-mark nor subject+id provided", async () => {
		const result = await handler(
			{ entityId: "https://ta.example.com", verify: false },
			{ httpClient: mockClient(""), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("Either --trust-mark");
		}
	});

	it("returns error when both trust-mark and subject+id provided", async () => {
		const result = await handler(
			{
				entityId: "https://ta.example.com",
				trustMark: "eyJ.test.jwt",
				subject: "https://rp.example.com",
				trustMarkId: "https://trust.example/mark/1",
				verify: false,
			},
			{ httpClient: mockClient(""), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("Cannot use --trust-mark together");
		}
	});

	it("returns error when only subject provided without trust-mark-id", async () => {
		const result = await handler(
			{ entityId: "https://ta.example.com", subject: "https://rp.example.com", verify: false },
			{ httpClient: mockClient(""), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
	});
});
