import { generateSigningKey, type HttpClient, signEntityStatement } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/trust-mark-status.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const logger = createLogger({ quiet: true, verbose: false });

const ISSUER = "https://tmi.example.com";
const STATUS_ENDPOINT = "https://tmi.example.com/federation/trust-mark-status";

async function buildIssuerEcAndKey() {
	const key = await generateSigningKey("ES256");
	const issuerEc = await signEntityStatement(
		{
			iss: ISSUER,
			sub: ISSUER,
			iat: 1000,
			exp: 9_999_999_999,
			jwks: { keys: [key.publicKey] },
			metadata: {
				federation_entity: {
					federation_trust_mark_status_endpoint: STATUS_ENDPOINT,
				},
			},
		},
		key.privateKey,
	);
	return { key, issuerEc };
}

describe("trust-mark-status handler", () => {
	it("verifies JWT-mode response via fetchTrustMarkStatus", async () => {
		const { key, issuerEc } = await buildIssuerEcAndKey();
		const statusJwt = await signEntityStatement(
			{
				iss: ISSUER,
				sub: ISSUER,
				iat: 1000,
				exp: 9_999_999_999,
				status: "active",
			},
			key.privateKey,
			{ typ: "trust-mark-status-response+jwt" },
		);
		const captures: { statusUrl?: string; postBody?: string } = {};
		const client: HttpClient = async (input, init) => {
			const url = typeof input === "string" ? input : input.toString();
			if (url.includes("/.well-known/openid-federation")) {
				return new Response(issuerEc, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			captures.statusUrl = url;
			captures.postBody = init?.body as string;
			expect(init?.method).toBe("POST");
			return new Response(statusJwt, {
				status: 200,
				headers: { "Content-Type": "application/trust-mark-status-response+jwt" },
			});
		};

		const result = await handler(
			{ entityId: ISSUER, verify: true, trustMark: "eyJ.test.jwt" },
			{ httpClient: client, formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(true);
		expect(captures.statusUrl?.startsWith(STATUS_ENDPOINT)).toBe(true);
		const params = new URLSearchParams(captures.postBody ?? "");
		expect(params.get("trust_mark")).toBe("eyJ.test.jwt");
	});

	it("returns parsed payload for non-verify JWT-mode response (raw POST path)", async () => {
		const { key, issuerEc } = await buildIssuerEcAndKey();
		const responseJwt = await signEntityStatement(
			{
				iss: ISSUER,
				sub: ISSUER,
				iat: 1000,
				exp: 9_999_999_999,
				active: true,
			},
			key.privateKey,
		);
		const client: HttpClient = async (input) => {
			const url = typeof input === "string" ? input : input.toString();
			if (url.includes("/.well-known/openid-federation")) {
				return new Response(issuerEc, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			return new Response(responseJwt, { status: 200 });
		};

		const result = await handler(
			{ entityId: ISSUER, verify: false, trustMark: "eyJ.test.jwt" },
			{ httpClient: client, formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(parsed.active).toBe(true);
			expect(parsed.iss).toBe(ISSUER);
		}
	});

	it("falls back to JSON.parse for plain JSON responses", async () => {
		const { issuerEc } = await buildIssuerEcAndKey();
		const client: HttpClient = async (input) => {
			const url = typeof input === "string" ? input : input.toString();
			if (url.includes("/.well-known/openid-federation")) {
				return new Response(issuerEc, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			return new Response(JSON.stringify({ active: true }), { status: 200 });
		};
		const result = await handler(
			{ entityId: ISSUER, verify: false, trustMark: "eyJ.test.jwt" },
			{ httpClient: client, formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(JSON.parse(result.value).active).toBe(true);
		}
	});

	it("sends trust_mark in form body for JWT mode (raw POST)", async () => {
		const { issuerEc } = await buildIssuerEcAndKey();
		const captures: { body?: string } = {};
		const client: HttpClient = async (input, init) => {
			const url = typeof input === "string" ? input : input.toString();
			if (url.includes("/.well-known/openid-federation")) {
				return new Response(issuerEc, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			captures.body = init?.body as string;
			return new Response(JSON.stringify({ active: true }), { status: 200 });
		};
		await handler(
			{ entityId: ISSUER, trustMark: "eyJ.payload.sig", verify: false },
			{ httpClient: client, formatter: new JsonFormatter(), logger },
		);
		const params = new URLSearchParams(captures.body ?? "");
		expect(params.get("trust_mark")).toBe("eyJ.payload.sig");
	});

	it("sends sub and trust_mark_type (NOT id) in form body for sub+type mode", async () => {
		const { issuerEc } = await buildIssuerEcAndKey();
		const captures: { body?: string } = {};
		const client: HttpClient = async (input, init) => {
			const url = typeof input === "string" ? input : input.toString();
			if (url.includes("/.well-known/openid-federation")) {
				return new Response(issuerEc, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			captures.body = init?.body as string;
			return new Response(JSON.stringify({ active: true }), { status: 200 });
		};

		await handler(
			{
				entityId: ISSUER,
				subject: "https://rp.example.com",
				trustMarkType: "https://trust.example/mark/1",
				verify: false,
			},
			{ httpClient: client, formatter: new JsonFormatter(), logger },
		);
		const params = new URLSearchParams(captures.body ?? "");
		expect(params.get("sub")).toBe("https://rp.example.com");
		expect(params.get("trust_mark_type")).toBe("https://trust.example/mark/1");
		expect(params.has("trust_mark")).toBe(false);
		expect(params.has("id")).toBe(false);
	});

	it("uses --status-endpoint override and skips discovery", async () => {
		const captures: { ecCalled: boolean; statusUrl?: string } = { ecCalled: false };
		const override = "https://other.example.com/status";
		const client: HttpClient = async (input) => {
			const url = typeof input === "string" ? input : input.toString();
			if (url.includes("/.well-known/openid-federation")) {
				captures.ecCalled = true;
				return new Response("", { status: 500 });
			}
			captures.statusUrl = url;
			return new Response(JSON.stringify({ active: true }), { status: 200 });
		};
		await handler(
			{ entityId: ISSUER, trustMark: "eyJ.test.jwt", verify: false, statusEndpoint: override },
			{ httpClient: client, formatter: new JsonFormatter(), logger },
		);
		expect(captures.ecCalled).toBe(false);
		expect(captures.statusUrl?.startsWith(override)).toBe(true);
	});

	it("returns error for invalid entity ID", async () => {
		const result = await handler(
			{ entityId: "bad", trustMark: "jwt", verify: false },
			{ httpClient: async () => new Response(""), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
	});

	it("returns error on HTTP failure of status endpoint", async () => {
		const { issuerEc } = await buildIssuerEcAndKey();
		const client: HttpClient = async (input) => {
			const url = typeof input === "string" ? input : input.toString();
			if (url.includes("/.well-known/openid-federation")) {
				return new Response(issuerEc, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			return new Response("", { status: 500 });
		};
		const result = await handler(
			{ entityId: ISSUER, verify: false, trustMark: "jwt" },
			{ httpClient: client, formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
	});

	it("wraps non-JWT non-JSON response as raw", async () => {
		const { issuerEc } = await buildIssuerEcAndKey();
		const client: HttpClient = async (input) => {
			const url = typeof input === "string" ? input : input.toString();
			if (url.includes("/.well-known/openid-federation")) {
				return new Response(issuerEc, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			return new Response("plain text response", { status: 200 });
		};
		const result = await handler(
			{ entityId: ISSUER, verify: false, trustMark: "jwt" },
			{ httpClient: client, formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(JSON.parse(result.value).response).toBe("plain text response");
		}
	});

	it("returns error when neither trust-mark nor subject+type provided", async () => {
		const result = await handler(
			{ entityId: ISSUER, verify: false },
			{ httpClient: async () => new Response(""), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("Either --trust-mark");
		}
	});

	it("returns error when both trust-mark and subject+type provided", async () => {
		const result = await handler(
			{
				entityId: ISSUER,
				trustMark: "eyJ.test.jwt",
				subject: "https://rp.example.com",
				trustMarkType: "https://trust.example/mark/1",
				verify: false,
			},
			{ httpClient: async () => new Response(""), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("Cannot use --trust-mark together");
		}
	});

	it("returns error when only subject provided without trust-mark-type", async () => {
		const result = await handler(
			{ entityId: ISSUER, subject: "https://rp.example.com", verify: false },
			{ httpClient: async () => new Response(""), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
	});
});
