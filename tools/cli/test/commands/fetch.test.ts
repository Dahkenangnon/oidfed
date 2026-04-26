import { generateSigningKey, type HttpClient, signEntityStatement } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/fetch.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const logger = createLogger({ quiet: true, verbose: false });

const ISSUER = "https://ta.example.com";
const SUBJECT = "https://leaf.example.com";
const FETCH_ENDPOINT = "https://ta.example.com/federation/fetch";

async function buildIssuerEcAndSs() {
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
					federation_fetch_endpoint: FETCH_ENDPOINT,
				},
			},
		},
		key.privateKey,
	);
	const subordinateStatement = await signEntityStatement(
		{
			iss: ISSUER,
			sub: SUBJECT,
			iat: 1000,
			exp: 9_999_999_999,
			jwks: { keys: [key.publicKey] },
		},
		key.privateKey,
	);
	return { issuerEc, subordinateStatement };
}

function routedClient(
	issuerEc: string,
	subordinateStatement: string,
	captures: { fetchUrl?: string },
): HttpClient {
	return async (input) => {
		const url = typeof input === "string" ? input : input.toString();
		if (url.includes("/.well-known/openid-federation")) {
			return new Response(issuerEc, {
				status: 200,
				headers: { "Content-Type": "application/entity-statement+jwt" },
			});
		}
		captures.fetchUrl = url;
		return new Response(subordinateStatement, {
			status: 200,
			headers: { "Content-Type": "application/entity-statement+jwt" },
		});
	};
}

describe("fetch handler", () => {
	it("discovers federation_fetch_endpoint from EC and fetches subordinate statement", async () => {
		const { issuerEc, subordinateStatement } = await buildIssuerEcAndSs();
		const captures: { fetchUrl?: string } = {};
		const result = await handler(
			{ issuer: ISSUER, subject: SUBJECT, decode: false },
			{
				httpClient: routedClient(issuerEc, subordinateStatement, captures),
				formatter: new JsonFormatter(),
				logger,
			},
		);
		expect(result.ok).toBe(true);
		expect(captures.fetchUrl).toBeDefined();
		expect(captures.fetchUrl?.startsWith(FETCH_ENDPOINT)).toBe(true);
		expect(captures.fetchUrl).toContain(`sub=${encodeURIComponent(SUBJECT)}`);
	});

	it("decodes subordinate statement when --decode is set", async () => {
		const { issuerEc, subordinateStatement } = await buildIssuerEcAndSs();
		const result = await handler(
			{ issuer: ISSUER, subject: SUBJECT, decode: true },
			{
				httpClient: routedClient(issuerEc, subordinateStatement, {}),
				formatter: new JsonFormatter(),
				logger,
			},
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(parsed.iss).toBe(ISSUER);
			expect(parsed.sub).toBe(SUBJECT);
		}
	});

	it("uses --fetch-endpoint override and skips discovery", async () => {
		const { subordinateStatement } = await buildIssuerEcAndSs();
		const captures: { fetchUrl?: string; ecCalled: boolean } = { ecCalled: false };
		const client: HttpClient = async (input) => {
			const url = typeof input === "string" ? input : input.toString();
			if (url.includes("/.well-known/openid-federation")) {
				captures.ecCalled = true;
				return new Response("", { status: 500 });
			}
			captures.fetchUrl = url;
			return new Response(subordinateStatement, {
				status: 200,
				headers: { "Content-Type": "application/entity-statement+jwt" },
			});
		};
		const override = "https://other.example.com/fetch";
		const result = await handler(
			{ issuer: ISSUER, subject: SUBJECT, decode: false, fetchEndpoint: override },
			{ httpClient: client, formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(true);
		expect(captures.ecCalled).toBe(false);
		expect(captures.fetchUrl?.startsWith(override)).toBe(true);
	});

	it("returns error for invalid issuer", async () => {
		const result = await handler(
			{ issuer: "not-a-url", subject: SUBJECT, decode: false },
			{ httpClient: async () => new Response(""), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
	});

	it("returns error when EC has no federation_fetch_endpoint", async () => {
		const key = await generateSigningKey("ES256");
		const ecWithoutEndpoint = await signEntityStatement(
			{
				iss: ISSUER,
				sub: ISSUER,
				iat: 1000,
				exp: 9_999_999_999,
				jwks: { keys: [key.publicKey] },
				metadata: { federation_entity: {} },
			},
			key.privateKey,
		);
		const client: HttpClient = async () =>
			new Response(ecWithoutEndpoint, {
				status: 200,
				headers: { "Content-Type": "application/entity-statement+jwt" },
			});
		const result = await handler(
			{ issuer: ISSUER, subject: SUBJECT, decode: false },
			{ httpClient: client, formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("federation_fetch_endpoint");
		}
	});
});
