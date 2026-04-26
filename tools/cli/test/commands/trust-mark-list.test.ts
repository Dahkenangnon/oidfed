import { generateSigningKey, type HttpClient, signEntityStatement } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/trust-mark-list.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const logger = createLogger({ quiet: true, verbose: false });

const ISSUER = "https://tmi.example.com";
const TML_ENDPOINT = "https://tmi.example.com/federation/trust-mark-list";
const TM_TYPE = "https://trust.example/mark/v1";

async function buildIssuerEc() {
	const key = await generateSigningKey("ES256");
	return signEntityStatement(
		{
			iss: ISSUER,
			sub: ISSUER,
			iat: 1000,
			exp: 9_999_999_999,
			jwks: { keys: [key.publicKey] },
			metadata: {
				federation_entity: {
					federation_trust_mark_list_endpoint: TML_ENDPOINT,
				},
			},
		},
		key.privateKey,
	);
}

function routedClient(
	issuerEc: string,
	listResponse: string,
	captures: { listUrl?: string },
): HttpClient {
	return async (input) => {
		const url = typeof input === "string" ? input : input.toString();
		if (url.includes("/.well-known/openid-federation")) {
			return new Response(issuerEc, {
				status: 200,
				headers: { "Content-Type": "application/entity-statement+jwt" },
			});
		}
		captures.listUrl = url;
		return new Response(listResponse, {
			status: 200,
			headers: { "Content-Type": "application/json" },
		});
	};
}

describe("trust-mark-list handler", () => {
	it("discovers federation_trust_mark_list_endpoint from EC", async () => {
		const ec = await buildIssuerEc();
		const subjects = ["https://leaf1.example.com", "https://leaf2.example.com"];
		const captures: { listUrl?: string } = {};
		const result = await handler(
			{ entityId: ISSUER, trustMarkType: TM_TYPE },
			{
				httpClient: routedClient(ec, JSON.stringify(subjects), captures),
				formatter: new JsonFormatter(),
				logger,
			},
		);
		expect(result.ok).toBe(true);
		expect(captures.listUrl?.startsWith(TML_ENDPOINT)).toBe(true);
		const url = new URL(captures.listUrl as string);
		expect(url.searchParams.get("trust_mark_type")).toBe(TM_TYPE);
	});

	it("propagates --sub query param when set", async () => {
		const ec = await buildIssuerEc();
		const captures: { listUrl?: string } = {};
		const sub = "https://leaf.example.com";
		await handler(
			{ entityId: ISSUER, trustMarkType: TM_TYPE, sub },
			{
				httpClient: routedClient(ec, "[]", captures),
				formatter: new JsonFormatter(),
				logger,
			},
		);
		const url = new URL(captures.listUrl as string);
		expect(url.searchParams.get("sub")).toBe(sub);
	});

	it("returns error when --trust-mark-type is missing", async () => {
		const result = await handler(
			{ entityId: ISSUER },
			{ httpClient: async () => new Response(""), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("trust-mark-type");
		}
	});

	it("returns error for invalid entity ID", async () => {
		const result = await handler(
			{ entityId: "not-a-url", trustMarkType: TM_TYPE },
			{ httpClient: async () => new Response(""), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
	});

	it("uses --list-endpoint override and skips discovery", async () => {
		const captures: { listUrl?: string; ecCalled: boolean } = { ecCalled: false };
		const override = "https://other.example.com/tml";
		const client: HttpClient = async (input) => {
			const url = typeof input === "string" ? input : input.toString();
			if (url.includes("/.well-known/openid-federation")) {
				captures.ecCalled = true;
				return new Response("", { status: 500 });
			}
			captures.listUrl = url;
			return new Response("[]", {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		};
		const result = await handler(
			{ entityId: ISSUER, trustMarkType: TM_TYPE, listEndpoint: override },
			{ httpClient: client, formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(true);
		expect(captures.ecCalled).toBe(false);
		expect(captures.listUrl?.startsWith(override)).toBe(true);
	});
});
