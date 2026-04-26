import { generateSigningKey, type HttpClient, signEntityStatement } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/list.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const logger = createLogger({ quiet: true, verbose: false });

const AUTHORITY = "https://ta.example.com";
const LIST_ENDPOINT = "https://ta.example.com/federation/list";

async function buildAuthorityEc() {
	const key = await generateSigningKey("ES256");
	return signEntityStatement(
		{
			iss: AUTHORITY,
			sub: AUTHORITY,
			iat: 1000,
			exp: 9_999_999_999,
			jwks: { keys: [key.publicKey] },
			metadata: {
				federation_entity: {
					federation_list_endpoint: LIST_ENDPOINT,
				},
			},
		},
		key.privateKey,
	);
}

function routedClient(
	authorityEc: string,
	listResponse: string,
	captures: { listUrl?: string },
): HttpClient {
	return async (input) => {
		const url = typeof input === "string" ? input : input.toString();
		if (url.includes("/.well-known/openid-federation")) {
			return new Response(authorityEc, {
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

describe("list handler", () => {
	it("discovers federation_list_endpoint from EC and returns entities", async () => {
		const ec = await buildAuthorityEc();
		const entities = ["https://leaf1.example.com", "https://leaf2.example.com"];
		const captures: { listUrl?: string } = {};
		const result = await handler(
			{ entityId: AUTHORITY },
			{
				httpClient: routedClient(ec, JSON.stringify(entities), captures),
				formatter: new JsonFormatter(),
				logger,
			},
		);
		expect(result.ok).toBe(true);
		expect(captures.listUrl?.startsWith(LIST_ENDPOINT)).toBe(true);
		if (result.ok) {
			expect(JSON.parse(result.value)).toEqual(entities);
		}
	});

	it("returns error for invalid entity ID", async () => {
		const result = await handler(
			{ entityId: "not-a-url" },
			{ httpClient: async () => new Response("[]"), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
	});

	it("sends trust_marked=true (NOT is_leaf=false) when --trust-marked is set", async () => {
		const ec = await buildAuthorityEc();
		const captures: { listUrl?: string } = {};
		await handler(
			{ entityId: AUTHORITY, trustMarked: true },
			{
				httpClient: routedClient(ec, "[]", captures),
				formatter: new JsonFormatter(),
				logger,
			},
		);
		const url = new URL(captures.listUrl as string);
		expect(url.searchParams.get("trust_marked")).toBe("true");
		expect(url.searchParams.has("is_leaf")).toBe(false);
	});

	it("sends trust_mark_type (NOT trust_mark_id) when --trust-mark-type is set", async () => {
		const ec = await buildAuthorityEc();
		const captures: { listUrl?: string } = {};
		const tmType = "https://trust.example/mark/1";
		await handler(
			{ entityId: AUTHORITY, trustMarkType: tmType },
			{
				httpClient: routedClient(ec, "[]", captures),
				formatter: new JsonFormatter(),
				logger,
			},
		);
		const url = new URL(captures.listUrl as string);
		expect(url.searchParams.get("trust_mark_type")).toBe(tmType);
		expect(url.searchParams.has("trust_mark_id")).toBe(false);
	});

	it("sends entity_type and intermediate filter params", async () => {
		const ec = await buildAuthorityEc();
		const captures: { listUrl?: string } = {};
		await handler(
			{ entityId: AUTHORITY, entityType: "openid_relying_party", intermediate: true },
			{
				httpClient: routedClient(ec, "[]", captures),
				formatter: new JsonFormatter(),
				logger,
			},
		);
		const url = new URL(captures.listUrl as string);
		expect(url.searchParams.get("entity_type")).toBe("openid_relying_party");
		expect(url.searchParams.get("intermediate")).toBe("true");
	});

	it("combines multiple filter params correctly", async () => {
		const ec = await buildAuthorityEc();
		const captures: { listUrl?: string } = {};
		await handler(
			{
				entityId: AUTHORITY,
				entityType: "openid_relying_party",
				trustMarked: true,
				intermediate: true,
			},
			{
				httpClient: routedClient(ec, "[]", captures),
				formatter: new JsonFormatter(),
				logger,
			},
		);
		const url = new URL(captures.listUrl as string);
		expect(url.searchParams.get("entity_type")).toBe("openid_relying_party");
		expect(url.searchParams.get("trust_marked")).toBe("true");
		expect(url.searchParams.get("intermediate")).toBe("true");
	});

	it("uses --list-endpoint override and skips discovery", async () => {
		const captures: { listUrl?: string; ecCalled: boolean } = { ecCalled: false };
		const override = "https://other.example.com/list";
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
			{ entityId: AUTHORITY, listEndpoint: override },
			{ httpClient: client, formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(true);
		expect(captures.ecCalled).toBe(false);
		expect(captures.listUrl?.startsWith(override)).toBe(true);
	});

	it("returns error when EC has no federation_list_endpoint", async () => {
		const key = await generateSigningKey("ES256");
		const ecWithoutEndpoint = await signEntityStatement(
			{
				iss: AUTHORITY,
				sub: AUTHORITY,
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
			{ entityId: AUTHORITY },
			{ httpClient: client, formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("federation_list_endpoint");
		}
	});
});
