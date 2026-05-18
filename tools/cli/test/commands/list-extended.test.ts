import { generateSigningKey, type HttpClient, signEntityStatement } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/list-extended.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const logger = createLogger({ quiet: true, verbose: false });

const AUTHORITY = "https://ta.example.com";
const EXTENDED_ENDPOINT = "https://ta.example.com/federation/extended_list";

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
					federation_extended_list_endpoint: EXTENDED_ENDPOINT,
				},
			},
		},
		key.privateKey,
	);
}

function routedClient(
	authorityEc: string,
	responseBody: string,
	captures: { extendedUrl?: string },
	statusOverride?: { status: number; contentType?: string },
): HttpClient {
	return async (input) => {
		const url = typeof input === "string" ? input : input.toString();
		if (url.includes("/.well-known/openid-federation")) {
			return new Response(authorityEc, {
				status: 200,
				headers: { "Content-Type": "application/entity-statement+jwt" },
			});
		}
		captures.extendedUrl = url;
		return new Response(responseBody, {
			status: statusOverride?.status ?? 200,
			headers: {
				"Content-Type": statusOverride?.contentType ?? "application/json",
			},
		});
	};
}

describe("list-extended handler", () => {
	it("discovers federation_extended_list_endpoint from EC and prints the response body", async () => {
		const ec = await buildAuthorityEc();
		const body = {
			immediate_subordinate_entities: [
				{ id: "https://leaf1.example.com" },
				{ id: "https://leaf2.example.com" },
			],
		};
		const captures: { extendedUrl?: string } = {};
		const result = await handler(
			{ entityId: AUTHORITY },
			{
				httpClient: routedClient(ec, JSON.stringify(body), captures),
				formatter: new JsonFormatter(),
				logger,
			},
		);
		expect(result.ok).toBe(true);
		expect(captures.extendedUrl?.startsWith(EXTENDED_ENDPOINT)).toBe(true);
		if (result.ok) {
			expect(JSON.parse(result.value)).toEqual(body);
		}
	});

	it("passes from_entity_id, limit, audit_timestamps and claims through to the URL", async () => {
		const ec = await buildAuthorityEc();
		const captures: { extendedUrl?: string } = {};
		await handler(
			{
				entityId: AUTHORITY,
				from: "https://x.example.com",
				limit: 25,
				auditTimestamps: true,
				claims: ["subordinate_statement", "trust_marks"],
			},
			{
				httpClient: routedClient(
					ec,
					JSON.stringify({ immediate_subordinate_entities: [] }),
					captures,
				),
				formatter: new JsonFormatter(),
				logger,
			},
		);
		const url = new URL(captures.extendedUrl as string);
		expect(url.searchParams.get("from_entity_id")).toBe("https://x.example.com");
		expect(url.searchParams.get("limit")).toBe("25");
		expect(url.searchParams.get("audit_timestamps")).toBe("true");
		expect(url.searchParams.get("claims")).toBe("subordinate_statement,trust_marks");
	});

	it("passes updated_after / updated_before NumericDates to the URL", async () => {
		const ec = await buildAuthorityEc();
		const captures: { extendedUrl?: string } = {};
		await handler(
			{ entityId: AUTHORITY, updatedAfter: 1700000000, updatedBefore: 1700000500 },
			{
				httpClient: routedClient(
					ec,
					JSON.stringify({ immediate_subordinate_entities: [] }),
					captures,
				),
				formatter: new JsonFormatter(),
				logger,
			},
		);
		const url = new URL(captures.extendedUrl as string);
		expect(url.searchParams.get("updated_after")).toBe("1700000000");
		expect(url.searchParams.get("updated_before")).toBe("1700000500");
	});

	it("inherits base filters entity_type, intermediate, trust_marked, trust_mark_type", async () => {
		const ec = await buildAuthorityEc();
		const captures: { extendedUrl?: string } = {};
		await handler(
			{
				entityId: AUTHORITY,
				entityType: "openid_relying_party",
				intermediate: false,
				trustMarked: true,
				trustMarkType: "https://trust.example/mark/audited",
			},
			{
				httpClient: routedClient(
					ec,
					JSON.stringify({ immediate_subordinate_entities: [] }),
					captures,
				),
				formatter: new JsonFormatter(),
				logger,
			},
		);
		const url = new URL(captures.extendedUrl as string);
		expect(url.searchParams.get("entity_type")).toBe("openid_relying_party");
		expect(url.searchParams.get("intermediate")).toBe("false");
		expect(url.searchParams.get("trust_marked")).toBe("true");
		expect(url.searchParams.get("trust_mark_type")).toBe("https://trust.example/mark/audited");
	});

	it("surfaces 400 entity_id_not_found from the server as a federation error", async () => {
		const ec = await buildAuthorityEc();
		const captures: { extendedUrl?: string } = {};
		const result = await handler(
			{ entityId: AUTHORITY, from: "https://missing.example.com" },
			{
				httpClient: routedClient(
					ec,
					JSON.stringify({
						error: "entity_id_not_found",
						error_description: "no such entity",
					}),
					captures,
					{ status: 400, contentType: "application/json" },
				),
				formatter: new JsonFormatter(),
				logger,
			},
		);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.code).toBe("entity_id_not_found");
		}
	});

	it("returns error for invalid authority entity ID", async () => {
		const result = await handler(
			{ entityId: "not-a-url" },
			{
				httpClient: async () => new Response("{}"),
				formatter: new JsonFormatter(),
				logger,
			},
		);
		expect(result.ok).toBe(false);
	});

	it("uses --extended-list-endpoint override and skips discovery", async () => {
		const captures: { extendedUrl?: string } = {};
		const body = { immediate_subordinate_entities: [] };
		const result = await handler(
			{
				entityId: AUTHORITY,
				extendedListEndpoint: "https://override.example.com/x",
			},
			{
				httpClient: async (input) => {
					const url = typeof input === "string" ? input : input.toString();
					if (url.includes("/.well-known/openid-federation")) {
						throw new Error("discovery MUST NOT happen when override is set");
					}
					captures.extendedUrl = url;
					return new Response(JSON.stringify(body), {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				},
				formatter: new JsonFormatter(),
				logger,
			},
		);
		expect(result.ok).toBe(true);
		expect(captures.extendedUrl?.startsWith("https://override.example.com/x")).toBe(true);
	});
});
