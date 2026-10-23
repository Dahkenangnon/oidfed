import { generateSigningKey, type HttpClient, JwkSigner, signEntityStatement } from "@oidfed/core";
import { Command } from "commander";
import { describe, expect, it, vi } from "vitest";
import { handler, register } from "../../src/commands/list-extended.js";
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
		new JwkSigner(key.privateKey),
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
	it("parses fractional, negative and exponent NumericDates through the command", async () => {
		const ec = await buildAuthorityEc();
		const body = {
			immediate_subordinate_entities: [
				{ id: "https://leaf.example.com", registered: -0.5, updated: 1500.5 },
			],
		};
		const output = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
		try {
			for (const [after, before] of [
				["-0.5", "1.5005e3"],
				["1500.5", "1500.5"],
				["001500", "1e-7"],
			] as const) {
				const captures: { extendedUrl?: string } = {};
				const program = new Command().exitOverride();
				register(program, {
					httpClient: routedClient(ec, JSON.stringify(body), captures),
					formatter: new JsonFormatter(),
					logger,
				});
				await program.parseAsync(
					["list-extended", AUTHORITY, "--updated-after", after, "--updated-before", before],
					{ from: "user" },
				);
				if (!captures.extendedUrl) throw new Error("Expected an extended listing request");
				const params = new URL(captures.extendedUrl).searchParams;
				expect(Number(params.get("updated_after"))).toBe(Number(after));
				expect(Number(params.get("updated_before"))).toBe(Number(before));
				expect(output).toHaveBeenLastCalledWith(`${JSON.stringify(body, null, 2)}\n`);
			}
		} finally {
			output.mockRestore();
		}
	});
	it("rejects malformed or non-finite NumericDate options before fetching", async () => {
		const httpClient = vi.fn<HttpClient>();
		for (const option of ["--updated-after", "--updated-before"]) {
			for (const raw of [
				"",
				" ",
				" 1",
				"1 ",
				"1\n",
				"1\r\n",
				"0x10",
				"1.5junk",
				"NaN",
				"Infinity",
				"-Infinity",
				"1e309",
			]) {
				const program = new Command().exitOverride();
				register(program, { httpClient, formatter: new JsonFormatter(), logger });
				await expect(
					program.parseAsync(["list-extended", AUTHORITY, `${option}=${raw}`], { from: "user" }),
				).rejects.toThrow("expected finite NumericDate");
			}
		}
		expect(httpClient).not.toHaveBeenCalled();
	});
	it("parses repeated mark types, empty claims and opaque cursors through the command", async () => {
		const captures: { extendedUrl?: string } = {};
		const types = ["https://marks.example/alpha", "https://marks.example/beta"] as const;
		const response = {
			immediate_subordinate_entities: [{ id: "https://leaf.example.com" }],
			next: "next +/=",
		};
		const program = new Command().exitOverride();
		register(program, {
			httpClient: routedClient(await buildAuthorityEc(), JSON.stringify(response), captures),
			formatter: new JsonFormatter(),
			logger,
		});
		const output = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
		try {
			await program.parseAsync(
				[
					"list-extended",
					AUTHORITY,
					"--from",
					"opaque +/=cursor",
					"--claims",
					"",
					"--trust-mark-type",
					types[0],
					"--trust-mark-type",
					types[1],
				],
				{ from: "user" },
			);
			if (!captures.extendedUrl) throw new Error("Expected an extended listing request");
			const url = new URL(captures.extendedUrl);
			expect(url.searchParams.get("from")).toBe("opaque +/=cursor");
			expect(url.searchParams.has("claims")).toBe(true);
			expect(url.searchParams.get("claims")).toBe("");
			expect(url.searchParams.getAll("trust_mark_type")).toEqual(types);
			expect(output).toHaveBeenCalledWith(`${JSON.stringify(response, null, 2)}\n`);
		} finally {
			output.mockRestore();
		}
	});

	it("distinguishes omitted, empty and selected claims", async () => {
		for (const claims of [undefined, [], ["metadata"], ["subordinate_statement"]]) {
			const captures: { extendedUrl?: string } = {};
			const result = await handler(
				{ entityId: AUTHORITY, ...(claims === undefined ? {} : { claims }) },
				{
					httpClient: routedClient(
						await buildAuthorityEc(),
						JSON.stringify({ immediate_subordinate_entities: [] }),
						captures,
					),
					formatter: new JsonFormatter(),
					logger,
				},
			);
			expect(result.ok).toBe(true);
			if (!captures.extendedUrl) throw new Error("Expected an extended listing request");
			const params = new URL(captures.extendedUrl).searchParams;
			expect(params.has("claims")).toBe(claims !== undefined);
			expect(params.get("claims")).toBe(claims === undefined ? null : claims.join(","));
		}
	});
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

	it("passes from, limit, audit_timestamps and claims through to the URL", async () => {
		const ec = await buildAuthorityEc();
		const captures: { extendedUrl?: string } = {};
		await handler(
			{
				entityId: AUTHORITY,
				from: "opaque +/=cursor",
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
		expect(url.searchParams.get("from")).toBe("opaque +/=cursor");
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

	it("surfaces 404 page_not_found from the server as a federation error", async () => {
		const ec = await buildAuthorityEc();
		const captures: { extendedUrl?: string } = {};
		const result = await handler(
			{ entityId: AUTHORITY, from: "https://missing.example.com" },
			{
				httpClient: routedClient(
					ec,
					JSON.stringify({
						error: "page_not_found",
						error_description: "Unknown continuation cursor",
					}),
					captures,
					{ status: 404, contentType: "application/json" },
				),
				formatter: new JsonFormatter(),
				logger,
			},
		);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.code).toBe("page_not_found");
			expect(result.error.description).toBe("Unknown continuation cursor");
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
