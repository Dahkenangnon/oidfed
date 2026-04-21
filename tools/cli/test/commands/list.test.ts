import type { HttpClient } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/list.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const logger = createLogger({ quiet: true, verbose: false });

function mockClient(body: string, ok = true): HttpClient {
	return async () => new Response(body, { status: ok ? 200 : 404 });
}

describe("list handler", () => {
	it("lists subordinates", async () => {
		const entities = ["https://leaf1.example.com", "https://leaf2.example.com"];
		const result = await handler(
			{ entityId: "https://ta.example.com" },
			{ httpClient: mockClient(JSON.stringify(entities)), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(JSON.parse(result.value)).toEqual(entities);
		}
	});

	it("returns error for invalid entity ID", async () => {
		const result = await handler(
			{ entityId: "not-a-url" },
			{ httpClient: mockClient("[]"), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
	});

	it("returns error on HTTP failure", async () => {
		const result = await handler(
			{ entityId: "https://ta.example.com" },
			{ httpClient: mockClient("", false), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
	});

	it("appends is_leaf=false when trustMarked is true", async () => {
		let capturedUrl = "";
		const client: HttpClient = async (url) => {
			capturedUrl = url;
			return new Response(JSON.stringify([]), { status: 200 });
		};
		await handler(
			{ entityId: "https://ta.example.com", trustMarked: true },
			{ httpClient: client, formatter: new JsonFormatter(), logger },
		);
		expect(capturedUrl).toContain("is_leaf=false");
	});

	it("appends trust_mark_id param", async () => {
		let capturedUrl = "";
		const client: HttpClient = async (url) => {
			capturedUrl = url;
			return new Response(JSON.stringify([]), { status: 200 });
		};
		await handler(
			{ entityId: "https://ta.example.com", trustMarkId: "https://trust.example/mark/1" },
			{ httpClient: client, formatter: new JsonFormatter(), logger },
		);
		expect(capturedUrl).toContain("trust_mark_id=");
		expect(capturedUrl).toContain(encodeURIComponent("https://trust.example/mark/1"));
	});

	it("appends intermediate=true param", async () => {
		let capturedUrl = "";
		const client: HttpClient = async (url) => {
			capturedUrl = url;
			return new Response(JSON.stringify([]), { status: 200 });
		};
		await handler(
			{ entityId: "https://ta.example.com", intermediate: true },
			{ httpClient: client, formatter: new JsonFormatter(), logger },
		);
		expect(capturedUrl).toContain("intermediate=true");
	});

	it("combines multiple filter params", async () => {
		let capturedUrl = "";
		const client: HttpClient = async (url) => {
			capturedUrl = url;
			return new Response(JSON.stringify([]), { status: 200 });
		};
		await handler(
			{
				entityId: "https://ta.example.com",
				entityType: "openid_relying_party",
				trustMarked: true,
				intermediate: true,
			},
			{ httpClient: client, formatter: new JsonFormatter(), logger },
		);
		const url = new URL(capturedUrl);
		expect(url.searchParams.get("entity_type")).toBe("openid_relying_party");
		expect(url.searchParams.get("is_leaf")).toBe("false");
		expect(url.searchParams.get("intermediate")).toBe("true");
	});
});
