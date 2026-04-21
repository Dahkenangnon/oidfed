import type { HttpClient } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/trust-mark-list.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const logger = createLogger({ quiet: true, verbose: false });

function mockClient(body: string, ok = true): HttpClient {
	return async () => new Response(body, { status: ok ? 200 : 404 });
}

describe("trust-mark-list handler", () => {
	it("lists trust marks", async () => {
		const marks = ["https://rp.example.com", "https://op.example.com"];
		const result = await handler(
			{ entityId: "https://ta.example.com" },
			{ httpClient: mockClient(JSON.stringify(marks)), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(JSON.parse(result.value)).toEqual(marks);
		}
	});

	it("sends trust_mark_type query param", async () => {
		const tmType = "https://ta.example.com/tm/certified";
		const result = await handler(
			{ entityId: "https://ta.example.com", trustMarkType: tmType },
			{
				httpClient: async (url) => {
					const parsed = new URL(url as string);
					expect(parsed.searchParams.get("trust_mark_type")).toBe(tmType);
					return new Response(JSON.stringify([]), { status: 200 });
				},
				formatter: new JsonFormatter(),
				logger,
			},
		);
		expect(result.ok).toBe(true);
	});

	it("returns error on HTTP failure", async () => {
		const result = await handler(
			{ entityId: "https://ta.example.com" },
			{ httpClient: mockClient("", false), formatter: new JsonFormatter(), logger },
		);
		expect(result.ok).toBe(false);
	});
});
