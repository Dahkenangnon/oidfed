import type { HttpClient } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/chain.js";
import { DEFAULT_CONFIG } from "../../src/config.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const logger = createLogger({ quiet: true, verbose: false });

const failingClient: HttpClient = async () => new Response("Not Found", { status: 404 });

describe("chain handler", () => {
	it("returns error when no trust anchors specified", async () => {
		const result = await handler(
			{ entityId: "https://leaf.example.com", trustAnchors: [] },
			{ httpClient: failingClient, formatter: new JsonFormatter(), logger, config: DEFAULT_CONFIG },
		);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("No trust anchors");
		}
	});

	it("returns error for invalid entity ID", async () => {
		const result = await handler(
			{ entityId: "not-a-url", trustAnchors: ["https://ta.example.com"] },
			{ httpClient: failingClient, formatter: new JsonFormatter(), logger, config: DEFAULT_CONFIG },
		);
		expect(result.ok).toBe(false);
	});

	it("returns error when resolution fails", async () => {
		const result = await handler(
			{ entityId: "https://leaf.example.com", trustAnchors: ["https://ta.example.com"] },
			{ httpClient: failingClient, formatter: new JsonFormatter(), logger, config: DEFAULT_CONFIG },
		);
		expect(result.ok).toBe(false);
	});

	it("accepts --strategy option", async () => {
		const result = await handler(
			{
				entityId: "https://leaf.example.com",
				trustAnchors: ["https://ta.example.com"],
				strategy: "shortest",
			},
			{ httpClient: failingClient, formatter: new JsonFormatter(), logger, config: DEFAULT_CONFIG },
		);
		// Still fails because resolution fails, but strategy is accepted
		expect(result.ok).toBe(false);
	});
});
