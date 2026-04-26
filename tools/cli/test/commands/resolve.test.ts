import { generateSigningKey, type HttpClient, signEntityStatement } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/resolve.js";
import { DEFAULT_CONFIG } from "../../src/config.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const logger = createLogger({ quiet: true, verbose: false });

const failingClient: HttpClient = async () => new Response("Not Found", { status: 404 });

describe("resolve handler", () => {
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

	it("returns error when trust anchor fetch fails", async () => {
		const result = await handler(
			{ entityId: "https://leaf.example.com", trustAnchors: ["https://ta.example.com"] },
			{ httpClient: failingClient, formatter: new JsonFormatter(), logger, config: DEFAULT_CONFIG },
		);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("Failed to fetch entity configuration");
		}
	});

	it("returns chain summary when resolution succeeds", async () => {
		const taKey = await generateSigningKey("ES256");
		const leafKey = await generateSigningKey("ES256");
		const taEc = await signEntityStatement(
			{
				iss: "https://ta.example.com",
				sub: "https://ta.example.com",
				iat: 1000,
				exp: 9_999_999_999,
				jwks: { keys: [taKey.publicKey] },
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: "https://ta.example.com/federation/fetch",
					},
				},
			},
			taKey.privateKey,
		);
		const leafEc = await signEntityStatement(
			{
				iss: "https://leaf.example.com",
				sub: "https://leaf.example.com",
				iat: 1000,
				exp: 9_999_999_999,
				jwks: { keys: [leafKey.publicKey] },
				authority_hints: ["https://ta.example.com"],
			},
			leafKey.privateKey,
		);
		const subordinate = await signEntityStatement(
			{
				iss: "https://ta.example.com",
				sub: "https://leaf.example.com",
				iat: 1000,
				exp: 9_999_999_999,
				jwks: { keys: [leafKey.publicKey] },
			},
			taKey.privateKey,
		);

		const client: HttpClient = async (input) => {
			const parsed = new URL(typeof input === "string" ? input : input.toString());
			if (
				parsed.hostname === "ta.example.com" &&
				parsed.pathname === "/.well-known/openid-federation"
			) {
				return new Response(taEc, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			if (
				parsed.hostname === "leaf.example.com" &&
				parsed.pathname === "/.well-known/openid-federation"
			) {
				return new Response(leafEc, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			if (parsed.hostname === "ta.example.com" && parsed.pathname === "/federation/fetch") {
				return new Response(subordinate, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			return new Response("Not Found", { status: 404 });
		};

		const result = await handler(
			{ entityId: "https://leaf.example.com", trustAnchors: ["https://ta.example.com"] },
			{ httpClient: client, formatter: new JsonFormatter(), logger, config: DEFAULT_CONFIG },
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(parsed.chains_found).toBe(1);
			expect(parsed.chains[0].entity_id).toBe("https://leaf.example.com");
			expect(parsed.chains[0].trust_anchor_id).toBe("https://ta.example.com");
		}
	});
});
