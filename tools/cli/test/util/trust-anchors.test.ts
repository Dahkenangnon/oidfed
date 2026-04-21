import { generateSigningKey, type HttpClient, signEntityStatement } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../../src/config.js";
import {
	buildTrustAnchors,
	requireAnchorIds,
	resolveOrError,
} from "../../src/util/trust-anchors.js";

const failingClient: HttpClient = async () => new Response("Not Found", { status: 404 });

describe("requireAnchorIds", () => {
	it("returns args when provided", () => {
		const result = requireAnchorIds(["https://ta.example.com"], DEFAULT_CONFIG);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value).toEqual(["https://ta.example.com"]);
		}
	});

	it("falls back to config trust anchors", () => {
		const config = {
			...DEFAULT_CONFIG,
			trust_anchors: [{ entity_id: "https://config-ta.example.com" }],
		};
		const result = requireAnchorIds([], config);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value).toEqual(["https://config-ta.example.com"]);
		}
	});

	it("returns error when no anchors available", () => {
		const result = requireAnchorIds([], DEFAULT_CONFIG);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("No trust anchors");
		}
	});
});

describe("buildTrustAnchors", () => {
	it("builds anchors from valid EC responses", async () => {
		const key = await generateSigningKey("ES256");
		const jwt = await signEntityStatement(
			{
				iss: "https://ta.example.com",
				sub: "https://ta.example.com",
				iat: 1000,
				exp: 9999999999,
				jwks: { keys: [key.publicKey] },
			},
			key.privateKey,
		);
		const client: HttpClient = async () =>
			new Response(jwt, {
				status: 200,
				headers: { "Content-Type": "application/entity-statement+jwt" },
			});

		const result = await buildTrustAnchors(["https://ta.example.com"], client);
		expect(result.ok).toBe(true);
	});

	it("returns error for invalid anchor ID", async () => {
		const result = await buildTrustAnchors(["not-a-url"], failingClient);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("Invalid trust anchor ID");
		}
	});

	it("returns error when fetch fails", async () => {
		const result = await buildTrustAnchors(["https://ta.example.com"], failingClient);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("Failed to fetch");
		}
	});

	it("returns error when EC has no jwks", async () => {
		const key = await generateSigningKey("ES256");
		const jwt = await signEntityStatement(
			{
				iss: "https://ta.example.com",
				sub: "https://ta.example.com",
				iat: 1000,
				exp: 9999999999,
			},
			key.privateKey,
		);
		const client: HttpClient = async () =>
			new Response(jwt, {
				status: 200,
				headers: { "Content-Type": "application/entity-statement+jwt" },
			});
		const result = await buildTrustAnchors(["https://ta.example.com"], client);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("missing required jwks");
		}
	});
});

describe("resolveOrError", () => {
	it("returns error when no chains found", async () => {
		const key = await generateSigningKey("ES256");
		const jwt = await signEntityStatement(
			{
				iss: "https://ta.example.com",
				sub: "https://ta.example.com",
				iat: 1000,
				exp: 9999999999,
				jwks: { keys: [key.publicKey] },
			},
			key.privateKey,
		);
		// Return TA EC for anchor fetch, 404 for everything else
		const client: HttpClient = async (url) => {
			const urlStr = typeof url === "string" ? url : url.toString();
			if (urlStr.includes("ta.example.com/.well-known/openid-federation")) {
				return new Response(jwt, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			return new Response("Not Found", { status: 404 });
		};

		const { entityId } = await import("@oidfed/core");
		const result = await resolveOrError(
			entityId("https://leaf.example.com"),
			["https://ta.example.com"],
			client,
		);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("No trust chains found");
		}
	});
});
