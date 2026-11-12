import {
	generateSigningKey,
	type HttpClient,
	JwkSigner,
	JwtTyp,
	MediaType,
	signEntityStatement,
} from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { handler } from "../../src/commands/validate.js";
import { DEFAULT_CONFIG } from "../../src/config.js";
import { JsonFormatter } from "../../src/output/json.js";
import { createLogger } from "../../src/util/logger.js";

const failingClient: HttpClient = async () => new Response("Not Found", { status: 404 });

const deps = {
	httpClient: failingClient,
	formatter: new JsonFormatter(),
	logger: createLogger({ quiet: true, verbose: false }),
	config: DEFAULT_CONFIG,
};

describe("validate handler", () => {
	it("returns error when no JWTs provided", async () => {
		const result = await handler({ jwts: [], trustAnchors: ["https://ta.example.com"] }, deps);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("At least one JWT");
		}
	});

	it("returns error when no trust anchors specified", async () => {
		const result = await handler({ jwts: ["some-jwt"], trustAnchors: [] }, deps);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("No trust anchors");
		}
	});

	it("validates a self-signed trust anchor EC", async () => {
		const key = await generateSigningKey("ES256");
		const jwt = await signEntityStatement(
			{
				iss: "https://ta.example.com",
				sub: "https://ta.example.com",
				iat: 1000,
				exp: 9999999999,
				jwks: { keys: [key.publicKey] },
			},
			new JwkSigner(key.privateKey),
		);

		const taClient: HttpClient = async () =>
			new Response(jwt, {
				status: 200,
				headers: { "content-type": "application/entity-statement+jwt" },
			});

		const result = await handler(
			{ jwts: [jwt], trustAnchors: ["https://ta.example.com"] },
			{ ...deps, httpClient: taClient },
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const parsed = JSON.parse(result.value);
			expect(typeof parsed.valid).toBe("boolean");
		}
	});

	it("auto-detects entity-id mode for HTTP URLs", async () => {
		const result = await handler({ jwts: ["https://entity.example.com"], trustAnchors: [] }, deps);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.description).toContain("No trust anchors");
		}
	});

	it("entity-id mode returns error when TA is unreachable", async () => {
		const result = await handler(
			{ jwts: ["https://leaf.example.com"], trustAnchors: ["https://ta.example.com"] },
			deps,
		);
		expect(result.ok).toBe(false);
	});

	it("entity-id mode returns error for invalid entity URL", async () => {
		// Need a TA that can be fetched so buildTrustAnchors doesn't fail first
		const key = await generateSigningKey("ES256");
		const taJwt = await signEntityStatement(
			{
				iss: "https://ta.example.com",
				sub: "https://ta.example.com",
				iat: 1000,
				exp: 9999999999,
				jwks: { keys: [key.publicKey] },
			},
			new JwkSigner(key.privateKey),
		);
		const client: HttpClient = async (input) => {
			const parsed = new URL(typeof input === "string" ? input : input.toString());
			if (parsed.hostname === "ta.example.com") {
				return new Response(taJwt, {
					status: 200,
					headers: { "content-type": "application/entity-statement+jwt" },
				});
			}
			return new Response("Not Found", { status: 404 });
		};

		const result = await handler(
			{ jwts: ["https://nonexistent.example.com"], trustAnchors: ["https://ta.example.com"] },
			{ ...deps, httpClient: client },
		);
		// Resolution will fail because leaf is unreachable
		expect(result.ok).toBe(false);
	});
	it("reports chain validity and mark outcomes in both input modes", async () => {
		const key = await generateSigningKey("ES256");
		const now = Math.floor(Date.now() / 1000);
		const id = "https://ta.example.com";
		const type = "https://marks.example/accredited";
		const mark = await signEntityStatement(
			{ iss: id, sub: id, iat: now - 600, exp: now - 300, trust_mark_type: type },
			new JwkSigner(key.privateKey),
			{ typ: JwtTyp.TrustMark },
		);
		const jwt = await signEntityStatement(
			{
				iss: id,
				sub: id,
				iat: now,
				exp: now + 3600,
				jwks: { keys: [key.publicKey] },
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${id}/fetch`,
						federation_list_endpoint: `${id}/list`,
					},
				},
				trust_mark_issuers: { [type]: [id] },
				trust_marks: [{ trust_mark_type: type, trust_mark: mark }],
			},
			new JwkSigner(key.privateKey),
		);
		const httpClient: HttpClient = async () =>
			new Response(jwt, { headers: { "content-type": MediaType.EntityStatement } });
		for (const input of [id, jwt]) {
			const result = await handler({ jwts: [input], trustAnchors: [id] }, { ...deps, httpClient });
			expect(result.ok).toBe(true);
			if (!result.ok) continue;
			const output = JSON.parse(result.value);
			expect(output.valid).toBe(true);
			expect(output.pass).toBeUndefined();
			expect(output.trust_marks).toEqual([
				expect.objectContaining({ referenceIndex: 0, trustMarkType: type, status: "invalid" }),
			]);
		}
	});
});
