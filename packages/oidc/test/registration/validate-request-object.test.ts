import { entityId, generateSigningKey, type JWK, JwtTyp, signEntityStatement } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { RequestObjectTyp } from "../../src/constants.js";
import type { AutomaticRegistrationContext } from "../../src/registration/types.js";
import { validateAutomaticRegistrationRequest } from "../../src/registration/validate-request-object.js";

const RP_ID = entityId("https://rp.example.com");
const OP_ID = entityId("https://op.example.com");

const context: AutomaticRegistrationContext = { opEntityId: OP_ID };

async function buildRequestObject(
	signingKey: JWK,
	overrides?: {
		payloadOverrides?: Record<string, unknown>;
		typOverride?: string;
		extraHeaders?: Record<string, unknown>;
		removeClaims?: string[];
	},
): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	const payload: Record<string, unknown> = {
		iss: RP_ID,
		client_id: RP_ID,
		aud: OP_ID,
		jti: crypto.randomUUID(),
		iat: now,
		exp: now + 300,
		redirect_uri: "https://rp.example.com/callback",
		scope: "openid",
		response_type: "code",
		...overrides?.payloadOverrides,
	};

	for (const key of overrides?.removeClaims ?? []) {
		delete payload[key];
	}

	return signEntityStatement(payload, signingKey, {
		kid: signingKey.kid as string,
		typ: (overrides?.typOverride ?? RequestObjectTyp) as string,
		...(overrides?.extraHeaders ? { extraHeaders: overrides.extraHeaders } : {}),
	});
}

describe("validateAutomaticRegistrationRequest", () => {
	it("accepts a valid Request Object", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const jwt = await buildRequestObject(privateKey);

		const result = validateAutomaticRegistrationRequest(jwt, context);

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.rpEntityId).toBe(RP_ID);
		expect(result.value.opEntityId).toBe(OP_ID);
		expect(typeof result.value.jti).toBe("string");
		expect(typeof result.value.exp).toBe("number");
	});

	it("rejects wrong typ header", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const jwt = await buildRequestObject(privateKey, {
			typOverride: "entity-statement+jwt",
		});

		const result = validateAutomaticRegistrationRequest(jwt, context);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("typ");
	});

	it("rejects with sub present", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const jwt = await buildRequestObject(privateKey, {
			payloadOverrides: { sub: "https://rp.example.com" },
		});

		const result = validateAutomaticRegistrationRequest(jwt, context);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("sub");
	});

	it("rejects missing client_id", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const jwt = await buildRequestObject(privateKey, {
			removeClaims: ["client_id"],
		});

		const result = validateAutomaticRegistrationRequest(jwt, context);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("client_id");
	});

	it("rejects iss !== client_id", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const jwt = await buildRequestObject(privateKey, {
			payloadOverrides: { iss: "https://other.example.com" },
		});

		const result = validateAutomaticRegistrationRequest(jwt, context);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("iss");
		expect(result.error.description).toContain("client_id");
	});

	it("rejects wrong aud", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const jwt = await buildRequestObject(privateKey, {
			payloadOverrides: { aud: "https://wrong-op.example.com" },
		});

		const result = validateAutomaticRegistrationRequest(jwt, context);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("aud");
	});

	it("rejects multi-value aud", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const jwt = await buildRequestObject(privateKey, {
			payloadOverrides: { aud: [OP_ID, "https://other.example.com"] },
		});

		const result = validateAutomaticRegistrationRequest(jwt, context);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("single string");
	});

	it("rejects expired JWT", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const past = Math.floor(Date.now() / 1000) - 3600;
		const jwt = await buildRequestObject(privateKey, {
			payloadOverrides: { exp: past, iat: past - 300 },
		});

		const result = validateAutomaticRegistrationRequest(jwt, context);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("expired");
	});

	it("rejects missing jti", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const jwt = await buildRequestObject(privateKey, {
			removeClaims: ["jti"],
		});

		const result = validateAutomaticRegistrationRequest(jwt, context);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("jti");
	});

	it("rejects registration claim present", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const jwt = await buildRequestObject(privateKey, {
			payloadOverrides: { registration: { client_name: "Test" } },
		});

		const result = validateAutomaticRegistrationRequest(jwt, context);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("registration");
	});

	it("validates trust_chain header first entry", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const { privateKey: otherKey, publicKey: otherPub } = await generateSigningKey("ES256");

		// Create an EC for a different entity
		const wrongEc = await signEntityStatement(
			{
				iss: "https://other.example.com",
				sub: "https://other.example.com",
				iat: Math.floor(Date.now() / 1000),
				exp: Math.floor(Date.now() / 1000) + 3600,
				jwks: { keys: [otherPub] },
			},
			otherKey,
			{ typ: JwtTyp.EntityStatement },
		);

		const jwt = await buildRequestObject(privateKey, {
			extraHeaders: { trust_chain: [wrongEc] },
		});

		const result = validateAutomaticRegistrationRequest(jwt, context);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("subject's Entity Configuration");
	});

	it("accepts valid trust_chain header", async () => {
		const { privateKey, publicKey } = await generateSigningKey("ES256");

		// Create a valid EC for the RP
		const rpEc = await signEntityStatement(
			{
				iss: RP_ID,
				sub: RP_ID,
				iat: Math.floor(Date.now() / 1000),
				exp: Math.floor(Date.now() / 1000) + 3600,
				jwks: { keys: [publicKey] },
			},
			privateKey,
			{ typ: JwtTyp.EntityStatement },
		);

		const jwt = await buildRequestObject(privateKey, {
			extraHeaders: { trust_chain: [rpEc] },
		});

		const result = validateAutomaticRegistrationRequest(jwt, context);

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.trustChainHeader).toHaveLength(1);
	});
});
