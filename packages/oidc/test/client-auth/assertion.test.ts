import { decodeEntityStatement, generateSigningKey } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { createClientAssertion } from "../../src/client-auth/assertion.js";

describe("createClientAssertion", () => {
	const clientId = "https://rp.example.com";
	const audience = "https://op.example.com";

	it("produces valid JWT with correct claims", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const jwt = await createClientAssertion(clientId, audience, privateKey);

		const decoded = decodeEntityStatement(jwt);
		expect(decoded.ok).toBe(true);
		if (!decoded.ok) return;

		const { payload, header } = decoded.value;
		expect(payload.iss).toBe(clientId);
		expect(payload.sub).toBe(clientId);
		expect(header.typ).toBe("JWT");
		expect(header.alg).toBe("ES256");
		expect(header.kid).toBe(privateKey.kid);

		const p = payload as Record<string, unknown>;
		expect(p.aud).toBe(audience);
		expect(typeof p.jti).toBe("string");
		expect(typeof p.iat).toBe("number");
		expect(typeof p.exp).toBe("number");
	});

	it("sets iss === sub === clientId", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const jwt = await createClientAssertion(clientId, audience, privateKey);

		const decoded = decodeEntityStatement(jwt);
		expect(decoded.ok).toBe(true);
		if (!decoded.ok) return;

		expect(decoded.value.payload.iss).toBe(clientId);
		expect(decoded.value.payload.sub).toBe(clientId);
	});

	it("generates unique jti across calls", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const jwt1 = await createClientAssertion(clientId, audience, privateKey);
		const jwt2 = await createClientAssertion(clientId, audience, privateKey);

		const d1 = decodeEntityStatement(jwt1);
		const d2 = decodeEntityStatement(jwt2);
		expect(d1.ok && d2.ok).toBe(true);
		if (!d1.ok || !d2.ok) return;

		const jti1 = (d1.value.payload as Record<string, unknown>).jti;
		const jti2 = (d2.value.payload as Record<string, unknown>).jti;
		expect(jti1).not.toBe(jti2);
	});

	it("respects expiresInSeconds option", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const jwt = await createClientAssertion(clientId, audience, privateKey, {
			expiresInSeconds: 120,
		});

		const decoded = decodeEntityStatement(jwt);
		expect(decoded.ok).toBe(true);
		if (!decoded.ok) return;

		const p = decoded.value.payload as Record<string, unknown>;
		const iat = p.iat as number;
		const exp = p.exp as number;
		expect(exp - iat).toBe(120);
	});

	it("defaults expiresInSeconds to 60", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const jwt = await createClientAssertion(clientId, audience, privateKey);

		const decoded = decodeEntityStatement(jwt);
		expect(decoded.ok).toBe(true);
		if (!decoded.ok) return;

		const p = decoded.value.payload as Record<string, unknown>;
		const iat = p.iat as number;
		const exp = p.exp as number;
		expect(exp - iat).toBe(60);
	});

	it("signs with the provided key", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const jwt = await createClientAssertion(clientId, audience, privateKey);

		const decoded = decodeEntityStatement(jwt);
		expect(decoded.ok).toBe(true);
		if (!decoded.ok) return;

		expect(decoded.value.header.kid).toBe(privateKey.kid);
		expect(jwt.split(".")).toHaveLength(3);
	});

	it("works with RS256 key", async () => {
		const { privateKey } = await generateSigningKey("RS256");
		const jwt = await createClientAssertion(clientId, audience, privateKey);

		const decoded = decodeEntityStatement(jwt);
		expect(decoded.ok).toBe(true);
		if (!decoded.ok) return;

		expect(decoded.value.header.alg).toBe("RS256");
		expect(decoded.value.header.typ).toBe("JWT");
		expect(decoded.value.payload.iss).toBe(clientId);
	});

	it("throws if signing key has no kid", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const keyWithoutKid = { ...privateKey, kid: undefined } as unknown as typeof privateKey;

		await expect(createClientAssertion(clientId, audience, keyWithoutKid)).rejects.toThrow("kid");
	});
});
