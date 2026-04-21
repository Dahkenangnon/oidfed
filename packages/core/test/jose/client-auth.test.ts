import { describe, expect, it } from "vitest";
import { isErr, isOk } from "../../src/errors.js";
import { verifyClientAssertion } from "../../src/jose/client-auth.js";
import { generateSigningKey } from "../../src/jose/keys.js";
import { signEntityStatement } from "../../src/jose/sign.js";

const AUDIENCE = "https://authority.example.com";
const CLIENT_ID = "https://client.example.com";

async function createAssertion(
	overrides?: {
		iss?: string;
		sub?: string;
		aud?: string | string[];
		exp?: number;
		jti?: string;
		typ?: string;
		alg?: string;
	},
	keyOverride?: Awaited<ReturnType<typeof generateSigningKey>>,
) {
	const keys = keyOverride ?? (await generateSigningKey("ES256"));
	const now = Math.floor(Date.now() / 1000);
	const payload: Record<string, unknown> = {
		iss: overrides?.iss ?? CLIENT_ID,
		sub: overrides?.sub ?? CLIENT_ID,
		aud: overrides?.aud ?? AUDIENCE,
		iat: now,
		exp: overrides?.exp ?? now + 60,
	};
	if (overrides?.jti !== undefined) {
		payload.jti = overrides.jti;
	}
	const jwt = await signEntityStatement(payload, keys.privateKey, {
		kid: keys.privateKey.kid,
		typ: overrides?.typ ?? "JWT",
		alg: overrides?.alg,
	});
	return { jwt, keys };
}

describe("verifyClientAssertion", () => {
	it("verifies a valid assertion and returns correct fields", async () => {
		const { jwt, keys } = await createAssertion();
		const result = await verifyClientAssertion(jwt, { keys: [keys.publicKey] }, AUDIENCE);
		expect(isOk(result)).toBe(true);
		if (!isOk(result)) return;
		expect(result.value.clientId).toBe(CLIENT_ID);
		expect(result.value.expiresAt).toBeGreaterThan(0);
		expect(result.value.issuedAt).toBeGreaterThan(0);
		expect(result.value.jti).toBeUndefined();
	});

	it("returns jti when present", async () => {
		const { jwt, keys } = await createAssertion({ jti: "unique-id-123" });
		const result = await verifyClientAssertion(jwt, { keys: [keys.publicKey] }, AUDIENCE);
		expect(isOk(result)).toBe(true);
		if (!isOk(result)) return;
		expect(result.value.jti).toBe("unique-id-123");
	});

	it("rejects expired assertion", async () => {
		const now = Math.floor(Date.now() / 1000);
		const { jwt, keys } = await createAssertion({ exp: now - 120 });
		const result = await verifyClientAssertion(jwt, { keys: [keys.publicKey] }, AUDIENCE, {
			clockSkewSeconds: 0,
		});
		expect(isErr(result)).toBe(true);
		if (!isErr(result)) return;
		expect(result.error.code).toBe("ERR_SIGNATURE_INVALID");
	});

	it("rejects when iss !== sub", async () => {
		const { jwt, keys } = await createAssertion({
			iss: CLIENT_ID,
			sub: "https://other.example.com",
		});
		const result = await verifyClientAssertion(jwt, { keys: [keys.publicKey] }, AUDIENCE);
		expect(isErr(result)).toBe(true);
		if (!isErr(result)) return;
		expect(result.error.code).toBe("invalid_client");
		expect(result.error.description).toContain("iss");
	});

	it("rejects wrong aud (single string)", async () => {
		const { jwt, keys } = await createAssertion({ aud: "https://wrong.example.com" });
		const result = await verifyClientAssertion(jwt, { keys: [keys.publicKey] }, AUDIENCE);
		expect(isErr(result)).toBe(true);
		if (!isErr(result)) return;
		expect(result.error.code).toBe("invalid_client");
		expect(result.error.description).toContain("audience");
	});

	it("rejects aud array with extra values", async () => {
		const { jwt, keys } = await createAssertion({
			aud: [AUDIENCE, "https://extra.example.com"],
		});
		const result = await verifyClientAssertion(jwt, { keys: [keys.publicKey] }, AUDIENCE);
		expect(isErr(result)).toBe(true);
		if (!isErr(result)) return;
		expect(result.error.code).toBe("invalid_client");
		expect(result.error.description).toContain("audience");
	});

	it("rejects aud array with wrong single value", async () => {
		const { jwt, keys } = await createAssertion({
			aud: ["https://wrong.example.com"],
		});
		const result = await verifyClientAssertion(jwt, { keys: [keys.publicKey] }, AUDIENCE);
		expect(isErr(result)).toBe(true);
		if (!isErr(result)) return;
		expect(result.error.code).toBe("invalid_client");
	});

	it("rejects alg: 'none'", async () => {
		// Create a valid JWT then tamper the header to claim alg: "none"
		const keys = await generateSigningKey("ES256");
		const { jwt } = await createAssertion({}, keys);
		const parts = jwt.split(".");
		const fakeHeader = btoa(JSON.stringify({ alg: "none", typ: "JWT", kid: keys.privateKey.kid }))
			.replace(/\+/g, "-")
			.replace(/\//g, "_")
			.replace(/=+$/, "");
		const tamperedJwt = `${fakeHeader}.${parts[1]}.${parts[2]}`;

		const result = await verifyClientAssertion(tamperedJwt, { keys: [keys.publicKey] }, AUDIENCE);
		expect(isErr(result)).toBe(true);
		if (!isErr(result)) return;
		expect(result.error.code).toBe("ERR_UNSUPPORTED_ALG");
	});

	it("rejects unsupported algorithm", async () => {
		// Create a valid JWT then tamper the header to claim HS256
		const keys = await generateSigningKey("ES256");
		const { jwt } = await createAssertion({}, keys);
		const parts = jwt.split(".");
		const fakeHeader = btoa(JSON.stringify({ alg: "HS256", typ: "JWT", kid: keys.privateKey.kid }))
			.replace(/\+/g, "-")
			.replace(/\//g, "_")
			.replace(/=+$/, "");
		const tamperedJwt = `${fakeHeader}.${parts[1]}.${parts[2]}`;

		const result = await verifyClientAssertion(tamperedJwt, { keys: [keys.publicKey] }, AUDIENCE);
		expect(isErr(result)).toBe(true);
		if (!isErr(result)) return;
		expect(result.error.code).toBe("ERR_UNSUPPORTED_ALG");
	});

	it("rejects when no matching key in JWKS", async () => {
		const { jwt } = await createAssertion();
		const otherKeys = await generateSigningKey("ES256");
		const result = await verifyClientAssertion(jwt, { keys: [otherKeys.publicKey] }, AUDIENCE);
		expect(isErr(result)).toBe(true);
		if (!isErr(result)) return;
		// Could be no matching key or signature verification failed
		expect(result.error.code).toBe("ERR_SIGNATURE_INVALID");
	});

	it("rejects malformed JWT", async () => {
		const result = await verifyClientAssertion("not.a.valid-jwt", { keys: [] }, AUDIENCE);
		expect(isErr(result)).toBe(true);
		if (!isErr(result)) return;
		expect(result.error.code).toBe("ERR_SIGNATURE_INVALID");
	});

	it("accepts assertion with absent typ header", async () => {
		const keys = await generateSigningKey("ES256");
		const now = Math.floor(Date.now() / 1000);
		const payload: Record<string, unknown> = {
			iss: CLIENT_ID,
			sub: CLIENT_ID,
			aud: AUDIENCE,
			iat: now,
			exp: now + 60,
		};
		// signEntityStatement with typ undefined — jose will not include typ in header
		// Use jose directly to create a JWT without typ
		const jose = await import("jose");
		const cryptoKey = await jose.importJWK(keys.privateKey as unknown as jose.JWK, "ES256");
		const jwt = await new jose.SignJWT(payload as jose.JWTPayload)
			.setProtectedHeader({ alg: "ES256", kid: keys.privateKey.kid })
			.sign(cryptoKey as Parameters<jose.SignJWT["sign"]>[0]);

		const result = await verifyClientAssertion(jwt, { keys: [keys.publicKey] }, AUDIENCE);
		expect(isOk(result)).toBe(true);
		if (!isOk(result)) return;
		expect(result.value.clientId).toBe(CLIENT_ID);
	});

	it("accepts aud as single-element array matching expected audience", async () => {
		const { jwt, keys } = await createAssertion({ aud: [AUDIENCE] });
		const result = await verifyClientAssertion(jwt, { keys: [keys.publicKey] }, AUDIENCE);
		expect(isOk(result)).toBe(true);
		if (!isOk(result)) return;
		expect(result.value.clientId).toBe(CLIENT_ID);
	});
});
