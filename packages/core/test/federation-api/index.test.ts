import { describe, expect, it } from "vitest";
import { JwtTyp } from "../../src/constants.js";
import {
	verifyHistoricalKeysResponse,
	verifyResolveResponse,
	verifySignedJwkSet,
	verifyTrustMarkStatusResponse,
} from "../../src/federation-api/index.js";
import { generateSigningKey, signEntityStatement } from "../../src/jose/index.js";
import type { JWKSet } from "../../src/schemas/jwk.js";

const now = Math.floor(Date.now() / 1000);

async function setupKeys() {
	const { privateKey, publicKey } = await generateSigningKey("ES256");
	const kid = "test-key-1";
	const priv = { ...privateKey, kid };
	const pub = { ...publicKey, kid };
	const jwks: JWKSet = { keys: [pub] };
	return { priv, pub, jwks, kid };
}

describe("verifyResolveResponse", () => {
	it("accepts valid resolve-response+jwt", async () => {
		const { priv, jwks, kid } = await setupKeys();
		const jwt = await signEntityStatement(
			{
				iss: "https://authority.example.com",
				sub: "https://leaf.example.com",
				iat: now,
				exp: now + 3600,
				metadata: { federation_entity: { organization_name: "Test" } },
				trust_chain: ["jwt1", "jwt2"],
			},
			priv,
			{ kid, typ: JwtTyp.ResolveResponse },
		);

		const result = await verifyResolveResponse(jwt, jwks);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.sub).toBe("https://leaf.example.com");
		}
	});

	it("rejects wrong typ header", async () => {
		const { priv, jwks, kid } = await setupKeys();
		const jwt = await signEntityStatement(
			{
				iss: "https://authority.example.com",
				sub: "https://leaf.example.com",
				iat: now,
				exp: now + 3600,
				metadata: { federation_entity: {} },
				trust_chain: ["jwt1"],
			},
			priv,
			{ kid, typ: JwtTyp.EntityStatement },
		);

		const result = await verifyResolveResponse(jwt, jwks);
		expect(result.ok).toBe(false);
	});

	it("accepts resolve response with aud claim", async () => {
		const { priv, jwks, kid } = await setupKeys();
		const jwt = await signEntityStatement(
			{
				iss: "https://authority.example.com",
				sub: "https://leaf.example.com",
				iat: now,
				exp: now + 3600,
				metadata: { federation_entity: { organization_name: "Test" } },
				trust_chain: ["jwt1", "jwt2"],
				aud: "https://client.example.com",
			},
			priv,
			{ kid, typ: JwtTyp.ResolveResponse },
		);

		const result = await verifyResolveResponse(jwt, jwks);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.aud).toBe("https://client.example.com");
		}
	});

	it("accepts resolve response with additional claims", async () => {
		const { priv, jwks, kid } = await setupKeys();
		const jwt = await signEntityStatement(
			{
				iss: "https://authority.example.com",
				sub: "https://leaf.example.com",
				iat: now,
				exp: now + 3600,
				metadata: { federation_entity: { organization_name: "Test" } },
				trust_chain: ["jwt1"],
				custom_claim: "value",
			},
			priv,
			{ kid, typ: JwtTyp.ResolveResponse },
		);

		const result = await verifyResolveResponse(jwt, jwks);
		expect(result.ok).toBe(true);
	});

	it("rejects invalid signature", async () => {
		const { priv, kid } = await setupKeys();
		const { publicKey: otherPub } = await generateSigningKey("ES256");
		const otherJwks: JWKSet = { keys: [{ ...otherPub, kid }] };

		const jwt = await signEntityStatement(
			{
				iss: "https://authority.example.com",
				sub: "https://leaf.example.com",
				iat: now,
				exp: now + 3600,
				metadata: { federation_entity: {} },
				trust_chain: ["jwt1"],
			},
			priv,
			{ kid, typ: JwtTyp.ResolveResponse },
		);

		const result = await verifyResolveResponse(jwt, otherJwks);
		expect(result.ok).toBe(false);
	});
});

describe("verifyTrustMarkStatusResponse", () => {
	it("accepts valid trust-mark-status-response+jwt", async () => {
		const { priv, jwks, kid } = await setupKeys();
		const jwt = await signEntityStatement(
			{
				iss: "https://authority.example.com",
				iat: now,
				trust_mark: "some.jwt.token",
				status: "active",
			},
			priv,
			{ kid, typ: JwtTyp.TrustMarkStatusResponse },
		);

		const result = await verifyTrustMarkStatusResponse(jwt, jwks);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.status).toBe("active");
		}
	});

	it("rejects wrong typ header", async () => {
		const { priv, jwks, kid } = await setupKeys();
		const jwt = await signEntityStatement(
			{
				iss: "https://authority.example.com",
				iat: now,
				trust_mark: "some.jwt",
				status: "active",
			},
			priv,
			{ kid, typ: JwtTyp.EntityStatement },
		);

		const result = await verifyTrustMarkStatusResponse(jwt, jwks);
		expect(result.ok).toBe(false);
	});

	it("accepts additional status values", async () => {
		const { priv, jwks, kid } = await setupKeys();
		const jwt = await signEntityStatement(
			{
				iss: "https://authority.example.com",
				iat: now,
				trust_mark: "some.jwt.token",
				status: "suspended",
			},
			priv,
			{ kid, typ: JwtTyp.TrustMarkStatusResponse },
		);

		const result = await verifyTrustMarkStatusResponse(jwt, jwks);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.status).toBe("suspended");
		}
	});

	it("accepts additional claims in trust mark status response", async () => {
		const { priv, jwks, kid } = await setupKeys();
		const jwt = await signEntityStatement(
			{
				iss: "https://authority.example.com",
				iat: now,
				trust_mark: "some.jwt.token",
				status: "active",
				custom_field: "extra",
			},
			priv,
			{ kid, typ: JwtTyp.TrustMarkStatusResponse },
		);

		const result = await verifyTrustMarkStatusResponse(jwt, jwks);
		expect(result.ok).toBe(true);
	});
});

describe("verifyHistoricalKeysResponse", () => {
	it("accepts valid jwk-set+jwt", async () => {
		const { priv, jwks, kid } = await setupKeys();
		const jwt = await signEntityStatement(
			{
				iss: "https://authority.example.com",
				iat: now,
				keys: [{ kty: "EC", kid: "old-key-1", exp: now - 3600 }],
			},
			priv,
			{ kid, typ: JwtTyp.JwkSet },
		);

		const result = await verifyHistoricalKeysResponse(jwt, jwks);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.keys).toHaveLength(1);
		}
	});

	it("rejects wrong typ header", async () => {
		const { priv, jwks, kid } = await setupKeys();
		const jwt = await signEntityStatement(
			{
				iss: "https://authority.example.com",
				iat: now,
				keys: [{ kty: "EC", kid: "k1", exp: now }],
			},
			priv,
			{ kid, typ: JwtTyp.EntityStatement },
		);

		const result = await verifyHistoricalKeysResponse(jwt, jwks);
		expect(result.ok).toBe(false);
	});

	it("rejects keys without kid", async () => {
		const { priv, jwks, kid } = await setupKeys();
		const jwt = await signEntityStatement(
			{
				iss: "https://authority.example.com",
				iat: now,
				keys: [{ kty: "EC", exp: now }],
			},
			priv,
			{ kid, typ: JwtTyp.JwkSet },
		);

		const result = await verifyHistoricalKeysResponse(jwt, jwks);
		expect(result.ok).toBe(false);
	});
});

describe("verifySignedJwkSet", () => {
	it("accepts valid jwk-set+jwt with required claims iss, sub, keys", async () => {
		const { priv, pub, jwks, kid } = await setupKeys();
		const jwt = await signEntityStatement(
			{
				iss: "https://entity.example.com",
				sub: "https://entity.example.com",
				iat: now,
				keys: [pub],
			},
			priv,
			{ kid, typ: JwtTyp.JwkSet },
		);

		const result = await verifySignedJwkSet(jwt, jwks);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.iss).toBe("https://entity.example.com");
			expect(result.value.sub).toBe("https://entity.example.com");
			expect(result.value.keys).toHaveLength(1);
		}
	});

	it("rejects wrong typ header", async () => {
		const { priv, jwks, kid } = await setupKeys();
		const { publicKey: otherPub } = await generateSigningKey("ES256");
		const jwt = await signEntityStatement(
			{
				iss: "https://entity.example.com",
				sub: "https://entity.example.com",
				iat: now,
				keys: [otherPub],
			},
			priv,
			{ kid, typ: JwtTyp.EntityStatement },
		);

		const result = await verifySignedJwkSet(jwt, jwks);
		expect(result.ok).toBe(false);
	});

	it("rejects missing keys in payload", async () => {
		const { priv, jwks, kid } = await setupKeys();
		const jwt = await signEntityStatement(
			{
				iss: "https://entity.example.com",
				sub: "https://entity.example.com",
				iat: now,
			},
			priv,
			{ kid, typ: JwtTyp.JwkSet },
		);

		const result = await verifySignedJwkSet(jwt, jwks);
		expect(result.ok).toBe(false);
	});

	it("rejects missing iss in payload", async () => {
		const { priv, pub, jwks, kid } = await setupKeys();
		const jwt = await signEntityStatement(
			{
				sub: "https://entity.example.com",
				iat: now,
				keys: [pub],
			} as Parameters<typeof signEntityStatement>[0],
			priv,
			{ kid, typ: JwtTyp.JwkSet },
		);

		const result = await verifySignedJwkSet(jwt, jwks);
		expect(result.ok).toBe(false);
	});

	it("rejects missing sub in payload", async () => {
		const { priv, pub, jwks, kid } = await setupKeys();
		const jwt = await signEntityStatement(
			{
				iss: "https://entity.example.com",
				iat: now,
				keys: [pub],
			} as Parameters<typeof signEntityStatement>[0],
			priv,
			{ kid, typ: JwtTyp.JwkSet },
		);

		const result = await verifySignedJwkSet(jwt, jwks);
		expect(result.ok).toBe(false);
	});

	it("rejects invalid signature (wrong key)", async () => {
		const { pub } = await setupKeys();
		const { privateKey: wrongPriv, publicKey: wrongPub } = await generateSigningKey("ES256");
		const wrongJwks: JWKSet = { keys: [wrongPub] };
		const jwt = await signEntityStatement(
			{
				iss: "https://entity.example.com",
				sub: "https://entity.example.com",
				iat: now,
				keys: [pub],
			},
			wrongPriv,
			{ kid: wrongPub.kid as string, typ: JwtTyp.JwkSet },
		);

		const { privateKey: signerPriv, publicKey: signerPub } = await generateSigningKey("ES256");
		const signerJwks: JWKSet = { keys: [signerPub] };
		const jwtSignedByOther = await signEntityStatement(
			{
				iss: "https://entity.example.com",
				sub: "https://entity.example.com",
				iat: now,
				keys: [pub],
			},
			signerPriv,
			{ kid: signerPub.kid as string, typ: JwtTyp.JwkSet },
		);

		const result = await verifySignedJwkSet(jwtSignedByOther, wrongJwks);
		expect(result.ok).toBe(false);
	});
});
