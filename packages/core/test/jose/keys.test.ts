import { describe, expect, it } from "vitest";
import {
	generateSigningKey,
	isValidAlgorithm,
	JWK_PUBLIC_FIELDS,
	selectVerificationKey,
	stripPrivateFields,
	timingSafeEqual,
} from "../../src/jose/keys.js";
import type { JWK, JWKSet } from "../../src/schemas/jwk.js";

describe("generateSigningKey", () => {
	it("generates an ES256 key pair by default", async () => {
		const { publicKey, privateKey } = await generateSigningKey();
		expect(publicKey.kty).toBe("EC");
		expect(publicKey.kid).toBeDefined();
		expect(publicKey.alg).toBe("ES256");
		expect(publicKey.use).toBe("sig");
		expect(privateKey.kid).toBe(publicKey.kid);
		expect(privateKey.alg).toBe("ES256");
		// Private key should have d parameter
		expect(privateKey.d).toBeDefined();
		// Public key should NOT have d parameter
		expect(publicKey.d).toBeUndefined();
	});

	it("generates a PS256 key pair", async () => {
		const { publicKey, privateKey } = await generateSigningKey("PS256");
		expect(publicKey.kty).toBe("RSA");
		expect(publicKey.alg).toBe("PS256");
		expect(privateKey.kty).toBe("RSA");
	});

	it("generates unique kids for different keys", async () => {
		const key1 = await generateSigningKey();
		const key2 = await generateSigningKey();
		expect(key1.publicKey.kid).not.toBe(key2.publicKey.kid);
	});
});

describe("selectVerificationKey", () => {
	const ecKey = {
		kty: "EC" as const,
		kid: "ec-key-1",
		alg: "ES256",
		use: "sig" as const,
		crv: "P-256",
		x: "abc",
		y: "def",
	};

	const rsaKey = {
		kty: "RSA" as const,
		kid: "rsa-key-1",
		alg: "PS256",
		use: "sig" as const,
		n: "modulus",
		e: "AQAB",
	};

	const jwks: JWKSet = { keys: [ecKey, rsaKey] };

	it("selects key by kid", () => {
		const key = selectVerificationKey({ kid: "ec-key-1" }, jwks);
		expect(key).toEqual(ecKey);
	});

	it("selects RSA key by kid", () => {
		const key = selectVerificationKey({ kid: "rsa-key-1" }, jwks);
		expect(key).toEqual(rsaKey);
	});

	it("falls back to algorithm-based selection", () => {
		const key = selectVerificationKey({ alg: "ES256" }, { keys: [ecKey] });
		expect(key).toEqual(ecKey);
	});

	it("returns undefined when no key matches", () => {
		const key = selectVerificationKey({ kid: "nonexistent" }, jwks);
		expect(key).toBeUndefined();
	});

	it("returns key when kid matches and alg matches", () => {
		const key = selectVerificationKey({ kid: "ec-key-1", alg: "ES256" }, jwks);
		expect(key).toEqual(ecKey);
	});

	it("returns undefined when kid matches but key.alg differs from header.alg", () => {
		const key = selectVerificationKey({ kid: "ec-key-1", alg: "RS256" }, jwks);
		expect(key).toBeUndefined();
	});

	it("returns key when kid matches and key has no alg restriction", () => {
		const keyNoAlg = {
			kty: "EC" as const,
			kid: "no-alg-key",
			use: "sig" as const,
			crv: "P-256",
			x: "abc",
			y: "def",
		};
		const jwksNoAlg: JWKSet = { keys: [keyNoAlg] };
		const key = selectVerificationKey({ kid: "no-alg-key", alg: "ES256" }, jwksNoAlg);
		expect(key).toEqual(keyNoAlg);
	});

	it("rejects key with use: 'enc' even when kid matches", () => {
		const encKey = {
			kty: "EC" as const,
			kid: "enc-key",
			use: "enc" as const,
			crv: "P-256",
			x: "abc",
			y: "def",
		};
		const jwksEnc: JWKSet = { keys: [encKey as unknown as JWK] };
		const key = selectVerificationKey({ kid: "enc-key" }, jwksEnc);
		expect(key).toBeUndefined();
	});
});

describe("isValidAlgorithm", () => {
	it("returns true for supported algorithms", () => {
		expect(isValidAlgorithm("ES256")).toBe(true);
		expect(isValidAlgorithm("PS256")).toBe(true);
		expect(isValidAlgorithm("RS256")).toBe(true);
	});

	it('rejects "none"', () => {
		expect(isValidAlgorithm("none")).toBe(false);
	});

	it("rejects empty/undefined/null", () => {
		expect(isValidAlgorithm("")).toBe(false);
		expect(isValidAlgorithm(undefined)).toBe(false);
		expect(isValidAlgorithm(null)).toBe(false);
	});

	it("rejects unsupported algorithms", () => {
		expect(isValidAlgorithm("HS256")).toBe(false);
		expect(isValidAlgorithm("EdDSA")).toBe(false);
	});
});

describe("timingSafeEqual", () => {
	it("returns true for equal strings", () => {
		expect(timingSafeEqual("hello", "hello")).toBe(true);
	});

	it("returns false for different strings same length", () => {
		expect(timingSafeEqual("hello", "world")).toBe(false);
	});

	it("returns false for different length strings", () => {
		expect(timingSafeEqual("short", "longer")).toBe(false);
	});

	it("returns true for empty strings", () => {
		expect(timingSafeEqual("", "")).toBe(true);
	});

	it("returns true for equal HTTPS URLs", () => {
		expect(timingSafeEqual("https://example.com", "https://example.com")).toBe(true);
	});

	it("returns false for different HTTPS URLs", () => {
		expect(timingSafeEqual("https://example.com", "https://other.com")).toBe(false);
	});
});

describe("stripPrivateFields", () => {
	it("strips EC private key field (d) and preserves public fields", () => {
		const ecPrivate = {
			kty: "EC",
			crv: "P-256",
			x: "x-coord",
			y: "y-coord",
			d: "secret-d",
			kid: "ec-1",
			alg: "ES256",
			use: "sig",
		} as unknown as JWK;

		const pub = stripPrivateFields(ecPrivate);
		expect(pub).toEqual({
			kty: "EC",
			crv: "P-256",
			x: "x-coord",
			y: "y-coord",
			kid: "ec-1",
			alg: "ES256",
			use: "sig",
		});
		expect((pub as Record<string, unknown>).d).toBeUndefined();
	});

	it("strips all RSA private key fields (d, p, q, dp, dq, qi)", () => {
		const rsaPrivate = {
			kty: "RSA",
			n: "modulus",
			e: "AQAB",
			d: "private-exp",
			p: "prime1",
			q: "prime2",
			dp: "exp1",
			dq: "exp2",
			qi: "coeff",
			kid: "rsa-1",
			alg: "PS256",
			use: "sig",
		} as unknown as JWK;

		const pub = stripPrivateFields(rsaPrivate);
		expect(pub).toEqual({
			kty: "RSA",
			n: "modulus",
			e: "AQAB",
			kid: "rsa-1",
			alg: "PS256",
			use: "sig",
		});
		const raw = pub as Record<string, unknown>;
		expect(raw.d).toBeUndefined();
		expect(raw.p).toBeUndefined();
		expect(raw.q).toBeUndefined();
		expect(raw.dp).toBeUndefined();
		expect(raw.dq).toBeUndefined();
		expect(raw.qi).toBeUndefined();
	});

	it("strips RSA multi-prime 'oth' field", () => {
		const rsaMultiPrime = {
			kty: "RSA",
			n: "modulus",
			e: "AQAB",
			d: "private-exp",
			p: "prime1",
			q: "prime2",
			dp: "exp1",
			dq: "exp2",
			qi: "coeff",
			oth: [{ r: "prime3", d: "exp3", t: "coeff3" }],
			kid: "rsa-multi",
		} as unknown as JWK;

		const pub = stripPrivateFields(rsaMultiPrime);
		expect((pub as Record<string, unknown>).oth).toBeUndefined();
		expect((pub as Record<string, unknown>).d).toBeUndefined();
		expect(pub.n).toBe("modulus");
		expect(pub.e).toBe("AQAB");
	});

	it("strips OKP private key field (d) and preserves crv, x", () => {
		const okpPrivate = {
			kty: "OKP",
			crv: "Ed25519",
			x: "x-value",
			d: "secret-d",
			kid: "okp-1",
		} as unknown as JWK;

		const pub = stripPrivateFields(okpPrivate);
		expect(pub).toEqual({
			kty: "OKP",
			crv: "Ed25519",
			x: "x-value",
			kid: "okp-1",
		});
		expect((pub as Record<string, unknown>).d).toBeUndefined();
	});

	it("throws TypeError for symmetric keys (kty 'oct')", () => {
		const symmetricKey = { kty: "oct", k: "secret-value", kid: "sym-1" } as unknown as JWK;
		expect(() => stripPrivateFields(symmetricKey)).toThrow(TypeError);
		expect(() => stripPrivateFields(symmetricKey)).toThrow(/symmetric key/i);
	});

	it("excludes unknown/arbitrary fields not in the public allowlist", () => {
		const keyWithExtra = {
			kty: "EC",
			crv: "P-256",
			x: "x-coord",
			y: "y-coord",
			kid: "ec-extra",
			custom_field: "should-be-dropped",
			internal_secret: "should-be-dropped",
		} as unknown as JWK;

		const pub = stripPrivateFields(keyWithExtra);
		const raw = pub as Record<string, unknown>;
		expect(raw.custom_field).toBeUndefined();
		expect(raw.internal_secret).toBeUndefined();
		expect(raw.kty).toBe("EC");
		expect(raw.kid).toBe("ec-extra");
	});

	it("preserves all common JWK fields", () => {
		const fullKey = {
			kty: "EC",
			use: "sig",
			key_ops: ["verify"],
			alg: "ES256",
			kid: "full-key",
			x5u: "https://example.com/cert",
			x5c: ["base64cert"],
			x5t: "thumbprint",
			"x5t#S256": "thumbprint256",
			crv: "P-256",
			x: "x-coord",
			y: "y-coord",
			d: "secret",
		} as unknown as JWK;

		const pub = stripPrivateFields(fullKey);
		const raw = pub as Record<string, unknown>;
		expect(raw.kty).toBe("EC");
		expect(raw.use).toBe("sig");
		expect(raw.key_ops).toEqual(["verify"]);
		expect(raw.alg).toBe("ES256");
		expect(raw.kid).toBe("full-key");
		expect(raw.x5u).toBe("https://example.com/cert");
		expect(raw.x5c).toEqual(["base64cert"]);
		expect(raw.x5t).toBe("thumbprint");
		expect(raw["x5t#S256"]).toBe("thumbprint256");
		expect(raw.crv).toBe("P-256");
		expect(raw.x).toBe("x-coord");
		expect(raw.y).toBe("y-coord");
		expect(raw.d).toBeUndefined();
	});

	it("handles minimal key with only kty", () => {
		const minKey = { kty: "EC" } as unknown as JWK;
		const pub = stripPrivateFields(minKey);
		expect(pub).toEqual({ kty: "EC" });
	});

	it("works with a real generated key pair", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		expect((privateKey as Record<string, unknown>).d).toBeDefined();

		const pub = stripPrivateFields(privateKey);
		expect((pub as Record<string, unknown>).d).toBeUndefined();
		expect(pub.kty).toBe("EC");
		expect(pub.kid).toBe(privateKey.kid);
		expect(pub.alg).toBe("ES256");
	});

	it("JWK_PUBLIC_FIELDS contains exactly the 14 spec-defined fields", () => {
		expect(JWK_PUBLIC_FIELDS.size).toBe(14);
		for (const field of [
			"kty",
			"use",
			"key_ops",
			"alg",
			"kid",
			"x5u",
			"x5c",
			"x5t",
			"x5t#S256",
			"crv",
			"x",
			"y",
			"n",
			"e",
		]) {
			expect(JWK_PUBLIC_FIELDS.has(field)).toBe(true);
		}
	});
});
