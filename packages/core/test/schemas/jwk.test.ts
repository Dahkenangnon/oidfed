import { describe, expect, it } from "vitest";
import { JWKSchema, JWKSetSchema } from "../../src/schemas/jwk.js";

describe("JWKSchema", () => {
	it("accepts a minimal EC key", () => {
		const result = JWKSchema.safeParse({
			kty: "EC",
			crv: "P-256",
			x: "abc",
			y: "def",
		});
		expect(result.success).toBe(true);
	});

	it("accepts a minimal RSA key", () => {
		const result = JWKSchema.safeParse({
			kty: "RSA",
			n: "modulus",
			e: "AQAB",
		});
		expect(result.success).toBe(true);
	});

	it("accepts OKP key type", () => {
		const result = JWKSchema.safeParse({
			kty: "OKP",
			crv: "Ed25519",
			x: "abc",
		});
		expect(result.success).toBe(true);
	});

	it("rejects invalid kty", () => {
		const result = JWKSchema.safeParse({ kty: "oct" });
		expect(result.success).toBe(false);
	});

	it("rejects missing kty", () => {
		const result = JWKSchema.safeParse({ kid: "test" });
		expect(result.success).toBe(false);
	});

	it("preserves unknown fields (looseObject)", () => {
		const result = JWKSchema.safeParse({
			kty: "EC",
			crv: "P-256",
			x: "abc",
			y: "def",
			customField: "custom",
		});
		expect(result.success).toBe(true);
		if (result.success) {
			expect((result.data as Record<string, unknown>).customField).toBe("custom");
		}
	});

	it("accepts valid use values", () => {
		expect(JWKSchema.safeParse({ kty: "EC", use: "sig" }).success).toBe(true);
		expect(JWKSchema.safeParse({ kty: "EC", use: "enc" }).success).toBe(true);
	});

	it("rejects invalid use values", () => {
		expect(JWKSchema.safeParse({ kty: "EC", use: "other" }).success).toBe(false);
	});

	it("rejects EC key with private key field 'd'", () => {
		const result = JWKSchema.safeParse({
			kty: "EC",
			crv: "P-256",
			x: "abc",
			y: "def",
			d: "private-value",
		});
		expect(result.success).toBe(false);
	});

	it("rejects RSA key with private key fields", () => {
		const result = JWKSchema.safeParse({
			kty: "RSA",
			n: "modulus",
			e: "AQAB",
			d: "private-d",
			p: "private-p",
			q: "private-q",
			dp: "private-dp",
			dq: "private-dq",
			qi: "private-qi",
		});
		expect(result.success).toBe(false);
	});

	it("accepts public EC key without private fields", () => {
		const result = JWKSchema.safeParse({
			kty: "EC",
			crv: "P-256",
			x: "abc",
			y: "def",
		});
		expect(result.success).toBe(true);
	});
});

describe("JWKSetSchema", () => {
	it("accepts a set with one key", () => {
		const result = JWKSetSchema.safeParse({
			keys: [{ kty: "EC", kid: "k1", crv: "P-256", x: "abc", y: "def" }],
		});
		expect(result.success).toBe(true);
	});

	it("accepts a set with multiple keys with unique kids", () => {
		const result = JWKSetSchema.safeParse({
			keys: [
				{ kty: "EC", kid: "k1", crv: "P-256", x: "abc", y: "def" },
				{ kty: "RSA", kid: "k2", n: "modulus", e: "AQAB" },
			],
		});
		expect(result.success).toBe(true);
	});

	it("rejects an empty keys array", () => {
		const result = JWKSetSchema.safeParse({ keys: [] });
		expect(result.success).toBe(false);
	});

	it("rejects missing keys", () => {
		const result = JWKSetSchema.safeParse({});
		expect(result.success).toBe(false);
	});

	it("rejects keys without kid", () => {
		const result = JWKSetSchema.safeParse({
			keys: [{ kty: "EC", crv: "P-256", x: "abc", y: "def" }],
		});
		expect(result.success).toBe(false);
	});

	it("rejects duplicate kids", () => {
		const result = JWKSetSchema.safeParse({
			keys: [
				{ kty: "EC", kid: "same", crv: "P-256", x: "a", y: "b" },
				{ kty: "EC", kid: "same", crv: "P-256", x: "c", y: "d" },
			],
		});
		expect(result.success).toBe(false);
	});
});
