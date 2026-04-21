import { describe, expect, it } from "vitest";
import {
	TrustMarkDelegationPayloadSchema,
	TrustMarkOwnerSchema,
	TrustMarkPayloadSchema,
	TrustMarkRefSchema,
} from "../../src/schemas/trust-mark.js";

describe("TrustMarkRefSchema", () => {
	it("accepts valid trust mark ref", () => {
		const result = TrustMarkRefSchema.safeParse({
			trust_mark_type: "https://example.com/tm/type1",
			trust_mark: "eyJhbGciOiJFUzI1NiJ9...",
		});
		expect(result.success).toBe(true);
	});

	it("rejects missing trust_mark field", () => {
		const result = TrustMarkRefSchema.safeParse({
			trust_mark_type: "https://example.com/tm/type1",
		});
		expect(result.success).toBe(false);
	});

	it("rejects missing trust_mark_type", () => {
		const result = TrustMarkRefSchema.safeParse({
			trust_mark: "eyJhbGciOiJFUzI1NiJ9...",
		});
		expect(result.success).toBe(false);
	});
});

describe("TrustMarkOwnerSchema", () => {
	it("accepts valid trust mark owner with jwks", () => {
		const result = TrustMarkOwnerSchema.safeParse({
			sub: "https://tm-owner.example.com",
			jwks: { keys: [{ kty: "EC", kid: "key-1", crv: "P-256", x: "abc", y: "def" }] },
		});
		expect(result.success).toBe(true);
	});

	it("rejects missing sub", () => {
		const result = TrustMarkOwnerSchema.safeParse({
			jwks: { keys: [{ kty: "EC", kid: "key-1", crv: "P-256", x: "abc", y: "def" }] },
		});
		expect(result.success).toBe(false);
	});
});

describe("TrustMarkPayloadSchema", () => {
	const validPayload = {
		iss: "https://issuer.example.com",
		sub: "https://subject.example.com",
		trust_mark_type: "https://example.com/tm/type1",
		iat: 1700000000,
	};

	it("accepts valid payload with all required fields", () => {
		const result = TrustMarkPayloadSchema.safeParse(validPayload);
		expect(result.success).toBe(true);
	});

	it("accepts payload with optional fields", () => {
		const result = TrustMarkPayloadSchema.safeParse({
			...validPayload,
			exp: 1700100000,
			logo_uri: "https://example.com/logo.png",
			ref: "https://example.com/policy",
			delegation: "eyJhbGciOiJFUzI1NiJ9...",
		});
		expect(result.success).toBe(true);
	});

	it("rejects non-HTTPS iss", () => {
		const result = TrustMarkPayloadSchema.safeParse({
			...validPayload,
			iss: "http://issuer.example.com",
		});
		expect(result.success).toBe(false);
	});

	it("rejects missing iat", () => {
		const { iat: _, ...noIat } = validPayload;
		const result = TrustMarkPayloadSchema.safeParse(noIat);
		expect(result.success).toBe(false);
	});
});

describe("TrustMarkDelegationPayloadSchema", () => {
	const validDelegation = {
		iss: "https://owner.example.com",
		sub: "https://delegatee.example.com",
		trust_mark_type: "https://example.com/tm/type1",
		iat: 1700000000,
	};

	it("accepts valid delegation payload", () => {
		const result = TrustMarkDelegationPayloadSchema.safeParse(validDelegation);
		expect(result.success).toBe(true);
	});

	it("rejects missing required fields", () => {
		const { iss: _, ...noIss } = validDelegation;
		const result = TrustMarkDelegationPayloadSchema.safeParse(noIss);
		expect(result.success).toBe(false);
	});

	it("accepts optional exp field", () => {
		const result = TrustMarkDelegationPayloadSchema.safeParse({
			...validDelegation,
			exp: 1700100000,
		});
		expect(result.success).toBe(true);
	});
});
