import { describe, expect, it } from "vitest";
import { JwtTyp } from "../../src/constants.js";
import { isErr, isOk } from "../../src/errors.js";
import { generateSigningKey } from "../../src/jose/keys.js";
import { signEntityStatement } from "../../src/jose/sign.js";
import {
	assertTypHeader,
	decodeEntityStatement,
	verifyEntityStatement,
} from "../../src/jose/verify.js";

const now = Math.floor(Date.now() / 1000);

describe("sign and verify round-trip", () => {
	it("signs and verifies an entity statement with ES256", async () => {
		const { publicKey, privateKey } = await generateSigningKey("ES256");
		const payload = {
			iss: "https://example.com",
			sub: "https://example.com",
			iat: now,
			exp: now + 3600,
		};

		const jwt = await signEntityStatement(payload, privateKey);
		expect(typeof jwt).toBe("string");
		expect(jwt.split(".")).toHaveLength(3);

		const result = await verifyEntityStatement(jwt, {
			keys: [publicKey],
		});
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.payload.iss).toBe("https://example.com");
			expect(result.value.payload.sub).toBe("https://example.com");
			expect(result.value.header.typ).toBe(JwtTyp.EntityStatement);
		}
	});

	it("signs and verifies with PS256", async () => {
		const { publicKey, privateKey } = await generateSigningKey("PS256");
		const payload = {
			iss: "https://rsa.example.com",
			sub: "https://rsa.example.com",
			iat: now,
			exp: now + 3600,
		};

		const jwt = await signEntityStatement(payload, privateKey, {
			alg: "PS256",
		});

		const result = await verifyEntityStatement(jwt, {
			keys: [publicKey],
		});
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.header.alg).toBe("PS256");
		}
	});

	it("fails verification with wrong key", async () => {
		const keys1 = await generateSigningKey("ES256");
		const keys2 = await generateSigningKey("ES256");

		const jwt = await signEntityStatement(
			{
				iss: "https://example.com",
				sub: "https://example.com",
				iat: now,
				exp: now + 3600,
			},
			keys1.privateKey,
		);

		const result = await verifyEntityStatement(jwt, {
			keys: [keys2.publicKey],
		});
		expect(isErr(result)).toBe(true);
	});

	it("fails verification with wrong typ", async () => {
		const { publicKey, privateKey } = await generateSigningKey("ES256");
		const jwt = await signEntityStatement(
			{
				iss: "https://example.com",
				sub: "https://example.com",
				iat: now,
				exp: now + 3600,
			},
			privateKey,
			{ typ: "trust-mark+jwt" },
		);

		const result = await verifyEntityStatement(jwt, {
			keys: [publicKey],
		});
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("typ");
		}
	});

	it("fails verification when kid doesn't match even if algorithm does", async () => {
		const keys1 = await generateSigningKey("ES256");
		const keys2 = await generateSigningKey("ES256");

		// Sign with keys1
		const jwt = await signEntityStatement(
			{
				iss: "https://example.com",
				sub: "https://example.com",
				iat: now,
				exp: now + 3600,
			},
			keys1.privateKey,
			{ kid: keys1.publicKey.kid },
		);

		// Verify against JWKS containing keys2 (different kid, same alg)
		const result = await verifyEntityStatement(jwt, {
			keys: [keys2.publicKey],
		});
		expect(isErr(result)).toBe(true);
	});
});

describe("decodeEntityStatement", () => {
	it("decodes a JWT without verification", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		const jwt = await signEntityStatement(
			{
				iss: "https://decode.example.com",
				sub: "https://decode.example.com",
				iat: now,
				exp: now + 3600,
			},
			privateKey,
		);

		const result = decodeEntityStatement(jwt);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.payload.iss).toBe("https://decode.example.com");
			expect(result.value.header.alg).toBe("ES256");
		}
	});

	it("returns error for invalid JWT", () => {
		const result = decodeEntityStatement("not-a-jwt");
		expect(isErr(result)).toBe(true);
	});
});

describe("assertTypHeader", () => {
	it("does not throw for matching typ", () => {
		expect(() =>
			assertTypHeader({ typ: "entity-statement+jwt" }, "entity-statement+jwt"),
		).not.toThrow();
	});

	it("throws for mismatched typ", () => {
		expect(() => assertTypHeader({ typ: "trust-mark+jwt" }, "entity-statement+jwt")).toThrow(
			"Expected typ 'entity-statement+jwt'",
		);
	});

	it("throws for missing typ", () => {
		expect(() => assertTypHeader({}, "entity-statement+jwt")).toThrow();
	});
});

describe("signEntityStatement algorithm validation", () => {
	it("throws for alg: 'none'", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		await expect(
			signEntityStatement({ iss: "https://example.com", sub: "https://example.com" }, privateKey, {
				alg: "none",
			}),
		).rejects.toThrow(/Unsupported signing algorithm/);
	});

	it("throws for unsupported alg with descriptive message", async () => {
		const { privateKey } = await generateSigningKey("ES256");
		await expect(
			signEntityStatement({ iss: "https://example.com", sub: "https://example.com" }, privateKey, {
				alg: "HS256",
			}),
		).rejects.toThrow(/HS256/);
	});
});
