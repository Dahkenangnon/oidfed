import { describe, expect, it } from "vitest";
import { JwtTyp } from "../../src/constants.js";
import { isErr, isOk } from "../../src/errors.js";
import { generateSigningKey } from "../../src/jose/keys.js";
import { signEntityStatement } from "../../src/jose/sign.js";
import { decodeEntityStatement } from "../../src/jose/verify.js";
import type { JWK, JWKSet } from "../../src/schemas/jwk.js";
import { signTrustMarkDelegation, validateTrustMark } from "../../src/trust-marks/index.js";

const now = Math.floor(Date.now() / 1000);

async function createTrustMarkJwt(
	payload: Record<string, unknown>,
	privateKey: JWK,
	typ = JwtTyp.TrustMark,
) {
	return signEntityStatement(payload, privateKey, { typ });
}

describe("validateTrustMark", () => {
	it("validates a well-formed trust mark", async () => {
		const issuerKeys = await generateSigningKey("ES256");
		const trustMarkPayload = {
			iss: "https://issuer.example.com",
			sub: "https://subject.example.com",
			trust_mark_type: "https://example.com/trust-mark/certified",
			iat: now,
		};
		const jwt = await createTrustMarkJwt(trustMarkPayload, issuerKeys.privateKey);

		const result = await validateTrustMark(
			jwt,
			{ "https://example.com/trust-mark/certified": ["https://issuer.example.com"] },
			{ keys: [issuerKeys.publicKey] },
		);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.trustMarkType).toBe("https://example.com/trust-mark/certified");
			expect(result.value.issuer).toBe("https://issuer.example.com");
			expect(result.value.subject).toBe("https://subject.example.com");
			expect(result.value.issuedAt).toBe(now);
		}
	});

	it("rejects trust mark with wrong typ", async () => {
		const issuerKeys = await generateSigningKey("ES256");
		const jwt = await createTrustMarkJwt(
			{
				iss: "https://issuer.example.com",
				sub: "https://subject.example.com",
				trust_mark_type: "https://example.com/tm",
				iat: now,
			},
			issuerKeys.privateKey,
			JwtTyp.EntityStatement, // wrong typ
		);

		const result = await validateTrustMark(
			jwt,
			{ "https://example.com/tm": ["https://issuer.example.com"] },
			{ keys: [issuerKeys.publicKey] },
		);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.code).toBe("ERR_TRUST_MARK_INVALID");
		}
	});

	it("rejects trust mark from unauthorized issuer", async () => {
		const issuerKeys = await generateSigningKey("ES256");
		const jwt = await createTrustMarkJwt(
			{
				iss: "https://unauthorized.example.com",
				sub: "https://subject.example.com",
				trust_mark_type: "https://example.com/tm",
				iat: now,
			},
			issuerKeys.privateKey,
		);

		const result = await validateTrustMark(
			jwt,
			{ "https://example.com/tm": ["https://issuer.example.com"] },
			{ keys: [issuerKeys.publicKey] },
		);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.code).toBe("ERR_TRUST_MARK_INVALID");
		}
	});

	it("rejects expired trust mark", async () => {
		const issuerKeys = await generateSigningKey("ES256");
		const jwt = await createTrustMarkJwt(
			{
				iss: "https://issuer.example.com",
				sub: "https://subject.example.com",
				trust_mark_type: "https://example.com/tm",
				iat: now - 7200,
				exp: now - 3600, // expired
			},
			issuerKeys.privateKey,
		);

		const result = await validateTrustMark(
			jwt,
			{ "https://example.com/tm": ["https://issuer.example.com"] },
			{ keys: [issuerKeys.publicKey] },
		);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.code).toBe("ERR_TRUST_MARK_INVALID");
		}
	});

	it("rejects trust mark with missing required claims", async () => {
		const issuerKeys = await generateSigningKey("ES256");
		// Missing trust_mark_type
		const jwt = await createTrustMarkJwt(
			{
				iss: "https://issuer.example.com",
				sub: "https://subject.example.com",
				iat: now,
			},
			issuerKeys.privateKey,
		);

		const result = await validateTrustMark(jwt, {}, { keys: [issuerKeys.publicKey] });
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.code).toBe("ERR_TRUST_MARK_INVALID");
		}
	});

	it("accepts trust mark with exp in the future", async () => {
		const issuerKeys = await generateSigningKey("ES256");
		const jwt = await createTrustMarkJwt(
			{
				iss: "https://issuer.example.com",
				sub: "https://subject.example.com",
				trust_mark_type: "https://example.com/tm",
				iat: now,
				exp: now + 3600,
			},
			issuerKeys.privateKey,
		);

		const result = await validateTrustMark(
			jwt,
			{ "https://example.com/tm": ["https://issuer.example.com"] },
			{ keys: [issuerKeys.publicKey] },
		);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.expiresAt).toBe(now + 3600);
		}
	});

	it("rejects trust mark with iat in the future (beyond clock skew)", async () => {
		const issuerKeys = await generateSigningKey("ES256");
		const jwt = await createTrustMarkJwt(
			{
				iss: "https://issuer.example.com",
				sub: "https://subject.example.com",
				trust_mark_type: "https://example.com/tm",
				iat: now + 3600, // far in the future
				exp: now + 7200,
			},
			issuerKeys.privateKey,
		);

		const result = await validateTrustMark(
			jwt,
			{ "https://example.com/tm": ["https://issuer.example.com"] },
			{ keys: [issuerKeys.publicKey] },
		);
		expect(isErr(result)).toBe(true);
	});

	it("rejects trust mark with signature verified against wrong JWKS", async () => {
		const issuerKeys = await generateSigningKey("ES256");
		const otherKeys = await generateSigningKey("ES256");

		const jwt = await createTrustMarkJwt(
			{
				iss: "https://issuer.example.com",
				sub: "https://subject.example.com",
				trust_mark_type: "https://example.com/tm",
				iat: now,
			},
			issuerKeys.privateKey,
		);

		// Pass wrong JWKS — should fail signature verification
		const result = await validateTrustMark(
			jwt,
			{ "https://example.com/tm": ["https://issuer.example.com"] },
			{ keys: [otherKeys.publicKey] }, // wrong keys
		);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("Signature verification failed");
		}
	});

	it("rejects delegation where iss doesn't match owner sub", async () => {
		const ownerKeys = await generateSigningKey("ES256");
		const issuerKeys = await generateSigningKey("ES256");

		// Delegation with wrong iss (not matching owner.sub)
		const delegationJwt = await signEntityStatement(
			{
				iss: "https://wrong-owner.example.com", // mismatch
				sub: "https://issuer.example.com",
				trust_mark_type: "https://example.com/tm",
				iat: now,
				exp: now + 86400,
			},
			ownerKeys.privateKey,
			{ typ: JwtTyp.TrustMarkDelegation },
		);

		const jwt = await createTrustMarkJwt(
			{
				iss: "https://issuer.example.com",
				sub: "https://subject.example.com",
				trust_mark_type: "https://example.com/tm",
				iat: now,
				delegation: delegationJwt,
			},
			issuerKeys.privateKey,
		);

		const result = await validateTrustMark(
			jwt,
			{ "https://example.com/tm": ["https://issuer.example.com"] },
			{ keys: [issuerKeys.publicKey] },
			{
				trustMarkOwners: {
					"https://example.com/tm": {
						sub: "https://owner.example.com",
						jwks: { keys: [ownerKeys.publicKey] },
					},
				},
			},
		);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("does not match trust_mark_owners sub");
		}
	});

	it("rejects delegation with iat in the future", async () => {
		const ownerKeys = await generateSigningKey("ES256");
		const issuerKeys = await generateSigningKey("ES256");

		const delegationJwt = await signEntityStatement(
			{
				iss: "https://owner.example.com",
				sub: "https://issuer.example.com",
				trust_mark_type: "https://example.com/tm",
				iat: now + 7200, // far future
				exp: now + 86400,
			},
			ownerKeys.privateKey,
			{ typ: JwtTyp.TrustMarkDelegation },
		);

		const jwt = await createTrustMarkJwt(
			{
				iss: "https://issuer.example.com",
				sub: "https://subject.example.com",
				trust_mark_type: "https://example.com/tm",
				iat: now,
				delegation: delegationJwt,
			},
			issuerKeys.privateKey,
		);

		const result = await validateTrustMark(
			jwt,
			{ "https://example.com/tm": ["https://issuer.example.com"] },
			{ keys: [issuerKeys.publicKey] },
			{
				trustMarkOwners: {
					"https://example.com/tm": {
						sub: "https://owner.example.com",
						jwks: { keys: [ownerKeys.publicKey] },
					},
				},
			},
		);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("Delegation iat is in the future");
		}
	});

	it("validates trust mark with delegation", async () => {
		// Trust mark owner's keys (in TA's trust_mark_owners)
		const ownerKeys = await generateSigningKey("ES256");
		// Trust mark issuer's keys
		const issuerKeys = await generateSigningKey("ES256");

		// Create delegation JWT: owner delegates to issuer
		const delegationPayload = {
			iss: "https://owner.example.com",
			sub: "https://issuer.example.com",
			trust_mark_type: "https://example.com/tm",
			iat: now,
			exp: now + 86400,
		};
		const delegationJwt = await signEntityStatement(delegationPayload, ownerKeys.privateKey, {
			typ: JwtTyp.TrustMarkDelegation,
		});

		// Create trust mark JWT with delegation
		const trustMarkPayload = {
			iss: "https://issuer.example.com",
			sub: "https://subject.example.com",
			trust_mark_type: "https://example.com/tm",
			iat: now,
			delegation: delegationJwt,
		};
		const jwt = await createTrustMarkJwt(trustMarkPayload, issuerKeys.privateKey);

		// TA's entity configuration has trust_mark_owners
		const taJwks: JWKSet = {
			keys: [issuerKeys.publicKey],
		};

		const result = await validateTrustMark(
			jwt,
			{ "https://example.com/tm": ["https://issuer.example.com"] },
			taJwks,
			{
				// Provide trust_mark_owners for delegation validation
				trustMarkOwners: {
					"https://example.com/tm": {
						sub: "https://owner.example.com",
						jwks: { keys: [ownerKeys.publicKey] },
					},
				},
			},
		);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.delegation).toBeDefined();
			expect(result.value.delegation?.issuer).toBe("https://owner.example.com");
			expect(result.value.delegation?.subject).toBe("https://issuer.example.com");
		}
	});

	// Trust Mark JWT must include kid header
	it("rejects trust mark without kid header", async () => {
		const issuerKeys = await generateSigningKey("ES256");
		// Sign without kid by explicitly setting kid to undefined
		const jwt = await signEntityStatement(
			{
				iss: "https://issuer.example.com",
				sub: "https://subject.example.com",
				trust_mark_type: "https://example.com/tm",
				iat: now,
			},
			{ ...issuerKeys.privateKey, kid: undefined } as JWK,
			{ typ: JwtTyp.TrustMark, kid: undefined },
		);

		const result = await validateTrustMark(
			jwt,
			{ "https://example.com/tm": ["https://issuer.example.com"] },
			{ keys: [issuerKeys.publicKey] },
		);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("kid");
		}
	});

	// sub must match expectedSubject
	it("rejects trust mark where sub does not match expectedSubject", async () => {
		const issuerKeys = await generateSigningKey("ES256");
		const jwt = await createTrustMarkJwt(
			{
				iss: "https://issuer.example.com",
				sub: "https://wrong-subject.example.com",
				trust_mark_type: "https://example.com/tm",
				iat: now,
			},
			issuerKeys.privateKey,
		);

		const result = await validateTrustMark(
			jwt,
			{ "https://example.com/tm": ["https://issuer.example.com"] },
			{ keys: [issuerKeys.publicKey] },
			{ expectedSubject: "https://correct-subject.example.com" },
		);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("does not match expected entity");
		}
	});

	// Fix V: sub matching expectedSubject should pass
	it("accepts trust mark where sub matches expectedSubject", async () => {
		const issuerKeys = await generateSigningKey("ES256");
		const jwt = await createTrustMarkJwt(
			{
				iss: "https://issuer.example.com",
				sub: "https://subject.example.com",
				trust_mark_type: "https://example.com/tm",
				iat: now,
			},
			issuerKeys.privateKey,
		);

		const result = await validateTrustMark(
			jwt,
			{ "https://example.com/tm": ["https://issuer.example.com"] },
			{ keys: [issuerKeys.publicKey] },
			{ expectedSubject: "https://subject.example.com" },
		);
		expect(isOk(result)).toBe(true);
	});

	// trust_mark_type in trust_mark_owners but no delegation
	it("rejects trust mark when trust_mark_type in trustMarkOwners but no delegation", async () => {
		const issuerKeys = await generateSigningKey("ES256");
		const ownerKeys = await generateSigningKey("ES256");
		const jwt = await createTrustMarkJwt(
			{
				iss: "https://issuer.example.com",
				sub: "https://subject.example.com",
				trust_mark_type: "https://example.com/tm",
				iat: now,
				// no delegation field
			},
			issuerKeys.privateKey,
		);

		const result = await validateTrustMark(
			jwt,
			{ "https://example.com/tm": ["https://issuer.example.com"] },
			{ keys: [issuerKeys.publicKey] },
			{
				trustMarkOwners: {
					"https://example.com/tm": {
						sub: "https://owner.example.com",
						jwks: { keys: [ownerKeys.publicKey] },
					},
				},
			},
		);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("requires delegation");
		}
	});

	// Delegation JWT must include kid header
	it("rejects delegation without kid header", async () => {
		const ownerKeys = await generateSigningKey("ES256");
		const issuerKeys = await generateSigningKey("ES256");

		// Create delegation without kid
		const delegationJwt = await signEntityStatement(
			{
				iss: "https://owner.example.com",
				sub: "https://issuer.example.com",
				trust_mark_type: "https://example.com/tm",
				iat: now,
				exp: now + 86400,
			},
			{ ...ownerKeys.privateKey, kid: undefined } as JWK,
			{ typ: JwtTyp.TrustMarkDelegation, kid: undefined },
		);

		const jwt = await createTrustMarkJwt(
			{
				iss: "https://issuer.example.com",
				sub: "https://subject.example.com",
				trust_mark_type: "https://example.com/tm",
				iat: now,
				delegation: delegationJwt,
			},
			issuerKeys.privateKey,
		);

		const result = await validateTrustMark(
			jwt,
			{ "https://example.com/tm": ["https://issuer.example.com"] },
			{ keys: [issuerKeys.publicKey] },
			{
				trustMarkOwners: {
					"https://example.com/tm": {
						sub: "https://owner.example.com",
						jwks: { keys: [ownerKeys.publicKey] },
					},
				},
			},
		);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toContain("kid");
		}
	});

	it("allows any issuer when trust_mark_issuers has empty array", async () => {
		const issuerKeys = await generateSigningKey("ES256");
		const jwt = await createTrustMarkJwt(
			{
				iss: "https://anyone.example.com",
				sub: "https://subject.example.com",
				trust_mark_type: "https://example.com/tm",
				iat: now,
			},
			issuerKeys.privateKey,
		);

		const result = await validateTrustMark(
			jwt,
			{ "https://example.com/tm": [] }, // empty array = anyone may issue
			{ keys: [issuerKeys.publicKey] },
		);
		expect(isOk(result)).toBe(true);
	});

	it("rejects trust mark with unrecognized type (not in trust_mark_issuers)", async () => {
		const issuerKeys = await generateSigningKey("ES256");
		const jwt = await createTrustMarkJwt(
			{
				iss: "https://issuer.example.com",
				sub: "https://subject.example.com",
				trust_mark_type: "https://example.com/unknown-type",
				iat: now,
			},
			issuerKeys.privateKey,
		);

		const result = await validateTrustMark(
			jwt,
			{ "https://example.com/tm": ["https://issuer.example.com"] },
			{ keys: [issuerKeys.publicKey] },
		);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.description).toBe("Trust mark type not recognized");
		}
	});

	it("rejects delegation with alg=none (signEntityStatement blocks it)", async () => {
		const ownerKeys = await generateSigningKey("ES256");
		await expect(
			signEntityStatement(
				{
					iss: "https://owner.example.com",
					sub: "https://issuer.example.com",
					trust_mark_type: "https://example.com/tm",
					iat: now,
					exp: now + 86400,
				},
				ownerKeys.privateKey,
				{ typ: JwtTyp.TrustMarkDelegation, alg: "none" },
			),
		).rejects.toThrow(/Unsupported signing algorithm/);
	});
});

describe("signTrustMarkDelegation", () => {
	it("creates a valid delegation JWT with correct typ header", async () => {
		const ownerKeys = await generateSigningKey("ES256");
		const delegationJwt = await signTrustMarkDelegation({
			issuer: "https://owner.example.com",
			subject: "https://issuer.example.com",
			trustMarkType: "https://example.com/tm",
			privateKey: ownerKeys.privateKey,
		});

		const decoded = decodeEntityStatement(delegationJwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		expect(decoded.value.header.typ).toBe(JwtTyp.TrustMarkDelegation);
		const payload = decoded.value.payload as Record<string, unknown>;
		expect(payload.iss).toBe("https://owner.example.com");
		expect(payload.sub).toBe("https://issuer.example.com");
		expect(payload.trust_mark_type).toBe("https://example.com/tm");
		expect(typeof payload.iat).toBe("number");
		expect(typeof payload.exp).toBe("number");
	});

	it("roundtrips through validateTrustMark when embedded in a trust mark", async () => {
		const ownerKeys = await generateSigningKey("ES256");
		const issuerKeys = await generateSigningKey("ES256");

		const delegationJwt = await signTrustMarkDelegation({
			issuer: "https://owner.example.com",
			subject: "https://issuer.example.com",
			trustMarkType: "https://example.com/tm",
			privateKey: ownerKeys.privateKey,
		});

		const jwt = await createTrustMarkJwt(
			{
				iss: "https://issuer.example.com",
				sub: "https://subject.example.com",
				trust_mark_type: "https://example.com/tm",
				iat: now,
				delegation: delegationJwt,
			},
			issuerKeys.privateKey,
		);

		const result = await validateTrustMark(
			jwt,
			{ "https://example.com/tm": ["https://issuer.example.com"] },
			{ keys: [issuerKeys.publicKey] },
			{
				trustMarkOwners: {
					"https://example.com/tm": {
						sub: "https://owner.example.com",
						jwks: { keys: [ownerKeys.publicKey] },
					},
				},
			},
		);

		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.delegation).toBeDefined();
			expect(result.value.delegation?.issuer).toBe("https://owner.example.com");
			expect(result.value.delegation?.subject).toBe("https://issuer.example.com");
			expect(result.value.delegation?.trustMarkType).toBe("https://example.com/tm");
		}
	});

	it("respects custom ttlSeconds", async () => {
		const ownerKeys = await generateSigningKey("ES256");
		const delegationJwt = await signTrustMarkDelegation({
			issuer: "https://owner.example.com",
			subject: "https://issuer.example.com",
			trustMarkType: "https://example.com/tm",
			privateKey: ownerKeys.privateKey,
			ttlSeconds: 3600,
		});

		const decoded = decodeEntityStatement(delegationJwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		expect((payload.exp as number) - (payload.iat as number)).toBe(3600);
	});
});
