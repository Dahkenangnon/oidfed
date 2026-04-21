import * as jose from "jose";
import { describe, expect, it } from "vitest";
import { JwtTyp } from "../../src/constants.js";
import { generateSigningKey } from "../../src/jose/keys.js";
import { signEntityStatement } from "../../src/jose/sign.js";
import type { EntityStatementPayload } from "../../src/schemas/entity-statement.js";
import type { JWK } from "../../src/schemas/jwk.js";
import {
	calculateChainExpiration,
	chainRemainingTtl,
	describeTrustChain,
	isChainExpired,
	longestExpiry,
	preferTrustAnchor,
	shortestChain,
	validateTrustChain,
} from "../../src/trust-chain/validate.js";
import type {
	EntityId,
	ParsedEntityStatement,
	TrustAnchorSet,
	ValidatedTrustChain,
} from "../../src/types.js";

const now = Math.floor(Date.now() / 1000);

async function signEC(
	entityId: string,
	privateKey: JWK,
	publicKey: JWK,
	overrides?: Record<string, unknown>,
) {
	return signEntityStatement(
		{
			iss: entityId,
			sub: entityId,
			iat: now,
			exp: now + 3600,
			jwks: { keys: [publicKey] },
			...overrides,
		},
		privateKey,
		{ typ: JwtTyp.EntityStatement },
	);
}

async function signSS(
	issuer: string,
	subject: string,
	privateKey: JWK,
	subjectPublicKey: JWK,
	overrides?: Record<string, unknown>,
) {
	return signEntityStatement(
		{
			iss: issuer,
			sub: subject,
			iat: now,
			exp: now + 3600,
			jwks: { keys: [subjectPublicKey] },
			...overrides,
		},
		privateKey,
		{ typ: JwtTyp.EntityStatement },
	);
}

// Helper to build a simple 2-entity chain: leaf → TA
async function buildSimpleChain() {
	const taKeys = await generateSigningKey("ES256");
	const leafKeys = await generateSigningKey("ES256");

	const leafEc = await signEC("https://leaf.example.com", leafKeys.privateKey, leafKeys.publicKey, {
		authority_hints: ["https://ta.example.com"],
		metadata: {
			federation_entity: { organization_name: "Leaf Org" },
			openid_relying_party: { client_name: "Leaf RP" },
		},
	});
	const ss = await signSS(
		"https://ta.example.com",
		"https://leaf.example.com",
		taKeys.privateKey,
		leafKeys.publicKey,
	);
	const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

	const taSet: TrustAnchorSet = new Map([
		["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
	]);

	return { chain: [leafEc, ss, taEc], taSet, taKeys, leafKeys };
}

// Helper to build a 3-entity chain: leaf → intermediate → TA
async function _buildThreeEntityChain() {
	const taKeys = await generateSigningKey("ES256");
	const intKeys = await generateSigningKey("ES256");
	const leafKeys = await generateSigningKey("ES256");

	const leafEc = await signEC("https://leaf.example.com", leafKeys.privateKey, leafKeys.publicKey, {
		authority_hints: ["https://int.example.com"],
		metadata: { openid_relying_party: { client_name: "Leaf RP", scope: "openid profile email" } },
	});
	const ssIntLeaf = await signSS(
		"https://int.example.com",
		"https://leaf.example.com",
		intKeys.privateKey,
		leafKeys.publicKey,
		{
			metadata_policy: {
				openid_relying_party: {
					scope: { subset_of: ["openid", "profile"] },
				},
			},
		},
	);
	const ssTaInt = await signSS(
		"https://ta.example.com",
		"https://int.example.com",
		taKeys.privateKey,
		intKeys.publicKey,
	);
	const _intEc = await signEC("https://int.example.com", intKeys.privateKey, intKeys.publicKey, {
		authority_hints: ["https://ta.example.com"],
	});
	const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

	const taSet: TrustAnchorSet = new Map([
		["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
	]);

	// Chain order: [leafEC, SS_int→leaf, SS_ta→int, taEC]
	return { chain: [leafEc, ssIntLeaf, ssTaInt, taEc], taSet, taKeys, intKeys, leafKeys };
}

describe("validateTrustChain", () => {
	it("validates a simple 2-entity chain (leaf → TA)", async () => {
		const { chain, taSet } = await buildSimpleChain();
		const result = await validateTrustChain(chain, taSet);
		expect(result.valid).toBe(true);
		if (result.valid) {
			expect(result.chain.entityId).toBe("https://leaf.example.com");
			expect(result.chain.trustAnchorId).toBe("https://ta.example.com");
			expect(result.chain.statements).toHaveLength(3);
		}
	});

	it("rejects chain with unknown trust anchor", async () => {
		const { chain } = await buildSimpleChain();
		const emptyTaSet: TrustAnchorSet = new Map();
		const result = await validateTrustChain(chain, emptyTaSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(result.errors.some((e) => e.code === "ERR_TRUST_ANCHOR_UNKNOWN")).toBe(true);
	});

	it("rejects expired statements", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				iat: now - 7200,
				exp: now - 3600, // expired
				authority_hints: ["https://ta.example.com"],
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
			{
				iat: now - 7200,
				exp: now - 3600,
			},
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey, {
			iat: now - 7200,
			exp: now - 3600,
		});

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(result.errors.some((e) => e.checkNumber === 5)).toBe(true);
	});

	it("rejects chain with invalid leaf self-signature", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");
		const wrongKeys = await generateSigningKey("ES256");

		// Leaf EC signed with wrong key but claims different jwks
		const leafEc = await signEC(
			"https://leaf.example.com",
			wrongKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(result.errors.some((e) => e.checkNumber === 10)).toBe(true);
	});

	it("accumulates multiple errors", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		// Expired leaf + expired SS + expired TA
		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				iat: now - 7200,
				exp: now - 3600,
				authority_hints: ["https://ta.example.com"],
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
			{
				iat: now - 7200,
				exp: now - 3600,
			},
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey, {
			iat: now - 7200,
			exp: now - 3600,
		});

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(result.errors.length).toBeGreaterThan(1);
	});

	it("detects chain continuity violation (check 12)", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");
		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
			},
		);
		// SS claims to be from "other.example.com" but TA EC claims "ta.example.com"
		const ss = await signSS(
			"https://other.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		// Chain continuity: SS iss "other.example.com" !== TA EC sub "ta.example.com"
		expect(result.errors.some((e) => e.checkNumber === 12)).toBe(true);
	});

	it("validates signature at all chain positions including j=0 (check 13)", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");
		const wrongKeys = await generateSigningKey("ES256");

		// Leaf is properly self-signed, but SS contains wrong JWKS for leaf
		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
			},
		);
		// SS signed by TA (correct), but provides wrong pubkey for leaf verification
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			wrongKeys.publicKey, // wrong pubkey — leaf EC won't verify against this
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		// Signature check at j=0: leaf EC verified against SS's jwks fails
		expect(result.errors.some((e) => e.checkNumber === 13)).toBe(true);
	});

	it("applies superior metadata override from immediate superior (first SS, not last)", async () => {
		const taKeys = await generateSigningKey("ES256");
		const intKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://int.example.com"],
				metadata: {
					openid_relying_party: { client_name: "Original", scope: "openid profile email" },
				},
			},
		);
		// Immediate superior SS has metadata override + a policy to trigger application
		const ssIntLeaf = await signSS(
			"https://int.example.com",
			"https://leaf.example.com",
			intKeys.privateKey,
			leafKeys.publicKey,
			{
				metadata: {
					openid_relying_party: { client_name: "Overridden by Int" },
				},
				metadata_policy: {
					openid_relying_party: {
						scope: { subset_of: ["openid", "profile", "email"] },
					},
				},
			},
		);
		// TA SS for intermediate — also has a metadata override with different client_name
		const ssTaInt = await signSS(
			"https://ta.example.com",
			"https://int.example.com",
			taKeys.privateKey,
			intKeys.publicKey,
			{
				metadata: {
					openid_relying_party: { client_name: "Should Not Override" },
				},
			},
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ssIntLeaf, ssTaInt, taEc], taSet, {
			verboseErrors: true,
		});
		expect(result.valid).toBe(true);
		if (result.valid) {
			// Should use immediate superior's metadata, not TA's SS metadata
			expect(result.chain.resolvedMetadata.openid_relying_party?.client_name).toBe(
				"Overridden by Int",
			);
		}
	});

	it("rejects statement without jwks", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
			},
		);
		// SS without jwks
		const ss = await signEntityStatement(
			{
				iss: "https://ta.example.com",
				sub: "https://leaf.example.com",
				iat: now,
				exp: now + 3600,
				// no jwks
			},
			taKeys.privateKey,
			{ typ: JwtTyp.EntityStatement },
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(result.errors.some((e) => e.message.includes("jwks"))).toBe(true);
	});

	it("rejects crit containing standard claim", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
				crit: ["iss"],
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(result.errors.some((e) => e.message.includes("crit"))).toBe(true);
	});

	it("rejects crit with unknown extension", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
				crit: ["x_custom_ext"],
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		// No understoodCriticalClaims → reject unknown
		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
	});

	it("accepts crit with registered extension", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
				crit: ["x_custom_ext"],
				x_custom_ext: "some value",
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, {
			understoodCriticalClaims: new Set(["x_custom_ext"]),
			verboseErrors: true,
		});
		expect(result.valid).toBe(true);
	});

	it("rejects EC-only claims in subordinate statement", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
			},
		);
		// SS with EC-only claim: trust_marks
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
			{ trust_marks: [{ trust_mark_type: "x", trust_mark: "y" }] },
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(result.errors.some((e) => e.message.includes("trust_marks"))).toBe(true);
	});

	it("rejects empty authority_hints array", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: [],
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(
			result.errors.some(
				(e) => e.message.includes("authority_hints") && e.message.includes("empty"),
			),
		).toBe(true);
	});

	it("rejects TA EC with authority_hints", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		// TA EC with authority_hints — invalid
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey, {
			authority_hints: ["https://other.example.com"],
		});

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(
			result.errors.some(
				(e) => e.message.includes("Trust Anchor") && e.message.includes("authority_hints"),
			),
		).toBe(true);
	});

	it("rejects SS issuer not in subject's authority_hints", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		// Leaf's authority_hints says "https://other.example.com" but SS is from "https://ta.example.com"
		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://other.example.com"],
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(result.errors.some((e) => e.message.includes("authority_hints"))).toBe(true);
	});

	it("rejects SS-only claims in entity configuration", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		// Leaf EC with SS-only claim: source_endpoint
		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
				source_endpoint: "https://example.com/fetch",
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(result.errors.some((e) => e.message.includes("source_endpoint"))).toBe(true);
	});

	it("rejects metadata containing null values", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
				metadata: {
					openid_relying_party: { client_name: "Test", scope: null },
				},
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(result.errors.some((e) => e.message.includes("null"))).toBe(true);
	});

	it("rejects chain statement with aud", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
				aud: "https://someone.example.com",
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(result.errors.some((e) => e.message.includes("aud"))).toBe(true);
	});

	it("rejects chain statement with trust_anchor", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
				trust_anchor: "https://ta.example.com",
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(result.errors.some((e) => e.message.includes("trust_anchor"))).toBe(true);
	});

	it("only collects trust_mark_issuers from TA EC", async () => {
		const taKeys = await generateSigningKey("ES256");
		const intKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");
		const tmIssuerKeys = await generateSigningKey("ES256");

		// Create a trust mark from a non-TA-approved issuer
		const trustMarkJwt = await signEntityStatement(
			{
				iss: "https://non-approved-issuer.example.com",
				sub: "https://leaf.example.com",
				iat: now,
				exp: now + 3600,
				id: "https://trust-mark-type.example.com",
			},
			tmIssuerKeys.privateKey,
			{ typ: "trust-mark+jwt" },
		);

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://int.example.com"],
				trust_marks: [
					{ trust_mark_type: "https://trust-mark-type.example.com", trust_mark: trustMarkJwt },
				],
			},
		);

		// Intermediate SS has trust_mark_issuers — these should be IGNORED
		const ssIntLeaf = await signSS(
			"https://int.example.com",
			"https://leaf.example.com",
			intKeys.privateKey,
			leafKeys.publicKey,
		);
		const ssTaInt = await signSS(
			"https://ta.example.com",
			"https://int.example.com",
			taKeys.privateKey,
			intKeys.publicKey,
		);
		// TA EC is the only source of trust_mark_issuers
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey, {
			trust_mark_issuers: {
				"https://trust-mark-type.example.com": ["https://approved-issuer.example.com"],
			},
		});

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ssIntLeaf, ssTaInt, taEc], taSet, {
			verboseErrors: true,
		});
		// The chain should be valid but the trust mark from non-approved issuer should not be in validatedTrustMarks
		expect(result.valid).toBe(true);
		if (result.valid) {
			// non-approved-issuer is not in TA's trust_mark_issuers list
			expect(result.chain.trustMarks).toHaveLength(0);
		}
	});

	it("rejects EC containing trust_chain header", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		// Leaf EC with trust_chain in header — forbidden (use jose directly to bypass sign guard)
		const leafCryptoKey = await jose.importJWK(leafKeys.privateKey as unknown as jose.JWK, "ES256");
		const leafEc = await new jose.SignJWT({
			iss: "https://leaf.example.com",
			sub: "https://leaf.example.com",
			iat: now,
			exp: now + 3600,
			jwks: { keys: [leafKeys.publicKey] },
			authority_hints: ["https://ta.example.com"],
		} as unknown as jose.JWTPayload)
			.setProtectedHeader({
				alg: "ES256",
				typ: JwtTyp.EntityStatement,
				kid: leafKeys.publicKey.kid as string,
				trust_chain: ["some.jwt"],
			} as jose.JWTHeaderParameters)
			.sign(leafCryptoKey as Parameters<jose.SignJWT["sign"]>[0]);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(result.errors.some((e) => e.message.includes("trust_chain"))).toBe(true);
	});

	it("rejects SS containing peer_trust_chain header", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
			},
		);
		// SS with peer_trust_chain in header — forbidden (use jose directly to bypass sign guard)
		const taCryptoKey = await jose.importJWK(taKeys.privateKey as unknown as jose.JWK, "ES256");
		const ss = await new jose.SignJWT({
			iss: "https://ta.example.com",
			sub: "https://leaf.example.com",
			iat: now,
			exp: now + 3600,
			jwks: { keys: [leafKeys.publicKey] },
		} as unknown as jose.JWTPayload)
			.setProtectedHeader({
				alg: "ES256",
				typ: JwtTyp.EntityStatement,
				kid: taKeys.publicKey.kid as string,
				peer_trust_chain: ["some.jwt"],
			} as jose.JWTHeaderParameters)
			.sign(taCryptoKey as Parameters<jose.SignJWT["sign"]>[0]);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(result.errors.some((e) => e.message.includes("peer_trust_chain"))).toBe(true);
	});

	it("rejects federation_entity metadata containing jwks", async () => {
		const { chain: _, taSet, leafKeys, taKeys } = await buildSimpleChain();
		// Rebuild leaf EC with federation_entity containing jwks
		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
				metadata: {
					federation_entity: {
						organization_name: "Test",
						jwks: { keys: [leafKeys.publicKey] },
					},
				},
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(
			result.errors.some(
				(e) => e.message.includes("jwks") && e.message.includes("federation_entity"),
			),
		).toBe(true);
	});

	it("rejects federation_entity metadata containing jwks_uri", async () => {
		const { taSet, leafKeys, taKeys } = await buildSimpleChain();
		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
				metadata: {
					federation_entity: {
						organization_name: "Test",
						jwks_uri: "https://example.com/jwks",
					},
				},
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(
			result.errors.some(
				(e) => e.message.includes("jwks_uri") && e.message.includes("federation_entity"),
			),
		).toBe(true);
	});

	it("rejects federation_entity metadata containing signed_jwks_uri", async () => {
		const { taSet, leafKeys, taKeys } = await buildSimpleChain();
		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
				metadata: {
					federation_entity: {
						organization_name: "Test",
						signed_jwks_uri: "https://example.com/signed-jwks",
					},
				},
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(
			result.errors.some(
				(e) => e.message.includes("signed_jwks_uri") && e.message.includes("federation_entity"),
			),
		).toBe(true);
	});

	it("rejects openid_provider.issuer not matching entity identifier", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
				metadata: {
					openid_provider: {
						issuer: "https://different.example.com",
						authorization_endpoint: "https://leaf.example.com/auth",
						token_endpoint: "https://leaf.example.com/token",
						response_types_supported: ["code"],
						subject_types_supported: ["public"],
						id_token_signing_alg_values_supported: ["RS256"],
					},
				},
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(
			result.errors.some(
				(e) => e.message.includes("openid_provider") && e.message.includes("issuer"),
			),
		).toBe(true);
	});

	it("rejects oauth_authorization_server.issuer not matching entity identifier", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
				metadata: {
					oauth_authorization_server: {
						issuer: "https://different.example.com",
					},
				},
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(
			result.errors.some(
				(e) => e.message.includes("oauth_authorization_server") && e.message.includes("issuer"),
			),
		).toBe(true);
	});

	it("rejects SS metadata with openid_provider.issuer not matching subject", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		// Leaf EC has no openid_provider metadata — it comes from SS
		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
			},
		);
		// SS carries openid_provider metadata with wrong issuer
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
			{
				metadata: {
					openid_provider: {
						issuer: "https://wrong.example.com",
					},
				},
			},
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(
			result.errors.some(
				(e) => e.message.includes("openid_provider") && e.message.includes("issuer"),
			),
		).toBe(true);
	});

	it("rejects SS metadata with oauth_authorization_server.issuer not matching subject", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
			{
				metadata: {
					oauth_authorization_server: {
						issuer: "https://wrong.example.com",
					},
				},
			},
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		expect(result.valid).toBe(false);
		expect(
			result.errors.some(
				(e) => e.message.includes("oauth_authorization_server") && e.message.includes("issuer"),
			),
		).toBe(true);
	});

	it("rejects crit with duplicate claim names", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
				crit: ["x_ext", "x_ext"],
				x_ext: "value",
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, {
			understoodCriticalClaims: new Set(["x_ext"]),
			verboseErrors: true,
		});
		expect(result.valid).toBe(false);
		expect(
			result.errors.some((e) => e.message.includes("Duplicate") && e.message.includes("crit")),
		).toBe(true);
	});

	it("rejects crit claim name absent from JWT payload", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
				crit: ["x_absent"],
				// x_absent is NOT in the payload
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, {
			understoodCriticalClaims: new Set(["x_absent"]),
			verboseErrors: true,
		});
		expect(result.valid).toBe(false);
		expect(
			result.errors.some((e) => e.message.includes("does not exist") && e.message.includes("crit")),
		).toBe(true);
	});

	it("validates chain with constraints (max_path_length)", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
			},
		);
		const ss = await signSS(
			"https://ta.example.com",
			"https://leaf.example.com",
			taKeys.privateKey,
			leafKeys.publicKey,
			{
				constraints: { max_path_length: 0 },
			},
		);
		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);

		const taSet: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
		// SS at position 1, intermediates = 1-1 = 0, max=0 → pass
		expect(result.valid).toBe(true);
	});
});

describe("calculateChainExpiration", () => {
	it("returns minimum exp from all statements", () => {
		const statements: ParsedEntityStatement[] = [
			{
				header: { alg: "ES256", typ: "entity-statement+jwt", kid: "k1" },
				payload: { iss: "a", sub: "a", iat: now, exp: now + 7200 } as EntityStatementPayload,
			},
			{
				header: { alg: "ES256", typ: "entity-statement+jwt", kid: "k1" },
				payload: { iss: "b", sub: "a", iat: now, exp: now + 3600 } as EntityStatementPayload,
			},
			{
				header: { alg: "ES256", typ: "entity-statement+jwt", kid: "k1" },
				payload: { iss: "c", sub: "c", iat: now, exp: now + 1800 } as EntityStatementPayload,
			},
		];
		expect(calculateChainExpiration(statements)).toBe(now + 1800);
	});
});

describe("isChainExpired", () => {
	it("returns true when chain has expired", () => {
		const chain = {
			statements: [],
			entityId: "https://leaf.example.com" as EntityId,
			trustAnchorId: "https://ta.example.com" as EntityId,
			expiresAt: now - 100,
			resolvedMetadata: {},
			trustMarks: [],
		} as ValidatedTrustChain;

		expect(isChainExpired(chain, { now: () => now })).toBe(true);
	});

	it("returns false when chain is still valid", () => {
		const chain = {
			statements: [],
			entityId: "https://leaf.example.com" as EntityId,
			trustAnchorId: "https://ta.example.com" as EntityId,
			expiresAt: now + 3600,
			resolvedMetadata: {},
			trustMarks: [],
		} as ValidatedTrustChain;

		expect(isChainExpired(chain, { now: () => now })).toBe(false);
	});

	it("returns true when expiresAt equals now (boundary)", () => {
		const chain = {
			statements: [],
			entityId: "https://leaf.example.com" as EntityId,
			trustAnchorId: "https://ta.example.com" as EntityId,
			expiresAt: now,
			resolvedMetadata: {},
			trustMarks: [],
		} as ValidatedTrustChain;

		expect(isChainExpired(chain, { now: () => now })).toBe(true);
	});
});

describe("chainRemainingTtl", () => {
	it("returns remaining seconds", () => {
		const chain = {
			expiresAt: now + 3600,
		} as ValidatedTrustChain;
		expect(chainRemainingTtl(chain, { now: () => now })).toBe(3600);
	});

	it("returns 0 when expired", () => {
		const chain = {
			expiresAt: now - 100,
		} as ValidatedTrustChain;
		expect(chainRemainingTtl(chain, { now: () => now })).toBe(0);
	});
});

describe("describeTrustChain", () => {
	it("returns hostnames joined by ←", () => {
		const chain = {
			statements: [
				{ header: {}, payload: { sub: "https://leaf.example.com" } },
				{ header: {}, payload: { sub: "https://leaf.example.com" } },
				{ header: {}, payload: { sub: "https://ta.example.com" } },
			],
		} as unknown as ValidatedTrustChain;

		expect(describeTrustChain(chain)).toBe("leaf.example.com ← leaf.example.com ← ta.example.com");
	});
});

describe("chain selection strategies", () => {
	const makeChain = (length: number, expiresAt: number, taId: string): ValidatedTrustChain => ({
		statements: Array(length).fill({
			header: {},
			payload: {
				sub: "https://a.example.com",
				iss: "https://a.example.com",
				iat: now,
				exp: expiresAt,
			},
		} as ParsedEntityStatement),
		entityId: "https://leaf.example.com" as EntityId,
		trustAnchorId: taId as EntityId,
		expiresAt,
		resolvedMetadata: {},
		trustMarks: [],
	});

	describe("shortestChain", () => {
		it("selects chain with fewest statements", () => {
			const chains = [
				makeChain(4, now + 3600, "https://ta1.example.com"),
				makeChain(2, now + 3600, "https://ta2.example.com"),
				makeChain(3, now + 3600, "https://ta3.example.com"),
			];
			const selected = shortestChain(chains);
			expect(selected.statements).toHaveLength(2);
		});
	});

	describe("longestExpiry", () => {
		it("selects chain with latest expiration", () => {
			const chains = [
				makeChain(3, now + 1800, "https://ta1.example.com"),
				makeChain(3, now + 7200, "https://ta2.example.com"),
				makeChain(3, now + 3600, "https://ta3.example.com"),
			];
			const selected = longestExpiry(chains);
			expect(selected.expiresAt).toBe(now + 7200);
		});
	});

	describe("preferTrustAnchor", () => {
		it("prefers chain with matching TA", () => {
			const chains = [
				makeChain(3, now + 3600, "https://ta1.example.com"),
				makeChain(4, now + 3600, "https://preferred.example.com"),
				makeChain(2, now + 3600, "https://ta3.example.com"),
			];
			const strategy = preferTrustAnchor("https://preferred.example.com");
			const selected = strategy(chains);
			expect(selected.trustAnchorId).toBe("https://preferred.example.com");
		});

		it("falls back to shortest when no TA match", () => {
			const chains = [
				makeChain(4, now + 3600, "https://ta1.example.com"),
				makeChain(2, now + 3600, "https://ta2.example.com"),
			];
			const strategy = preferTrustAnchor("https://nonexistent.example.com");
			const selected = strategy(chains);
			expect(selected.statements).toHaveLength(2);
		});
	});
});
