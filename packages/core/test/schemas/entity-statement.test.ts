import { describe, expect, it } from "vitest";
import {
	BaseEntityStatementSchema,
	EntityConfigurationSchema,
	EntityIdSchema,
	ExplicitRegistrationRequestPayloadSchema,
	ExplicitRegistrationResponsePayloadSchema,
	HistoricalKeyEntrySchema,
	SubordinateStatementSchema,
} from "../../src/schemas/entity-statement.js";
import { TrustMarkOwnerSchema } from "../../src/schemas/trust-mark.js";
import { entityId, isValidEntityId } from "../../src/types.js";

const now = Math.floor(Date.now() / 1000);

describe("EntityIdSchema", () => {
	it("accepts a valid HTTPS URL", () => {
		const result = EntityIdSchema.safeParse("https://example.com");
		expect(result.success).toBe(true);
	});

	it("rejects HTTP URL", () => {
		const result = EntityIdSchema.safeParse("http://example.com");
		expect(result.success).toBe(false);
	});

	it("rejects URL with credentials", () => {
		const result = EntityIdSchema.safeParse("https://user:pass@example.com");
		expect(result.success).toBe(false);
	});

	it("rejects URL with only username", () => {
		const result = EntityIdSchema.safeParse("https://user@example.com");
		expect(result.success).toBe(false);
	});

	it("rejects non-URL string", () => {
		const result = EntityIdSchema.safeParse("not-a-url");
		expect(result.success).toBe(false);
	});

	it("rejects empty string", () => {
		const result = EntityIdSchema.safeParse("");
		expect(result.success).toBe(false);
	});

	it("accepts HTTPS URL with path", () => {
		const result = EntityIdSchema.safeParse("https://example.com/path/to/entity");
		expect(result.success).toBe(true);
	});

	it("rejects URL with query parameters", () => {
		const result = EntityIdSchema.safeParse("https://example.com?foo=bar");
		expect(result.success).toBe(false);
	});

	it("rejects URL with fragment", () => {
		const result = EntityIdSchema.safeParse("https://example.com#section");
		expect(result.success).toBe(false);
	});

	it("rejects URL with both query and fragment", () => {
		const result = EntityIdSchema.safeParse("https://example.com?foo=bar#section");
		expect(result.success).toBe(false);
	});

	it("rejects URL with path and query", () => {
		const result = EntityIdSchema.safeParse("https://example.com/path?q=1");
		expect(result.success).toBe(false);
	});

	it("rejects URL exceeding 2048 characters", () => {
		const long = `https://example.com/${"a".repeat(2040)}`;
		expect(long.length).toBeGreaterThan(2048);
		expect(EntityIdSchema.safeParse(long).success).toBe(false);
	});

	it("accepts URL exactly 2048 characters", () => {
		const path = "a".repeat(2048 - "https://example.com/".length);
		const exact = `https://example.com/${path}`;
		expect(exact.length).toBe(2048);
		expect(EntityIdSchema.safeParse(exact).success).toBe(true);
	});
});

describe("entityId() constructor", () => {
	it("throws for URL exceeding 2048 characters", () => {
		const long = `https://example.com/${"a".repeat(2040)}`;
		expect(() => entityId(long)).toThrow("2048");
	});

	it("accepts valid HTTPS URL within 2048 characters", () => {
		expect(() => entityId("https://example.com")).not.toThrow();
	});
});

describe("isValidEntityId()", () => {
	it("returns false for URL exceeding 2048 characters", () => {
		const long = `https://example.com/${"a".repeat(2040)}`;
		expect(isValidEntityId(long)).toBe(false);
	});

	it("returns true for valid HTTPS URL within 2048 characters", () => {
		expect(isValidEntityId("https://example.com")).toBe(true);
	});
});

describe("BaseEntityStatementSchema", () => {
	const validBase = {
		iss: "https://issuer.example.com",
		sub: "https://subject.example.com",
		iat: now,
		exp: now + 3600,
		jwks: {
			keys: [{ kty: "EC" as const, kid: "k1", crv: "P-256", x: "a", y: "b" }],
		},
	};

	it("accepts valid base entity statement", () => {
		const result = BaseEntityStatementSchema.safeParse(validBase);
		expect(result.success).toBe(true);
	});

	it("rejects when exp <= iat", () => {
		const result = BaseEntityStatementSchema.safeParse({
			...validBase,
			exp: now - 100,
		});
		expect(result.success).toBe(false);
	});

	it("rejects when exp === iat", () => {
		const result = BaseEntityStatementSchema.safeParse({
			...validBase,
			exp: now,
			iat: now,
		});
		expect(result.success).toBe(false);
	});

	it("allows optional fields to be absent", () => {
		const minimal = {
			iss: "https://issuer.example.com",
			sub: "https://subject.example.com",
			iat: now,
			exp: now + 3600,
		};
		const result = BaseEntityStatementSchema.safeParse(minimal);
		expect(result.success).toBe(true);
	});

	it("accepts metadata as nested records", () => {
		const result = BaseEntityStatementSchema.safeParse({
			...validBase,
			metadata: {
				federation_entity: {
					organization_name: "Test Org",
				},
			},
		});
		expect(result.success).toBe(true);
	});
});

describe("EntityConfigurationSchema", () => {
	const validEC = {
		iss: "https://entity.example.com",
		sub: "https://entity.example.com",
		iat: now,
		exp: now + 3600,
		jwks: {
			keys: [{ kty: "EC" as const, kid: "k1", crv: "P-256", x: "a", y: "b" }],
		},
		authority_hints: ["https://authority.example.com"],
	};

	it("accepts valid entity configuration where iss === sub", () => {
		const result = EntityConfigurationSchema.safeParse(validEC);
		expect(result.success).toBe(true);
	});

	it("rejects when iss !== sub", () => {
		const result = EntityConfigurationSchema.safeParse({
			...validEC,
			sub: "https://other.example.com",
		});
		expect(result.success).toBe(false);
	});

	it("allows authority_hints to be absent", () => {
		const { authority_hints: _, ...ecWithout } = validEC;
		const result = EntityConfigurationSchema.safeParse(ecWithout);
		expect(result.success).toBe(true);
	});

	it("accepts metadata with at least one entity type", () => {
		const result = EntityConfigurationSchema.safeParse({
			...validEC,
			metadata: {
				federation_entity: { organization_name: "Test Org" },
			},
		});
		expect(result.success).toBe(true);
	});

	it("rejects when jwks is missing", () => {
		const { jwks: _, ...ecWithoutJwks } = validEC;
		const result = EntityConfigurationSchema.safeParse(ecWithoutJwks);
		expect(result.success).toBe(false);
	});

	it("rejects metadata with no entity types (empty object)", () => {
		const result = EntityConfigurationSchema.safeParse({
			...validEC,
			metadata: {},
		});
		expect(result.success).toBe(false);
	});

	it("accepts metadata with multiple entity types", () => {
		const result = EntityConfigurationSchema.safeParse({
			...validEC,
			metadata: {
				federation_entity: { organization_name: "Test" },
				openid_relying_party: { client_name: "Test RP" },
			},
		});
		expect(result.success).toBe(true);
	});
});

describe("EntityConfigurationSchema — trust_anchor_hints", () => {
	const baseEC = {
		iss: "https://entity.example.com",
		sub: "https://entity.example.com",
		iat: now,
		exp: now + 3600,
		jwks: { keys: [{ kty: "EC" as const, kid: "k1", crv: "P-256", x: "a", y: "b" }] },
	};

	it("rejects empty trust_anchor_hints array", () => {
		const result = EntityConfigurationSchema.safeParse({
			...baseEC,
			trust_anchor_hints: [],
		});
		expect(result.success).toBe(false);
	});

	it("accepts trust_anchor_hints with at least one entry", () => {
		const result = EntityConfigurationSchema.safeParse({
			...baseEC,
			trust_anchor_hints: ["https://ta.example.com"],
		});
		expect(result.success).toBe(true);
	});
});

describe("BaseEntityStatementSchema — metadata_policy_crit", () => {
	const validBase = {
		iss: "https://issuer.example.com",
		sub: "https://subject.example.com",
		iat: now,
		exp: now + 3600,
	};

	it("rejects empty metadata_policy_crit array", () => {
		const result = BaseEntityStatementSchema.safeParse({
			...validBase,
			metadata_policy_crit: [],
		});
		expect(result.success).toBe(false);
	});

	it("accepts metadata_policy_crit with at least one entry", () => {
		const result = BaseEntityStatementSchema.safeParse({
			...validBase,
			metadata_policy_crit: ["custom_operator"],
		});
		expect(result.success).toBe(true);
	});
});

describe("BaseEntityStatementSchema — crit", () => {
	const validBase = {
		iss: "https://issuer.example.com",
		sub: "https://subject.example.com",
		iat: now,
		exp: now + 3600,
	};

	it("rejects empty crit array", () => {
		const result = BaseEntityStatementSchema.safeParse({
			...validBase,
			crit: [],
		});
		expect(result.success).toBe(false);
	});

	it("accepts crit with at least one entry", () => {
		const result = BaseEntityStatementSchema.safeParse({
			...validBase,
			crit: ["x_custom"],
		});
		expect(result.success).toBe(true);
	});
});

describe("SubordinateStatementSchema", () => {
	const validSS = {
		iss: "https://authority.example.com",
		sub: "https://subordinate.example.com",
		iat: now,
		exp: now + 3600,
		jwks: {
			keys: [{ kty: "EC" as const, kid: "k1", crv: "P-256", x: "a", y: "b" }],
		},
	};

	it("accepts valid subordinate statement", () => {
		const result = SubordinateStatementSchema.safeParse(validSS);
		expect(result.success).toBe(true);
	});

	it("accepts with optional source_endpoint", () => {
		const result = SubordinateStatementSchema.safeParse({
			...validSS,
			source_endpoint: "https://authority.example.com/federation_fetch",
		});
		expect(result.success).toBe(true);
	});

	it("rejects when exp <= iat", () => {
		const result = SubordinateStatementSchema.safeParse({
			...validSS,
			exp: now - 100,
		});
		expect(result.success).toBe(false);
	});

	it("rejects when iss === sub", () => {
		const result = SubordinateStatementSchema.safeParse({
			...validSS,
			iss: "https://same.example.com",
			sub: "https://same.example.com",
		});
		expect(result.success).toBe(false);
	});

	it("rejects when jwks is missing", () => {
		const { jwks: _, ...withoutJwks } = validSS;
		const result = SubordinateStatementSchema.safeParse(withoutJwks);
		expect(result.success).toBe(false);
	});
});

describe("ExplicitRegistrationRequestPayloadSchema", () => {
	const validReq = {
		iss: "https://rp.example.com",
		sub: "https://rp.example.com",
		aud: "https://op.example.com",
		iat: now,
		exp: now + 3600,
		jwks: { keys: [{ kty: "EC" as const, kid: "k1", crv: "P-256", x: "a", y: "b" }] },
		authority_hints: ["https://ta.example.com"],
		metadata: {
			openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
		},
	};

	it("accepts valid registration request", () => {
		const result = ExplicitRegistrationRequestPayloadSchema.safeParse(validReq);
		expect(result.success).toBe(true);
	});

	it("rejects when iss !== sub", () => {
		const result = ExplicitRegistrationRequestPayloadSchema.safeParse({
			...validReq,
			sub: "https://other.example.com",
		});
		expect(result.success).toBe(false);
	});

	it("requires aud", () => {
		const { aud: _, ...noAud } = validReq;
		const result = ExplicitRegistrationRequestPayloadSchema.safeParse(noAud);
		expect(result.success).toBe(false);
	});

	it("requires authority_hints", () => {
		const { authority_hints: _, ...noHints } = validReq;
		const result = ExplicitRegistrationRequestPayloadSchema.safeParse(noHints);
		expect(result.success).toBe(false);
	});

	it("requires metadata", () => {
		const { metadata: _, ...noMeta } = validReq;
		const result = ExplicitRegistrationRequestPayloadSchema.safeParse(noMeta);
		expect(result.success).toBe(false);
	});

	it("requires metadata to contain openid_relying_party", () => {
		const result = ExplicitRegistrationRequestPayloadSchema.safeParse({
			...validReq,
			metadata: { federation_entity: { organization_name: "Test" } },
		});
		expect(result.success).toBe(false);
	});
});

describe("ExplicitRegistrationResponsePayloadSchema", () => {
	const validResp = {
		iss: "https://op.example.com",
		sub: "https://rp.example.com",
		aud: "https://rp.example.com",
		iat: now,
		exp: now + 3600,
		trust_anchor: "https://ta.example.com",
		authority_hints: ["https://intermediate.example.com"],
	};

	it("accepts valid registration response", () => {
		const result = ExplicitRegistrationResponsePayloadSchema.safeParse(validResp);
		expect(result.success).toBe(true);
	});

	it("requires trust_anchor", () => {
		const { trust_anchor: _, ...noTA } = validResp;
		const result = ExplicitRegistrationResponsePayloadSchema.safeParse(noTA);
		expect(result.success).toBe(false);
	});

	it("accepts optional client_secret", () => {
		const result = ExplicitRegistrationResponsePayloadSchema.safeParse({
			...validResp,
			client_secret: "secret123",
		});
		expect(result.success).toBe(true);
	});

	it("requires authority_hints in response", () => {
		const { authority_hints: _, ...noHints } = validResp;
		const result = ExplicitRegistrationResponsePayloadSchema.safeParse(noHints);
		expect(result.success).toBe(false);
	});

	it("requires authority_hints to be exactly one element", () => {
		const result = ExplicitRegistrationResponsePayloadSchema.safeParse({
			...validResp,
			authority_hints: ["https://a.example.com", "https://b.example.com"],
		});
		expect(result.success).toBe(false);
	});
});

describe("TrustMarkOwnerSchema", () => {
	it("preserves extra members (Other members MAY also be defined)", () => {
		const result = TrustMarkOwnerSchema.safeParse({
			sub: "https://owner.example.com",
			jwks: { keys: [{ kty: "EC", kid: "k1", crv: "P-256", x: "a", y: "b" }] },
			organization_name: "Example Org",
		});
		expect(result.success).toBe(true);
		if (result.success) {
			expect((result.data as Record<string, unknown>).organization_name).toBe("Example Org");
		}
	});
});

describe("HistoricalKeyEntrySchema", () => {
	it("requires kid field", () => {
		const result = HistoricalKeyEntrySchema.safeParse({
			kty: "EC",
			exp: now + 3600,
		});
		expect(result.success).toBe(false);
	});

	it("accepts entry with kid", () => {
		const result = HistoricalKeyEntrySchema.safeParse({
			kty: "EC",
			kid: "key-1",
			exp: now + 3600,
		});
		expect(result.success).toBe(true);
	});
});
