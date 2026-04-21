import { describe, expect, it } from "vitest";
import {
	applyAllowedEntityTypes,
	checkConstraints,
	checkMaxPathLength,
	checkNamingConstraints,
} from "../../src/constraints/index.js";
import { isErr, isOk } from "../../src/errors.js";
import type { TrustChainConstraints } from "../../src/schemas/constraints.js";
import type { EntityId, ParsedEntityStatement } from "../../src/types.js";

// Helper to create a minimal ParsedEntityStatement for testing
function makeStatement(
	iss: string,
	sub: string,
	overrides?: Partial<ParsedEntityStatement["payload"]>,
): ParsedEntityStatement {
	const now = Math.floor(Date.now() / 1000);
	return {
		header: { alg: "ES256", typ: "entity-statement+jwt", kid: "k1" },
		payload: {
			iss: iss as EntityId,
			sub: sub as EntityId,
			iat: now,
			exp: now + 3600,
			...overrides,
		} as ParsedEntityStatement["payload"],
	};
}

describe("checkMaxPathLength", () => {
	it("returns true when 0 intermediates and max=0", () => {
		// constrainer at position 1, intermediates between constrainer and leaf = 1-1 = 0
		expect(checkMaxPathLength(0, 1, 3)).toBe(true);
	});

	it("returns false when 2 intermediates and max=1", () => {
		// constrainer at position 3, intermediates between constrainer and leaf = 3-1 = 2
		expect(checkMaxPathLength(1, 3, 5)).toBe(false);
	});

	it("returns true at exact boundary (1 intermediate, max=1)", () => {
		// constrainer at position 2, intermediates = 2-1 = 1
		expect(checkMaxPathLength(1, 2, 4)).toBe(true);
	});

	it("returns true when max exceeds intermediates", () => {
		expect(checkMaxPathLength(10, 2, 4)).toBe(true);
	});

	it("returns true when constrainer is direct superior of leaf (position 1)", () => {
		// position 1, intermediates = 1-1 = 0
		expect(checkMaxPathLength(0, 1, 3)).toBe(true);
	});
});

describe("checkNamingConstraints", () => {
	it("returns true with no constraints", () => {
		expect(checkNamingConstraints({}, "https://example.com" as EntityId)).toBe(true);
	});

	it("matches exact hostname in permitted list", () => {
		const constraints = { permitted: ["example.com"] };
		expect(checkNamingConstraints(constraints, "https://example.com" as EntityId)).toBe(true);
	});

	it("rejects hostname not in permitted list", () => {
		const constraints = { permitted: ["example.com"] };
		expect(checkNamingConstraints(constraints, "https://other.com" as EntityId)).toBe(false);
	});

	it("matches subdomain with dot-prefix pattern", () => {
		const constraints = { permitted: [".example.com"] };
		expect(checkNamingConstraints(constraints, "https://sub.example.com" as EntityId)).toBe(true);
	});

	it("dot-prefix does not match the domain itself (only subdomains)", () => {
		const constraints = { permitted: [".example.com"] };
		expect(checkNamingConstraints(constraints, "https://example.com" as EntityId)).toBe(false);
	});

	it("excluded overrides permitted", () => {
		const constraints = {
			permitted: [".example.com"],
			excluded: ["bad.example.com"],
		};
		expect(checkNamingConstraints(constraints, "https://bad.example.com" as EntityId)).toBe(false);
	});

	it("excluded alone blocks matching hostname", () => {
		const constraints = { excluded: ["blocked.com"] };
		expect(checkNamingConstraints(constraints, "https://blocked.com" as EntityId)).toBe(false);
	});

	it("excluded alone allows non-matching hostname", () => {
		const constraints = { excluded: ["blocked.com"] };
		expect(checkNamingConstraints(constraints, "https://allowed.com" as EntityId)).toBe(true);
	});

	it("extracts hostname correctly from URL with path", () => {
		const constraints = { permitted: ["example.com"] };
		expect(checkNamingConstraints(constraints, "https://example.com/some/path" as EntityId)).toBe(
			true,
		);
	});

	it("extracts hostname correctly from URL with port", () => {
		const constraints = { permitted: ["example.com"] };
		expect(checkNamingConstraints(constraints, "https://example.com:8443" as EntityId)).toBe(true);
	});

	it("handles subdomain pattern with multiple levels", () => {
		const constraints = { permitted: [".example.com"] };
		expect(checkNamingConstraints(constraints, "https://deep.sub.example.com" as EntityId)).toBe(
			true,
		);
	});
});

describe("applyAllowedEntityTypes", () => {
	it("filters metadata to only allowed entity types", () => {
		const metadata = {
			federation_entity: { organization_name: "Test" },
			openid_relying_party: { client_name: "RP" },
			openid_provider: { issuer: "https://op.example.com" },
		};
		const result = applyAllowedEntityTypes(["openid_relying_party"], metadata);
		expect(result).toHaveProperty("federation_entity");
		expect(result).toHaveProperty("openid_relying_party");
		expect(result).not.toHaveProperty("openid_provider");
	});

	it("always keeps federation_entity even if not in list", () => {
		const metadata = {
			federation_entity: { organization_name: "Test" },
			openid_provider: { issuer: "https://op.example.com" },
		};
		const result = applyAllowedEntityTypes(["openid_provider"], metadata);
		expect(result).toHaveProperty("federation_entity");
		expect(result).toHaveProperty("openid_provider");
	});

	it("returns only federation_entity when empty array", () => {
		const metadata = {
			federation_entity: { organization_name: "Test" },
			openid_relying_party: { client_name: "RP" },
		};
		const result = applyAllowedEntityTypes([], metadata);
		expect(result).toHaveProperty("federation_entity");
		expect(result).not.toHaveProperty("openid_relying_party");
	});

	it("does not mutate input metadata", () => {
		const metadata = {
			federation_entity: { organization_name: "Test" },
			openid_relying_party: { client_name: "RP" },
		};
		const original = { ...metadata };
		applyAllowedEntityTypes(["openid_relying_party"], metadata);
		expect(metadata).toEqual(original);
	});
});

describe("checkConstraints", () => {
	it("returns ok when no constraint violations", () => {
		const chain = [
			makeStatement("https://leaf.example.com", "https://leaf.example.com"),
			makeStatement("https://intermediate.example.com", "https://leaf.example.com", {
				constraints: {
					max_path_length: 1,
					naming_constraints: { permitted: [".example.com"] },
				},
			}),
			makeStatement("https://ta.example.com", "https://ta.example.com"),
		];
		const result = checkConstraints(
			chain[1]?.payload.constraints as TrustChainConstraints,
			1,
			chain,
		);
		expect(isOk(result)).toBe(true);
	});

	it("returns error when max_path_length exceeded", () => {
		const chain = [
			makeStatement("https://leaf.example.com", "https://leaf.example.com"),
			makeStatement("https://int1.example.com", "https://leaf.example.com"),
			makeStatement("https://int2.example.com", "https://int1.example.com"),
			makeStatement("https://ta.example.com", "https://int2.example.com", {
				constraints: { max_path_length: 0 },
			}),
			makeStatement("https://ta.example.com", "https://ta.example.com"),
		];
		// constrainer at position 3, intermediates to leaf = 3-1 = 2, max=0 -> fail
		const result = checkConstraints(
			chain[3]?.payload.constraints as TrustChainConstraints,
			3,
			chain,
		);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.code).toBe("ERR_CONSTRAINT_VIOLATION");
		}
	});

	it("returns error when naming constraint violated by entity below constrainer", () => {
		const chain = [
			makeStatement("https://evil.other.com", "https://evil.other.com"),
			makeStatement("https://intermediate.example.com", "https://evil.other.com", {
				constraints: {
					naming_constraints: { permitted: [".example.com"] },
				},
			}),
			makeStatement("https://ta.example.com", "https://ta.example.com"),
		];
		const result = checkConstraints(
			chain[1]?.payload.constraints as TrustChainConstraints,
			1,
			chain,
		);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.code).toBe("ERR_CONSTRAINT_VIOLATION");
		}
	});
});
