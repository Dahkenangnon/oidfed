import { describe, expect, it } from "vitest";
import { isErr, isOk } from "../../src/errors.js";
import { resolveMetadataPolicy } from "../../src/metadata-policy/merge.js";
import type { EntityId, ParsedEntityStatement } from "../../src/types.js";

function makeStatement(
	overrides?: Partial<ParsedEntityStatement["payload"]>,
): ParsedEntityStatement {
	const now = Math.floor(Date.now() / 1000);
	return {
		header: { alg: "ES256", typ: "entity-statement+jwt", kid: "k1" },
		payload: {
			iss: "https://superior.example.com" as EntityId,
			sub: "https://leaf.example.com" as EntityId,
			iat: now,
			exp: now + 3600,
			...overrides,
		} as ParsedEntityStatement["payload"],
	};
}

describe("resolveMetadataPolicy", () => {
	it("returns empty policy when no statements have metadata_policy", () => {
		const result = resolveMetadataPolicy([makeStatement()]);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value).toEqual({});
		}
	});

	it("passes through single statement policy unchanged", () => {
		const stmt = makeStatement({
			metadata_policy: {
				openid_relying_party: {
					scope: { subset_of: ["openid", "profile", "email"] },
				},
			},
		});
		const result = resolveMetadataPolicy([stmt]);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value).toEqual({
				openid_relying_party: {
					scope: { subset_of: ["openid", "profile", "email"] },
				},
			});
		}
	});

	it("merges two compatible policies (TA→leaf order)", () => {
		// subordinateStatements[1] = closest to TA (applied first)
		// subordinateStatements[0] = closest to leaf (applied second)
		const taLevelStmt = makeStatement({
			metadata_policy: {
				openid_relying_party: {
					scope: { subset_of: ["openid", "profile", "email", "address"] },
				},
			},
		});
		const midLevelStmt = makeStatement({
			metadata_policy: {
				openid_relying_party: {
					scope: { subset_of: ["openid", "profile", "email"] },
				},
			},
		});
		// Array order: [closest to leaf, ..., closest to TA]
		const result = resolveMetadataPolicy([midLevelStmt, taLevelStmt]);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			// subset_of merge = intersection: ["openid", "profile", "email"]
			expect(result.value).toEqual({
				openid_relying_party: {
					scope: { subset_of: ["openid", "profile", "email"] },
				},
			});
		}
	});

	it("detects merge conflict (value ≠ value)", () => {
		const stmt1 = makeStatement({
			metadata_policy: {
				openid_relying_party: {
					token_endpoint_auth_method: { value: "client_secret_basic" },
				},
			},
		});
		const stmt2 = makeStatement({
			metadata_policy: {
				openid_relying_party: {
					token_endpoint_auth_method: { value: "private_key_jwt" },
				},
			},
		});
		const result = resolveMetadataPolicy([stmt1, stmt2]);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.code).toBe("ERR_METADATA_POLICY_ERROR");
		}
	});

	it("errors on unknown critical operator", () => {
		const stmt = makeStatement({
			metadata_policy_crit: ["unknown_op"],
			metadata_policy: {
				openid_relying_party: {
					scope: { unknown_op: ["x"] } as Record<string, unknown>,
				},
			},
		});
		const result = resolveMetadataPolicy([stmt]);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.code).toBe("ERR_METADATA_POLICY_ERROR");
		}
	});

	it("silently skips unknown non-critical operators", () => {
		const stmt = makeStatement({
			metadata_policy: {
				openid_relying_party: {
					scope: {
						subset_of: ["openid", "profile"],
						unknown_op: ["x"],
					} as Record<string, unknown>,
				},
			},
		});
		const result = resolveMetadataPolicy([stmt]);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value).toEqual({
				openid_relying_party: {
					scope: { subset_of: ["openid", "profile"] },
				},
			});
		}
	});

	it("does not mutate input statements", () => {
		const policy = {
			openid_relying_party: {
				scope: { subset_of: ["openid", "profile"] },
			},
		};
		const stmt = makeStatement({ metadata_policy: policy });
		const originalPolicy = JSON.parse(JSON.stringify(policy));
		resolveMetadataPolicy([stmt]);
		expect(policy).toEqual(originalPolicy);
	});

	it("merges three-level nested policies", () => {
		const taStmt = makeStatement({
			metadata_policy: {
				openid_relying_party: {
					grant_types: { subset_of: ["authorization_code", "implicit", "refresh_token"] },
					scope: { superset_of: ["openid"] },
				},
			},
		});
		const midStmt = makeStatement({
			metadata_policy: {
				openid_relying_party: {
					grant_types: { subset_of: ["authorization_code", "refresh_token"] },
					scope: { superset_of: ["openid", "profile"] },
				},
			},
		});
		const lowStmt = makeStatement({
			metadata_policy: {
				openid_relying_party: {
					scope: { default: "openid profile" },
				},
			},
		});
		// Order: [lowStmt (closest to leaf), midStmt, taStmt (closest to TA)]
		const result = resolveMetadataPolicy([lowStmt, midStmt, taStmt]);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			const rp = result.value.openid_relying_party as Record<string, unknown>;
			// grant_types: subset_of intersection
			expect(rp.grant_types).toEqual({
				subset_of: ["authorization_code", "refresh_token"],
			});
			// scope: superset_of union + default
			expect(rp.scope).toEqual({
				superset_of: ["openid", "profile"],
				default: "openid profile",
			});
		}
	});

	it("validates operator combinations during merge", () => {
		// add + one_of is never allowed (-)
		const stmt1 = makeStatement({
			metadata_policy: {
				openid_relying_party: {
					scope: { add: ["extra"] },
				},
			},
		});
		const stmt2 = makeStatement({
			metadata_policy: {
				openid_relying_party: {
					scope: { one_of: ["openid", "profile"] },
				},
			},
		});
		const result = resolveMetadataPolicy([stmt1, stmt2]);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.code).toBe("ERR_METADATA_POLICY_ERROR");
		}
	});

	it("merges different entity types independently", () => {
		const stmt = makeStatement({
			metadata_policy: {
				openid_relying_party: {
					scope: { default: "openid" },
				},
				openid_provider: {
					response_types_supported: { superset_of: ["code"] },
				},
			},
		});
		const result = resolveMetadataPolicy([stmt]);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.openid_relying_party).toEqual({ scope: { default: "openid" } });
			expect(result.value.openid_provider).toEqual({
				response_types_supported: { superset_of: ["code"] },
			});
		}
	});

	it("validates operator combinations bidirectionally", () => {
		// value=null + essential=true: the C* rule says this is not allowed
		// The check must be done in both directions (A→B and B→A)
		const stmt1 = makeStatement({
			metadata_policy: {
				openid_relying_party: {
					scope: { value: null },
				},
			},
		});
		const stmt2 = makeStatement({
			metadata_policy: {
				openid_relying_party: {
					scope: { essential: true },
				},
			},
		});
		const result = resolveMetadataPolicy([stmt1, stmt2]);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.code).toBe("ERR_METADATA_POLICY_ERROR");
			expect(result.error.description).toContain("Incompatible operators");
		}
	});

	it("rejects one_of + subset_of forbidden combination during merge", () => {
		const stmt1 = makeStatement({
			metadata_policy: {
				openid_relying_party: {
					token_endpoint_auth_method: {
						one_of: ["private_key_jwt", "client_secret_basic"],
					},
				},
			},
		});
		const stmt2 = makeStatement({
			metadata_policy: {
				openid_relying_party: {
					token_endpoint_auth_method: {
						subset_of: ["private_key_jwt", "client_secret_post"],
					},
				},
			},
		});
		const result = resolveMetadataPolicy([stmt1, stmt2]);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.code).toBe("ERR_METADATA_POLICY_ERROR");
		}
	});

	it("accumulates operators from different levels for same parameter", () => {
		const taStmt = makeStatement({
			metadata_policy: {
				openid_relying_party: {
					scope: { essential: true },
				},
			},
		});
		const midStmt = makeStatement({
			metadata_policy: {
				openid_relying_party: {
					scope: { subset_of: ["openid", "profile", "email"] },
				},
			},
		});
		const result = resolveMetadataPolicy([midStmt, taStmt]);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.openid_relying_party?.scope).toEqual({
				essential: true,
				subset_of: ["openid", "profile", "email"],
			});
		}
	});
});
