import { describe, expect, it } from "vitest";
import {
	EntityTypeMetadataPolicySchema,
	FederationMetadataPolicySchema,
	MetadataParameterPolicySchema,
} from "../../src/schemas/metadata-policy.js";

describe("MetadataParameterPolicySchema", () => {
	it("accepts valid policy with all operators", () => {
		const result = MetadataParameterPolicySchema.safeParse({
			value: "openid",
			add: ["profile"],
			default: "openid",
			one_of: ["openid", "profile"],
			subset_of: ["openid", "profile", "email"],
			superset_of: ["openid"],
			essential: true,
		});
		expect(result.success).toBe(true);
	});

	it("accepts policy with subset of operators", () => {
		const result = MetadataParameterPolicySchema.safeParse({
			subset_of: ["ES256", "PS256"],
			essential: true,
		});
		expect(result.success).toBe(true);
	});

	it("accepts extra fields (looseObject)", () => {
		const result = MetadataParameterPolicySchema.safeParse({
			value: "test",
			custom_operator: ["x"],
		});
		expect(result.success).toBe(true);
	});
});

describe("EntityTypeMetadataPolicySchema", () => {
	it("accepts record of parameter policies", () => {
		const result = EntityTypeMetadataPolicySchema.safeParse({
			id_token_signing_alg_values_supported: {
				subset_of: ["ES256", "PS256"],
			},
			scope: {
				superset_of: ["openid"],
				default: ["openid"],
			},
		});
		expect(result.success).toBe(true);
	});
});

describe("FederationMetadataPolicySchema", () => {
	it("accepts nested record structure", () => {
		const result = FederationMetadataPolicySchema.safeParse({
			openid_provider: {
				id_token_signing_alg_values_supported: {
					subset_of: ["ES256"],
				},
			},
			openid_relying_party: {
				scope: {
					superset_of: ["openid"],
				},
			},
		});
		expect(result.success).toBe(true);
	});
});
