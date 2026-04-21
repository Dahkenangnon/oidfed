import { describe, expect, it } from "vitest";
import {
	NamingConstraintsSchema,
	TrustChainConstraintsSchema,
} from "../../src/schemas/constraints.js";

describe("NamingConstraintsSchema", () => {
	it("accepts valid constraints", () => {
		const result = NamingConstraintsSchema.safeParse({
			permitted: [".example.com"],
			excluded: [".evil.example.com"],
		});
		expect(result.success).toBe(true);
	});

	it("rejects wildcards in patterns", () => {
		const result = NamingConstraintsSchema.safeParse({
			permitted: ["*.example.com"],
		});
		expect(result.success).toBe(false);
	});

	it("rejects question marks in patterns", () => {
		const result = NamingConstraintsSchema.safeParse({
			permitted: ["?.example.com"],
		});
		expect(result.success).toBe(false);
	});

	it("accepts empty object", () => {
		const result = NamingConstraintsSchema.safeParse({});
		expect(result.success).toBe(true);
	});
});

describe("TrustChainConstraintsSchema", () => {
	it("accepts valid constraints", () => {
		const result = TrustChainConstraintsSchema.safeParse({
			max_path_length: 2,
			naming_constraints: { permitted: [".example.com"] },
			allowed_entity_types: ["openid_relying_party"],
		});
		expect(result.success).toBe(true);
	});

	it("rejects negative max_path_length", () => {
		const result = TrustChainConstraintsSchema.safeParse({
			max_path_length: -1,
		});
		expect(result.success).toBe(false);
	});

	it("rejects max_path_length > 100", () => {
		const result = TrustChainConstraintsSchema.safeParse({
			max_path_length: 101,
		});
		expect(result.success).toBe(false);
	});

	it("accepts max_path_length of 0", () => {
		const result = TrustChainConstraintsSchema.safeParse({
			max_path_length: 0,
		});
		expect(result.success).toBe(true);
	});

	it("ignores additional constraint parameters not defined by this spec", () => {
		const result = TrustChainConstraintsSchema.safeParse({
			max_path_length: 1,
			custom_constraint: "some_value",
		});
		expect(result.success).toBe(true);
	});

	it("rejects invalid entity types", () => {
		const result = TrustChainConstraintsSchema.safeParse({
			allowed_entity_types: ["invalid_type"],
		});
		expect(result.success).toBe(false);
	});

	it("rejects federation_entity in allowed_entity_types constraint", () => {
		const result = TrustChainConstraintsSchema.safeParse({
			allowed_entity_types: ["federation_entity"],
		});
		expect(result.success).toBe(false);
	});
});
