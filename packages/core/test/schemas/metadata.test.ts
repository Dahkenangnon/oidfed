import { describe, expect, it } from "vitest";
import {
	FederationEntityMetadataSchema,
	FederationMetadataSchema,
} from "../../src/schemas/metadata.js";

describe("FederationMetadataSchema", () => {
	it("accepts metadata with at least one entity type", () => {
		const result = FederationMetadataSchema.safeParse({
			federation_entity: { organization_name: "Test" },
		});
		expect(result.success).toBe(true);
	});

	it("accepts metadata with multiple entity types", () => {
		const result = FederationMetadataSchema.safeParse({
			federation_entity: { organization_name: "Test" },
			openid_provider: {
				issuer: "https://op.example.com",
				authorization_endpoint: "https://op.example.com/auth",
			},
		});
		expect(result.success).toBe(true);
	});

	it("rejects empty metadata object (no entity types)", () => {
		const result = FederationMetadataSchema.safeParse({});
		expect(result.success).toBe(false);
	});

	it("rejects metadata where all known keys are undefined", () => {
		const result = FederationMetadataSchema.safeParse({
			federation_entity: undefined,
			openid_provider: undefined,
		});
		expect(result.success).toBe(false);
	});

	it("accepts openid_relying_party as loose record (OIDC validation in @oidfed/oidc)", () => {
		const result = FederationMetadataSchema.safeParse({
			openid_relying_party: {
				redirect_uris: ["https://rp.example.com/callback"],
				custom_field: "anything",
			},
		});
		expect(result.success).toBe(true);
	});

	it("accepts openid_provider as loose record (OIDC validation in @oidfed/oidc)", () => {
		const result = FederationMetadataSchema.safeParse({
			openid_provider: {
				issuer: "https://op.example.com",
				custom_field: 42,
			},
		});
		expect(result.success).toBe(true);
	});
});

describe("FederationEntityMetadataSchema — URL validation", () => {
	const endpoints = [
		"federation_fetch_endpoint",
		"federation_list_endpoint",
		"federation_resolve_endpoint",
		"federation_trust_mark_status_endpoint",
		"federation_trust_mark_list_endpoint",
		"federation_trust_mark_endpoint",
		"federation_historical_keys_endpoint",
	] as const;

	for (const field of endpoints) {
		it(`rejects http:// URL for ${field} (MUST use https)`, () => {
			const result = FederationEntityMetadataSchema.safeParse({
				[field]: "http://example.com/endpoint",
			});
			expect(result.success).toBe(false);
		});

		it(`rejects URL with fragment for ${field} (MUST NOT contain fragment)`, () => {
			const result = FederationEntityMetadataSchema.safeParse({
				[field]: "https://example.com/endpoint#frag",
			});
			expect(result.success).toBe(false);
		});

		it(`accepts valid https URL for ${field}`, () => {
			const result = FederationEntityMetadataSchema.safeParse({
				[field]: "https://example.com/endpoint?param=value",
			});
			expect(result.success).toBe(true);
		});
	}
});

describe("FederationEntityMetadataSchema — endpoint_auth_signing_alg", () => {
	it("rejects 'none' in endpoint_auth_signing_alg_values_supported", () => {
		const result = FederationEntityMetadataSchema.safeParse({
			endpoint_auth_signing_alg_values_supported: ["RS256", "none"],
		});
		expect(result.success).toBe(false);
	});

	it("accepts valid alg values", () => {
		const result = FederationEntityMetadataSchema.safeParse({
			endpoint_auth_signing_alg_values_supported: ["RS256", "ES256"],
		});
		expect(result.success).toBe(true);
	});
});
