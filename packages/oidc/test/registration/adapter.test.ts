import { entityId, type ValidatedTrustChain } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { OIDCRegistrationAdapter } from "../../src/registration/adapter.js";

const adapter = new OIDCRegistrationAdapter();

const mockTrustChain = {
	entityId: entityId("https://rp.example.com"),
	statements: [],
	resolvedMetadata: {},
	expiresAt: Math.floor(Date.now() / 1000) + 86400,
} as unknown as ValidatedTrustChain;

describe("OIDCRegistrationAdapter", () => {
	describe("validateClientMetadata", () => {
		it("accepts valid openid_relying_party metadata", () => {
			const result = adapter.validateClientMetadata({
				openid_relying_party: {
					redirect_uris: ["https://rp.example.com/callback"],
					response_types: ["code"],
					client_registration_types: ["automatic"],
				},
			});
			expect(result.ok).toBe(true);
		});

		it("accepts metadata without openid_relying_party (federation-only)", () => {
			const result = adapter.validateClientMetadata({
				federation_entity: {
					organization_name: "Test Org",
				},
			});
			expect(result.ok).toBe(true);
		});

		it("rejects invalid openid_relying_party metadata", () => {
			const result = adapter.validateClientMetadata({
				openid_relying_party: {
					redirect_uris: ["not-a-url"],
				},
			});
			expect(result.ok).toBe(false);
			if (result.ok) return;
			expect(result.error.code).toBe("invalid_metadata");
		});
	});

	describe("enrichResponseMetadata", () => {
		it("adds client_id from trust chain if missing", () => {
			const enriched = adapter.enrichResponseMetadata({}, mockTrustChain);
			expect(enriched.client_id).toBe("https://rp.example.com");
		});

		it("preserves existing client_id", () => {
			const enriched = adapter.enrichResponseMetadata({ client_id: "existing-id" }, mockTrustChain);
			expect(enriched.client_id).toBe("existing-id");
		});

		it("does not mutate the original metadata object", () => {
			const original = { scope: "openid" };
			const enriched = adapter.enrichResponseMetadata(original, mockTrustChain);
			expect(enriched.client_id).toBe("https://rp.example.com");
			expect(original).not.toHaveProperty("client_id");
		});
	});

	describe("validateClientMetadata edge cases", () => {
		it("rejects openid_relying_party with invalid signed_jwks_uri (http)", () => {
			const result = adapter.validateClientMetadata({
				openid_relying_party: {
					signed_jwks_uri: "http://insecure.example.com/jwks",
				},
			});
			expect(result.ok).toBe(false);
			if (result.ok) return;
			expect(result.error.code).toBe("invalid_metadata");
		});

		it("accepts openid_relying_party with only optional fields", () => {
			const result = adapter.validateClientMetadata({
				openid_relying_party: {
					client_name: "Test RP",
				},
			});
			expect(result.ok).toBe(true);
		});

		it("accepts empty openid_relying_party object", () => {
			const result = adapter.validateClientMetadata({
				openid_relying_party: {},
			});
			expect(result.ok).toBe(true);
		});
	});
});
