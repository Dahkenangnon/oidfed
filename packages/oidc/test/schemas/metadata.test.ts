import { describe, expect, it } from "vitest";
import {
	OIDCFederationMetadataSchema,
	OpenIDProviderMetadataSchema,
	OpenIDRelyingPartyMetadataSchema,
	validateOIDCMetadata,
} from "../../src/schemas/metadata.js";

describe("OIDCFederationMetadataSchema", () => {
	it("validates metadata with valid openid_provider fields", () => {
		const metadata = {
			openid_provider: {
				issuer: "https://op.example.com",
				authorization_endpoint: "https://op.example.com/authorize",
				token_endpoint: "https://op.example.com/token",
				response_types_supported: ["code"],
				subject_types_supported: ["public"],
				id_token_signing_alg_values_supported: ["ES256"],
			},
		};
		const result = OIDCFederationMetadataSchema.safeParse(metadata);
		expect(result.success).toBe(true);
	});

	it("validates metadata with valid openid_relying_party fields", () => {
		const metadata = {
			openid_relying_party: {
				redirect_uris: ["https://rp.example.com/callback"],
				response_types: ["code"],
				client_registration_types: ["automatic"],
			},
		};
		const result = OIDCFederationMetadataSchema.safeParse(metadata);
		expect(result.success).toBe(true);
	});

	it("rejects OP metadata with invalid issuer URL", () => {
		const metadata = {
			openid_provider: {
				issuer: "not-a-url",
				authorization_endpoint: "https://op.example.com/authorize",
				token_endpoint: "https://op.example.com/token",
				response_types_supported: ["code"],
				subject_types_supported: ["public"],
				id_token_signing_alg_values_supported: ["ES256"],
			},
		};
		const result = OIDCFederationMetadataSchema.safeParse(metadata);
		expect(result.success).toBe(false);
	});

	it("rejects RP metadata with invalid redirect_uris", () => {
		const metadata = {
			openid_relying_party: {
				redirect_uris: ["not-a-url"],
			},
		};
		const result = OIDCFederationMetadataSchema.safeParse(metadata);
		expect(result.success).toBe(false);
	});

	it("requires at least one entity type (inherited from FederationMetadataSchema)", () => {
		const metadata = {};
		const result = OIDCFederationMetadataSchema.safeParse(metadata);
		expect(result.success).toBe(false);
	});
});

describe("OpenIDProviderMetadataSchema — URL validation", () => {
	const validOP = {
		issuer: "https://op.example.com",
		authorization_endpoint: "https://op.example.com/auth",
		token_endpoint: "https://op.example.com/token",
		response_types_supported: ["code"],
		subject_types_supported: ["public"],
		id_token_signing_alg_values_supported: ["RS256"],
	};

	it("rejects http:// federation_registration_endpoint", () => {
		const result = OpenIDProviderMetadataSchema.safeParse({
			...validOP,
			federation_registration_endpoint: "http://op.example.com/register",
		});
		expect(result.success).toBe(false);
	});

	it("rejects fragment in federation_registration_endpoint", () => {
		const result = OpenIDProviderMetadataSchema.safeParse({
			...validOP,
			federation_registration_endpoint: "https://op.example.com/register#frag",
		});
		expect(result.success).toBe(false);
	});

	it("rejects http:// signed_jwks_uri", () => {
		const result = OpenIDProviderMetadataSchema.safeParse({
			...validOP,
			signed_jwks_uri: "http://op.example.com/jwks",
		});
		expect(result.success).toBe(false);
	});

	it("rejects http:// jwks_uri", () => {
		const result = OpenIDProviderMetadataSchema.safeParse({
			...validOP,
			jwks_uri: "http://op.example.com/jwks",
		});
		expect(result.success).toBe(false);
	});
});

describe("OpenIDRelyingPartyMetadataSchema — URL validation", () => {
	it("rejects http:// signed_jwks_uri", () => {
		const result = OpenIDRelyingPartyMetadataSchema.safeParse({
			signed_jwks_uri: "http://rp.example.com/jwks",
		});
		expect(result.success).toBe(false);
	});

	it("rejects http:// jwks_uri", () => {
		const result = OpenIDRelyingPartyMetadataSchema.safeParse({
			jwks_uri: "http://rp.example.com/jwks",
		});
		expect(result.success).toBe(false);
	});
});

describe("validateOIDCMetadata", () => {
	it("returns parsed metadata for valid input", () => {
		const metadata = {
			openid_provider: {
				issuer: "https://op.example.com",
				authorization_endpoint: "https://op.example.com/authorize",
				token_endpoint: "https://op.example.com/token",
				response_types_supported: ["code"],
				subject_types_supported: ["public"],
				id_token_signing_alg_values_supported: ["ES256"],
			},
		};
		const result = validateOIDCMetadata(metadata);
		expect(result.openid_provider?.issuer).toBe("https://op.example.com");
	});

	it("throws for invalid OP metadata", () => {
		expect(() =>
			validateOIDCMetadata({
				openid_provider: { issuer: "bad" },
			}),
		).toThrow();
	});

	it("throws for invalid RP metadata", () => {
		expect(() =>
			validateOIDCMetadata({
				openid_relying_party: { redirect_uris: [123] },
			}),
		).toThrow();
	});
});
