import { describe, expect, it } from "vitest";
import { decodeJwtPart, extractFederationEntity } from "@/lib/jwt";

describe("decodeJwtPart", () => {
	it("decodes a valid base64url-encoded JSON object", () => {
		const obj = { sub: "https://example.com", iss: "https://ta.example.com" };
		const encoded = btoa(JSON.stringify(obj))
			.replace(/\+/g, "-")
			.replace(/\//g, "_")
			.replace(/=+$/, "");
		expect(decodeJwtPart(encoded)).toEqual(obj);
	});

	it("handles standard base64 padding characters", () => {
		const obj = { a: 1 };
		const encoded = btoa(JSON.stringify(obj));
		expect(decodeJwtPart(encoded)).toEqual(obj);
	});

	it("returns null for invalid base64", () => {
		expect(decodeJwtPart("!!!invalid!!!")).toBeNull();
	});

	it("returns null for valid base64 but non-JSON content", () => {
		const encoded = btoa("not json");
		expect(decodeJwtPart(encoded)).toBeNull();
	});

	it("returns null for empty string", () => {
		expect(decodeJwtPart("")).toBeNull();
	});
});

describe("extractFederationEntity", () => {
	it("extracts federation_entity from metadata", () => {
		const payload = {
			metadata: {
				federation_entity: {
					organization_name: "Test Org",
					federation_list_endpoint: "https://example.com/list",
				},
			},
		};
		expect(extractFederationEntity(payload)).toEqual({
			organization_name: "Test Org",
			federation_list_endpoint: "https://example.com/list",
		});
	});

	it("returns empty object when federation_entity is missing", () => {
		const payload = { metadata: { openid_provider: { issuer: "https://op.example.com" } } };
		expect(extractFederationEntity(payload)).toEqual({});
	});

	it("returns empty object when metadata is undefined", () => {
		expect(extractFederationEntity({})).toEqual({});
	});
});
