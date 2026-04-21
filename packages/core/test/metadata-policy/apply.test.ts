import { describe, expect, it } from "vitest";
import { isErr, isOk } from "../../src/errors.js";
import {
	applyMetadataPolicy,
	denormalizeScope,
	normalizeScope,
} from "../../src/metadata-policy/apply.js";
import type { FederationMetadata } from "../../src/schemas/metadata.js";
import type { ResolvedMetadataPolicy } from "../../src/types.js";

describe("normalizeScope / denormalizeScope", () => {
	it("splits space-separated scope string", () => {
		expect(normalizeScope("openid profile email")).toEqual(["openid", "profile", "email"]);
	});

	it("filters empty strings from extra spaces", () => {
		expect(normalizeScope("openid  profile")).toEqual(["openid", "profile"]);
	});

	it("joins array back to space-separated string", () => {
		expect(denormalizeScope(["openid", "profile"])).toBe("openid profile");
	});
});

describe("applyMetadataPolicy", () => {
	it("returns metadata unchanged when policy is empty", () => {
		const metadata: FederationMetadata = {
			openid_relying_party: { client_name: "Test RP" },
		};
		const policy: ResolvedMetadataPolicy = {};
		const result = applyMetadataPolicy(metadata, policy);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value).toEqual(metadata);
		}
	});

	it("applies value operator (forces value)", () => {
		const metadata: FederationMetadata = {
			openid_relying_party: {
				token_endpoint_auth_method: "client_secret_basic",
			},
		};
		const policy: ResolvedMetadataPolicy = {
			openid_relying_party: {
				token_endpoint_auth_method: { value: "private_key_jwt" },
			},
		};
		const result = applyMetadataPolicy(metadata, policy);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.openid_relying_party?.token_endpoint_auth_method).toBe("private_key_jwt");
		}
	});

	it("applies default operator (fills absent value)", () => {
		const metadata: FederationMetadata = {
			openid_relying_party: {},
		};
		const policy: ResolvedMetadataPolicy = {
			openid_relying_party: {
				token_endpoint_auth_method: { default: "client_secret_basic" },
			},
		};
		const result = applyMetadataPolicy(metadata, policy);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.openid_relying_party?.token_endpoint_auth_method).toBe(
				"client_secret_basic",
			);
		}
	});

	it("applies add operator (union with existing)", () => {
		const metadata: FederationMetadata = {
			openid_relying_party: {
				grant_types: ["authorization_code"],
			},
		};
		const policy: ResolvedMetadataPolicy = {
			openid_relying_party: {
				grant_types: { add: ["refresh_token"] },
			},
		};
		const result = applyMetadataPolicy(metadata, policy);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.openid_relying_party?.grant_types).toEqual([
				"authorization_code",
				"refresh_token",
			]);
		}
	});

	it("applies subset_of operator (intersects)", () => {
		const metadata: FederationMetadata = {
			openid_relying_party: {
				response_types: ["code", "token", "id_token"],
			},
		};
		const policy: ResolvedMetadataPolicy = {
			openid_relying_party: {
				response_types: { subset_of: ["code", "id_token"] },
			},
		};
		const result = applyMetadataPolicy(metadata, policy);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.openid_relying_party?.response_types).toEqual(["code", "id_token"]);
		}
	});

	it("fails on superset_of violation", () => {
		const metadata: FederationMetadata = {
			openid_relying_party: {
				grant_types: ["authorization_code"],
			},
		};
		const policy: ResolvedMetadataPolicy = {
			openid_relying_party: {
				grant_types: { superset_of: ["authorization_code", "refresh_token"] },
			},
		};
		const result = applyMetadataPolicy(metadata, policy);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.code).toBe("ERR_METADATA_POLICY_VIOLATION");
		}
	});

	it("fails on one_of violation", () => {
		const metadata: FederationMetadata = {
			openid_relying_party: {
				token_endpoint_auth_method: "client_secret_post",
			},
		};
		const policy: ResolvedMetadataPolicy = {
			openid_relying_party: {
				token_endpoint_auth_method: { one_of: ["private_key_jwt", "client_secret_basic"] },
			},
		};
		const result = applyMetadataPolicy(metadata, policy);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.code).toBe("ERR_METADATA_POLICY_VIOLATION");
		}
	});

	it("fails on essential violation (missing required param)", () => {
		const metadata: FederationMetadata = {
			openid_relying_party: {},
		};
		const policy: ResolvedMetadataPolicy = {
			openid_relying_party: {
				contacts: { essential: true },
			},
		};
		const result = applyMetadataPolicy(metadata, policy);
		expect(isErr(result)).toBe(true);
		if (isErr(result)) {
			expect(result.error.code).toBe("ERR_METADATA_POLICY_VIOLATION");
		}
	});

	it("applies operators in correct order (value before add before default...)", () => {
		const metadata: FederationMetadata = {
			openid_relying_party: {},
		};
		// value sets it, then essential checks it — should pass since value provides the value
		const policy: ResolvedMetadataPolicy = {
			openid_relying_party: {
				token_endpoint_auth_method: {
					value: "private_key_jwt",
					essential: true,
				},
			},
		};
		const result = applyMetadataPolicy(metadata, policy);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.openid_relying_party?.token_endpoint_auth_method).toBe("private_key_jwt");
		}
	});

	it("handles scope normalization: string → array → operators → string", () => {
		const metadata: FederationMetadata = {
			openid_relying_party: {
				scope: "openid profile email address",
			},
		};
		const policy: ResolvedMetadataPolicy = {
			openid_relying_party: {
				scope: { subset_of: ["openid", "profile", "email"] },
			},
		};
		const result = applyMetadataPolicy(metadata, policy);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.openid_relying_party?.scope).toBe("openid profile email");
		}
	});

	it("applies superiorMetadataOverride before policy", () => {
		const metadata: FederationMetadata = {
			openid_relying_party: {
				client_name: "Old Name",
			},
		};
		const policy: ResolvedMetadataPolicy = {};
		const override: FederationMetadata = {
			openid_relying_party: {
				client_name: "Superior Override Name",
			},
		};
		const result = applyMetadataPolicy(metadata, policy, override);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.openid_relying_party?.client_name).toBe("Superior Override Name");
		}
	});

	it("removes parameter when value operator is null", () => {
		const metadata: FederationMetadata = {
			openid_relying_party: {
				client_name: "To Remove",
				scope: "openid",
			},
		};
		const policy: ResolvedMetadataPolicy = {
			openid_relying_party: {
				client_name: { value: null },
			},
		};
		const result = applyMetadataPolicy(metadata, policy);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.openid_relying_party?.client_name).toBeUndefined();
			expect(result.value.openid_relying_party?.scope).toBe("openid");
		}
	});

	it("essential=true + subset_of reducing to empty array does not error (param is present)", () => {
		const metadata: FederationMetadata = {
			openid_relying_party: {
				grant_types: ["implicit"],
			},
		};
		const policy: ResolvedMetadataPolicy = {
			openid_relying_party: {
				grant_types: {
					subset_of: ["authorization_code", "refresh_token"],
					essential: true,
				},
			},
		};
		// subset_of filters to [] (intersection of ["implicit"] and ["authorization_code","refresh_token"])
		// essential checks presence — [] is present (not undefined), so no error
		const result = applyMetadataPolicy(metadata, policy);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.openid_relying_party?.grant_types).toEqual([]);
		}
	});

	it("does not mutate original metadata", () => {
		const metadata: FederationMetadata = {
			openid_relying_party: {
				token_endpoint_auth_method: "old",
			},
		};
		const original = JSON.parse(JSON.stringify(metadata));
		const policy: ResolvedMetadataPolicy = {
			openid_relying_party: {
				token_endpoint_auth_method: { value: "new" },
			},
		};
		applyMetadataPolicy(metadata, policy);
		expect(metadata).toEqual(original);
	});

	it("skips entity types not in policy", () => {
		const metadata: FederationMetadata = {
			openid_relying_party: { client_name: "RP" },
			federation_entity: { organization_name: "Org" },
		};
		const policy: ResolvedMetadataPolicy = {
			openid_relying_party: {
				client_name: { value: "Forced RP" },
			},
		};
		const result = applyMetadataPolicy(metadata, policy);
		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.openid_relying_party?.client_name).toBe("Forced RP");
			expect(result.value.federation_entity?.organization_name).toBe("Org");
		}
	});
});
