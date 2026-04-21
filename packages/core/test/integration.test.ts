import { describe, expect, it } from "vitest";
import { resolveTrustChains } from "../src/trust-chain/resolve.js";
import { validateTrustChain } from "../src/trust-chain/validate.js";
import type { EntityId } from "../src/types.js";
import { MockFederationBuilder } from "./fixtures/mock-federation.js";

describe("integration: full resolve + validate round-trip", () => {
	it("resolves and validates a 2-entity chain (leaf → TA)", async () => {
		const builder = new MockFederationBuilder();
		await builder.addTrustAnchor("https://ta.example.com");
		await builder.addLeaf("https://leaf.example.com", "https://ta.example.com", {
			metadata: {
				openid_relying_party: { client_name: "Test RP" },
				federation_entity: { organization_name: "Test Org" },
			},
		});

		const { trustAnchors, httpClient } = builder.build();

		// Resolve
		const resolveResult = await resolveTrustChains(
			"https://leaf.example.com" as EntityId,
			trustAnchors,
			{ httpClient },
		);

		expect(resolveResult.chains.length).toBe(1);
		const chain = resolveResult.chains[0] as (typeof resolveResult.chains)[number];
		expect(chain.entityId).toBe("https://leaf.example.com");
		expect(chain.trustAnchorId).toBe("https://ta.example.com");
		expect(chain.statements).toHaveLength(3);

		// Validate
		const validateResult = await validateTrustChain(chain.statements as string[], trustAnchors);

		expect(validateResult.valid).toBe(true);
		if (validateResult.valid) {
			expect(validateResult.chain.entityId).toBe("https://leaf.example.com");
			expect(validateResult.chain.trustAnchorId).toBe("https://ta.example.com");
		}
	});

	it("resolves and validates a 3-entity chain (leaf → intermediate → TA)", async () => {
		const builder = new MockFederationBuilder();
		await builder.addTrustAnchor("https://ta.example.com");
		await builder.addIntermediate("https://int.example.com", "https://ta.example.com");
		await builder.addLeaf("https://leaf.example.com", "https://int.example.com", {
			metadata: {
				openid_relying_party: { client_name: "Leaf RP" },
			},
		});

		const { trustAnchors, httpClient } = builder.build();

		const resolveResult = await resolveTrustChains(
			"https://leaf.example.com" as EntityId,
			trustAnchors,
			{ httpClient },
		);

		expect(resolveResult.chains.length).toBe(1);
		const chain = resolveResult.chains[0] as (typeof resolveResult.chains)[number];
		expect(chain.statements).toHaveLength(4); // leafEC, SS_int→leaf, SS_ta→int, taEC

		const validateResult = await validateTrustChain(chain.statements as string[], trustAnchors);

		expect(validateResult.valid).toBe(true);
	});

	it("resolves and validates a 4-entity chain (leaf → int1 → int2 → TA)", async () => {
		const builder = new MockFederationBuilder();
		await builder.addTrustAnchor("https://edugain.example.com");
		await builder.addIntermediate("https://swamid.example.com", "https://edugain.example.com");
		await builder.addIntermediate("https://umu.example.com", "https://swamid.example.com");
		await builder.addLeaf("https://op.umu.example.com", "https://umu.example.com", {
			metadata: {
				openid_provider: {
					issuer: "https://op.umu.example.com",
					authorization_endpoint: "https://op.umu.example.com/auth",
					token_endpoint: "https://op.umu.example.com/token",
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256"],
				},
			},
		});

		const { trustAnchors, httpClient } = builder.build();

		const resolveResult = await resolveTrustChains(
			"https://op.umu.example.com" as EntityId,
			trustAnchors,
			{ httpClient },
		);

		expect(resolveResult.chains.length).toBe(1);
		const chain = resolveResult.chains[0] as (typeof resolveResult.chains)[number];
		// leafEC, SS_umu→leaf, SS_swamid→umu, SS_edugain→swamid, taEC
		expect(chain.statements).toHaveLength(5);

		const validateResult = await validateTrustChain(chain.statements as string[], trustAnchors);

		expect(validateResult.valid).toBe(true);
		if (validateResult.valid) {
			expect(validateResult.chain.entityId).toBe("https://op.umu.example.com");
			expect(validateResult.chain.trustAnchorId).toBe("https://edugain.example.com");
		}
	});

	it("applies metadata policy across intermediates during validation", async () => {
		const builder = new MockFederationBuilder();
		await builder.addTrustAnchor("https://ta.example.com");
		await builder.addIntermediate("https://int.example.com", "https://ta.example.com", {
			metadataPolicy: {
				openid_relying_party: {
					scope: { subset_of: ["openid", "profile", "email"] },
					token_endpoint_auth_method: { default: "private_key_jwt" },
				},
			},
		});
		await builder.addLeaf("https://leaf.example.com", "https://int.example.com", {
			metadata: {
				openid_relying_party: {
					client_name: "Policy Leaf",
					scope: "openid profile email address",
				},
			},
		});

		const { trustAnchors, httpClient } = builder.build();

		const resolveResult = await resolveTrustChains(
			"https://leaf.example.com" as EntityId,
			trustAnchors,
			{ httpClient },
		);

		expect(resolveResult.chains.length).toBe(1);

		const validateResult = await validateTrustChain(
			resolveResult.chains[0]?.statements as string[],
			trustAnchors,
		);

		expect(validateResult.valid).toBe(true);
		if (validateResult.valid) {
			const rpMeta = validateResult.chain.resolvedMetadata.openid_relying_party;
			expect(rpMeta).toBeDefined();
			// scope should be filtered by subset_of: "address" removed
			expect(rpMeta?.scope).toBe("openid profile email");
			// token_endpoint_auth_method should get default value
			expect(rpMeta?.token_endpoint_auth_method).toBe("private_key_jwt");
		}
	});

	it("enforces constraints during validation", async () => {
		const builder = new MockFederationBuilder();
		await builder.addTrustAnchor("https://ta.example.com");
		await builder.addIntermediate("https://int.example.com", "https://ta.example.com", {
			constraints: {
				max_path_length: 1, // 1 intermediate between TA's SS (position 2) and leaf is allowed
				naming_constraints: { permitted: [".example.com"] },
			},
		});
		await builder.addLeaf("https://leaf.example.com", "https://int.example.com", {
			metadata: { openid_relying_party: { client_name: "Constrained Leaf" } },
		});

		const { trustAnchors, httpClient } = builder.build();

		const resolveResult = await resolveTrustChains(
			"https://leaf.example.com" as EntityId,
			trustAnchors,
			{ httpClient },
		);

		expect(resolveResult.chains.length).toBe(1);

		const validateResult = await validateTrustChain(
			resolveResult.chains[0]?.statements as string[],
			trustAnchors,
		);

		// max_path_length=0 at SS position 1: intermediates to leaf = 1-1 = 0 → should pass
		// naming_constraints permitted=.example.com → leaf.example.com → should pass
		expect(validateResult.valid).toBe(true);
	});

	it("rejects chain when naming constraints violated", async () => {
		const builder = new MockFederationBuilder();
		await builder.addTrustAnchor("https://ta.example.com");
		await builder.addIntermediate("https://int.example.com", "https://ta.example.com", {
			constraints: {
				naming_constraints: { permitted: [".restricted.com"] },
			},
		});
		await builder.addLeaf("https://leaf.example.com", "https://int.example.com", {
			metadata: { openid_relying_party: { client_name: "Wrong Domain Leaf" } },
		});

		const { trustAnchors, httpClient } = builder.build();

		const resolveResult = await resolveTrustChains(
			"https://leaf.example.com" as EntityId,
			trustAnchors,
			{ httpClient },
		);

		expect(resolveResult.chains.length).toBe(1);

		const validateResult = await validateTrustChain(
			resolveResult.chains[0]?.statements as string[],
			trustAnchors,
			{ verboseErrors: true },
		);

		// leaf.example.com is NOT under .restricted.com → should fail
		expect(validateResult.valid).toBe(false);
		expect(validateResult.errors.some((e) => e.code === "ERR_CONSTRAINT_VIOLATION")).toBe(true);
	});
});
