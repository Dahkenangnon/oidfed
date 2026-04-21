import { entityId, resolveTrustChains, validateTrustChain } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { useFederation } from "../helpers/lifecycle.js";
import { policyOperatorsTopology } from "../topologies/policy-operators.js";

describe("Metadata policy operators", () => {
	const getTestBed = useFederation(policyOperatorsTopology);

	it("value operator overrides token_endpoint_auth_methods_supported", async () => {
		const { server, trustAnchors } = getTestBed();
		const port = server.port;

		const opId = entityId(`https://op.ofed.test:${port}`);
		const resolved = await resolveTrustChains(opId, trustAnchors);
		expect(resolved.chains).toHaveLength(1);

		const validation = await validateTrustChain([...resolved.chains[0].statements], trustAnchors);
		expect(validation.valid).toBe(true);
		if (!validation.valid) return;

		const opMetadata = validation.chain.resolvedMetadata.openid_provider as Record<string, unknown>;

		// `value` operator forces token_endpoint_auth_methods_supported to ["private_key_jwt"]
		// regardless of the OP's original claim of ["client_secret_basic"]
		expect(opMetadata.token_endpoint_auth_methods_supported).toEqual(["private_key_jwt"]);
	});

	it("add operator appends ES256 to id_token_signing_alg_values_supported", async () => {
		const { server, trustAnchors } = getTestBed();
		const port = server.port;

		const opId = entityId(`https://op.ofed.test:${port}`);
		const resolved = await resolveTrustChains(opId, trustAnchors);
		const validation = await validateTrustChain([...resolved.chains[0].statements], trustAnchors);
		expect(validation.valid).toBe(true);
		if (!validation.valid) return;

		const opMetadata = validation.chain.resolvedMetadata.openid_provider as Record<string, unknown>;

		// `add` operator adds "ES256" to the OP's original ["RS256"]
		const algValues = opMetadata.id_token_signing_alg_values_supported as string[];
		expect(algValues).toContain("RS256");
		expect(algValues).toContain("ES256");
	});

	it("subset_of operator intersects grant_types_supported", async () => {
		const { server, trustAnchors } = getTestBed();
		const port = server.port;

		const opId = entityId(`https://op.ofed.test:${port}`);
		const resolved = await resolveTrustChains(opId, trustAnchors);
		const validation = await validateTrustChain([...resolved.chains[0].statements], trustAnchors);
		expect(validation.valid).toBe(true);
		if (!validation.valid) return;

		const opMetadata = validation.chain.resolvedMetadata.openid_provider as Record<string, unknown>;

		// subset_of ["authorization_code"] intersected with OP's ["authorization_code"] = ["authorization_code"]
		expect(opMetadata.grant_types_supported).toEqual(["authorization_code"]);
	});

	it("essential operator requires subject_types_supported to be present", async () => {
		const { server, trustAnchors } = getTestBed();
		const port = server.port;

		const opId = entityId(`https://op.ofed.test:${port}`);
		const resolved = await resolveTrustChains(opId, trustAnchors);
		const validation = await validateTrustChain([...resolved.chains[0].statements], trustAnchors);
		expect(validation.valid).toBe(true);
		if (!validation.valid) return;

		const opMetadata = validation.chain.resolvedMetadata.openid_provider as Record<string, unknown>;

		// essential: true means the claim must be present — OP declares it as ["public"]
		expect(opMetadata.subject_types_supported).toEqual(["public"]);
	});
});
