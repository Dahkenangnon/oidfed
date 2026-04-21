import { entityId, resolveTrustChains, validateTrustChain } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { useFederation } from "../helpers/lifecycle.js";
import { hierarchicalTopology } from "../topologies/hierarchical.js";

describe("Metadata policy enforcement", () => {
	describe("hierarchical", () => {
		const getTestBed = useFederation(hierarchicalTopology);

		it("validates trust chain and resolves metadata with policy defaults for OP-Uni (edu branch)", async () => {
			const { server, trustAnchors } = getTestBed();
			const port = server.port;

			const opId = entityId(`https://op-uni.ofed.test:${port}`);
			const result = await resolveTrustChains(opId, trustAnchors);

			expect(result.errors).toHaveLength(0);
			expect(result.chains).toHaveLength(1);

			const chain = result.chains[0];
			expect(chain.statements).toHaveLength(4);

			// Validate the chain and get resolved metadata
			const validation = await validateTrustChain([...chain.statements], trustAnchors);
			expect(validation.valid).toBe(true);
			expect(validation.chain).toBeDefined();

			const resolved = validation.chain?.resolvedMetadata;
			expect(resolved.openid_provider).toBeDefined();
			expect(resolved.openid_provider?.token_endpoint_auth_methods_supported).toEqual([
				"private_key_jwt",
			]);
		});

		it("validates trust chain and resolves metadata with policy defaults for OP-Hospital (health branch)", async () => {
			const { server, trustAnchors } = getTestBed();
			const port = server.port;

			const opId = entityId(`https://op-hospital.ofed.test:${port}`);
			const result = await resolveTrustChains(opId, trustAnchors);

			expect(result.errors).toHaveLength(0);
			expect(result.chains).toHaveLength(1);

			const chain = result.chains[0];

			const validation = await validateTrustChain([...chain.statements], trustAnchors);
			expect(validation.valid).toBe(true);
			expect(validation.chain).toBeDefined();

			const resolved = validation.chain?.resolvedMetadata;
			expect(resolved.openid_provider).toBeDefined();
			expect(resolved.openid_provider?.token_endpoint_auth_methods_supported).toEqual([
				"private_key_jwt",
			]);
		});

		it("both IA branches resolve through the same TA", async () => {
			const { server, trustAnchors } = getTestBed();
			const port = server.port;

			const opUniId = entityId(`https://op-uni.ofed.test:${port}`);
			const opHospitalId = entityId(`https://op-hospital.ofed.test:${port}`);

			const [uniResult, hospitalResult] = await Promise.all([
				resolveTrustChains(opUniId, trustAnchors),
				resolveTrustChains(opHospitalId, trustAnchors),
			]);

			expect(uniResult.chains).toHaveLength(1);
			expect(hospitalResult.chains).toHaveLength(1);

			expect(uniResult.chains[0]?.trustAnchorId).toBe(hospitalResult.chains[0]?.trustAnchorId);
		});
	});
});
