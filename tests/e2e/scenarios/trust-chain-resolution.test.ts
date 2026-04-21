import { entityId, resolveTrustChains } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { useFederation } from "../helpers/lifecycle.js";
import { hierarchicalTopology } from "../topologies/hierarchical.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

describe("Trust chain resolution", () => {
	describe("single-anchor", () => {
		const getTestBed = useFederation(singleAnchorTopology);

		it("resolves 1-hop chain from RP to TA", async () => {
			const { server, trustAnchors } = getTestBed();
			const rpId = entityId(`https://rp.ofed.test:${server.port}`);

			const result = await resolveTrustChains(rpId, trustAnchors);

			expect(result.errors).toHaveLength(0);
			expect(result.chains).toHaveLength(1);

			const chain = result.chains[0];
			expect(chain.statements).toHaveLength(3); // RP EC + TA subordinate stmt + TA EC
			expect(chain.entityId).toBe(rpId);
			expect(chain.trustAnchorId).toBe(entityId(`https://ta.ofed.test:${server.port}`));
		});

		it("resolves 1-hop chain from OP to TA", async () => {
			const { server, trustAnchors } = getTestBed();
			const opId = entityId(`https://op.ofed.test:${server.port}`);

			const result = await resolveTrustChains(opId, trustAnchors);

			expect(result.errors).toHaveLength(0);
			expect(result.chains).toHaveLength(1);
			expect(result.chains[0]?.statements).toHaveLength(3);
		});

		it("resolves chain for rp2 (explicit)", async () => {
			const { server, trustAnchors } = getTestBed();
			const rp2Id = entityId(`https://rp2.ofed.test:${server.port}`);

			const result = await resolveTrustChains(rp2Id, trustAnchors);

			expect(result.errors).toHaveLength(0);
			expect(result.chains).toHaveLength(1);
		});
	});

	describe("hierarchical", () => {
		const getTestBed = useFederation(hierarchicalTopology);

		it("resolves 2-hop chain from OP-Uni through IA-Edu to TA", async () => {
			const { server, trustAnchors } = getTestBed();
			const opId = entityId(`https://op-uni.ofed.test:${server.port}`);

			const result = await resolveTrustChains(opId, trustAnchors);

			expect(result.errors).toHaveLength(0);
			expect(result.chains).toHaveLength(1);

			const chain = result.chains[0];
			// OP EC + IA sub stmt for OP + TA sub stmt for IA + TA EC = 4
			expect(chain.statements).toHaveLength(4);
			expect(chain.entityId).toBe(opId);
			expect(chain.trustAnchorId).toBe(entityId(`https://ta.ofed.test:${server.port}`));
		});

		it("resolves 2-hop chain from RP2 through IA-Health to TA", async () => {
			const { server, trustAnchors } = getTestBed();
			const rpId = entityId(`https://rp2.ofed.test:${server.port}`);

			const result = await resolveTrustChains(rpId, trustAnchors);

			expect(result.errors).toHaveLength(0);
			expect(result.chains).toHaveLength(1);
			expect(result.chains[0]?.statements).toHaveLength(4);
		});

		it("resolves chains for all leaf entities", async () => {
			const { server, trustAnchors } = getTestBed();
			const leaves = ["op-uni", "rp1", "op-hospital", "rp2"];

			for (const leaf of leaves) {
				const id = entityId(`https://${leaf}.ofed.test:${server.port}`);
				const result = await resolveTrustChains(id, trustAnchors);
				expect(result.errors, `errors for ${leaf}`).toHaveLength(0);
				expect(result.chains, `chains for ${leaf}`).toHaveLength(1);
			}
		});
	});
});
