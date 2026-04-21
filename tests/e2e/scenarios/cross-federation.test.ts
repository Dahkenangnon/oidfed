import { entityId, resolveTrustChains } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { useFederation } from "../helpers/lifecycle.js";
import { crossFederationTopology } from "../topologies/cross-federation.js";
import { multiAnchorTopology } from "../topologies/multi-anchor.js";

describe("Cross-federation trust", () => {
	describe("cross-federation topology", () => {
		const getTestBed = useFederation(crossFederationTopology);

		it("resolves trust chain within federation X", async () => {
			const { server, trustAnchors } = getTestBed();
			const port = server.port;

			const rpXId = entityId(`https://rp-x.ofed.test:${port}`);
			const result = await resolveTrustChains(rpXId, trustAnchors);

			expect(result.errors).toHaveLength(0);
			expect(result.chains.length).toBeGreaterThanOrEqual(1);

			// Should have a chain to TA-X
			const chainToX = result.chains.find(
				(c) => c.trustAnchorId === entityId(`https://ta-x.ofed.test:${port}`),
			);
			expect(chainToX).toBeDefined();
		});

		it("resolves trust chain within federation Y", async () => {
			const { server, trustAnchors } = getTestBed();
			const port = server.port;

			const rpYId = entityId(`https://rp-y.ofed.test:${port}`);
			const result = await resolveTrustChains(rpYId, trustAnchors);

			expect(result.errors).toHaveLength(0);
			expect(result.chains.length).toBeGreaterThanOrEqual(1);

			const chainToY = result.chains.find(
				(c) => c.trustAnchorId === entityId(`https://ta-y.ofed.test:${port}`),
			);
			expect(chainToY).toBeDefined();
		});

		it("bridge entity resolves to both trust anchors", async () => {
			const { server, trustAnchors } = getTestBed();
			const port = server.port;

			const bridgeId = entityId(`https://bridge.ofed.test:${port}`);
			const result = await resolveTrustChains(bridgeId, trustAnchors);

			expect(result.chains.length).toBe(2);

			const anchorIds = result.chains.map((c) => c.trustAnchorId).sort();
			expect(anchorIds).toContain(entityId(`https://ta-x.ofed.test:${port}`));
			expect(anchorIds).toContain(entityId(`https://ta-y.ofed.test:${port}`));
		});
	});

	describe("multi-anchor topology", () => {
		const getTestBed = useFederation(multiAnchorTopology);

		it("IA-Shared resolves to both trust anchors", async () => {
			const { server, trustAnchors } = getTestBed();
			const port = server.port;

			const iaId = entityId(`https://ia-shared.ofed.test:${port}`);
			const result = await resolveTrustChains(iaId, trustAnchors);

			expect(result.chains.length).toBe(2);

			const anchorIds = result.chains.map((c) => c.trustAnchorId).sort();
			expect(anchorIds).toContain(entityId(`https://ta-gov.ofed.test:${port}`));
			expect(anchorIds).toContain(entityId(`https://ta-industry.ofed.test:${port}`));
		});

		it("OP resolves chains to both trust anchors", async () => {
			const { server, trustAnchors } = getTestBed();
			const port = server.port;

			const opId = entityId(`https://op.ofed.test:${port}`);
			const result = await resolveTrustChains(opId, trustAnchors);

			expect(result.chains.length).toBe(2);
		});
	});
});
