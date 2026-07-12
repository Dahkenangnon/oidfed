import { entityId } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { getOidcClientEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { hierarchicalTopology } from "../topologies/hierarchical.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

describe("Explicit registration", () => {
	describe("single-anchor", () => {
		const getTestBed = useFederation(singleAnchorTopology);

		it("RP2 registers explicitly with OP", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const rp2Entity = getOidcClientEntity(entities, "https://rp2.ofed.test");

			const rpId = `https://rp2.ofed.test:${port}`;
			const opId = entityId(`https://op.ofed.test:${port}`);

			const resultVal = await rp2Entity.oidcClient.explicitlyRegister(opId, { trustAnchors });

			expect(resultVal.ok).toBe(true);
			if (!resultVal.ok) throw new Error("Registration failed");
			const result = resultVal.value;

			expect(result.clientId).toBe(rpId);
			expect(result.registeredMetadata).toBeDefined();
			expect(result.registeredMetadata.redirect_uris).toContain(`${rpId}/callback`);
			expect(result.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
			expect(result.trustChainExpiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
		});
	});

	describe("hierarchical", () => {
		const getTestBed = useFederation(hierarchicalTopology);

		it("RP2 registers explicitly with OP-Hospital through IA-Health", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const rp2Entity = getOidcClientEntity(entities, "https://rp2.ofed.test");

			const rpId = `https://rp2.ofed.test:${port}`;
			const opId = entityId(`https://op-hospital.ofed.test:${port}`);

			const resultVal = await rp2Entity.oidcClient.explicitlyRegister(opId, { trustAnchors });

			expect(resultVal.ok).toBe(true);
			if (!resultVal.ok) throw new Error("Registration failed");
			const result = resultVal.value;

			expect(result.clientId).toBe(rpId);
			expect(result.registeredMetadata).toBeDefined();
			expect(result.registeredMetadata.redirect_uris).toContain(`${rpId}/callback`);
			expect(result.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
			expect(result.trustChainExpiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
		});
	});
});
