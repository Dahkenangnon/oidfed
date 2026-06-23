import { entityId } from "@oidfed/core";
import { discoverEntity } from "@oidfed/leaf";
import { explicitRegistration } from "@oidfed/oidc";
import { describe, expect, it } from "vitest";
import { getEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { hierarchicalTopology } from "../topologies/hierarchical.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

describe("Explicit registration", () => {
	describe("single-anchor", () => {
		const getTestBed = useFederation(singleAnchorTopology);

		it("RP2 registers explicitly with OP", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const rp2Entity = getEntity(entities, "https://rp2.ofed.test");

			const rpId = `https://rp2.ofed.test:${port}`;
			const opId = entityId(`https://op.ofed.test:${port}`);
			const discoveryResult = await discoverEntity(opId, trustAnchors);
			expect(discoveryResult.ok).toBe(true);
			if (!discoveryResult.ok) throw new Error("Discovery failed");
			const discovery = discoveryResult.value;

			const resultVal = await explicitRegistration(
				discovery,
				{
					entityId: entityId(rpId),
					keyProvider: rp2Entity.keyProvider,
					authorityHints: [entityId(`https://ta.ofed.test:${port}`)],
					metadata: {
						openid_relying_party: {
							redirect_uris: [`${rpId}/callback`],
							response_types: ["code"],
							grant_types: ["authorization_code"],
							client_registration_types: ["explicit"],
							token_endpoint_auth_method: "private_key_jwt",
							jwks: { keys: [rp2Entity.keys.protocolPublic] },
						},
					},
				},
				trustAnchors,
			);

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

			const rp2Entity = getEntity(entities, "https://rp2.ofed.test");

			const rpId = `https://rp2.ofed.test:${port}`;
			const opId = entityId(`https://op-hospital.ofed.test:${port}`);
			const discoveryResult = await discoverEntity(opId, trustAnchors);
			expect(discoveryResult.ok).toBe(true);
			if (!discoveryResult.ok) throw new Error("Discovery failed");
			const discovery = discoveryResult.value;

			const resultVal = await explicitRegistration(
				discovery,
				{
					entityId: entityId(rpId),
					keyProvider: rp2Entity.keyProvider,
					authorityHints: [entityId(`https://ia-health.ofed.test:${port}`)],
					metadata: {
						openid_relying_party: {
							redirect_uris: [`${rpId}/callback`],
							response_types: ["code"],
							grant_types: ["authorization_code"],
							client_registration_types: ["explicit"],
							token_endpoint_auth_method: "private_key_jwt",
							jwks: { keys: [rp2Entity.keys.protocolPublic] },
						},
					},
				},
				trustAnchors,
			);

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
