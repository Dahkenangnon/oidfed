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
			const discovery = await discoverEntity(opId, trustAnchors);

			const result = await explicitRegistration(
				discovery,
				{
					entityId: entityId(rpId),
					signingKeys: [rp2Entity.keys.signing],
					authorityHints: [entityId(`https://ta.ofed.test:${port}`)],
					metadata: {
						openid_relying_party: {
							redirect_uris: [`${rpId}/callback`],
							response_types: ["code"],
							grant_types: ["authorization_code"],
							client_registration_types: ["explicit"],
							token_endpoint_auth_method: "private_key_jwt",
						},
					},
				},
				trustAnchors,
			);

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
			const discovery = await discoverEntity(opId, trustAnchors);

			const result = await explicitRegistration(
				discovery,
				{
					entityId: entityId(rpId),
					signingKeys: [rp2Entity.keys.signing],
					authorityHints: [entityId(`https://ia-health.ofed.test:${port}`)],
					metadata: {
						openid_relying_party: {
							redirect_uris: [`${rpId}/callback`],
							response_types: ["code"],
							grant_types: ["authorization_code"],
							client_registration_types: ["explicit"],
							token_endpoint_auth_method: "private_key_jwt",
						},
					},
				},
				trustAnchors,
			);

			expect(result.clientId).toBe(rpId);
			expect(result.registeredMetadata).toBeDefined();
			expect(result.registeredMetadata.redirect_uris).toContain(`${rpId}/callback`);
			expect(result.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
			expect(result.trustChainExpiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
		});
	});
});
