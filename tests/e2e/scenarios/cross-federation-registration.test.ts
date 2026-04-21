import { entityId } from "@oidfed/core";
import { discoverEntity } from "@oidfed/leaf";
import { automaticRegistration, explicitRegistration } from "@oidfed/oidc";
import { describe, expect, it } from "vitest";
import { getEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { multiAnchorTopology } from "../topologies/multi-anchor.js";

describe("Cross-federation registration", () => {
	describe("multi-anchor", () => {
		const getTestBed = useFederation(multiAnchorTopology);

		it("RP1 performs automatic registration with OP (same federation)", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const rpEntity = getEntity(entities, "https://rp1.ofed.test");

			const rpId = `https://rp1.ofed.test:${port}`;
			const opId = entityId(`https://op.ofed.test:${port}`);
			const discovery = await discoverEntity(opId, trustAnchors);

			const result = await automaticRegistration(
				discovery,
				{
					entityId: entityId(rpId),
					signingKeys: [rpEntity.keys.signing],
					authorityHints: [entityId(`https://ia-shared.ofed.test:${port}`)],
					metadata: {
						openid_relying_party: {
							redirect_uris: [`${rpId}/callback`],
							response_types: ["code"],
							grant_types: ["authorization_code"],
							client_registration_types: ["automatic"],
							token_endpoint_auth_method: "private_key_jwt",
						},
					},
				},
				{
					client_id: rpId,
					redirect_uri: `${rpId}/callback`,
					response_type: "code",
					scope: "openid",
				},
				trustAnchors,
			);

			expect(result.requestObjectJwt).toBeTruthy();
			expect(result.authorizationUrl).toContain(`https://op.ofed.test:${port}/auth`);
			expect(result.trustChain).toBeDefined();
		});

		it("RP2 performs explicit registration with OP selecting shared TA", async () => {
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
					authorityHints: [entityId(`https://ia-shared.ofed.test:${port}`)],
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
			expect(result.trustChainExpiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
		});
	});
});
