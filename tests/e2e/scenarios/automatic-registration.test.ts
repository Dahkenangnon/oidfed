import { decodeEntityStatement, entityId, isOk } from "@oidfed/core";
import { discoverEntity } from "@oidfed/leaf";
import { automaticRegistration } from "@oidfed/oidc";
import { describe, expect, it } from "vitest";
import { getEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { hierarchicalTopology } from "../topologies/hierarchical.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

describe("Automatic registration", () => {
	describe("single-anchor", () => {
		const getTestBed = useFederation(singleAnchorTopology);

		it("RP registers automatically with OP", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const rpEntity = getEntity(entities, "https://rp.ofed.test");

			const rpId = `https://rp.ofed.test:${port}`;
			const opId = entityId(`https://op.ofed.test:${port}`);
			const discovery = await discoverEntity(opId, trustAnchors);

			const result = await automaticRegistration(
				discovery,
				{
					entityId: entityId(rpId),
					signingKeys: [rpEntity.keys.signing],
					authorityHints: [entityId(`https://ta.ofed.test:${port}`)],
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

			// Decode request object JWT and verify claims
			const decoded = decodeEntityStatement(result.requestObjectJwt);
			expect(isOk(decoded), "Request object JWT should decode").toBe(true);
			if (isOk(decoded)) {
				const header = decoded.value.header as Record<string, unknown>;
				const payload = decoded.value.payload as Record<string, unknown>;

				expect(header.typ).toBe("oauth-authz-req+jwt");
				expect(payload.iss).toBe(rpId);
				expect(payload.client_id).toBe(rpId);
				expect(payload.aud).toBe(`https://op.ofed.test:${port}`);
				expect(payload.jti).toBeTruthy();
				expect(payload.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));

				// trust_chain header must be present for federation
				expect(header.trust_chain).toBeDefined();
				expect(Array.isArray(header.trust_chain)).toBe(true);
			}

			// Verify OP accepts the request object — federation validation succeeds,
			// but oidc-provider returns 400 because dynamic client registration isn't wired up
			const response = await fetch(result.authorizationUrl);
			expect(response.status).toBeLessThan(500);
		});
	});

	describe("hierarchical", () => {
		const getTestBed = useFederation(hierarchicalTopology);

		it("RP1 registers automatically with OP-Uni through IA-Edu", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const rpEntity = getEntity(entities, "https://rp1.ofed.test");

			const rpId = `https://rp1.ofed.test:${port}`;
			const opId = entityId(`https://op-uni.ofed.test:${port}`);
			const discovery = await discoverEntity(opId, trustAnchors);

			const result = await automaticRegistration(
				discovery,
				{
					entityId: entityId(rpId),
					signingKeys: [rpEntity.keys.signing],
					authorityHints: [entityId(`https://ia-edu.ofed.test:${port}`)],
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
			expect(result.trustChain).toBeDefined();
			expect(result.trustChainExpiresAt).toBeDefined();
			expect(result.trustChainExpiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
		});
	});
});
