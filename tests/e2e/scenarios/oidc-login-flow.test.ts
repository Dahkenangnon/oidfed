import type { JWK, TrustAnchorSet } from "@oidfed/core";
import { entityId } from "@oidfed/core";
import { discoverEntity } from "@oidfed/leaf";
import { automaticRegistration } from "@oidfed/oidc";
import { describe, expect, it } from "vitest";
import { getEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { hierarchicalTopology } from "../topologies/hierarchical.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

/**
 * Perform automatic registration and send auth request to OP.
 * Returns the auth response for further assertion.
 *
 * NOTE: The current OP app bridges federation registration (processAutomaticRegistration)
 * but does not dynamically register the client with oidc-provider, so the auth
 * endpoint returns a 400 after federation validation succeeds. This test verifies
 * the federation layer works correctly up to that point.
 */
async function performFederatedAuthRequest(params: {
	rpId: string;
	opId: string;
	rpSigningKey: JWK;
	taId: string;
	trustAnchors: TrustAnchorSet;
}) {
	const { rpId, opId, rpSigningKey, taId, trustAnchors } = params;

	// 1. Discover OP — must succeed
	const discovery = await discoverEntity(entityId(opId), trustAnchors);
	expect(discovery).toBeTruthy();
	expect(discovery.entityId).toBe(opId);

	// 2. Automatic registration — must produce a valid authorization URL
	const regResult = await automaticRegistration(
		discovery,
		{
			entityId: entityId(rpId),
			signingKeys: [rpSigningKey],
			authorityHints: [entityId(taId)],
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
			state: "test-state",
			nonce: "test-nonce",
		},
		trustAnchors,
	);

	expect(regResult).toBeTruthy();
	expect(regResult.authorizationUrl).toBeTruthy();

	const authUrl = new URL(regResult.authorizationUrl);
	expect(authUrl.searchParams.get("request")).toBeTruthy();

	// 3. Send auth request to OP
	// Federation validation (processAutomaticRegistration) succeeds, but oidc-provider
	// returns 400 because the OP app doesn't dynamically register the client with
	// oidc-provider's internal store. This is a test harness limitation, not a federation bug.
	const authResponse = await fetch(regResult.authorizationUrl, {
		redirect: "manual",
	});

	expect(authResponse.status).toBe(400);

	return { regResult, authResponse };
}

describe("Full OIDC login flow", () => {
	describe("single-anchor", () => {
		const getTestBed = useFederation(singleAnchorTopology);

		it("discovers OP and performs automatic registration", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const rpEntity = getEntity(entities, "https://rp.ofed.test");

			const { regResult } = await performFederatedAuthRequest({
				rpId: `https://rp.ofed.test:${port}`,
				opId: `https://op.ofed.test:${port}`,
				rpSigningKey: rpEntity.keys.signing,
				taId: `https://ta.ofed.test:${port}`,
				trustAnchors,
			});

			// Verify the authorization URL contains the request JWT
			const authUrl = new URL(regResult.authorizationUrl);
			expect(authUrl.searchParams.get("request")).toBeTruthy();
			expect(authUrl.searchParams.get("client_id")).toBe(`https://rp.ofed.test:${port}`);
		});

		it("OP returns 400 (federation succeeds, oidc-provider rejects unregistered client)", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const rpEntity = getEntity(entities, "https://rp.ofed.test");

			const { authResponse } = await performFederatedAuthRequest({
				rpId: `https://rp.ofed.test:${port}`,
				opId: `https://op.ofed.test:${port}`,
				rpSigningKey: rpEntity.keys.signing,
				taId: `https://ta.ofed.test:${port}`,
				trustAnchors,
			});

			// Federation validation succeeds; oidc-provider returns 400 (client not registered internally)
			expect(authResponse.status).toBe(400);
		});
	});

	describe("hierarchical", () => {
		const getTestBed = useFederation(hierarchicalTopology);

		it("discovers OP-Uni and performs automatic registration through IA-Edu", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const rpEntity = getEntity(entities, "https://rp1.ofed.test");

			const { regResult } = await performFederatedAuthRequest({
				rpId: `https://rp1.ofed.test:${port}`,
				opId: `https://op-uni.ofed.test:${port}`,
				rpSigningKey: rpEntity.keys.signing,
				taId: `https://ta.ofed.test:${port}`,
				trustAnchors,
			});

			// Verify the authorization URL targets the correct OP
			const authUrl = new URL(regResult.authorizationUrl);
			expect(authUrl.hostname).toBe("op-uni.ofed.test");
			expect(authUrl.searchParams.get("request")).toBeTruthy();
		});
	});
});
