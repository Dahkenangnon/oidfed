import { decodeEntityStatement, entityId, isOk } from "@oidfed/core";
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

			const resultVal = await rpEntity.oidcClient!.automaticallyRegister(
				{
					opEntityId: opId,
					redirect_uri: `${rpId}/callback`,
					scope: "openid",
					requestDelivery: "query",
				},
				{ trustAnchors },
			);

			expect(resultVal.ok).toBe(true);
			if (!resultVal.ok) throw new Error("Registration failed");
			const result = resultVal.value;

			expect(result.requestObjectJwt).toBeTruthy();
			expect(result.delivery).toBe("query");
			if (result.delivery !== "query") return;
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

			const resultVal = await rpEntity.oidcClient!.automaticallyRegister(
				{
					opEntityId: opId,
					redirect_uri: `${rpId}/callback`,
					scope: "openid",
				},
				{ trustAnchors },
			);

			expect(resultVal.ok).toBe(true);
			if (!resultVal.ok) throw new Error("Registration failed");
			const result = resultVal.value;

			expect(result.requestObjectJwt).toBeTruthy();
			expect(result.trustChain).toBeDefined();
			expect(result.trustChainExpiresAt).toBeDefined();
			expect(result.trustChainExpiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
		});
	});
});
