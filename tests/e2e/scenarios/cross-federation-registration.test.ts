import { entityId, FederationErrorCode } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { getOidcClientEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { crossFederationTopology } from "../topologies/cross-federation.js";
import { multiAnchorTopology } from "../topologies/multi-anchor.js";

describe("Cross-federation registration", () => {
	describe("multi-anchor", () => {
		const getTestBed = useFederation(multiAnchorTopology);

		it("RP1 performs automatic registration with OP (same federation)", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const rpEntity = getOidcClientEntity(entities, "https://rp1.ofed.test");

			const rpId = `https://rp1.ofed.test:${port}`;
			const opId = entityId(`https://op.ofed.test:${port}`);

			const resultVal = await rpEntity.oidcClient.automaticallyRegister(
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
			expect(result.trustChain).toBeDefined();
		});

		it("RP2 performs explicit registration with OP selecting shared TA", async () => {
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
			expect(result.trustChainExpiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
		});
	});

	describe("disjoint federations", () => {
		const getTestBed = useFederation(crossFederationTopology);

		it("RP-X automatic registration with OP-Y fails without a shared Trust Anchor", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;
			const rpEntity = getOidcClientEntity(entities, "https://rp-x.ofed.test");
			const rpId = `https://rp-x.ofed.test:${port}`;
			const opId = entityId(`https://op-y.ofed.test:${port}`);

			const resultVal = await rpEntity.oidcClient.automaticallyRegister(
				{
					opEntityId: opId,
					redirect_uri: `${rpId}/callback`,
					scope: "openid",
					requestDelivery: "query",
				},
				{ trustAnchors },
			);

			expect(resultVal.ok).toBe(false);
			if (resultVal.ok) throw new Error("Registration unexpectedly succeeded");
			expect(resultVal.error.code).toBe(FederationErrorCode.InvalidTrustAnchor);
			expect(resultVal.error.description).toContain("No shared Trust Anchor");
		});

		it("RP-X explicit registration with OP-Y fails without a shared Trust Anchor", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;
			const rpEntity = getOidcClientEntity(entities, "https://rp-x.ofed.test");
			const opId = entityId(`https://op-y.ofed.test:${port}`);

			const resultVal = await rpEntity.oidcClient.explicitlyRegister(opId, { trustAnchors });

			expect(resultVal.ok).toBe(false);
			if (resultVal.ok) throw new Error("Registration unexpectedly succeeded");
			expect(resultVal.error.code).toBe(FederationErrorCode.InvalidTrustAnchor);
			expect(resultVal.error.description).toContain("No shared Trust Anchor");
		});
	});
});
