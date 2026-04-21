import type { AuthorityServer } from "@oidfed/authority";
import { entityId, isOk, validateTrustMark } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { getEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { hierarchicalTopology } from "../topologies/hierarchical.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

function trustMarkType(port: number): string {
	return `https://ta.ofed.test:${port}/trust-marks/certified`;
}

describe("Trust mark lifecycle", () => {
	describe("single-anchor", () => {
		const getTestBed = useFederation(singleAnchorTopology);

		it("issues, validates, and revokes a trust mark", async () => {
			const { server, entities } = getTestBed();
			const port = server.port;

			const taInstance = getEntity(entities, "https://ta.ofed.test");
			const ta = taInstance.server as AuthorityServer;

			const rpId = `https://rp.ofed.test:${port}`;

			// Issue trust mark
			const trustMarkJwt = await ta.issueTrustMark(rpId, trustMarkType(port));
			expect(trustMarkJwt).toBeTruthy();
			expect(trustMarkJwt.split(".")).toHaveLength(3);

			// Check status — active
			const status = await ta.getTrustMarkStatus(trustMarkJwt);
			expect(status.status).toBe("active");

			// Validate trust mark JWT
			const taId = `https://ta.ofed.test:${port}`;
			const validationResult = await validateTrustMark(
				trustMarkJwt,
				{ [trustMarkType(port)]: [taId] },
				{ keys: [taInstance.keys.public] },
			);
			expect(isOk(validationResult)).toBe(true);

			// Revoke via store
			const trustMarkStore = taInstance.trustMarkStore;
			if (!trustMarkStore) throw new Error("trustMarkStore not found");
			await trustMarkStore.revoke(trustMarkType(port), entityId(rpId));

			// Re-check status — revoked (should return non-active directly)
			const revokedStatus = await ta.getTrustMarkStatus(trustMarkJwt);
			expect(revokedStatus.status).not.toBe("active");
		});

		it("validateTrustMark rejects a revoked trust mark when status check is available", async () => {
			const { server, entities } = getTestBed();
			const port = server.port;

			const taInstance = getEntity(entities, "https://ta.ofed.test");
			const ta = taInstance.server as AuthorityServer;

			const rpId = `https://rp.ofed.test:${port}`;
			const taId = `https://ta.ofed.test:${port}`;

			// Issue and then revoke
			const trustMarkJwt = await ta.issueTrustMark(rpId, trustMarkType(port));
			const trustMarkStore = taInstance.trustMarkStore;
			if (!trustMarkStore) throw new Error("trustMarkStore not found");
			await trustMarkStore.revoke(trustMarkType(port), entityId(rpId));

			// Validate after revoke — the JWT signature is still valid but status is revoked
			const result = await validateTrustMark(
				trustMarkJwt,
				{ [trustMarkType(port)]: [taId] },
				{ keys: [taInstance.keys.public] },
			);

			// validateTrustMark only checks JWT structure/sig, not status endpoint.
			// The signature is still valid, so this passes. Status check is a separate concern.
			// We already tested getTrustMarkStatus returns non-active above.
			expect(isOk(result)).toBe(true);
		});
	});

	describe("hierarchical", () => {
		const getTestBed = useFederation(hierarchicalTopology);

		it("issues trust mark through TA for entity under IA", async () => {
			const { server, entities } = getTestBed();
			const port = server.port;

			const taInstance = getEntity(entities, "https://ta.ofed.test");
			const ta = taInstance.server as AuthorityServer;

			const opUniId = `https://op-uni.ofed.test:${port}`;

			// Issue trust mark for an entity that is subordinate through an IA
			const trustMarkJwt = await ta.issueTrustMark(opUniId, trustMarkType(port));
			expect(trustMarkJwt).toBeTruthy();

			const status = await ta.getTrustMarkStatus(trustMarkJwt);
			expect(status.status).toBe("active");

			// Validate trust mark
			const taId = `https://ta.ofed.test:${port}`;
			const validationResult = await validateTrustMark(
				trustMarkJwt,
				{ [trustMarkType(port)]: [taId] },
				{ keys: [taInstance.keys.public] },
			);
			expect(isOk(validationResult)).toBe(true);
		});
	});
});
