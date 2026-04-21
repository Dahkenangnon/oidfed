import type { AuthorityServer } from "@oidfed/authority";
import { decodeEntityStatement, isOk, validateTrustMark } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { getEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

function trustMarkType(port: number): string {
	return `https://ta.ofed.test:${port}/trust-marks/certified`;
}

describe("Trust mark issuer constraints", () => {
	const getTestBed = useFederation(singleAnchorTopology);

	it("TA issues trust mark with correct claims", async () => {
		const { server, entities } = getTestBed();
		const port = server.port;

		const taInstance = getEntity(entities, "https://ta.ofed.test");
		const ta = taInstance.server as AuthorityServer;

		const rpId = `https://rp.ofed.test:${port}`;
		const taId = `https://ta.ofed.test:${port}`;

		const trustMarkJwt = await ta.issueTrustMark(rpId, trustMarkType(port));
		expect(trustMarkJwt).toBeTruthy();

		// Decode and verify trust mark claims per §8
		const decoded = decodeEntityStatement(trustMarkJwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;

		// trust_mark_type: trust mark type identifier (§8)
		expect(payload.trust_mark_type).toBe(trustMarkType(port));
		// sub: entity the trust mark is issued to
		expect(payload.sub).toBe(rpId);
		// iss: trust mark issuer (the TA)
		expect(payload.iss).toBe(taId);
		// iat: issued at
		expect(payload.iat).toBeGreaterThan(0);
	});

	it("validates trust mark when TA is authorized issuer", async () => {
		const { server, entities } = getTestBed();
		const port = server.port;

		const taInstance = getEntity(entities, "https://ta.ofed.test");
		const ta = taInstance.server as AuthorityServer;

		const rpId = `https://rp.ofed.test:${port}`;
		const taId = `https://ta.ofed.test:${port}`;

		const trustMarkJwt = await ta.issueTrustMark(rpId, trustMarkType(port));

		// Validate with TA as authorized issuer for this trust mark type
		const result = await validateTrustMark(
			trustMarkJwt,
			{ [trustMarkType(port)]: [taId] },
			{ keys: [taInstance.keys.public] },
		);

		expect(isOk(result)).toBe(true);
	});

	it("rejects trust mark when issuer is not in authorized list", async () => {
		const { server, entities } = getTestBed();
		const port = server.port;

		const taInstance = getEntity(entities, "https://ta.ofed.test");
		const ta = taInstance.server as AuthorityServer;

		const rpId = `https://rp.ofed.test:${port}`;

		const trustMarkJwt = await ta.issueTrustMark(rpId, trustMarkType(port));

		// Validate with a different entity as the only authorized issuer — should fail
		const result = await validateTrustMark(
			trustMarkJwt,
			{ [trustMarkType(port)]: ["https://other-ta.ofed.test:9999"] },
			{ keys: [taInstance.keys.public] },
		);

		expect(isOk(result)).toBe(false);
	});
});
