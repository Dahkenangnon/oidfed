import type { AuthorityServer } from "@oidfed/authority";
import { decodeEntityStatement, isOk, validateTrustMark } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { getEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

function trustMarkType(port: number): string {
	return `https://ta.ofed.test:${port}/trust-marks/certified`;
}

describe("Trust marks in entity configurations", () => {
	const getTestBed = useFederation(singleAnchorTopology);

	it("trust marks appear in TA entity configuration", async () => {
		const { server, entities } = getTestBed();
		const port = server.port;

		const taInstance = getEntity(entities, "https://ta.ofed.test");
		const ta = taInstance.server as AuthorityServer;
		const opId = `https://op.ofed.test:${port}`;

		// Issue trust mark to OP
		const trustMarkJwt = await ta.issueTrustMark(opId, trustMarkType(port));
		expect(trustMarkJwt).toBeTruthy();

		// Fetch TA's EC and check trust_mark_issuers is present
		const ecResponse = await fetch(`https://ta.ofed.test:${port}/.well-known/openid-federation`);
		expect(ecResponse.status).toBe(200);

		const ecJwt = await ecResponse.text();
		const decoded = decodeEntityStatement(ecJwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;

		// TA should have trust_mark_issuers in its EC
		expect(payload.trust_mark_issuers).toBeDefined();
		const issuers = payload.trust_mark_issuers as Record<string, string[]>;
		expect(issuers[trustMarkType(port)]).toBeDefined();
	});

	it("validates trust mark JWT against TA JWKS", async () => {
		const { server, entities } = getTestBed();
		const port = server.port;

		const taInstance = getEntity(entities, "https://ta.ofed.test");
		const ta = taInstance.server as AuthorityServer;
		const taId = `https://ta.ofed.test:${port}`;
		const opId = `https://op.ofed.test:${port}`;

		// Issue trust mark
		const trustMarkJwt = await ta.issueTrustMark(opId, trustMarkType(port));

		// Validate using TA's public key
		const result = await validateTrustMark(
			trustMarkJwt,
			{ [trustMarkType(port)]: [taId] },
			{ keys: [taInstance.keys.public] },
		);

		expect(isOk(result)).toBe(true);
	});

	it("trust mark has correct iss, sub, trust_mark_type claims", async () => {
		const { server, entities } = getTestBed();
		const port = server.port;

		const taInstance = getEntity(entities, "https://ta.ofed.test");
		const ta = taInstance.server as AuthorityServer;
		const taId = `https://ta.ofed.test:${port}`;
		const opId = `https://op.ofed.test:${port}`;

		const trustMarkJwt = await ta.issueTrustMark(opId, trustMarkType(port));
		const decoded = decodeEntityStatement(trustMarkJwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		expect(payload.iss).toBe(taId);
		expect(payload.sub).toBe(opId);
		expect(payload.trust_mark_type).toBe(trustMarkType(port));
		expect(payload.iat).toBeGreaterThan(0);
	});
});
