import type { AuthorityServer } from "@oidfed/authority";
import {
	decodeEntityStatement,
	isOk,
	signTrustMarkDelegation,
	validateTrustMark,
} from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { getEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

function trustMarkType(port: number): string {
	return `https://ta.ofed.test:${port}/trust-marks/certified`;
}

describe("Trust mark delegation", () => {
	const getTestBed = useFederation(singleAnchorTopology);

	it("TA delegates TM issuance to OP via signTrustMarkDelegation", async () => {
		const { server, entities } = getTestBed();
		const port = server.port;

		const taInstance = getEntity(entities, "https://ta.ofed.test");
		const _ta = taInstance.server as AuthorityServer;
		const taId = `https://ta.ofed.test:${port}`;
		const opId = `https://op.ofed.test:${port}`;

		// TA delegates trust mark issuance to OP
		const delegationJwt = await signTrustMarkDelegation({
			issuer: taId,
			subject: opId,
			trustMarkType: trustMarkType(port),
			privateKey: taInstance.keys.signing,
		});

		expect(delegationJwt).toBeTruthy();
		expect(delegationJwt.split(".")).toHaveLength(3);

		// Decode and verify delegation claims
		const decoded = decodeEntityStatement(delegationJwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		expect(payload.iss).toBe(taId);
		expect(payload.sub).toBe(opId);
		expect(payload.trust_mark_type).toBe(trustMarkType(port));
	});

	it("TA issueTrustMarkDelegation server method returns valid delegation JWT", async () => {
		const { server, entities } = getTestBed();
		const port = server.port;

		const taInstance = getEntity(entities, "https://ta.ofed.test");
		const ta = taInstance.server as AuthorityServer;
		const taId = `https://ta.ofed.test:${port}`;
		const opId = `https://op.ofed.test:${port}`;

		const delegationJwt = await ta.issueTrustMarkDelegation(opId, trustMarkType(port));
		expect(delegationJwt).toBeTruthy();

		const decoded = decodeEntityStatement(delegationJwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		const header = decoded.value.header as Record<string, unknown>;
		expect(header.typ).toBe("trust-mark-delegation+jwt");
		expect(payload.iss).toBe(taId);
		expect(payload.sub).toBe(opId);
		expect(payload.trust_mark_type).toBe(trustMarkType(port));
	});

	it("validates trust mark without trustMarkOwners when TA issues directly", async () => {
		const { server, entities } = getTestBed();
		const port = server.port;

		const taInstance = getEntity(entities, "https://ta.ofed.test");
		const ta = taInstance.server as AuthorityServer;
		const taId = `https://ta.ofed.test:${port}`;
		const rpId = `https://rp.ofed.test:${port}`;

		// TA issues trust mark directly — no delegation needed
		const trustMarkJwt = await ta.issueTrustMark(rpId, trustMarkType(port));

		// Validate without trustMarkOwners (direct issuance by TA)
		const result = await validateTrustMark(
			trustMarkJwt,
			{ [trustMarkType(port)]: [taId] },
			{ keys: [taInstance.keys.public] },
		);

		expect(isOk(result)).toBe(true);
	});
});
