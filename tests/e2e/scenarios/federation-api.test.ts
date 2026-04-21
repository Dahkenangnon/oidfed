import type { AuthorityServer } from "@oidfed/authority";
import type { JWK } from "@oidfed/core";
import { decodeEntityStatement, generateSigningKey, isOk } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { getEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

describe("Federation API endpoints", () => {
	const getTestBed = useFederation(singleAnchorTopology);

	it("GET /federation_resolve returns resolved chain JWT", async () => {
		const { server } = getTestBed();
		const port = server.port;

		const response = await fetch(
			`https://ta.ofed.test:${port}/federation_resolve?sub=${encodeURIComponent(`https://rp.ofed.test:${port}`)}&trust_anchor=${encodeURIComponent(`https://ta.ofed.test:${port}`)}`,
		);

		expect(response.status).toBe(200);
		const body = await response.text();
		expect(body.split(".")).toHaveLength(3);

		const decoded = decodeEntityStatement(body);
		expect(isOk(decoded)).toBe(true);
	});

	it("GET /federation_list returns subordinate entity IDs", async () => {
		const { server } = getTestBed();
		const port = server.port;

		const response = await fetch(`https://ta.ofed.test:${port}/federation_list`);

		expect(response.status).toBe(200);
		const body = (await response.json()) as string[];
		expect(Array.isArray(body)).toBe(true);
		expect(body.length).toBeGreaterThan(0);

		// TA has OP, RP, RP2 as subordinates
		expect(body).toContain(`https://op.ofed.test:${port}`);
		expect(body).toContain(`https://rp.ofed.test:${port}`);
		expect(body).toContain(`https://rp2.ofed.test:${port}`);
	});

	it("GET /federation_list?entity_type= filters by entity type", async () => {
		const { server } = getTestBed();
		const port = server.port;

		const response = await fetch(
			`https://ta.ofed.test:${port}/federation_list?entity_type=openid_provider`,
		);

		expect(response.status).toBe(200);
		const body = (await response.json()) as string[];
		expect(Array.isArray(body)).toBe(true);
		expect(body).toContain(`https://op.ofed.test:${port}`);
		// RPs should not appear in openid_provider filter
		expect(body).not.toContain(`https://rp.ofed.test:${port}`);
	});

	it("GET /federation_fetch?sub= returns subordinate statement JWT", async () => {
		const { server } = getTestBed();
		const port = server.port;

		const response = await fetch(
			`https://ta.ofed.test:${port}/federation_fetch?sub=${encodeURIComponent(`https://op.ofed.test:${port}`)}`,
		);

		expect(response.status).toBe(200);
		expect(response.headers.get("content-type")).toContain("application/entity-statement+jwt");
		const body = await response.text();
		expect(body.split(".")).toHaveLength(3);

		const decoded = decodeEntityStatement(body);
		expect(isOk(decoded)).toBe(true);
		if (isOk(decoded)) {
			const payload = decoded.value.payload as Record<string, unknown>;
			// Subordinate statement: iss = TA, sub = OP
			expect(payload.iss).toBe(`https://ta.ofed.test:${port}`);
			expect(payload.sub).toBe(`https://op.ofed.test:${port}`);
		}
	});

	it("historical keys contain old kid after TA key rotation", async () => {
		const { entities } = getTestBed();

		const taInstance = getEntity(entities, "https://ta.ofed.test");
		const ta = taInstance.server as AuthorityServer;

		// Get original kid
		const originalEc = await ta.getEntityConfiguration();
		const originalDecoded = decodeEntityStatement(originalEc);
		expect(isOk(originalDecoded)).toBe(true);
		if (!isOk(originalDecoded)) return;
		const originalKid = originalDecoded.value.header.kid as string;

		// Rotate
		const newKey = await generateSigningKey("ES256");
		await ta.rotateSigningKey(newKey.privateKey as JWK);

		// Historical keys should include old kid
		const historicalJwt = await ta.getHistoricalKeys();
		expect(historicalJwt).toBeTruthy();

		const historicalDecoded = decodeEntityStatement(historicalJwt as string);
		expect(isOk(historicalDecoded)).toBe(true);
		if (isOk(historicalDecoded)) {
			const payload = historicalDecoded.value.payload as Record<string, unknown>;
			const keys = payload.keys as Array<{ kid?: string }>;
			const kids = keys.map((k) => k.kid);
			expect(kids).toContain(originalKid);
		}
	});
});
