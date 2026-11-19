import type { JWK } from "@oidfed/core";
import { decodeEntityStatement, isOk, verifyHistoricalKeysResponse } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import {
	fixtureSigner,
	generateSigningKey,
	testEngine,
} from "../../tap/fixtures/software-crypto.js";
import { federationSigningKey, getAuthorityEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

describe("Federation API endpoints", () => {
	const getTestBed = useFederation(singleAnchorTopology);

	it("GET /federation_resolve returns resolved chain JWT", async () => {
		const { server, entities } = getTestBed();
		const port = server.port;

		await getAuthorityEntity(entities, "https://ta.ofed.test").server.resolveEntity(
			`https://rp.ofed.test:${port}` as import("@oidfed/core").EntityId,
			`https://ta.ofed.test:${port}` as import("@oidfed/core").EntityId,
		);
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
		const { entities, server } = getTestBed();

		const taInstance = getAuthorityEntity(entities, "https://ta.ofed.test");
		const ta = taInstance.server;

		// Get original kid
		const originalEc = await ta.getEntityConfiguration();
		const originalDecoded = decodeEntityStatement(originalEc);
		expect(isOk(originalDecoded)).toBe(true);
		if (!isOk(originalDecoded)) return;
		const originalKid = originalDecoded.value.header.kid as string;

		// Rotate
		const newKey = await generateSigningKey("ES256");
		const crypto = taInstance.crypto;
		const nextSigningKey = federationSigningKey(newKey.privateKey as JWK);
		await crypto.keyring.publish("federation", fixtureSigner(nextSigningKey));
		await crypto.keyring.activate("federation", nextSigningKey.signer.kid);
		await crypto.keyring.retire("federation", originalKid);

		const response = await fetch(`https://ta.ofed.test:${server.port}/federation_historical_keys`);
		expect(response.status).toBe(200);
		expect(response.headers.get("Content-Type")).toBe("application/jwk-set+jwt");
		const verified = await verifyHistoricalKeysResponse(
			await response.text(),
			(await crypto.keyring.entry("federation")).publishedJwks,
			{ expectedIssuer: `https://ta.ofed.test:${server.port}`, engine: testEngine },
		);
		expect(verified.ok).toBe(true);
		if (verified.ok) expect(verified.value.keys.map((key) => key.kid)).toEqual([originalKid]);
	});
});
