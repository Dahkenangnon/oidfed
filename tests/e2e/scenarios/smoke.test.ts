import { decodeEntityStatement, isOk } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { useFederation } from "../helpers/lifecycle.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

/** Decode EC JWT and verify iss === sub === entityId, jwks present, exp > now */
function verifyEntityConfiguration(jwt: string, expectedEntityId: string) {
	const decoded = decodeEntityStatement(jwt);
	expect(isOk(decoded), "EC JWT should decode successfully").toBe(true);
	if (!isOk(decoded)) return;

	const payload = decoded.value.payload as Record<string, unknown>;
	expect(payload.iss).toBe(expectedEntityId);
	expect(payload.sub).toBe(expectedEntityId);
	expect(payload.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));

	const jwks = payload.jwks as { keys: unknown[] } | undefined;
	expect(jwks).toBeDefined();
	expect(jwks?.keys.length).toBeGreaterThan(0);
}

describe("E2E smoke test", () => {
	const getTestBed = useFederation(singleAnchorTopology);

	it("fetches TA entity configuration", async () => {
		const { server } = getTestBed();
		const taId = `https://ta.ofed.test:${server.port}`;
		const response = await fetch(`${taId}/.well-known/openid-federation`);
		const body = await response.text();

		expect(response.status, body).toBe(200);
		expect(response.headers.get("content-type")).toContain("application/entity-statement+jwt");
		expect(body.split(".")).toHaveLength(3);

		verifyEntityConfiguration(body, taId);
	});

	it("fetches RP entity configuration", async () => {
		const { server } = getTestBed();
		const rpId = `https://rp.ofed.test:${server.port}`;
		const response = await fetch(`${rpId}/.well-known/openid-federation`);
		const body = await response.text();

		expect(response.status, body).toBe(200);
		expect(response.headers.get("content-type")).toContain("application/entity-statement+jwt");
		expect(body.split(".")).toHaveLength(3);

		verifyEntityConfiguration(body, rpId);
	});

	it("fetches OP entity configuration", async () => {
		const { server } = getTestBed();
		const opId = `https://op.ofed.test:${server.port}`;
		const response = await fetch(`${opId}/.well-known/openid-federation`);
		const body = await response.text();

		expect(response.status, body).toBe(200);
		expect(response.headers.get("content-type")).toContain("application/entity-statement+jwt");
		expect(body.split(".")).toHaveLength(3);

		verifyEntityConfiguration(body, opId);
	});
});
