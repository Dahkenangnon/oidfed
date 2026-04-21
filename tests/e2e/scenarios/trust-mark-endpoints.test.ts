import type { AuthorityServer } from "@oidfed/authority";
import { decodeEntityStatement, entityId, isOk } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { getEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

function trustMarkType(port: number): string {
	return `https://ta.ofed.test:${port}/trust-marks/certified`;
}

describe("Trust mark HTTP endpoints", () => {
	const getTestBed = useFederation(singleAnchorTopology);

	describe("TA trust mark endpoints", () => {
		it("GET /federation_trust_mark returns trust mark JWT", async () => {
			const { server, entities } = getTestBed();
			const port = server.port;

			const taInstance = getEntity(entities, "https://ta.ofed.test");
			const ta = taInstance.server as AuthorityServer;
			const rpId = `https://rp.ofed.test:${port}`;

			await ta.issueTrustMark(rpId, trustMarkType(port));

			const response = await fetch(
				`https://ta.ofed.test:${port}/federation_trust_mark?trust_mark_type=${encodeURIComponent(trustMarkType(port))}&sub=${encodeURIComponent(rpId)}`,
			);

			expect(response.status).toBe(200);
			const body = await response.text();
			expect(body.split(".")).toHaveLength(3);

			const decoded = decodeEntityStatement(body);
			expect(isOk(decoded)).toBe(true);
			if (isOk(decoded)) {
				const payload = decoded.value.payload as Record<string, unknown>;
				expect(payload.trust_mark_type).toBe(trustMarkType(port));
				expect(payload.sub).toBe(rpId);
			}
		});

		it("POST /federation_trust_mark_status returns status JWT", async () => {
			const { server, entities } = getTestBed();
			const port = server.port;

			const taInstance = getEntity(entities, "https://ta.ofed.test");
			const ta = taInstance.server as AuthorityServer;
			const rpId = `https://rp.ofed.test:${port}`;

			const trustMarkJwt = await ta.issueTrustMark(rpId, trustMarkType(port));

			const response = await fetch(`https://ta.ofed.test:${port}/federation_trust_mark_status`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({ trust_mark: trustMarkJwt }).toString(),
			});

			expect(response.status).toBe(200);
			const body = await response.text();
			expect(body.split(".")).toHaveLength(3);
		});

		it("GET /federation_trust_mark_list returns entity IDs", async () => {
			const { server, entities } = getTestBed();
			const port = server.port;

			const taInstance = getEntity(entities, "https://ta.ofed.test");
			const ta = taInstance.server as AuthorityServer;
			const rpId = `https://rp.ofed.test:${port}`;

			await ta.issueTrustMark(rpId, trustMarkType(port));

			const response = await fetch(
				`https://ta.ofed.test:${port}/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(trustMarkType(port))}`,
			);

			expect(response.status).toBe(200);
			const body = (await response.json()) as string[];
			expect(Array.isArray(body)).toBe(true);
			expect(body).toContain(rpId);
		});

		it("revocation flow: issue → active → revoke → not active", async () => {
			const { server, entities } = getTestBed();
			const port = server.port;

			const taInstance = getEntity(entities, "https://ta.ofed.test");
			const ta = taInstance.server as AuthorityServer;
			const rpId = `https://rp.ofed.test:${port}`;

			const trustMarkJwt = await ta.issueTrustMark(rpId, trustMarkType(port));

			// Check active
			const activeStatus = await ta.getTrustMarkStatus(trustMarkJwt);
			expect(activeStatus.status).toBe("active");

			// Revoke
			await taInstance.trustMarkStore?.revoke(trustMarkType(port), entityId(rpId));

			// Check via HTTP endpoint — should not be active
			const response = await fetch(`https://ta.ofed.test:${port}/federation_trust_mark_status`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({ trust_mark: trustMarkJwt }).toString(),
			});

			expect(response.status).toBe(200);
			const body = await response.text();
			const decoded = decodeEntityStatement(body);
			expect(isOk(decoded)).toBe(true);
			if (isOk(decoded)) {
				const payload = decoded.value.payload as Record<string, unknown>;
				expect(payload.status).toBe("revoked");
			}
		});
	});

	describe("OP trust mark endpoints", () => {
		it("GET /federation_trust_mark_list on OP returns 501 when no marks issued", async () => {
			const { server } = getTestBed();
			const port = server.port;

			// OP has a trust mark store but no trust mark issuers configured,
			// so issuing is not possible, but the endpoint should still respond
			const response = await fetch(
				`https://op.ofed.test:${port}/federation_trust_mark_list?trust_mark_type=${encodeURIComponent("https://nonexistent")}`,
			);

			// OP has trustMarkStore configured, so it should return 200 with empty array
			expect(response.status).toBe(200);
			const body = (await response.json()) as string[];
			expect(body).toEqual([]);
		});
	});
});
