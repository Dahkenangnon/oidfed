import { decodeEntityStatement, generateSigningKey, isOk } from "@oidfed/core";
import { createClientAssertion } from "@oidfed/oidc";
import { describe, expect, it } from "vitest";
import { getEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

describe("Client authentication", () => {
	describe("single-anchor", () => {
		const getTestBed = useFederation(singleAnchorTopology);

		it("builds valid private_key_jwt client assertion via createClientAssertion API", async () => {
			const { server, entities } = getTestBed();
			const port = server.port;

			const rpEntity = getEntity(entities, "https://rp.ofed.test");
			const rpId = `https://rp.ofed.test:${port}`;
			const opId = `https://op.ofed.test:${port}`;

			const assertion = await createClientAssertion(rpId, opId, rpEntity.keys.signing);

			expect(assertion).toBeTruthy();
			expect(assertion.split(".")).toHaveLength(3);

			const decoded = decodeEntityStatement(assertion);
			expect(isOk(decoded)).toBe(true);
			if (!isOk(decoded)) return;

			expect(decoded.value.header.alg).toBe("ES256");
			expect(decoded.value.header.typ).toBe("JWT");

			const payload = decoded.value.payload as Record<string, unknown>;
			expect(payload.iss).toBe(rpId);
			expect(payload.sub).toBe(rpId);
			expect(payload.aud).toBe(opId);
			expect(payload.jti).toBeTruthy();
			expect(payload.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
		});

		it("token request without assertion is rejected", async () => {
			const { server } = getTestBed();
			const port = server.port;

			const response = await fetch(`https://op.ofed.test:${port}/token`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					grant_type: "authorization_code",
					code: "fake-code",
					redirect_uri: `https://rp.ofed.test:${port}/callback`,
				}).toString(),
			});

			expect(response.status).toBeGreaterThanOrEqual(400);
		});

		it("rejects token request with assertion signed by wrong key", async () => {
			const { server } = getTestBed();
			const port = server.port;

			const rpId = `https://rp.ofed.test:${port}`;
			const opId = `https://op.ofed.test:${port}`;

			const wrongKey = await generateSigningKey("ES256");
			const assertion = await createClientAssertion(rpId, opId, wrongKey.privateKey);

			const response = await fetch(`${opId}/token`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					grant_type: "authorization_code",
					code: "fake-code",
					redirect_uri: `${rpId}/callback`,
					client_id: rpId,
					client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
					client_assertion: assertion,
				}).toString(),
			});

			expect(response.status).toBeGreaterThanOrEqual(400);
		});

		it("rejects token request with wrong client_assertion_type", async () => {
			const { server, entities } = getTestBed();
			const port = server.port;

			const rpEntity = getEntity(entities, "https://rp.ofed.test");
			const rpId = `https://rp.ofed.test:${port}`;
			const opId = `https://op.ofed.test:${port}`;

			const assertion = await createClientAssertion(rpId, opId, rpEntity.keys.signing);

			const response = await fetch(`${opId}/token`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					grant_type: "authorization_code",
					code: "fake-code",
					redirect_uri: `${rpId}/callback`,
					client_id: rpId,
					client_assertion_type: "urn:ietf:params:oauth:wrong-type",
					client_assertion: assertion,
				}).toString(),
			});

			expect(response.status).toBeGreaterThanOrEqual(400);
		});
	});
});
