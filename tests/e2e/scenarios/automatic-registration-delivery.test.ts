import { decodeEntityStatement, entityId, isOk } from "@oidfed/core";
import { discoverEntity } from "@oidfed/leaf";
import { automaticRegistration } from "@oidfed/oidc";
import { describe, expect, it } from "vitest";
import { getEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

/**
 * Per-delivery-mode end-to-end exercises against a real federation OP.
 * The TAP unit tests in `tests/tap/packages/oidc.ts` pin the lib contract for
 * each mode with a mocked httpClient; these tests prove the same lib also
 * composes correctly against a real OP test bed.
 */
describe("Automatic registration — Request Object delivery modes", () => {
	describe("single-anchor", () => {
		const getTestBed = useFederation(singleAnchorTopology);

		it("form_post: returns formParams + authorizationEndpoint; POST is accepted by OP", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const rpEntity = getEntity(entities, "https://rp.ofed.test");
			const rpId = `https://rp.ofed.test:${port}`;
			const opId = entityId(`https://op.ofed.test:${port}`);
			const discoveryResult = await discoverEntity(opId, trustAnchors);
			expect(discoveryResult.ok).toBe(true);
			if (!discoveryResult.ok) throw new Error("Discovery failed");
			const discovery = discoveryResult.value;

			const resultVal = await automaticRegistration(
				discovery,
				{
					entityId: entityId(rpId),
					protocolKeyProvider: rpEntity.oidcProtocolKeyProvider,
					authorityHints: [entityId(`https://ta.ofed.test:${port}`)],
					metadata: {
						openid_relying_party: {
							redirect_uris: [`${rpId}/callback`],
							response_types: ["code"],
							grant_types: ["authorization_code"],
							client_registration_types: ["automatic"],
							token_endpoint_auth_method: "private_key_jwt",
							jwks: { keys: [rpEntity.keys.protocolPublic] },
						},
					},
					requestDelivery: "form_post",
				},
				{
					client_id: rpId,
					redirect_uri: `${rpId}/callback`,
					response_type: "code",
					scope: "openid",
				},
				trustAnchors,
			);

			expect(resultVal.ok).toBe(true);
			if (!resultVal.ok) throw new Error("Registration failed");
			const result = resultVal.value;

			expect(result.delivery).toBe("form_post");
			if (result.delivery !== "form_post") return;
			expect(result.authorizationEndpoint).toContain(`https://op.ofed.test:${port}/auth`);
			expect(result.formParams.request).toBe(result.requestObjectJwt);
			expect(result.formParams.client_id).toBe(rpId);

			const decoded = decodeEntityStatement(result.requestObjectJwt);
			expect(isOk(decoded)).toBe(true);
			if (isOk(decoded)) {
				const payload = decoded.value.payload as Record<string, unknown>;
				expect(payload.aud).toBe(`https://op.ofed.test:${port}`);
				expect(payload.client_id).toBe(rpId);
			}

			// POST the formParams to the authorization endpoint — verifies the OP
			// at minimum doesn't 5xx on a Request Object delivered via POST.
			const body = new URLSearchParams(result.formParams).toString();
			const response = await fetch(result.authorizationEndpoint, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body,
			});
			expect(response.status).toBeLessThan(500);
		});

		it("par: lib POSTs to PAR endpoint and returns urn-style authorizationUrl", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const rpEntity = getEntity(entities, "https://rp.ofed.test");
			const rpId = `https://rp.ofed.test:${port}`;
			const opId = entityId(`https://op.ofed.test:${port}`);
			const discoveryResult = await discoverEntity(opId, trustAnchors);
			expect(discoveryResult.ok).toBe(true);
			if (!discoveryResult.ok) throw new Error("Discovery failed");
			const discovery = discoveryResult.value;

			const resultVal = await automaticRegistration(
				discovery,
				{
					entityId: entityId(rpId),
					protocolKeyProvider: rpEntity.oidcProtocolKeyProvider,
					authorityHints: [entityId(`https://ta.ofed.test:${port}`)],
					metadata: {
						openid_relying_party: {
							redirect_uris: [`${rpId}/callback`],
							response_types: ["code"],
							grant_types: ["authorization_code"],
							client_registration_types: ["automatic"],
							token_endpoint_auth_method: "private_key_jwt",
							jwks: { keys: [rpEntity.keys.protocolPublic] },
						},
					},
					requestDelivery: "par",
				},
				{
					client_id: rpId,
					redirect_uri: `${rpId}/callback`,
					response_type: "code",
					scope: "openid",
				},
				trustAnchors,
			);

			expect(resultVal.ok).toBe(true);
			if (!resultVal.ok) throw new Error("Registration failed");
			const result = resultVal.value;

			expect(result.delivery).toBe("par");
			if (result.delivery !== "par") return;
			expect(result.pushedAuthorizationRequestEndpoint).toBe(
				`https://op.ofed.test:${port}/request`,
			);
			expect(result.parRequestUri.startsWith("urn:ietf:params:oauth:request_uri:")).toBe(true);
			const url = new URL(result.authorizationUrl);
			expect(url.searchParams.get("request_uri")).toBe(result.parRequestUri);
			expect(url.searchParams.get("client_id")).toBe(rpId);
			expect(result.parExpiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
		});

		it("request_uri: returns authorizationUrl referencing the caller-supplied URL", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const rpEntity = getEntity(entities, "https://rp.ofed.test");
			const rpId = `https://rp.ofed.test:${port}`;
			const opId = entityId(`https://op.ofed.test:${port}`);
			const discoveryResult = await discoverEntity(opId, trustAnchors);
			expect(discoveryResult.ok).toBe(true);
			if (!discoveryResult.ok) throw new Error("Discovery failed");
			const discovery = discoveryResult.value;

			const hostedUri = `${rpId}/request-object/abc123`;

			const resultVal = await automaticRegistration(
				discovery,
				{
					entityId: entityId(rpId),
					protocolKeyProvider: rpEntity.oidcProtocolKeyProvider,
					authorityHints: [entityId(`https://ta.ofed.test:${port}`)],
					metadata: {
						openid_relying_party: {
							redirect_uris: [`${rpId}/callback`],
							response_types: ["code"],
							grant_types: ["authorization_code"],
							client_registration_types: ["automatic"],
							token_endpoint_auth_method: "private_key_jwt",
							jwks: { keys: [rpEntity.keys.protocolPublic] },
						},
					},
					requestDelivery: "request_uri",
					requestUri: hostedUri,
				},
				{
					client_id: rpId,
					redirect_uri: `${rpId}/callback`,
					response_type: "code",
					scope: "openid",
				},
				trustAnchors,
			);

			expect(resultVal.ok).toBe(true);
			if (!resultVal.ok) throw new Error("Registration failed");
			const result = resultVal.value;

			expect(result.delivery).toBe("request_uri");
			if (result.delivery !== "request_uri") return;
			expect(result.requestUri).toBe(hostedUri);
			const url = new URL(result.authorizationUrl);
			expect(url.searchParams.get("request_uri")).toBe(hostedUri);
			expect(url.searchParams.get("client_id")).toBe(rpId);
			expect(url.searchParams.get("request")).toBeNull();
		});
	});
});
