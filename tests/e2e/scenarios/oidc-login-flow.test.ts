import { randomUUID } from "node:crypto";
import type { JWK, TrustAnchorSet } from "@oidfed/core";
import { entityId } from "@oidfed/core";
import { discoverEntity } from "@oidfed/leaf";
import type { OidcProtocolKeyProvider } from "@oidfed/oidc";
import { automaticRegistration } from "@oidfed/oidc";
import { describe, expect, it } from "vitest";
import { getEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { hierarchicalTopology } from "../topologies/hierarchical.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

/**
 * Perform automatic registration and send auth request to OP.
 * Returns the auth response for further assertion.
 *
 * The OP participant now bridges federation registration into oidc-provider's
 * client adapter, so on success the auth endpoint advances past client lookup.
 * For the GET-query delivery mode this typically yields a 302 redirect to the
 * interaction endpoint (login prompt) or a 200 HTML form. Federation-layer
 * failures still surface as 400.
 */
async function performFederatedAuthRequest(params: {
	rpId: string;
	opId: string;
	protocolKeyProvider: OidcProtocolKeyProvider;
	protocolPublicKey: JWK;
	taId: string;
	trustAnchors: TrustAnchorSet;
}) {
	const { rpId, opId, protocolKeyProvider, protocolPublicKey, taId, trustAnchors } = params;

	// 1. Discover OP — must succeed
	const discovery = await discoverEntity(entityId(opId), trustAnchors);
	expect(discovery).toBeTruthy();
	expect(discovery.entityId).toBe(opId);

	// 2. Automatic registration in GET-query mode — must produce a valid authorization URL
	const regResult = await automaticRegistration(
		discovery,
		{
			entityId: entityId(rpId),
			protocolKeyProvider,
			authorityHints: [entityId(taId)],
			metadata: {
				openid_relying_party: {
					redirect_uris: [`${rpId}/callback`],
					response_types: ["code"],
					grant_types: ["authorization_code"],
					client_registration_types: ["automatic"],
					token_endpoint_auth_method: "private_key_jwt",
					jwks: { keys: [protocolPublicKey] },
				},
			},
			requestDelivery: "query",
		},
		{
			client_id: rpId,
			redirect_uri: `${rpId}/callback`,
			response_type: "code",
			scope: "openid",
			state: "test-state",
			nonce: "test-nonce",
		},
		trustAnchors,
	);

	expect(regResult).toBeTruthy();
	expect(regResult.delivery).toBe("query");
	if (regResult.delivery !== "query") {
		throw new Error("Expected query-mode registration result");
	}
	expect(regResult.authorizationUrl).toBeTruthy();

	const authUrl = new URL(regResult.authorizationUrl);
	expect(authUrl.searchParams.get("request")).toBeTruthy();

	// 3. Send auth request to OP. The participant pre-registers the client via
	// processAutomaticRegistration, so oidc-provider proceeds past client lookup
	// and returns 302 (to its interaction endpoint) or 200 (HTML form) — anything
	// below 500. Federation-layer rejections would still surface as 400.
	const authResponse = await fetch(regResult.authorizationUrl, {
		redirect: "manual",
	});

	expect(authResponse.status).toBeLessThan(500);

	return { regResult, authResponse };
}

describe("Full OIDC login flow", () => {
	describe("single-anchor", () => {
		const getTestBed = useFederation(singleAnchorTopology);

		it("discovers OP and performs automatic registration", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const rpEntity = getEntity(entities, "https://rp.ofed.test");

			const { regResult } = await performFederatedAuthRequest({
				rpId: `https://rp.ofed.test:${port}`,
				opId: `https://op.ofed.test:${port}`,
				protocolKeyProvider: rpEntity.oidcProtocolKeyProvider,
				protocolPublicKey: rpEntity.keys.protocolPublic,
				taId: `https://ta.ofed.test:${port}`,
				trustAnchors,
			});

			// Verify the authorization URL contains the request JWT
			expect(regResult.delivery).toBe("query");
			if (regResult.delivery !== "query") return;
			const authUrl = new URL(regResult.authorizationUrl);
			expect(authUrl.searchParams.get("request")).toBeTruthy();
			expect(authUrl.searchParams.get("client_id")).toBe(`https://rp.ofed.test:${port}`);
		});

		it("OP accepts the auth request after federation pre-registration", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const rpEntity = getEntity(entities, "https://rp.ofed.test");

			const { authResponse } = await performFederatedAuthRequest({
				rpId: `https://rp.ofed.test:${port}`,
				opId: `https://op.ofed.test:${port}`,
				protocolKeyProvider: rpEntity.oidcProtocolKeyProvider,
				protocolPublicKey: rpEntity.keys.protocolPublic,
				taId: `https://ta.ofed.test:${port}`,
				trustAnchors,
			});

			// Federation pre-registration succeeded; oidc-provider proceeds past client lookup.
			expect(authResponse.status).toBeLessThan(500);
		});

		it("OP fetches Request Object from RP via request_uri delivery", async () => {
			const bed = getTestBed();
			const { server, entities, trustAnchors, requestObjectStores } = bed;
			const port = server.port;

			const rpId = `https://rp.ofed.test:${port}`;
			const opId = `https://op.ofed.test:${port}`;
			const rpEntity = getEntity(entities, "https://rp.ofed.test");

			const discovery = await discoverEntity(entityId(opId), trustAnchors);
			expect(discovery.entityId).toBe(opId);

			const hostedId = randomUUID();
			const hostedUri = `${rpId}/request-object/${hostedId}`;

			const regResult = await automaticRegistration(
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
					state: "test-state",
					nonce: "test-nonce",
				},
				trustAnchors,
			);

			expect(regResult.delivery).toBe("request_uri");
			if (regResult.delivery !== "request_uri") return;
			expect(regResult.requestUri).toBe(hostedUri);

			const store = requestObjectStores.get("https://rp.ofed.test");
			if (store === undefined) throw new Error("Expected request-object store for rp.ofed.test");
			store.set(hostedId, regResult.requestObjectJwt, 60_000);
			expect(store.has(hostedId)).toBe(true);

			const authResponse = await fetch(regResult.authorizationUrl, { redirect: "manual" });

			// The OP fetched the JWT, pre-registered, and forwarded to node-oidc-provider
			// — which advances past client lookup. Federation-layer rejections would surface as 400.
			expect(authResponse.status).toBeLessThan(500);
			// The store entry was consumed by the OP's single-use fetch.
			expect(store.has(hostedId)).toBe(false);
		});
	});

	describe("hierarchical", () => {
		const getTestBed = useFederation(hierarchicalTopology);

		it("discovers OP-Uni and performs automatic registration through IA-Edu", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const rpEntity = getEntity(entities, "https://rp1.ofed.test");

			const { regResult } = await performFederatedAuthRequest({
				rpId: `https://rp1.ofed.test:${port}`,
				opId: `https://op-uni.ofed.test:${port}`,
				protocolKeyProvider: rpEntity.oidcProtocolKeyProvider,
				protocolPublicKey: rpEntity.keys.protocolPublic,
				taId: `https://ta.ofed.test:${port}`,
				trustAnchors,
			});

			// Verify the authorization URL targets the correct OP
			expect(regResult.delivery).toBe("query");
			if (regResult.delivery !== "query") return;
			const authUrl = new URL(regResult.authorizationUrl);
			expect(authUrl.hostname).toBe("op-uni.ofed.test");
			expect(authUrl.searchParams.get("request")).toBeTruthy();
		});
	});
});
