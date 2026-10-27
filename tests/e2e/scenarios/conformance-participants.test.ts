import { discoverEntity, entityId } from "@oidfed/core";
import { Leaf } from "@oidfed/leaf";
import { importJWK, type JWK } from "jose";
import * as client from "openid-client";
import { beforeEach, describe, expect, it } from "vitest";
import { getOidcClientEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { createLeafApp } from "../participants/leaf-app.js";
import { createOpenIDProviderApp } from "../participants/openid-provider-app.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

/** Follow this fixture's GET-only login redirects, retaining only its OP cookies. */
async function followLogin(start: string, op: string, rp: string): Promise<Response> {
	let target = new URL(start);
	const cookies = new Map<string, string>();
	for (let hop = 0; hop < 15; hop++) {
		if (target.origin !== op && target.origin !== rp)
			throw new Error("Unexpected fixture redirect");
		const response = await fetch(target, {
			redirect: "manual",
			headers: target.origin === op ? { cookie: [...cookies.values()].join("; ") } : {},
		});
		if (target.origin === op) {
			for (const raw of response.headers.getSetCookie()) {
				const cookie = raw.split(";")[0] ?? "";
				cookies.set(cookie.split("=")[0] ?? "", cookie);
			}
		}
		if (![302, 303].includes(response.status)) return response;
		const location = response.headers.get("location");
		await response.body?.cancel();
		if (!location) throw new Error("Missing fixture redirect");
		target = new URL(location, target);
	}
	throw new Error("Too many fixture login redirects");
}

describe("Disposable conformance OP integration", () => {
	const getBed = useFederation(singleAnchorTopology);

	beforeEach(() => {
		const { entities, server, trustAnchors } = getBed();
		const op = entities.get("https://op.ofed.test");
		const rp = getOidcClientEntity(entities, "https://rp.ofed.test");
		if (!op || !(op.server instanceof Leaf) || !(rp.server instanceof Leaf)) {
			throw new Error("Expected leaf fixtures");
		}
		const rpId = `https://rp.ofed.test:${server.port}`;
		server.addEntity(
			"https://op.ofed.test",
			createOpenIDProviderApp({
				leaf: op.server,
				entityId: `https://op.ofed.test:${server.port}`,
				trustAnchors,
				federationKeyProvider: op.keyProvider,
				oidcSigningKey: op.keys.protocolSigning,
				allowedRequestUriHosts: new Set(["rp.ofed.test"]),
				automaticInteractions: true,
				authorizationErrorRedirect: `${rpId}/callback`,
			}),
		);
		const app = createLeafApp(rp.server, rpId);
		app.get("/callback", (_req, res) => res.json({ received: true }));
		server.addEntity(rpId, app);
	});

	async function authorization() {
		const { entities, server, trustAnchors } = getBed();
		const opId = `https://op.ofed.test:${server.port}`;
		const rpId = `https://rp.ofed.test:${server.port}`;
		const rp = getOidcClientEntity(entities, "https://rp.ofed.test");
		const discovery = await discoverEntity(entityId(opId), trustAnchors);
		if (!discovery.ok) throw new Error("Fixture discovery failed");
		const verifier = client.randomPKCECodeVerifier();
		const state = client.randomState();
		const nonce = client.randomNonce();
		const result = await rp.oidcClient.createAuthorizationRequest(
			discovery.value,
			{
				client_id: rpId,
				response_type: "code",
				redirect_uri: `${rpId}/callback`,
				scope: "openid",
				state,
				nonce,
				code_challenge: await client.calculatePKCECodeChallenge(verifier),
				code_challenge_method: "S256",
			},
			trustAnchors,
			{ requestDelivery: "query" },
		);
		if (!result.ok || result.value.delivery !== "query") throw new Error("Fixture request failed");
		return { result: result.value, rp, rpId, opId, verifier, nonce, state };
	}

	it("completes automatic login, consent, code exchange, and ID Token validation", async () => {
		const { result, rp, rpId, opId, verifier, nonce, state } = await authorization();
		{
			const response = await followLogin(result.authorizationUrl, opId, rpId);
			expect(response.status).toBe(200);
			const callback = new URL(response.url);
			expect(callback.origin + callback.pathname).toBe(`${rpId}/callback`);
			expect(callback.searchParams.get("state")).toBe(state);
			expect(callback.searchParams.get("error")).toBeNull();
			expect(callback.searchParams.get("code")).toBeTruthy();
			const signingKey = await importJWK(
				JSON.parse(JSON.stringify(rp.keys.protocolSigning)) as JWK,
				"ES256",
			);
			if (signingKey instanceof Uint8Array) throw new Error("Expected an asymmetric key");
			const configuration = new client.Configuration(
				{
					issuer: opId,
					token_endpoint: `${opId}/token`,
					jwks_uri: `${opId}/jwks`,
				},
				rpId,
				{ token_endpoint_auth_signing_alg: "ES256", id_token_signed_response_alg: "ES256" },
				client.PrivateKeyJwt(signingKey),
			);
			const tokens = await client.authorizationCodeGrant(configuration, callback, {
				pkceCodeVerifier: verifier,
				expectedState: state,
				expectedNonce: nonce,
				idTokenExpected: true,
			});
			expect(tokens.claims()?.sub).toBe("conformance-user");
		}
	});

	it("returns errors only to the configured callback and rejects replay", async () => {
		const { result, rpId, state } = await authorization();
		const first = await fetch(result.authorizationUrl, { redirect: "manual" });
		expect(first.status).toBe(303);
		const replay = await fetch(result.authorizationUrl, { redirect: "manual" });
		expect(replay.status).toBe(302);
		const callback = new URL(replay.headers.get("location") ?? "");
		expect(callback.origin + callback.pathname).toBe(`${rpId}/callback`);
		expect(callback.searchParams.get("error")).toBe("invalid_request_object");
		expect(callback.searchParams.get("state")).toBe(state);
		const pieces = result.requestObjectJwt.split(".");
		const claims = JSON.parse(Buffer.from(pieces[1] ?? "", "base64url").toString());
		claims.redirect_uri = "https://attacker.invalid/callback";
		const malicious = new URL(result.authorizationUrl);
		malicious.searchParams.set(
			"request",
			`${pieces[0]}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${pieces[2]}`,
		);
		const rejected = await fetch(malicious, { redirect: "manual" });
		expect(rejected.status).toBe(400);
		expect(rejected.headers.get("location")).toBeNull();
	});
});
