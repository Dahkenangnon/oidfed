import { discoverEntity, entityId } from "@oidfed/core";
import { Leaf } from "@oidfed/leaf";
import { importJWK, type JWK } from "jose";
import * as client from "openid-client";
import { beforeEach, describe, expect, it } from "vitest";
import { testEngine } from "../../tap/fixtures/software-crypto.js";
import { getOidcClientEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { createLeafApp } from "../participants/leaf-app.js";
import { createOpenIDProviderApp } from "../participants/openid-provider-app.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

/** Submit the initial request, then follow GET redirects while retaining only the OP's cookies. */
async function followLogin(
	start: string,
	op: string,
	rp: string,
	initialBody?: URLSearchParams,
): Promise<Response> {
	let target = new URL(start);
	let body = initialBody;
	const cookies = new Map<string, string>();
	for (let hop = 0; hop < 15; hop++) {
		if (target.origin !== op && target.origin !== rp)
			throw new Error("Unexpected fixture redirect");
		const response = await fetch(target, {
			redirect: "manual",
			...(body ? { method: "POST", body } : {}),
			headers: {
				...(body ? { "content-type": "application/x-www-form-urlencoded" } : {}),
				...(target.origin === op ? { cookie: [...cookies.values()].join("; ") } : {}),
			},
		});
		body = undefined;
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

	beforeEach(async () => {
		const { entities, server, trustAnchors } = getBed();
		const op = entities.get("https://op.ofed.test");
		const rp = getOidcClientEntity(entities, "https://rp.ofed.test");
		if (!op || !(op.server instanceof Leaf) || !(rp.server instanceof Leaf)) {
			throw new Error("Expected leaf fixtures");
		}
		const rpId = `https://rp.ofed.test:${server.port}`;
		server.addEntity(
			"https://op.ofed.test",
			await createOpenIDProviderApp({
				leaf: op.server,
				entityId: `https://op.ofed.test:${server.port}`,
				trustAnchors,
				federationKeyProvider: op.crypto,
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
		const discovery = await discoverEntity(entityId(opId), trustAnchors, { engine: testEngine });
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

	it.each(["GET", "POST"] as const)(
		"completes %s automatic login, consent, code exchange, and ID Token validation",
		async (method) => {
			const { result, rp, rpId, opId, verifier, nonce, state } = await authorization();
			const url = new URL(result.authorizationUrl);
			const body = method === "POST" ? new URLSearchParams(url.searchParams) : undefined;
			if (body) url.search = "";
			const response = await followLogin(url.href, opId, rpId, body);
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
		},
	);

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

	it("limits requests before authentication and does not trust forwarded identities", async () => {
		const { entities, server, trustAnchors } = getBed();
		const op = entities.get("https://op.ofed.test");
		if (!op || !(op.server instanceof Leaf)) throw new Error("Expected an OP leaf");
		const opId = `https://op.ofed.test:${server.port}`;
		server.addEntity(
			opId,
			await createOpenIDProviderApp({
				leaf: op.server,
				entityId: opId,
				trustAnchors,
				federationKeyProvider: op.crypto,
				oidcSigningKey: op.keys.protocolSigning,
				allowedRequestUriHosts: new Set(),
				requestLimitPerMinute: 1,
			}),
		);
		const first = await fetch(`${opId}/.well-known/openid-federation`);
		expect(first.status).toBe(200);
		await first.body?.cancel();
		for (const forwarded of ["198.51.100.1", "198.51.100.2"]) {
			const blocked = await fetch(`${opId}/auth`, {
				method: "POST",
				headers: { "X-Forwarded-For": forwarded },
			});
			expect(blocked.status).toBe(429);
			expect(blocked.headers.get("retry-after")).toBeTruthy();
			await blocked.body?.cancel();
		}
	});
});
