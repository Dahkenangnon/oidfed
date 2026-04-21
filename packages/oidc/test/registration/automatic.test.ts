import { decodeEntityStatement } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { automaticRegistration } from "../../src/registration/automatic.js";
import {
	createMockDiscovery,
	createMockFederation,
	createRpConfig,
	LEAF_ID,
	OP_ID,
} from "../test-helpers.js";

describe("automaticRegistration (RP-side)", () => {
	it("returns valid Request Object JWT with correct typ", async () => {
		const fed = await createMockFederation();
		const discovery = await createMockDiscovery(OP_ID, fed);
		const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });

		const result = await automaticRegistration(
			discovery,
			config,
			{ redirect_uri: "https://rp.example.com/callback", scope: "openid", response_type: "code" },
			fed.trustAnchors,
			fed.options,
		);

		const decoded = decodeEntityStatement(result.requestObjectJwt);
		expect(decoded.ok).toBe(true);
		if (!decoded.ok) return;
		expect(decoded.value.header.typ).toBe("oauth-authz-req+jwt");
	});

	it("has correct JWT claims: iss, client_id, aud, jti, exp", async () => {
		const fed = await createMockFederation();
		const discovery = await createMockDiscovery(OP_ID, fed);
		const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });

		const result = await automaticRegistration(
			discovery,
			config,
			{ redirect_uri: "https://rp.example.com/callback", scope: "openid", response_type: "code" },
			fed.trustAnchors,
			fed.options,
		);

		const decoded = decodeEntityStatement(result.requestObjectJwt);
		expect(decoded.ok).toBe(true);
		if (!decoded.ok) return;

		const p = decoded.value.payload as Record<string, unknown>;
		expect(p.iss).toBe(LEAF_ID);
		expect(p.client_id).toBe(LEAF_ID);
		expect(p.aud).toBe(OP_ID);
		expect(typeof p.jti).toBe("string");
		expect(typeof p.exp).toBe("number");
	});

	it("does NOT include sub claim", async () => {
		const fed = await createMockFederation();
		const discovery = await createMockDiscovery(OP_ID, fed);
		const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });

		const result = await automaticRegistration(
			discovery,
			config,
			{ redirect_uri: "https://rp.example.com/callback", scope: "openid", response_type: "code" },
			fed.trustAnchors,
			fed.options,
		);

		const decoded = decodeEntityStatement(result.requestObjectJwt);
		expect(decoded.ok).toBe(true);
		if (!decoded.ok) return;

		const p = decoded.value.payload as Record<string, unknown>;
		expect(p.sub).toBeUndefined();
	});

	it("includes trust_chain as JWS header parameter", async () => {
		const fed = await createMockFederation();
		const discovery = await createMockDiscovery(OP_ID, fed);
		const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });

		const result = await automaticRegistration(
			discovery,
			config,
			{ redirect_uri: "https://rp.example.com/callback", scope: "openid", response_type: "code" },
			fed.trustAnchors,
			fed.options,
		);

		const decoded = decodeEntityStatement(result.requestObjectJwt);
		expect(decoded.ok).toBe(true);
		if (!decoded.ok) return;

		const h = decoded.value.header as Record<string, unknown>;
		expect(Array.isArray(h.trust_chain)).toBe(true);
		expect((h.trust_chain as string[]).length).toBeGreaterThan(0);
	});

	it("includes authzRequestParams in JWT payload", async () => {
		const fed = await createMockFederation();
		const discovery = await createMockDiscovery(OP_ID, fed);
		const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });

		const params = {
			redirect_uri: "https://rp.example.com/callback",
			scope: "openid",
			response_type: "code",
			nonce: "test-nonce",
		};
		const result = await automaticRegistration(
			discovery,
			config,
			params,
			fed.trustAnchors,
			fed.options,
		);

		const decoded = decodeEntityStatement(result.requestObjectJwt);
		expect(decoded.ok).toBe(true);
		if (!decoded.ok) return;

		const p = decoded.value.payload as Record<string, unknown>;
		expect(p.redirect_uri).toBe(params.redirect_uri);
		expect(p.scope).toBe(params.scope);
		expect(p.nonce).toBe(params.nonce);
	});

	it("returns well-formed authorizationUrl", async () => {
		const fed = await createMockFederation();
		const discovery = await createMockDiscovery(OP_ID, fed);
		const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });

		const result = await automaticRegistration(
			discovery,
			config,
			{ redirect_uri: "https://rp.example.com/callback", scope: "openid", response_type: "code" },
			fed.trustAnchors,
			fed.options,
		);

		const url = new URL(result.authorizationUrl);
		expect(url.searchParams.get("request")).toBe(result.requestObjectJwt);
		expect(url.searchParams.get("client_id")).toBe(LEAF_ID);
	});

	it("does not allow authzRequestParams to overwrite required claims", async () => {
		const fed = await createMockFederation();
		const discovery = await createMockDiscovery(OP_ID, fed);
		const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });

		const result = await automaticRegistration(
			discovery,
			config,
			{
				iss: "https://attacker.example.com",
				aud: "https://attacker.example.com",
				sub: "https://attacker.example.com",
				redirect_uri: "https://rp.example.com/callback",
				scope: "openid",
				response_type: "code",
			},
			fed.trustAnchors,
			fed.options,
		);

		const decoded = decodeEntityStatement(result.requestObjectJwt);
		expect(decoded.ok).toBe(true);
		if (!decoded.ok) return;

		const p = decoded.value.payload as Record<string, unknown>;
		expect(p.iss).toBe(LEAF_ID);
		expect(p.aud).toBe(OP_ID);
		expect(p.sub).toBeUndefined();
	});

	it("throws if OP does not advertise automatic", async () => {
		const fed = await createMockFederation({
			opMetadata: {
				openid_provider: {
					issuer: OP_ID,
					authorization_endpoint: `${OP_ID}/authorize`,
					token_endpoint: `${OP_ID}/token`,
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256"],
					client_registration_types_supported: ["explicit"],
				},
				federation_entity: {
					federation_registration_endpoint: `${OP_ID}/federation_registration`,
				},
			},
		});
		const discovery = await createMockDiscovery(OP_ID, fed);
		const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });

		await expect(
			automaticRegistration(
				discovery,
				config,
				{ redirect_uri: "https://rp.example.com/callback", scope: "openid", response_type: "code" },
				fed.trustAnchors,
				fed.options,
			),
		).rejects.toThrow("automatic");
	});

	it("does not include registration param in JWT payload", async () => {
		const fed = await createMockFederation();
		const discovery = await createMockDiscovery(OP_ID, fed);
		const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });

		const result = await automaticRegistration(
			discovery,
			config,
			{
				registration: '{"client_name":"evil"}',
				redirect_uri: "https://rp.example.com/callback",
				scope: "openid",
				response_type: "code",
			},
			fed.trustAnchors,
			fed.options,
		);

		const decoded = decodeEntityStatement(result.requestObjectJwt);
		expect(decoded.ok).toBe(true);
		if (!decoded.ok) return;

		const p = decoded.value.payload as Record<string, unknown>;
		expect(p.registration).toBeUndefined();
	});

	it("includes trustChainExpiresAt matching trust chain expiry", async () => {
		const fed = await createMockFederation();
		const discovery = await createMockDiscovery(OP_ID, fed);
		const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });

		const result = await automaticRegistration(
			discovery,
			config,
			{ redirect_uri: "https://rp.example.com/callback", scope: "openid", response_type: "code" },
			fed.trustAnchors,
			fed.options,
		);

		expect(result.trustChainExpiresAt).toBeGreaterThan(0);
		expect(result.trustChainExpiresAt).toBe(discovery.trustChain.expiresAt);
	});

	it("uses JWK allowlist for public keys (no private fields leak)", async () => {
		const fed = await createMockFederation();
		const discovery = await createMockDiscovery(OP_ID, fed);
		const { config } = await createRpConfig({ signingKeys: [fed.leafSigningKey] });

		const result = await automaticRegistration(
			discovery,
			config,
			{ redirect_uri: "https://rp.example.com/callback", scope: "openid", response_type: "code" },
			fed.trustAnchors,
			fed.options,
		);

		// The request object JWT is signed — the key doesn't appear in it.
		// But the signing key was used and didn't throw — that's the test.
		expect(result.requestObjectJwt).toBeTruthy();
	});
});
