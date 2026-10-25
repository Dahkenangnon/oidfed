import {
	createTrustAnchorSet,
	entityId,
	generateSigningKey,
	JwkSigner,
	MemoryFederationKeyProvider,
	MemoryReplayStore,
} from "@oidfed/core";
import { Leaf } from "@oidfed/leaf";
import { CredentialIssuerRole, CredentialVerifierRole, WalletProviderRole } from "@oidfed/wallet";
import express from "express";
import { describe, expect, it } from "vitest";
import { getAuthorityEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { createLeafApp } from "../participants/leaf-app.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

describe("Wallet federation over HTTPS", () => {
	const bed = useFederation({ ...singleAnchorTopology, name: "wallet" });
	it("discovers protocol keys, authenticates a wallet, and checks an application-retrieved request", async () => {
		const { server, entities } = bed();
		const authority = getAuthorityEntity(entities, "https://ta.ofed.test");
		const anchorId = entityId(`https://ta.ofed.test:${server.port}`);
		const providerId = entityId(`https://wallet-provider.ofed.test:${server.port}`);
		const verifierId = entityId(`https://credential-verifier.ofed.test:${server.port}`);
		const anchors = createTrustAnchorSet([
			{ entityId: anchorId, jwks: { keys: [authority.keys.public] } },
		]);
		const providerKeys = await generateSigningKey();
		const providerProtocol = await generateSigningKey();
		const verifierKeys = await generateSigningKey();
		const verifierProtocol = await generateSigningKey();
		const walletKeys = await generateSigningKey();
		const provider = new WalletProviderRole({
			metadata: {
				vp_formats_supported: { "dc+sd-jwt": {} },
				jwks: { keys: [providerProtocol.publicKey] },
			},
		});
		const verifier = new CredentialVerifierRole({
			metadata: {
				vp_formats_supported: { "dc+sd-jwt": {} },
				jwks: { keys: [verifierProtocol.publicKey] },
				request_uris: [`${verifierId}/request`],
				response_uris: [`${verifierId}/response`],
				redirect_uris: [`${verifierId}/done`],
			},
		});
		const providerHost = new Leaf({
			entityId: providerId,
			authorityHints: [anchorId],
			metadata: { federation_entity: {} },
			keyProvider: MemoryFederationKeyProvider.fromJWK(providerKeys.privateKey),
			roles: [provider],
			trustAnchors: anchors,
		});
		const verifierHost = new Leaf({
			entityId: verifierId,
			authorityHints: [anchorId],
			metadata: { federation_entity: {} },
			keyProvider: MemoryFederationKeyProvider.fromJWK(verifierKeys.privateKey),
			roles: [verifier],
			trustAnchors: anchors,
		});
		server.addEntity(providerId, createLeafApp(providerHost, providerId));
		const verifierApp = createLeafApp(verifierHost, verifierId);
		let retrieved = 0;
		const query = {
			credentials: [
				{
					id: "identity",
					format: "dc+sd-jwt",
					meta: { vct_values: ["https://example.com/identity"] },
				},
			],
		};
		verifierApp.post("/request", express.urlencoded({ extended: false }), async (req, res) => {
			retrieved++;
			const signed = await verifier.createAuthorizationRequest(
				{
					response_type: "vp_token",
					response_mode: "direct_post",
					response_uri: `${verifierId}/response`,
					nonce: "session-nonce",
					dcql_query: query,
				},
				new JwkSigner(verifierProtocol.privateKey),
				{ walletNonce: String(req.body.wallet_nonce) },
			);
			if (!signed.ok) {
				res.status(500).end();
				return;
			}
			res.type("application/oauth-authz-req+jwt").send(signed.value);
		});
		server.addEntity(verifierId, verifierApp);
		await authority.server.registerSubordinate({
			entityId: providerId,
			jwks: { keys: [providerKeys.publicKey] },
		});
		await authority.server.registerSubordinate({
			entityId: verifierId,
			jwks: { keys: [verifierKeys.publicKey] },
		});
		expect((await WalletProviderRole.discover(providerId, anchors)).ok).toBe(true);
		const now = Math.floor(Date.now() / 1000);
		const signed = await provider.createWalletAttestation(
			{ subject: "wallet-type", confirmationKey: walletKeys.publicKey, expiresAt: now + 300 },
			new JwkSigner(providerProtocol.privateKey),
		);
		expect(signed.ok).toBe(true);
		if (!signed.ok) return;
		const audience = `https://op.ofed.test:${server.port}`;
		const pop = await new JwkSigner(walletKeys.privateKey).signJwt(
			new TextEncoder().encode(
				JSON.stringify({ iss: "wallet-type", aud: audience, iat: now, jti: crypto.randomUUID() }),
			),
			{ alg: "ES256", typ: "oauth-client-attestation-pop+jwt" },
		);
		const options = { audience, replayStore: new MemoryReplayStore(), acceptWallet: () => true };
		expect(
			(await CredentialIssuerRole.authenticateWallet(signed.value, pop, anchors, options)).ok,
		).toBe(true);
		expect(
			(await CredentialIssuerRole.authenticateWallet(signed.value, pop, anchors, options)).ok,
		).toBe(false);
		const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
			{
				client_id: `openid_federation:${verifierId}`,
				request_uri: `${verifierId}/request`,
				request_uri_method: "post",
			},
			anchors,
		);
		expect(prepared.ok, JSON.stringify(prepared)).toBe(true);
		if (!prepared.ok) return;
		expect(retrieved).toBe(0);
		const requestUri = prepared.value.requestUri;
		if (!requestUri) throw new Error("Prepared request URI is missing");
		const response = await fetch(requestUri, {
			method: "POST",
			body: new URLSearchParams({ wallet_nonce: "wallet-nonce" }),
			headers: { accept: "application/oauth-authz-req+jwt" },
		});
		expect(response.status).toBe(200);
		expect(response.headers.get("content-type")).toContain("application/oauth-authz-req+jwt");
		const jwt = await response.text();
		const completed = await CredentialVerifierRole.completeAuthorizationRequest(
			prepared.value,
			jwt,
			{ walletNonce: "wallet-nonce" },
		);
		expect(completed.ok, JSON.stringify(completed)).toBe(true);
		expect(
			(
				await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, jwt, {
					walletNonce: "wrong",
				})
			).ok,
		).toBe(false);
		expect(retrieved).toBe(1);
		if (completed.ok) expect(completed.value.effectiveQueries).toEqual([query]);
	});
});
