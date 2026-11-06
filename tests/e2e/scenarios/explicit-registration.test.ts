import {
	decodeEntityStatement,
	entityId,
	generateSigningKey,
	JwkSigner,
	JwtTyp,
	MediaType,
	resolveTrustChains,
	signEntityStatement,
} from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { getOidcClientEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { hierarchicalTopology } from "../topologies/hierarchical.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

describe("Explicit registration", () => {
	describe("single-anchor", () => {
		const getTestBed = useFederation(singleAnchorTopology);

		it("rejects an attacker-signed registration for a real RP over HTTPS", async () => {
			const { server, trustAnchors } = getTestBed();
			const rpId = entityId(`https://rp2.ofed.test:${server.port}`);
			const opId = entityId(`https://op.ofed.test:${server.port}`);
			const resolution = await resolveTrustChains(rpId, trustAnchors);
			const chain = resolution.chains[0]?.statements;
			expect(chain).toBeDefined();
			if (!chain) throw new Error("RP chain fixture is unavailable");
			const attacker = await generateSigningKey("ES256");
			const now = Math.floor(Date.now() / 1000);
			const payload = {
				iss: rpId,
				sub: rpId,
				aud: opId,
				iat: now,
				exp: now + 300,
				jwks: { keys: [attacker.publicKey] },
				authority_hints: [Array.from(trustAnchors.keys())[0]],
				metadata: {
					openid_relying_party: { redirect_uris: ["https://attacker.example/callback"] },
				},
			};
			for (const supplied of [false, true]) {
				const jwt = await signEntityStatement(payload, new JwkSigner(attacker.privateKey), {
					typ: JwtTyp.EntityStatement,
					...(supplied ? { extraHeaders: { trust_chain: [...chain] } } : {}),
				});
				const response = await fetch(`${opId}/federation_registration`, {
					method: "POST",
					headers: { "Content-Type": MediaType.EntityStatement },
					body: jwt,
				});
				expect(response.status).toBe(supplied ? 400 : 403);
				expect(await response.json()).toMatchObject({ error: "invalid_trust_chain" });
			}
		});

		it("RP2 registers explicitly with OP", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const rp2Entity = getOidcClientEntity(entities, "https://rp2.ofed.test");

			const rpId = `https://rp2.ofed.test:${port}`;
			const opId = entityId(`https://op.ofed.test:${port}`);

			const resultVal = await rp2Entity.oidcClient.explicitlyRegister(opId, { trustAnchors });

			expect(resultVal.ok, resultVal.ok ? undefined : resultVal.error.description).toBe(true);
			if (!resultVal.ok) throw new Error("Registration failed");
			const result = resultVal.value;

			expect(result.clientId).toBe(rpId);
			expect(result.registeredMetadata).toBeDefined();
			expect(result.registeredMetadata.redirect_uris).toContain(`${rpId}/callback`);
			expect(result.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
			expect(result.trustChainExpiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
		});
	});

	describe("hierarchical", () => {
		const getTestBed = useFederation(hierarchicalTopology);

		it("RP2 registers explicitly with OP-Hospital through IA-Health", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const rp2Entity = getOidcClientEntity(entities, "https://rp2.ofed.test");

			const rpId = `https://rp2.ofed.test:${port}`;
			const opId = entityId(`https://op-hospital.ofed.test:${port}`);

			const resultVal = await rp2Entity.oidcClient.explicitlyRegister(opId, { trustAnchors });

			expect(resultVal.ok, resultVal.ok ? undefined : resultVal.error.description).toBe(true);
			if (!resultVal.ok) throw new Error("Registration failed");
			const result = resultVal.value;

			expect(result.clientId).toBe(rpId);
			expect(result.registeredMetadata).toBeDefined();
			expect(result.registeredMetadata.redirect_uris).toContain(`${rpId}/callback`);
			expect(result.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
			expect(result.trustChainExpiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
		});
	});
	describe("tailored metadata and policy removals", () => {
		const topology = structuredClone(singleAnchorTopology);
		topology.name = "registration-policy";
		const rpDefinition = topology.entities.find((entity) => entity.id === "https://rp2.ofed.test");
		if (!rpDefinition) throw new Error("Missing RP definition");
		rpDefinition.metadataPolicy = {
			openid_relying_party: {
				scope: { essential: true },
				grant_types: { value: null },
				token_endpoint_auth_method: { value: null },
			},
		};
		const getTestBed = useFederation(topology);
		it("uses tailored header metadata and preserves fractional expiry over HTTPS", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const rp = getOidcClientEntity(entities, "https://rp2.ofed.test");
			const rpId = entityId(`https://rp2.ofed.test:${server.port}`);
			const opId = entityId(`https://op.ofed.test:${server.port}`);
			const chains = await resolveTrustChains(rpId, trustAnchors);
			const chain = chains.chains[0]?.statements;
			if (!chain) throw new Error("Missing RP evidence");
			const published = decodeEntityStatement(chain[0] as string);
			if (!published.ok) throw new Error(published.error.description);
			const now = Math.floor(Date.now() / 1000);
			const jwt = await signEntityStatement(
				{
					...published.value.payload,
					aud: opId,
					iat: now - 0.5,
					exp: now + 300.5,
					metadata: {
						openid_relying_party: {
							...published.value.payload.metadata?.openid_relying_party,
							scope: "openid",
						},
					},
				},
				new JwkSigner(rp.keys.signing),
				{ extraHeaders: { trust_chain: [...chain] } },
			);
			const response = await fetch(`${opId}/federation_registration`, {
				method: "POST",
				headers: { "Content-Type": MediaType.EntityStatement },
				body: jwt,
			});
			expect(response.status, await response.clone().text()).toBe(200);
			const parsed = decodeEntityStatement(await response.text());
			if (!parsed.ok) throw new Error(parsed.error.description);
			expect(parsed.value.payload.exp).toBe(now + 300.5);
			expect(parsed.value.payload.metadata?.openid_relying_party).toMatchObject({
				scope: "openid",
			});
			expect(parsed.value.payload.metadata?.openid_relying_party).not.toHaveProperty("grant_types");
			expect(parsed.value.payload.metadata?.openid_relying_party).not.toHaveProperty(
				"token_endpoint_auth_method",
			);
		});
	});
});
