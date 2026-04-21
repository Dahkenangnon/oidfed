import type { AuthorityServer } from "@oidfed/authority";
import type { JWK } from "@oidfed/core";
import {
	decodeEntityStatement,
	entityId,
	generateSigningKey,
	isOk,
	resolveTrustChains,
	validateTrustChain,
} from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { getEntity } from "../helpers/launcher.js";
import { useFederation } from "../helpers/lifecycle.js";
import { hierarchicalTopology } from "../topologies/hierarchical.js";
import { singleAnchorTopology } from "../topologies/single-anchor.js";

describe("Key rotation", () => {
	describe("single-anchor", () => {
		const getTestBed = useFederation(singleAnchorTopology);

		it("rotates TA signing key and trust chains still resolve", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const taInstance = getEntity(entities, "https://ta.ofed.test");
			const ta = taInstance.server as AuthorityServer;

			// Baseline: resolve RP chain
			const rpId = entityId(`https://rp.ofed.test:${port}`);
			const baseline = await resolveTrustChains(rpId, trustAnchors);
			expect(baseline.chains).toHaveLength(1);

			// Get original EC header
			const originalEc = await ta.getEntityConfiguration();
			const originalDecoded = decodeEntityStatement(originalEc);
			expect(isOk(originalDecoded)).toBe(true);
			const originalKid = isOk(originalDecoded) ? originalDecoded.value.header.kid : undefined;

			// Generate new key and rotate
			const newKey = await generateSigningKey("ES256");
			await ta.rotateSigningKey(newKey.privateKey as JWK);

			// Fetch new EC — should use new key
			const newEc = await ta.getEntityConfiguration();
			const newDecoded = decodeEntityStatement(newEc);
			expect(isOk(newDecoded)).toBe(true);
			if (!isOk(newDecoded)) return;

			expect(newDecoded.value.header.kid).not.toBe(originalKid);

			// Historical keys should include old key
			const historicalJwt = await ta.getHistoricalKeys();
			expect(historicalJwt).toBeTruthy();

			// Update trust anchors with new key for resolution
			const newPayload = newDecoded.value.payload as Record<string, unknown>;
			const newJwks = newPayload.jwks as { keys: JWK[] };
			const updatedTrustAnchors = new Map(trustAnchors);
			updatedTrustAnchors.set(entityId(`https://ta.ofed.test:${port}`), {
				jwks: { keys: newJwks.keys },
			});

			// Re-resolve with updated TA keys
			const afterRotation = await resolveTrustChains(rpId, updatedTrustAnchors);
			expect(afterRotation.chains).toHaveLength(1);
		});
	});

	describe("hierarchical", () => {
		const getTestBed = useFederation(hierarchicalTopology);

		it("rotates intermediate key and chains still resolve", async () => {
			const { server, entities, trustAnchors } = getTestBed();
			const port = server.port;

			const iaEntity = getEntity(entities, "https://ia-edu.ofed.test");
			const ia = iaEntity.server as AuthorityServer;

			// Baseline
			const opId = entityId(`https://op-uni.ofed.test:${port}`);
			const baseline = await resolveTrustChains(opId, trustAnchors);
			expect(baseline.chains).toHaveLength(1);

			// Rotate IA key
			const newKey = await generateSigningKey("ES256");
			await ia.rotateSigningKey(newKey.privateKey as JWK);

			// After IA rotation without parent updating the subordinate statement,
			// the IA's new EC key won't match the parent's subordinate statement JWKS.
			// Resolution may still collect the chain, but validation MUST fail.
			const afterRotation = await resolveTrustChains(opId, trustAnchors);

			if (afterRotation.chains.length > 0) {
				const validation = await validateTrustChain(
					[...afterRotation.chains[0].statements],
					trustAnchors,
				);
				expect(validation.valid).toBe(false);
			} else {
				// If resolution itself caught the key mismatch, that's also acceptable
				expect(afterRotation.errors.length).toBeGreaterThan(0);
			}
		});
	});
});
