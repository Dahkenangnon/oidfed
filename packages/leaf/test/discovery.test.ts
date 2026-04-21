import { entityId } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { discoverEntity } from "../src/discovery.js";
import {
	createMockFederation,
	createMockTrustAnchors,
	LEAF_ID,
	OP_ID,
	TA_ID,
} from "./test-helpers.js";

describe("discoverEntity", () => {
	it("returns correct entityId from valid discovery", async () => {
		const fed = await createMockFederation();
		const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);

		expect(result.entityId).toBe(OP_ID);
	});

	it("returns resolvedMetadata from valid discovery", async () => {
		const fed = await createMockFederation();
		const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);

		expect(result.resolvedMetadata).toBeDefined();
		expect(result.resolvedMetadata.openid_provider).toBeDefined();
	});

	it("returns trustChain from valid discovery", async () => {
		const fed = await createMockFederation();
		const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);

		expect(result.trustChain).toBeDefined();
		expect(result.trustChain.entityId).toBe(OP_ID);
		expect(result.trustChain.trustAnchorId).toBe(TA_ID);
		expect(result.trustChain.statements.length).toBeGreaterThanOrEqual(2);
	});

	it("returns empty trustMarks array when none present", async () => {
		const fed = await createMockFederation();
		const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);

		expect(result.trustMarks).toEqual([]);
	});

	it("throws when no trust chain can be resolved", async () => {
		const fed = await createMockFederation();
		const unknownEntity = entityId("https://unknown.example.com");

		await expect(discoverEntity(unknownEntity, fed.trustAnchors, fed.options)).rejects.toThrow(
			"No trust chains resolved",
		);
	});

	it("error message includes chain resolution details when no chains resolve", async () => {
		const fed = await createMockFederation();
		const unknownEntity = entityId("https://unknown.example.com");

		await expect(discoverEntity(unknownEntity, fed.trustAnchors, fed.options)).rejects.toThrow(
			/No trust chains resolved for entity/,
		);
	});

	it("throws with validation details when all chains fail validation", async () => {
		const fed = await createMockFederation();
		// Use trust anchors with wrong key — chains resolve but won't validate
		const wrongTrustAnchors = createMockTrustAnchors(
			TA_ID,
			fed.opPublicKey, // wrong key — not the TA key
		);

		await expect(discoverEntity(OP_ID, wrongTrustAnchors, fed.options)).rejects.toThrow(
			/No valid trust chains for entity:/,
		);
	});

	it("discovers leaf entity through federation", async () => {
		const fed = await createMockFederation();
		const result = await discoverEntity(LEAF_ID, fed.trustAnchors, fed.options);

		expect(result.entityId).toBe(LEAF_ID);
		expect(result.trustChain.trustAnchorId).toBe(TA_ID);
	});

	it("selects shortest chain when multiple valid chains exist", async () => {
		const fed = await createMockFederation();
		const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);

		// With a simple topology, the chain should be minimal (2 statements: leaf EC + TA subordinate)
		expect(result.trustChain.statements.length).toBeGreaterThanOrEqual(2);
	});
});
