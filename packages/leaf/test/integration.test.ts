import { decodeEntityStatement, MediaType, WELL_KNOWN_OPENID_FEDERATION } from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { discoverEntity } from "../src/discovery.js";
import { createLeafEntity, type LeafConfig } from "../src/entity-configuration.js";
import { createMockFederation, LEAF_ID, OP_ID, TA_ID } from "./test-helpers.js";

describe("integration", () => {
	it("end-to-end: EC generation + handler serving", async () => {
		const fed = await createMockFederation();

		const config: LeafConfig = {
			entityId: LEAF_ID,
			signingKeys: [fed.leafSigningKey],
			authorityHints: [TA_ID],
			metadata: {
				openid_relying_party: {
					redirect_uris: ["https://rp.example.com/callback"],
					response_types: ["code"],
					client_registration_types: ["automatic"],
				},
			},
		};

		const entity = createLeafEntity(config);
		const handler = entity.handler();

		// Serve EC at well-known endpoint
		const request = new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`);
		const response = await handler(request);

		expect(response.status).toBe(200);
		expect(response.headers.get("Content-Type")).toBe(MediaType.EntityStatement);

		const jwt = await response.text();
		const decoded = decodeEntityStatement(jwt);
		expect(decoded.ok).toBe(true);
		if (!decoded.ok) return;

		expect(decoded.value.payload.iss).toBe(LEAF_ID);
		expect(decoded.value.payload.sub).toBe(LEAF_ID);
		const p = decoded.value.payload as Record<string, unknown>;
		expect(p.authority_hints).toEqual([TA_ID]);
	});

	it("end-to-end: discover OP through mock federation", async () => {
		const fed = await createMockFederation();

		const config: LeafConfig = {
			entityId: LEAF_ID,
			signingKeys: [fed.leafSigningKey],
			authorityHints: [TA_ID],
			metadata: {
				openid_relying_party: {
					redirect_uris: ["https://rp.example.com/callback"],
					response_types: ["code"],
				},
			},
		};

		const _entity = createLeafEntity(config);
		const discovery = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);

		expect(discovery.entityId).toBe(OP_ID);
		expect(discovery.resolvedMetadata.openid_provider).toBeDefined();
		expect(discovery.trustChain.trustAnchorId).toBe(TA_ID);
	});

	it("EC caching and refresh cycle", async () => {
		const fed = await createMockFederation();

		const config: LeafConfig = {
			entityId: LEAF_ID,
			signingKeys: [fed.leafSigningKey],
			authorityHints: [TA_ID],
			metadata: {
				openid_relying_party: {
					redirect_uris: ["https://rp.example.com/callback"],
				},
			},
		};

		const entity = createLeafEntity(config);

		// Before generating, expired = true
		expect(entity.isEntityConfigurationExpired()).toBe(true);

		// Generate EC
		const ec1 = await entity.getEntityConfiguration();
		expect(entity.isEntityConfigurationExpired()).toBe(false);

		// Cached
		const ec2 = await entity.getEntityConfiguration();
		expect(ec1).toBe(ec2);

		// Refresh
		const ec3 = await entity.refreshEntityConfiguration();
		expect(typeof ec3).toBe("string");

		// New cache
		const ec4 = await entity.getEntityConfiguration();
		expect(ec4).toBe(ec3);
	});
});
