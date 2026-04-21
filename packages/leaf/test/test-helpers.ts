import { type FederationMetadata, generateSigningKey, type JWK } from "@oidfed/core";
import {
	createMockFederation,
	createMockTrustAnchors,
	LEAF_ID,
	type MockFederation,
	OP_ID,
	TA_ID,
} from "../../core/test/fixtures/index.js";
import type { LeafConfig } from "../src/entity-configuration.js";

export { createMockFederation, createMockTrustAnchors, LEAF_ID, type MockFederation, OP_ID, TA_ID };

/** Creates a leaf entity configuration with fresh ES256 keys and sensible defaults. */
export async function createLeafConfig(
	overrides?: Partial<LeafConfig>,
): Promise<{ config: LeafConfig; signingKey: JWK; publicKey: JWK }> {
	const { privateKey, publicKey } = await generateSigningKey("ES256");
	const config: LeafConfig = {
		entityId: LEAF_ID,
		signingKeys: [privateKey],
		authorityHints: [TA_ID],
		metadata: {
			openid_relying_party: {
				redirect_uris: ["https://rp.example.com/callback"],
				response_types: ["code"],
				client_registration_types: ["automatic"],
			},
		} as FederationMetadata,
		...overrides,
	};
	return { config, signingKey: privateKey, publicKey };
}
