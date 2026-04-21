import {
	type DiscoveryResult,
	type EntityId,
	generateSigningKey,
	type JWK,
	resolveTrustChains,
	shortestChain,
	stripPrivateFields,
	type ValidatedTrustChain,
	validateTrustChain,
} from "@oidfed/core";
import {
	createMockFederation,
	createMockTrustAnchors,
	LEAF_ID,
	type MockFederation,
	OP_ID,
	TA_ID,
} from "../../core/test/fixtures/index.js";
import type { AutomaticRegistrationConfig } from "../src/registration/automatic.js";
import type { ExplicitRegistrationConfig } from "../src/registration/explicit.js";

export {
	createMockFederation,
	createMockTrustAnchors,
	LEAF_ID,
	type MockFederation,
	OP_ID,
	stripPrivateFields,
	TA_ID,
};

export type RpConfig = AutomaticRegistrationConfig & ExplicitRegistrationConfig;

/** Creates an RP configuration with fresh ES256 keys and sensible defaults for registration tests. */
export async function createRpConfig(
	overrides?: Partial<RpConfig>,
): Promise<{ config: RpConfig; signingKey: JWK; publicKey: JWK }> {
	const { privateKey, publicKey } = await generateSigningKey("ES256");
	const config: RpConfig = {
		entityId: LEAF_ID,
		signingKeys: [privateKey],
		authorityHints: [TA_ID],
		metadata: {
			openid_relying_party: {
				redirect_uris: ["https://rp.example.com/callback"],
				response_types: ["code"],
				client_registration_types: ["automatic"],
			},
		},
		...overrides,
	};
	return { config, signingKey: privateKey, publicKey };
}

/**
 * Create a DiscoveryResult for a given entity using the mock federation.
 * This produces the branded type that automaticRegistration/explicitRegistration expect.
 */
export async function createMockDiscovery(
	targetEntityId: EntityId,
	fed: MockFederation,
): Promise<DiscoveryResult> {
	const chainResult = await resolveTrustChains(targetEntityId, fed.trustAnchors, fed.options);
	if (chainResult.chains.length === 0) {
		throw new Error(`No chains resolved for ${targetEntityId}`);
	}
	const validChains: ValidatedTrustChain[] = [];
	for (const chain of chainResult.chains) {
		const result = await validateTrustChain(
			chain.statements as string[],
			fed.trustAnchors,
			fed.options,
		);
		if (result.valid) {
			validChains.push(result.chain);
		}
	}
	if (validChains.length === 0) {
		throw new Error(`No valid chains for ${targetEntityId}`);
	}
	const bestChain = shortestChain(validChains);
	return {
		entityId: targetEntityId,
		resolvedMetadata: bestChain.resolvedMetadata,
		trustChain: bestChain,
		trustMarks: bestChain.trustMarks,
	} as DiscoveryResult;
}
