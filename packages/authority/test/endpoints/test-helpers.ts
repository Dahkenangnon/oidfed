import { entityId, generateSigningKey, type JWK } from "@oidfed/core";
import type { HandlerContext } from "../../src/endpoints/context.js";
import {
	MemoryKeyStore,
	MemorySubordinateStore,
	MemoryTrustMarkStore,
} from "../../src/storage/memory.js";

/** Default authority entity ID used across endpoint tests. */
export const ENTITY_ID = entityId("https://authority.example.com");
const TEST_KID = "test-key-1";

/** Creates a fully wired HandlerContext with in-memory stores and a fresh ES256 signing key. */
export async function createTestContext(overrides?: Partial<HandlerContext>): Promise<{
	ctx: HandlerContext;
	signingKey: JWK;
	publicKey: JWK;
	keyStore: MemoryKeyStore;
	subordinateStore: MemorySubordinateStore;
	trustMarkStore: MemoryTrustMarkStore;
}> {
	const { privateKey, publicKey: rawPublicKey } = await generateSigningKey("ES256");
	const signingKey = { ...privateKey, kid: TEST_KID };
	const publicKey = { ...rawPublicKey, kid: TEST_KID };

	const keyStore = new MemoryKeyStore();
	await keyStore.addKey(signingKey);
	await keyStore.activateKey(TEST_KID);

	const subordinateStore = new MemorySubordinateStore();
	const trustMarkStore = new MemoryTrustMarkStore();

	const ctx: HandlerContext = {
		entityId: ENTITY_ID,
		keyStore,
		subordinateStore,
		trustMarkStore,
		metadata: {
			federation_entity: {
				federation_fetch_endpoint: `${ENTITY_ID}/federation_fetch`,
				federation_list_endpoint: `${ENTITY_ID}/federation_list`,
			},
		},
		getSigningKey: async () => ({
			key: signingKey,
			kid: TEST_KID,
		}),
		...overrides,
	};

	return { ctx, signingKey, publicKey, keyStore, subordinateStore, trustMarkStore };
}
