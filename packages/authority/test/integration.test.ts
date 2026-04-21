import {
	decodeEntityStatement,
	EntityType,
	entityId,
	FederationEndpoint,
	generateSigningKey,
	isOk,
	verifyEntityStatement,
	WELL_KNOWN_OPENID_FEDERATION,
} from "@oidfed/core";
import { beforeEach, describe, expect, it } from "vitest";
import { type AuthorityConfig, createAuthorityServer } from "../src/server.js";
import {
	MemoryKeyStore,
	MemorySubordinateStore,
	MemoryTrustMarkStore,
} from "../src/storage/memory.js";
import type { SubordinateRecord } from "../src/storage/types.js";

const AUTHORITY_ID = entityId("https://ta.example.com");
const INTERMEDIATE_ID = entityId("https://intermediate.example.com");
const LEAF_OP = entityId("https://op.example.com");
const LEAF_RP = entityId("https://rp.example.com");
const MARK_TYPE = "https://trust.example.com/certified";

describe("Integration: Authority Server end-to-end", () => {
	let keyStore: MemoryKeyStore;
	let subordinateStore: MemorySubordinateStore;
	let trustMarkStore: MemoryTrustMarkStore;
	let server: ReturnType<typeof createAuthorityServer>;

	beforeEach(async () => {
		keyStore = new MemoryKeyStore();
		subordinateStore = new MemorySubordinateStore();
		trustMarkStore = new MemoryTrustMarkStore();

		const { privateKey } = await generateSigningKey("ES256");
		const signingKey = { ...privateKey, kid: "ta-key-1" };
		await keyStore.addKey(signingKey);
		await keyStore.activateKey("ta-key-1");

		const config: AuthorityConfig = {
			entityId: AUTHORITY_ID,
			metadata: {
				federation_entity: {
					organization_name: "Test Trust Anchor",
					federation_fetch_endpoint: `${AUTHORITY_ID}${FederationEndpoint.Fetch}`,
					federation_list_endpoint: `${AUTHORITY_ID}${FederationEndpoint.List}`,
					federation_trust_mark_status_endpoint: `${AUTHORITY_ID}${FederationEndpoint.TrustMarkStatus}`,
					federation_trust_mark_list_endpoint: `${AUTHORITY_ID}${FederationEndpoint.TrustMarkList}`,
					federation_trust_mark_endpoint: `${AUTHORITY_ID}${FederationEndpoint.TrustMark}`,
					federation_historical_keys_endpoint: `${AUTHORITY_ID}${FederationEndpoint.HistoricalKeys}`,
				},
			},
			subordinateStore,
			keyStore,
			trustMarkStore,
			trustMarkIssuers: { [MARK_TYPE]: [AUTHORITY_ID] },
			trustMarkOwners: {
				[MARK_TYPE]: {
					iss: AUTHORITY_ID,
					sub: AUTHORITY_ID,
				},
			},
		};

		server = createAuthorityServer(config);
	});

	describe("Entity Configuration lifecycle", () => {
		it("fetches EC via programmatic API and HTTP handler", async () => {
			const ecJwt = await server.getEntityConfiguration();
			const decoded = decodeEntityStatement(ecJwt);
			expect(isOk(decoded)).toBe(true);
			if (!isOk(decoded)) return;

			expect(decoded.value.payload.iss).toBe(AUTHORITY_ID);
			expect(decoded.value.payload.sub).toBe(AUTHORITY_ID);

			const payload = decoded.value.payload as Record<string, unknown>;
			expect(payload.metadata).toBeDefined();
			expect(payload.jwks).toBeDefined();
			expect(payload.trust_mark_issuers).toEqual({ [MARK_TYPE]: [AUTHORITY_ID] });
			expect(payload.trust_mark_owners).toBeDefined();

			const httpHandler = server.handler();
			const httpRes = await httpHandler(
				new Request(`${AUTHORITY_ID}${WELL_KNOWN_OPENID_FEDERATION}`),
			);
			expect(httpRes.status).toBe(200);

			const activeKeys = await keyStore.getActiveKeys();
			const verifyResult = await verifyEntityStatement(ecJwt, activeKeys);
			expect(isOk(verifyResult)).toBe(true);
		});

		it("EC includes authority_hints for intermediates", async () => {
			const { privateKey: intKey } = await generateSigningKey("ES256");
			const intKeyStore = new MemoryKeyStore();
			await intKeyStore.addKey({ ...intKey, kid: "int-key-1" });
			await intKeyStore.activateKey("int-key-1");

			const intServer = createAuthorityServer({
				entityId: INTERMEDIATE_ID,
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${INTERMEDIATE_ID}${FederationEndpoint.Fetch}`,
					},
				},
				subordinateStore: new MemorySubordinateStore(),
				keyStore: intKeyStore,
				authorityHints: [AUTHORITY_ID],
			});

			const ecJwt = await intServer.getEntityConfiguration();
			const decoded = decodeEntityStatement(ecJwt);
			expect(isOk(decoded)).toBe(true);
			if (!isOk(decoded)) return;

			const payload = decoded.value.payload as Record<string, unknown>;
			expect(payload.authority_hints).toEqual([AUTHORITY_ID]);
		});
	});

	describe("Subordinate management lifecycle", () => {
		it("adds subordinates, lists them, and fetches statements", async () => {
			const opRecord: SubordinateRecord = {
				entityId: LEAF_OP,
				jwks: { keys: [{ kty: "EC", crv: "P-256", x: "abc", y: "def" }] },
				metadata: { openid_provider: { issuer: LEAF_OP } },
				entityTypes: [EntityType.OpenIDProvider],
				sourceEndpoint: `${LEAF_OP}${FederationEndpoint.Fetch}`,
				createdAt: Date.now(),
				updatedAt: Date.now(),
			};
			const rpRecord: SubordinateRecord = {
				entityId: LEAF_RP,
				jwks: { keys: [{ kty: "EC", crv: "P-256", x: "ghi", y: "jkl" }] },
				metadata: { openid_relying_party: { client_name: "Test RP" } },
				entityTypes: [EntityType.OpenIDRelyingParty],
				createdAt: Date.now(),
				updatedAt: Date.now(),
			};

			await subordinateStore.add(opRecord);
			await subordinateStore.add(rpRecord);

			const allSubs = await server.listSubordinates();
			expect(allSubs).toHaveLength(2);
			expect(allSubs).toContain(LEAF_OP);
			expect(allSubs).toContain(LEAF_RP);

			const opOnly = await server.listSubordinates({
				entityTypes: [EntityType.OpenIDProvider],
			});
			expect(opOnly).toEqual([LEAF_OP]);

			const ssJwt = await server.getSubordinateStatement(LEAF_OP);
			const decoded = decodeEntityStatement(ssJwt);
			expect(isOk(decoded)).toBe(true);
			if (!isOk(decoded)) return;

			expect(decoded.value.payload.iss).toBe(AUTHORITY_ID);
			expect(decoded.value.payload.sub).toBe(LEAF_OP);
			const payload = decoded.value.payload as Record<string, unknown>;
			expect(payload.source_endpoint).toBe(`${LEAF_OP}${FederationEndpoint.Fetch}`);
			expect(payload.metadata).toBeDefined();
		});

		it("fetches subordinate via HTTP handler", async () => {
			await subordinateStore.add({
				entityId: LEAF_OP,
				jwks: { keys: [{ kty: "EC", crv: "P-256", x: "abc", y: "def" }] },
				createdAt: Date.now(),
				updatedAt: Date.now(),
			});

			const httpHandler = server.handler();
			const res = await httpHandler(
				new Request(
					`${AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(LEAF_OP)}`,
				),
			);

			expect(res.status).toBe(200);
			expect(res.headers.get("Content-Type")).toBe("application/entity-statement+jwt");
		});
	});

	describe("Trust Mark lifecycle", () => {
		it("issues, lists, checks status, and revokes trust marks", async () => {
			const tmJwt = await server.issueTrustMark(LEAF_OP, MARK_TYPE);
			expect(tmJwt).toBeTruthy();

			const decoded = decodeEntityStatement(tmJwt);
			expect(isOk(decoded)).toBe(true);
			if (!isOk(decoded)) return;

			const payload = decoded.value.payload as Record<string, unknown>;
			expect(payload.iss).toBe(AUTHORITY_ID);
			expect(payload.sub).toBe(LEAF_OP);
			expect(payload.trust_mark_type).toBe(MARK_TYPE);

			const entities = await server.listTrustMarkedEntities(MARK_TYPE);
			expect(entities).toContain(LEAF_OP);

			const status = await server.getTrustMarkStatus(tmJwt);
			expect(status.status).toBe("active");

			await trustMarkStore.revoke(MARK_TYPE, LEAF_OP);

			const statusAfterRevoke = await server.getTrustMarkStatus(tmJwt);
			expect(statusAfterRevoke.status).toBe("revoked");

			const entitiesAfterRevoke = await server.listTrustMarkedEntities(MARK_TYPE);
			expect(entitiesAfterRevoke).not.toContain(LEAF_OP);
		});
	});

	describe("Key rotation lifecycle", () => {
		it("rotates key and verifies historical keys", async () => {
			const activeKeysBefore = await keyStore.getActiveKeys();
			expect(activeKeysBefore.keys).toHaveLength(1);

			const { privateKey: newKey } = await generateSigningKey("ES256");
			const newSigningKey = { ...newKey, kid: "ta-key-2" };
			await server.rotateSigningKey(newSigningKey);

			const signing = await keyStore.getSigningKey();
			expect(signing.key.kid).toBe("ta-key-2");

			const activeKeysAfter = await keyStore.getActiveKeys();
			expect(activeKeysAfter.keys).toHaveLength(2);

			const historicalJwt = await server.getHistoricalKeys();
			const decoded = decodeEntityStatement(historicalJwt);
			expect(isOk(decoded)).toBe(true);
			if (!isOk(decoded)) return;

			const payload = decoded.value.payload as Record<string, unknown>;
			const keys = payload.keys as Array<Record<string, unknown>>;
			expect(keys).toHaveLength(2);

			const oldKey = keys.find((k) => k.kid === "ta-key-1");
			expect(oldKey).toBeDefined();

			const ecAfterRotation = await server.getEntityConfiguration();
			const ecDecoded = decodeEntityStatement(ecAfterRotation);
			expect(isOk(ecDecoded)).toBe(true);
			if (!isOk(ecDecoded)) return;

			const ecPayload = ecDecoded.value.payload as Record<string, unknown>;
			const ecJwks = ecPayload.jwks as { keys: Array<Record<string, unknown>> };
			expect(ecJwks.keys).toHaveLength(2);

			const verifyResult = await verifyEntityStatement(ecAfterRotation, activeKeysAfter);
			expect(isOk(verifyResult)).toBe(true);
		});
	});

	describe("HTTP routing coverage", () => {
		it("all endpoints respond with security headers", async () => {
			const httpHandler = server.handler();
			const endpoints = [
				WELL_KNOWN_OPENID_FEDERATION,
				`${FederationEndpoint.List}`,
				`${FederationEndpoint.HistoricalKeys}`,
			];

			for (const endpoint of endpoints) {
				const res = await httpHandler(new Request(`${AUTHORITY_ID}${endpoint}`));
				expect(res.headers.get("Cache-Control")).toBe("no-store");
				expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
				expect(res.headers.get("Strict-Transport-Security")).toBeTruthy();
			}
		});

		it("404 for unknown paths", async () => {
			const httpHandler = server.handler();
			const res = await httpHandler(new Request(`${AUTHORITY_ID}/nonexistent`));
			expect(res.status).toBe(404);

			const body = await res.json();
			expect(body.error).toBe("not_found");
		});
	});
});
