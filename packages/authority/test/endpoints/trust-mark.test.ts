import {
	decodeEntityStatement,
	entityId,
	generateSigningKey,
	isOk,
	JwtTyp,
	signTrustMarkDelegation,
	validateTrustMark,
} from "@oidfed/core";
import { describe, expect, it } from "vitest";
import {
	createTrustMarkHandler,
	createTrustMarkIssuanceHandler,
} from "../../src/endpoints/trust-mark.js";
import { createAuthorityServer } from "../../src/server.js";
import { MemoryKeyStore, MemorySubordinateStore } from "../../src/storage/memory.js";
import { createTestContext, ENTITY_ID } from "./test-helpers.js";

const SUB1 = entityId("https://sub1.example.com");
const MARK_TYPE = "https://trust.example.com/mark-a";

describe("createTrustMarkHandler (retrieval)", () => {
	it("returns existing active trust mark", async () => {
		const { ctx, trustMarkStore } = await createTestContext();

		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB1,
			jwt: "existing.jwt.token",
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});

		const handler = createTrustMarkHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(MARK_TYPE)}&sub=${encodeURIComponent(SUB1)}`,
			),
		);

		expect(res.status).toBe(200);
		expect(res.headers.get("Content-Type")).toBe("application/trust-mark+jwt");
		const body = await res.text();
		expect(body).toBe("existing.jwt.token");
	});

	it("returns 404 when trust mark is expired", async () => {
		const { ctx, trustMarkStore } = await createTestContext();
		const now = Math.floor(Date.now() / 1000);

		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB1,
			jwt: "expired.jwt.token",
			issuedAt: now - 7200,
			expiresAt: now - 3600,
			active: true,
		});

		const handler = createTrustMarkHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(MARK_TYPE)}&sub=${encodeURIComponent(SUB1)}`,
			),
		);

		expect(res.status).toBe(404);
	});

	it("returns 404 when entity does not have the trust mark", async () => {
		const { ctx } = await createTestContext();
		const handler = createTrustMarkHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(MARK_TYPE)}&sub=${encodeURIComponent(SUB1)}`,
			),
		);

		expect(res.status).toBe(404);
		const body = await res.json();
		expect(body.error).toBe("not_found");
	});

	it("returns 404 when trust mark is revoked", async () => {
		const { ctx, trustMarkStore } = await createTestContext();

		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB1,
			jwt: "revoked.jwt.token",
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});
		await trustMarkStore.revoke(MARK_TYPE, SUB1);

		const handler = createTrustMarkHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(MARK_TYPE)}&sub=${encodeURIComponent(SUB1)}`,
			),
		);

		expect(res.status).toBe(404);
	});

	it("returns 400 for missing trust_mark_type", async () => {
		const { ctx } = await createTestContext();
		const handler = createTrustMarkHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark?sub=${encodeURIComponent(SUB1)}`,
			),
		);

		expect(res.status).toBe(400);
	});

	it("returns 400 for missing sub", async () => {
		const { ctx } = await createTestContext();
		const handler = createTrustMarkHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(MARK_TYPE)}`,
			),
		);

		expect(res.status).toBe(400);
	});

	it("returns 501 when no trust mark store", async () => {
		const { ctx } = await createTestContext({ trustMarkStore: undefined });
		const handler = createTrustMarkHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(MARK_TYPE)}&sub=${encodeURIComponent(SUB1)}`,
			),
		);

		expect(res.status).toBe(501);
	});

	it("returns 405 for POST", async () => {
		const { ctx } = await createTestContext();
		const handler = createTrustMarkHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_trust_mark", { method: "POST" }),
		);

		expect(res.status).toBe(405);
	});
});

describe("createTrustMarkIssuanceHandler (administrative issuance)", () => {
	it("issues a new trust mark", async () => {
		const { ctx } = await createTestContext({
			trustMarkIssuers: { [MARK_TYPE]: [ENTITY_ID] },
		});
		const handler = createTrustMarkIssuanceHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(MARK_TYPE)}&sub=${encodeURIComponent(SUB1)}`,
			),
		);

		expect(res.status).toBe(200);
		expect(res.headers.get("Content-Type")).toBe("application/trust-mark+jwt");

		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		expect(payload.iss).toBe(ENTITY_ID);
		expect(payload.sub).toBe(SUB1);
		expect(payload.trust_mark_type).toBe(MARK_TYPE);
		expect(typeof payload.iat).toBe("number");
		expect(typeof payload.exp).toBe("number");
		expect((payload.exp as number) - (payload.iat as number)).toBe(86400);
	});

	it("respects custom trustMarkTtlSeconds", async () => {
		const { ctx } = await createTestContext({
			trustMarkIssuers: { [MARK_TYPE]: [ENTITY_ID] },
			trustMarkTtlSeconds: 3600,
		});
		const handler = createTrustMarkIssuanceHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(MARK_TYPE)}&sub=${encodeURIComponent(SUB1)}`,
			),
		);

		expect(res.status).toBe(200);
		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		expect((payload.exp as number) - (payload.iat as number)).toBe(3600);
	});

	it("returns existing active trust mark", async () => {
		const { ctx, trustMarkStore } = await createTestContext({
			trustMarkIssuers: { [MARK_TYPE]: [ENTITY_ID] },
		});

		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB1,
			jwt: "existing.jwt.token",
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});

		const handler = createTrustMarkIssuanceHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(MARK_TYPE)}&sub=${encodeURIComponent(SUB1)}`,
			),
		);

		const body = await res.text();
		expect(body).toBe("existing.jwt.token");
	});

	it("returns 403 when authority is not in the authorized issuers list", async () => {
		const otherAuthority = entityId("https://other-authority.example.com");
		const { ctx } = await createTestContext({
			trustMarkIssuers: { [MARK_TYPE]: [otherAuthority] },
		});
		const handler = createTrustMarkIssuanceHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(MARK_TYPE)}&sub=${encodeURIComponent(SUB1)}`,
			),
		);

		expect(res.status).toBe(403);
	});

	it("allows issuance when trust mark type is not in issuers map", async () => {
		const { ctx } = await createTestContext({
			trustMarkIssuers: { "https://other.example.com/mark": [ENTITY_ID] },
		});
		const handler = createTrustMarkIssuanceHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(MARK_TYPE)}&sub=${encodeURIComponent(SUB1)}`,
			),
		);

		expect(res.status).toBe(200);
	});

	it("embeds delegation when trustMarkDelegations is configured for the type", async () => {
		const ownerKeys = await generateSigningKey("ES256");
		const delegationJwt = await signTrustMarkDelegation({
			issuer: "https://owner.example.com",
			subject: ENTITY_ID,
			trustMarkType: MARK_TYPE,
			privateKey: ownerKeys.privateKey,
		});

		const { ctx } = await createTestContext({
			trustMarkIssuers: { [MARK_TYPE]: [ENTITY_ID] },
			trustMarkDelegations: { [MARK_TYPE]: delegationJwt },
		});
		const handler = createTrustMarkIssuanceHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(MARK_TYPE)}&sub=${encodeURIComponent(SUB1)}`,
			),
		);

		expect(res.status).toBe(200);
		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		expect(payload.delegation).toBe(delegationJwt);
	});

	it("does NOT embed delegation when trustMarkDelegations is not configured", async () => {
		const { ctx } = await createTestContext({
			trustMarkIssuers: { [MARK_TYPE]: [ENTITY_ID] },
		});
		const handler = createTrustMarkIssuanceHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(MARK_TYPE)}&sub=${encodeURIComponent(SUB1)}`,
			),
		);

		expect(res.status).toBe(200);
		const jwt = await res.text();
		const decoded = decodeEntityStatement(jwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		expect(payload.delegation).toBeUndefined();
	});

	it("issued trust mark with delegation passes validateTrustMark", async () => {
		const ownerKeys = await generateSigningKey("ES256");
		const delegationJwt = await signTrustMarkDelegation({
			issuer: "https://owner.example.com",
			subject: ENTITY_ID,
			trustMarkType: MARK_TYPE,
			privateKey: ownerKeys.privateKey,
		});

		const { ctx, publicKey } = await createTestContext({
			trustMarkIssuers: { [MARK_TYPE]: [ENTITY_ID] },
			trustMarkDelegations: { [MARK_TYPE]: delegationJwt },
		});
		const handler = createTrustMarkIssuanceHandler(ctx);
		const res = await handler(
			new Request(
				`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(MARK_TYPE)}&sub=${encodeURIComponent(SUB1)}`,
			),
		);

		const jwt = await res.text();
		const result = await validateTrustMark(
			jwt,
			{ [MARK_TYPE]: [ENTITY_ID] },
			{ keys: [publicKey] },
			{
				trustMarkOwners: {
					[MARK_TYPE]: {
						sub: "https://owner.example.com",
						jwks: { keys: [ownerKeys.publicKey] },
					},
				},
			},
		);

		expect(isOk(result)).toBe(true);
		if (isOk(result)) {
			expect(result.value.delegation).toBeDefined();
			expect(result.value.delegation?.issuer).toBe("https://owner.example.com");
			expect(result.value.delegation?.subject).toBe(ENTITY_ID);
		}
	});

	it("issueTrustMarkDelegation() server method returns valid delegation JWT", async () => {
		const keyStore = new MemoryKeyStore();
		const keys = await generateSigningKey("ES256");
		const signingKey = { ...keys.privateKey, kid: "delegation-key-1" };
		await keyStore.addKey(signingKey);
		await keyStore.activateKey("delegation-key-1");

		const server = createAuthorityServer({
			entityId: entityId("https://owner.example.com"),
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://owner.example.com/federation_fetch",
					federation_list_endpoint: "https://owner.example.com/federation_list",
				},
			},
			subordinateStore: new MemorySubordinateStore(),
			keyStore,
		});

		const delegationJwt = await server.issueTrustMarkDelegation(
			"https://issuer.example.com",
			"https://example.com/tm",
		);

		const decoded = decodeEntityStatement(delegationJwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		expect(decoded.value.header.typ).toBe(JwtTyp.TrustMarkDelegation);
		const payload = decoded.value.payload as Record<string, unknown>;
		expect(payload.iss).toBe("https://owner.example.com");
		expect(payload.sub).toBe("https://issuer.example.com");
		expect(payload.trust_mark_type).toBe("https://example.com/tm");
	});
});
