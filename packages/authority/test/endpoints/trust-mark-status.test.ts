import {
	decodeEntityStatement,
	entityId,
	generateSigningKey,
	isOk,
	type JWK,
	JwtTyp,
	signEntityStatement,
	TrustMarkStatus,
} from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { createTrustMarkStatusHandler } from "../../src/endpoints/trust-mark-status.js";
import { rotateKey, rotateKeyCompromise } from "../../src/keys/index.js";
import { createTestContext, ENTITY_ID } from "./test-helpers.js";

const SUB1 = entityId("https://sub1.example.com");
const MARK_TYPE = "https://trust.example.com/mark-a";

async function issueTrustMarkJwt(
	iss: string,
	sub: string,
	trustMarkType: string,
	signingKey: JWK,
	overrides?: Record<string, unknown>,
): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	return signEntityStatement(
		{ iss, sub, trust_mark_type: trustMarkType, iat: now, exp: now + 3600, ...overrides },
		signingKey,
		{ typ: JwtTyp.TrustMark },
	);
}

function postRequest(body: string): Request {
	return new Request("https://authority.example.com/federation_trust_mark_status", {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body,
	});
}

async function decodeStatusResponse(res: Response): Promise<{ status: string }> {
	const jwt = await res.text();
	const decoded = decodeEntityStatement(jwt);
	expect(isOk(decoded)).toBe(true);
	if (!isOk(decoded)) throw new Error("Failed to decode");
	return decoded.value.payload as unknown as { status: string };
}

describe("createTrustMarkStatusHandler", () => {
	it("returns status: active for active trust mark", async () => {
		const { ctx, signingKey, trustMarkStore } = await createTestContext();
		const jwt = await issueTrustMarkJwt(ENTITY_ID, SUB1, MARK_TYPE, signingKey);
		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB1,
			jwt,
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});

		const handler = createTrustMarkStatusHandler(ctx);
		const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
		expect(res.status).toBe(200);
		expect(res.headers.get("Content-Type")).toBe("application/trust-mark-status-response+jwt");

		const payload = await decodeStatusResponse(res);
		expect(payload.status).toBe(TrustMarkStatus.Active);
	});

	it("returns status: revoked for revoked trust mark", async () => {
		const { ctx, signingKey, trustMarkStore } = await createTestContext();
		const jwt = await issueTrustMarkJwt(ENTITY_ID, SUB1, MARK_TYPE, signingKey);
		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB1,
			jwt,
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});
		await trustMarkStore.revoke(MARK_TYPE, SUB1);

		const handler = createTrustMarkStatusHandler(ctx);
		const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
		expect(res.status).toBe(200);

		const payload = await decodeStatusResponse(res);
		expect(payload.status).toBe(TrustMarkStatus.Revoked);
	});

	it("returns status: expired for expired trust mark", async () => {
		const { ctx, signingKey, trustMarkStore } = await createTestContext();
		const now = Math.floor(Date.now() / 1000);
		const jwt = await issueTrustMarkJwt(ENTITY_ID, SUB1, MARK_TYPE, signingKey, {
			iat: now - 7200,
			exp: now - 3600,
		});
		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB1,
			jwt,
			issuedAt: now - 7200,
			active: true,
		});

		const handler = createTrustMarkStatusHandler(ctx);
		const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
		expect(res.status).toBe(200);

		const payload = await decodeStatusResponse(res);
		expect(payload.status).toBe(TrustMarkStatus.Expired);
	});

	it("returns 404 for unknown trust mark", async () => {
		const { ctx, signingKey } = await createTestContext();
		const jwt = await issueTrustMarkJwt(ENTITY_ID, SUB1, MARK_TYPE, signingKey);

		const handler = createTrustMarkStatusHandler(ctx);
		const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
		expect(res.status).toBe(404);
	});

	it("returns 404 for wrong issuer", async () => {
		const { ctx, trustMarkStore } = await createTestContext();
		const { privateKey: otherKey } = await generateSigningKey("ES256");
		const wrongIssuer = entityId("https://other-authority.example.com");
		const jwt = await issueTrustMarkJwt(wrongIssuer, SUB1, MARK_TYPE, otherKey);

		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB1,
			jwt,
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});

		const handler = createTrustMarkStatusHandler(ctx);
		const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
		expect(res.status).toBe(404);
	});

	it("returns 400 for missing trust_mark body", async () => {
		const { ctx } = await createTestContext();
		const handler = createTrustMarkStatusHandler(ctx);
		const res = await handler(postRequest(""));

		expect(res.status).toBe(400);
		const body = await res.json();
		expect(body.error).toBe("invalid_request");
	});

	it("returns 405 for GET", async () => {
		const { ctx } = await createTestContext();
		const handler = createTrustMarkStatusHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_trust_mark_status"),
		);

		expect(res.status).toBe(405);
		expect(res.headers.get("Allow")).toBe("POST");
	});

	it("returns expired before checking revocation status", async () => {
		const { ctx, signingKey, trustMarkStore } = await createTestContext();
		const now = Math.floor(Date.now() / 1000);
		// Issue an expired trust mark that is also revoked
		const jwt = await issueTrustMarkJwt(ENTITY_ID, SUB1, MARK_TYPE, signingKey, {
			iat: now - 7200,
			exp: now - 3600,
		});
		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB1,
			jwt,
			issuedAt: now - 7200,
			active: true,
		});
		await trustMarkStore.revoke(MARK_TYPE, SUB1);

		const handler = createTrustMarkStatusHandler(ctx);
		const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
		expect(res.status).toBe(200);

		const payload = await decodeStatusResponse(res);
		// Expired should take precedence over revoked
		expect(payload.status).toBe(TrustMarkStatus.Expired);
	});

	it("returns Invalid for tampered trust mark signature (MED-2)", async () => {
		const { ctx, signingKey, trustMarkStore } = await createTestContext();
		const jwt = await issueTrustMarkJwt(ENTITY_ID, SUB1, MARK_TYPE, signingKey);
		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB1,
			jwt,
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});

		// Tamper the JWT signature by flipping a character
		const parts = jwt.split(".");
		const tamperedSignature = `${(parts[2] ?? "").slice(0, -2)}xx`;
		const tamperedJwt = `${parts[0]}.${parts[1]}.${tamperedSignature}`;

		const handler = createTrustMarkStatusHandler(ctx);
		const res = await handler(postRequest(`trust_mark=${encodeURIComponent(tamperedJwt)}`));
		expect(res.status).toBe(200);
		const payload = await decodeStatusResponse(res);
		expect(payload.status).toBe(TrustMarkStatus.Invalid);
	});

	it("returns 413 for body exceeding 64KB (MED-3)", async () => {
		const { ctx } = await createTestContext();
		const handler = createTrustMarkStatusHandler(ctx);
		const oversized = "x".repeat(65 * 1024);
		const res = await handler(
			new Request("https://authority.example.com/federation_trust_mark_status", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					"Content-Length": String(oversized.length),
				},
				body: oversized,
			}),
		);
		expect(res.status).toBe(413);
	});

	it("returns Invalid for trust_mark_type that is not a URL (LOW-6)", async () => {
		const { ctx, signingKey } = await createTestContext();
		const now = Math.floor(Date.now() / 1000);
		const jwt = await signEntityStatement(
			{
				iss: ENTITY_ID,
				sub: SUB1,
				trust_mark_type: "not-a-url",
				iat: now,
				exp: now + 3600,
			},
			signingKey,
			{ typ: JwtTyp.TrustMark },
		);

		const handler = createTrustMarkStatusHandler(ctx);
		const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
		expect(res.status).toBe(200);
		const payload = await decodeStatusResponse(res);
		expect(payload.status).toBe(TrustMarkStatus.Invalid);
	});

	it("returns expired for trust mark with exp: 0 (epoch)", async () => {
		const { ctx, signingKey, trustMarkStore } = await createTestContext();
		const jwt = await issueTrustMarkJwt(ENTITY_ID, SUB1, MARK_TYPE, signingKey, {
			iat: 0,
			exp: 0,
		});
		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB1,
			jwt,
			issuedAt: 0,
			active: true,
		});

		const handler = createTrustMarkStatusHandler(ctx);
		const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
		expect(res.status).toBe(200);

		const payload = await decodeStatusResponse(res);
		expect(payload.status).toBe(TrustMarkStatus.Expired);
	});

	it("validates trust mark signed with retiring key as active", async () => {
		const { ctx, signingKey, trustMarkStore, keyStore } = await createTestContext();
		// Issue trust mark with current key
		const jwt = await issueTrustMarkJwt(ENTITY_ID, SUB1, MARK_TYPE, signingKey);
		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB1,
			jwt,
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});

		// Rotate key — original key becomes "retiring"
		const { privateKey: newKey } = await generateSigningKey("ES256");
		const newSigningKey = { ...newKey, kid: "rotated-key-1" };
		await rotateKey(keyStore, newSigningKey);

		const handler = createTrustMarkStatusHandler(ctx);
		const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
		expect(res.status).toBe(200);

		const payload = await decodeStatusResponse(res);
		expect(payload.status).toBe(TrustMarkStatus.Active);
	});

	it("returns invalid for trust mark signed with revoked key", async () => {
		const { ctx, signingKey, trustMarkStore, keyStore } = await createTestContext();
		const jwt = await issueTrustMarkJwt(ENTITY_ID, SUB1, MARK_TYPE, signingKey);
		await trustMarkStore.issue({
			trustMarkType: MARK_TYPE,
			subject: SUB1,
			jwt,
			issuedAt: Math.floor(Date.now() / 1000),
			active: true,
		});

		// Revoke the signing key due to compromise
		const { privateKey: newKey } = await generateSigningKey("ES256");
		const newSigningKey = { ...newKey, kid: "new-key-1" };
		await rotateKeyCompromise(keyStore, newSigningKey, "test-key-1");

		const handler = createTrustMarkStatusHandler(ctx);
		const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
		expect(res.status).toBe(200);

		const payload = await decodeStatusResponse(res);
		expect(payload.status).toBe(TrustMarkStatus.Invalid);
	});

	it("returns 501 when no trust mark store", async () => {
		const { ctx } = await createTestContext({ trustMarkStore: undefined });
		const handler = createTrustMarkStatusHandler(ctx);
		const res = await handler(
			new Request("https://authority.example.com/federation_trust_mark_status", {
				method: "POST",
				body: "trust_mark=foo",
			}),
		);

		expect(res.status).toBe(501);
	});
});
