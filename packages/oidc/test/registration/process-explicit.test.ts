import {
	entityId,
	generateSigningKey,
	type JWK,
	JwtTyp,
	MediaType,
	signEntityStatement,
} from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { processExplicitRegistration } from "../../src/registration/process-explicit.js";
import { createMockFederation, LEAF_ID, OP_ID, TA_ID } from "../test-helpers.js";

/** Build sign options, safely narrowing kid from `string | undefined` for exactOptionalPropertyTypes. */
function signOpts(key: JWK): { kid?: string; typ: string } {
	return key.kid != null
		? { kid: key.kid, typ: JwtTyp.EntityStatement }
		: { typ: JwtTyp.EntityStatement };
}

describe("processExplicitRegistration (Result pattern)", () => {
	async function createValidExplicitRequest(fed: Awaited<ReturnType<typeof createMockFederation>>) {
		const now = Math.floor(Date.now() / 1000);
		const payload = {
			iss: LEAF_ID,
			sub: LEAF_ID,
			aud: OP_ID,
			iat: now,
			exp: now + 86400,
			jwks: { keys: [fed.leafPublicKey] },
			authority_hints: [TA_ID],
			metadata: {
				openid_relying_party: {
					redirect_uris: ["https://rp.example.com/callback"],
					response_types: ["code"],
				},
			},
		};

		return signEntityStatement(payload, fed.leafSigningKey, signOpts(fed.leafSigningKey));
	}

	it("returns ok for valid explicit request", async () => {
		const fed = await createMockFederation();
		const ecJwt = await createValidExplicitRequest(fed);

		const result = await processExplicitRegistration(
			ecJwt,
			MediaType.EntityStatement,
			fed.trustAnchors,
			{ ...fed.options, opEntityId: OP_ID },
		);

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.rpEntityId).toBe(LEAF_ID);
		expect(result.value.resolvedRpMetadata).toBeDefined();
	});

	it("returns err for unknown Content-Type", async () => {
		const fed = await createMockFederation();
		const ecJwt = await createValidExplicitRequest(fed);

		const result = await processExplicitRegistration(ecJwt, "text/plain", fed.trustAnchors, {
			...fed.options,
			opEntityId: OP_ID,
		});

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("Content-Type");
	});

	it("returns err if iss !== sub", async () => {
		const fed = await createMockFederation();
		const now = Math.floor(Date.now() / 1000);
		const ecJwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				sub: "https://different-entity.example.com",
				aud: OP_ID,
				iat: now,
				exp: now + 86400,
				jwks: { keys: [fed.leafPublicKey] },
				authority_hints: [TA_ID],
				metadata: {},
			},
			fed.leafSigningKey,
			signOpts(fed.leafSigningKey),
		);

		const result = await processExplicitRegistration(
			ecJwt,
			MediaType.EntityStatement,
			fed.trustAnchors,
			{ ...fed.options, opEntityId: OP_ID },
		);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("iss");
		expect(result.error.description).toContain("sub");
	});

	it("returns err if aud does not match opEntityId", async () => {
		const fed = await createMockFederation();
		const now = Math.floor(Date.now() / 1000);
		const ecJwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				sub: LEAF_ID,
				aud: "https://wrong-op.example.com",
				iat: now,
				exp: now + 86400,
				jwks: { keys: [fed.leafPublicKey] },
				authority_hints: [TA_ID],
				metadata: {},
			},
			fed.leafSigningKey,
			signOpts(fed.leafSigningKey),
		);

		const result = await processExplicitRegistration(
			ecJwt,
			MediaType.EntityStatement,
			fed.trustAnchors,
			{ ...fed.options, opEntityId: OP_ID },
		);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("aud");
	});

	it("verifies RP EC self-signature", async () => {
		const fed = await createMockFederation();
		const { privateKey: wrongKey } = await generateSigningKey("ES256");
		const now = Math.floor(Date.now() / 1000);

		// Sign with wrong key but claim leafPublicKey in jwks
		const ecJwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				sub: LEAF_ID,
				aud: OP_ID,
				iat: now,
				exp: now + 86400,
				jwks: { keys: [fed.leafPublicKey] }, // Doesn't match signing key
				authority_hints: [TA_ID],
				metadata: { openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] } },
			},
			wrongKey,
			signOpts(wrongKey),
		);

		const result = await processExplicitRegistration(
			ecJwt,
			MediaType.EntityStatement,
			fed.trustAnchors,
			{ ...fed.options, opEntityId: OP_ID },
		);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("signature");
	});

	it("returns ok with trustChain", async () => {
		const fed = await createMockFederation();
		const ecJwt = await createValidExplicitRequest(fed);

		const result = await processExplicitRegistration(
			ecJwt,
			MediaType.EntityStatement,
			fed.trustAnchors,
			{ ...fed.options, opEntityId: OP_ID },
		);

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.trustChain.entityId).toBe(LEAF_ID);
	});

	it("returns err if RP EC has no jwks", async () => {
		const fed = await createMockFederation();
		const now = Math.floor(Date.now() / 1000);

		const ecJwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				sub: LEAF_ID,
				aud: OP_ID,
				iat: now,
				exp: now + 86400,
				// No jwks!
				authority_hints: [TA_ID],
				metadata: { openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] } },
			},
			fed.leafSigningKey,
			signOpts(fed.leafSigningKey),
		);

		const result = await processExplicitRegistration(
			ecJwt,
			MediaType.EntityStatement,
			fed.trustAnchors,
			{ ...fed.options, opEntityId: OP_ID },
		);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("jwks");
	});

	it("returns err if aud is missing from RP EC", async () => {
		const fed = await createMockFederation();
		const now = Math.floor(Date.now() / 1000);
		const ecJwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				sub: LEAF_ID,
				// no aud
				iat: now,
				exp: now + 86400,
				jwks: { keys: [fed.leafPublicKey] },
				authority_hints: [TA_ID],
				metadata: {},
			},
			fed.leafSigningKey,
			signOpts(fed.leafSigningKey),
		);

		const result = await processExplicitRegistration(
			ecJwt,
			MediaType.EntityStatement,
			fed.trustAnchors,
			{ ...fed.options, opEntityId: OP_ID },
		);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("aud");
	});

	it("accepts valid trust-chain+json body", async () => {
		const fed = await createMockFederation();
		const ecJwt = await createValidExplicitRequest(fed);
		const trustChainBody = JSON.stringify([ecJwt]);

		const result = await processExplicitRegistration(
			trustChainBody,
			MediaType.TrustChain,
			fed.trustAnchors,
			{ ...fed.options, opEntityId: OP_ID },
		);

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.rpEntityId).toBe(LEAF_ID);
	});

	it("returns err for invalid trust-chain+json (not valid JSON)", async () => {
		const fed = await createMockFederation();

		const result = await processExplicitRegistration(
			"not-json",
			MediaType.TrustChain,
			fed.trustAnchors,
			{ ...fed.options, opEntityId: OP_ID },
		);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("trust-chain+json");
	});

	it("returns err for empty trust-chain+json array", async () => {
		const fed = await createMockFederation();

		const result = await processExplicitRegistration("[]", MediaType.TrustChain, fed.trustAnchors, {
			...fed.options,
			opEntityId: OP_ID,
		});

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("non-empty array");
	});

	it("returns err for unknown RP", async () => {
		const fed = await createMockFederation();
		const { privateKey, publicKey } = await generateSigningKey("ES256");
		const unknownEntity = entityId("https://unknown-rp.example.com");
		const now = Math.floor(Date.now() / 1000);

		const ecJwt = await signEntityStatement(
			{
				iss: unknownEntity,
				sub: unknownEntity,
				aud: OP_ID,
				iat: now,
				exp: now + 86400,
				jwks: { keys: [publicKey] },
				authority_hints: [TA_ID],
				metadata: { openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] } },
			},
			privateKey,
			signOpts(privateKey),
		);

		const result = await processExplicitRegistration(
			ecJwt,
			MediaType.EntityStatement,
			fed.trustAnchors,
			{ ...fed.options, opEntityId: OP_ID },
		);

		expect(result.ok).toBe(false);
	});

	it("returns err for expired RP Entity Configuration (SEC-1)", async () => {
		const fed = await createMockFederation();
		const past = Math.floor(Date.now() / 1000) - 7200;
		const ecJwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				sub: LEAF_ID,
				aud: OP_ID,
				iat: past - 86400,
				exp: past,
				jwks: { keys: [fed.leafPublicKey] },
				authority_hints: [TA_ID],
				metadata: { openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] } },
			},
			fed.leafSigningKey,
			signOpts(fed.leafSigningKey),
		);

		const result = await processExplicitRegistration(
			ecJwt,
			MediaType.EntityStatement,
			fed.trustAnchors,
			{ ...fed.options, opEntityId: OP_ID },
		);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("expired");
	});

	it("returns err for future-dated RP EC iat (SEC-1)", async () => {
		const fed = await createMockFederation();
		const future = Math.floor(Date.now() / 1000) + 7200;
		const ecJwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				sub: LEAF_ID,
				aud: OP_ID,
				iat: future,
				exp: future + 86400,
				jwks: { keys: [fed.leafPublicKey] },
				authority_hints: [TA_ID],
				metadata: { openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] } },
			},
			fed.leafSigningKey,
			signOpts(fed.leafSigningKey),
		);

		const result = await processExplicitRegistration(
			ecJwt,
			MediaType.EntityStatement,
			fed.trustAnchors,
			{ ...fed.options, opEntityId: OP_ID },
		);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("future");
	});

	it("returns err for missing iat claim (SEC-1)", async () => {
		const fed = await createMockFederation();
		const now = Math.floor(Date.now() / 1000);
		const ecJwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				sub: LEAF_ID,
				aud: OP_ID,
				exp: now + 86400,
				jwks: { keys: [fed.leafPublicKey] },
				authority_hints: [TA_ID],
				metadata: { openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] } },
			},
			fed.leafSigningKey,
			signOpts(fed.leafSigningKey),
		);

		const result = await processExplicitRegistration(
			ecJwt,
			MediaType.EntityStatement,
			fed.trustAnchors,
			{ ...fed.options, opEntityId: OP_ID },
		);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("iat");
	});

	it("returns err for missing exp claim (SEC-1)", async () => {
		const fed = await createMockFederation();
		const now = Math.floor(Date.now() / 1000);
		const ecJwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				sub: LEAF_ID,
				aud: OP_ID,
				iat: now,
				jwks: { keys: [fed.leafPublicKey] },
				authority_hints: [TA_ID],
				metadata: { openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] } },
			},
			fed.leafSigningKey,
			signOpts(fed.leafSigningKey),
		);

		const result = await processExplicitRegistration(
			ecJwt,
			MediaType.EntityStatement,
			fed.trustAnchors,
			{ ...fed.options, opEntityId: OP_ID },
		);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("exp");
	});

	it("returns err if metadata is missing openid_relying_party (SEC-2)", async () => {
		const fed = await createMockFederation();
		const now = Math.floor(Date.now() / 1000);
		const ecJwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				sub: LEAF_ID,
				aud: OP_ID,
				iat: now,
				exp: now + 86400,
				jwks: { keys: [fed.leafPublicKey] },
				authority_hints: [TA_ID],
				metadata: { federation_entity: { organization_name: "Test" } },
			},
			fed.leafSigningKey,
			signOpts(fed.leafSigningKey),
		);

		const result = await processExplicitRegistration(
			ecJwt,
			MediaType.EntityStatement,
			fed.trustAnchors,
			{ ...fed.options, opEntityId: OP_ID },
		);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("openid_relying_party");
	});

	it("returns err if metadata is missing entirely (SEC-2)", async () => {
		const fed = await createMockFederation();
		const now = Math.floor(Date.now() / 1000);
		const ecJwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				sub: LEAF_ID,
				aud: OP_ID,
				iat: now,
				exp: now + 86400,
				jwks: { keys: [fed.leafPublicKey] },
				authority_hints: [TA_ID],
			},
			fed.leafSigningKey,
			signOpts(fed.leafSigningKey),
		);

		const result = await processExplicitRegistration(
			ecJwt,
			MediaType.EntityStatement,
			fed.trustAnchors,
			{ ...fed.options, opEntityId: OP_ID },
		);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("metadata");
	});

	it("returns err if authority_hints is missing (SPEC-2)", async () => {
		const fed = await createMockFederation();
		const now = Math.floor(Date.now() / 1000);
		const ecJwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				sub: LEAF_ID,
				aud: OP_ID,
				iat: now,
				exp: now + 86400,
				jwks: { keys: [fed.leafPublicKey] },
				metadata: { openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] } },
			},
			fed.leafSigningKey,
			signOpts(fed.leafSigningKey),
		);

		const result = await processExplicitRegistration(
			ecJwt,
			MediaType.EntityStatement,
			fed.trustAnchors,
			{ ...fed.options, opEntityId: OP_ID },
		);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("authority_hints");
	});
});
