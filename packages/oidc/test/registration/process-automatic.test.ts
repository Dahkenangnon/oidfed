import {
	entityId,
	generateSigningKey,
	InMemoryJtiStore,
	JwtTyp,
	signEntityStatement,
} from "@oidfed/core";
import { describe, expect, it, vi } from "vitest";
import { processAutomaticRegistration } from "../../src/registration/process-automatic.js";
import { createMockFederation, LEAF_ID, OP_ID } from "../test-helpers.js";

describe("processAutomaticRegistration (Result pattern)", () => {
	async function createValidRequestObject(fed: Awaited<ReturnType<typeof createMockFederation>>) {
		const now = Math.floor(Date.now() / 1000);
		const payload = {
			iss: LEAF_ID,
			client_id: LEAF_ID,
			aud: OP_ID,
			jti: crypto.randomUUID(),
			iat: now,
			exp: now + 300,
			redirect_uri: "https://rp.example.com/callback",
			scope: "openid",
			response_type: "code",
		};

		return signEntityStatement(payload, fed.leafSigningKey, {
			kid: fed.leafSigningKey.kid,
			typ: "oauth-authz-req+jwt",
		});
	}

	it("returns ok for valid Request Object", async () => {
		const fed = await createMockFederation();
		const jwt = await createValidRequestObject(fed);

		const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
			...fed.options,
			opEntityId: OP_ID,
		});

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.rpEntityId).toBe(LEAF_ID);
	});

	it("returns ok with resolvedRpMetadata", async () => {
		const fed = await createMockFederation();
		const jwt = await createValidRequestObject(fed);

		const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
			...fed.options,
			opEntityId: OP_ID,
		});

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.resolvedRpMetadata).toBeDefined();
	});

	it("returns ok with trustChain", async () => {
		const fed = await createMockFederation();
		const jwt = await createValidRequestObject(fed);

		const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
			...fed.options,
			opEntityId: OP_ID,
		});

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.trustChain.entityId).toBe(LEAF_ID);
	});

	it("returns err for wrong typ header", async () => {
		const fed = await createMockFederation();
		const now = Math.floor(Date.now() / 1000);
		const jwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				client_id: LEAF_ID,
				aud: OP_ID,
				jti: crypto.randomUUID(),
				iat: now,
				exp: now + 300,
			},
			fed.leafSigningKey,
			{ kid: fed.leafSigningKey.kid, typ: JwtTyp.EntityStatement },
		);

		const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
			...fed.options,
			opEntityId: OP_ID,
		});

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("typ");
	});

	it("returns err if sub claim is present", async () => {
		const fed = await createMockFederation();
		const now = Math.floor(Date.now() / 1000);
		const jwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				sub: LEAF_ID,
				client_id: LEAF_ID,
				aud: OP_ID,
				jti: crypto.randomUUID(),
				iat: now,
				exp: now + 300,
			},
			fed.leafSigningKey,
			{ kid: fed.leafSigningKey.kid, typ: "oauth-authz-req+jwt" },
		);

		const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
			...fed.options,
			opEntityId: OP_ID,
		});

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("sub");
	});

	it("returns err if iss !== client_id", async () => {
		const fed = await createMockFederation();
		const now = Math.floor(Date.now() / 1000);
		const jwt = await signEntityStatement(
			{
				iss: "https://other.example.com",
				client_id: LEAF_ID,
				aud: OP_ID,
				jti: crypto.randomUUID(),
				iat: now,
				exp: now + 300,
			},
			fed.leafSigningKey,
			{ kid: fed.leafSigningKey.kid, typ: "oauth-authz-req+jwt" },
		);

		const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
			...fed.options,
			opEntityId: OP_ID,
		});

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("iss");
	});

	it("CRIT-2: returns err if aud does not match opEntityId (required)", async () => {
		const fed = await createMockFederation();
		const now = Math.floor(Date.now() / 1000);
		const jwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				client_id: LEAF_ID,
				aud: "https://wrong-op.example.com",
				jti: crypto.randomUUID(),
				iat: now,
				exp: now + 300,
			},
			fed.leafSigningKey,
			{ kid: fed.leafSigningKey.kid, typ: "oauth-authz-req+jwt" },
		);

		const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
			...fed.options,
			opEntityId: OP_ID,
		});

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("aud");
	});

	it("returns err for expired Request Object", async () => {
		const fed = await createMockFederation();
		const now = Math.floor(Date.now() / 1000);
		const jwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				client_id: LEAF_ID,
				aud: OP_ID,
				jti: crypto.randomUUID(),
				iat: now - 600,
				exp: now - 300,
			},
			fed.leafSigningKey,
			{ kid: fed.leafSigningKey.kid, typ: "oauth-authz-req+jwt" },
		);

		const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
			...fed.options,
			opEntityId: OP_ID,
		});

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("expired");
	});

	it("returns err for missing exp", async () => {
		const fed = await createMockFederation();
		const now = Math.floor(Date.now() / 1000);
		const jwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				client_id: LEAF_ID,
				aud: OP_ID,
				jti: crypto.randomUUID(),
				iat: now,
			},
			fed.leafSigningKey,
			{ kid: fed.leafSigningKey.kid, typ: "oauth-authz-req+jwt" },
		);

		const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
			...fed.options,
			opEntityId: OP_ID,
		});

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("exp");
	});

	it("returns err for missing jti", async () => {
		const fed = await createMockFederation();
		const now = Math.floor(Date.now() / 1000);
		const jwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				client_id: LEAF_ID,
				aud: OP_ID,
				iat: now,
				exp: now + 300,
			},
			fed.leafSigningKey,
			{ kid: fed.leafSigningKey.kid, typ: "oauth-authz-req+jwt" },
		);

		const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
			...fed.options,
			opEntityId: OP_ID,
		});

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.description).toContain("jti");
	});

	it("HIGH-1: detects replay via JTI store", async () => {
		const fed = await createMockFederation();
		const jtiStore = new InMemoryJtiStore();
		const jwt = await createValidRequestObject(fed);

		// First request succeeds
		const result1 = await processAutomaticRegistration(jwt, fed.trustAnchors, {
			...fed.options,
			opEntityId: OP_ID,
			jtiStore,
		});
		expect(result1.ok).toBe(true);

		// Replay detected
		const result2 = await processAutomaticRegistration(jwt, fed.trustAnchors, {
			...fed.options,
			opEntityId: OP_ID,
			jtiStore,
		});
		expect(result2.ok).toBe(false);
		if (result2.ok) return;
		expect(result2.error.description).toContain("replay");

		jtiStore.dispose();
	});

	it("HIGH-3: respects clock skew", async () => {
		const fed = await createMockFederation();
		const now = Math.floor(Date.now() / 1000);
		// Expired 30 seconds ago, but with 60s clock skew should still be valid
		const jwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				client_id: LEAF_ID,
				aud: OP_ID,
				jti: crypto.randomUUID(),
				iat: now - 330,
				exp: now - 30,
			},
			fed.leafSigningKey,
			{ kid: fed.leafSigningKey.kid, typ: "oauth-authz-req+jwt" },
		);

		const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
			...fed.options,
			opEntityId: OP_ID,
			clockSkewSeconds: 60,
		});

		// now - 60 = now - 60, exp = now - 30, now - clockSkew < exp so valid
		expect(result.ok).toBe(true);
	});

	it("returns err for unknown RP", async () => {
		const fed = await createMockFederation();
		const { privateKey } = await generateSigningKey("ES256");
		const unknownEntity = entityId("https://unknown-rp.example.com");
		const now = Math.floor(Date.now() / 1000);
		const jwt = await signEntityStatement(
			{
				iss: unknownEntity,
				client_id: unknownEntity,
				aud: OP_ID,
				jti: crypto.randomUUID(),
				iat: now,
				exp: now + 300,
			},
			privateKey,
			{ kid: privateKey.kid, typ: "oauth-authz-req+jwt" },
		);

		const result = await processAutomaticRegistration(jwt, fed.trustAnchors, {
			...fed.options,
			opEntityId: OP_ID,
		});

		expect(result.ok).toBe(false);
	});
});

describe("processAutomaticRegistration — jtiStore", () => {
	it("does not emit console.warn when no jtiStore is provided (BP-3)", async () => {
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const fed = await createMockFederation();
		const now = Math.floor(Date.now() / 1000);
		const jwt = await signEntityStatement(
			{
				iss: LEAF_ID,
				client_id: LEAF_ID,
				aud: OP_ID,
				jti: crypto.randomUUID(),
				iat: now,
				exp: now + 300,
			},
			fed.leafSigningKey,
			{ kid: fed.leafSigningKey.kid, typ: "oauth-authz-req+jwt" },
		);

		await processAutomaticRegistration(jwt, fed.trustAnchors, {
			...fed.options,
			opEntityId: OP_ID,
			// jtiStore intentionally omitted
		});

		expect(warnSpy).not.toHaveBeenCalled();
		warnSpy.mockRestore();
	});
});
