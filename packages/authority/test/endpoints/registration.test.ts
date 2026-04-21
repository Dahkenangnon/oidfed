import {
	decodeEntityStatement,
	err,
	FederationErrorCode,
	federationError,
	generateSigningKey,
	isOk,
	JwtTyp,
	MediaType,
	signEntityStatement,
} from "@oidfed/core";
import { describe, expect, it } from "vitest";
import { createRegistrationHandler } from "../../src/endpoints/registration.js";
import type { RegistrationProtocolAdapter } from "../../src/endpoints/registration-adapter.js";
import { createTestContext, ENTITY_ID } from "./test-helpers.js";

const now = Math.floor(Date.now() / 1000);

/** Default metadata and authority_hints required by explicit registration schema. */
const REQUIRED_FIELDS = {
	authority_hints: ["https://ta.example.com"],
	metadata: {
		openid_relying_party: {
			redirect_uris: ["https://rp.example.com/callback"],
			response_types: ["code"],
		},
	},
};

async function buildRegistrationRequest(
	rpEntityId: string,
	opEntityId: string,
	rpPrivateKey: Parameters<typeof signEntityStatement>[1],
	rpPublicKey: Record<string, unknown>,
	overrides?: Record<string, unknown>,
) {
	const payload: Record<string, unknown> = {
		iss: rpEntityId,
		sub: rpEntityId,
		aud: opEntityId,
		iat: now,
		exp: now + 3600,
		jwks: { keys: [rpPublicKey] },
		...REQUIRED_FIELDS,
		...overrides,
	};
	return signEntityStatement(payload, rpPrivateKey, {
		typ: JwtTyp.EntityStatement,
	});
}

describe("createRegistrationHandler", () => {
	it("accepts a valid explicit registration request", async () => {
		const { ctx } = await createTestContext();
		const handler = createRegistrationHandler(ctx);

		const rpKeys = await generateSigningKey("ES256");
		const rpId = "https://rp.example.com";
		const jwt = await buildRegistrationRequest(
			rpId,
			ENTITY_ID as string,
			rpKeys.privateKey,
			rpKeys.publicKey as unknown as Record<string, unknown>,
		);

		const res = await handler(
			new Request("https://authority.example.com/federation_registration", {
				method: "POST",
				headers: { "Content-Type": MediaType.EntityStatement },
				body: jwt,
			}),
		);

		expect(res.status).toBe(200);
		expect(res.headers.get("Content-Type")).toBe(MediaType.ExplicitRegistrationResponse);

		const responseJwt = await res.text();
		const decoded = decodeEntityStatement(responseJwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		expect(decoded.value.header.typ).toBe(JwtTyp.ExplicitRegistrationResponse);
		expect(decoded.value.payload.iss).toBe(ENTITY_ID);
		expect(decoded.value.payload.sub).toBe(rpId);
		const payload = decoded.value.payload as Record<string, unknown>;
		expect(payload.aud).toBe(rpId);
		expect(payload.trust_anchor).toBeDefined();
		// authority_hints required in response
		expect(payload.authority_hints).toBeDefined();
		expect(Array.isArray(payload.authority_hints)).toBe(true);
		expect((payload.authority_hints as string[]).length).toBe(1);
	});

	it("response includes metadata with openid_relying_party and client_id", async () => {
		const { ctx } = await createTestContext();
		const handler = createRegistrationHandler(ctx);

		const rpKeys = await generateSigningKey("ES256");
		const rpId = "https://rp.example.com";
		const jwt = await buildRegistrationRequest(
			rpId,
			ENTITY_ID as string,
			rpKeys.privateKey,
			rpKeys.publicKey as unknown as Record<string, unknown>,
		);

		const res = await handler(
			new Request("https://authority.example.com/federation_registration", {
				method: "POST",
				headers: { "Content-Type": MediaType.EntityStatement },
				body: jwt,
			}),
		);

		expect(res.status).toBe(200);
		const responseJwt = await res.text();
		const decoded = decodeEntityStatement(responseJwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		const meta = payload.metadata as Record<string, Record<string, unknown>>;
		expect(meta.openid_relying_party).toBeDefined();
		expect(meta.openid_relying_party.client_id).toBe(rpId);
	});

	it("response includes OIDC default values", async () => {
		const { ctx } = await createTestContext();
		const handler = createRegistrationHandler(ctx);

		const rpKeys = await generateSigningKey("ES256");
		const rpId = "https://rp.example.com";
		const jwt = await buildRegistrationRequest(
			rpId,
			ENTITY_ID as string,
			rpKeys.privateKey,
			rpKeys.publicKey as unknown as Record<string, unknown>,
		);

		const res = await handler(
			new Request("https://authority.example.com/federation_registration", {
				method: "POST",
				headers: { "Content-Type": MediaType.EntityStatement },
				body: jwt,
			}),
		);

		expect(res.status).toBe(200);
		const responseJwt = await res.text();
		const decoded = decodeEntityStatement(responseJwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		const rpMeta = (payload.metadata as Record<string, Record<string, unknown>>)
			.openid_relying_party;
		// Should have defaults if not present in request
		expect(rpMeta.grant_types).toEqual(["authorization_code"]);
		expect(rpMeta.token_endpoint_auth_method).toBe("client_secret_basic");
	});

	it("rejects wrong Content-Type", async () => {
		const { ctx } = await createTestContext();
		const handler = createRegistrationHandler(ctx);

		const res = await handler(
			new Request("https://authority.example.com/federation_registration", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: "{}",
			}),
		);

		expect(res.status).toBe(400);
	});

	it("accepts application/trust-chain+json Content-Type", async () => {
		const { ctx } = await createTestContext();
		const handler = createRegistrationHandler(ctx);

		const rpKeys = await generateSigningKey("ES256");
		const rpId = "https://rp.example.com";
		const ecJwt = await buildRegistrationRequest(
			rpId,
			ENTITY_ID as string,
			rpKeys.privateKey,
			rpKeys.publicKey as unknown as Record<string, unknown>,
		);

		// Wrap EC in a trust chain JSON array
		const chainBody = JSON.stringify([ecJwt]);

		const res = await handler(
			new Request("https://authority.example.com/federation_registration", {
				method: "POST",
				headers: { "Content-Type": MediaType.TrustChain },
				body: chainBody,
			}),
		);

		expect(res.status).toBe(200);
	});

	it("rejects wrong aud", async () => {
		const { ctx } = await createTestContext();
		const handler = createRegistrationHandler(ctx);

		const rpKeys = await generateSigningKey("ES256");
		const jwt = await buildRegistrationRequest(
			"https://rp.example.com",
			"https://wrong-op.example.com",
			rpKeys.privateKey,
			rpKeys.publicKey as unknown as Record<string, unknown>,
		);

		const res = await handler(
			new Request("https://authority.example.com/federation_registration", {
				method: "POST",
				headers: { "Content-Type": MediaType.EntityStatement },
				body: jwt,
			}),
		);

		expect(res.status).toBe(400);
		const body = (await res.json()) as Record<string, string>;
		expect(body.error_description).toContain("aud");
	});

	it("uses custom registrationResponseTtlSeconds for exp", async () => {
		const { ctx } = await createTestContext({ registrationResponseTtlSeconds: 7200 });
		const handler = createRegistrationHandler(ctx);

		const rpKeys = await generateSigningKey("ES256");
		const rpId = "https://rp.example.com";
		const jwt = await buildRegistrationRequest(
			rpId,
			ENTITY_ID as string,
			rpKeys.privateKey,
			rpKeys.publicKey as unknown as Record<string, unknown>,
		);

		const res = await handler(
			new Request("https://authority.example.com/federation_registration", {
				method: "POST",
				headers: { "Content-Type": MediaType.EntityStatement },
				body: jwt,
			}),
		);

		expect(res.status).toBe(200);
		const responseJwt = await res.text();
		const decoded = decodeEntityStatement(responseJwt);
		expect(isOk(decoded)).toBe(true);
		if (!isOk(decoded)) return;

		const payload = decoded.value.payload as Record<string, unknown>;
		const iat = payload.iat as number;
		const exp = payload.exp as number;
		expect(exp - iat).toBe(7200);
	});

	it("rejects GET method", async () => {
		const { ctx } = await createTestContext();
		const handler = createRegistrationHandler(ctx);

		const res = await handler(new Request("https://authority.example.com/federation_registration"));

		expect(res.status).toBe(405);
	});

	it("rejects invalid self-signature", async () => {
		const { ctx } = await createTestContext();
		const handler = createRegistrationHandler(ctx);

		const rpKeys = await generateSigningKey("ES256");
		const wrongKeys = await generateSigningKey("ES256");
		// Sign with wrong key but include rpKeys.publicKey in jwks
		const jwt = await buildRegistrationRequest(
			"https://rp.example.com",
			ENTITY_ID as string,
			wrongKeys.privateKey,
			rpKeys.publicKey as unknown as Record<string, unknown>,
		);

		const res = await handler(
			new Request("https://authority.example.com/federation_registration", {
				method: "POST",
				headers: { "Content-Type": MediaType.EntityStatement },
				body: jwt,
			}),
		);

		expect(res.status).toBe(400);
		const body = (await res.json()) as Record<string, string>;
		expect(body.error_description).toContain("signature");
	});

	it("validates trust_chain header — first entry must be subject's EC", async () => {
		const { ctx } = await createTestContext();
		const handler = createRegistrationHandler(ctx);

		const rpKeys = await generateSigningKey("ES256");
		const otherKeys = await generateSigningKey("ES256");
		const rpId = "https://rp.example.com";

		// Create an EC for a different entity
		const wrongEc = await signEntityStatement(
			{
				iss: "https://other.example.com",
				sub: "https://other.example.com",
				iat: now,
				exp: now + 3600,
				jwks: { keys: [otherKeys.publicKey] },
			},
			otherKeys.privateKey,
			{ typ: JwtTyp.EntityStatement },
		);

		const payload: Record<string, unknown> = {
			iss: rpId,
			sub: rpId,
			aud: ENTITY_ID,
			iat: now,
			exp: now + 3600,
			jwks: { keys: [rpKeys.publicKey] },
			...REQUIRED_FIELDS,
		};

		const jwt = await signEntityStatement(payload, rpKeys.privateKey, {
			typ: JwtTyp.EntityStatement,
			extraHeaders: { trust_chain: [wrongEc] },
		});

		const res = await handler(
			new Request("https://authority.example.com/federation_registration", {
				method: "POST",
				headers: { "Content-Type": MediaType.EntityStatement },
				body: jwt,
			}),
		);

		expect(res.status).toBe(400);
		const body = (await res.json()) as Record<string, string>;
		expect(body.error).toBe("invalid_trust_chain");
	});

	it("calls registrationProtocolAdapter.validateClientMetadata when configured", async () => {
		const rejectingAdapter: RegistrationProtocolAdapter = {
			validateClientMetadata: () =>
				err(federationError(FederationErrorCode.InvalidMetadata, "Bad RP metadata")),
			enrichResponseMetadata: (meta) => meta,
		};

		const { ctx } = await createTestContext({ registrationProtocolAdapter: rejectingAdapter });
		const handler = createRegistrationHandler(ctx);

		const rpKeys = await generateSigningKey("ES256");
		const rpId = "https://rp.example.com";
		const jwt = await buildRegistrationRequest(
			rpId,
			ENTITY_ID as string,
			rpKeys.privateKey,
			rpKeys.publicKey as unknown as Record<string, unknown>,
		);

		const res = await handler(
			new Request("https://authority.example.com/federation_registration", {
				method: "POST",
				headers: { "Content-Type": MediaType.EntityStatement },
				body: jwt,
			}),
		);

		expect(res.status).toBe(400);
		const body = (await res.json()) as Record<string, string>;
		expect(body.error).toBe("invalid_metadata");
	});

	it("succeeds without adapter (federation-only)", async () => {
		const { ctx } = await createTestContext();
		const handler = createRegistrationHandler(ctx);

		const rpKeys = await generateSigningKey("ES256");
		const rpId = "https://rp.example.com";
		const jwt = await buildRegistrationRequest(
			rpId,
			ENTITY_ID as string,
			rpKeys.privateKey,
			rpKeys.publicKey as unknown as Record<string, unknown>,
		);

		const res = await handler(
			new Request("https://authority.example.com/federation_registration", {
				method: "POST",
				headers: { "Content-Type": MediaType.EntityStatement },
				body: jwt,
			}),
		);

		// Without adapter, no protocol-specific validation — succeeds
		expect(res.status).toBe(200);
	});

	it("rejects request missing authority_hints", async () => {
		const { ctx } = await createTestContext();
		const handler = createRegistrationHandler(ctx);

		const rpKeys = await generateSigningKey("ES256");
		const rpId = "https://rp.example.com";

		const payload: Record<string, unknown> = {
			iss: rpId,
			sub: rpId,
			aud: ENTITY_ID,
			iat: now,
			exp: now + 3600,
			jwks: { keys: [rpKeys.publicKey] },
			metadata: {
				openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
			},
			// No authority_hints
		};

		const jwt = await signEntityStatement(payload, rpKeys.privateKey, {
			typ: JwtTyp.EntityStatement,
		});

		const res = await handler(
			new Request("https://authority.example.com/federation_registration", {
				method: "POST",
				headers: { "Content-Type": MediaType.EntityStatement },
				body: jwt,
			}),
		);

		expect(res.status).toBe(400);
	});

	it("rejects request without openid_relying_party in metadata", async () => {
		const { ctx } = await createTestContext();
		const handler = createRegistrationHandler(ctx);

		const rpKeys = await generateSigningKey("ES256");
		const rpId = "https://rp.example.com";

		const payload: Record<string, unknown> = {
			iss: rpId,
			sub: rpId,
			aud: ENTITY_ID,
			iat: now,
			exp: now + 3600,
			jwks: { keys: [rpKeys.publicKey] },
			authority_hints: ["https://ta.example.com"],
			metadata: {
				federation_entity: { organization_name: "Test" },
			},
		};

		const jwt = await signEntityStatement(payload, rpKeys.privateKey, {
			typ: JwtTyp.EntityStatement,
		});

		const res = await handler(
			new Request("https://authority.example.com/federation_registration", {
				method: "POST",
				headers: { "Content-Type": MediaType.EntityStatement },
				body: jwt,
			}),
		);

		expect(res.status).toBe(400);
	});

	it("calls onRegistrationInvalidation hook", async () => {
		let invalidatedSub: string | undefined;
		const { ctx } = await createTestContext({
			registrationConfig: {
				onRegistrationInvalidation: async (sub) => {
					invalidatedSub = sub as string;
				},
			},
		});
		const handler = createRegistrationHandler(ctx);

		const rpKeys = await generateSigningKey("ES256");
		const rpId = "https://rp.example.com";
		const jwt = await buildRegistrationRequest(
			rpId,
			ENTITY_ID as string,
			rpKeys.privateKey,
			rpKeys.publicKey as unknown as Record<string, unknown>,
		);

		const res = await handler(
			new Request("https://authority.example.com/federation_registration", {
				method: "POST",
				headers: { "Content-Type": MediaType.EntityStatement },
				body: jwt,
			}),
		);

		expect(res.status).toBe(200);
		expect(invalidatedSub).toBe(rpId);
	});
});

describe("createRegistrationHandler — body size limits", () => {
	it("body exactly at 64KB boundary is not rejected with 413", async () => {
		const { ctx } = await createTestContext();
		const handler = createRegistrationHandler(ctx);

		// 64KB of arbitrary content — will fail JWT validation (400), but NOT body size (413)
		const body = "x".repeat(64 * 1024);
		const res = await handler(
			new Request("https://authority.example.com/federation_registration", {
				method: "POST",
				headers: { "Content-Type": MediaType.EntityStatement },
				body,
			}),
		);

		expect(res.status).not.toBe(413);
	});

	it("body 1 byte over 64KB is rejected with 413", async () => {
		const { ctx } = await createTestContext();
		const handler = createRegistrationHandler(ctx);

		const body = "x".repeat(64 * 1024 + 1);
		const res = await handler(
			new Request("https://authority.example.com/federation_registration", {
				method: "POST",
				headers: { "Content-Type": MediaType.EntityStatement },
				body,
			}),
		);

		expect(res.status).toBe(413);
		const json = (await res.json()) as Record<string, string>;
		expect(json.error).toBe("invalid_request");
	});

	it("spoofed Content-Length: 10 with 65KB actual body is rejected with 413", async () => {
		const { ctx } = await createTestContext();
		const handler = createRegistrationHandler(ctx);

		// Simulate an attacker sending Content-Length: 10 but 65KB of actual body.
		// The streaming check must catch this regardless of the header lie.
		const bigBody = "x".repeat(65 * 1024);
		const res = await handler(
			new Request("https://authority.example.com/federation_registration", {
				method: "POST",
				headers: {
					"Content-Type": MediaType.EntityStatement,
					"Content-Length": "10",
				},
				body: bigBody,
			}),
		);

		expect(res.status).toBe(413);
	});
});
