import { describe, expect, it, vi } from "vitest";
import { JwtTyp } from "../../src/constants.js";
import { generateSigningKey } from "../../src/jose/keys.js";
import { signEntityStatement } from "../../src/jose/sign.js";
import type { JWK } from "../../src/schemas/jwk.js";
import { refreshTrustChain } from "../../src/trust-chain/refresh.js";
import type {
	Clock,
	EntityId,
	ParsedEntityStatement,
	TrustAnchorSet,
	ValidatedTrustChain,
} from "../../src/types.js";

const now = Math.floor(Date.now() / 1000);

async function signEC(
	entityId: string,
	privateKey: JWK,
	publicKey: JWK,
	overrides?: Record<string, unknown>,
) {
	return signEntityStatement(
		{
			iss: entityId,
			sub: entityId,
			iat: now,
			exp: now + 3600,
			jwks: { keys: [publicKey] },
			...overrides,
		},
		privateKey,
		{ typ: JwtTyp.EntityStatement },
	);
}

function makeValidatedChain(overrides: Partial<ValidatedTrustChain> = {}): ValidatedTrustChain {
	return {
		statements: [
			{
				header: { alg: "ES256", typ: "entity-statement+jwt", kid: "k1" },
				payload: {
					iss: "https://leaf.example.com",
					sub: "https://leaf.example.com",
					iat: now,
					exp: now + 3600,
					jwks: { keys: [{ kty: "EC", kid: "k1", crv: "P-256", x: "x", y: "y" }] },
				},
			} as ParsedEntityStatement,
		],
		entityId: "https://leaf.example.com" as EntityId,
		trustAnchorId: "https://ta.example.com" as EntityId,
		expiresAt: now + 3600,
		resolvedMetadata: {},
		trustMarks: [],
		...overrides,
	};
}

describe("refreshTrustChain", () => {
	it("returns the same chain if not expired", async () => {
		const chain = makeValidatedChain({ expiresAt: now + 3600 });
		const trustAnchors: TrustAnchorSet = new Map();
		const futureClock: Clock = { now: () => now };

		const result = await refreshTrustChain(chain, trustAnchors, undefined, futureClock);
		expect(result).toBe(chain);
	});

	it("re-resolves when chain is expired", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
				metadata: { openid_relying_party: { client_name: "Leaf" } },
			},
		);

		const ss = await signEntityStatement(
			{
				iss: "https://ta.example.com",
				sub: "https://leaf.example.com",
				iat: now,
				exp: now + 7200,
				jwks: { keys: [leafKeys.publicKey] },
			},
			taKeys.privateKey,
			{ typ: JwtTyp.EntityStatement },
		);

		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey, {
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ta.example.com/fetch",
				},
			},
		});

		const trustAnchors: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		// Create an expired chain
		const expiredChain = makeValidatedChain({ expiresAt: now - 100 });
		const pastClock: Clock = { now: () => now };

		// Mock httpClient to return the chain entities
		const httpClient = vi
			.fn()
			.mockResolvedValueOnce(
				new Response(leafEc, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				}),
			)
			.mockResolvedValueOnce(
				new Response(taEc, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				}),
			)
			.mockResolvedValueOnce(
				new Response(ss, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				}),
			)
			.mockResolvedValueOnce(
				new Response(taEc, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				}),
			);

		const result = await refreshTrustChain(expiredChain, trustAnchors, { httpClient }, pastClock);
		expect(result).not.toBe(expiredChain);
		expect(result.entityId).toBe("https://leaf.example.com");
	});

	it("re-resolves when forceRefresh is true even if not expired", async () => {
		const taKeys = await generateSigningKey("ES256");
		const leafKeys = await generateSigningKey("ES256");

		const leafEc = await signEC(
			"https://leaf.example.com",
			leafKeys.privateKey,
			leafKeys.publicKey,
			{
				authority_hints: ["https://ta.example.com"],
				metadata: { openid_relying_party: { client_name: "Leaf" } },
			},
		);

		const ss = await signEntityStatement(
			{
				iss: "https://ta.example.com",
				sub: "https://leaf.example.com",
				iat: now,
				exp: now + 7200,
				jwks: { keys: [leafKeys.publicKey] },
			},
			taKeys.privateKey,
			{ typ: JwtTyp.EntityStatement },
		);

		const taEc = await signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey, {
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ta.example.com/fetch",
				},
			},
		});

		const trustAnchors: TrustAnchorSet = new Map([
			["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
		]);

		const freshChain = makeValidatedChain({ expiresAt: now + 9999 });
		const clock: Clock = { now: () => now };

		const httpClient = vi
			.fn()
			.mockResolvedValueOnce(
				new Response(leafEc, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				}),
			)
			.mockResolvedValueOnce(
				new Response(taEc, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				}),
			)
			.mockResolvedValueOnce(
				new Response(ss, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				}),
			)
			.mockResolvedValueOnce(
				new Response(taEc, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				}),
			);

		const result = await refreshTrustChain(
			freshChain,
			trustAnchors,
			{ httpClient, forceRefresh: true },
			clock,
		);
		expect(result).not.toBe(freshChain);
		expect(httpClient).toHaveBeenCalled();
	});

	it("throws if re-resolve fails", async () => {
		const expiredChain = makeValidatedChain({ expiresAt: now - 100 });
		const trustAnchors: TrustAnchorSet = new Map();
		const clock: Clock = { now: () => now };

		const httpClient = vi.fn().mockResolvedValue(new Response("Not Found", { status: 404 }));

		await expect(
			refreshTrustChain(expiredChain, trustAnchors, { httpClient }, clock),
		).rejects.toThrow("Failed to refresh trust chain");
	});
});
