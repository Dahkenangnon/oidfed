import {
	decodeEntityStatement,
	type EntityId,
	generateSigningKey,
	type JWK,
	JwtTyp,
	verifyEntityStatement,
} from "@oidfed/core";
import { describe, expect, it, vi } from "vitest";
import { createLeafEntity } from "../src/entity-configuration.js";
import { createLeafConfig, LEAF_ID, TA_ID } from "./test-helpers.js";

describe("createLeafEntity", () => {
	describe("validation", () => {
		it("rejects empty metadata — requires at least one Entity Type", async () => {
			const { config } = await createLeafConfig({
				metadata: {} as never,
			});
			expect(() => createLeafEntity(config)).toThrow(
				"metadata MUST contain at least one Entity Type",
			);
		});

		it("throws on empty authorityHints", async () => {
			const { config } = await createLeafConfig({ authorityHints: [] });
			expect(() => createLeafEntity(config)).toThrow("authorityHints");
		});

		it("rejects non-HTTPS authorityHint — requires valid Entity Identifiers", async () => {
			const { config } = await createLeafConfig({
				authorityHints: ["http://ta.example.com" as EntityId],
			});
			expect(() => createLeafEntity(config)).toThrow("authorityHint");
		});

		it("throws on empty signingKeys", async () => {
			const { config } = await createLeafConfig({ signingKeys: [] });
			expect(() => createLeafEntity(config)).toThrow("signingKeys");
		});

		it("throws on signing key without kid", async () => {
			const { privateKey } = await generateSigningKey("ES256");
			const keyWithoutKid = { ...privateKey } as Record<string, unknown>;
			delete keyWithoutKid.kid;
			const { config } = await createLeafConfig({
				signingKeys: [keyWithoutKid as unknown as JWK],
			});
			expect(() => createLeafEntity(config)).toThrow("kid");
		});

		it("throws when metadata includes federation_fetch_endpoint", async () => {
			const { config } = await createLeafConfig({
				metadata: {
					openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
					federation_entity: { federation_fetch_endpoint: "https://rp.example.com/fetch" },
				} as never,
			});
			expect(() => createLeafEntity(config)).toThrow(
				"Leaf entities MUST NOT publish federation_fetch_endpoint",
			);
		});

		it("throws when metadata includes federation_list_endpoint", async () => {
			const { config } = await createLeafConfig({
				metadata: {
					openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
					federation_entity: { federation_list_endpoint: "https://rp.example.com/list" },
				} as never,
			});
			expect(() => createLeafEntity(config)).toThrow(
				"Leaf entities MUST NOT publish federation_list_endpoint",
			);
		});

		it("throws on duplicate kid values", async () => {
			const { privateKey: key1 } = await generateSigningKey("ES256");
			const { privateKey: key2 } = await generateSigningKey("ES256");
			const key2WithSameKid = { ...key2, kid: key1.kid } as unknown as JWK;
			const { config } = await createLeafConfig({ signingKeys: [key1, key2WithSameKid] });
			expect(() => createLeafEntity(config)).toThrow("Duplicate kid");
		});

		it("rejects symmetric key (kty 'oct') — requires asymmetric keys", async () => {
			const { config } = await createLeafConfig({
				signingKeys: [{ kty: "oct", kid: "sym-1", k: "c2VjcmV0" } as unknown as JWK],
			});
			expect(() => createLeafEntity(config)).toThrow("Symmetric keys");
		});

		it("rejects non-HTTPS entityId — requires https scheme", async () => {
			const { config } = await createLeafConfig({
				entityId: "http://rp.example.com" as EntityId,
			});
			expect(() => createLeafEntity(config)).toThrow("HTTPS URL");
		});

		it("rejects entityId with query parameter", async () => {
			const { config } = await createLeafConfig({
				entityId: "https://rp.example.com?foo=bar" as EntityId,
			});
			expect(() => createLeafEntity(config)).toThrow("HTTPS URL");
		});

		it("rejects entityId with fragment", async () => {
			const { config } = await createLeafConfig({
				entityId: "https://rp.example.com#frag" as EntityId,
			});
			expect(() => createLeafEntity(config)).toThrow("HTTPS URL");
		});

		it("rejects empty entityId", async () => {
			const { config } = await createLeafConfig({
				entityId: "" as EntityId,
			});
			expect(() => createLeafEntity(config)).toThrow();
		});

		it("rejects ttlSeconds of 0", async () => {
			const { config } = await createLeafConfig({
				entityConfigurationTtlSeconds: 0,
			});
			expect(() => createLeafEntity(config)).toThrow(
				"entityConfigurationTtlSeconds must be positive",
			);
		});

		it("rejects negative ttlSeconds", async () => {
			const { config } = await createLeafConfig({
				entityConfigurationTtlSeconds: -1,
			});
			expect(() => createLeafEntity(config)).toThrow(
				"entityConfigurationTtlSeconds must be positive",
			);
		});
	});

	describe("entity ID normalization", () => {
		it("normalizes trailing slash in iss/sub", async () => {
			const { config } = await createLeafConfig({
				entityId: "https://rp.example.com/" as EntityId,
			});
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();

			const decoded = decodeEntityStatement(jwt);
			expect(decoded.ok).toBe(true);
			if (!decoded.ok) return;

			expect(decoded.value.payload.iss).toBe("https://rp.example.com");
			expect(decoded.value.payload.sub).toBe("https://rp.example.com");
		});

		it("preserves entityId without trailing slash", async () => {
			const { config } = await createLeafConfig({
				entityId: "https://rp.example.com" as EntityId,
			});
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();

			const decoded = decodeEntityStatement(jwt);
			expect(decoded.ok).toBe(true);
			if (!decoded.ok) return;

			expect(decoded.value.payload.iss).toBe("https://rp.example.com");
		});
	});

	describe("getEntityConfiguration", () => {
		it("returns a valid signed JWT", async () => {
			const { config, publicKey } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();

			expect(jwt.split(".")).toHaveLength(3);

			const result = await verifyEntityStatement(jwt, {
				keys: [publicKey],
			});
			expect(result.ok).toBe(true);
		});

		it("has iss === sub === entityId", async () => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();

			const decoded = decodeEntityStatement(jwt);
			expect(decoded.ok).toBe(true);
			if (!decoded.ok) return;

			expect(decoded.value.payload.iss).toBe(LEAF_ID);
			expect(decoded.value.payload.sub).toBe(LEAF_ID);
		});

		it("includes typ: entity-statement+jwt", async () => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();

			const decoded = decodeEntityStatement(jwt);
			expect(decoded.ok).toBe(true);
			if (!decoded.ok) return;

			expect(decoded.value.header.typ).toBe(JwtTyp.EntityStatement);
		});

		it("contains public keys only in jwks (no d field)", async () => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();

			const decoded = decodeEntityStatement(jwt);
			expect(decoded.ok).toBe(true);
			if (!decoded.ok) return;

			const jwks = decoded.value.payload.jwks;
			expect(jwks).toBeDefined();
			if (!jwks) return;
			expect(jwks.keys.length).toBeGreaterThan(0);
			for (const key of jwks.keys) {
				const k = key as Record<string, unknown>;
				expect(k.d).toBeUndefined();
				expect(k.p).toBeUndefined();
				expect(k.q).toBeUndefined();
				expect(k.dp).toBeUndefined();
				expect(k.dq).toBeUndefined();
				expect(k.qi).toBeUndefined();
			}
		});

		it("includes authority_hints", async () => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();

			const decoded = decodeEntityStatement(jwt);
			expect(decoded.ok).toBe(true);
			if (!decoded.ok) return;

			const p = decoded.value.payload as Record<string, unknown>;
			expect(p.authority_hints).toEqual([TA_ID]);
		});

		it("includes metadata", async () => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();

			const decoded = decodeEntityStatement(jwt);
			expect(decoded.ok).toBe(true);
			if (!decoded.ok) return;

			expect(decoded.value.payload.metadata).toEqual(config.metadata);
		});

		it("includes trust_marks when configured", async () => {
			const trustMarks = [{ trust_mark_type: "https://example.com/tm1", trust_mark: "jwt-value" }];
			const { config } = await createLeafConfig({ trustMarks });
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();

			const decoded = decodeEntityStatement(jwt);
			expect(decoded.ok).toBe(true);
			if (!decoded.ok) return;

			const p = decoded.value.payload as Record<string, unknown>;
			expect(p.trust_marks).toEqual(trustMarks);
		});

		it("omits trust_marks when not configured", async () => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();

			const decoded = decodeEntityStatement(jwt);
			expect(decoded.ok).toBe(true);
			if (!decoded.ok) return;

			const p = decoded.value.payload as Record<string, unknown>;
			expect(p.trust_marks).toBeUndefined();
		});

		it("sets exp = iat + ttlSeconds (default 86400)", async () => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();

			const decoded = decodeEntityStatement(jwt);
			expect(decoded.ok).toBe(true);
			if (!decoded.ok) return;

			const { iat, exp } = decoded.value.payload;
			expect(exp - iat).toBe(86400);
		});

		it("respects custom entityConfigurationTtlSeconds", async () => {
			const { config } = await createLeafConfig({
				entityConfigurationTtlSeconds: 3600,
			});
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();

			const decoded = decodeEntityStatement(jwt);
			expect(decoded.ok).toBe(true);
			if (!decoded.ok) return;

			const { iat, exp } = decoded.value.payload;
			expect(exp - iat).toBe(3600);
		});

		it("caches the signed JWT", async () => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const jwt1 = await entity.getEntityConfiguration();
			const jwt2 = await entity.getEntityConfiguration();
			expect(jwt1).toBe(jwt2);
		});

		it("includes all public keys for multi-key config", async () => {
			const { privateKey: key1 } = await generateSigningKey("ES256");
			const { privateKey: key2 } = await generateSigningKey("ES256");
			const { config } = await createLeafConfig({ signingKeys: [key1, key2] });
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();

			const decoded = decodeEntityStatement(jwt);
			expect(decoded.ok).toBe(true);
			if (!decoded.ok) return;

			expect(decoded.value.payload.jwks?.keys).toHaveLength(2);
			// kid header matches first signing key
			expect(decoded.value.header.kid).toBe(key1.kid);
		});

		it("concurrent calls share one signing operation (stampede protection)", async () => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);

			const spy = vi.spyOn(await import("@oidfed/core"), "signEntityStatement");

			// Force expiry so both calls trigger a build
			const [jwt1, jwt2] = await Promise.all([
				entity.getEntityConfiguration(),
				entity.getEntityConfiguration(),
			]);

			expect(jwt1).toBe(jwt2);
			// signEntityStatement should have been called only once (first build)
			// Note: the first getEntityConfiguration call creates the inflight promise;
			// the second one joins it.
			expect(spy).toHaveBeenCalledTimes(1);
			spy.mockRestore();
		});

		it("propagates signEntityStatement rejection", async () => {
			const spy = vi
				.spyOn(await import("@oidfed/core"), "signEntityStatement")
				.mockRejectedValueOnce(new Error("signing failure"));

			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);

			await expect(entity.getEntityConfiguration()).rejects.toThrow("signing failure");
			spy.mockRestore();
		});
	});

	describe("isEntityConfigurationExpired", () => {
		it("returns false for fresh EC", async () => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			await entity.getEntityConfiguration();
			expect(entity.isEntityConfigurationExpired()).toBe(false);
		});

		it("returns true when no EC has been generated", async () => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			expect(entity.isEntityConfigurationExpired()).toBe(true);
		});

		it("returns true at exact expiry boundary (now === exp)", async () => {
			vi.useFakeTimers();
			try {
				const ttl = 3600;
				const { config } = await createLeafConfig({
					entityConfigurationTtlSeconds: ttl,
				});
				const entity = createLeafEntity(config);
				await entity.getEntityConfiguration();

				// Advance time to exactly the expiry point
				vi.advanceTimersByTime(ttl * 1000);
				expect(entity.isEntityConfigurationExpired()).toBe(true);
			} finally {
				vi.useRealTimers();
			}
		});
	});

	describe("cache expiry", () => {
		it("rebuilds EC after TTL expires", async () => {
			vi.useFakeTimers();
			try {
				const ttl = 60;
				const { config } = await createLeafConfig({
					entityConfigurationTtlSeconds: ttl,
				});
				const entity = createLeafEntity(config);
				const jwt1 = await entity.getEntityConfiguration();

				// Advance past TTL
				vi.advanceTimersByTime((ttl + 1) * 1000);
				const jwt2 = await entity.getEntityConfiguration();

				// Should have rebuilt (different iat/exp)
				expect(jwt2).not.toBe(jwt1);
			} finally {
				vi.useRealTimers();
			}
		});
	});

	describe("refreshEntityConfiguration", () => {
		it("produces a new JWT", async () => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const _jwt1 = await entity.getEntityConfiguration();
			const jwt2 = await entity.refreshEntityConfiguration();
			expect(typeof jwt2).toBe("string");
			expect(jwt2.split(".")).toHaveLength(3);
		});

		it("replaces the cached EC", async () => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			await entity.getEntityConfiguration();
			const refreshed = await entity.refreshEntityConfiguration();
			const cached = await entity.getEntityConfiguration();
			expect(cached).toBe(refreshed);
		});
	});

	describe("handler", () => {
		it("responds 200 with entity-statement+jwt on /.well-known/openid-federation", async () => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const handler = entity.handler();
			const request = new Request("https://rp.example.com/.well-known/openid-federation");
			const response = await handler(request);
			expect(response.status).toBe(200);
			expect(response.headers.get("content-type")).toBe("application/entity-statement+jwt");
			const body = await response.text();
			expect(body.split(".")).toHaveLength(3);
		});
	});
});
