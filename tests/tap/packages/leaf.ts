import type QUnit from "qunit";
import type { FederationMetadata } from "../../../packages/core/src/index.js";
import {
	decodeEntityStatement,
	type EntityId,
	entityId,
	generateSigningKey,
	type JWK,
	JwtTyp,
	MediaType,
	signEntityStatement,
	verifyEntityStatement,
	WELL_KNOWN_OPENID_FEDERATION,
} from "../../../packages/core/src/index.js";
import { discoverEntity } from "../../../packages/leaf/src/discovery.js";
import {
	createLeafEntity,
	type LeafConfig,
} from "../../../packages/leaf/src/entity-configuration.js";
import { createLeafHandler } from "../../../packages/leaf/src/handler.js";
import {
	createMockFederation,
	createMockTrustAnchors,
	LEAF_ID,
	OP_ID,
	TA_ID,
} from "../fixtures/index.js";

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

async function createLeafConfig(
	overrides?: Partial<LeafConfig>,
): Promise<{ config: LeafConfig; signingKey: JWK; publicKey: JWK }> {
	const { privateKey, publicKey } = await generateSigningKey("ES256");
	const config: LeafConfig = {
		entityId: LEAF_ID,
		signingKeys: [privateKey],
		authorityHints: [TA_ID],
		metadata: {
			openid_relying_party: {
				redirect_uris: ["https://rp.example.com/callback"],
				response_types: ["code"],
				client_registration_types: ["automatic"],
			},
		} as FederationMetadata,
		...overrides,
	};
	return { config, signingKey: privateKey, publicKey };
}

// Tiny mock function — replaces vi.fn()
function mockFn<A extends unknown[]>() {
	const calls: A[] = [];
	const fn = (...args: A): void => {
		calls.push(args);
	};
	fn.calls = calls;
	fn.callCount = () => calls.length;
	fn.lastCall = () => calls[calls.length - 1] as A;
	return fn;
}

// ---------------------------------------------------------------------------

export default (QUnit: QUnit) => {
	const { module, test } = QUnit;

	// -------------------------------------------------------------------------
	// discovery
	// -------------------------------------------------------------------------
	module("leaf / discoverEntity", () => {
		test("returns correct entityId from valid discovery", async (t) => {
			const fed = await createMockFederation();
			const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);
			t.equal(result.entityId, OP_ID);
		});

		test("returns resolvedMetadata from valid discovery", async (t) => {
			const fed = await createMockFederation();
			const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);
			t.ok(result.resolvedMetadata, "resolvedMetadata defined");
			t.ok(result.resolvedMetadata.openid_provider, "openid_provider defined");
		});

		test("returns trustChain from valid discovery", async (t) => {
			const fed = await createMockFederation();
			const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);
			t.ok(result.trustChain, "trustChain defined");
			t.equal(result.trustChain.entityId, OP_ID);
			t.equal(result.trustChain.trustAnchorId, TA_ID);
			t.ok(result.trustChain.statements.length >= 2, "at least 2 statements");
		});

		test("returns empty trustMarks array when none present", async (t) => {
			const fed = await createMockFederation();
			const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);
			t.deepEqual(result.trustMarks, []);
		});

		test("throws when no trust chain can be resolved", async (t) => {
			const fed = await createMockFederation();
			const unknownEntity = entityId("https://unknown.example.com");
			try {
				await discoverEntity(unknownEntity, fed.trustAnchors, fed.options);
				t.ok(false, "should have thrown");
			} catch (e) {
				t.ok((e as Error).message.includes("No trust chains resolved"), (e as Error).message);
			}
		});

		test("error message includes chain resolution details when no chains resolve", async (t) => {
			const fed = await createMockFederation();
			const unknownEntity = entityId("https://unknown.example.com");
			try {
				await discoverEntity(unknownEntity, fed.trustAnchors, fed.options);
				t.ok(false, "should have thrown");
			} catch (e) {
				t.ok(
					/No trust chains resolved for entity/.test((e as Error).message),
					(e as Error).message,
				);
			}
		});

		test("throws with validation details when all chains fail validation", async (t) => {
			const fed = await createMockFederation();
			const wrongTrustAnchors = createMockTrustAnchors(TA_ID, fed.opPublicKey);
			try {
				await discoverEntity(OP_ID, wrongTrustAnchors, fed.options);
				t.ok(false, "should have thrown");
			} catch (e) {
				t.ok(/No valid trust chains for entity:/.test((e as Error).message), (e as Error).message);
			}
		});

		test("discovers leaf entity through federation", async (t) => {
			const fed = await createMockFederation();
			const result = await discoverEntity(LEAF_ID, fed.trustAnchors, fed.options);
			t.equal(result.entityId, LEAF_ID);
			t.equal(result.trustChain.trustAnchorId, TA_ID);
		});

		test("selects shortest chain when multiple valid chains exist", async (t) => {
			const fed = await createMockFederation();
			const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);
			t.ok(result.trustChain.statements.length >= 2, "at least 2 statements");
		});
	});

	// -------------------------------------------------------------------------
	// entity-configuration — validation
	// -------------------------------------------------------------------------
	module("leaf / createLeafEntity / validation", () => {
		test("rejects empty metadata — requires at least one Entity Type", async (t) => {
			const { config } = await createLeafConfig({ metadata: {} as never });
			t.throws(() => createLeafEntity(config), /metadata MUST contain at least one Entity Type/);
		});

		test("throws on empty authorityHints", async (t) => {
			const { config } = await createLeafConfig({ authorityHints: [] });
			t.throws(() => createLeafEntity(config), /authorityHints/);
		});

		test("rejects non-HTTPS authorityHint — requires valid Entity Identifiers", async (t) => {
			const { config } = await createLeafConfig({
				authorityHints: ["http://ta.example.com" as EntityId],
			});
			t.throws(() => createLeafEntity(config), /authorityHint/);
		});

		test("throws on empty signingKeys", async (t) => {
			const { config } = await createLeafConfig({ signingKeys: [] });
			t.throws(() => createLeafEntity(config), /signingKeys/);
		});

		test("throws on signing key without kid", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const keyWithoutKid = { ...privateKey } as Record<string, unknown>;
			delete keyWithoutKid.kid;
			const { config } = await createLeafConfig({
				signingKeys: [keyWithoutKid as unknown as JWK],
			});
			t.throws(() => createLeafEntity(config), /kid/);
		});

		test("throws when metadata includes federation_fetch_endpoint", async (t) => {
			const { config } = await createLeafConfig({
				metadata: {
					openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
					federation_entity: { federation_fetch_endpoint: "https://rp.example.com/fetch" },
				} as never,
			});
			t.throws(
				() => createLeafEntity(config),
				/Leaf entities MUST NOT publish federation_fetch_endpoint/,
			);
		});

		test("throws when metadata includes federation_list_endpoint", async (t) => {
			const { config } = await createLeafConfig({
				metadata: {
					openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
					federation_entity: { federation_list_endpoint: "https://rp.example.com/list" },
				} as never,
			});
			t.throws(
				() => createLeafEntity(config),
				/Leaf entities MUST NOT publish federation_list_endpoint/,
			);
		});

		test("throws on duplicate kid values", async (t) => {
			const { privateKey: key1 } = await generateSigningKey("ES256");
			const { privateKey: key2 } = await generateSigningKey("ES256");
			const key2WithSameKid = { ...key2, kid: key1.kid } as unknown as JWK;
			const { config } = await createLeafConfig({ signingKeys: [key1, key2WithSameKid] });
			t.throws(() => createLeafEntity(config), /Duplicate kid/);
		});

		test("rejects symmetric key (kty 'oct') — requires asymmetric keys", async (t) => {
			const { config } = await createLeafConfig({
				signingKeys: [{ kty: "oct", kid: "sym-1", k: "c2VjcmV0" } as unknown as JWK],
			});
			t.throws(() => createLeafEntity(config), /Symmetric keys/);
		});

		test("rejects non-HTTPS entityId — requires https scheme", async (t) => {
			const { config } = await createLeafConfig({
				entityId: "http://rp.example.com" as EntityId,
			});
			t.throws(() => createLeafEntity(config), /HTTPS URL/);
		});

		test("rejects entityId with query parameter", async (t) => {
			const { config } = await createLeafConfig({
				entityId: "https://rp.example.com?foo=bar" as EntityId,
			});
			t.throws(() => createLeafEntity(config), /HTTPS URL/);
		});

		test("rejects entityId with fragment", async (t) => {
			const { config } = await createLeafConfig({
				entityId: "https://rp.example.com#frag" as EntityId,
			});
			t.throws(() => createLeafEntity(config), /HTTPS URL/);
		});

		test("rejects empty entityId", async (t) => {
			const { config } = await createLeafConfig({ entityId: "" as EntityId });
			t.throws(() => createLeafEntity(config));
		});

		test("rejects ttlSeconds of 0", async (t) => {
			const { config } = await createLeafConfig({ entityConfigurationTtlSeconds: 0 });
			t.throws(() => createLeafEntity(config), /entityConfigurationTtlSeconds must be positive/);
		});

		test("rejects negative ttlSeconds", async (t) => {
			const { config } = await createLeafConfig({ entityConfigurationTtlSeconds: -1 });
			t.throws(() => createLeafEntity(config), /entityConfigurationTtlSeconds must be positive/);
		});
	});

	// -------------------------------------------------------------------------
	// entity-configuration — entity ID normalization
	// -------------------------------------------------------------------------
	module("leaf / createLeafEntity / entity ID normalization", () => {
		test("normalizes trailing slash in iss/sub", async (t) => {
			const { config } = await createLeafConfig({
				entityId: "https://rp.example.com/" as EntityId,
			});
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.iss, "https://rp.example.com");
			t.equal(decoded.value.payload.sub, "https://rp.example.com");
		});

		test("preserves entityId without trailing slash", async (t) => {
			const { config } = await createLeafConfig({
				entityId: "https://rp.example.com" as EntityId,
			});
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.iss, "https://rp.example.com");
		});
	});

	// -------------------------------------------------------------------------
	// entity-configuration — getEntityConfiguration
	// -------------------------------------------------------------------------
	module("leaf / createLeafEntity / getEntityConfiguration", () => {
		test("returns a valid signed JWT", async (t) => {
			const { config, publicKey } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();
			t.equal(jwt.split(".").length, 3);
			const result = await verifyEntityStatement(jwt, { keys: [publicKey] });
			t.true(result.ok);
		});

		test("has iss === sub === entityId", async (t) => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.iss, LEAF_ID);
			t.equal(decoded.value.payload.sub, LEAF_ID);
		});

		test("includes typ: entity-statement+jwt", async (t) => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.header.typ, JwtTyp.EntityStatement);
		});

		test("contains public keys only in jwks (no d field)", async (t) => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const jwks = decoded.value.payload.jwks;
			t.ok(jwks, "jwks present");
			if (!jwks) return;
			t.ok(jwks.keys.length > 0, "has keys");
			for (const key of jwks.keys) {
				const k = key as Record<string, unknown>;
				t.equal(k.d, undefined, "no d");
				t.equal(k.p, undefined, "no p");
				t.equal(k.q, undefined, "no q");
				t.equal(k.dp, undefined, "no dp");
				t.equal(k.dq, undefined, "no dq");
				t.equal(k.qi, undefined, "no qi");
			}
		});

		test("includes authority_hints", async (t) => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.deepEqual(p.authority_hints, [TA_ID]);
		});

		test("includes metadata", async (t) => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.deepEqual(
				decoded.value.payload.metadata,
				config.metadata as Record<string, Record<string, unknown>>,
			);
		});

		test("includes trust_marks when configured", async (t) => {
			const trustMarks = [{ trust_mark_type: "https://example.com/tm1", trust_mark: "jwt-value" }];
			const { config } = await createLeafConfig({ trustMarks });
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.deepEqual(p.trust_marks, trustMarks);
		});

		test("omits trust_marks when not configured", async (t) => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.equal(p.trust_marks, undefined);
		});

		test("sets exp = iat + ttlSeconds (default 86400)", async (t) => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const { iat, exp } = decoded.value.payload;
			t.equal(exp - iat, 86400);
		});

		test("respects custom entityConfigurationTtlSeconds", async (t) => {
			const { config } = await createLeafConfig({ entityConfigurationTtlSeconds: 3600 });
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const { iat, exp } = decoded.value.payload;
			t.equal(exp - iat, 3600);
		});

		test("caches the signed JWT", async (t) => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const jwt1 = await entity.getEntityConfiguration();
			const jwt2 = await entity.getEntityConfiguration();
			t.equal(jwt1, jwt2);
		});

		test("includes all public keys for multi-key config", async (t) => {
			const { privateKey: key1 } = await generateSigningKey("ES256");
			const { privateKey: key2 } = await generateSigningKey("ES256");
			const { config } = await createLeafConfig({ signingKeys: [key1, key2] });
			const entity = createLeafEntity(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.jwks?.keys.length, 2);
			t.equal(decoded.value.header.kid, key1.kid);
		});

		test("concurrent calls share one signing operation (stampede protection)", async (t) => {
			let signCalls = 0;
			const countingSigner: typeof signEntityStatement = (payload, key, opts) => {
				signCalls++;
				return signEntityStatement(payload, key, opts);
			};
			const { config } = await createLeafConfig({ _signFn: countingSigner });
			const entity = createLeafEntity(config);
			const [jwt1, jwt2] = await Promise.all([
				entity.getEntityConfiguration(),
				entity.getEntityConfiguration(),
			]);
			t.equal(jwt1, jwt2);
			t.equal(signCalls, 1);
		});

		test("propagates signEntityStatement rejection", async (t) => {
			const failingSigner = () => Promise.reject(new Error("signing failure"));
			const { config } = await createLeafConfig({
				_signFn: failingSigner as unknown as typeof signEntityStatement,
			});
			const entity = createLeafEntity(config);
			try {
				await entity.getEntityConfiguration();
				t.ok(false, "should have thrown");
			} catch (e) {
				t.ok((e as Error).message.includes("signing failure"), (e as Error).message);
			}
		});
	});

	// -------------------------------------------------------------------------
	// entity-configuration — isEntityConfigurationExpired
	// -------------------------------------------------------------------------
	module("leaf / createLeafEntity / isEntityConfigurationExpired", () => {
		test("returns false for fresh EC", async (t) => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			await entity.getEntityConfiguration();
			t.false(entity.isEntityConfigurationExpired());
		});

		test("returns true when no EC has been generated", async (t) => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			t.true(entity.isEntityConfigurationExpired());
		});

		test("returns true at exact expiry boundary (now === exp)", async (t) => {
			const ttl = 3600;
			let nowMs = Date.now();
			const clock = { now: () => Math.floor(nowMs / 1000) };
			const { config } = await createLeafConfig({ entityConfigurationTtlSeconds: ttl, clock });
			const entity = createLeafEntity(config);
			await entity.getEntityConfiguration();
			nowMs += ttl * 1000;
			t.true(entity.isEntityConfigurationExpired());
		});
	});

	// -------------------------------------------------------------------------
	// entity-configuration — cache expiry
	// -------------------------------------------------------------------------
	module("leaf / createLeafEntity / cache expiry", () => {
		test("rebuilds EC after TTL expires", async (t) => {
			const ttl = 60;
			let nowMs = Date.now();
			const clock = { now: () => Math.floor(nowMs / 1000) };
			const { config } = await createLeafConfig({ entityConfigurationTtlSeconds: ttl, clock });
			const entity = createLeafEntity(config);
			const jwt1 = await entity.getEntityConfiguration();
			nowMs += (ttl + 1) * 1000;
			const jwt2 = await entity.getEntityConfiguration();
			t.notEqual(jwt1, jwt2, "rebuilt after TTL");
		});
	});

	// -------------------------------------------------------------------------
	// entity-configuration — refreshEntityConfiguration
	// -------------------------------------------------------------------------
	module("leaf / createLeafEntity / refreshEntityConfiguration", () => {
		test("produces a new JWT", async (t) => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			await entity.getEntityConfiguration();
			const jwt2 = await entity.refreshEntityConfiguration();
			t.equal(typeof jwt2, "string");
			t.equal(jwt2.split(".").length, 3);
		});

		test("replaces the cached EC", async (t) => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			await entity.getEntityConfiguration();
			const refreshed = await entity.refreshEntityConfiguration();
			const cached = await entity.getEntityConfiguration();
			t.equal(cached, refreshed);
		});
	});

	// -------------------------------------------------------------------------
	// entity-configuration — handler (inline)
	// -------------------------------------------------------------------------
	module("leaf / createLeafEntity / handler", () => {
		test("responds 200 with entity-statement+jwt on /.well-known/openid-federation", async (t) => {
			const { config } = await createLeafConfig();
			const entity = createLeafEntity(config);
			const handler = entity.handler();
			const request = new Request("https://rp.example.com/.well-known/openid-federation");
			const response = await handler(request);
			t.equal(response.status, 200);
			t.equal(response.headers.get("content-type"), "application/entity-statement+jwt");
			const body = await response.text();
			t.equal(body.split(".").length, 3);
		});
	});

	// -------------------------------------------------------------------------
	// handler
	// -------------------------------------------------------------------------
	module("leaf / createLeafHandler", () => {
		async function createHandler() {
			const { config } = await createLeafConfig();
			const e = createLeafEntity(config);
			return { handler: createLeafHandler(e), entity: e };
		}

		test("returns 200 with correct Content-Type for well-known path", async (t) => {
			const { handler } = await createHandler();
			const response = await handler(new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`));
			t.equal(response.status, 200);
			t.equal(response.headers.get("Content-Type"), MediaType.EntityStatement);
		});

		test("response body is valid JWT", async (t) => {
			const { handler } = await createHandler();
			const response = await handler(new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`));
			const body = await response.text();
			t.equal(body.split(".").length, 3);
		});

		test("returns 405 for POST to well-known path", async (t) => {
			const { handler } = await createHandler();
			const response = await handler(
				new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`, { method: "POST" }),
			);
			t.equal(response.status, 405);
			t.equal(response.headers.get("Allow"), "GET");
		});

		test("returns 404 for unknown paths", async (t) => {
			const { handler } = await createHandler();
			const response = await handler(new Request(`${LEAF_ID}/unknown-path`));
			t.equal(response.status, 404);
		});

		test("includes security headers on 200 response", async (t) => {
			const { handler } = await createHandler();
			const response = await handler(new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`));
			t.equal(response.headers.get("Cache-Control"), "no-store");
			t.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
			t.ok(response.headers.get("Strict-Transport-Security")?.includes("max-age="));
		});

		test("includes security headers on 404 response", async (t) => {
			const { handler } = await createHandler();
			const response = await handler(new Request(`${LEAF_ID}/unknown`));
			t.equal(response.headers.get("Cache-Control"), "no-store");
			t.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
		});

		test("includes security headers on 405 response", async (t) => {
			const { handler } = await createHandler();
			const response = await handler(
				new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`, { method: "DELETE" }),
			);
			t.equal(response.headers.get("Cache-Control"), "no-store");
			t.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
		});

		test("returns 500 when getEntityConfiguration throws", async (t) => {
			const faultyEntity = {
				getEntityConfiguration: () => {
					throw new Error("signing failure");
				},
			} as unknown as import("../../../packages/leaf/src/entity-configuration.js").LeafEntity;
			const handler = createLeafHandler(faultyEntity);
			const response = await handler(new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`));
			t.equal(response.status, 500);
			const body = (await response.json()) as Record<string, unknown>;
			t.equal(body.error, "server_error");
			t.equal(response.headers.get("Cache-Control"), "no-store");
		});

		test("500 body does NOT contain internal error message (no info leak)", async (t) => {
			const secretMessage = "database password is hunter2";
			const faultyEntity = {
				getEntityConfiguration: () => {
					throw new Error(secretMessage);
				},
			} as unknown as import("../../../packages/leaf/src/entity-configuration.js").LeafEntity;
			const handler = createLeafHandler(faultyEntity);
			const response = await handler(new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`));
			const text = await response.text();
			t.notOk(text.includes(secretMessage), "secret not in response");
		});

		test("logger error() is called with original error on 500", async (t) => {
			const originalError = new Error("signing failure");
			const faultyEntity = {
				getEntityConfiguration: () => {
					throw originalError;
				},
			} as unknown as import("../../../packages/leaf/src/entity-configuration.js").LeafEntity;
			const errorFn = mockFn<[string, Record<string, unknown>]>();
			const logger = {
				debug: mockFn(),
				info: mockFn(),
				warn: mockFn(),
				error: errorFn,
			};
			const handler = createLeafHandler(faultyEntity, { logger });
			await handler(new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`));
			t.equal(errorFn.callCount(), 1);
			const [msg, ctx] = errorFn.lastCall();
			t.equal(msg, "Failed to serve entity configuration");
			t.equal((ctx as Record<string, unknown>).error, originalError);
		});

		test("404 response has error and error_description fields", async (t) => {
			const { handler } = await createHandler();
			const response = await handler(new Request(`${LEAF_ID}/unknown`));
			const body = (await response.json()) as Record<string, unknown>;
			t.equal(body.error, "not_found");
			t.equal(body.error_description, "Unknown endpoint");
		});

		test("405 response has error field", async (t) => {
			const { handler } = await createHandler();
			const response = await handler(
				new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`, { method: "POST" }),
			);
			const body = (await response.json()) as Record<string, unknown>;
			t.equal(body.error, "method_not_allowed");
		});

		test("500 response has error and error_description fields", async (t) => {
			const faultyEntity = {
				getEntityConfiguration: () => {
					throw new Error("fail");
				},
			} as unknown as import("../../../packages/leaf/src/entity-configuration.js").LeafEntity;
			const handler = createLeafHandler(faultyEntity);
			const response = await handler(new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`));
			const body = (await response.json()) as Record<string, unknown>;
			t.equal(body.error, "server_error");
			t.equal(body.error_description, "An internal error occurred");
		});
	});

	// -------------------------------------------------------------------------
	// integration
	// -------------------------------------------------------------------------
	module("leaf / integration", () => {
		test("end-to-end: EC generation + handler serving", async (t) => {
			const fed = await createMockFederation();
			const config: LeafConfig = {
				entityId: LEAF_ID,
				signingKeys: [fed.leafSigningKey],
				authorityHints: [TA_ID],
				metadata: {
					openid_relying_party: {
						redirect_uris: ["https://rp.example.com/callback"],
						response_types: ["code"],
						client_registration_types: ["automatic"],
					},
				},
			};
			const entity = createLeafEntity(config);
			const handler = entity.handler();
			const response = await handler(new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`));
			t.equal(response.status, 200);
			t.equal(response.headers.get("Content-Type"), MediaType.EntityStatement);
			const jwt = await response.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.iss, LEAF_ID);
			t.equal(decoded.value.payload.sub, LEAF_ID);
			const p = decoded.value.payload as Record<string, unknown>;
			t.deepEqual(p.authority_hints, [TA_ID]);
		});

		test("end-to-end: discover OP through mock federation", async (t) => {
			const fed = await createMockFederation();
			const config: LeafConfig = {
				entityId: LEAF_ID,
				signingKeys: [fed.leafSigningKey],
				authorityHints: [TA_ID],
				metadata: {
					openid_relying_party: {
						redirect_uris: ["https://rp.example.com/callback"],
						response_types: ["code"],
					},
				},
			};
			createLeafEntity(config);
			const discovery = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);
			t.equal(discovery.entityId, OP_ID);
			t.ok(discovery.resolvedMetadata.openid_provider, "openid_provider present");
			t.equal(discovery.trustChain.trustAnchorId, TA_ID);
		});

		test("EC caching and refresh cycle", async (t) => {
			const fed = await createMockFederation();
			const config: LeafConfig = {
				entityId: LEAF_ID,
				signingKeys: [fed.leafSigningKey],
				authorityHints: [TA_ID],
				metadata: {
					openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
				},
			};
			const entity = createLeafEntity(config);
			t.true(entity.isEntityConfigurationExpired());
			const ec1 = await entity.getEntityConfiguration();
			t.false(entity.isEntityConfigurationExpired());
			const ec2 = await entity.getEntityConfiguration();
			t.equal(ec1, ec2);
			const ec3 = await entity.refreshEntityConfiguration();
			t.equal(typeof ec3, "string");
			const ec4 = await entity.getEntityConfiguration();
			t.equal(ec4, ec3);
		});
	});
};
