import type QUnit from "qunit";
import {
	decodeEntityStatement,
	discoverEntity,
	type EntityId,
	type EntityStatementMetadata,
	entityId,
	generateSigningKey,
	isErr,
	isOk,
	type JWK,
	JwkSigner,
	JwtTyp,
	MediaType,
	MemoryFederationKeyProvider,
	stripPrivateFields,
	verifyEntityStatement,
	WELL_KNOWN_OPENID_FEDERATION,
} from "../../../packages/core/src/index.js";
import * as LeafPublic from "../../../packages/leaf/src/index.js";
import { Leaf, type LeafConfig } from "../../../packages/leaf/src/index.js";
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

function federationKey(signingKey: JWK) {
	return { signer: new JwkSigner(signingKey), publicJwk: stripPrivateFields(signingKey) };
}

async function createLeafConfig(
	overrides?: Partial<LeafConfig>,
): Promise<{ config: LeafConfig; signingKey: JWK; publicKey: JWK }> {
	const { privateKey, publicKey } = await generateSigningKey("ES256");
	const signingKey = { ...privateKey, kid: privateKey.kid ?? "leaf-key-1" };
	const config: LeafConfig = {
		entityId: LEAF_ID,
		keyProvider: new MemoryFederationKeyProvider(federationKey(signingKey)),
		authorityHints: [TA_ID],
		metadata: {
			openid_relying_party: {
				redirect_uris: ["https://rp.example.com/callback"],
				response_types: ["code"],
				client_registration_types: ["automatic"],
			},
		} satisfies EntityStatementMetadata,
		...overrides,
	};
	return { config, signingKey, publicKey };
}

// Minimal call recorder used in place of vi.fn().
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

	module("leaf / public root exports", () => {
		test("exports only the leaf class as a runtime entrypoint", (t) => {
			t.equal(LeafPublic.Leaf, Leaf);
			t.equal(typeof LeafPublic.Leaf.discoverEntity, "function");
			t.false("discoverEntity" in LeafPublic);
			t.false("federationKey" in LeafPublic);
		});
	});

	// -------------------------------------------------------------------------
	// discovery
	// -------------------------------------------------------------------------
	module("leaf / discoverEntity", () => {
		test("returns correct entityId from valid discovery", async (t) => {
			const fed = await createMockFederation();
			const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);
			t.true(isOk(result));
			if (isOk(result)) {
				t.equal(result.value.entityId, OP_ID);
			}
		});

		test("returns resolvedMetadata from valid discovery", async (t) => {
			const fed = await createMockFederation();
			const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);
			t.true(isOk(result));
			if (isOk(result)) {
				t.ok(result.value.resolvedMetadata, "resolvedMetadata defined");
				t.ok(result.value.resolvedMetadata.openid_provider, "openid_provider defined");
			}
		});

		test("returns trustChain from valid discovery", async (t) => {
			const fed = await createMockFederation();
			const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);
			t.true(isOk(result));
			if (isOk(result)) {
				t.ok(result.value.trustChain, "trustChain defined");
				t.equal(result.value.trustChain.entityId, OP_ID);
				t.equal(result.value.trustChain.trustAnchorId, TA_ID);
				t.ok(result.value.trustChain.statements.length >= 2, "at least 2 statements");
			}
		});

		test("returns empty trustMarks array when none present", async (t) => {
			const fed = await createMockFederation();
			const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);
			t.true(isOk(result));
			if (isOk(result)) {
				t.deepEqual(result.value.trustMarks, []);
			}
		});

		test("fails when no trust chain can be resolved", async (t) => {
			const fed = await createMockFederation();
			const unknownEntity = entityId("https://unknown.example.com");
			const result = await discoverEntity(unknownEntity, fed.trustAnchors, fed.options);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(
					result.error.description.includes("No trust chains resolved"),
					result.error.description,
				);
			}
		});

		test("error message includes chain resolution details when no chains resolve", async (t) => {
			const fed = await createMockFederation();
			const unknownEntity = entityId("https://unknown.example.com");
			const result = await discoverEntity(unknownEntity, fed.trustAnchors, fed.options);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(
					/No trust chains resolved for entity/.test(result.error.description),
					result.error.description,
				);
			}
		});

		test("fails with validation details when all chains fail validation", async (t) => {
			const fed = await createMockFederation();
			const wrongTrustAnchors = createMockTrustAnchors(TA_ID, fed.opPublicKey);
			const result = await discoverEntity(OP_ID, wrongTrustAnchors, fed.options);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(
					/No valid trust chains for entity:/.test(result.error.description),
					result.error.description,
				);
			}
		});

		test("discovers leaf entity through federation", async (t) => {
			const fed = await createMockFederation();
			const result = await discoverEntity(LEAF_ID, fed.trustAnchors, fed.options);
			t.true(isOk(result));
			if (isOk(result)) {
				t.equal(result.value.entityId, LEAF_ID);
				t.equal(result.value.trustChain.trustAnchorId, TA_ID);
			}
		});

		test("selects shortest chain when multiple valid chains exist", async (t) => {
			const fed = await createMockFederation();
			const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);
			t.true(isOk(result));
			if (isOk(result)) {
				t.ok(result.value.trustChain.statements.length >= 2, "at least 2 statements");
			}
		});
	});

	// -------------------------------------------------------------------------
	// Leaf — validation
	// -------------------------------------------------------------------------
	module("leaf / Leaf / validation", () => {
		test("rejects empty metadata — requires at least one Entity Type", async (t) => {
			const { config } = await createLeafConfig({ metadata: {} as never });
			t.throws(() => new Leaf(config), /metadata MUST contain at least one Entity Type/);
		});

		test("throws on empty authorityHints", async (t) => {
			const { config } = await createLeafConfig({
				authorityHints: [] as unknown as [EntityId, ...EntityId[]],
			});
			t.throws(() => new Leaf(config), /authorityHints/);
		});

		test("rejects non-HTTPS authorityHint — requires valid Entity Identifiers", async (t) => {
			const { config } = await createLeafConfig({
				authorityHints: ["http://ta.example.com" as EntityId],
			});
			t.throws(() => new Leaf(config), /authorityHint/);
		});

		test("throws on empty trustAnchorHints", async (t) => {
			const { config } = await createLeafConfig({
				trustAnchorHints: [],
			});
			t.throws(() => new Leaf(config), /trustAnchorHints/);
		});

		test("rejects non-HTTPS trustAnchorHint — requires valid Entity Identifiers", async (t) => {
			const { config } = await createLeafConfig({
				trustAnchorHints: ["http://ta.example.com" as EntityId],
			});
			t.throws(() => new Leaf(config), /trustAnchorHint/);
		});

		test("throws when keyProvider is missing", async (t) => {
			const { config } = await createLeafConfig({ keyProvider: undefined });
			t.throws(() => new Leaf(config), /keyProvider/);
		});

		test("throws on signer key without kid", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const keyWithoutKid = { ...privateKey } as Record<string, unknown>;
			delete keyWithoutKid.kid;
			t.throws(() => new JwkSigner(keyWithoutKid as unknown as JWK), /kid/);
		});

		test("throws when metadata includes federation_fetch_endpoint", async (t) => {
			const { config } = await createLeafConfig({
				metadata: {
					openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
					federation_entity: { federation_fetch_endpoint: "https://rp.example.com/fetch" },
				} as never,
			});
			t.throws(() => new Leaf(config), /Leaf entities MUST NOT publish federation_fetch_endpoint/);
		});

		test("throws when metadata includes federation_list_endpoint", async (t) => {
			const { config } = await createLeafConfig({
				metadata: {
					openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
					federation_entity: { federation_list_endpoint: "https://rp.example.com/list" },
				} as never,
			});
			t.throws(() => new Leaf(config), /Leaf entities MUST NOT publish federation_list_endpoint/);
		});

		test("throws on duplicate kid values", async (t) => {
			const { privateKey: key1 } = await generateSigningKey("ES256");
			const { privateKey: key2 } = await generateSigningKey("ES256");
			const key2WithSameKid = { ...key2, kid: key1.kid } as unknown as JWK;
			t.throws(
				() =>
					new MemoryFederationKeyProvider([federationKey(key1), federationKey(key2WithSameKid)]),
				/Duplicate|already exists/,
			);
		});

		test("rejects symmetric key (kty 'oct') — requires asymmetric keys", async (t) => {
			t.throws(
				() => new JwkSigner({ kty: "oct", kid: "sym-1", k: "c2VjcmV0" } as unknown as JWK),
				/Symmetric keys/,
			);
		});

		test("rejects private material in the published federation JWK", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			t.throws(
				() =>
					new MemoryFederationKeyProvider({
						signer: new JwkSigner(privateKey),
						publicJwk: privateKey,
					}),
				/public JWK/,
			);
		});

		test("rejects a federation public JWK whose kid differs from the signer", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			t.throws(
				() =>
					new MemoryFederationKeyProvider({
						signer: new JwkSigner(privateKey),
						publicJwk: { ...stripPrivateFields(privateKey), kid: "different-key" },
					}),
				/kid MUST match/,
			);
		});

		test("rejects non-HTTPS entityId — requires https scheme", async (t) => {
			const { config } = await createLeafConfig({
				entityId: "http://rp.example.com" as EntityId,
			});
			t.throws(() => new Leaf(config), /HTTPS URL/);
		});

		test("rejects entityId with query parameter", async (t) => {
			const { config } = await createLeafConfig({
				entityId: "https://rp.example.com?foo=bar" as EntityId,
			});
			t.throws(() => new Leaf(config), /HTTPS URL/);
		});

		test("rejects entityId with fragment", async (t) => {
			const { config } = await createLeafConfig({
				entityId: "https://rp.example.com#frag" as EntityId,
			});
			t.throws(() => new Leaf(config), /HTTPS URL/);
		});

		test("rejects empty entityId", async (t) => {
			const { config } = await createLeafConfig({ entityId: "" as EntityId });
			t.throws(() => new Leaf(config));
		});

		test("rejects ttlSeconds of 0", async (t) => {
			const { config } = await createLeafConfig({ entityConfigurationTtlSeconds: 0 });
			t.throws(() => new Leaf(config), /entityConfigurationTtlSeconds must be positive/);
		});

		test("rejects negative ttlSeconds", async (t) => {
			const { config } = await createLeafConfig({ entityConfigurationTtlSeconds: -1 });
			t.throws(() => new Leaf(config), /entityConfigurationTtlSeconds must be positive/);
		});
	});

	// -------------------------------------------------------------------------
	// Leaf — entity ID normalization
	// -------------------------------------------------------------------------
	module("leaf / Leaf / entity ID normalization", () => {
		test("normalizes trailing slash in iss/sub", async (t) => {
			const { config } = await createLeafConfig({
				entityId: "https://rp.example.com/" as EntityId,
			});
			const entity = new Leaf(config);
			t.equal(entity.entityId, "https://rp.example.com");
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
			const entity = new Leaf(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.iss, "https://rp.example.com");
		});
	});

	// -------------------------------------------------------------------------
	// Leaf — getEntityConfiguration
	// -------------------------------------------------------------------------
	module("leaf / Leaf / getEntityConfiguration", () => {
		test("returns a valid signed JWT", async (t) => {
			const { config, publicKey } = await createLeafConfig();
			const entity = new Leaf(config);
			const jwt = await entity.getEntityConfiguration();
			t.equal(jwt.split(".").length, 3);
			const result = await verifyEntityStatement(jwt, { keys: [publicKey] });
			t.true(result.ok);
		});

		test("has iss === sub === entityId", async (t) => {
			const { config } = await createLeafConfig();
			const entity = new Leaf(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.iss, LEAF_ID);
			t.equal(decoded.value.payload.sub, LEAF_ID);
		});

		test("includes typ: entity-statement+jwt", async (t) => {
			const { config } = await createLeafConfig();
			const entity = new Leaf(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.header.typ, JwtTyp.EntityStatement);
		});

		test("contains public keys only in jwks (no d field)", async (t) => {
			const { config } = await createLeafConfig();
			const entity = new Leaf(config);
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
			const entity = new Leaf(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.deepEqual(p.authority_hints, [TA_ID]);
		});

		test("includes trust_anchor_hints when configured", async (t) => {
			const trustAnchorHint = entityId("https://preferred-ta.example.com");
			const { config } = await createLeafConfig({ trustAnchorHints: [trustAnchorHint] });
			const entity = new Leaf(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.deepEqual(p.trust_anchor_hints, [trustAnchorHint]);
		});

		test("includes metadata", async (t) => {
			const { config } = await createLeafConfig();
			const entity = new Leaf(config);
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
			const entity = new Leaf(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.deepEqual(p.trust_marks, trustMarks);
		});

		test("omits trust_marks when not configured", async (t) => {
			const { config } = await createLeafConfig();
			const entity = new Leaf(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.equal(p.trust_marks, undefined);
		});

		test("sets exp = iat + ttlSeconds (default 86400)", async (t) => {
			const { config } = await createLeafConfig();
			const entity = new Leaf(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const { iat, exp } = decoded.value.payload;
			t.equal(exp - iat, 86400);
		});

		test("respects custom entityConfigurationTtlSeconds", async (t) => {
			const { config } = await createLeafConfig({ entityConfigurationTtlSeconds: 3600 });
			const entity = new Leaf(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const { iat, exp } = decoded.value.payload;
			t.equal(exp - iat, 3600);
		});

		test("caches the signed JWT", async (t) => {
			const { config } = await createLeafConfig();
			const entity = new Leaf(config);
			const jwt1 = await entity.getEntityConfiguration();
			const jwt2 = await entity.getEntityConfiguration();
			t.equal(jwt1, jwt2);
		});

		test("includes all public keys for multi-key config", async (t) => {
			const { privateKey: key1 } = await generateSigningKey("ES256");
			const { privateKey: key2 } = await generateSigningKey("ES256");
			const { config } = await createLeafConfig({
				keyProvider: new MemoryFederationKeyProvider([federationKey(key1), federationKey(key2)]),
			});
			const entity = new Leaf(config);
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.jwks?.keys.length, 2);
			t.equal(decoded.value.header.kid, key2.kid);
		});

		test("concurrent calls share one signing operation (stampede protection)", async (t) => {
			const { config: baseConfig } = await createLeafConfig();
			let providerCalls = 0;
			const keySet = await baseConfig.keyProvider.getFederationKeySet();
			const { config } = await createLeafConfig({
				keyProvider: {
					getFederationKeySet: async () => {
						providerCalls++;
						return keySet;
					},
				},
			});
			const entity = new Leaf(config);
			const [jwt1, jwt2] = await Promise.all([
				entity.getEntityConfiguration(),
				entity.getEntityConfiguration(),
			]);
			t.equal(jwt1, jwt2);
			t.equal(providerCalls, 1);
		});

		test("propagates key provider rejection", async (t) => {
			const { config } = await createLeafConfig({
				keyProvider: {
					getFederationKeySet: async () => {
						throw new Error("key provider failure");
					},
				},
			});
			const entity = new Leaf(config);
			try {
				await entity.getEntityConfiguration();
				t.ok(false, "should have thrown");
			} catch (e) {
				t.ok((e as Error).message.includes("key provider failure"), (e as Error).message);
			}
		});
	});

	// -------------------------------------------------------------------------
	// Leaf — isEntityConfigurationExpired
	// -------------------------------------------------------------------------
	module("leaf / Leaf / isEntityConfigurationExpired", () => {
		test("returns false for fresh EC", async (t) => {
			const { config } = await createLeafConfig();
			const entity = new Leaf(config);
			await entity.getEntityConfiguration();
			t.false(entity.isEntityConfigurationExpired());
		});

		test("returns true when no EC has been generated", async (t) => {
			const { config } = await createLeafConfig();
			const entity = new Leaf(config);
			t.true(entity.isEntityConfigurationExpired());
		});

		test("returns true at exact expiry boundary (now === exp)", async (t) => {
			const ttl = 3600;
			let nowMs = Date.now();
			const clock = { now: () => Math.floor(nowMs / 1000) };
			const { config } = await createLeafConfig({
				entityConfigurationTtlSeconds: ttl,
				options: { clock },
			});
			const entity = new Leaf(config);
			await entity.getEntityConfiguration();
			nowMs += ttl * 1000;
			t.true(entity.isEntityConfigurationExpired());
		});
	});

	// -------------------------------------------------------------------------
	// Leaf — cache expiry
	// -------------------------------------------------------------------------
	module("leaf / Leaf / cache expiry", () => {
		test("rebuilds EC after TTL expires", async (t) => {
			const ttl = 60;
			let nowMs = Date.now();
			const clock = { now: () => Math.floor(nowMs / 1000) };
			const { config } = await createLeafConfig({
				entityConfigurationTtlSeconds: ttl,
				options: { clock },
			});
			const entity = new Leaf(config);
			const jwt1 = await entity.getEntityConfiguration();
			nowMs += (ttl + 1) * 1000;
			const jwt2 = await entity.getEntityConfiguration();
			t.notEqual(jwt1, jwt2, "rebuilt after TTL");
		});
	});

	// -------------------------------------------------------------------------
	// Leaf — refreshEntityConfiguration
	// -------------------------------------------------------------------------
	module("leaf / Leaf / refreshEntityConfiguration", () => {
		test("produces a new JWT", async (t) => {
			const { config } = await createLeafConfig();
			const entity = new Leaf(config);
			await entity.getEntityConfiguration();
			const jwt2 = await entity.refreshEntityConfiguration();
			t.equal(typeof jwt2, "string");
			t.equal(jwt2.split(".").length, 3);
		});

		test("replaces the cached EC", async (t) => {
			const { config } = await createLeafConfig();
			const entity = new Leaf(config);
			await entity.getEntityConfiguration();
			const refreshed = await entity.refreshEntityConfiguration();
			const cached = await entity.getEntityConfiguration();
			t.equal(cached, refreshed);
		});
	});

	// -------------------------------------------------------------------------
	// Leaf — handleRequest
	// -------------------------------------------------------------------------
	module("leaf / Leaf / handleRequest", () => {
		test("responds 200 with entity-statement+jwt on /.well-known/openid-federation", async (t) => {
			const { config } = await createLeafConfig();
			const entity = new Leaf(config);
			const request = new Request("https://rp.example.com/.well-known/openid-federation");
			const response = await entity.handleRequest(request);
			t.equal(response.status, 200);
			t.equal(response.headers.get("content-type"), "application/entity-statement+jwt");
			const body = await response.text();
			t.equal(body.split(".").length, 3);
		});

		test("merges role metadata without mutating caller metadata", async (t) => {
			const inputMetadata = {
				federation_entity: { organization_name: "Leaf" },
			};
			const role = {
				type: "openid_relying_party",
				metadata: { client_name: "Role RP" },
			};
			const { config } = await createLeafConfig({
				metadata: inputMetadata,
				roles: [role],
			});
			const entity = new Leaf(config);

			t.false(Object.hasOwn(inputMetadata, "openid_relying_party"));
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			t.deepEqual(decoded.value.payload.metadata?.federation_entity, {
				organization_name: "Leaf",
			});
			t.deepEqual(decoded.value.payload.metadata?.openid_relying_party, {
				client_name: "Role RP",
			});
		});

		test("serves path-based Entity Identifier at derived well-known path", async (t) => {
			const pathEntityId = entityId("https://rp.example.com/tenant");
			const { config } = await createLeafConfig({ entityId: pathEntityId });
			const entity = new Leaf(config);
			const response = await entity.handleRequest(
				new Request(`${pathEntityId}${WELL_KNOWN_OPENID_FEDERATION}`),
			);
			t.equal(response.status, 200);
			const jwt = await response.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			t.equal(decoded.value.payload.iss, pathEntityId);
			t.equal(decoded.value.payload.sub, pathEntityId);
		});

		test("normalizes trailing slash before deriving well-known route", async (t) => {
			const { config } = await createLeafConfig({
				entityId: "https://rp.example.com/tenant/" as EntityId,
			});
			const entity = new Leaf(config);
			t.equal(entity.entityId, "https://rp.example.com/tenant");
			const response = await entity.handleRequest(
				new Request("https://rp.example.com/tenant/.well-known/openid-federation"),
			);
			t.equal(response.status, 200);
			const rootResponse = await entity.handleRequest(
				new Request("https://rp.example.com/.well-known/openid-federation"),
			);
			t.equal(rootResponse.status, 404);
		});

		test("returns 405 for POST to well-known path", async (t) => {
			const { config } = await createLeafConfig();
			const entity = new Leaf(config);
			const response = await entity.handleRequest(
				new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`, { method: "POST" }),
			);
			t.equal(response.status, 405);
		});

		test("returns 404 for unknown paths", async (t) => {
			const { config } = await createLeafConfig();
			const entity = new Leaf(config);
			const response = await entity.handleRequest(new Request(`${LEAF_ID}/unknown-path`));
			t.equal(response.status, 404);
		});

		test("returns 500 when getEntityConfiguration throws", async (t) => {
			const originalError = new Error("signing failure");
			const { config } = await createLeafConfig({
				keyProvider: {
					getFederationKeySet: async () => {
						throw originalError;
					},
				},
			});
			const entity = new Leaf(config);
			const response = await entity.handleRequest(
				new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`),
			);
			t.equal(response.status, 500);
			const body = (await response.json()) as Record<string, unknown>;
			t.equal(body.error, "server_error");
		});

		test("500 body does NOT contain internal error message (no info leak)", async (t) => {
			const secretMessage = "database password is hunter2";
			const { config } = await createLeafConfig({
				keyProvider: {
					getFederationKeySet: async () => {
						throw new Error(secretMessage);
					},
				},
			});
			const entity = new Leaf(config);
			const response = await entity.handleRequest(
				new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`),
			);
			const text = await response.text();
			t.notOk(text.includes(secretMessage), "secret not in response");
		});

		test("logger error() is called with original error on 500", async (t) => {
			const originalError = new Error("signing failure");
			const errorFn = mockFn<[string, Record<string, unknown>]>();
			const { config } = await createLeafConfig({
				keyProvider: {
					getFederationKeySet: async () => {
						throw originalError;
					},
				},
				options: {
					logger: {
						debug: mockFn(),
						info: mockFn(),
						warn: mockFn(),
						error: errorFn,
					},
				},
			});
			const entity = new Leaf(config);
			await entity.handleRequest(new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`));
			t.equal(errorFn.callCount(), 1);
			const [msg, ctx] = errorFn.lastCall();
			t.equal(msg, "Failed to serve entity configuration");
			t.equal((ctx as Record<string, unknown>).error, originalError);
		});

		test("404 response has error and error_description fields", async (t) => {
			const { config } = await createLeafConfig();
			const entity = new Leaf(config);
			const response = await entity.handleRequest(new Request(`${LEAF_ID}/unknown`));
			const body = (await response.json()) as Record<string, unknown>;
			t.equal(body.error, "not_found");
			t.equal(body.error_description, "Unknown endpoint");
		});

		test("405 response has error field", async (t) => {
			const { config } = await createLeafConfig();
			const entity = new Leaf(config);
			const response = await entity.handleRequest(
				new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`, { method: "POST" }),
			);
			const body = (await response.json()) as Record<string, unknown>;
			t.equal(body.error, "method_not_allowed");
		});

		test("500 response has error and error_description fields", async (t) => {
			const { config } = await createLeafConfig({
				keyProvider: {
					getFederationKeySet: async () => {
						throw new Error("fail");
					},
				},
			});
			const entity = new Leaf(config);
			const response = await entity.handleRequest(
				new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`),
			);
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
			const fed = await createMockMockFederation();
			const config: LeafConfig = {
				entityId: LEAF_ID,
				keyProvider: new MemoryFederationKeyProvider(federationKey(fed.leafSigningKey)),
				authorityHints: [TA_ID],
				metadata: {
					openid_relying_party: {
						redirect_uris: ["https://rp.example.com/callback"],
						response_types: ["code"],
						client_registration_types: ["automatic"],
					},
				},
			};
			const entity = new Leaf(config);
			const response = await entity.handleRequest(
				new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`),
			);
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
			const fed = await createMockMockFederation();
			const config: LeafConfig = {
				entityId: LEAF_ID,
				keyProvider: new MemoryFederationKeyProvider(federationKey(fed.leafSigningKey)),
				authorityHints: [TA_ID],
				metadata: {
					openid_relying_party: {
						redirect_uris: ["https://rp.example.com/callback"],
						response_types: ["code"],
					},
				},
			};
			new Leaf(config);
			const discovery = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);
			t.true(isOk(discovery));
			if (isOk(discovery)) {
				t.equal(discovery.value.entityId, OP_ID);
				t.ok(discovery.value.resolvedMetadata.openid_provider, "openid_provider present");
				t.equal(discovery.value.trustChain.trustAnchorId, TA_ID);
			}
		});

		test("EC caching and refresh cycle", async (t) => {
			const fed = await createMockMockFederation();
			const config: LeafConfig = {
				entityId: LEAF_ID,
				keyProvider: new MemoryFederationKeyProvider(federationKey(fed.leafSigningKey)),
				authorityHints: [TA_ID],
				metadata: {
					openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
				},
			};
			const entity = new Leaf(config);
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

async function createMockMockFederation() {
	return createMockFederation();
}
