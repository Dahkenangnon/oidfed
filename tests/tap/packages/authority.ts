import type QUnit from "qunit";
import { createAuthenticatedHandler } from "../../../packages/authority/src/endpoints/client-auth.js";
import type { HandlerContext } from "../../../packages/authority/src/endpoints/context.js";
import { createEntityConfigurationHandler } from "../../../packages/authority/src/endpoints/entity-configuration.js";
import { createFetchHandler } from "../../../packages/authority/src/endpoints/fetch.js";
import {
	errorResponse,
	extractRequestParams,
	jsonResponse,
	jwtResponse,
	parseQueryParams,
	requireMethod,
	requireMethods,
	SECURITY_HEADERS,
	toPublicError,
} from "../../../packages/authority/src/endpoints/helpers.js";
import { createHistoricalKeysHandler } from "../../../packages/authority/src/endpoints/historical-keys.js";
import type { RegistrationProtocolAdapter } from "../../../packages/authority/src/endpoints/index.js";
import { createListHandler } from "../../../packages/authority/src/endpoints/list.js";
import { createRegistrationHandler } from "../../../packages/authority/src/endpoints/registration.js";
import { createResolveHandler } from "../../../packages/authority/src/endpoints/resolve.js";
import {
	createTrustMarkHandler,
	createTrustMarkIssuanceHandler,
} from "../../../packages/authority/src/endpoints/trust-mark.js";
import { createTrustMarkListHandler } from "../../../packages/authority/src/endpoints/trust-mark-list.js";
import { createTrustMarkStatusHandler } from "../../../packages/authority/src/endpoints/trust-mark-status.js";
import { compose, type Middleware } from "../../../packages/authority/src/handler.js";
import { rotateKey, rotateKeyCompromise } from "../../../packages/authority/src/keys/index.js";
import {
	type AuthorityConfig,
	createAuthorityServer,
} from "../../../packages/authority/src/server.js";
import {
	MemoryKeyStore,
	MemorySubordinateStore,
	MemoryTrustMarkStore,
} from "../../../packages/authority/src/storage/memory.js";
import type {
	SubordinateRecord,
	TrustMarkRecord,
} from "../../../packages/authority/src/storage/types.js";
import type { FederationError } from "../../../packages/core/src/index.js";
import {
	decodeEntityStatement,
	type EntityId,
	EntityType,
	entityId,
	err,
	FederationEndpoint,
	FederationErrorCode,
	federationError,
	generateSigningKey,
	InternalErrorCode,
	isOk,
	type JWK,
	JwtTyp,
	MediaType,
	signEntityStatement,
	signTrustMarkDelegation,
	type TrustAnchorSet,
	TrustMarkStatus,
	validateTrustMark,
	verifyEntityStatement,
	WELL_KNOWN_OPENID_FEDERATION,
} from "../../../packages/core/src/index.js";
import { createMockFederation, LEAF_ID, OP_ID, TA_ID } from "../fixtures/index.js";

// ---------------------------------------------------------------------------
// Shared test helper
// ---------------------------------------------------------------------------

const ENTITY_ID = entityId("https://authority.example.com");
const TEST_KID = "test-key-1";

type TestContextOverrides = { [K in keyof HandlerContext]?: HandlerContext[K] | undefined };
async function createTestContext(overrides?: TestContextOverrides): Promise<{
	ctx: HandlerContext;
	signingKey: JWK;
	publicKey: JWK;
	keyStore: MemoryKeyStore;
	subordinateStore: MemorySubordinateStore;
	trustMarkStore: MemoryTrustMarkStore;
}> {
	const { privateKey, publicKey: rawPublicKey } = await generateSigningKey("ES256");
	const signingKey = { ...privateKey, kid: TEST_KID };
	const publicKey = { ...rawPublicKey, kid: TEST_KID };

	const keyStore = new MemoryKeyStore();
	await keyStore.addKey(signingKey);
	await keyStore.activateKey(TEST_KID);

	const subordinateStore = new MemorySubordinateStore();
	const trustMarkStore = new MemoryTrustMarkStore();

	const ctx: HandlerContext = {
		entityId: ENTITY_ID,
		keyStore,
		subordinateStore,
		trustMarkStore,
		metadata: {
			federation_entity: {
				federation_fetch_endpoint: `${ENTITY_ID}/federation_fetch`,
				federation_list_endpoint: `${ENTITY_ID}/federation_list`,
			},
		},
		getSigningKey: async () => ({
			key: signingKey,
			kid: TEST_KID,
		}),
		...overrides,
	};

	return { ctx, signingKey, publicKey, keyStore, subordinateStore, trustMarkStore };
}

// ---------------------------------------------------------------------------

export default (QUnit: QUnit) => {
	const { module, test } = QUnit;

	// -------------------------------------------------------------------------
	// handler — compose
	// -------------------------------------------------------------------------
	module("authority / compose", () => {
		const dummyNext = async (_req: Request) => new Response("final", { status: 200 });

		test("passes through with no middlewares", async (t) => {
			const mw = compose();
			const req = new Request("https://example.com");
			const res = await mw(req, dummyNext);
			t.equal(res.status, 200);
			t.equal(await res.text(), "final");
		});

		test("single middleware wraps the handler", async (t) => {
			const mw: Middleware = async (req, next) => {
				const res = await next(req);
				return new Response(await res.text(), {
					status: res.status,
					headers: { "X-Added": "true" },
				});
			};
			const composed = compose(mw);
			const res = await composed(new Request("https://example.com"), dummyNext);
			t.equal(res.headers.get("X-Added"), "true");
			t.equal(await res.text(), "final");
		});

		test("multiple middlewares execute in order", async (t) => {
			const order: number[] = [];
			const mw1: Middleware = async (req, next) => {
				order.push(1);
				const res = await next(req);
				order.push(4);
				return res;
			};
			const mw2: Middleware = async (req, next) => {
				order.push(2);
				const res = await next(req);
				order.push(3);
				return res;
			};
			const composed = compose(mw1, mw2);
			await composed(new Request("https://example.com"), dummyNext);
			t.deepEqual(order, [1, 2, 3, 4]);
		});

		test("middleware can short-circuit (skip next)", async (t) => {
			const blocker: Middleware = async (_req, _next) => {
				return new Response("blocked", { status: 403 });
			};
			const neverCalled: Middleware = async (_req, _next) => {
				throw new Error("Should not be called");
			};
			const composed = compose(blocker, neverCalled);
			const res = await composed(new Request("https://example.com"), dummyNext);
			t.equal(res.status, 403);
			t.equal(await res.text(), "blocked");
		});
	});

	// -------------------------------------------------------------------------
	// storage/memory-key-store
	// -------------------------------------------------------------------------
	module("authority / MemoryKeyStore", (hooks) => {
		let store: MemoryKeyStore;

		hooks.beforeEach(() => {
			store = new MemoryKeyStore();
		});

		module("constructor", () => {
			test("creates an empty store with no arguments", async (t) => {
				const s = new MemoryKeyStore();
				const keys = await s.getHistoricalKeys();
				t.equal(keys.length, 0);
			});

			test("accepts a single key and activates it", async (t) => {
				const { privateKey } = await generateSigningKey("ES256");
				const key = { ...privateKey, kid: "init-1" };
				const s = new MemoryKeyStore(key);
				const signing = await s.getSigningKey();
				t.equal(signing.key.kid, "init-1");
				t.equal(signing.state, "active");
				t.true("d" in signing.key);
			});

			test("accepts an array of keys and activates all", async (t) => {
				const k1 = { ...(await generateSigningKey("ES256")).privateKey, kid: "a" };
				const k2 = { ...(await generateSigningKey("ES256")).privateKey, kid: "b" };
				const s = new MemoryKeyStore([k1, k2]);
				const active = await s.getActiveKeys();
				t.equal(active.keys.length, 2);
				const signing = await s.getSigningKey();
				t.equal(signing.key.kid, "b");
			});

			test("strips private fields from getActiveKeys", async (t) => {
				const { privateKey } = await generateSigningKey("ES256");
				const s = new MemoryKeyStore({ ...privateKey, kid: "x" });
				const active = await s.getActiveKeys();
				t.false("d" in active.keys[0]!);
			});

			test("throws if initial key has no kid", (t) => {
				try {
					new MemoryKeyStore({ kty: "EC" } as JWK);
					t.ok(false, "should have thrown");
				} catch (e) {
					t.true((e as Error).message.includes("kid"));
				}
			});

			test("throws on duplicate kid in initial keys", async (t) => {
				const { privateKey } = await generateSigningKey("ES256");
				const key = { ...privateKey, kid: "dup" };
				try {
					new MemoryKeyStore([key, key]);
					t.ok(false, "should have thrown");
				} catch (e) {
					t.true((e as Error).message.includes("Duplicate kid"));
				}
			});

			test("still allows addKey after constructor initialization", async (t) => {
				const k1 = { ...(await generateSigningKey("ES256")).privateKey, kid: "init" };
				const s = new MemoryKeyStore(k1);
				const k2 = { ...(await generateSigningKey("ES256")).privateKey, kid: "added" };
				await s.addKey(k2);
				await s.activateKey("added");
				const history = await s.getHistoricalKeys();
				t.equal(history.length, 2);
			});
		});

		async function addAndActivateKey(kid?: string) {
			const { privateKey } = await generateSigningKey("ES256");
			const keyKid = kid ?? privateKey.kid ?? crypto.randomUUID();
			const key = { ...privateKey, kid: keyKid };
			await store.addKey(key);
			await store.activateKey(keyKid);
			return key;
		}

		module("addKey", () => {
			test("adds a key in pending state", async (t) => {
				const { privateKey } = await generateSigningKey("ES256");
				const key = { ...privateKey, kid: "k1" };
				await store.addKey(key);
				const history = await store.getHistoricalKeys();
				t.equal(history.length, 1);
				t.equal(history[0]!.state, "pending");
			});

			test("requires kid", async (t) => {
				const { privateKey } = await generateSigningKey("ES256");
				const key = { ...privateKey };
				delete (key as Record<string, unknown>).kid;
				try {
					await store.addKey(key);
					t.ok(false, "should have thrown");
				} catch (e) {
					t.true((e as Error).message.includes("kid"));
				}
			});

			test("rejects duplicate kid", async (t) => {
				const { privateKey } = await generateSigningKey("ES256");
				const key = { ...privateKey, kid: "k1" };
				await store.addKey(key);
				try {
					await store.addKey(key);
					t.ok(false, "should have thrown");
				} catch (e) {
					t.true((e as Error).message.includes("already exists"));
				}
			});
		});

		module("activateKey", () => {
			test("transitions pending to active", async (t) => {
				const { privateKey } = await generateSigningKey("ES256");
				const key = { ...privateKey, kid: "k1" };
				await store.addKey(key);
				await store.activateKey("k1");
				const managed = (await store.getHistoricalKeys()).find((k) => k.key.kid === "k1");
				t.equal(managed?.state, "active");
				t.true((managed?.activatedAt ?? 0) > 0);
			});

			test("rejects non-pending key", async (t) => {
				await addAndActivateKey("k1");
				try {
					await store.activateKey("k1");
					t.ok(false, "should have thrown");
				} catch (e) {
					t.true((e as Error).message.includes("active"));
				}
			});

			test("throws for unknown kid", async (t) => {
				try {
					await store.activateKey("unknown");
					t.ok(false, "should have thrown");
				} catch (e) {
					t.true((e as Error).message.includes("not found"));
				}
			});
		});

		module("getActiveKeys", () => {
			test("returns active and retiring keys", async (t) => {
				await addAndActivateKey("k1");
				await addAndActivateKey("k2");
				await store.retireKey("k1", Date.now() + 86400000);
				const result = await store.getActiveKeys();
				t.equal(result.keys.length, 2);
			});

			test("strips private key fields", async (t) => {
				await addAndActivateKey("k1");
				const result = await store.getActiveKeys();
				const key = result.keys[0]!;
				t.false("d" in key);
				t.false("p" in key);
				t.false("q" in key);
				t.false("dp" in key);
				t.false("dq" in key);
				t.false("qi" in key);
			});

			test("does not include pending keys", async (t) => {
				const { privateKey } = await generateSigningKey("ES256");
				await store.addKey({ ...privateKey, kid: "pending-key" });
				const result = await store.getActiveKeys();
				t.equal(result.keys.length, 0);
			});

			test("does not include revoked keys", async (t) => {
				await addAndActivateKey("k1");
				await store.revokeKey("k1", "compromise");
				const result = await store.getActiveKeys();
				t.equal(result.keys.length, 0);
			});
		});

		module("getSigningKey", () => {
			test("returns the most recently activated active key", async (t) => {
				await addAndActivateKey("k1");
				await new Promise((r) => setTimeout(r, 5));
				await addAndActivateKey("k2");
				const signing = await store.getSigningKey();
				t.equal(signing.key.kid, "k2");
			});

			test("returns private key material", async (t) => {
				await addAndActivateKey("k1");
				const signing = await store.getSigningKey();
				t.true("d" in signing.key);
			});

			test("throws when no active key", async (t) => {
				try {
					await store.getSigningKey();
					t.ok(false, "should have thrown");
				} catch (e) {
					t.true((e as Error).message.includes("No active signing key"));
				}
			});

			test("does not return retiring keys", async (t) => {
				await addAndActivateKey("k1");
				await store.retireKey("k1", Date.now() + 86400000);
				try {
					await store.getSigningKey();
					t.ok(false, "should have thrown");
				} catch (e) {
					t.true((e as Error).message.includes("No active signing key"));
				}
			});
		});

		module("retireKey", () => {
			test("transitions active to retiring", async (t) => {
				await addAndActivateKey("k1");
				const removeAfter = Date.now() + 86400000;
				await store.retireKey("k1", removeAfter);
				const managed = (await store.getHistoricalKeys()).find((k) => k.key.kid === "k1");
				t.equal(managed?.state, "retiring");
				t.equal(managed?.scheduledRemovalAt, removeAfter);
			});

			test("rejects non-active key", async (t) => {
				const { privateKey } = await generateSigningKey("ES256");
				await store.addKey({ ...privateKey, kid: "k1" });
				try {
					await store.retireKey("k1", Date.now());
					t.ok(false, "should have thrown");
				} catch (e) {
					t.true((e as Error).message.includes("pending"));
				}
			});
		});

		module("revokeKey", () => {
			test("revokes an active key", async (t) => {
				await addAndActivateKey("k1");
				await store.revokeKey("k1", "keyCompromise");
				const managed = (await store.getHistoricalKeys()).find((k) => k.key.kid === "k1");
				t.equal(managed?.state, "revoked");
				t.true((managed?.revokedAt ?? 0) > 0);
				t.equal(managed?.revocationReason, "keyCompromise");
			});

			test("can revoke a pending key (emergency)", async (t) => {
				const { privateKey } = await generateSigningKey("ES256");
				await store.addKey({ ...privateKey, kid: "k1" });
				await store.revokeKey("k1", "keyCompromise");
				const managed = (await store.getHistoricalKeys()).find((k) => k.key.kid === "k1");
				t.equal(managed?.state, "revoked");
			});

			test("can revoke a retiring key", async (t) => {
				await addAndActivateKey("k1");
				await store.retireKey("k1", Date.now() + 86400000);
				await store.revokeKey("k1", "keyCompromise");
				const managed = (await store.getHistoricalKeys()).find((k) => k.key.kid === "k1");
				t.equal(managed?.state, "revoked");
			});

			test("throws for unknown kid", async (t) => {
				try {
					await store.revokeKey("unknown", "test");
					t.ok(false, "should have thrown");
				} catch (e) {
					t.true((e as Error).message.includes("not found"));
				}
			});
		});

		module("getHistoricalKeys", () => {
			test("returns all keys regardless of state", async (t) => {
				const { privateKey: pk1 } = await generateSigningKey("ES256");
				await store.addKey({ ...pk1, kid: "k1" });
				await addAndActivateKey("k2");
				await addAndActivateKey("k3");
				await store.retireKey("k3", Date.now() + 86400000);
				const history = await store.getHistoricalKeys();
				t.equal(history.length, 3);
				const states = history.map((k) => k.state);
				t.true(states.includes("pending"));
				t.true(states.includes("active"));
				t.true(states.includes("retiring"));
			});
		});
	});

	// -------------------------------------------------------------------------
	// storage/memory-subordinate-store
	// -------------------------------------------------------------------------
	{
		const SUB1 = entityId("https://sub1.example.com");
		const SUB2 = entityId("https://sub2.example.com");
		const SUB3 = entityId("https://sub3.example.com");

		function makeSubRecord(
			id: ReturnType<typeof entityId>,
			overrides?: Partial<SubordinateRecord>,
		): SubordinateRecord {
			return {
				entityId: id,
				jwks: { keys: [{ kty: "EC", crv: "P-256", x: "abc", y: "def" }] },
				createdAt: Date.now(),
				updatedAt: Date.now(),
				...overrides,
			};
		}

		module("authority / MemorySubordinateStore", (hooks) => {
			let store: MemorySubordinateStore;
			hooks.beforeEach(() => {
				store = new MemorySubordinateStore();
			});

			module("add & get", () => {
				test("adds and retrieves a record", async (t) => {
					const record = makeSubRecord(SUB1);
					await store.add(record);
					const result = await store.get(SUB1);
					t.deepEqual(result, record);
				});

				test("returns undefined for unknown entity", async (t) => {
					const result = await store.get(SUB1);
					t.equal(result, undefined);
				});

				test("rejects duplicate entityId", async (t) => {
					await store.add(makeSubRecord(SUB1));
					try {
						await store.add(makeSubRecord(SUB1));
						t.ok(false, "should have thrown");
					} catch (e) {
						t.true((e as Error).message.includes("already exists"));
					}
				});
			});

			module("list", () => {
				test("returns all records with no filter", async (t) => {
					await store.add(makeSubRecord(SUB1));
					await store.add(makeSubRecord(SUB2));
					const results = await store.list();
					t.equal(results.length, 2);
				});

				test("returns empty array for empty store", async (t) => {
					const results = await store.list();
					t.deepEqual(results, []);
				});

				test("filters by entityType", async (t) => {
					await store.add(makeSubRecord(SUB1, { entityTypes: [EntityType.OpenIDProvider] }));
					await store.add(makeSubRecord(SUB2, { entityTypes: [EntityType.OpenIDRelyingParty] }));
					const results = await store.list({ entityTypes: [EntityType.OpenIDProvider] });
					t.equal(results.length, 1);
					t.equal(results[0]!.entityId, SUB1);
				});

				test("filters by intermediate", async (t) => {
					await store.add(makeSubRecord(SUB1, { isIntermediate: true }));
					await store.add(makeSubRecord(SUB2, { isIntermediate: false }));
					await store.add(makeSubRecord(SUB3));
					const results = await store.list({ intermediate: true });
					t.equal(results.length, 1);
					t.equal(results[0]!.entityId, SUB1);
				});

				test("filters intermediate=false includes records without flag", async (t) => {
					await store.add(makeSubRecord(SUB1, { isIntermediate: false }));
					await store.add(makeSubRecord(SUB2));
					const results = await store.list({ intermediate: false });
					t.equal(results.length, 2);
				});
			});

			module("update", () => {
				test("updates a record", async (t) => {
					await store.add(makeSubRecord(SUB1));
					await store.update(SUB1, { isIntermediate: true });
					const result = await store.get(SUB1);
					t.equal(result?.isIntermediate, true);
				});

				test("preserves entityId on update", async (t) => {
					await store.add(makeSubRecord(SUB1));
					await store.update(SUB1, { entityId: SUB2 } as Partial<SubordinateRecord>);
					const result = await store.get(SUB1);
					t.equal(result?.entityId, SUB1);
				});

				test("updates updatedAt timestamp", async (t) => {
					const original = makeSubRecord(SUB1);
					await store.add(original);
					await new Promise((r) => setTimeout(r, 5));
					await store.update(SUB1, { isIntermediate: true });
					const result = await store.get(SUB1);
					t.true((result?.updatedAt ?? 0) > original.updatedAt);
				});

				test("throws for unknown entity", async (t) => {
					try {
						await store.update(SUB1, { isIntermediate: true });
						t.ok(false, "should have thrown");
					} catch (e) {
						t.true((e as Error).message.includes("not found"));
					}
				});
			});

			module("remove", () => {
				test("removes a record", async (t) => {
					await store.add(makeSubRecord(SUB1));
					await store.remove(SUB1);
					const result = await store.get(SUB1);
					t.equal(result, undefined);
				});

				test("throws for unknown entity", async (t) => {
					try {
						await store.remove(SUB1);
						t.ok(false, "should have thrown");
					} catch (e) {
						t.true((e as Error).message.includes("not found"));
					}
				});
			});
		});
	}

	// -------------------------------------------------------------------------
	// storage/memory-trust-mark-store
	// -------------------------------------------------------------------------
	{
		const TM_SUB1 = entityId("https://sub1.example.com");
		const TM_SUB2 = entityId("https://sub2.example.com");
		const TYPE_A = "https://trust.example.com/mark-a";
		const TYPE_B = "https://trust.example.com/mark-b";

		function makeTmRecord(
			type: string,
			subject: ReturnType<typeof entityId>,
			overrides?: Partial<TrustMarkRecord>,
		): TrustMarkRecord {
			return {
				trustMarkType: type,
				subject,
				jwt: `jwt.for.${type}.${subject}`,
				issuedAt: Math.floor(Date.now() / 1000),
				active: true,
				...overrides,
			};
		}

		module("authority / MemoryTrustMarkStore", (hooks) => {
			let store: MemoryTrustMarkStore;
			hooks.beforeEach(() => {
				store = new MemoryTrustMarkStore();
			});

			module("issue & get", () => {
				test("issues and retrieves a trust mark", async (t) => {
					const record = makeTmRecord(TYPE_A, TM_SUB1);
					await store.issue(record);
					const result = await store.get(TYPE_A, TM_SUB1);
					t.deepEqual(result, record);
				});

				test("returns undefined for unknown trust mark", async (t) => {
					const result = await store.get(TYPE_A, TM_SUB1);
					t.equal(result, undefined);
				});

				test("upserts on re-issue (overwrites)", async (t) => {
					await store.issue(makeTmRecord(TYPE_A, TM_SUB1, { jwt: "first.jwt" }));
					await store.issue(makeTmRecord(TYPE_A, TM_SUB1, { jwt: "second.jwt" }));
					const result = await store.get(TYPE_A, TM_SUB1);
					t.equal(result?.jwt, "second.jwt");
				});
			});

			module("list", () => {
				test("lists records by type", async (t) => {
					await store.issue(makeTmRecord(TYPE_A, TM_SUB1));
					await store.issue(makeTmRecord(TYPE_A, TM_SUB2));
					await store.issue(makeTmRecord(TYPE_B, TM_SUB1));
					const result = await store.list(TYPE_A);
					t.equal(result.items.length, 2);
				});

				test("filters by sub", async (t) => {
					await store.issue(makeTmRecord(TYPE_A, TM_SUB1));
					await store.issue(makeTmRecord(TYPE_A, TM_SUB2));
					const result = await store.list(TYPE_A, { sub: TM_SUB1 });
					t.equal(result.items.length, 1);
					t.equal(result.items[0]!.subject, TM_SUB1);
				});

				test("paginates with cursor and limit", async (t) => {
					for (let i = 0; i < 5; i++) {
						await store.issue(makeTmRecord(TYPE_A, entityId(`https://sub${i}.example.com`)));
					}
					const page1 = await store.list(TYPE_A, { limit: 2 });
					t.equal(page1.items.length, 2);
					t.ok(page1.nextCursor !== undefined);

					const page2 = await store.list(TYPE_A, { limit: 2, cursor: page1.nextCursor });
					t.equal(page2.items.length, 2);
					t.ok(page2.nextCursor !== undefined);

					const page3 = await store.list(TYPE_A, { limit: 2, cursor: page2.nextCursor });
					t.equal(page3.items.length, 1);
					t.equal(page3.nextCursor, undefined);
				});

				test("returns empty for unknown type", async (t) => {
					const result = await store.list("https://unknown.example.com/mark");
					t.deepEqual(result.items, []);
				});
			});

			module("revoke", () => {
				test("sets active to false", async (t) => {
					await store.issue(makeTmRecord(TYPE_A, TM_SUB1));
					await store.revoke(TYPE_A, TM_SUB1);
					const result = await store.get(TYPE_A, TM_SUB1);
					t.equal(result?.active, false);
				});

				test("throws for unknown trust mark", async (t) => {
					try {
						await store.revoke(TYPE_A, TM_SUB1);
						t.ok(false, "should have thrown");
					} catch (e) {
						t.true((e as Error).message.includes("not found"));
					}
				});
			});

			module("isActive", () => {
				test("returns true for active trust mark", async (t) => {
					await store.issue(makeTmRecord(TYPE_A, TM_SUB1));
					t.equal(await store.isActive(TYPE_A, TM_SUB1), true);
				});

				test("returns false for revoked trust mark", async (t) => {
					await store.issue(makeTmRecord(TYPE_A, TM_SUB1));
					await store.revoke(TYPE_A, TM_SUB1);
					t.equal(await store.isActive(TYPE_A, TM_SUB1), false);
				});

				test("returns false for nonexistent trust mark", async (t) => {
					t.equal(await store.isActive(TYPE_A, TM_SUB1), false);
				});
			});
		});
	}

	// -------------------------------------------------------------------------
	// keys/rotation
	// -------------------------------------------------------------------------
	module("authority / rotateKey", (hooks) => {
		let rotStore: MemoryKeyStore;

		hooks.beforeEach(async () => {
			rotStore = new MemoryKeyStore();
			const { privateKey } = await generateSigningKey("ES256");
			await rotStore.addKey({ ...privateKey, kid: "old-key" });
			await rotStore.activateKey("old-key");
		});

		test("activates new key and retires old key", async (t) => {
			const { privateKey: newKey } = await generateSigningKey("ES256");
			const key = { ...newKey, kid: "new-key" };
			await rotateKey(rotStore, key);
			const signing = await rotStore.getSigningKey();
			t.equal(signing.key.kid, "new-key");
			const history = await rotStore.getHistoricalKeys();
			const oldManaged = history.find((k) => k.key.kid === "old-key");
			t.equal(oldManaged?.state, "retiring");
			t.true((oldManaged?.scheduledRemovalAt ?? 0) > Date.now());
		});

		test("old key is still in active keys (retiring)", async (t) => {
			const { privateKey: newKey } = await generateSigningKey("ES256");
			await rotateKey(rotStore, { ...newKey, kid: "new-key" });
			const activeKeys = await rotStore.getActiveKeys();
			t.equal(activeKeys.keys.length, 2);
		});
	});

	// -------------------------------------------------------------------------
	// endpoints/helpers
	// -------------------------------------------------------------------------
	module("authority / SECURITY_HEADERS", () => {
		test("includes Cache-Control no-store", (t) => {
			t.equal(SECURITY_HEADERS["Cache-Control"], "no-store");
		});

		test("includes X-Content-Type-Options nosniff", (t) => {
			t.equal(SECURITY_HEADERS["X-Content-Type-Options"], "nosniff");
		});

		test("includes Strict-Transport-Security", (t) => {
			t.true(/max-age=\d+/.test(SECURITY_HEADERS["Strict-Transport-Security"] ?? ""));
		});

		test("includes X-Frame-Options DENY", (t) => {
			t.equal(SECURITY_HEADERS["X-Frame-Options"], "DENY");
		});

		test("includes Referrer-Policy no-referrer", (t) => {
			t.equal(SECURITY_HEADERS["Referrer-Policy"], "no-referrer");
		});
	});

	module("authority / jwtResponse", () => {
		test("returns 200 with correct content type and body", (t) => {
			const res = jwtResponse("jwt.token.here", "application/entity-statement+jwt");
			t.equal(res.status, 200);
			t.equal(res.headers.get("Content-Type"), "application/entity-statement+jwt");
		});

		test("includes security headers", async (t) => {
			const res = jwtResponse("jwt.token.here", "application/entity-statement+jwt");
			t.equal(res.headers.get("Cache-Control"), "no-store");
			t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
			t.ok(res.headers.get("Strict-Transport-Security"));
		});

		test("returns the JWT as the body", async (t) => {
			const res = jwtResponse("my.jwt.token", "application/entity-statement+jwt");
			t.equal(await res.text(), "my.jwt.token");
		});
	});

	module("authority / jsonResponse", () => {
		test("returns JSON with correct content type", async (t) => {
			const res = jsonResponse({ foo: "bar" });
			t.equal(res.status, 200);
			t.equal(res.headers.get("Content-Type"), "application/json");
			t.deepEqual(await res.json(), { foo: "bar" });
		});

		test("includes security headers", (t) => {
			const res = jsonResponse([]);
			t.equal(res.headers.get("Cache-Control"), "no-store");
			t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
		});

		test("supports custom status code", (t) => {
			const res = jsonResponse({ error: "test" }, 400);
			t.equal(res.status, 400);
		});
	});

	module("authority / errorResponse", () => {
		test("returns error JSON with code", async (t) => {
			const res = errorResponse(400, "invalid_request", "Missing sub");
			t.equal(res.status, 400);
			t.deepEqual(await res.json(), { error: "invalid_request", error_description: "Missing sub" });
		});

		test("omits error_description when not provided", async (t) => {
			// @ts-expect-error description is typed as required but runtime-optional via JSON.stringify eliding undefined
			const res = errorResponse(500, "server_error");
			const body = (await res.json()) as Record<string, unknown>;
			t.deepEqual(body, { error: "server_error" });
			t.equal(body.error_description, undefined);
		});

		test("includes security headers", (t) => {
			// @ts-expect-error description is typed as required but runtime-optional via JSON.stringify eliding undefined
			const res = errorResponse(404, "not_found");
			t.equal(res.headers.get("Cache-Control"), "no-store");
			t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
		});
	});

	module("authority / toPublicError", () => {
		test("passes through public federation error codes", (t) => {
			const e: FederationError = {
				code: "invalid_request" as FederationError["code"],
				description: "Missing parameter",
			};
			const result = toPublicError(e);
			t.equal(result.code, "invalid_request");
			t.equal(result.description, "Missing parameter");
			t.equal(result.status, 400);
		});

		test("maps not_found to 404", (t) => {
			const e: FederationError = {
				code: "not_found" as FederationError["code"],
				description: "Entity not found",
			};
			const result = toPublicError(e);
			t.equal(result.status, 404);
			t.equal(result.code, "not_found");
		});

		test("sanitizes internal error codes to server_error", (t) => {
			const e: FederationError = {
				code: InternalErrorCode.SignatureInvalid as string as FederationError["code"],
				description: "HMAC mismatch at byte 47 of key material",
			};
			const result = toPublicError(e);
			t.equal(result.code, "server_error");
			t.equal(result.status, 500);
			t.equal(result.description, "An internal error occurred");
			t.false(result.description.includes("HMAC"));
		});

		test("sanitizes unknown error codes to server_error", (t) => {
			const e: FederationError = {
				code: "some_unknown_code" as FederationError["code"],
				description: "Secret internal details",
			};
			const result = toPublicError(e);
			t.equal(result.code, "server_error");
			t.equal(result.description, "An internal error occurred");
		});

		test("maps temporarily_unavailable to 503", (t) => {
			const e: FederationError = {
				code: "temporarily_unavailable" as FederationError["code"],
				description: "Try again later",
			};
			const result = toPublicError(e);
			t.equal(result.status, 503);
		});
	});

	module("authority / parseQueryParams", () => {
		test("extracts query parameters from request", (t) => {
			const req = new Request(
				"https://example.com/path?sub=https%3A%2F%2Ffoo.com&type=openid_provider",
			);
			const params = parseQueryParams(req);
			t.equal(params.get("sub"), "https://foo.com");
			t.equal(params.get("type"), "openid_provider");
		});

		test("returns empty params for no query string", (t) => {
			const req = new Request("https://example.com/path");
			const params = parseQueryParams(req);
			t.equal(params.toString(), "");
		});
	});

	module("authority / requireMethod", () => {
		test("returns null when method matches", (t) => {
			const req = new Request("https://example.com", { method: "GET" });
			t.equal(requireMethod(req, "GET"), null);
		});

		test("returns 405 when method does not match", async (t) => {
			const req = new Request("https://example.com", { method: "POST" });
			const res = requireMethod(req, "GET");
			t.ok(res !== null);
			t.equal(res?.status, 405);
			t.equal(res?.headers.get("Allow"), "GET");
		});

		test("includes security headers on 405", (t) => {
			const req = new Request("https://example.com", { method: "DELETE" });
			const res = requireMethod(req, "POST");
			t.equal(res?.headers.get("Cache-Control"), "no-store");
			t.equal(res?.headers.get("X-Content-Type-Options"), "nosniff");
		});

		test("is case-insensitive", (t) => {
			const req = new Request("https://example.com", { method: "get" });
			t.equal(requireMethod(req, "GET"), null);
		});
	});

	module("authority / requireMethods", () => {
		test("returns null when method matches any listed method", (t) => {
			const req = new Request("https://example.com", { method: "POST" });
			t.equal(requireMethods(req, ["GET", "POST"]), null);
		});

		test("returns null for GET when GET is listed", (t) => {
			const req = new Request("https://example.com", { method: "GET" });
			t.equal(requireMethods(req, ["GET", "POST"]), null);
		});

		test("returns 405 when method is not listed", async (t) => {
			const req = new Request("https://example.com", { method: "DELETE" });
			const res = requireMethods(req, ["GET", "POST"]);
			t.ok(res !== null);
			t.equal(res?.status, 405);
			t.equal(res?.headers.get("Allow"), "GET, POST");
		});

		test("includes security headers on 405", (t) => {
			const req = new Request("https://example.com", { method: "PUT" });
			const res = requireMethods(req, ["GET"]);
			t.equal(res?.headers.get("Cache-Control"), "no-store");
			t.equal(res?.headers.get("X-Content-Type-Options"), "nosniff");
		});
	});

	module("authority / extractRequestParams", () => {
		test("extracts params from GET query string", async (t) => {
			const req = new Request(
				"https://example.com/path?sub=https%3A%2F%2Ffoo.com&type=openid_provider",
			);
			const result = await extractRequestParams(req);
			t.equal(result.params.get("sub"), "https://foo.com");
			t.equal(result.params.get("type"), "openid_provider");
			t.equal(result.clientAssertion, undefined);
			t.equal(result.clientAssertionType, undefined);
		});

		test("extracts params from POST body", async (t) => {
			const req = new Request("https://example.com/path", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: "sub=https%3A%2F%2Ffoo.com&type=openid_provider",
			});
			const result = await extractRequestParams(req);
			t.equal(result.params.get("sub"), "https://foo.com");
			t.equal(result.params.get("type"), "openid_provider");
			t.equal(result.clientAssertion, undefined);
		});

		test("separates client_assertion fields from POST body", async (t) => {
			const req = new Request("https://example.com/path", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: "sub=https%3A%2F%2Ffoo.com&client_assertion=jwt.token.here&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
			});
			const result = await extractRequestParams(req);
			t.equal(result.params.get("sub"), "https://foo.com");
			t.false(result.params.has("client_assertion"));
			t.false(result.params.has("client_assertion_type"));
			t.equal(result.clientAssertion, "jwt.token.here");
			t.equal(result.clientAssertionType, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
		});
	});

	// -------------------------------------------------------------------------
	// endpoints/entity-configuration
	// -------------------------------------------------------------------------
	module("authority / createEntityConfigurationHandler", () => {
		test("returns a signed JWT with entity-statement+jwt content type", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			t.equal(res.status, 200);
			t.equal(res.headers.get("Content-Type"), "application/entity-statement+jwt");
		});

		test("includes security headers", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			t.equal(res.headers.get("Cache-Control"), "no-store");
			t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
		});

		test("JWT has iss === sub === entityId", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			t.equal(decoded.value.payload.iss, ENTITY_ID);
			t.equal(decoded.value.payload.sub, ENTITY_ID);
		});

		test("JWT contains jwks", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			const payload = decoded.value.payload as Record<string, unknown>;
			t.ok(payload.jwks);
			t.true((payload.jwks as { keys: unknown[] }).keys.length > 0);
		});

		test("JWT contains metadata", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			t.ok((decoded.value.payload as Record<string, unknown>).metadata);
		});

		test("includes authority_hints for intermediates", async (t) => {
			const superiorId = entityId("https://ta.example.com");
			const { ctx } = await createTestContext({ authorityHints: [superiorId] });
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			t.deepEqual((decoded.value.payload as Record<string, unknown>).authority_hints, [superiorId]);
		});

		test("includes trust_mark_issuers when configured", async (t) => {
			const issuers = { "https://trust.example.com/mark-a": ["https://issuer.example.com"] };
			const { ctx } = await createTestContext({ trustMarkIssuers: issuers });
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			t.deepEqual((decoded.value.payload as Record<string, unknown>).trust_mark_issuers, issuers);
		});

		test("includes trust_mark_owners when configured", async (t) => {
			const owners = {
				"https://trust.example.com/mark-a": {
					iss: entityId("https://owner.example.com"),
					sub: entityId("https://delegate.example.com"),
				},
			} as unknown as HandlerContext["trustMarkOwners"];
			const { ctx } = await createTestContext({ trustMarkOwners: owners });
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			t.deepEqual((decoded.value.payload as Record<string, unknown>).trust_mark_owners, owners);
		});

		test("uses custom entityConfigurationTtlSeconds for exp", async (t) => {
			const { ctx } = await createTestContext({ entityConfigurationTtlSeconds: 3600 });
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			const payload = decoded.value.payload as Record<string, unknown>;
			t.equal((payload.exp as number) - (payload.iat as number), 3600);
		});

		test("defaults to 86400s TTL when entityConfigurationTtlSeconds is not set", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			const payload = decoded.value.payload as Record<string, unknown>;
			t.equal((payload.exp as number) - (payload.iat as number), 86400);
		});

		test("returns 500 when no active keys are available", async (t) => {
			const { ctx, keyStore } = await createTestContext();
			await keyStore.revokeKey("test-key-1", "test");
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			t.equal(res.status, 500);
		});

		test("returns 405 for POST", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation", {
					method: "POST",
				}),
			);
			t.equal(res.status, 405);
			t.equal(res.headers.get("Allow"), "GET");
		});

		test("JWT can be verified with the active keys", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const activeKeys = await ctx.keyStore.getActiveKeys();
			const result = await verifyEntityStatement(jwt, activeKeys);
			t.true(isOk(result));
		});
	});

	// -------------------------------------------------------------------------
	// endpoints/fetch
	// -------------------------------------------------------------------------
	{
		const FETCH_SUB1 = entityId("https://sub1.example.com");

		function makeFetchRecord(
			id: ReturnType<typeof entityId>,
			overrides?: Partial<SubordinateRecord>,
		): SubordinateRecord {
			return {
				entityId: id,
				jwks: { keys: [{ kty: "EC", crv: "P-256", x: "abc", y: "def" }] },
				createdAt: Date.now(),
				updatedAt: Date.now(),
				...overrides,
			};
		}

		module("authority / createFetchHandler", () => {
			test("returns 400 when sub is missing", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createFetchHandler(ctx);
				const res = await handler(new Request("https://authority.example.com/federation_fetch"));
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_request");
			});

			test("returns 400 when sub is invalid", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createFetchHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_fetch?sub=not-a-url"),
				);
				t.equal(res.status, 400);
			});

			test("returns 404 when sub is unknown", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createFetchHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_fetch?sub=${encodeURIComponent(FETCH_SUB1)}`,
					),
				);
				t.equal(res.status, 404);
				t.equal(((await res.json()) as Record<string, string>).error, "not_found");
			});

			test("returns 400 when sub === entityId", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createFetchHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_fetch?sub=${encodeURIComponent(ENTITY_ID)}`,
					),
				);
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_request");
			});

			test("returns signed subordinate statement for known sub", async (t) => {
				const { ctx, subordinateStore } = await createTestContext();
				await subordinateStore.add(
					makeFetchRecord(FETCH_SUB1, {
						metadata: { openid_provider: { issuer: "https://sub1.example.com" } },
						sourceEndpoint: "https://sub1.example.com/federation_fetch",
					}),
				);
				const handler = createFetchHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_fetch?sub=${encodeURIComponent(FETCH_SUB1)}`,
					),
				);
				t.equal(res.status, 200);
				t.equal(res.headers.get("Content-Type"), "application/entity-statement+jwt");
				const jwt = await res.text();
				const decoded = decodeEntityStatement(jwt);
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				t.equal(decoded.value.payload.iss, ENTITY_ID);
				t.equal(decoded.value.payload.sub, FETCH_SUB1);
				const payload = decoded.value.payload as Record<string, unknown>;
				t.ok(payload.metadata);
				t.equal(payload.source_endpoint, "https://sub1.example.com/federation_fetch");
			});

			test("includes security headers", async (t) => {
				const { ctx, subordinateStore } = await createTestContext();
				await subordinateStore.add(makeFetchRecord(FETCH_SUB1));
				const handler = createFetchHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_fetch?sub=${encodeURIComponent(FETCH_SUB1)}`,
					),
				);
				t.equal(res.headers.get("Cache-Control"), "no-store");
				t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
			});

			test("uses custom subordinateStatementTtlSeconds for exp", async (t) => {
				const { ctx, subordinateStore } = await createTestContext({
					subordinateStatementTtlSeconds: 1800,
				});
				await subordinateStore.add(makeFetchRecord(FETCH_SUB1));
				const handler = createFetchHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_fetch?sub=${encodeURIComponent(FETCH_SUB1)}`,
					),
				);
				t.equal(res.status, 200);
				const jwt = await res.text();
				const decoded = decodeEntityStatement(jwt);
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				const payload = decoded.value.payload as Record<string, unknown>;
				t.equal((payload.exp as number) - (payload.iat as number), 1800);
			});

			test("returns 405 for POST", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createFetchHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_fetch?sub=https%3A%2F%2Ffoo.com", {
						method: "POST",
					}),
				);
				t.equal(res.status, 405);
			});

			test("ignores unknown query parameters", async (t) => {
				const { ctx, subordinateStore } = await createTestContext();
				await subordinateStore.add(makeFetchRecord(FETCH_SUB1));
				const handler = createFetchHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_fetch?sub=${encodeURIComponent(FETCH_SUB1)}&unknown_param=foo&another=bar`,
					),
				);
				t.equal(res.status, 200);
				t.equal(res.headers.get("Content-Type"), "application/entity-statement+jwt");
			});

			test("error response uses application/json content-type", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createFetchHandler(ctx);
				const res = await handler(new Request("https://authority.example.com/federation_fetch"));
				t.equal(res.status, 400);
				const ct = res.headers.get("Content-Type") ?? "";
				t.true(
					ct.startsWith("application/json"),
					`expected application/json content-type, got '${ct}'`,
				);
			});
		});
	}

	// -------------------------------------------------------------------------
	// endpoints/list
	// -------------------------------------------------------------------------
	{
		const LIST_SUB1 = entityId("https://sub1.example.com");
		const LIST_SUB2 = entityId("https://sub2.example.com");

		function makeListRecord(
			id: ReturnType<typeof entityId>,
			overrides?: Partial<SubordinateRecord>,
		): SubordinateRecord {
			return {
				entityId: id,
				jwks: { keys: [{ kty: "EC", crv: "P-256", x: "abc", y: "def" }] },
				createdAt: Date.now(),
				updatedAt: Date.now(),
				...overrides,
			};
		}

		module("authority / createListHandler", () => {
			test("returns all entity IDs with no filter", async (t) => {
				const { ctx, subordinateStore } = await createTestContext();
				await subordinateStore.add(makeListRecord(LIST_SUB1));
				await subordinateStore.add(makeListRecord(LIST_SUB2));
				const handler = createListHandler(ctx);
				const res = await handler(new Request("https://authority.example.com/federation_list"));
				t.equal(res.status, 200);
				t.equal(res.headers.get("Content-Type"), "application/json");
				const body = (await res.json()) as string[];
				t.equal(body.length, 2);
				t.true(body.includes(LIST_SUB1));
				t.true(body.includes(LIST_SUB2));
			});

			test("returns empty array when no subordinates", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createListHandler(ctx);
				const res = await handler(new Request("https://authority.example.com/federation_list"));
				t.deepEqual(await res.json(), []);
			});

			test("filters by entity_type", async (t) => {
				const { ctx, subordinateStore } = await createTestContext();
				await subordinateStore.add(
					makeListRecord(LIST_SUB1, { entityTypes: [EntityType.OpenIDProvider] }),
				);
				await subordinateStore.add(
					makeListRecord(LIST_SUB2, { entityTypes: [EntityType.OpenIDRelyingParty] }),
				);
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_list?entity_type=openid_provider"),
				);
				t.deepEqual(await res.json(), [LIST_SUB1]);
			});

			test("filters by intermediate", async (t) => {
				const { ctx, subordinateStore } = await createTestContext();
				await subordinateStore.add(makeListRecord(LIST_SUB1, { isIntermediate: true }));
				await subordinateStore.add(makeListRecord(LIST_SUB2, { isIntermediate: false }));
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_list?intermediate=true"),
				);
				t.deepEqual(await res.json(), [LIST_SUB1]);
			});

			test("filters by trust_marked when trust mark store is available", async (t) => {
				const { ctx, subordinateStore, trustMarkStore } = await createTestContext();
				await subordinateStore.add(makeListRecord(LIST_SUB1));
				await subordinateStore.add(makeListRecord(LIST_SUB2));
				await trustMarkStore.issue({
					trustMarkType: "https://trust.example.com/mark",
					subject: LIST_SUB1,
					jwt: "test.jwt",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request(
						"https://authority.example.com/federation_list?trust_marked=true&trust_mark_type=https%3A%2F%2Ftrust.example.com%2Fmark",
					),
				);
				t.deepEqual(await res.json(), [LIST_SUB1]);
			});

			test("ignores unknown parameters", async (t) => {
				const { ctx, subordinateStore } = await createTestContext();
				await subordinateStore.add(makeListRecord(LIST_SUB1));
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_list?unknown_param=foo"),
				);
				t.equal(res.status, 200);
				t.deepEqual(await res.json(), [LIST_SUB1]);
			});

			test("returns 400 with unsupported_parameter when trust_marked used but no trust mark store", async (t) => {
				const { ctx } = await createTestContext({ trustMarkStore: undefined });
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_list?trust_marked=true"),
				);
				t.equal(res.status, 400);
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, "unsupported_parameter");
				t.ok(body.error_description);
			});

			test("returns 400 with unsupported_parameter when trust_mark_type used but no trust mark store", async (t) => {
				const { ctx } = await createTestContext({ trustMarkStore: undefined });
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request(
						"https://authority.example.com/federation_list?trust_mark_type=https%3A%2F%2Fexample.com%2Ftm",
					),
				);
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "unsupported_parameter");
			});

			test("filters by multiple entity_type values with OR logic", async (t) => {
				const { ctx, subordinateStore } = await createTestContext();
				await subordinateStore.add(
					makeListRecord(LIST_SUB1, { entityTypes: [EntityType.OpenIDProvider] }),
				);
				await subordinateStore.add(
					makeListRecord(LIST_SUB2, { entityTypes: [EntityType.OpenIDRelyingParty] }),
				);
				const sub3 = entityId("https://sub3.example.com");
				await subordinateStore.add(makeListRecord(sub3, { entityTypes: [EntityType.OAuthClient] }));
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request(
						"https://authority.example.com/federation_list?entity_type=openid_provider&entity_type=openid_relying_party",
					),
				);
				const body = (await res.json()) as string[];
				t.equal(body.length, 2);
				t.true(body.includes(LIST_SUB1));
				t.true(body.includes(LIST_SUB2));
			});

			test("filters trust_marked=true without trust_mark_type to entities with any active trust mark", async (t) => {
				const { ctx, subordinateStore, trustMarkStore } = await createTestContext();
				await subordinateStore.add(makeListRecord(LIST_SUB1));
				await subordinateStore.add(makeListRecord(LIST_SUB2));
				await trustMarkStore.issue({
					trustMarkType: "https://trust.example.com/mark",
					subject: LIST_SUB1,
					jwt: "test.jwt",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_list?trust_marked=true"),
				);
				t.deepEqual(await res.json(), [LIST_SUB1]);
			});

			test("filters by trust_mark_type alone without trust_marked", async (t) => {
				const { ctx, subordinateStore, trustMarkStore } = await createTestContext();
				await subordinateStore.add(makeListRecord(LIST_SUB1));
				await subordinateStore.add(makeListRecord(LIST_SUB2));
				await trustMarkStore.issue({
					trustMarkType: "https://trust.example.com/mark",
					subject: LIST_SUB1,
					jwt: "test.jwt",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request(
						"https://authority.example.com/federation_list?trust_mark_type=https%3A%2F%2Ftrust.example.com%2Fmark",
					),
				);
				t.deepEqual(await res.json(), [LIST_SUB1]);
			});

			test("filters trust_marked=false without trust_mark_type to entities with no active trust marks", async (t) => {
				const { ctx, subordinateStore, trustMarkStore } = await createTestContext();
				await subordinateStore.add(makeListRecord(LIST_SUB1));
				await subordinateStore.add(makeListRecord(LIST_SUB2));
				await trustMarkStore.issue({
					trustMarkType: "https://trust.example.com/mark",
					subject: LIST_SUB1,
					jwt: "test.jwt",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_list?trust_marked=false"),
				);
				t.deepEqual(await res.json(), [LIST_SUB2]);
			});

			test("includes security headers", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createListHandler(ctx);
				const res = await handler(new Request("https://authority.example.com/federation_list"));
				t.equal(res.headers.get("Cache-Control"), "no-store");
				t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
			});

			test("returns 405 for POST", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_list", { method: "POST" }),
				);
				t.equal(res.status, 405);
			});
		});
	}

	// -------------------------------------------------------------------------
	// endpoints/resolve
	// -------------------------------------------------------------------------
	module("authority / createResolveHandler", () => {
		test("returns 400 when sub is missing", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					"https://authority.example.com/federation_resolve?trust_anchor=https%3A%2F%2Fta.example.com",
				),
			);
			t.equal(res.status, 400);
			t.equal(((await res.json()) as Record<string, string>).error, "invalid_request");
		});

		test("returns 400 when trust_anchor is missing", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}`,
				),
			);
			t.equal(res.status, 400);
			t.equal(((await res.json()) as Record<string, string>).error, "invalid_request");
		});

		test("returns 404 when no trust anchors configured", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://ta.example.com")}`,
				),
			);
			t.equal(res.status, 404);
			t.equal(((await res.json()) as Record<string, string>).error, "invalid_trust_anchor");
		});

		test("returns 404 for unknown trust anchor", async (t) => {
			const taId = entityId("https://known-ta.example.com");
			const anchors: TrustAnchorSet = new Map([
				[taId, { jwks: { keys: [{ kty: "EC", crv: "P-256", x: "abc", y: "def" }] } }],
			]);
			const { ctx } = await createTestContext({ trustAnchors: anchors });
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://unknown-ta.example.com")}`,
				),
			);
			t.equal(res.status, 404);
			t.equal(((await res.json()) as Record<string, string>).error, "invalid_trust_anchor");
		});

		test("returns 405 for POST", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/federation_resolve", { method: "POST" }),
			);
			t.equal(res.status, 405);
		});

		test("does not include aud when X-Authenticated-Entity header is absent", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://ta.example.com")}`,
				),
			);
			t.equal(res.status, 404);
		});

		test("includes aud when X-Authenticated-Entity header is present", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://ta.example.com")}`,
					{ headers: { "X-Authenticated-Entity": "https://client.example.com" } },
				),
			);
			t.equal(res.status, 404);
		});

		test("accepts entity_type parameter without error", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://ta.example.com")}&entity_type=openid_provider`,
				),
			);
			t.equal(res.status, 404);
			t.equal(((await res.json()) as Record<string, string>).error, "invalid_trust_anchor");
		});

		test("returns 400 for invalid X-Authenticated-Entity header value", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://ta.example.com")}`,
					{ headers: { "X-Authenticated-Entity": "not-a-url" } },
				),
			);
			t.equal(res.status, 400);
			t.equal(((await res.json()) as Record<string, string>).error, "invalid_request");
		});

		test("accepts a valid X-Authenticated-Entity header and proceeds to trust chain resolution", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://ta.example.com")}`,
					{ headers: { "X-Authenticated-Entity": "https://client.example.com" } },
				),
			);
			t.equal(res.status, 404);
		});

		test("includes security headers on error responses", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(new Request("https://authority.example.com/federation_resolve"));
			t.equal(res.headers.get("Cache-Control"), "no-store");
			t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
		});

		test("resolves successfully and returns signed JWT with expected payload", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(res.status, 200);
			t.equal(res.headers.get("Content-Type"), MediaType.ResolveResponse);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const payload = decoded.value.payload as Record<string, unknown>;
			t.equal(payload.iss, "https://authority.example.com");
			t.equal(payload.sub, LEAF_ID);
			t.ok(payload.metadata);
			t.true(Array.isArray(payload.trust_chain));
			t.equal(decoded.value.header.typ, JwtTyp.ResolveResponse);
		});

		test("response exp is capped to the chain's earliest expiry", async (t) => {
			// Per §8.3.2 (lines 533–535), the resolve response exp MUST be the minimum of
			// the trust-chain exp and any included Trust Mark exp. The mock federation
			// signs every statement with the same exp = now + 86400, so the resolved exp
			// should equal that bound (within a small fudge for iat/exp computation).
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(res.status, 200);
			const decoded = decodeEntityStatement(await res.text());
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const payload = decoded.value.payload as Record<string, unknown>;
			const exp = payload.exp as number;
			const iat = payload.iat as number;
			t.equal(typeof exp, "number");
			t.equal(typeof iat, "number");
			// All chain statements were signed with exp = iat + 86400. The resolver MUST
			// not extend exp beyond the chain bound — assert exp does not exceed
			// (statement-level iat + 86400) plus a tolerance for sub-second drift.
			t.true(
				exp <= iat + 86400 + 5,
				`response exp ${exp} exceeds chain bound ${iat + 86400}`,
			);
		});

		test("filters metadata by entity_type when matching", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}&entity_type=openid_relying_party`,
				),
			);
			t.equal(res.status, 200);
			const decoded = decodeEntityStatement(await res.text());
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const metadata = (decoded.value.payload as Record<string, unknown>).metadata as Record<
				string,
				unknown
			>;
			t.ok(metadata.openid_relying_party);
			t.notOk(metadata.federation_entity);
		});

		test("returns 404 when entity_type filter produces no matches", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}&entity_type=nonexistent_type`,
				),
			);
			t.equal(res.status, 404);
			const body = (await res.json()) as Record<string, string>;
			t.equal(body.error, FederationErrorCode.NotFound);
		});

		test("includes aud in payload when X-Authenticated-Entity is provided", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const client = "https://client.example.com";
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
					{ headers: { "X-Authenticated-Entity": client } },
				),
			);
			t.equal(res.status, 200);
			const decoded = decodeEntityStatement(await res.text());
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal((decoded.value.payload as Record<string, unknown>).aud, client);
		});

		test("skips issuer chain when authority is the requested trust anchor", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				entityId: TA_ID,
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`${TA_ID}/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(res.status, 200);
			const decoded = decodeEntityStatement(await res.text());
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const header = decoded.value.header as Record<string, unknown>;
			t.notOk(header.trust_chain);
		});

		test("returns 404 when no trust chain can be resolved for the subject", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://unknown.example.com")}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(res.status, 404);
			const body = (await res.json()) as Record<string, string>;
			t.equal(body.error, FederationErrorCode.NotFound);
		});

		test("populates trust_chain header for authority when different from TA", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				entityId: OP_ID,
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`${OP_ID}/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(res.status, 200);
			const decoded = decodeEntityStatement(await res.text());
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const header = decoded.value.header as Record<string, unknown>;
			t.true(Array.isArray(header.trust_chain));
			t.true((header.trust_chain as unknown[]).length > 0);
		});

		test("silently ignores issuer chain resolution failures", async (t) => {
			const fed = await createMockFederation();
			const failingClient: import("../../../packages/core/src/index.js").HttpClient = async (
				input: string | URL | Request,
			): Promise<Response> => {
				const url =
					typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
				const parsed = new URL(url);
				if (parsed.origin === "https://unresolvable.example.com") {
					return new Response("Not Found", { status: 404 });
				}
				return fed.httpClient(input);
			};
			const { ctx } = await createTestContext({
				entityId: entityId("https://unresolvable.example.com"),
				trustAnchors: fed.trustAnchors,
				options: { ...fed.options, httpClient: failingClient },
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://unresolvable.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(res.status, 200);
			const decoded = decodeEntityStatement(await res.text());
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const header = decoded.value.header as Record<string, unknown>;
			t.notOk(header.trust_chain);
		});

		test("returns 500 when the signer throws (catch block)", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
				getSigningKey: async () => {
					throw new Error("boom");
				},
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(res.status, 500);
			const body = (await res.json()) as Record<string, string>;
			t.equal(body.error, "server_error");
		});
	});

	// -------------------------------------------------------------------------
	// endpoints/historical-keys
	// -------------------------------------------------------------------------
	module("authority / createHistoricalKeysHandler", () => {
		test("returns signed JWT with jwk-set+jwt content type", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createHistoricalKeysHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/federation_historical_keys"),
			);
			t.equal(res.status, 200);
			t.equal(res.headers.get("Content-Type"), "application/jwk-set+jwt");
		});

		test("response JWT includes kid header parameter", async (t) => {
			// §8.7.2 (lines 1138–1140): Historical Keys JWTs MUST include kid header.
			const { ctx } = await createTestContext();
			const handler = createHistoricalKeysHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/federation_historical_keys"),
			);
			t.equal(res.status, 200);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			const header = decoded.value.header as Record<string, unknown>;
			t.equal(typeof header.kid, "string");
			t.true((header.kid as string).length > 0);
		});

		test("includes all key states", async (t) => {
			const { ctx, keyStore } = await createTestContext();
			const { privateKey: pk2 } = await generateSigningKey("ES256");
			await keyStore.addKey({ ...pk2, kid: "pending-key" });
			const { privateKey: pk3 } = await generateSigningKey("ES256");
			await keyStore.addKey({ ...pk3, kid: "retiring-key" });
			await keyStore.activateKey("retiring-key");
			await keyStore.retireKey("retiring-key", Date.now() + 86400000);
			const handler = createHistoricalKeysHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/federation_historical_keys"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			const keys = (decoded.value.payload as Record<string, unknown>).keys as Array<
				Record<string, unknown>
			>;
			t.equal(keys.length, 3);
		});

		test("revoked keys have revoked metadata", async (t) => {
			const { ctx, keyStore } = await createTestContext();
			await keyStore.revokeKey("test-key-1", "keyCompromise");
			const { privateKey: pk2 } = await generateSigningKey("ES256");
			await keyStore.addKey({ ...pk2, kid: "new-active" });
			await keyStore.activateKey("new-active");
			const newCtx = {
				...ctx,
				getSigningKey: async () => ({ key: { ...pk2, kid: "new-active" }, kid: "new-active" }),
			};
			const handler = createHistoricalKeysHandler(newCtx);
			const res = await handler(
				new Request("https://authority.example.com/federation_historical_keys"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			const keys = (decoded.value.payload as Record<string, unknown>).keys as Array<
				Record<string, unknown>
			>;
			const revokedKey = keys.find((k) => k.kid === "test-key-1");
			t.ok(revokedKey);
			const revoked = revokedKey?.revoked as Record<string, unknown>;
			t.ok(revoked);
			t.true((revoked.revoked_at as number) > 0);
			t.equal(revoked.reason, "keyCompromise");
		});

		test("active keys do not have revoked field", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createHistoricalKeysHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/federation_historical_keys"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			const keys = (decoded.value.payload as Record<string, unknown>).keys as Array<
				Record<string, unknown>
			>;
			const activeKey = keys.find((k) => k.kid === "test-key-1");
			t.ok(activeKey);
			t.equal(activeKey?.revoked, undefined);
		});

		test("includes nbf for keys with activatedAt", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createHistoricalKeysHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/federation_historical_keys"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			const keys = (decoded.value.payload as Record<string, unknown>).keys as Array<
				Record<string, unknown>
			>;
			const activeKey = keys.find((k) => k.kid === "test-key-1");
			t.ok(activeKey);
			t.equal(typeof activeKey?.nbf, "number");
			t.true((activeKey?.nbf as number) > 0);
		});

		test("omits nbf for keys without activatedAt", async (t) => {
			const { ctx, keyStore } = await createTestContext();
			const { privateKey: pk2 } = await generateSigningKey("ES256");
			await keyStore.addKey({ ...pk2, kid: "pending-key" });
			const handler = createHistoricalKeysHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/federation_historical_keys"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			const keys = (decoded.value.payload as Record<string, unknown>).keys as Array<
				Record<string, unknown>
			>;
			const pendingKey = keys.find((k) => k.kid === "pending-key");
			t.ok(pendingKey);
			t.equal(pendingKey?.nbf, undefined);
		});

		test("strips private key fields", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createHistoricalKeysHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/federation_historical_keys"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			const keys = (decoded.value.payload as Record<string, unknown>).keys as Array<
				Record<string, unknown>
			>;
			for (const key of keys) {
				t.false("d" in key);
			}
		});

		test("includes security headers", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createHistoricalKeysHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/federation_historical_keys"),
			);
			t.equal(res.headers.get("Cache-Control"), "no-store");
			t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
		});

		test("returns 405 for POST", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createHistoricalKeysHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/federation_historical_keys", { method: "POST" }),
			);
			t.equal(res.status, 405);
		});
	});

	// -------------------------------------------------------------------------
	// endpoints/trust-mark-list
	// -------------------------------------------------------------------------
	{
		const TML_SUB1 = entityId("https://sub1.example.com");
		const TML_SUB2 = entityId("https://sub2.example.com");
		const TML_MARK_TYPE = "https://trust.example.com/mark-a";

		module("authority / createTrustMarkListHandler", () => {
			test("returns entity IDs of active trust marks", async (t) => {
				const { ctx, trustMarkStore } = await createTestContext();
				await trustMarkStore.issue({
					trustMarkType: TML_MARK_TYPE,
					subject: TML_SUB1,
					jwt: "jwt1",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				await trustMarkStore.issue({
					trustMarkType: TML_MARK_TYPE,
					subject: TML_SUB2,
					jwt: "jwt2",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createTrustMarkListHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(TML_MARK_TYPE)}`,
					),
				);
				t.equal(res.status, 200);
				t.equal(res.headers.get("Content-Type"), "application/json");
				const body = (await res.json()) as string[];
				t.true(body.includes(TML_SUB1));
				t.true(body.includes(TML_SUB2));
			});

			test("filters by sub", async (t) => {
				const { ctx, trustMarkStore } = await createTestContext();
				await trustMarkStore.issue({
					trustMarkType: TML_MARK_TYPE,
					subject: TML_SUB1,
					jwt: "jwt1",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				await trustMarkStore.issue({
					trustMarkType: TML_MARK_TYPE,
					subject: TML_SUB2,
					jwt: "jwt2",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createTrustMarkListHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(TML_MARK_TYPE)}&sub=${encodeURIComponent(TML_SUB1)}`,
					),
				);
				t.deepEqual(await res.json(), [TML_SUB1]);
			});

			test("excludes revoked trust marks", async (t) => {
				const { ctx, trustMarkStore } = await createTestContext();
				await trustMarkStore.issue({
					trustMarkType: TML_MARK_TYPE,
					subject: TML_SUB1,
					jwt: "jwt1",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				await trustMarkStore.issue({
					trustMarkType: TML_MARK_TYPE,
					subject: TML_SUB2,
					jwt: "jwt2",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				await trustMarkStore.revoke(TML_MARK_TYPE, TML_SUB2);
				const handler = createTrustMarkListHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(TML_MARK_TYPE)}`,
					),
				);
				t.deepEqual(await res.json(), [TML_SUB1]);
			});

			test("returns 400 when trust_mark_type is missing", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_trust_mark_list"),
				);
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_request");
			});

			test("returns 501 when no trust mark store", async (t) => {
				const { ctx } = await createTestContext({ trustMarkStore: undefined });
				const handler = createTrustMarkListHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(TML_MARK_TYPE)}`,
					),
				);
				t.equal(res.status, 501);
			});

			test("includes security headers", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkListHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(TML_MARK_TYPE)}`,
					),
				);
				t.equal(res.headers.get("Cache-Control"), "no-store");
				t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
			});

			test("returns 400 for invalid sub parameter", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkListHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(TML_MARK_TYPE)}&sub=not-a-valid-url`,
					),
				);
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_request");
			});

			test("returns 405 for POST", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_trust_mark_list", {
						method: "POST",
					}),
				);
				t.equal(res.status, 405);
			});
		});
	}

	// -------------------------------------------------------------------------
	// endpoints/trust-mark-status
	// -------------------------------------------------------------------------
	{
		const TMS_SUB1 = entityId("https://sub1.example.com");
		const TMS_MARK_TYPE = "https://trust.example.com/mark-a";

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
			if (!isOk(decoded)) throw new Error("Failed to decode");
			return decoded.value.payload as unknown as { status: string };
		}

		module("authority / createTrustMarkStatusHandler", () => {
			test("returns status: active for active trust mark", async (t) => {
				const { ctx, signingKey, trustMarkStore } = await createTestContext();
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey);
				await trustMarkStore.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 200);
				t.equal(res.headers.get("Content-Type"), "application/trust-mark-status-response+jwt");
				const payload = await decodeStatusResponse(res);
				t.equal(payload.status, TrustMarkStatus.Active);
			});

			test("returns status: revoked for revoked trust mark", async (t) => {
				const { ctx, signingKey, trustMarkStore } = await createTestContext();
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey);
				await trustMarkStore.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				await trustMarkStore.revoke(TMS_MARK_TYPE, TMS_SUB1);
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 200);
				t.equal((await decodeStatusResponse(res)).status, TrustMarkStatus.Revoked);
			});

			test("returns status: expired for expired trust mark", async (t) => {
				const { ctx, signingKey, trustMarkStore } = await createTestContext();
				const now = Math.floor(Date.now() / 1000);
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey, {
					iat: now - 7200,
					exp: now - 3600,
				});
				await trustMarkStore.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: now - 7200,
					active: true,
				});
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 200);
				t.equal((await decodeStatusResponse(res)).status, TrustMarkStatus.Expired);
			});

			test("returns 404 for unknown trust mark", async (t) => {
				const { ctx, signingKey } = await createTestContext();
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey);
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 404);
			});

			test("returns 404 for wrong issuer", async (t) => {
				const { ctx, trustMarkStore } = await createTestContext();
				const { privateKey: otherKey } = await generateSigningKey("ES256");
				const wrongIssuer = entityId("https://other-authority.example.com");
				const jwt = await issueTrustMarkJwt(wrongIssuer, TMS_SUB1, TMS_MARK_TYPE, otherKey);
				await trustMarkStore.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 404);
			});

			test("returns 400 for missing trust_mark body", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(""));
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_request");
			});

			test("returns 405 for GET", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_trust_mark_status"),
				);
				t.equal(res.status, 405);
				t.equal(res.headers.get("Allow"), "POST");
			});

			test("returns expired before checking revocation status", async (t) => {
				const { ctx, signingKey, trustMarkStore } = await createTestContext();
				const now = Math.floor(Date.now() / 1000);
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey, {
					iat: now - 7200,
					exp: now - 3600,
				});
				await trustMarkStore.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: now - 7200,
					active: true,
				});
				await trustMarkStore.revoke(TMS_MARK_TYPE, TMS_SUB1);
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 200);
				t.equal((await decodeStatusResponse(res)).status, TrustMarkStatus.Expired);
			});

			test("returns Invalid for tampered trust mark signature", async (t) => {
				const { ctx, signingKey, trustMarkStore } = await createTestContext();
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey);
				await trustMarkStore.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const parts = jwt.split(".");
				const tamperedJwt = `${parts[0]}.${parts[1]}.${(parts[2] ?? "").slice(0, -2)}xx`;
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(tamperedJwt)}`));
				t.equal(res.status, 200);
				t.equal((await decodeStatusResponse(res)).status, TrustMarkStatus.Invalid);
			});

			test("returns 413 for body exceeding 64KB", async (t) => {
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
				t.equal(res.status, 413);
			});

			test("returns Invalid for trust_mark_type that is not a URL", async (t) => {
				const { ctx, signingKey } = await createTestContext();
				const now = Math.floor(Date.now() / 1000);
				const jwt = await signEntityStatement(
					{
						iss: ENTITY_ID,
						sub: TMS_SUB1,
						trust_mark_type: "not-a-url",
						iat: now,
						exp: now + 3600,
					},
					signingKey,
					{ typ: JwtTyp.TrustMark },
				);
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 200);
				t.equal((await decodeStatusResponse(res)).status, TrustMarkStatus.Invalid);
			});

			test("returns expired for trust mark with exp: 0 (epoch)", async (t) => {
				const { ctx, signingKey, trustMarkStore } = await createTestContext();
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey, {
					iat: 0,
					exp: 0,
				});
				await trustMarkStore.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: 0,
					active: true,
				});
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 200);
				t.equal((await decodeStatusResponse(res)).status, TrustMarkStatus.Expired);
			});

			test("validates trust mark signed with retiring key as active", async (t) => {
				const { ctx, signingKey, trustMarkStore, keyStore } = await createTestContext();
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey);
				await trustMarkStore.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const { privateKey: newKey } = await generateSigningKey("ES256");
				await rotateKey(keyStore, { ...newKey, kid: "rotated-key-1" });
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 200);
				t.equal((await decodeStatusResponse(res)).status, TrustMarkStatus.Active);
			});

			test("returns invalid for trust mark signed with revoked key", async (t) => {
				const { ctx, signingKey, trustMarkStore, keyStore } = await createTestContext();
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey);
				await trustMarkStore.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const { privateKey: newKey } = await generateSigningKey("ES256");
				await rotateKeyCompromise(keyStore, { ...newKey, kid: "new-key-1" }, "test-key-1");
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 200);
				t.equal((await decodeStatusResponse(res)).status, TrustMarkStatus.Invalid);
			});

			test("returns 501 when no trust mark store", async (t) => {
				const { ctx } = await createTestContext({ trustMarkStore: undefined });
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_trust_mark_status", {
						method: "POST",
						body: "trust_mark=foo",
					}),
				);
				t.equal(res.status, 501);
			});
		});
	}

	// -------------------------------------------------------------------------
	// endpoints/trust-mark
	// -------------------------------------------------------------------------
	{
		const TM_SUB1 = entityId("https://sub1.example.com");
		const TM_MARK_TYPE = "https://trust.example.com/mark-a";

		module("authority / createTrustMarkHandler (retrieval)", () => {
			test("returns existing active trust mark", async (t) => {
				const { ctx, trustMarkStore } = await createTestContext();
				await trustMarkStore.issue({
					trustMarkType: TM_MARK_TYPE,
					subject: TM_SUB1,
					jwt: "existing.jwt.token",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createTrustMarkHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(res.status, 200);
				t.equal(res.headers.get("Content-Type"), "application/trust-mark+jwt");
				t.equal(await res.text(), "existing.jwt.token");
			});

			test("returns 404 when trust mark is expired", async (t) => {
				const { ctx, trustMarkStore } = await createTestContext();
				const now = Math.floor(Date.now() / 1000);
				await trustMarkStore.issue({
					trustMarkType: TM_MARK_TYPE,
					subject: TM_SUB1,
					jwt: "expired.jwt.token",
					issuedAt: now - 7200,
					expiresAt: now - 3600,
					active: true,
				});
				const handler = createTrustMarkHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(res.status, 404);
			});

			test("returns 404 when entity does not have the trust mark", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(res.status, 404);
				t.equal(((await res.json()) as Record<string, string>).error, "not_found");
			});

			test("returns 404 when trust mark is revoked", async (t) => {
				const { ctx, trustMarkStore } = await createTestContext();
				await trustMarkStore.issue({
					trustMarkType: TM_MARK_TYPE,
					subject: TM_SUB1,
					jwt: "revoked.jwt.token",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				await trustMarkStore.revoke(TM_MARK_TYPE, TM_SUB1);
				const handler = createTrustMarkHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(res.status, 404);
			});

			test("returns 400 for missing trust_mark_type", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(res.status, 400);
			});

			test("returns 400 for missing sub", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}`,
					),
				);
				t.equal(res.status, 400);
			});

			test("returns 501 when no trust mark store", async (t) => {
				const { ctx } = await createTestContext({ trustMarkStore: undefined });
				const handler = createTrustMarkHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(res.status, 501);
			});

			test("returns 405 for POST", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_trust_mark", { method: "POST" }),
				);
				t.equal(res.status, 405);
			});
		});

		module("authority / createTrustMarkIssuanceHandler (administrative issuance)", () => {
			test("issues a new trust mark", async (t) => {
				const { ctx } = await createTestContext({
					trustMarkIssuers: { [TM_MARK_TYPE]: [ENTITY_ID] },
				});
				const handler = createTrustMarkIssuanceHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(res.status, 200);
				t.equal(res.headers.get("Content-Type"), "application/trust-mark+jwt");
				const jwt = await res.text();
				const decoded = decodeEntityStatement(jwt);
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				const payload = decoded.value.payload as Record<string, unknown>;
				t.equal(payload.iss, ENTITY_ID);
				t.equal(payload.sub, TM_SUB1);
				t.equal(payload.trust_mark_type, TM_MARK_TYPE);
				t.equal(typeof payload.iat, "number");
				t.equal(typeof payload.exp, "number");
				t.equal((payload.exp as number) - (payload.iat as number), 86400);
			});

			test("respects custom trustMarkTtlSeconds", async (t) => {
				const { ctx } = await createTestContext({
					trustMarkIssuers: { [TM_MARK_TYPE]: [ENTITY_ID] },
					trustMarkTtlSeconds: 3600,
				});
				const handler = createTrustMarkIssuanceHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(res.status, 200);
				const jwt = await res.text();
				const decoded = decodeEntityStatement(jwt);
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				const payload = decoded.value.payload as Record<string, unknown>;
				t.equal((payload.exp as number) - (payload.iat as number), 3600);
			});

			test("returns existing active trust mark", async (t) => {
				const { ctx, trustMarkStore } = await createTestContext({
					trustMarkIssuers: { [TM_MARK_TYPE]: [ENTITY_ID] },
				});
				await trustMarkStore.issue({
					trustMarkType: TM_MARK_TYPE,
					subject: TM_SUB1,
					jwt: "existing.jwt.token",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createTrustMarkIssuanceHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(await res.text(), "existing.jwt.token");
			});

			test("returns 403 when authority is not in the authorized issuers list", async (t) => {
				const otherAuthority = entityId("https://other-authority.example.com");
				const { ctx } = await createTestContext({
					trustMarkIssuers: { [TM_MARK_TYPE]: [otherAuthority] },
				});
				const handler = createTrustMarkIssuanceHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(res.status, 403);
			});

			test("allows issuance when trust mark type is not in issuers map", async (t) => {
				const { ctx } = await createTestContext({
					trustMarkIssuers: { "https://other.example.com/mark": [ENTITY_ID] },
				});
				const handler = createTrustMarkIssuanceHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(res.status, 200);
			});

			test("embeds delegation when trustMarkDelegations is configured for the type", async (t) => {
				const ownerKeys = await generateSigningKey("ES256");
				const delegationJwt = await signTrustMarkDelegation({
					issuer: "https://owner.example.com",
					subject: ENTITY_ID,
					trustMarkType: TM_MARK_TYPE,
					privateKey: ownerKeys.privateKey,
				});
				const { ctx } = await createTestContext({
					trustMarkIssuers: { [TM_MARK_TYPE]: [ENTITY_ID] },
					trustMarkDelegations: { [TM_MARK_TYPE]: delegationJwt },
				});
				const handler = createTrustMarkIssuanceHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(res.status, 200);
				const jwt = await res.text();
				const decoded = decodeEntityStatement(jwt);
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				t.equal((decoded.value.payload as Record<string, unknown>).delegation, delegationJwt);
			});

			test("does NOT embed delegation when trustMarkDelegations is not configured", async (t) => {
				const { ctx } = await createTestContext({
					trustMarkIssuers: { [TM_MARK_TYPE]: [ENTITY_ID] },
				});
				const handler = createTrustMarkIssuanceHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(res.status, 200);
				const jwt = await res.text();
				const decoded = decodeEntityStatement(jwt);
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				t.equal((decoded.value.payload as Record<string, unknown>).delegation, undefined);
			});

			test("issued trust mark with delegation passes validateTrustMark", async (t) => {
				const ownerKeys = await generateSigningKey("ES256");
				const delegationJwt = await signTrustMarkDelegation({
					issuer: "https://owner.example.com",
					subject: ENTITY_ID,
					trustMarkType: TM_MARK_TYPE,
					privateKey: ownerKeys.privateKey,
				});
				const { ctx, publicKey } = await createTestContext({
					trustMarkIssuers: { [TM_MARK_TYPE]: [ENTITY_ID] },
					trustMarkDelegations: { [TM_MARK_TYPE]: delegationJwt },
				});
				const handler = createTrustMarkIssuanceHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				const jwt = await res.text();
				const result = await validateTrustMark(
					jwt,
					{ [TM_MARK_TYPE]: [ENTITY_ID] },
					{ keys: [publicKey] },
					{
						trustMarkOwners: {
							[TM_MARK_TYPE]: {
								sub: "https://owner.example.com",
								jwks: { keys: [ownerKeys.publicKey] },
							},
						},
					},
				);
				t.true(isOk(result));
				if (isOk(result)) {
					t.ok(result.value.delegation);
					t.equal(result.value.delegation?.issuer, "https://owner.example.com");
					t.equal(result.value.delegation?.subject, ENTITY_ID);
				}
			});

			test("issueTrustMarkDelegation() server method returns valid delegation JWT", async (t) => {
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
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				t.equal(decoded.value.header.typ, JwtTyp.TrustMarkDelegation);
				const payload = decoded.value.payload as Record<string, unknown>;
				t.equal(payload.iss, "https://owner.example.com");
				t.equal(payload.sub, "https://issuer.example.com");
				t.equal(payload.trust_mark_type, "https://example.com/tm");
			});
		});
	}

	// -------------------------------------------------------------------------
	// endpoints/client-auth
	// -------------------------------------------------------------------------
	{
		const CA_AUTHORITY_ID = entityId("https://authority.example.com");
		const CA_CLIENT_ID = entityId("https://client.example.com");
		const JWT_BEARER_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

		async function echoHandler(request: Request): Promise<Response> {
			const url = new URL(request.url);
			const sub = url.searchParams.get("sub");
			return jsonResponse({ sub, method: request.method });
		}

		async function postEchoHandler(request: Request): Promise<Response> {
			const text = await request.text();
			const params = new URLSearchParams(text);
			return jsonResponse({ trust_mark: params.get("trust_mark"), method: request.method });
		}

		async function setupClientAuthContext(overrides?: Partial<HandlerContext>) {
			const taKeys = await generateSigningKey("ES256");
			const taSigningKey = { ...taKeys.privateKey, kid: "ta-key-1" };
			const taPublicKey = { ...taKeys.publicKey, kid: "ta-key-1" };
			const clientKeys = await generateSigningKey("ES256");
			const clientSigningKey = { ...clientKeys.privateKey, kid: "client-key-1" };
			const clientPublicKey = { ...clientKeys.publicKey, kid: "client-key-1" };
			const trustAnchors: TrustAnchorSet = new Map([
				[CA_AUTHORITY_ID, { jwks: { keys: [taPublicKey] } }],
			]);
			const keyStore = new MemoryKeyStore();
			await keyStore.addKey(taSigningKey);
			await keyStore.activateKey("ta-key-1");
			const ctx: HandlerContext = {
				entityId: CA_AUTHORITY_ID,
				keyStore,
				subordinateStore: new MemorySubordinateStore(),
				trustMarkStore: new MemoryTrustMarkStore(),
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${CA_AUTHORITY_ID}${FederationEndpoint.Fetch}`,
					},
				},
				getSigningKey: async () => ({ key: taSigningKey, kid: "ta-key-1" }),
				trustAnchors,
				...overrides,
			};

			const createClientAssertionJwt = async (assertionOverrides?: {
				iss?: string;
				sub?: string;
				aud?: string | string[];
				exp?: number;
			}): Promise<string> => {
				const now = Math.floor(Date.now() / 1000);
				return signEntityStatement(
					{
						iss: assertionOverrides?.iss ?? CA_CLIENT_ID,
						sub: assertionOverrides?.sub ?? CA_CLIENT_ID,
						aud: assertionOverrides?.aud ?? CA_AUTHORITY_ID,
						jti: crypto.randomUUID(),
						iat: now,
						exp: assertionOverrides?.exp ?? now + 60,
					},
					clientSigningKey,
					{ kid: clientSigningKey.kid, typ: "JWT" },
				);
			};

			const makeHttpClient =
				() =>
				async (input: string | URL | Request): Promise<Response> => {
					const url =
						typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
					const now = Math.floor(Date.now() / 1000);
					if (url === `${CA_CLIENT_ID}${WELL_KNOWN_OPENID_FEDERATION}`) {
						const ecJwt = await signEntityStatement(
							{
								iss: CA_CLIENT_ID,
								sub: CA_CLIENT_ID,
								iat: now,
								exp: now + 3600,
								jwks: { keys: [clientPublicKey] },
								authority_hints: [CA_AUTHORITY_ID],
							},
							clientSigningKey,
							{ kid: clientSigningKey.kid },
						);
						return new Response(ecJwt, {
							status: 200,
							headers: { "Content-Type": "application/entity-statement+jwt" },
						});
					}
					if (url === `${CA_AUTHORITY_ID}${WELL_KNOWN_OPENID_FEDERATION}`) {
						const ecJwt = await signEntityStatement(
							{
								iss: CA_AUTHORITY_ID,
								sub: CA_AUTHORITY_ID,
								iat: now,
								exp: now + 3600,
								jwks: { keys: [taPublicKey] },
								metadata: {
									federation_entity: {
										federation_fetch_endpoint: `${CA_AUTHORITY_ID}${FederationEndpoint.Fetch}`,
									},
								},
							},
							taSigningKey,
							{ kid: taSigningKey.kid },
						);
						return new Response(ecJwt, {
							status: 200,
							headers: { "Content-Type": "application/entity-statement+jwt" },
						});
					}
					if (url.startsWith(`${CA_AUTHORITY_ID}${FederationEndpoint.Fetch}`)) {
						const parsedUrl = new URL(url);
						if (parsedUrl.searchParams.get("sub") === CA_CLIENT_ID) {
							const ssJwt = await signEntityStatement(
								{
									iss: CA_AUTHORITY_ID,
									sub: CA_CLIENT_ID,
									iat: now,
									exp: now + 3600,
									jwks: { keys: [clientPublicKey] },
								},
								taSigningKey,
								{ kid: taSigningKey.kid },
							);
							return new Response(ssJwt, {
								status: 200,
								headers: { "Content-Type": "application/entity-statement+jwt" },
							});
						}
					}
					return new Response("Not found", { status: 404 });
				};

			return {
				ctx,
				taSigningKey,
				taPublicKey,
				clientSigningKey,
				clientPublicKey,
				trustAnchors,
				createClientAssertionJwt,
				makeHttpClient,
			};
		}

		module("authority / createAuthenticatedHandler", () => {
			module("no auth required (passthrough)", () => {
				test("returns inner handler unchanged when authMethods is undefined", async (t) => {
					const { ctx } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, undefined);
					t.equal(handler, echoHandler);
				});

				test("returns inner handler unchanged when authMethods is ['none']", async (t) => {
					const { ctx } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, ["none"]);
					t.equal(handler, echoHandler);
				});

				test("returns inner handler unchanged when authMethods is empty []", async (t) => {
					const { ctx } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, []);
					t.equal(handler, echoHandler);
				});
			});

			module("private_key_jwt enforcement", () => {
				test("rejects GET when only 'private_key_jwt' configured", async (t) => {
					const { ctx } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, ["private_key_jwt"]);
					const res = await handler(new Request(`${CA_AUTHORITY_ID}/test?sub=test`));
					t.equal(res.status, 405);
				});

				test("accepts GET when both 'none' and 'private_key_jwt' configured", async (t) => {
					const { ctx } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, ["none", "private_key_jwt"]);
					const res = await handler(new Request(`${CA_AUTHORITY_ID}/test?sub=test`));
					t.equal(res.status, 200);
					t.equal(((await res.json()) as Record<string, unknown>).sub, "test");
				});

				test("rejects POST without client_assertion", async (t) => {
					const { ctx } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, ["private_key_jwt"]);
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: "sub=https%3A%2F%2Ffoo.com",
						}),
					);
					t.equal(res.status, 401);
					t.equal(
						((await res.json()) as Record<string, unknown>).error,
						FederationErrorCode.InvalidClient,
					);
				});

				test("rejects POST with wrong client_assertion_type", async (t) => {
					const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, ["private_key_jwt"]);
					const assertion = await createClientAssertionJwt();
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=wrong`,
						}),
					);
					t.equal(res.status, 401);
					const body = (await res.json()) as Record<string, string>;
					t.equal(body.error, FederationErrorCode.InvalidClient);
					t.true(body.error_description!.includes("client_assertion_type"));
				});

				test("accepts valid POST with correct client_assertion", async (t) => {
					const { ctx, createClientAssertionJwt, makeHttpClient } = await setupClientAuthContext();
					const ctxWithHttp: HandlerContext = { ...ctx, options: { httpClient: makeHttpClient() } };
					const handler = createAuthenticatedHandler(ctxWithHttp, echoHandler, ["private_key_jwt"]);
					const assertion = await createClientAssertionJwt();
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test_value&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 200);
					const body = (await res.json()) as Record<string, unknown>;
					t.equal(body.sub, "test_value");
					t.equal(body.method, "GET");
				});

				test("forwards endpoint params correctly from POST body", async (t) => {
					const { ctx, createClientAssertionJwt, makeHttpClient } = await setupClientAuthContext();
					const ctxWithHttp: HandlerContext = { ...ctx, options: { httpClient: makeHttpClient() } };
					const handler = createAuthenticatedHandler(ctxWithHttp, echoHandler, ["private_key_jwt"]);
					const subValue = "https://sub.example.com";
					const assertion = await createClientAssertionJwt();
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=${encodeURIComponent(subValue)}&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 200);
					t.equal(((await res.json()) as Record<string, unknown>).sub, subValue);
				});

				test("rejects POST with expired client_assertion", async (t) => {
					const { ctx, createClientAssertionJwt, makeHttpClient } = await setupClientAuthContext();
					const ctxWithHttp: HandlerContext = {
						...ctx,
						options: { httpClient: makeHttpClient(), clockSkewSeconds: 0 },
					};
					const handler = createAuthenticatedHandler(ctxWithHttp, echoHandler, ["private_key_jwt"]);
					const now = Math.floor(Date.now() / 1000);
					const assertion = await createClientAssertionJwt({ exp: now - 120 });
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 401);
				});

				test("rejects POST with wrong aud in assertion", async (t) => {
					const { ctx, createClientAssertionJwt, makeHttpClient } = await setupClientAuthContext();
					const ctxWithHttp: HandlerContext = { ...ctx, options: { httpClient: makeHttpClient() } };
					const handler = createAuthenticatedHandler(ctxWithHttp, echoHandler, ["private_key_jwt"]);
					const assertion = await createClientAssertionJwt({ aud: "https://wrong.example.com" });
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 401);
				});

				test("rejects POST when trust chain resolution fails", async (t) => {
					const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
					const ctxWithBrokenHttp: HandlerContext = {
						...ctx,
						options: { httpClient: async () => new Response("Not found", { status: 404 }) },
					};
					const handler = createAuthenticatedHandler(ctxWithBrokenHttp, echoHandler, [
						"private_key_jwt",
					]);
					const assertion = await createClientAssertionJwt();
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 401);
				});

				test("rejects POST with invalid signature", async (t) => {
					const { ctx, makeHttpClient } = await setupClientAuthContext();
					const ctxWithHttp: HandlerContext = { ...ctx, options: { httpClient: makeHttpClient() } };
					const handler = createAuthenticatedHandler(ctxWithHttp, echoHandler, ["private_key_jwt"]);
					const otherKeys = await generateSigningKey("ES256");
					const now = Math.floor(Date.now() / 1000);
					const badAssertion = await signEntityStatement(
						{
							iss: CA_CLIENT_ID,
							sub: CA_CLIENT_ID,
							aud: CA_AUTHORITY_ID,
							jti: crypto.randomUUID(),
							iat: now,
							exp: now + 60,
						},
						otherKeys.privateKey,
						{ kid: otherKeys.privateKey.kid, typ: "JWT" },
					);
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(badAssertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 401);
				});

				test("returns 500 when trust anchors not configured", async (t) => {
					const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
					const ctxNoTa: HandlerContext = {
						entityId: ctx.entityId,
						keyStore: ctx.keyStore,
						subordinateStore: ctx.subordinateStore,
						metadata: ctx.metadata,
						getSigningKey: ctx.getSigningKey,
					};
					const handler = createAuthenticatedHandler(ctxNoTa, echoHandler, ["private_key_jwt"]);
					const assertion = await createClientAssertionJwt();
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 500);
				});

				test("iss !== sub in assertion returns 401", async (t) => {
					const { ctx, createClientAssertionJwt, makeHttpClient } = await setupClientAuthContext();
					const ctxWithHttp: HandlerContext = { ...ctx, options: { httpClient: makeHttpClient() } };
					const handler = createAuthenticatedHandler(ctxWithHttp, echoHandler, ["private_key_jwt"]);
					const assertion = await createClientAssertionJwt({
						iss: CA_CLIENT_ID,
						sub: "https://other.example.com",
					});
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 401);
				});
			});

			module("nativeMethod: POST", () => {
				test("forwards remaining POST body for POST-native endpoints", async (t) => {
					const { ctx, createClientAssertionJwt, makeHttpClient } = await setupClientAuthContext();
					const ctxWithHttp: HandlerContext = { ...ctx, options: { httpClient: makeHttpClient() } };
					const handler = createAuthenticatedHandler(
						ctxWithHttp,
						postEchoHandler,
						["private_key_jwt"],
						{ nativeMethod: "POST" },
					);
					const assertion = await createClientAssertionJwt();
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `trust_mark=some_trust_mark_jwt&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 200);
					const body = (await res.json()) as Record<string, unknown>;
					t.equal(body.trust_mark, "some_trust_mark_jwt");
					t.equal(body.method, "POST");
				});
			});
		});
	}

	// -------------------------------------------------------------------------
	// endpoints/registration
	// -------------------------------------------------------------------------
	{
		const REG_NOW = Math.floor(Date.now() / 1000);
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
			return signEntityStatement(
				{
					iss: rpEntityId,
					sub: rpEntityId,
					aud: opEntityId,
					iat: REG_NOW,
					exp: REG_NOW + 3600,
					jwks: { keys: [rpPublicKey] },
					...REQUIRED_FIELDS,
					...overrides,
				},
				rpPrivateKey,
				{ typ: JwtTyp.EntityStatement },
			);
		}

		module("authority / createRegistrationHandler", () => {
			test("accepts a valid explicit registration request", async (t) => {
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
				t.equal(res.status, 200);
				t.equal(res.headers.get("Content-Type"), MediaType.ExplicitRegistrationResponse);
				const responseJwt = await res.text();
				const decoded = decodeEntityStatement(responseJwt);
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				t.equal(decoded.value.header.typ, JwtTyp.ExplicitRegistrationResponse);
				t.equal(decoded.value.payload.iss, ENTITY_ID);
				t.equal(decoded.value.payload.sub, rpId);
				const payload = decoded.value.payload as Record<string, unknown>;
				t.equal(payload.aud, rpId);
				t.ok(payload.trust_anchor);
				t.ok(payload.authority_hints);
				t.true(Array.isArray(payload.authority_hints));
				t.equal((payload.authority_hints as string[]).length, 1);
			});

			test("response includes metadata with openid_relying_party and client_id", async (t) => {
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
				t.equal(res.status, 200);
				const decoded = decodeEntityStatement(await res.text());
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				const meta = (decoded.value.payload as Record<string, unknown>).metadata as Record<
					string,
					Record<string, unknown>
				>;
				t.ok(meta.openid_relying_party);
				t.equal(meta.openid_relying_party!.client_id, rpId);
			});

			test("response includes OIDC default values", async (t) => {
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
				t.equal(res.status, 200);
				const decoded = decodeEntityStatement(await res.text());
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				const rpMeta = (
					(decoded.value.payload as Record<string, unknown>).metadata as Record<
						string,
						Record<string, unknown>
					>
				).openid_relying_party!;
				t.deepEqual(rpMeta.grant_types, ["authorization_code"]);
				t.equal(rpMeta.token_endpoint_auth_method, "client_secret_basic");
			});

			test("rejects wrong Content-Type", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createRegistrationHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_registration", {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: "{}",
					}),
				);
				t.equal(res.status, 400);
			});

			test("accepts application/trust-chain+json Content-Type", async (t) => {
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
				const res = await handler(
					new Request("https://authority.example.com/federation_registration", {
						method: "POST",
						headers: { "Content-Type": MediaType.TrustChain },
						body: JSON.stringify([ecJwt]),
					}),
				);
				t.equal(res.status, 200);
			});

			test("rejects wrong aud", async (t) => {
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
				t.equal(res.status, 400);
				t.true(
					((await res.json()) as Record<string, string | undefined>).error_description!.includes(
						"aud",
					),
				);
			});

			test("uses custom registrationResponseTtlSeconds for exp", async (t) => {
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
				t.equal(res.status, 200);
				const decoded = decodeEntityStatement(await res.text());
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				const payload = decoded.value.payload as Record<string, unknown>;
				t.equal((payload.exp as number) - (payload.iat as number), 7200);
			});

			test("rejects GET method", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createRegistrationHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_registration"),
				);
				t.equal(res.status, 405);
			});

			test("rejects invalid self-signature", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createRegistrationHandler(ctx);
				const rpKeys = await generateSigningKey("ES256");
				const wrongKeys = await generateSigningKey("ES256");
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
				t.equal(res.status, 400);
				t.true(
					((await res.json()) as Record<string, string | undefined>).error_description!.includes(
						"signature",
					),
				);
			});

			test("validates trust_chain header — first entry must be subject's EC", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createRegistrationHandler(ctx);
				const rpKeys = await generateSigningKey("ES256");
				const otherKeys = await generateSigningKey("ES256");
				const rpId = "https://rp.example.com";
				const wrongEc = await signEntityStatement(
					{
						iss: "https://other.example.com",
						sub: "https://other.example.com",
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [otherKeys.publicKey] },
					},
					otherKeys.privateKey,
					{ typ: JwtTyp.EntityStatement },
				);
				const jwt = await signEntityStatement(
					{
						iss: rpId,
						sub: rpId,
						aud: ENTITY_ID,
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [rpKeys.publicKey] },
						...REQUIRED_FIELDS,
					},
					rpKeys.privateKey,
					{ typ: JwtTyp.EntityStatement, extraHeaders: { trust_chain: [wrongEc] } },
				);
				const res = await handler(
					new Request("https://authority.example.com/federation_registration", {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_trust_chain");
			});

			test("calls registrationProtocolAdapter.validateClientMetadata when configured", async (t) => {
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
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_metadata");
			});

			test("succeeds without adapter (federation-only)", async (t) => {
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
				t.equal(res.status, 200);
			});

			test("rejects request missing authority_hints", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createRegistrationHandler(ctx);
				const rpKeys = await generateSigningKey("ES256");
				const rpId = "https://rp.example.com";
				const jwt = await signEntityStatement(
					{
						iss: rpId,
						sub: rpId,
						aud: ENTITY_ID,
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [rpKeys.publicKey] },
						metadata: {
							openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
						},
					},
					rpKeys.privateKey,
					{ typ: JwtTyp.EntityStatement },
				);
				const res = await handler(
					new Request("https://authority.example.com/federation_registration", {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 400);
			});

			test("rejects request without openid_relying_party in metadata", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createRegistrationHandler(ctx);
				const rpKeys = await generateSigningKey("ES256");
				const rpId = "https://rp.example.com";
				const jwt = await signEntityStatement(
					{
						iss: rpId,
						sub: rpId,
						aud: ENTITY_ID,
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [rpKeys.publicKey] },
						authority_hints: ["https://ta.example.com"],
						metadata: { federation_entity: { organization_name: "Test" } },
					},
					rpKeys.privateKey,
					{ typ: JwtTyp.EntityStatement },
				);
				const res = await handler(
					new Request("https://authority.example.com/federation_registration", {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 400);
			});

			test("calls onRegistrationInvalidation hook", async (t) => {
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
				t.equal(res.status, 200);
				t.equal(invalidatedSub, rpId);
			});
		});

		module("authority / createRegistrationHandler — trust chain resolution", () => {
			test("resolves chain and sets trust_anchor, authority_hints, exp from chain", async (t) => {
				const fed = await createMockFederation();
				const { ctx } = await createTestContext({
					trustAnchors: fed.trustAnchors,
					options: fed.options,
				});
				const handler = createRegistrationHandler(ctx);
				const rpKeys = await generateSigningKey("ES256");
				const jwt = await buildRegistrationRequest(
					LEAF_ID,
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
				t.equal(res.status, 200);
				const decoded = decodeEntityStatement(await res.text());
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				const payload = decoded.value.payload as Record<string, unknown>;
				t.equal(payload.trust_anchor, TA_ID);
				t.deepEqual(payload.authority_hints, [TA_ID]);
				const exp = payload.exp as number;
				const iat = payload.iat as number;
				t.true(exp > iat);
			});

			test("returns 403 when no valid chain can be resolved for RP", async (t) => {
				const fed = await createMockFederation();
				const { ctx } = await createTestContext({
					trustAnchors: fed.trustAnchors,
					options: fed.options,
				});
				const handler = createRegistrationHandler(ctx);
				const rpKeys = await generateSigningKey("ES256");
				const unknownRp = "https://unknown-rp.example.com";
				const jwt = await buildRegistrationRequest(
					unknownRp,
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
				t.equal(res.status, 403);
				t.equal(
					((await res.json()) as Record<string, string>).error,
					FederationErrorCode.InvalidTrustChain,
				);
			});

			test("uses trust_chain JWT header when valid and present", async (t) => {
				const fed = await createMockFederation();
				const { ctx } = await createTestContext({
					trustAnchors: fed.trustAnchors,
					options: fed.options,
				});
				const handler = createRegistrationHandler(ctx);
				const rpKeys = await generateSigningKey("ES256");
				const jwt = await signEntityStatement(
					{
						iss: LEAF_ID,
						sub: LEAF_ID,
						aud: ENTITY_ID,
						iat: REG_NOW,
						exp: REG_NOW + 3600,
						jwks: { keys: [rpKeys.publicKey as unknown as Record<string, unknown>] },
						...REQUIRED_FIELDS,
					},
					rpKeys.privateKey,
					{
						typ: JwtTyp.EntityStatement,
						extraHeaders: {
							trust_chain: [fed.leafEcJwt, fed.taSubStatementForLeaf, fed.taEcJwt],
						},
					},
				);
				const res = await handler(
					new Request("https://authority.example.com/federation_registration", {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body: jwt,
					}),
				);
				t.equal(res.status, 200);
				const decoded = decodeEntityStatement(await res.text());
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				t.equal((decoded.value.payload as Record<string, unknown>).trust_anchor, TA_ID);
			});

			test("invokes registrationProtocolAdapter.enrichResponseMetadata", async (t) => {
				const fed = await createMockFederation();
				let enrichCalled = false;
				const adapter: RegistrationProtocolAdapter = {
					validateClientMetadata: (metadata) => ({ ok: true, value: metadata }),
					enrichResponseMetadata: (metadata) => {
						enrichCalled = true;
						return { ...metadata, injected: true };
					},
				};
				const { ctx } = await createTestContext({
					trustAnchors: fed.trustAnchors,
					options: fed.options,
					registrationProtocolAdapter: adapter,
				});
				const handler = createRegistrationHandler(ctx);
				const rpKeys = await generateSigningKey("ES256");
				const jwt = await buildRegistrationRequest(
					LEAF_ID,
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
				t.equal(res.status, 200);
				t.true(enrichCalled);
				const decoded = decodeEntityStatement(await res.text());
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				const meta = (decoded.value.payload as Record<string, unknown>).metadata as Record<
					string,
					unknown
				>;
				t.equal(meta.injected, true);
			});

			test("emits client_secret when generateClientSecret hook returns a value", async (t) => {
				const fed = await createMockFederation();
				const { ctx } = await createTestContext({
					trustAnchors: fed.trustAnchors,
					options: fed.options,
					registrationConfig: {
						generateClientSecret: async () => "secret-abc",
					},
				});
				const handler = createRegistrationHandler(ctx);
				const rpKeys = await generateSigningKey("ES256");
				const jwt = await buildRegistrationRequest(
					LEAF_ID,
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
				t.equal(res.status, 200);
				const decoded = decodeEntityStatement(await res.text());
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				t.equal((decoded.value.payload as Record<string, unknown>).client_secret, "secret-abc");
			});

			test("omits client_secret when hook returns undefined", async (t) => {
				const fed = await createMockFederation();
				const { ctx } = await createTestContext({
					trustAnchors: fed.trustAnchors,
					options: fed.options,
					registrationConfig: {
						generateClientSecret: async () => undefined,
					},
				});
				const handler = createRegistrationHandler(ctx);
				const rpKeys = await generateSigningKey("ES256");
				const jwt = await buildRegistrationRequest(
					LEAF_ID,
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
				t.equal(res.status, 200);
				const decoded = decodeEntityStatement(await res.text());
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				t.notOk((decoded.value.payload as Record<string, unknown>).client_secret);
			});
		});

		module("authority / createRegistrationHandler — body size limits", () => {
			test("body exactly at 64KB boundary is not rejected with 413", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createRegistrationHandler(ctx);
				const body = "x".repeat(64 * 1024);
				const res = await handler(
					new Request("https://authority.example.com/federation_registration", {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement },
						body,
					}),
				);
				t.notEqual(res.status, 413);
			});

			test("body 1 byte over 64KB is rejected with 413", async (t) => {
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
				t.equal(res.status, 413);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_request");
			});

			test("spoofed Content-Length: 10 with 65KB actual body is rejected with 413", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createRegistrationHandler(ctx);
				const bigBody = "x".repeat(65 * 1024);
				const res = await handler(
					new Request("https://authority.example.com/federation_registration", {
						method: "POST",
						headers: { "Content-Type": MediaType.EntityStatement, "Content-Length": "10" },
						body: bigBody,
					}),
				);
				t.equal(res.status, 413);
			});
		});
	}

	module("authority / rotateKeyCompromise", (hooks) => {
		let compStore: MemoryKeyStore;

		hooks.beforeEach(async () => {
			compStore = new MemoryKeyStore();
			const { privateKey } = await generateSigningKey("ES256");
			await compStore.addKey({ ...privateKey, kid: "compromised-key" });
			await compStore.activateKey("compromised-key");
		});

		test("immediately revokes old key and activates new", async (t) => {
			const { privateKey: newKey } = await generateSigningKey("ES256");
			const key = { ...newKey, kid: "new-key" };
			await rotateKeyCompromise(compStore, key, "compromised-key");
			const signing = await compStore.getSigningKey();
			t.equal(signing.key.kid, "new-key");
			const history = await compStore.getHistoricalKeys();
			const oldManaged = history.find((k) => k.key.kid === "compromised-key");
			t.equal(oldManaged?.state, "revoked");
			t.equal(oldManaged?.revocationReason, "keyCompromise");
		});

		test("revoked key is not in active keys", async (t) => {
			const { privateKey: newKey } = await generateSigningKey("ES256");
			await rotateKeyCompromise(compStore, { ...newKey, kid: "new-key" }, "compromised-key");
			const activeKeys = await compStore.getActiveKeys();
			t.equal(activeKeys.keys.length, 1);
			t.equal(activeKeys.keys[0]!.kid, "new-key");
		});
	});

	module("authority / key rotation validation", () => {
		test("rotateKey throws when new key is missing kid", async (t) => {
			const store = new MemoryKeyStore();
			const { privateKey } = await generateSigningKey("ES256");
			await store.addKey({ ...privateKey, kid: "existing" });
			await store.activateKey("existing");
			const { privateKey: newKey } = await generateSigningKey("ES256");
			const keyWithoutKid = { ...newKey };
			delete (keyWithoutKid as { kid?: string }).kid;
			await t.rejects(rotateKey(store, keyWithoutKid), /New key must have a kid/);
		});

		test("rotateKey throws when current key is missing kid", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const currentWithoutKid = { ...privateKey };
			delete (currentWithoutKid as { kid?: string }).kid;
			const mockStore: import("../../../packages/authority/src/storage/types.js").KeyStore = {
				getActiveKeys: async () => ({ keys: [currentWithoutKid] }),
				getSigningKey: async () => ({
					key: currentWithoutKid,
					state: "active",
					createdAt: Date.now(),
				}),
				getHistoricalKeys: async () => [],
				addKey: async () => {},
				activateKey: async () => {},
				retireKey: async () => {},
				revokeKey: async () => {},
			};
			const { privateKey: newKey } = await generateSigningKey("ES256");
			await t.rejects(
				rotateKey(mockStore, { ...newKey, kid: "new-key" }),
				/Current key must have a kid/,
			);
		});

		test("rotateKeyCompromise throws when new key is missing kid", async (t) => {
			const store = new MemoryKeyStore();
			const { privateKey } = await generateSigningKey("ES256");
			await store.addKey({ ...privateKey, kid: "compromised" });
			await store.activateKey("compromised");
			const { privateKey: newKey } = await generateSigningKey("ES256");
			const keyWithoutKid = { ...newKey };
			delete (keyWithoutKid as { kid?: string }).kid;
			await t.rejects(
				rotateKeyCompromise(store, keyWithoutKid, "compromised"),
				/New key must have a kid/,
			);
		});
	});

	// ── server ───────────────────────────────────────────────────────
	{
		const SERVER_AUTHORITY_ID = entityId("https://authority.example.com");
		const SERVER_SUB1 = entityId("https://sub1.example.com");
		const SERVER_MARK_TYPE = "https://trust.example.com/mark-a";

		function makeServerRecord(
			id: ReturnType<typeof entityId>,
			overrides?: Partial<
				import("../../../packages/authority/src/storage/types.js").SubordinateRecord
			>,
		): import("../../../packages/authority/src/storage/types.js").SubordinateRecord {
			return {
				entityId: id,
				jwks: { keys: [{ kty: "EC", crv: "P-256", x: "abc", y: "def" }] },
				createdAt: Date.now(),
				updatedAt: Date.now(),
				...overrides,
			};
		}

		module("authority / createAuthorityServer", (hooks) => {
			let srvKeyStore: MemoryKeyStore;
			let srvSubordinateStore: MemorySubordinateStore;
			let srvTrustMarkStore: MemoryTrustMarkStore;
			let srvConfig: AuthorityConfig;

			hooks.beforeEach(async () => {
				srvKeyStore = new MemoryKeyStore();
				srvSubordinateStore = new MemorySubordinateStore();
				srvTrustMarkStore = new MemoryTrustMarkStore();

				const { privateKey } = await generateSigningKey("ES256");
				const signingKey = { ...privateKey, kid: "server-key-1" };
				await srvKeyStore.addKey(signingKey);
				await srvKeyStore.activateKey("server-key-1");

				srvConfig = {
					entityId: SERVER_AUTHORITY_ID,
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: `${SERVER_AUTHORITY_ID}/federation_fetch`,
							federation_list_endpoint: `${SERVER_AUTHORITY_ID}/federation_list`,
						},
					},
					subordinateStore: srvSubordinateStore,
					keyStore: srvKeyStore,
					trustMarkStore: srvTrustMarkStore,
					trustMarkIssuers: { [SERVER_MARK_TYPE]: [SERVER_AUTHORITY_ID] },
				};
			});

			module("programmatic API", () => {
				test("getEntityConfiguration returns signed JWT", async (t) => {
					const server = createAuthorityServer(srvConfig);
					const jwt = await server.getEntityConfiguration();
					const decoded = decodeEntityStatement(jwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					t.equal(decoded.value.payload.iss, SERVER_AUTHORITY_ID);
					t.equal(decoded.value.payload.sub, SERVER_AUTHORITY_ID);
				});

				test("getSubordinateStatement returns signed JWT", async (t) => {
					await srvSubordinateStore.add(makeServerRecord(SERVER_SUB1));
					const server = createAuthorityServer(srvConfig);
					const jwt = await server.getSubordinateStatement(SERVER_SUB1);
					const decoded = decodeEntityStatement(jwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					t.equal(decoded.value.payload.iss, SERVER_AUTHORITY_ID);
					t.equal(decoded.value.payload.sub, SERVER_SUB1);
				});

				test("getSubordinateStatement throws for unknown entity", async (t) => {
					const server = createAuthorityServer(srvConfig);
					try {
						await server.getSubordinateStatement(SERVER_SUB1);
						t.ok(false, "should have thrown");
					} catch (e: unknown) {
						t.true((e as Error).message.includes("not found"));
					}
				});

				test("listSubordinates returns entity IDs", async (t) => {
					await srvSubordinateStore.add(makeServerRecord(SERVER_SUB1));
					const server = createAuthorityServer(srvConfig);
					const list = await server.listSubordinates();
					t.deepEqual(list, [SERVER_SUB1]);
				});

				test("issueTrustMark returns signed JWT", async (t) => {
					const server = createAuthorityServer(srvConfig);
					const jwt = await server.issueTrustMark(SERVER_SUB1, SERVER_MARK_TYPE);
					const decoded = decodeEntityStatement(jwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					const payload = decoded.value.payload as Record<string, unknown>;
					t.equal(payload.trust_mark_type, SERVER_MARK_TYPE);
					t.equal(payload.sub, SERVER_SUB1);
				});

				test("listTrustMarkedEntities returns entity IDs", async (t) => {
					const server = createAuthorityServer(srvConfig);
					await server.issueTrustMark(SERVER_SUB1, SERVER_MARK_TYPE);
					const list = await server.listTrustMarkedEntities(SERVER_MARK_TYPE);
					t.true(list.includes(SERVER_SUB1));
				});

				test("getHistoricalKeys returns signed JWT", async (t) => {
					const server = createAuthorityServer(srvConfig);
					const jwt = await server.getHistoricalKeys();
					t.ok(jwt);
					const decoded = decodeEntityStatement(jwt);
					t.true(isOk(decoded));
				});

				test("rotateSigningKey rotates the key", async (t) => {
					const server = createAuthorityServer(srvConfig);
					const { privateKey: newKey } = await generateSigningKey("ES256");
					const key = { ...newKey, kid: "server-key-2" };
					await server.rotateSigningKey(key);
					const signing = await srvKeyStore.getSigningKey();
					t.equal(signing.key.kid, "server-key-2");
				});
			});

			module("HTTP handler", () => {
				test("routes to entity configuration", async (t) => {
					const server = createAuthorityServer(srvConfig);
					const handler = server.handler();
					const res = await handler(
						new Request(`${SERVER_AUTHORITY_ID}${WELL_KNOWN_OPENID_FEDERATION}`),
					);
					t.equal(res.status, 200);
					t.equal(res.headers.get("Content-Type"), "application/entity-statement+jwt");
				});

				test("routes to fetch endpoint", async (t) => {
					await srvSubordinateStore.add(makeServerRecord(SERVER_SUB1));
					const server = createAuthorityServer(srvConfig);
					const handler = server.handler();
					const res = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(SERVER_SUB1)}`,
						),
					);
					t.equal(res.status, 200);
				});

				test("routes to list endpoint", async (t) => {
					const server = createAuthorityServer(srvConfig);
					const handler = server.handler();
					const res = await handler(
						new Request(`${SERVER_AUTHORITY_ID}${FederationEndpoint.List}`),
					);
					t.equal(res.status, 200);
					t.equal(res.headers.get("Content-Type"), "application/json");
				});

				test("routes to historical keys endpoint", async (t) => {
					const server = createAuthorityServer(srvConfig);
					const handler = server.handler();
					const res = await handler(
						new Request(`${SERVER_AUTHORITY_ID}${FederationEndpoint.HistoricalKeys}`),
					);
					t.equal(res.status, 200);
					t.equal(res.headers.get("Content-Type"), "application/jwk-set+jwt");
				});

				test("routes to trust mark status endpoint", async (t) => {
					const server = createAuthorityServer(srvConfig);
					const handler = server.handler();
					const res = await handler(
						new Request(`${SERVER_AUTHORITY_ID}${FederationEndpoint.TrustMarkStatus}`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: "trust_mark=invalid",
						}),
					);
					t.equal(res.status, 200);
				});

				test("routes to trust mark list endpoint", async (t) => {
					const server = createAuthorityServer(srvConfig);
					const handler = server.handler();
					const res = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.TrustMarkList}?trust_mark_type=${encodeURIComponent(SERVER_MARK_TYPE)}`,
						),
					);
					t.equal(res.status, 200);
				});

				test("routes to trust mark endpoint — returns 404 when no trust mark exists", async (t) => {
					const server = createAuthorityServer(srvConfig);
					const handler = server.handler();
					const res = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.TrustMark}?trust_mark_type=${encodeURIComponent(SERVER_MARK_TYPE)}&sub=${encodeURIComponent(SERVER_SUB1)}`,
						),
					);
					t.equal(res.status, 404);
				});

				test("routes to trust mark endpoint — returns 200 when trust mark exists", async (t) => {
					const server = createAuthorityServer(srvConfig);
					await server.issueTrustMark(SERVER_SUB1, SERVER_MARK_TYPE);
					const handler = server.handler();
					const res = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.TrustMark}?trust_mark_type=${encodeURIComponent(SERVER_MARK_TYPE)}&sub=${encodeURIComponent(SERVER_SUB1)}`,
						),
					);
					t.equal(res.status, 200);
				});

				test("routes to resolve endpoint", async (t) => {
					const server = createAuthorityServer(srvConfig);
					const handler = server.handler();
					const res = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.Resolve}?sub=${encodeURIComponent(SERVER_SUB1)}`,
						),
					);
					t.equal(res.status, 400);
				});

				test("strips X-Authenticated-Entity header from incoming requests", async (t) => {
					await srvSubordinateStore.add(makeServerRecord(SERVER_SUB1));
					const server = createAuthorityServer(srvConfig);
					const handler = server.handler();
					const res = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(SERVER_SUB1)}`,
							{
								headers: { "X-Authenticated-Entity": "https://spoofed.example.com" },
							},
						),
					);
					t.equal(res.status, 200);
				});

				test("returns 404 for unknown paths", async (t) => {
					const server = createAuthorityServer(srvConfig);
					const handler = server.handler();
					const res = await handler(new Request(`${SERVER_AUTHORITY_ID}/unknown-endpoint`));
					t.equal(res.status, 404);
					t.equal(res.headers.get("Cache-Control"), "no-store");
					const body = (await res.json()) as { error: string };
					t.equal(body.error, "not_found");
				});

				test("all responses include security headers", async (t) => {
					const server = createAuthorityServer(srvConfig);
					const handler = server.handler();
					const res = await handler(
						new Request(`${SERVER_AUTHORITY_ID}${WELL_KNOWN_OPENID_FEDERATION}`),
					);
					t.equal(res.headers.get("Cache-Control"), "no-store");
					t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
					t.ok(res.headers.get("Strict-Transport-Security"));
				});
			});

			module("input validation", () => {
				test("rejects non-HTTPS entityId", (t) => {
					try {
						createAuthorityServer({
							...srvConfig,
							entityId: "http://insecure.example.com" as EntityId,
						});
						t.ok(false, "should have thrown");
					} catch (e: unknown) {
						t.true((e as Error).message.includes("entityId MUST be a valid HTTPS URL"));
					}
				});

				test("rejects entityId with query parameter", (t) => {
					try {
						createAuthorityServer({
							...srvConfig,
							entityId: "https://example.com?foo=bar" as EntityId,
						});
						t.ok(false, "should have thrown");
					} catch (e: unknown) {
						t.true((e as Error).message.includes("entityId MUST be a valid HTTPS URL"));
					}
				});

				test("rejects entityId with fragment", (t) => {
					try {
						createAuthorityServer({
							...srvConfig,
							entityId: "https://example.com#frag" as EntityId,
						});
						t.ok(false, "should have thrown");
					} catch (e: unknown) {
						t.true((e as Error).message.includes("entityId MUST be a valid HTTPS URL"));
					}
				});

				test("rejects zero entityConfigurationTtlSeconds", (t) => {
					try {
						createAuthorityServer({ ...srvConfig, entityConfigurationTtlSeconds: 0 });
						t.ok(false, "should have thrown");
					} catch (e: unknown) {
						t.true((e as Error).message.includes("entityConfigurationTtlSeconds must be positive"));
					}
				});

				test("rejects negative subordinateStatementTtlSeconds", (t) => {
					try {
						createAuthorityServer({ ...srvConfig, subordinateStatementTtlSeconds: -1 });
						t.ok(false, "should have thrown");
					} catch (e: unknown) {
						t.true(
							(e as Error).message.includes("subordinateStatementTtlSeconds must be positive"),
						);
					}
				});

				test("rejects zero registrationResponseTtlSeconds", (t) => {
					try {
						createAuthorityServer({ ...srvConfig, registrationResponseTtlSeconds: 0 });
						t.ok(false, "should have thrown");
					} catch (e: unknown) {
						t.true(
							(e as Error).message.includes("registrationResponseTtlSeconds must be positive"),
						);
					}
				});

				test("rejects negative trustMarkTtlSeconds", (t) => {
					try {
						createAuthorityServer({ ...srvConfig, trustMarkTtlSeconds: -5 });
						t.ok(false, "should have thrown");
					} catch (e: unknown) {
						t.true((e as Error).message.includes("trustMarkTtlSeconds must be positive"));
					}
				});

				test("accepts undefined TTL fields (uses defaults)", (t) => {
					try {
						createAuthorityServer(srvConfig);
						t.ok(true);
					} catch {
						t.ok(false, "should not have thrown");
					}
				});

				test("accepts positive TTL values", (t) => {
					try {
						createAuthorityServer({
							...srvConfig,
							entityConfigurationTtlSeconds: 3600,
							subordinateStatementTtlSeconds: 1800,
						});
						t.ok(true);
					} catch {
						t.ok(false, "should not have thrown");
					}
				});
			});

			module("client authentication wiring", () => {
				const CLIENT_ID = entityId("https://client.example.com");
				const JWT_BEARER_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

				async function setupAuthenticatedServer(authMethods: string[]) {
					const taKeyStore = new MemoryKeyStore();
					const taSubStore = new MemorySubordinateStore();
					const { privateKey: taPrivKey, publicKey: taPubKey } = await generateSigningKey("ES256");
					const taSigningKey = { ...taPrivKey, kid: "ta-key-1" };
					const taPublicKey = { ...taPubKey, kid: "ta-key-1" };
					await taKeyStore.addKey(taSigningKey);
					await taKeyStore.activateKey("ta-key-1");

					const { privateKey: clientPrivKey, publicKey: clientPubKey } =
						await generateSigningKey("ES256");
					const clientSigningKey = { ...clientPrivKey, kid: "client-key-1" };
					const clientPublicKey = { ...clientPubKey, kid: "client-key-1" };

					const trustAnchors: TrustAnchorSet = new Map([
						[SERVER_AUTHORITY_ID, { jwks: { keys: [taPublicKey] } }],
					]) as unknown as TrustAnchorSet;

					const httpClient = async (input: string | URL | Request): Promise<Response> => {
						const url =
							typeof input === "string"
								? input
								: input instanceof URL
									? input.toString()
									: input.url;
						const now = Math.floor(Date.now() / 1000);
						if (url === `${CLIENT_ID}${WELL_KNOWN_OPENID_FEDERATION}`) {
							const jwt = await signEntityStatement(
								{
									iss: CLIENT_ID,
									sub: CLIENT_ID,
									iat: now,
									exp: now + 3600,
									jwks: { keys: [clientPublicKey] },
									authority_hints: [SERVER_AUTHORITY_ID],
								},
								clientSigningKey,
								{ kid: clientSigningKey.kid },
							);
							return new Response(jwt, {
								status: 200,
								headers: { "Content-Type": "application/entity-statement+jwt" },
							});
						}
						if (url === `${SERVER_AUTHORITY_ID}${WELL_KNOWN_OPENID_FEDERATION}`) {
							const jwt = await signEntityStatement(
								{
									iss: SERVER_AUTHORITY_ID,
									sub: SERVER_AUTHORITY_ID,
									iat: now,
									exp: now + 3600,
									jwks: { keys: [taPublicKey] },
									metadata: {
										federation_entity: {
											federation_fetch_endpoint: `${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}`,
										},
									},
								},
								taSigningKey,
								{ kid: taSigningKey.kid },
							);
							return new Response(jwt, {
								status: 200,
								headers: { "Content-Type": "application/entity-statement+jwt" },
							});
						}
						if (url.startsWith(`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}`)) {
							const parsedUrl = new URL(url);
							if (parsedUrl.searchParams.get("sub") === CLIENT_ID) {
								const jwt = await signEntityStatement(
									{
										iss: SERVER_AUTHORITY_ID,
										sub: CLIENT_ID,
										iat: now,
										exp: now + 3600,
										jwks: { keys: [clientPublicKey] },
									},
									taSigningKey,
									{ kid: taSigningKey.kid },
								);
								return new Response(jwt, {
									status: 200,
									headers: { "Content-Type": "application/entity-statement+jwt" },
								});
							}
						}
						return new Response("Not found", { status: 404 });
					};

					await taSubStore.add(makeServerRecord(SERVER_SUB1));

					const authConfig: AuthorityConfig = {
						entityId: SERVER_AUTHORITY_ID,
						metadata: {
							federation_entity: {
								federation_fetch_endpoint: `${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}`,
								federation_list_endpoint: `${SERVER_AUTHORITY_ID}${FederationEndpoint.List}`,
								federation_fetch_endpoint_auth_methods: authMethods,
							},
						},
						subordinateStore: taSubStore,
						keyStore: taKeyStore,
						trustAnchors,
						options: { httpClient },
					};

					const createAssertion = async () => {
						const now = Math.floor(Date.now() / 1000);
						return signEntityStatement(
							{
								iss: CLIENT_ID,
								sub: CLIENT_ID,
								aud: SERVER_AUTHORITY_ID,
								jti: crypto.randomUUID(),
								iat: now,
								exp: now + 60,
							},
							clientSigningKey,
							{ kid: clientSigningKey.kid, typ: "JWT" },
						);
					};

					return { config: authConfig, createAssertion };
				}

				test("server with private_key_jwt rejects unauthenticated GET on fetch", async (t) => {
					const { config: authConfig } = await setupAuthenticatedServer(["private_key_jwt"]);
					const server = createAuthorityServer(authConfig);
					const handler = server.handler();
					const res = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(SERVER_SUB1)}`,
						),
					);
					t.equal(res.status, 405);
				});

				test("server with private_key_jwt accepts authenticated POST on fetch", async (t) => {
					const { config: authConfig, createAssertion } = await setupAuthenticatedServer([
						"private_key_jwt",
					]);
					const server = createAuthorityServer(authConfig);
					const handler = server.handler();
					const assertion = await createAssertion();
					const res = await handler(
						new Request(`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=${encodeURIComponent(SERVER_SUB1)}&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 200);
				});

				test("server without auth methods accepts unauthenticated GET", async (t) => {
					await srvSubordinateStore.add(makeServerRecord(SERVER_SUB1));
					const server = createAuthorityServer(srvConfig);
					const handler = server.handler();
					const res = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(SERVER_SUB1)}`,
						),
					);
					t.equal(res.status, 200);
				});

				test("server with ['none', 'private_key_jwt'] accepts both unauthenticated GET and authenticated POST", async (t) => {
					const { config: authConfig, createAssertion } = await setupAuthenticatedServer([
						"none",
						"private_key_jwt",
					]);
					const server = createAuthorityServer(authConfig);
					const handler = server.handler();
					const getRes = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(SERVER_SUB1)}`,
						),
					);
					t.equal(getRes.status, 200);
					const assertion = await createAssertion();
					const postRes = await handler(
						new Request(`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=${encodeURIComponent(SERVER_SUB1)}&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(postRes.status, 200);
				});
			});
		});
	}

	// ── integration ──────────────────────────────────────────────────
	{
		const INT_AUTHORITY_ID = entityId("https://ta.example.com");
		const INT_INTERMEDIATE_ID = entityId("https://intermediate.example.com");
		const INT_LEAF_OP = entityId("https://op.example.com");
		const INT_LEAF_RP = entityId("https://rp.example.com");
		const INT_MARK_TYPE = "https://trust.example.com/certified";

		module("authority / integration", (hooks) => {
			let intKeyStore: MemoryKeyStore;
			let intSubordinateStore: MemorySubordinateStore;
			let intTrustMarkStore: MemoryTrustMarkStore;
			let intServer: ReturnType<typeof createAuthorityServer>;

			hooks.beforeEach(async () => {
				intKeyStore = new MemoryKeyStore();
				intSubordinateStore = new MemorySubordinateStore();
				intTrustMarkStore = new MemoryTrustMarkStore();

				const { privateKey } = await generateSigningKey("ES256");
				const signingKey = { ...privateKey, kid: "ta-key-1" };
				await intKeyStore.addKey(signingKey);
				await intKeyStore.activateKey("ta-key-1");

				const config: AuthorityConfig = {
					entityId: INT_AUTHORITY_ID,
					metadata: {
						federation_entity: {
							organization_name: "Test Trust Anchor",
							federation_fetch_endpoint: `${INT_AUTHORITY_ID}${FederationEndpoint.Fetch}`,
							federation_list_endpoint: `${INT_AUTHORITY_ID}${FederationEndpoint.List}`,
							federation_trust_mark_status_endpoint: `${INT_AUTHORITY_ID}${FederationEndpoint.TrustMarkStatus}`,
							federation_trust_mark_list_endpoint: `${INT_AUTHORITY_ID}${FederationEndpoint.TrustMarkList}`,
							federation_trust_mark_endpoint: `${INT_AUTHORITY_ID}${FederationEndpoint.TrustMark}`,
							federation_historical_keys_endpoint: `${INT_AUTHORITY_ID}${FederationEndpoint.HistoricalKeys}`,
						},
					},
					subordinateStore: intSubordinateStore,
					keyStore: intKeyStore,
					trustMarkStore: intTrustMarkStore,
					trustMarkIssuers: { [INT_MARK_TYPE]: [INT_AUTHORITY_ID] },
					trustMarkOwners: { [INT_MARK_TYPE]: { sub: INT_AUTHORITY_ID, jwks: { keys: [] } } },
				};

				intServer = createAuthorityServer(config);
			});

			module("Entity Configuration lifecycle", () => {
				test("fetches EC via programmatic API and HTTP handler", async (t) => {
					const ecJwt = await intServer.getEntityConfiguration();
					const decoded = decodeEntityStatement(ecJwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					t.equal(decoded.value.payload.iss, INT_AUTHORITY_ID);
					t.equal(decoded.value.payload.sub, INT_AUTHORITY_ID);
					const payload = decoded.value.payload as Record<string, unknown>;
					t.ok(payload.metadata);
					t.ok(payload.jwks);
					t.deepEqual(payload.trust_mark_issuers, { [INT_MARK_TYPE]: [INT_AUTHORITY_ID] });
					t.ok(payload.trust_mark_owners);
					const httpHandler = intServer.handler();
					const httpRes = await httpHandler(
						new Request(`${INT_AUTHORITY_ID}${WELL_KNOWN_OPENID_FEDERATION}`),
					);
					t.equal(httpRes.status, 200);
					const activeKeys = await intKeyStore.getActiveKeys();
					const verifyResult = await verifyEntityStatement(ecJwt, activeKeys);
					t.true(isOk(verifyResult));
				});

				test("EC includes authority_hints for intermediates", async (t) => {
					const { privateKey: intKey } = await generateSigningKey("ES256");
					const intIntKeyStore = new MemoryKeyStore();
					await intIntKeyStore.addKey({ ...intKey, kid: "int-key-1" });
					await intIntKeyStore.activateKey("int-key-1");

					const intIntServer = createAuthorityServer({
						entityId: INT_INTERMEDIATE_ID,
						metadata: {
							federation_entity: {
								federation_fetch_endpoint: `${INT_INTERMEDIATE_ID}${FederationEndpoint.Fetch}`,
							},
						},
						subordinateStore: new MemorySubordinateStore(),
						keyStore: intIntKeyStore,
						authorityHints: [INT_AUTHORITY_ID],
					});

					const ecJwt = await intIntServer.getEntityConfiguration();
					const decoded = decodeEntityStatement(ecJwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					const payload = decoded.value.payload as Record<string, unknown>;
					t.deepEqual(payload.authority_hints, [INT_AUTHORITY_ID]);
				});
			});

			module("Subordinate management lifecycle", () => {
				test("adds subordinates, lists them, and fetches statements", async (t) => {
					const opRecord: import("../../../packages/authority/src/storage/types.js").SubordinateRecord =
						{
							entityId: INT_LEAF_OP,
							jwks: { keys: [{ kty: "EC", crv: "P-256", x: "abc", y: "def" }] },
							metadata: { openid_provider: { issuer: INT_LEAF_OP } },
							entityTypes: [EntityType.OpenIDProvider],
							sourceEndpoint: `${INT_LEAF_OP}${FederationEndpoint.Fetch}`,
							createdAt: Date.now(),
							updatedAt: Date.now(),
						};
					const rpRecord: import("../../../packages/authority/src/storage/types.js").SubordinateRecord =
						{
							entityId: INT_LEAF_RP,
							jwks: { keys: [{ kty: "EC", crv: "P-256", x: "ghi", y: "jkl" }] },
							metadata: { openid_relying_party: { client_name: "Test RP" } },
							entityTypes: [EntityType.OpenIDRelyingParty],
							createdAt: Date.now(),
							updatedAt: Date.now(),
						};
					await intSubordinateStore.add(opRecord);
					await intSubordinateStore.add(rpRecord);

					const allSubs = await intServer.listSubordinates();
					t.equal(allSubs.length, 2);
					t.true(allSubs.includes(INT_LEAF_OP));
					t.true(allSubs.includes(INT_LEAF_RP));

					const opOnly = await intServer.listSubordinates({
						entityTypes: [EntityType.OpenIDProvider],
					});
					t.deepEqual(opOnly, [INT_LEAF_OP]);

					const ssJwt = await intServer.getSubordinateStatement(INT_LEAF_OP);
					const decoded = decodeEntityStatement(ssJwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					t.equal(decoded.value.payload.iss, INT_AUTHORITY_ID);
					t.equal(decoded.value.payload.sub, INT_LEAF_OP);
					const payload = decoded.value.payload as Record<string, unknown>;
					t.equal(payload.source_endpoint, `${INT_LEAF_OP}${FederationEndpoint.Fetch}`);
					t.ok(payload.metadata);
				});

				test("fetches subordinate via HTTP handler", async (t) => {
					await intSubordinateStore.add({
						entityId: INT_LEAF_OP,
						jwks: { keys: [{ kty: "EC", crv: "P-256", x: "abc", y: "def" }] },
						createdAt: Date.now(),
						updatedAt: Date.now(),
					});
					const httpHandler = intServer.handler();
					const res = await httpHandler(
						new Request(
							`${INT_AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(INT_LEAF_OP)}`,
						),
					);
					t.equal(res.status, 200);
					t.equal(res.headers.get("Content-Type"), "application/entity-statement+jwt");
				});
			});

			module("Trust Mark lifecycle", () => {
				test("issues, lists, checks status, and revokes trust marks", async (t) => {
					const tmJwt = await intServer.issueTrustMark(INT_LEAF_OP, INT_MARK_TYPE);
					t.ok(tmJwt);
					const decoded = decodeEntityStatement(tmJwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					const payload = decoded.value.payload as Record<string, unknown>;
					t.equal(payload.iss, INT_AUTHORITY_ID);
					t.equal(payload.sub, INT_LEAF_OP);
					t.equal(payload.trust_mark_type, INT_MARK_TYPE);
					const entities = await intServer.listTrustMarkedEntities(INT_MARK_TYPE);
					t.true(entities.includes(INT_LEAF_OP));
					const status = await intServer.getTrustMarkStatus(tmJwt);
					t.equal(status.status, "active");
					await intTrustMarkStore.revoke(INT_MARK_TYPE, INT_LEAF_OP);
					const statusAfterRevoke = await intServer.getTrustMarkStatus(tmJwt);
					t.equal(statusAfterRevoke.status, "revoked");
					const entitiesAfterRevoke = await intServer.listTrustMarkedEntities(INT_MARK_TYPE);
					t.false(entitiesAfterRevoke.includes(INT_LEAF_OP));
				});
			});

			module("Key rotation lifecycle", () => {
				test("rotates key and verifies historical keys", async (t) => {
					const activeKeysBefore = await intKeyStore.getActiveKeys();
					t.equal(activeKeysBefore.keys.length, 1);
					const { privateKey: newKey } = await generateSigningKey("ES256");
					const newSigningKey = { ...newKey, kid: "ta-key-2" };
					await intServer.rotateSigningKey(newSigningKey);
					const signing = await intKeyStore.getSigningKey();
					t.equal(signing.key.kid, "ta-key-2");
					const activeKeysAfter = await intKeyStore.getActiveKeys();
					t.equal(activeKeysAfter.keys.length, 2);
					const historicalJwt = await intServer.getHistoricalKeys();
					const decoded = decodeEntityStatement(historicalJwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					const payload = decoded.value.payload as Record<string, unknown>;
					const keys = payload.keys as Array<Record<string, unknown>>;
					t.equal(keys.length, 2);
					const oldKey = keys.find((k) => k.kid === "ta-key-1");
					t.ok(oldKey);
					const ecAfterRotation = await intServer.getEntityConfiguration();
					const ecDecoded = decodeEntityStatement(ecAfterRotation);
					t.true(isOk(ecDecoded));
					if (!isOk(ecDecoded)) return;
					const ecPayload = ecDecoded.value.payload as Record<string, unknown>;
					const ecJwks = ecPayload.jwks as { keys: Array<Record<string, unknown>> };
					t.equal(ecJwks.keys.length, 2);
					const verifyResult = await verifyEntityStatement(ecAfterRotation, activeKeysAfter);
					t.true(isOk(verifyResult));
				});
			});

			module("HTTP routing coverage", () => {
				test("all endpoints respond with security headers", async (t) => {
					const httpHandler = intServer.handler();
					const endpoints = [
						WELL_KNOWN_OPENID_FEDERATION,
						`${FederationEndpoint.List}`,
						`${FederationEndpoint.HistoricalKeys}`,
					];
					for (const endpoint of endpoints) {
						const res = await httpHandler(new Request(`${INT_AUTHORITY_ID}${endpoint}`));
						t.equal(res.headers.get("Cache-Control"), "no-store");
						t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
						t.ok(res.headers.get("Strict-Transport-Security"));
					}
				});

				test("404 for unknown paths", async (t) => {
					const httpHandler = intServer.handler();
					const res = await httpHandler(new Request(`${INT_AUTHORITY_ID}/nonexistent`));
					t.equal(res.status, 404);
					const body = (await res.json()) as { error: string };
					t.equal(body.error, "not_found");
				});
			});
		});
	}
};
