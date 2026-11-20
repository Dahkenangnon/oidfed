import {
	assertStorageCapabilities,
	assertStorageView,
	bindFederationOptions,
	composeFederationStorage,
	createTrustAnchorSet,
	describeStorageRequirements,
	EntityCollectionService,
	entityId,
	fetchEntityConfiguration,
	MemoryFederationStorage,
	StorageCapabilityError,
	storageSnapshot,
	storageTransaction,
	type TransactionView,
	TrustMarkIssuerService,
} from "@oidfed/core";
import { Leaf } from "@oidfed/leaf";
import { OidcProviderRole } from "@oidfed/oidc";
import type QUnit from "qunit";
import { STORED_PUBLIC_JWK } from "../../storage-fixtures.js";
import { FixtureCrypto, generateSigningKey, testEngine } from "../fixtures/software-crypto.js";

export default function storageTests(Q: QUnit): void {
	Q.module("federation storage", () => {
		Q.test("rejects mismatched interfaces and composes only matching namespaces", async (t) => {
			const base = new MemoryFederationStorage({
				namespace: "authority",
				capabilities: ["subordinate:read", "transaction", "snapshot", "namespace"],
			});
			const replay = new MemoryFederationStorage({
				namespace: "authority",
				capabilities: ["replay", "namespace"],
			});
			const cache = new MemoryFederationStorage({
				namespace: "authority",
				capabilities: ["cache", "namespace"],
			});
			t.throws(
				() => assertStorageCapabilities({ ...base, transaction: undefined }, ["transaction"]),
				StorageCapabilityError,
			);
			t.throws(
				() => assertStorageCapabilities({ ...base, isolation: undefined }, ["transaction"]),
				/serializable/,
			);
			const rebound = replay.withNamespace?.("other");
			t.throws(() => composeFederationStorage({ base, replay: rebound }), /namespaces differ/);
			t.throws(
				() =>
					composeFederationStorage({
						base: replay,
						replay: new MemoryFederationStorage({
							namespace: "authority",
							capabilities: ["replay"],
						}),
					}),
				/More than one/,
			);
			const combined = composeFederationStorage({ base, replay, cache });
			assertStorageCapabilities(combined, ["replay", "cache", "namespace"]);
			t.strictEqual(combined.replay, replay.replay);
			t.strictEqual(combined.cache, cache.cache);
			const isolated = combined.withNamespace("other");
			await combined.cache.set("item", { value: 1 }, 60);
			t.strictEqual(await isolated.cache?.get("item"), undefined);
			t.strictEqual(combined[Symbol.asyncDispose], undefined);
			t.false(combined.capabilities.includes("subordinate:write"));
		});
		Q.test("composition and discovery ignore undeclared repositories", async (t) => {
			const memory = new MemoryFederationStorage({ namespace: "undeclared" });
			assertStorageCapabilities(memory, ["subordinate:write", "cache"]);
			const base = {
				namespace: memory.namespace,
				capabilities: ["subordinate:read"] as const,
				subordinate: memory.subordinate,
				cache: {
					...memory.cache,
					get: async () => {
						throw new Error("Undeclared cache accessed");
					},
				},
			};
			const combined = composeFederationStorage({ base });
			t.strictEqual(combined.cache, undefined);
			t.false("register" in (combined.subordinate ?? {}));
			const fetch = () =>
				new Response("jwt-from-network", {
					headers: { "content-type": "application/entity-statement+jwt" },
				});
			const id = entityId("https://uncached.example");
			t.deepEqual(
				await fetchEntityConfiguration(id, {
					engine: testEngine,
					storage: base,
					httpClient: async () => fetch(),
				}),
				{ ok: true, value: "jwt-from-network" },
			);
			await t.rejects(
				fetchEntityConfiguration(id, {
					engine: testEngine,
					storage: { ...base, cache: undefined, capabilities: ["cache"] },
					httpClient: async () => fetch(),
				}),
				StorageCapabilityError,
			);
		});
		Q.test(
			"scoped reads and writes only expose declared repositories and close their views",
			async (t) => {
				const storage = new MemoryFederationStorage({ namespace: "scoped" });
				assertStorageCapabilities(storage, ["trustMark:read", "transaction"]);
				const revision = await storage.trustMark.revision();
				t.false("checkRevision" in storage.trustMark);
				let escaped: TransactionView = {};
				await storageTransaction(storage, async (view) => {
					escaped = view;
					t.false("cache" in view);
					t.false("replay" in view);
					t.false("entityCollection" in view);
					t.false("withNamespace" in view);
					t.false("readSnapshot" in view);
					assertStorageView(view, ["trustMark:write"], "Check scoped revision");
					t.true(await view.trustMark.checkRevision(revision));
				});
				assertStorageView(escaped, ["trustMark:write"], "Check escaped view");
				await t.rejects(escaped.trustMark.revision(), /closed/);
				await t.rejects(escaped.trustMark.checkRevision(revision), /closed/);
				await storageSnapshot(storage, async (view) => {
					t.false("register" in (view.subordinate ?? {}));
					t.false("issue" in (view.trustMark ?? {}));
					t.false("append" in (view.subordinateEvent ?? {}));
					t.false("checkRevision" in (view.trustMark ?? {}));
				});
				const broken = {
					...storage,
					readSnapshot: async <T>(
						callback: (view: import("@oidfed/core").ReadSnapshotView) => Promise<T>,
					) => callback({}),
				};
				await t.rejects(
					storageSnapshot(broken, async () => undefined),
					StorageCapabilityError,
				);
				const withoutGuard = {
					...storage,
					transaction: <T>(callback: (view: TransactionView) => Promise<T>) =>
						storage.transaction((view) => {
							assertStorageView(view, ["trustMark:write"], "Expect source revision guard");
							const { checkRevision, ...trustMark } = view.trustMark;
							t.strictEqual(typeof checkRevision, "function");
							return callback({ ...view, trustMark });
						}),
				};
				await t.rejects(
					storageTransaction(withoutGuard, async () => undefined),
					/trustMark\.checkRevision/,
				);
			},
		);
		Q.test("a callback that leaves an outstanding write rolls back", async (t) => {
			const base = new MemoryFederationStorage({ namespace: "pending-write" });
			assertStorageCapabilities(base, ["transaction", "subordinate:read"]);
			const id = entityId("https://member.example");
			const storage = {
				...base,
				transaction<T>(operation: (view: TransactionView) => Promise<T>) {
					return base.transaction((view) => {
						assertStorageView(view, ["subordinate:write"], "Test subordinate writes");
						const subordinate = view.subordinate;
						const register = subordinate.register.bind(subordinate);
						return operation({
							...view,
							subordinate: {
								...subordinate,
								async register(record) {
									await new Promise((resolve) => setTimeout(resolve, 10));
									await register(record);
								},
							},
						});
					});
				},
			};
			await t.rejects(
				storageTransaction(storage, async (view) => {
					assertStorageView(view, ["subordinate:write"], "Test pending write");
					void view.subordinate.register({
						entityId: id,
						jwks: { keys: [STORED_PUBLIC_JWK] },
						createdAt: 1,
						updatedAt: 1,
					});
				}),
				/must await/,
			);
			t.strictEqual(await base.subordinate.fetch(id), undefined);
		});
		Q.test(
			"host storage is required only for the published provider functions that use it",
			async (t) => {
				const keys = await generateSigningKey("ES256");
				const crypto = FixtureCrypto.fromJWK(keys.privateKey);
				const id = "https://provider.example";
				const anchor = entityId("https://anchor.example");
				const trustAnchors = createTrustAnchorSet([
					{ entityId: anchor, jwks: { keys: [keys.publicKey] } },
				]);
				const config = {
					entityId: id,
					crypto,
					authorityHints: [anchor],
					trustAnchors,
					metadata: {},
				};
				const explicit = () =>
					new OidcProviderRole({ metadata: { client_registration_types_supported: ["explicit"] } });
				t.ok(await Leaf.create({ ...config, roles: [explicit()] }));
				const automatic = () =>
					new OidcProviderRole({
						metadata: { client_registration_types_supported: ["automatic", "explicit"] },
					});
				await t.rejects(Leaf.create({ ...config, roles: [automatic()] }), StorageCapabilityError);
				const storage = new MemoryFederationStorage({ namespace: id, capabilities: ["replay"] });
				t.ok(await Leaf.create({ ...config, storage, roles: [automatic()] }));
				const injected = new MemoryFederationStorage({ namespace: "ignored" });
				const override = { storage: injected, clockSkewSeconds: 123 };
				t.strictEqual(bindFederationOptions({ crypto, storage }, override).storage, storage);
				t.strictEqual(bindFederationOptions(crypto, override).storage, undefined);
			},
		);
		Q.test("Collection requires explicit replay for private_key_jwt", (t) => {
			const issuer = entityId("https://collection.example");
			const options = {
				engine: testEngine,
				storage: new MemoryFederationStorage({
					namespace: issuer,
					capabilities: ["entityCollection"],
				}),
			};
			const config = {
				trustAnchors: createTrustAnchorSet([]),
				options,
				authentication: {
					methods: ["private_key_jwt"],
					receiverEntityId: issuer,
					getClientFederationJwks: async () => undefined,
				},
			};
			t.throws(() => new EntityCollectionService(config), /storage capability replay/);
		});
		Q.test("managed issuance performs key work outside the storage callback", async (t) => {
			const keys = await generateSigningKey("ES256");
			const crypto = FixtureCrypto.fromJWK(keys.privateKey);
			const issuer = "https://issuer.example";
			const subject = "https://member.example";
			const type = "https://marks.example/test";
			const clock = { now: () => 1000 };
			const storage = new MemoryFederationStorage({
				namespace: issuer,
				capabilities: describeStorageRequirements("trustMarkWrite"),
			});
			const getKey = crypto.keyring.entry.bind(crypto.keyring);
			const service = new TrustMarkIssuerService({
				issuer,
				storage,
				crypto: {
					...crypto,
					keyring: {
						async entry(purpose, selection) {
							await storageTransaction(storage, async () => undefined);
							return getKey(purpose, selection);
						},
					},
				},
				options: { engine: testEngine, clock },
			});
			const tokens = await Promise.all([
				service.issueTrustMark(subject, type),
				service.issueTrustMark(subject, type),
			]);
			t.equal(tokens[0], tokens[1]);
			t.equal((await storage.trustMark?.candidates({ issuer }))?.length, 1);
			t.equal(await service.getTrustMark(subject, type), tokens[0]);
		});
	});
}
