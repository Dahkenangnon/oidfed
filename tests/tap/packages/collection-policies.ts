import type QUnit from "qunit";
import {
	decodeEntityConfiguration,
	type EntityCollectionCandidate,
	type EntityCollectionCollectorContext,
	EntityCollectionEntitySchema,
	EntityCollectionService,
	entityId,
	err,
	fetchEntityConfiguration,
	JwkSigner,
	MemoryEntityCollectionStore,
	ok,
	signEntityStatement,
	validateTrustChain,
} from "../../../packages/core/src/index.js";
import { createCollectionFederation } from "../fixtures/collection-federation.js";

const anchor = entityId("https://ta.example");
const candidate = (id = "https://leaf.example", expiresAt = 3000): EntityCollectionCandidate => ({
	entity: EntityCollectionEntitySchema.parse({ entity_id: id, entity_types: ["custom"] }),
	expiresAt,
});
const keys = { keys: [] };
const anchors = new Map([[anchor, { jwks: keys }]]);

export default function collectionPolicies(QUnit: QUnit): void {
	QUnit.module("Collection policies", () => {
		QUnit.test(
			"custom inventories use anchor context without traversal or query-time callbacks",
			async (assert) => {
				const other = entityId("https://other.example");
				let collected = 0;
				let filtered = 0;
				const contexts: EntityCollectionCollectorContext[] = [];
				const original = candidate();
				const service = new EntityCollectionService({
					trustAnchors: new Map([...anchors, [other, { jwks: keys }]]),
					options: {
						clock: { now: () => 1500 },
						httpClient: async () => {
							throw new Error("Unexpected network call");
						},
					},
					collector: async (context) => {
						collected++;
						contexts.push(context);
						return ok([
							candidate("https://z.example"),
							context.trustAnchor === anchor ? original : candidate("https://other-leaf.example"),
						]);
					},
					filter: async (entry, context) => {
						filtered++;
						assert.true(Object.isFrozen(entry.entity));
						assert.false(Reflect.set(entry.entity, "entity_id", "https://changed.example"));
						assert.true(Object.isFrozen(context.trustAnchorJwks.keys));
						assert.strictEqual(entry.chainExpiresAt, undefined);
						return true;
					},
				});
				assert.true((await service.refresh(anchor)).ok);
				original.entity.entity_types?.push("changed-after-collection");
				assert.true((await service.refresh(other)).ok);
				for (let i = 0; i < 2; i++) {
					const page = await service.query({ trustAnchor: anchor });
					assert.true(page.ok);
					if (page.ok) {
						assert.deepEqual(
							page.value.entities.map((entity) => entity.entity_id),
							["https://leaf.example", "https://z.example"],
						);
						assert.deepEqual(page.value.entities[0]?.entity_types, ["custom"]);
					}
				}
				assert.equal(collected, 2);
				assert.equal(filtered, 4);
				assert.deepEqual(
					contexts.map((context) => context.trustAnchor),
					[anchor, other],
				);
				assert.equal(contexts[0]?.options.maxTotalFetches, 1000);
				const snapshot = await service.store.getCurrent(anchor);
				assert.equal(snapshot?.lastUpdated, 1500);
				assert.equal(snapshot?.entries[0]?.expiresAt, 3000);
				assert.strictEqual(snapshot?.entries[0]?.chainExpiresAt, undefined);
				assert.false((await service.refresh(entityId("https://unsupported.example"))).ok);
				assert.equal(collected, 2);
			},
		);

		QUnit.test(
			"filters can exclude entries and shorten but never extend eligibility",
			async (assert) => {
				let time = 1500;
				let deadline = 4000;
				const service = new EntityCollectionService({
					trustAnchors: anchors,
					options: { clock: { now: () => time } },
					collector: async () => ok([candidate(), candidate("https://excluded.example")]),
					filter: (entry) =>
						entry.entity.entity_id === "https://excluded.example" ? false : { expiresAt: deadline },
				});
				assert.true((await service.refresh(anchor)).ok);
				assert.equal((await service.store.getCurrent(anchor))?.entries[0]?.expiresAt, 3000);
				deadline = 2000;
				assert.true((await service.refresh(anchor)).ok);
				assert.equal((await service.store.getCurrent(anchor))?.entries.length, 1);
				assert.equal((await service.store.getCurrent(anchor))?.entries[0]?.expiresAt, 2000);
				time = 2000;
				assert.deepEqual(await service.query({ trustAnchor: anchor }), {
					ok: true,
					value: { entities: [], last_updated: 1500 },
				});
			},
		);

		QUnit.test("excluding an intermediate does not prune its descendants", async (assert) => {
			const graph = await createCollectionFederation({
				edges: [
					{ issuer: "ta", subject: "mid" },
					{ issuer: "mid", subject: "leaf" },
				],
			});
			const service = new EntityCollectionService({
				trustAnchors: graph.trustAnchors,
				options: { clock: { now: () => 1500 }, httpClient: graph.httpClient },
				filter: (entry) => String(entry.entity.entity_id) === graph.id("leaf"),
			});
			assert.true((await service.refresh(anchor)).ok);
			const result = await service.query({ trustAnchor: anchor });
			assert.true(result.ok);
			if (result.ok)
				assert.deepEqual(
					result.value.entities.map((entity) => String(entity.entity_id)),
					[String(graph.id("leaf"))],
				);
			assert.equal((await service.store.getCurrent(anchor))?.entries[0]?.chainExpiresAt, 5000);
		});

		QUnit.test(
			"invalid candidate sets preserve the current snapshot and existing cursors",
			async (assert) => {
				const graph = await createCollectionFederation({
					edges: [
						{ issuer: "ta", subject: "issuer" },
						{ issuer: "ta", subject: "leaf" },
					],
					marked: true,
				});
				const leaf = decodeEntityConfiguration(graph.configurations.get("leaf")!);
				if (!leaf.ok) throw new Error("Invalid fixture");
				const mismatch = {
					...candidate(),
					entity: {
						...candidate().entity,
						trust_marks: leaf.value.payload.trust_marks?.map((ref) => ({
							...ref,
							trust_mark_type: "different",
						})),
					},
				};
				let values: unknown = [candidate(), candidate("https://second.example")];
				const service = new EntityCollectionService({
					trustAnchors: anchors,
					maxEntities: 3,
					maxPageSize: 1,
					options: { clock: { now: () => 1500 } },
					collector: async () => ok(values as EntityCollectionCandidate[]),
				});
				assert.true((await service.refresh(anchor)).ok);
				const previous = await service.store.getCurrent(anchor);
				const first = await service.query({ trustAnchor: anchor });
				assert.true(first.ok && !!first.value.next);
				for (const invalid of [
					null,
					[mismatch],
					[{ ...candidate(), expiresAt: Infinity }],
					[{ ...candidate(), entity: { entity_id: "invalid" } }],
					[candidate(), candidate()],
					[1, 2, 3, 4].map((i) => candidate(`https://leaf${i}.example`)),
					[{ ...candidate(), verifiedMarks: [{ type: "forged", expiresAt: 3000 }] }],
					[
						{
							...candidate(),
							entity: {
								...candidate().entity,
								trust_marks: [{ trust_mark_type: "one", trust_mark: "not-a-jwt" }],
							},
						},
					],
				]) {
					values = invalid;
					assert.false((await service.refresh(anchor)).ok);
					assert.deepEqual(await service.store.getCurrent(anchor), previous);
					if (first.ok)
						assert.true((await service.query({ trustAnchor: anchor, from: first.value.next })).ok);
				}
			},
		);

		QUnit.test(
			"callback errors and invalid decisions never replace a published snapshot",
			async (assert) => {
				for (const phase of ["collector", "source-error", "filter", "decision"] as const) {
					let fail = false;
					const service = new EntityCollectionService({
						trustAnchors: anchors,
						options: { clock: { now: () => 1500 } },
						collector: async () => {
							if (fail && phase === "collector") throw new Error("Source failed");
							if (fail && phase === "source-error")
								return err({ code: "temporarily_unavailable", description: "Source unavailable" });
							return ok([candidate()]);
						},
						filter: () => {
							if (fail && phase === "filter") throw new Error("Policy failed");
							return fail && phase === "decision" ? { expiresAt: NaN } : true;
						},
					});
					assert.true((await service.refresh(anchor)).ok);
					const previous = await service.store.getCurrent(anchor);
					fail = true;
					assert.false((await service.refresh(anchor)).ok, phase);
					assert.deepEqual(await service.store.getCurrent(anchor), previous);
				}
			},
		);

		QUnit.test(
			"cancellation settles uncooperative callbacks and releases subsequent refreshes",
			async (assert) => {
				for (const phase of ["collector", "filter", "transport"]) {
					let calls = 0;
					let transportSignal: AbortSignal | null | undefined;
					let entered!: () => void;
					let release!: () => void;
					const started = new Promise<void>((resolve) => {
						entered = resolve;
					});
					const gate = new Promise<void>((resolve) => {
						release = resolve;
					});
					const wait = async () => {
						if (++calls === 1) {
							entered();
							await gate;
						}
					};
					const service = new EntityCollectionService({
						trustAnchors: anchors,
						options: {
							clock: { now: () => 1500 },
							httpClient: async (_url, init) => {
								transportSignal = init?.signal;
								await wait();
								return new Response("{}");
							},
						},
						collector: async (context) => {
							if (phase === "collector") await wait();
							if (phase === "transport") await context.options.httpClient!("https://slow.example");
							return ok([candidate()]);
						},
						filter: async () => {
							if (phase === "filter") await wait();
							return true;
						},
					});
					const controller = new AbortController();
					const pending = service.refresh(anchor, { signal: controller.signal });
					await started;
					controller.abort();
					if (phase === "transport") assert.true(transportSignal?.aborted ?? false);
					let timer: ReturnType<typeof setTimeout> | undefined;
					const settled = await Promise.race([
						pending,
						new Promise<undefined>((resolve) => {
							timer = setTimeout(() => resolve(undefined), 1000);
						}),
					]);
					clearTimeout(timer);
					if (!settled) {
						release();
						await pending;
						assert.ok(settled, `${phase}: abort must settle refresh`);
						continue;
					}
					assert.false(settled.ok, phase);
					assert.strictEqual(await service.store.getCurrent(anchor), undefined);
					assert.true((await service.refresh(anchor)).ok);
					const published = await service.store.getCurrent(anchor);
					release();
					await Promise.resolve();
					assert.deepEqual(await service.store.getCurrent(anchor), published);
				}
			},
		);

		QUnit.test("pre-aborted refreshes do not invoke application code", async (assert) => {
			let calls = 0;
			const service = new EntityCollectionService({
				trustAnchors: anchors,
				collector: async () => {
					calls++;
					return ok([]);
				},
			});
			const controller = new AbortController();
			controller.abort();
			assert.false((await service.refresh(anchor, { signal: controller.signal })).ok);
			assert.equal(calls, 0);
		});

		QUnit.test(
			"custom sources qualify only marks published and verified by core",
			async (assert) => {
				for (const mode of ["valid", "unpublished", "untrusted-issuer", "bad-publication"]) {
					const graph = await createCollectionFederation({
						edges: [
							{ issuer: "ta", subject: "issuer" },
							{ issuer: "ta", subject: "leaf" },
						],
						marked: true,
						...(mode === "untrusted-issuer" ? { badKeyEdge: "ta|issuer" } : {}),
					});
					const raw = graph.configurations.get("leaf")!;
					const decoded = decodeEntityConfiguration(raw);
					if (!decoded.ok) throw new Error("Invalid fixture");
					if (mode === "unpublished" || mode === "bad-publication") {
						const jwt = await signEntityStatement(
							{ ...decoded.value.payload, ...(mode === "unpublished" ? { trust_marks: [] } : {}) },
							new JwkSigner(graph.keys.get(mode === "bad-publication" ? "ta" : "leaf")!.privateKey),
						);
						graph.routes.set(
							`${graph.id("leaf")}/.well-known/openid-federation`,
							() =>
								new Response(jwt, {
									headers: { "content-type": "application/entity-statement+jwt" },
								}),
						);
					}
					const service = new EntityCollectionService({
						trustAnchors: graph.trustAnchors,
						options: { clock: { now: () => 1500 }, httpClient: graph.httpClient },
						collector: async () =>
							ok([
								{
									entity: EntityCollectionEntitySchema.parse({
										entity_id: graph.id("leaf"),
										trust_marks: decoded.value.payload.trust_marks,
									}),
									expiresAt: 6000,
								},
							]),
						filter: (entry) => {
							assert.equal(entry.verifiedMarks.length, mode === "valid" ? 1 : 0);
							return true;
						},
					});
					assert.true((await service.refresh(anchor)).ok, mode);
					const unfiltered = await service.query({ trustAnchor: anchor });
					assert.true(unfiltered.ok && unfiltered.value.entities.length === 1, mode);
					const filtered = await service.query({ trustAnchor: anchor, trustMarkType: ["one"] });
					assert.true(filtered.ok);
					if (filtered.ok) assert.equal(filtered.value.entities.length, mode === "valid" ? 1 : 0);
					const entry = (await service.store.getCurrent(anchor))?.entries[0];
					assert.equal(entry?.expiresAt, 6000);
					assert.strictEqual(entry?.chainExpiresAt, undefined);
					if (mode === "valid") assert.equal(entry?.verifiedMarks[0]?.expiresAt, 4000);
					assert.false(
						graph.requests.some((url) => url.endsWith("/list")),
						"custom collection never traverses listings",
					);
				}
			},
		);

		QUnit.test(
			"network limits and incomplete custom mark verification preserve prior snapshots",
			async (assert) => {
				for (const mode of ["transport", "issuer-budget", "collector-budget"]) {
					const graph = await createCollectionFederation({
						edges: [
							{ issuer: "ta", subject: "issuer" },
							{ issuer: "ta", subject: "leaf" },
						],
						marked: true,
					});
					const leaf = decodeEntityConfiguration(graph.configurations.get("leaf")!);
					if (!leaf.ok) throw new Error("Invalid fixture");
					let changed = false;
					const service = new EntityCollectionService({
						trustAnchors: graph.trustAnchors,
						options: {
							clock: { now: () => 1500 },
							maxTotalFetches: mode === "transport" ? 1000 : mode === "issuer-budget" ? 2 : 1,
							httpClient: async (url, init) => {
								if (mode === "transport" && String(url).startsWith(graph.id("issuer")))
									throw new Error("Issuer unavailable");
								assert.equal(init?.redirect, "manual");
								return graph.httpClient(url, init);
							},
						},
						collector: async (context) => {
							if (changed && mode === "collector-budget") {
								await fetchEntityConfiguration(anchor, context.options);
								await fetchEntityConfiguration(graph.id("leaf"), context.options);
							}
							return ok([
								{
									...candidate(),
									...(changed && mode !== "collector-budget"
										? {
												entity: EntityCollectionEntitySchema.parse({
													entity_id: graph.id("leaf"),
													trust_marks: leaf.value.payload.trust_marks,
												}),
											}
										: {}),
								},
							]);
						},
					});
					assert.true((await service.refresh(anchor)).ok);
					const previous = await service.store.getCurrent(anchor);
					changed = true;
					assert.false((await service.refresh(anchor)).ok, mode);
					assert.deepEqual(await service.store.getCurrent(anchor), previous, mode);
				}
			},
		);

		QUnit.test(
			"legacy chain validation remains strict about invalid published marks",
			async (assert) => {
				const graph = await createCollectionFederation({
					edges: [
						{ issuer: "ta", subject: "issuer" },
						{ issuer: "ta", subject: "leaf" },
					],
					marked: true,
				});
				const result = await validateTrustChain(
					[
						graph.configurations.get("leaf")!,
						graph.statements.get(`${anchor}|${graph.id("leaf")}`)!,
						graph.configurations.get("ta")!,
					],
					graph.trustAnchors,
					{
						clock: { now: () => 4250 },
						verboseErrors: true,
						trustMarkIssuerKeys: new Map([
							[graph.id("issuer"), { keys: [graph.keys.get("issuer")!.publicKey] }],
						]),
					},
				);
				assert.false(result.valid);
				assert.true(result.errors.some((error) => error.code === "ERR_TRUST_MARK_INVALID"));
			},
		);

		QUnit.test(
			"entry lifetime and optional chain evidence independently bound eligibility",
			async (assert) => {
				const store = new MemoryEntityCollectionStore({ clock: { now: () => 1500 } });
				await store.publish({
					id: "mixed",
					trustAnchor: anchor,
					lastUpdated: 1400,
					entries: [
						{ ...candidate(), chainExpiresAt: 1400, verifiedMarks: [] },
						{ ...candidate("https://informational.example"), verifiedMarks: [] },
					],
				});
				const service = new EntityCollectionService({
					trustAnchors: anchors,
					store,
					options: { clock: { now: () => 1500 } },
				});
				const page = await service.query({ trustAnchor: anchor });
				assert.true(page.ok);
				if (page.ok)
					assert.deepEqual(
						page.value.entities.map((entity) => entity.entity_id),
						["https://informational.example"],
					);
			},
		);
	});
}
