import type QUnit from "qunit";
import { MemoryStorageAdapter, TrustAnchor } from "../../../packages/authority/src/index.js";
import { buildCollectionSnapshot } from "../../../packages/core/src/entity-collection/refresh.js";
import {
	createConcurrencyLimiter,
	EntityCollectionEntitySchema,
	type EntityCollectionRequestParams,
	EntityCollectionService,
	type EntityCollectionSnapshot,
	entityId,
	esCacheKey,
	fetchEntityCollection,
	fetchSubordinateStatement,
	generateSigningKey,
	type HttpClient,
	JwkSigner,
	MemoryCache,
	MemoryEntityCollectionStore,
	MemoryFederationKeyProvider,
	resolveTrustChains,
} from "../../../packages/core/src/index.js";
import { performFetch } from "../../../packages/core/src/trust-chain/fetch.js";
import { Leaf } from "../../../packages/leaf/src/index.js";
import {
	type CollectionGraphEdge,
	createCollectionFederation,
} from "../fixtures/collection-federation.js";

const clock = { now: () => 1500 };
const anchor = entityId("https://ta.example");
const endpoint = "https://provider.example/collect";
async function seeded() {
	const store = new MemoryEntityCollectionStore({ clock });
	const snapshot: EntityCollectionSnapshot = {
		id: "previous",
		trustAnchor: anchor,
		lastUpdated: 1200,
		entries: [],
	};
	await store.publish(snapshot);
	return { store, snapshot };
}

export default function collectionRegressions(QUnit: QUnit): void {
	QUnit.module("Collection regressions", () => {
		QUnit.test(
			"subordinate fetches without issuer context retain their cache contract",
			async (assert) => {
				const cache = new MemoryCache({ clock });
				const subject = entityId("https://client.example");
				await cache.set(await esCacheKey(anchor, subject), "cached statement", 1000);
				let requests = 0;
				const result = await fetchSubordinateStatement(`${anchor}/fetch`, subject, {
					cache,
					httpClient: async () => {
						requests++;
						throw new Error("Unexpected fetch");
					},
				});
				assert.true(result.ok);
				if (result.ok) assert.equal(result.value, "cached statement");
				assert.equal(requests, 0);
			},
		);
		QUnit.test(
			"aborted limiter waiters settle without acquiring an occupied slot",
			async (assert) => {
				const ac = new AbortController();
				const limiter = createConcurrencyLimiter(1, ac.signal);
				let release!: () => void;
				let started!: () => void;
				const gate = new Promise<void>((resolve) => {
					release = resolve;
				});
				const entered = new Promise<void>((resolve) => {
					started = resolve;
				});
				const active = limiter(async () => {
					started();
					await gate;
					return "active";
				});
				await entered;
				let admitted = 0;
				const queued = [1, 2, 3].map(() =>
					limiter(async () => {
						admitted++;
					}).then(
						() => "ran",
						(error: Error) => error.name,
					),
				);
				ac.abort();
				assert.deepEqual(await Promise.all(queued), ["AbortError", "AbortError", "AbortError"]);
				assert.equal(admitted, 0);
				release();
				assert.equal(await active, "active");
				assert.equal(
					await limiter(async () => "late").catch((error: Error) => error.name),
					"AbortError",
				);
			},
		);

		QUnit.test("resolver completion status identifies limits and cancellation", async (assert) => {
			const graph = await createCollectionFederation({
				edges: [
					{ issuer: "ta", subject: "a" },
					{ issuer: "ta", subject: "b" },
					{ issuer: "a", subject: "issuer" },
					{ issuer: "b", subject: "issuer" },
				],
			});
			for (const limits of [
				{ maxTotalFetches: 0 },
				{ maxTotalFetches: 1 },
				{ maxChainDepth: 1 },
				{ maxAuthorityHints: 1 },
			]) {
				const result = await resolveTrustChains(graph.id("issuer"), graph.trustAnchors, {
					clock,
					httpClient: graph.httpClient,
					maxConcurrentFetches: 1,
					...limits,
				});
				assert.true(result.incomplete === true, JSON.stringify(limits));
				if ("maxAuthorityHints" in limits)
					assert.equal(result.chains.length, 1, "a valid partial result is still incomplete");
			}
			const ac = new AbortController();
			ac.abort();
			assert.true(
				(
					await resolveTrustChains(graph.id("issuer"), graph.trustAnchors, {
						clock,
						httpClient: graph.httpClient,
						signal: ac.signal,
					})
				).incomplete === true,
			);
			const complete = await resolveTrustChains(graph.id("issuer"), graph.trustAnchors, {
				clock,
				httpClient: graph.httpClient,
				maxConcurrentFetches: 1,
			});
			assert.equal(complete.chains.length, 2);
			assert.notOk(complete.incomplete);
		});
		QUnit.test(
			"issuer resolution finishes at concurrency one and abort releases refresh queues",
			async (assert) => {
				const graph = await createCollectionFederation({
					edges: [
						{ issuer: "ta", subject: "leaf" },
						{ issuer: "ta", subject: "mid" },
						{ issuer: "mid", subject: "issuer" },
					],
					marked: true,
				});
				const service = new EntityCollectionService({
					trustAnchors: graph.trustAnchors,
					options: { clock, httpClient: graph.httpClient, maxConcurrentFetches: 1 },
				});
				const ac = new AbortController();
				const first = service.refresh(graph.id("ta"), { signal: ac.signal });
				let timeout: ReturnType<typeof setTimeout> | undefined;
				const result = await Promise.race([
					first,
					new Promise<undefined>((resolve) => {
						timeout = setTimeout(() => resolve(undefined), 1000);
					}),
				]);
				clearTimeout(timeout);
				if (!result) {
					ac.abort();
					assert.ok(result, "refresh must finish instead of deadlocking");
					return;
				}
				assert.true(result.ok, JSON.stringify(result));
				assert.equal(result.ok ? result.value.entityCount : 0, 3);
				const cancelled = new AbortController();
				cancelled.abort();
				assert.false((await service.refresh(graph.id("ta"), { signal: cancelled.signal })).ok);
				assert.true(
					(await service.refresh(graph.id("ta"))).ok,
					"a cancelled refresh must not block its successor",
				);
			},
		);

		QUnit.test(
			"documented default budget matches explicit budget for outside-chain issuers",
			async (assert) => {
				const edges: CollectionGraphEdge[] = [{ issuer: "ta", subject: "leaf" }];
				for (let i = 0; i < 10; i++)
					edges.push(
						{ issuer: "ta", subject: `b${i}` },
						{ issuer: `b${i}`, subject: `a${i}` },
						{ issuer: `a${i}`, subject: "issuer" },
					);
				const graph = await createCollectionFederation({ edges, marked: true });
				const config = {
					trustAnchors: graph.trustAnchors,
					options: { clock, httpClient: graph.httpClient, maxConcurrentFetches: 64 },
				};
				const explicit = await buildCollectionSnapshot(graph.id("ta"), {
					...config,
					options: { ...config.options, maxTotalFetches: 1000 },
				});
				const implicit = await buildCollectionSnapshot(graph.id("ta"), config);
				assert.true(explicit.ok);
				assert.true(implicit.ok);
				if (implicit.ok && explicit.ok)
					assert.deepEqual(implicit.value.entries, explicit.value.entries);
			},
		);

		QUnit.test("truncated issuer resolution preserves the published snapshot", async (assert) => {
			const graph = await createCollectionFederation({
				edges: [
					{ issuer: "ta", subject: "leaf" },
					{ issuer: "ta", subject: "b" },
					{ issuer: "b", subject: "a" },
					{ issuer: "a", subject: "issuer" },
				],
				marked: true,
				listOrder: { ta: ["leaf"] },
			});
			const { store, snapshot } = await seeded();
			const service = new EntityCollectionService({
				trustAnchors: graph.trustAnchors,
				store,
				options: { clock, httpClient: graph.httpClient, maxChainDepth: 1, maxConcurrentFetches: 8 },
			});
			assert.false((await service.refresh(graph.id("ta"))).ok);
			assert.deepEqual(await store.getCurrent(anchor), snapshot);
		});

		QUnit.test(
			"alternate paths retain valid descendants and merge their expiry bounds",
			async (assert) => {
				for (const order of [
					["a", "b"],
					["b", "a"],
				]) {
					const graph = await createCollectionFederation({
						edges: [
							{ issuer: "ta", subject: "a", constraints: { max_path_length: 1 }, expiresAt: 2000 },
							{ issuer: "ta", subject: "b", expiresAt: 4000 },
							{ issuer: "a", subject: "issuer" },
							{ issuer: "b", subject: "issuer" },
							{ issuer: "issuer", subject: "leaf" },
						],
						listOrder: { ta: order },
						marked: true,
					});
					const result = await buildCollectionSnapshot(graph.id("ta"), {
						trustAnchors: graph.trustAnchors,
						options: { clock, httpClient: graph.httpClient },
					});
					assert.true(result.ok);
					if (result.ok) {
						assert.equal(result.value.entries.length, 4, order.join(","));
						assert.equal(
							result.value.entries.find(
								(entry) => String(entry.entity.entity_id) === graph.id("leaf"),
							)?.verifiedMarks[0]?.expiresAt,
							4000,
						);
						assert.equal(
							new Set(graph.requests.filter((url) => url.endsWith("/list"))).size,
							graph.requests.filter((url) => url.endsWith("/list")).length,
							"alternate paths reuse listings",
						);
						assert.equal(
							result.value.entries.find(
								(entry) => String(entry.entity.entity_id) === graph.id("issuer"),
							)?.chainExpiresAt,
							4000,
						);
						assert.equal(
							result.value.entries.find(
								(entry) => String(entry.entity.entity_id) === graph.id("leaf"),
							)?.chainExpiresAt,
							4000,
						);
					}
				}
			},
		);

		QUnit.test(
			"same-origin authorities do not share cached subordinate attestations",
			async (assert) => {
				const graph = await createCollectionFederation({
					edges: [
						{ issuer: "ta", subject: "a" },
						{ issuer: "ta", subject: "b" },
						{ issuer: "a", subject: "i" },
						{ issuer: "b", subject: "i" },
					],
					ids: {
						ta: "https://host.example/ta",
						a: "https://host.example/a",
						b: "https://host.example/b",
					},
					badKeyEdge: "a|i",
				});
				for (const cache of [undefined, new MemoryCache({ clock })]) {
					const result = await buildCollectionSnapshot(graph.id("ta"), {
						trustAnchors: graph.trustAnchors,
						options: { clock, httpClient: graph.httpClient, ...(cache ? { cache } : {}) },
					});
					assert.true(result.ok);
					if (result.ok)
						assert.true(
							result.value.entries.some(
								(entry) => String(entry.entity.entity_id) === graph.id("i"),
							),
						);
				}
			},
		);

		QUnit.test("hosted authentication cannot disagree with its metadata", async (assert) => {
			const key = await generateSigningKey("ES256");
			const keyProvider = new MemoryFederationKeyProvider({
				signer: new JwkSigner(key.privateKey),
				publicJwk: key.publicKey,
			});
			const trustAnchors = new Map([[anchor, { jwks: { keys: [key.publicKey] } }]]);
			for (const kind of ["authority", "leaf"]) {
				for (const declared of [
					undefined,
					["none"],
					["private_key_jwt"],
					["none", "private_key_jwt"],
				]) {
					const methods = declared ?? ["none"];
					const config = {
						entityId: anchor,
						keyProvider,
						metadata: {
							federation_entity: {
								federation_collection_endpoint: `${anchor}/collect`,
								...(declared ? { federation_collection_endpoint_auth_methods: declared } : {}),
								...(kind === "authority"
									? {
											federation_fetch_endpoint: `${anchor}/fetch`,
											federation_list_endpoint: `${anchor}/list`,
										}
									: {}),
							},
						},
						collection: {
							trustAnchors,
							authentication: {
								methods: [...methods].reverse() as ("none" | "private_key_jwt")[],
								getClientFederationJwks: async () => ({ keys: [key.publicKey] }),
							},
						},
					};
					const construct = () =>
						kind === "authority"
							? new TrustAnchor({ ...config, storage: new MemoryStorageAdapter() })
							: new Leaf({ ...config, authorityHints: [entityId("https://superior.example")] });
					assert.ok(construct());
					config.collection.authentication.methods = methods.includes("none")
						? ["private_key_jwt"]
						: ["none"];
					assert.throws(construct, `${kind}: conflicting methods are rejected`);
				}
			}
		});

		QUnit.test(
			"JSON charset policy is collection-specific for success and error bodies",
			async (assert) => {
				for (const contentType of [
					"application/json; charset=utf-8",
					"Application/JSON; charset=UTF-8",
				]) {
					const httpClient: HttpClient = async () =>
						new Response('{"entities":[]}', { headers: { "content-type": contentType } });
					assert.true((await fetchEntityCollection(endpoint, {}, { httpClient })).ok);
					assert.false(
						(await performFetch(endpoint, { httpClient, accept: "application/json" })).ok,
						"legacy exact matching remains the default",
					);
					const error = await fetchEntityCollection(
						endpoint,
						{},
						{
							httpClient: async () =>
								new Response(
									'{"error":"unsupported_claim","error_description":"Unsupported claim"}',
									{ status: 400, headers: { "content-type": contentType } },
								),
						},
					);
					assert.false(error.ok);
					if (!error.ok) assert.equal(error.error.code, "unsupported_claim");
				}
			},
		);

		QUnit.test("empty wire selectors fail before fetching", async (assert) => {
			let calls = 0;
			for (const params of [
				{ entityClaims: [] },
				{ infoClaims: [] },
			] satisfies EntityCollectionRequestParams[]) {
				const result = await fetchEntityCollection(endpoint, params, {
					httpClient: async () => {
						calls++;
						return new Response('{"entities":[]}');
					},
				});
				assert.false(result.ok);
				if (!result.ok) assert.equal(result.error.code, "invalid_request");
			}
			assert.equal(calls, 0);
		});

		QUnit.test(
			"authority routing preserves abort signals for form body readers",
			async (assert) => {
				const key = await generateSigningKey("ES256");
				const keyProvider = new MemoryFederationKeyProvider({
					signer: new JwkSigner(key.privateKey),
					publicJwk: key.publicKey,
				});
				const authority = new TrustAnchor({
					entityId: anchor,
					keyProvider,
					storage: new MemoryStorageAdapter(),
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: `${anchor}/fetch`,
							federation_list_endpoint: `${anchor}/list`,
							federation_collection_endpoint: `${anchor}/collect`,
						},
					},
					collection: { trustAnchors: new Map(), options: { httpTimeoutMs: 1000 } },
				});
				let signal: AbortSignal | undefined;
				const handle = authority.collection!.handleRequest.bind(authority.collection);
				authority.collection!.handleRequest = async (request) => {
					signal = request.signal;
					return handle(request);
				};
				const ac = new AbortController();
				ac.abort();
				let cancelled = false;
				const pending = authority.handleRequest(
					new Request(`${anchor}/collect`, {
						method: "POST",
						headers: { "content-type": "application/x-www-form-urlencoded" },
						body: new ReadableStream({
							cancel() {
								cancelled = true;
							},
						}),
						signal: ac.signal,
						...({ duplex: "half" } as RequestInit),
					}),
				);
				assert.true(
					signal?.aborted ?? false,
					"the handler must receive the incoming aborted state",
				);
				assert.equal((await pending).status, 400);
				assert.true(cancelled);
			},
		);

		QUnit.test(
			"declared hash-containing claims and their locales preserve their full names",
			async (assert) => {
				const { store } = await seeded();
				const name = "https://claims.example/#name";
				await store.publish({
					id: "custom",
					trustAnchor: anchor,
					lastUpdated: 1500,
					entries: [
						{
							entity: EntityCollectionEntitySchema.parse({
								entity_id: "https://leaf.example",
								entity_infos: {
									custom: {
										[name]: "Default",
										[`${name}#en-US`]: "English",
										[`${name}#de`]: "Deutsch",
									},
								},
							}),
							chainExpiresAt: 5000,
							verifiedMarks: [],
						},
					],
				});
				const service = new EntityCollectionService({
					trustAnchors: new Map([[anchor, { jwks: { keys: [] } }]]),
					store,
					options: { clock },
					infoClaims: [name],
				});
				for (const params of [
					{ infoClaims: [name] },
					{ infoClaims: [name], locale: ["en"] },
					{ infoClaims: [`${name}#en-US`], locale: ["en"] },
				]) {
					const result = await service.query({ trustAnchor: anchor, ...params });
					assert.true(result.ok, JSON.stringify(result));
					if (result.ok)
						assert.deepEqual(
							result.value.entities[0]?.entity_infos?.custom,
							params.infoClaims[0] !== name
								? { [`${name}#en-US`]: "English" }
								: params.locale
									? { [name]: "Default", [`${name}#en-US`]: "English" }
									: { [name]: "Default", [`${name}#en-US`]: "English", [`${name}#de`]: "Deutsch" },
						);
				}
			},
		);
	});
}
