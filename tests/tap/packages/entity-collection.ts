import type QUnit from "qunit";
import {
	Intermediate,
	MemoryStorageAdapter,
	TrustAnchor,
} from "../../../packages/authority/src/index.js";
import {
	COLLECTION_INFO_CLAIMS,
	createTrustAnchorSet,
	decodeEntityStatement,
	type EntityCollectionRequestParams,
	EntityCollectionRequestSchema,
	type EntityCollectionResponse,
	EntityCollectionResponseSchema,
	EntityCollectionService,
	type EntityCollectionSnapshot,
	entityId,
	FederationEntityMetadataSchema,
	fetchEntityCollection,
	generateSigningKey,
	type HttpClient,
	JwkSigner,
	MediaType,
	MemoryEntityCollectionStore,
	MemoryFederationKeyProvider,
	signEntityStatement,
} from "../../../packages/core/src/index.js";
import { createLeafHandler } from "../../../packages/leaf/src/handler.js";
import { Leaf } from "../../../packages/leaf/src/index.js";

const anchor = entityId("https://anchor.example");
const other = entityId("https://other.example");
const leafId = entityId("https://leaf.example");
const endpoint = "https://collection.example:8443/tenant/collect?version=1";
const now = 1500;

async function seed() {
	let time = now;
	const clock = { now: () => time };
	const key = await generateSigningKey("ES256");
	const trustAnchors = createTrustAnchorSet([
		{ entityId: anchor, jwks: { keys: [key.publicKey] } },
	]);
	const store = new MemoryEntityCollectionStore({ clock });
	const snapshot: EntityCollectionSnapshot = {
		id: "first",
		trustAnchor: anchor,
		lastUpdated: -0.5,
		entries: ["a", "b", "c"].map((name, index) => ({
			entity: {
				entity_id: EntityCollectionResponseSchema.parse({
					entities: [{ entity_id: `https://${name}.example` }],
				}).entities[0]!.entity_id,
				entity_types: [index === 1 ? "custom_type" : "openid_provider", "federation_entity"],
				entity_infos: {
					openid_provider: {
						display_name: name.toUpperCase(),
						"display_name#en-US": `${name} English`,
						"display_name#de": `${name} Deutsch`,
						description: "Example",
					},
					federation_entity: { organization_name: "Organization" },
				},
			},
			chainExpiresAt: 5000,
			verifiedMarks:
				index === 0
					? [
							{ type: "one", expiresAt: 2000 },
							{ type: "two", expiresAt: 3000 },
						]
					: [{ type: "one", expiresAt: 2000 }],
		})),
	};
	await store.publish(snapshot);
	const service = new EntityCollectionService({
		trustAnchors,
		store,
		endpoint,
		responder: { entityId: anchor, isTrustAnchor: true },
		options: { clock },
		maxPageSize: 2,
	});
	return {
		clock,
		key,
		trustAnchors,
		store,
		snapshot,
		service,
		setNow: (value: number) => {
			time = value;
		},
	};
}

async function query(
	service: EntityCollectionService,
	params: EntityCollectionRequestParams = {},
): Promise<EntityCollectionResponse> {
	const result = await service.query(params);
	if (!result.ok) throw new Error(`${result.error.code}: ${result.error.description}`);
	return result.value;
}

async function federation(
	markMode: "none" | "valid" | "expired" | "wrong-subject" | "wrong-type" | "unauthorized" = "none",
) {
	const rootKey = await generateSigningKey("ES256");
	const middleKey = await generateSigningKey("ES256");
	const leafKey = await generateSigningKey("ES256");
	const middleId = entityId("https://middle.example");
	const issuerId = entityId("https://issuer.example");
	const issuerKey = await generateSigningKey("ES256");
	const clock = { now: () => now };
	const provider = (key: typeof rootKey) =>
		new MemoryFederationKeyProvider({
			signer: new JwkSigner(key.privateKey),
			publicJwk: key.publicKey,
		});
	const trustAnchors = createTrustAnchorSet([
		{ entityId: anchor, jwks: { keys: [rootKey.publicKey] } },
	]);
	const storage = new MemoryStorageAdapter({ collections: true, clock });
	const middleStorage = new MemoryStorageAdapter({ clock });
	let requests = 0;
	let failedHost = "";
	const httpClient: HttpClient = async (input, init) => {
		requests++;
		const request = new Request(String(input), init);
		const host = new URL(request.url).hostname;
		if (host === failedHost) throw new Error("Offline");
		if (host === "anchor.example") {
			if (markMode !== "none" && new URL(request.url).pathname === "/list")
				return new Response(JSON.stringify([middleId]), {
					headers: { "content-type": MediaType.Json },
				});
			return root.handleRequest(request);
		}
		if (host === "issuer.example") return issuer.handleRequest(request);
		if (host === "middle.example") return middle.handleRequest(request);
		if (host === "leaf.example") return leaf.handleRequest(request);
		return new Response(null, { status: 404 });
	};
	const diagnostics: unknown[] = [];
	const collection = {
		trustAnchors,
		options: {
			clock,
			httpClient,
			logger: {
				debug: (message: string, context?: Record<string, unknown>) => {
					diagnostics.push({ message, context });
				},
				info() {},
				warn() {},
				error() {},
			},
		},
	};
	const root = new TrustAnchor({
		entityId: anchor,
		storage,
		keyProvider: provider(rootKey),
		...(markMode !== "none"
			? {
					trustMarkIssuers: {
						one: markMode === "unauthorized" ? ["https://unauthorized.example"] : [issuerId],
					},
				}
			: {}),
		options: { clock },
		collection,
		metadata: {
			federation_entity: {
				federation_fetch_endpoint: `${anchor}/fetch`,
				federation_list_endpoint: `${anchor}/list`,
				federation_collection_endpoint: `${anchor}/collect?version=1`,
			},
		},
	});
	const middle = new Intermediate({
		entityId: middleId,
		authorityHints: [anchor],
		storage: middleStorage,
		keyProvider: provider(middleKey),
		options: { clock },
		collection,
		metadata: {
			federation_entity: {
				federation_fetch_endpoint: `${middleId}/fetch`,
				federation_list_endpoint: `${middleId}/list`,
				federation_collection_endpoint: `${middleId}/collect`,
			},
		},
	});
	const issuer = new Leaf({
		entityId: issuerId,
		authorityHints: [anchor],
		keyProvider: provider(issuerKey),
		options: { clock },
		metadata: { federation_entity: { display_name: "External issuer" } },
	});
	const mark = await signEntityStatement(
		{
			iss: issuerId,
			sub: markMode === "wrong-subject" ? middleId : leafId,
			iat: 1000,
			exp: markMode === "expired" ? 1100 : 3000,
			trust_mark_type: markMode === "wrong-type" ? "two" : "one",
		},
		new JwkSigner(issuerKey.privateKey),
		{ typ: "trust-mark+jwt" },
	);
	const leaf = new Leaf({
		entityId: leafId,
		authorityHints: [middleId],
		keyProvider: provider(leafKey),
		...(markMode !== "none" ? { trustMarks: [{ trust_mark_type: "one", trust_mark: mark }] } : {}),
		options: { clock },
		collection,
		metadata: {
			federation_entity: { federation_collection_endpoint: `${leafId}/collect` },
			oauth_resource: { resource: leafId, resource_name: "API", "resource_name#en": "English API" },
		},
	});
	if (markMode !== "none")
		await storage.subordinates.add({
			entityId: issuerId,
			jwks: { keys: [issuerKey.publicKey] },
			createdAt: now,
			updatedAt: now,
		});
	await storage.subordinates.add({
		entityId: middleId,
		jwks: { keys: [middleKey.publicKey] },
		isIntermediate: true,
		createdAt: now,
		updatedAt: now,
	});
	await middleStorage.subordinates.add({
		entityId: leafId,
		jwks: { keys: [leafKey.publicKey] },
		createdAt: now,
		updatedAt: now,
	});
	return {
		root,
		middle,
		leaf,
		storage,
		middleStorage,
		collection,
		rootKey,
		diagnostics,
		leafKey,
		httpClient,
		requests: () => requests,
		fail: (host: string) => {
			failedHost = host;
		},
	};
}

export default async function entityCollectionTests(QUnit: QUnit): Promise<void> {
	QUnit.module("Entity Collection Draft 01", () => {
		QUnit.test("metadata and extensible schemas enforce wire types", (assert) => {
			assert.true(
				FederationEntityMetadataSchema.safeParse({ federation_collection_endpoint: endpoint })
					.success,
			);
			for (const url of ["http://example.com/collect", `${endpoint}#`, `${endpoint}#fragment`])
				assert.false(
					FederationEntityMetadataSchema.safeParse({ federation_collection_endpoint: url }).success,
				);
			assert.true(
				EntityCollectionResponseSchema.safeParse({
					entities: [],
					last_updated: -0.5,
					extension: true,
				}).success,
			);
			assert.true(
				EntityCollectionResponseSchema.safeParse({
					entities: [
						{
							entity_id: leafId,
							entity_types: ["custom"],
							entity_infos: { custom: { extension: true } },
						},
					],
				}).success,
			);
			for (const bad of [
				{},
				{ entities: [{}] },
				{ entities: [], last_updated: Infinity },
				{ entities: [{ entity_id: leafId, entity_infos: { custom: { keywords: "wrong" } } }] },
			])
				assert.false(EntityCollectionResponseSchema.safeParse(bad).success);
			for (const locale of ["en", "en-US", "zh-Hant", "x-private", "i-klingon"])
				assert.true(EntityCollectionRequestSchema.safeParse({ locale: [locale] }).success);
			for (const locale of ["*", "en_US", "", "en-!"])
				assert.false(EntityCollectionRequestSchema.safeParse({ locale: [locale] }).success);
		});

		QUnit.test(
			"standalone and hosted responders apply all anchor selection rules",
			async (assert) => {
				const f = await seed();
				const standalone = new EntityCollectionService({
					trustAnchors: f.trustAnchors,
					store: f.store,
					options: { clock: f.clock },
				});
				assert.false((await standalone.query()).ok);
				assert.equal((await query(standalone, { trustAnchor: anchor })).entities.length, 3);
				const identified = new EntityCollectionService({
					trustAnchors: f.trustAnchors,
					store: f.store,
					responder: { entityId: leafId, isTrustAnchor: false },
				});
				assert.deepEqual(await query(identified), { entities: [] });
				assert.equal((await query(f.service)).entities.length, 2);
				const unsupported = await f.service.query({ trustAnchor: other });
				assert.false(unsupported.ok);
				if (!unsupported.ok) assert.equal(unsupported.error.code, "invalid_trust_anchor");
				assert.equal(
					(await f.service.handleRequest(new Request(`${endpoint}&trust_anchor=${other}`))).status,
					404,
				);
			},
		);

		QUnit.test(
			"pagination retains snapshots, binds requests, and allows changed page sizes",
			async (assert) => {
				const f = await seed();
				const first = await query(f.service, { limit: 1 });
				assert.equal(first.entities[0]?.entity_id, "https://a.example");
				assert.ok(first.next);
				await f.store.publish({ ...f.snapshot, id: "second", lastUpdated: 1600, entries: [] });
				const remaining = await query(f.service, { from: first.next, limit: 2 });
				assert.deepEqual(
					remaining.entities.map((entity) => entity.entity_id),
					["https://b.example", "https://c.example"],
				);
				assert.equal(remaining.last_updated, -0.5);
				assert.notOk(remaining.next);
				assert.false((await f.service.query({ from: first.next, query: "different" })).ok);
				assert.false((await f.service.query({ from: "unknown" })).ok);
				f.setNow(now + 901);
				assert.false((await f.service.query({ from: first.next })).ok);
				assert.deepEqual((await query(f.service)).entities, []);
			},
		);

		QUnit.test("omitted, capped, zero, and malformed limits", async (assert) => {
			const f = await seed();
			assert.equal((await query(f.service)).entities.length, 2);
			assert.equal((await query(f.service, { limit: 1000 })).entities.length, 2);
			const zero = await query(f.service, { limit: 0 });
			assert.deepEqual(zero.entities, []);
			assert.ok(zero.next);
			assert.equal(
				(await query(f.service, { from: zero.next, limit: 1 })).entities[0]?.entity_id,
				"https://a.example",
			);
			for (const limit of [-1, 0.5, Infinity, Number.MAX_SAFE_INTEGER + 1])
				assert.false((await f.service.query({ limit })).ok);
		});

		QUnit.test(
			"OR types, AND verified marks, and case-insensitive query compose",
			async (assert) => {
				const f = await seed();
				const all = await query(f.service, { entityType: ["custom_type", "openid_provider"] });
				assert.equal(all.entities.length, 2);
				assert.equal(
					(await query(f.service, { trustMarkType: ["one", "two"] })).entities.length,
					1,
				);
				assert.equal((await query(f.service, { trustMarkType: ["unknown"] })).entities.length, 0);
				assert.equal(
					(await query(f.service, { entityType: ["custom_type"], query: "B DEUTSCH" })).entities[0]
						?.entity_id,
					"https://b.example",
				);
				const first = await query(f.service, { trustMarkType: ["one"], limit: 1 });
				f.setNow(2000);
				assert.equal((await query(f.service, { trustMarkType: ["one"] })).entities.length, 0);
				assert.false(
					(await f.service.query({ trustMarkType: ["one"], limit: 1, from: first.next })).ok,
				);
			},
		);

		QUnit.test(
			"claim projections and locales retain only requested available values",
			async (assert) => {
				const f = await seed();
				const result = await query(f.service, {
					entityType: ["openid_provider"],
					entityClaims: ["entity_infos", "entity_types"],
					infoClaims: ["display_name"],
					locale: ["EN", "de"],
				});
				const entity = result.entities[0]!;
				assert.deepEqual(entity.entity_types, ["openid_provider", "federation_entity"]);
				assert.deepEqual(entity.entity_infos?.openid_provider, {
					display_name: "A",
					"display_name#en-US": "a English",
					"display_name#de": "a Deutsch",
				});
				assert.deepEqual(entity.entity_infos?.federation_entity, {});
				const minimal = (await query(f.service, { entityClaims: [] })).entities[0]!;
				assert.deepEqual(Object.keys(minimal), ["entity_id"]);
				assert.equal(minimal.entity_id, "https://a.example");
				assert.equal(
					Object.keys(
						(await query(f.service, { infoClaims: ["display_name"], locale: ["fr"] })).entities[0]!
							.entity_infos!.openid_provider!,
					).length,
					1,
				);
				for (const params of [{ entityClaims: ["unknown"] }, { infoClaims: ["unknown"] }]) {
					const failed = await f.service.query(params);
					assert.false(failed.ok);
					if (!failed.ok) assert.equal(failed.error.code, "unsupported_claim");
				}
				assert.true((await f.service.query({ infoClaims: [...COLLECTION_INFO_CLAIMS] })).ok);
			},
		);

		QUnit.test(
			"HTTP GET and form POST preserve repetitions and fixed query components",
			async (assert) => {
				const f = await seed();
				const client: HttpClient = async (input, init) =>
					f.service.handleRequest(new Request(String(input), init));
				for (const method of ["GET", "POST"] as const) {
					const result = await fetchEntityCollection(
						endpoint,
						{
							entityType: ["openid_provider", "custom_type"],
							locale: ["en", "de"],
							entityClaims: ["entity_infos", "entity_types"],
						},
						{ httpClient: client, method },
					);
					assert.true(result.ok);
				}
				for (const [suffix, code] of [
					["&limit=one", "invalid_request"],
					["&limit=1&limit=2", "invalid_request"],
					["&info_claims=unknown", "unsupported_claim"],
				]) {
					const response = await f.service.handleRequest(new Request(`${endpoint}${suffix}`));
					assert.equal(response.status, 400);
					const body = (await response.json()) as Record<string, unknown>;
					assert.equal(body.error, code);
					assert.equal(typeof body.error_description, "string");
				}
				const badPost = await f.service.handleRequest(
					new Request(endpoint, {
						method: "POST",
						body: "{}",
						headers: { "content-type": "application/json" },
					}),
				);
				assert.equal(badPost.status, 400);
				const wrongMethod = await f.service.handleRequest(
					new Request(endpoint, { method: "DELETE" }),
				);
				assert.equal(wrongMethod.status, 405);
				assert.equal(
					typeof ((await wrongMethod.json()) as Record<string, unknown>).error_description,
					"string",
				);
			},
		);

		QUnit.test(
			"unknown GET and POST extensions leave filtering and validation unchanged",
			async (assert) => {
				const f = await seed();
				const expected = await query(f.service, {
					query: "https://a.example",
					entityClaims: ["entity_infos"],
					infoClaims: ["display_name"],
					locale: ["en"],
				});
				for (const method of ["GET", "POST"]) {
					const form = new URLSearchParams([
						["future_extension", "first"],
						["future_extension", "second"],
						["__proto__", "ignored"],
						["constructor", "ignored"],
						["query", "https://a.example"],
						["entity_claims", "entity_infos"],
						["info_claims", "display_name"],
						["locale", "en"],
					]);
					const request = (params: URLSearchParams) => {
						const url = new URL(endpoint);
						if (method === "GET")
							for (const [name, value] of params) url.searchParams.append(name, value);
						return new Request(url, {
							method,
							...(method === "POST" ? { body: params } : {}),
						});
					};
					const response = await f.service.handleRequest(request(form));
					assert.equal(response.status, 200, method);
					assert.deepEqual(await response.json(), expected, `${method}: same filtered projection`);
					for (const [name, value, code, status] of [
						["limit", "one", "invalid_request", 400],
						["info_claims", "unknown", "unsupported_claim", 400],
						["client_assertion", "invalid", "invalid_client", 401],
					] as const) {
						const invalid = new URLSearchParams(form);
						invalid.append(name, value);
						const rejected = await f.service.handleRequest(request(invalid));
						assert.equal(rejected.status, status, `${method}: ${name}`);
						assert.propContains(await rejected.json(), { error: code });
					}
				}
			},
		);

		QUnit.test(
			"mixed authentication permits anonymous POST but rejects supplied invalid credentials",
			async (assert) => {
				const f = await seed();
				const service = new EntityCollectionService({
					trustAnchors: f.trustAnchors,
					store: f.store,
					endpoint,
					responder: { entityId: anchor, isTrustAnchor: true },
					options: { clock: f.clock },
					authentication: {
						methods: ["none", "private_key_jwt"],
						receiverEntityId: anchor,
						getClientFederationJwks: async () => ({ keys: [f.key.publicKey] }),
					},
				});
				const client: HttpClient = async (input, init) =>
					service.handleRequest(new Request(String(input), init));
				assert.true(
					(await fetchEntityCollection(endpoint, {}, { httpClient: client, method: "POST" })).ok,
				);
				assert.false(
					(await fetchEntityCollection(endpoint, {}, { httpClient: client, clientAssertion: "" }))
						.ok,
				);
				assert.false(
					(
						await fetchEntityCollection(
							endpoint,
							{},
							{ httpClient: client, clientAssertion: "invalid" },
						)
					).ok,
				);
				const jwt = await signEntityStatement(
					{
						iss: leafId,
						sub: leafId,
						aud: anchor,
						iat: now,
						exp: 1800,
						jti: "unique-client-assertion",
					},
					new JwkSigner(f.key.privateKey),
					{ typ: "JWT" },
				);
				assert.true(
					(await fetchEntityCollection(endpoint, {}, { httpClient: client, clientAssertion: jwt }))
						.ok,
				);
				assert.equal(
					(await service.handleRequest(new Request(`${endpoint}&client_assertion_type=bad`)))
						.status,
					401,
				);
				assert.equal(
					(
						await service.handleRequest(
							new Request(`${endpoint}&client_assertion=invalid`, {
								method: "POST",
								headers: { "content-type": "application/x-www-form-urlencoded" },
								body: "",
							}),
						)
					).status,
					400,
					"misplaced credentials cannot fall back to anonymous POST",
				);
			},
		);

		QUnit.test(
			"response failures cancel unread streams and never follow redirects",
			async (assert) => {
				let cancelled = 0;
				for (const status of [301, 302, 303, 307, 308]) {
					let calls = 0;
					const result = await fetchEntityCollection(
						endpoint,
						{},
						{
							clientAssertion: "secret",
							httpClient: async (_url, init) => {
								calls++;
								assert.equal(init?.redirect, "manual");
								return new Response(
									new ReadableStream({
										cancel() {
											cancelled++;
										},
									}),
									{ status, headers: { location: "https://attacker.example" } },
								);
							},
						},
					);
					assert.false(result.ok);
					assert.equal(calls, 1);
				}
				assert.equal(cancelled, 5);
				for (const [body, contentType] of [
					["{}", "application/json"],
					["bad", "application/json"],
					["{}", "text/plain"],
				])
					assert.false(
						(
							await fetchEntityCollection(
								endpoint,
								{},
								{
									httpClient: async () =>
										new Response(body, { headers: { "content-type": contentType! } }),
								},
							)
						).ok,
					);
				assert.false(
					(
						await fetchEntityCollection(
							endpoint,
							{},
							{
								maxResponseBytes: 1,
								httpClient: async () =>
									new Response('{"entities":[]}', { headers: { "content-type": MediaType.Json } }),
							},
						)
					).ok,
				);
				const stalled = await fetchEntityCollection(
					endpoint,
					{},
					{
						httpTimeoutMs: 5,
						httpClient: async () =>
							new Response(
								new ReadableStream({
									cancel() {
										cancelled++;
									},
								}),
								{ headers: { "content-type": MediaType.Json } },
							),
					},
				);
				assert.false(stalled.ok);
				assert.equal(cancelled, 6);
			},
		);

		QUnit.test(
			"refresh traverses intermediates, maps metadata, and all hosts delegate to core",
			async (assert) => {
				const f = await federation();
				const refreshed = await f.root.collection!.refresh(anchor);
				assert.true(refreshed.ok, JSON.stringify(refreshed));
				const result = await query(f.root.collection!, { entityType: ["oauth_resource"] });
				assert.equal(result.entities.length, 1);
				assert.equal(result.entities[0]?.entity_infos?.oauth_resource?.display_name, "API");
				assert.equal(
					result.entities[0]?.entity_infos?.oauth_resource?.["display_name#en"],
					"English API",
				);
				const afterRefresh = f.requests();
				await query(f.root.collection!);
				assert.equal(f.requests(), afterRefresh, "queries do not crawl");
				assert.strictEqual(f.root.collection!.store, f.storage.collections);
				for (const entity of [f.middle, f.leaf]) {
					await entity.collection!.store.publish(
						(await f.root.collection!.store.getCurrent(anchor))!,
					);
					assert.deepEqual(await query(entity.collection!), { entities: [] });
					assert.deepEqual(
						await query(entity.collection!, { trustAnchor: anchor }),
						await query(f.root.collection!, { trustAnchor: anchor }),
					);
				}
				const request = new Request(`${leafId}/collect?trust_anchor=${encodeURIComponent(anchor)}`);
				assert.equal((await createLeafHandler(f.leaf)(request)).status, 200);
				const ec = decodeEntityStatement(await f.leaf.getEntityConfiguration());
				assert.true(ec.ok);
				if (ec.ok)
					assert.notOk(ec.value.payload.metadata?.federation_entity?.federation_fetch_endpoint);
				const statement = decodeEntityStatement(
					await f.root.getSubordinateStatement(entityId("https://middle.example")),
				);
				assert.true(statement.ok);
			},
		);

		QUnit.test(
			"failed, cancelled, and budget-limited refreshes preserve the preceding snapshot",
			async (assert) => {
				const f = await federation();
				assert.true((await f.root.collection!.refresh(anchor)).ok);
				const before = await f.root.collection!.store.getCurrent(anchor);
				f.fail("middle.example");
				assert.false((await f.root.collection!.refresh(anchor)).ok);
				assert.deepEqual(await f.root.collection!.store.getCurrent(anchor), before);
				const controller = new AbortController();
				controller.abort();
				assert.false((await f.root.collection!.refresh(anchor, { signal: controller.signal })).ok);
				assert.deepEqual(await f.root.collection!.store.getCurrent(anchor), before);
				const limited = new EntityCollectionService({
					...f.collection,
					store: f.root.collection!.store,
					options: { ...f.collection.options, maxTotalFetches: 1 },
				});
				assert.false((await limited.refresh(anchor)).ok);
				assert.deepEqual(await f.root.collection!.store.getCurrent(anchor), before);
			},
		);

		QUnit.test(
			"signed marks require an authorized issuer, correct binding, and current validity",
			async (assert) => {
				for (const mode of [
					"valid",
					"expired",
					"wrong-subject",
					"wrong-type",
					"unauthorized",
				] as const) {
					const f = await federation(mode);
					const refreshed = await f.root.collection!.refresh(anchor);
					assert.true(refreshed.ok, `${mode}: ${JSON.stringify(refreshed)}`);
					const response = await query(f.root.collection!, { trustMarkType: ["one"] });
					assert.equal(
						response.entities.length,
						mode === "valid" ? 1 : 0,
						`${mode}: ${JSON.stringify(f.diagnostics)}`,
					);
					if (mode === "valid") {
						assert.equal(response.entities[0]?.entity_id, leafId);
						assert.equal(response.entities[0]?.trust_marks?.[0]?.trust_mark_type, "one");
					}
				}
			},
		);

		QUnit.test(
			"cycles terminate and invalid attestations cannot introduce entities",
			async (assert) => {
				const f = await federation();
				await f.middleStorage.subordinates.add({
					entityId: anchor,
					jwks: { keys: [f.rootKey.publicKey] },
					createdAt: now,
					updatedAt: now,
				});
				assert.true((await f.root.collection!.refresh(anchor)).ok);
				assert.equal((await query(f.root.collection!)).entities.length, 2);
				await f.middleStorage.subordinates.update(leafId, {
					jwks: { keys: [f.rootKey.publicKey] },
				});
				await f.storage.cache.clear();
				assert.true((await f.root.collection!.refresh(anchor)).ok);
				assert.equal(
					(await query(f.root.collection!, { entityType: ["oauth_resource"] })).entities.length,
					0,
				);
				const limited = new EntityCollectionService({ ...f.collection, maxEntities: 1 });
				assert.false((await limited.refresh(anchor)).ok);
			},
		);

		QUnit.test(
			"byte caps paginate whole entries without dropping requested claims",
			async (assert) => {
				const f = await seed();
				const service = new EntityCollectionService({
					trustAnchors: f.trustAnchors,
					store: f.store,
					responder: { entityId: anchor, isTrustAnchor: true },
					options: { clock: f.clock, maxResponseBytes: 600 },
				});
				const page = await query(service);
				assert.equal(page.entities.length, 1);
				assert.ok(page.next);
				assert.deepEqual(
					page.entities[0]?.entity_infos,
					(await query(f.service)).entities[0]?.entity_infos,
				);
				const tiny = new EntityCollectionService({
					trustAnchors: f.trustAnchors,
					store: f.store,
					responder: { entityId: anchor, isTrustAnchor: true },
					options: { clock: f.clock, maxResponseBytes: 100 },
				});
				assert.false((await tiny.query()).ok);
			},
		);

		QUnit.test(
			"strict authentication rejects replay, wrong audience, and incomplete assertions",
			async (assert) => {
				const f = await seed();
				const service = new EntityCollectionService({
					trustAnchors: f.trustAnchors,
					store: f.store,
					responder: { entityId: anchor, isTrustAnchor: true },
					options: { clock: f.clock, clockSkewSeconds: 0 },
					authentication: {
						methods: ["private_key_jwt"],
						receiverEntityId: anchor,
						allowedAlgorithms: ["ES256"],
						getClientFederationJwks: async () => ({ keys: [f.key.publicKey] }),
					},
				});
				const httpClient: HttpClient = async (input, init) =>
					service.handleRequest(new Request(String(input), init));
				assert.false((await fetchEntityCollection(endpoint, {}, { httpClient })).ok);
				for (const extra of [
					{ aud: other },
					{ exp: 1000 },
					{ jti: "" },
					{ iat: 2000 },
					{ sub: other },
				]) {
					const jwt = await signEntityStatement(
						{
							iss: leafId,
							sub: leafId,
							aud: anchor,
							iat: now,
							exp: 2000,
							jti: crypto.randomUUID(),
							...extra,
						},
						new JwkSigner(f.key.privateKey),
						{ typ: "JWT" },
					);
					assert.false(
						(await fetchEntityCollection(endpoint, {}, { httpClient, clientAssertion: jwt })).ok,
						JSON.stringify(extra),
					);
				}
				const jwt = await signEntityStatement(
					{ iss: leafId, sub: leafId, aud: anchor, exp: 2000, jti: crypto.randomUUID() },
					new JwkSigner(f.key.privateKey),
					{ typ: "JWT" },
				);
				assert.true(
					(await fetchEntityCollection(endpoint, {}, { httpClient, clientAssertion: jwt })).ok,
				);
				assert.false(
					(await fetchEntityCollection(endpoint, {}, { httpClient, clientAssertion: jwt })).ok,
				);
			},
		);

		QUnit.test(
			"request bodies are bounded and cancellation cannot hang a handler",
			async (assert) => {
				const f = await seed();
				const service = new EntityCollectionService({
					trustAnchors: f.trustAnchors,
					options: { httpTimeoutMs: 5 },
				});
				let cancelled = false;
				const stalled = new Request(endpoint, {
					method: "POST",
					headers: { "content-type": "application/x-www-form-urlencoded" },
					body: new ReadableStream({
						cancel() {
							cancelled = true;
						},
					}),
					...({ duplex: "half" } as RequestInit),
				});
				assert.equal((await service.handleRequest(stalled)).status, 400);
				assert.true(cancelled);
				assert.equal(
					(
						await service.handleRequest(
							new Request(endpoint, {
								method: "POST",
								headers: { "content-type": "application/x-www-form-urlencoded" },
								body: "a".repeat(65537),
							}),
						)
					).status,
					400,
				);
				assert.equal(
					(await service.handleRequest(new Request(`${endpoint}&query=${"a".repeat(65537)}`)))
						.status,
					400,
				);
			},
		);

		QUnit.test("expired evidence and unsupported anchors remain isolated", async (assert) => {
			const f = await seed();
			const service = new EntityCollectionService({
				trustAnchors: new Map([...f.trustAnchors, [other, f.trustAnchors.get(anchor)!]]),
				store: f.store,
				options: { clock: f.clock },
			});
			const unavailable = await service.query({ trustAnchor: other });
			assert.false(unavailable.ok);
			if (!unavailable.ok) assert.equal(unavailable.error.code, "temporarily_unavailable");
			const first = await query(f.service, { limit: 1 });
			assert.false((await service.query({ trustAnchor: other, from: first.next })).ok);
			f.setNow(5000);
			assert.equal((await query(f.service)).entities.length, 0);
		});

		QUnit.test("receiver identity and claim support cannot be misrepresented", async (assert) => {
			const f = await seed();
			const service = new EntityCollectionService({
				trustAnchors: f.trustAnchors,
				authentication: { methods: ["none"], receiverEntityId: leafId },
			});
			assert.deepEqual(await query(service), { entities: [] });
			for (const endpoint of ["", "http://example.com/collect", "https://example.com/collect#"])
				assert.throws(
					() => new EntityCollectionService({ trustAnchors: f.trustAnchors, endpoint }),
				);
			assert.throws(
				() =>
					new EntityCollectionService({
						trustAnchors: f.trustAnchors,
						responder: { entityId: anchor, isTrustAnchor: true },
						authentication: { methods: ["none"], receiverEntityId: leafId },
					}),
			);
			const invalidClaim = await f.service.query({ entityClaims: ["entity_types#en"] });
			assert.false(invalidClaim.ok);
			if (!invalidClaim.ok) assert.equal(invalidClaim.error.code, "unsupported_claim");
		});

		QUnit.test(
			"snapshot/cursor capacity and detached reads protect stored state",
			async (assert) => {
				const f = await seed();
				const snapshot = (await f.store.getCurrent(anchor))!;
				snapshot.entries[0]!.entity.entity_infos!.openid_provider!.display_name = "mutated";
				assert.equal(
					(await query(f.service)).entities[0]?.entity_infos?.openid_provider?.display_name,
					"A",
				);
				const limited = new MemoryEntityCollectionStore({
					clock: f.clock,
					maxSnapshots: 1,
					maxCursors: 1,
				});
				await limited.publish(f.snapshot);
				await limited.publish({ ...f.snapshot, id: "replacement" });
				assert.notOk(await limited.getSnapshot("first"));
				assert.equal((await limited.getCurrent(anchor))?.id, "replacement");
				assert.throws(
					() => new EntityCollectionService({ trustAnchors: f.trustAnchors, maxPageSize: 0 }),
				);
			},
		);
	});
}
