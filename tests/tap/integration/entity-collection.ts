import type QUnit from "qunit";
import { MemoryStorageAdapter, TrustAnchor } from "../../../packages/authority/src/index.js";
import {
	decodeEntityStatement,
	EntityCollectionEntitySchema,
	EntityCollectionResponseSchema,
	entityId,
	generateSigningKey,
	JwkSigner,
	MemoryFederationKeyProvider,
	ok,
} from "../../../packages/core/src/index.js";
import { createLeafHandler } from "../../../packages/leaf/src/handler.js";
import { Leaf } from "../../../packages/leaf/src/index.js";
import * as EntityCollectionFixture from "../fixtures/entity-collection.js";

export default function integrationTests(QUnit: QUnit): void {
	{
		const { anchor, leafId, query, federation } = EntityCollectionFixture;
		QUnit.module("Entity Collection Draft 01", () => {
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
					const request = new Request(
						`${leafId}/collect?trust_anchor=${encodeURIComponent(anchor)}`,
					);
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
		});
	}

	{
		const anchor = entityId("https://ta.example");
		QUnit.module("Collection regressions", () => {
			QUnit.test(
				"Authority and Leaf forward custom collection search and normalized inventory",
				async (assert) => {
					const key = await generateSigningKey("ES256");
					const keyProvider = new MemoryFederationKeyProvider({
						signer: new JwkSigner(key.privateKey),
						publicJwk: key.publicKey,
					});
					const trustAnchors = new Map([[anchor, { jwks: { keys: [key.publicKey] } }]]);
					for (const kind of ["authority", "leaf"]) {
						let searches = 0;
						const config = {
							entityId: anchor,
							keyProvider,
							metadata: {
								federation_entity: {
									federation_collection_endpoint: `${anchor}/collect`,
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
								options: { clock: { now: () => 1500 } },
								collector: async () =>
									ok([
										{
											entity: EntityCollectionEntitySchema.parse({
												entity_id: "https://op.example",
												entity_infos: { openid_provider: { display_name: "Campus" } },
											}),
											expiresAt: 3000,
										},
									]),
								queryMatcher: (query: string) => {
									searches++;
									return query === "academic";
								},
							},
						};
						const host =
							kind === "authority"
								? new TrustAnchor({ ...config, storage: new MemoryStorageAdapter() })
								: new Leaf({ ...config, authorityHints: [entityId("https://superior.example")] });
						assert.true((await host.collection!.refresh(anchor)).ok);
						for (const method of ["GET", "POST"]) {
							const params = new URLSearchParams({
								query: "academic",
								entity_type: "openid_provider",
								trust_anchor: anchor,
								entity_claims: "entity_id",
							});
							const request = new Request(
								`${anchor}/collect${method === "GET" ? `?${params}` : ""}`,
								{
									method,
									...(method === "POST"
										? {
												headers: { "content-type": "application/x-www-form-urlencoded" },
												body: params,
											}
										: {}),
								},
							);
							const response = await host.handleRequest(request);
							assert.equal(response.status, 200);
							assert.deepEqual(
								EntityCollectionResponseSchema.parse(await response.json()).entities,
								[EntityCollectionEntitySchema.parse({ entity_id: "https://op.example" })],
							);
						}
						assert.equal(searches, 2);
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
		});
	}
}
