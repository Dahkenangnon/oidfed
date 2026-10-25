import type QUnit from "qunit";
import { MemoryStorageAdapter, TrustAnchor } from "../../../packages/authority/src/index.js";
import {
	decodeEntityStatement,
	entityId,
	generateSigningKey,
	JwkSigner,
	MemoryFederationKeyProvider,
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
