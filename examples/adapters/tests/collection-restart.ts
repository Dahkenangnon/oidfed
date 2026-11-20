import assert from "node:assert/strict";
import {
	assertStorageCapabilities,
	createTrustAnchorSet,
	EntityCollectionEntitySchema,
	EntityCollectionResponseSchema,
	EntityCollectionService,
	entityId,
} from "@oidfed/core";
import { createWebCryptoEngine } from "@oidfed/crypto/web";
import { openTestStorage, postgresUrl } from "./backend.js";

const [mode, namespace, cursor] = process.argv.slice(2);
assert.ok(mode === "seed" || mode === "verify");
assert.ok(namespace);
const trustAnchor = entityId("https://restart-anchor.example");
const first = entityId("https://a.example");
const second = entityId("https://b.example");
const replacement = entityId("https://replacement.example");
const endpoint = new URL("https://restart-anchor.example/collection");
endpoint.searchParams.set("trust_anchor", trustAnchor);
endpoint.searchParams.set("limit", "1");
const engine = createWebCryptoEngine();

assert.ok(postgresUrl, "Launch the PostgreSQL example database before running the suite");
await using database = await openTestStorage(postgresUrl, namespace);
const { storage } = database;
assertStorageCapabilities(storage, ["entityCollection"]);
const repository = storage.entityCollection;
const service = new EntityCollectionService({
	options: { engine, storage },
	trustAnchors: createTrustAnchorSet([{ entityId: trustAnchor, jwks: { keys: [] } }]),
});
const read = async (cursor?: string) => {
	const url = new URL(endpoint);
	if (cursor !== undefined) url.searchParams.set("from", cursor);
	const response = await service.handleRequest(new Request(url));
	assert.equal(response.status, 200, await response.clone().text());
	return EntityCollectionResponseSchema.parse(await response.json());
};
if (mode === "seed") {
	const now = Math.floor(Date.now() / 1000);
	const entry = (id: string) => ({
		entity: EntityCollectionEntitySchema.parse({ entity_id: id }),
		verifiedMarks: [],
		expiresAt: now + 600,
	});
	await repository.publish({
		id: "original",
		trustAnchor,
		lastUpdated: now,
		entries: [entry(first), entry(second)],
	});
	const page = await read();
	assert.deepEqual(page.entities, [{ entity_id: first }]);
	assert.ok(typeof page.next === "string");
	await repository.publish({
		id: "replacement",
		trustAnchor,
		lastUpdated: now + 1,
		entries: [entry(replacement)],
	});
	console.log(page.next);
} else {
	assert.ok(cursor);
	const current = await read();
	const continuation = await read(cursor);
	assert.deepEqual(current.entities, [{ entity_id: replacement }]);
	assert.deepEqual(continuation.entities, [{ entity_id: second }]);
	assert.ok(typeof current.last_updated === "number");
	assert.equal(continuation.last_updated, current.last_updated - 1);
	assert.equal(continuation.next, undefined);
	console.log("PostgreSQL: continued the exact Collection page after restart");
}
