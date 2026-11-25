import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { setTimeout } from "node:timers/promises";
import {
	assertStorageCapabilities,
	assertStorageView,
	EntityCollectionCursorCapacityError,
	type EntityId,
	type FederationStorage,
	InvalidStorageRecordError,
	parseStoragePayload,
	type StorageCapability,
	type StoragePayloadByKind,
	storageTransaction,
	type TransactionView,
} from "@oidfed/core";

export interface StorageContractFixture {
	connect(namespace: string): Promise<FederationStorage>;
	disconnect?(): Promise<void>;
	now: number;
}

const issuer = "https://authority.example";
const member = "https://member.example";
const other = "https://other.example";
const jwks = {
	keys: [
		{
			kty: "EC",
			kid: "test",
			crv: "P-256",
			x: "OUdYsCLIbES6cmG2MHFuXamZ60fem7Tkk7LPO3nX9QY",
			y: "7TjTIz97de-2yxmBudZuhUS-eP6egZSw3ZV_n4URxHQ",
		},
	],
};
const id = (value: string) => value as EntityId;
const record = {
	entityId: id(member),
	jwks,
	createdAt: 1000,
	updatedAt: 1000,
	metadata: { oauth_resource: { resource_name: "Original" } },
};
const jwt = [
	{ alg: "ES256", typ: "trust-mark+jwt", kid: "test" },
	{
		iss: issuer,
		sub: member,
		iat: 1000,
		exp: 4000,
		trust_mark_type: "https://marks.example/example",
	},
]
	.map((value) => Buffer.from(JSON.stringify(value)).toString("base64url"))
	.concat("AA")
	.join(".");
const mark = {
	jwt,
	subject: id(member),
	trustMarkType: "https://marks.example/example",
	issuedAt: 1000,
	expiresAt: 4000,
	active: true,
};

function required<T>(value: T | undefined): T {
	assert.notEqual(value, undefined);
	return value as T;
}

/** Exercise only declared groups after checking the example's promised minimum capability set. */
export async function verifyStorageContract(
	fixture: StorageContractFixture,
	minimum: readonly StorageCapability[],
	durable: boolean,
): Promise<readonly string[]> {
	const available = await fixture.connect(randomUUID());
	assertStorageCapabilities(available, minimum, "Storage contract minimum");
	const tested: string[] = [];
	const has = (capability: StorageCapability) => available.capabilities.includes(capability);
	const clients = async () => {
		const namespace = randomUUID();
		return {
			namespace,
			a: await fixture.connect(namespace),
			b: await fixture.connect(namespace),
			different: await fixture.connect(randomUUID()),
		};
	};

	if (has("subordinate:write")) {
		const { a, b, different } = await clients();
		assertStorageCapabilities(a, ["subordinate:write"]);
		const store = a.subordinate;
		await assert.rejects(
			store.register({ ...record, jwks: { keys: [{ ...required(jwks.keys[0]), d: "private" }] } }),
			InvalidStorageRecordError,
		);
		const extended = {
			...record,
			entityId: id("https://extension.example"),
			extensions: { app: { label: "kept" } },
		};
		await store.register(extended);
		assert.deepEqual(await store.fetch(extended.entityId), extended);
		await store.remove(extended.entityId);
		const another = required(b.subordinate);
		const input = structuredClone(record);
		const registered = required(store.register)(input);
		input.metadata.oauth_resource.resource_name = "Mutated input";
		await registered;
		const saved = required(await another.fetch(id(member)));
		assert.equal(
			saved.metadata?.oauth_resource &&
				Reflect.get(saved.metadata.oauth_resource as object, "resource_name"),
			"Original",
		);
		(saved.metadata as typeof input.metadata).oauth_resource.resource_name = "Mutated output";
		assert.deepEqual(await store.fetch(id(member)), record);
		assert.equal(await required(different.subordinate).fetch(id(member)), undefined);
		await assert.rejects(required(store.register)(record), /already exists/);
		await assert.rejects(required(store.remove)(id(other)), /not found/);
		await assert.rejects(required(store.update)(id(other), {}, 1200), /not found/);
		await required(store.register)({ ...record, entityId: id(other) });
		const page = await another.list(undefined, { limit: 1 });
		assert.equal(page.items[0]?.entityId, member);
		assert.equal(page.nextCursor, other);
		assert.deepEqual(
			(await another.list(undefined, { cursor: page.nextCursor ?? id(other) })).items.map(
				(item) => item.entityId,
			),
			[other],
		);
		tested.push("subordinates");
	}

	if (has("transaction") && has("subordinateEvent:write")) {
		const { a, b } = await clients();
		assertStorageCapabilities(a, ["transaction", "subordinate:write"]);
		await a.subordinate.register(record);
		const writes = (op: (tx: TransactionView) => Promise<void>) => a.transaction(op);
		const events = required(a.subordinateEvent);
		const list = () => required(b.subordinateEvent).history(id(issuer), id(member));
		const event = { event: "example", iat: 1200 };
		let leaked: TransactionView = {};
		await assert.rejects(
			writes(async (tx) => {
				assert.equal("cache" in tx, false);
				assertStorageView(tx, ["subordinate:write"], "Contract subordinate updates");
				await tx.subordinate.update(id(member), { isIntermediate: true }, 1200);
				assertStorageView(tx, ["subordinateEvent:write"], "Contract event append");
				await tx.subordinateEvent.append(id(issuer), id(member), [event]);
				throw new Error("abort");
			}),
			/abort/,
		);
		assert.deepEqual(await list(), []);
		assert.equal((await a.subordinate?.fetch(id(member)))?.isIntermediate, undefined);
		await writes(async (tx) => {
			leaked = tx;
			assertStorageView(tx, ["subordinateEvent:write"], "Contract event append");
			await tx.subordinateEvent.append(id(issuer), id(member), [event, event]);
			assertStorageView(tx, ["subordinate:write"], "Contract subordinate updates");
			await tx.subordinate.update(id(member), { isIntermediate: true }, 1200);
		});
		await assert.rejects(required(leaked.subordinate?.fetch)(id(member)), /closed/);
		assert.equal((await b.subordinate?.fetch(id(member)))?.updatedAt, 1200);
		await a.subordinate.remove(id(member));
		assert.deepEqual(await events.history(id(issuer), id(member)), [event, event]);
		assert.deepEqual(await list(), [event, event]);
		tested.push("transactions and events");
	}

	if (has("snapshot") && has("subordinate:write")) {
		const { a, b } = await clients();
		assertStorageCapabilities(a, ["subordinate:write"]);
		assertStorageCapabilities(b, ["subordinate:write"]);
		const read = a.readSnapshot;
		if (!read) throw new Error("Expected a read snapshot");
		let entered!: () => void;
		let proceed!: () => void;
		const ready = new Promise<void>((resolve) => {
			entered = resolve;
		});
		const release = new Promise<void>((resolve) => {
			proceed = resolve;
		});
		await a.subordinate.register(record);
		const pending = read.call(a, async (view) => {
			const repository = required(view.subordinate);
			assert.equal("register" in repository, false);
			assert.equal("replay" in view, false);
			const before = await repository.fetch(id(member));
			entered();
			await release;
			assert.deepEqual(await repository.fetch(id(member)), before);
		});
		await ready;
		try {
			await b.subordinate.update(id(member), { isIntermediate: true }, 1300);
		} finally {
			proceed();
		}
		await pending;
		assert.equal((await a.subordinate?.fetch(id(member)))?.isIntermediate, true);
		tested.push("consistent snapshot");
	}

	if (has("trustMark:write")) {
		const { a, b, namespace } = await clients();
		assertStorageCapabilities(a, ["trustMark:write"]);
		assertStorageCapabilities(b, ["trustMark:write"]);
		const ar = a.trustMark;
		const br = b.trustMark;
		assert.equal("checkRevision" in ar, false);
		const initial = await ar.revision();
		await assert.rejects(
			ar.issue({ ...mark, issuedAt: mark.issuedAt + 1 }),
			InvalidStorageRecordError,
		);
		assert.equal(await ar.revision(), initial);
		const decide = (storage: FederationStorage) => {
			if (!storage.transaction) throw new Error("Expected a transaction");
			return storage.transaction(async (view) => {
				assertStorageView(view, ["trustMark:write"], "Contract issue");
				if (!(await view.trustMark.checkRevision(initial))) return false;
				await view.trustMark.issue(mark);
				return true;
			});
		};
		assert.deepEqual((await Promise.all([decide(a), decide(b)])).sort(), [false, true]);
		const revision = await ar.revision();
		assert.notEqual(revision, initial);
		await required(br.issue)(mark);
		assert.equal(await ar.revision(), revision);
		await assert.rejects(
			required(br.revoke)(mark.trustMarkType, mark.subject, 1200, other),
			/not found/,
		);
		await required(br.revoke)(mark.trustMarkType, mark.subject, 1200, issuer);
		assert.notEqual(await ar.revision(), revision);
		assert.equal((await ar.status(jwt))?.active, false);
		assert.equal(await ar.status(`${jwt}A`), undefined);
		assert.equal((await ar.candidates({ issuer })).length, 1);
		assert.deepEqual(await br.candidates({ issuer: other }), []);
		if (ar.revokeExact && br.revokeExact) {
			const newMark = (iat: number) => ({
				...mark,
				issuedAt: iat,
				jwt: [
					jwt.split(".")[0],
					Buffer.from(
						JSON.stringify({
							iss: issuer,
							sub: member,
							iat,
							exp: mark.expiresAt,
							trust_mark_type: mark.trustMarkType,
						}),
					).toString("base64url"),
					"AA",
				].join("."),
			});
			const older = newMark(1100);
			const replacement = newMark(1150);
			await ar.issue(older);
			await br.issue(replacement);
			const prior = await ar.revision();
			await assert.rejects(br.revokeExact(older.jwt, 1220, other), /Trust Mark not found/);
			await assert.rejects(br.revokeExact(`${older.jwt}A`, 1220, issuer), /Trust Mark not found/);
			assert.equal(await ar.revision(), prior);
			await storageTransaction(b, async (view) => {
				assertStorageView(view, ["trustMark:write"], "Exact withdrawal contract");
				assert.ok(view.trustMark.revokeExact);
				await view.trustMark.revokeExact(older.jwt, 1230, issuer);
			});
			const withdrawn = await ar.revision();
			assert.notEqual(withdrawn, prior);
			await ar.revokeExact(older.jwt, 1240, issuer);
			assert.equal(await br.revision(), withdrawn);
			assert.equal((await ar.status(older.jwt))?.revokedAt, 1230);
			assert.equal((await ar.status(replacement.jwt))?.active, true);
			await required(a.readSnapshot).call(a, async (view) => {
				assert.equal("revokeExact" in required(view.trustMark), false);
			});
		}
		if (durable) {
			await fixture.disconnect?.();
			const reopened = await fixture.connect(namespace);
			assert.equal((await required(reopened.trustMark).status(jwt))?.active, false);
		}
		tested.push("Trust Mark exact status and write revision");
	}

	if (has("replay")) {
		const { a, b, different, namespace } = await clients();
		const aa = required(a.replay);
		const bb = required(b.replay);
		await assert.rejects(
			aa.useJti({ issuer, audience: member, jti: "", expiresAt: fixture.now + 10 }),
			InvalidStorageRecordError,
		);
		const value = { issuer, audience: member, jti: "contract", expiresAt: fixture.now + 1 };
		assert.deepEqual((await Promise.all([aa.useJti(value), bb.useJti(value)])).sort(), [
			false,
			true,
		]);
		assert.equal(await required(different.replay).useJti(value), true);
		assert.equal(await bb.useJti({ ...value, audience: other }), true);
		await assert.rejects(bb.useJti({ ...value, jti: "another" }), /capacity/i);
		assert.equal(await aa.useJti(value), false);
		fixture.now += 1;
		assert.equal(await bb.useJti(value), false);
		assert.equal(await aa.useJti({ ...value, expiresAt: fixture.now + 300 }), true);
		if (durable) {
			await fixture.disconnect?.();
			const reopened = await fixture.connect(namespace);
			assert.equal(
				await required(reopened.replay).useJti({ ...value, expiresAt: fixture.now + 300 }),
				false,
			);
		}
		tested.push("atomic replay");
	}

	if (has("cache")) {
		const { a, b, different } = await clients();
		const cache = required(b.cache);
		const isolated = required(different.cache);
		const claim = { issuer, audience: member, jti: "cache-contract", expiresAt: fixture.now + 100 };
		if (has("replay")) assert.equal(await required(a.replay).useJti(claim), true);
		const value = { keys: [{ kty: "EC" }], nullable: null, finite: 3 };
		await cache.set("shared-name", value, 60);
		await isolated.set("shared-name", true, 60);
		value.keys[0] = { kty: "changed" };
		const saved = required(await cache.get<typeof value>("shared-name"));
		assert.equal(saved.keys[0]?.kty, "EC");
		saved.keys[0] = { kty: "also changed" };
		assert.equal((await cache.get<typeof value>("shared-name"))?.keys[0]?.kty, "EC");
		await assert.rejects(cache.set("invalid", NaN, 60), /JSON/);
		await assert.rejects(cache.set("sparse", Array(2), 60), /JSON/);
		let reads = 0;
		const accessor = {
			get value() {
				reads++;
				return 42;
			},
		};
		await assert.rejects(cache.set("accessor", accessor, 60), /JSON/);
		assert.equal(reads, 0);
		await cache.clear();
		assert.equal(await cache.get("shared-name"), undefined);
		assert.equal(await isolated.get("shared-name"), true);
		await cache.set("short", 42, 0.02);
		fixture.now += 1;
		await setTimeout(60);
		assert.equal(await cache.get("short"), undefined);
		if (has("replay")) assert.equal(await required(b.replay).useJti(claim), false);
		tested.push("cache JSON, expiry, and scoped clear");
	}

	if (has("entityCollection")) {
		const { a, b, different } = await clients();
		const collection = required(b.entityCollection);
		const first = {
			id: "first",
			trustAnchor: id(issuer),
			lastUpdated: fixture.now,
			entries: [],
			extensions: { label: "kept" },
		};
		await assert.rejects(
			collection.publish({ ...first, lastUpdated: NaN }),
			InvalidStorageRecordError,
		);
		await assert.rejects(
			collection.saveCursor("invalid", {
				snapshotId: first.id,
				trustAnchor: id(issuer),
				context: "query",
				index: -1,
				expiresAt: fixture.now + 10,
			}),
			InvalidStorageRecordError,
		);
		await collection.publish(first);
		const second = { ...first, id: "second", lastUpdated: fixture.now + 1 };
		await required(a.entityCollection).publish(second);
		assert.deepEqual(await collection.current(id(issuer)), second);
		assert.deepEqual(await collection.snapshot(first.id), first);
		await assert.rejects(collection.publish(second), /unique/);
		assert.deepEqual(await collection.current(id(issuer)), second);
		const concurrent = ["third", "fourth"].map((name) => ({ ...first, id: name }));
		await Promise.all(
			concurrent.map((item, index) =>
				(index === 0 ? collection : required(a.entityCollection)).publish(item),
			),
		);
		const current = required(await collection.current(id(issuer)));
		assert.ok(concurrent.some((item) => item.id === current.id));
		assert.deepEqual(await collection.snapshot(current.id), current);
		for (const item of concurrent) assert.deepEqual(await collection.snapshot(item.id), item);
		const duplicate = { ...first, id: "concurrent-duplicate" };
		const outcomes = await Promise.allSettled([
			collection.publish(duplicate),
			required(a.entityCollection).publish(duplicate),
		]);
		assert.deepEqual(outcomes.map((result) => result.status).sort(), ["fulfilled", "rejected"]);
		assert.deepEqual(await collection.current(id(issuer)), duplicate);
		await collection.saveCursor("cursor", {
			snapshotId: first.id,
			trustAnchor: id(issuer),
			context: "query",
			index: 0,
			expiresAt: fixture.now + 1,
		});
		assert.equal(await different.entityCollection?.cursor("cursor"), undefined);
		assert.equal((await a.entityCollection?.cursor("cursor"))?.snapshotId, first.id);
		fixture.now += 1;
		assert.equal(await collection.cursor("cursor"), undefined);
		tested.push("collection pointer and cursor");
	}
	return tested;
}

/** Check bounded stores configured with 2 snapshots, 1 cursor, and 10 seconds of retention. */
export async function verifyCollectionLimits(fixture: StorageContractFixture): Promise<void> {
	const namespace = randomUUID();
	const a = required((await fixture.connect(namespace)).entityCollection);
	const b = required((await fixture.connect(namespace)).entityCollection);
	const first = { id: "first", trustAnchor: id(issuer), lastUpdated: fixture.now, entries: [] };
	const second = { ...first, id: "second" };
	await a.publish(first);
	await b.publish(second);
	fixture.now += 9;
	assert.deepEqual(await b.snapshot(first.id), first);
	fixture.now += 1;
	assert.equal(await b.snapshot(first.id), undefined);
	assert.deepEqual(await a.current(id(issuer)), second);

	const secondAnchor = { ...first, id: "other", trustAnchor: id(other) };
	const overflow = { ...first, id: "overflow", trustAnchor: id(member) };
	await a.publish(secondAnchor);
	await assert.rejects(b.publish(overflow), /capacity/);
	assert.equal(await a.snapshot(overflow.id), undefined);
	assert.equal(await b.current(id(member)), undefined);
	assert.deepEqual(await b.current(id(issuer)), second);
	assert.deepEqual(await b.current(id(other)), secondAnchor);

	const cursor = {
		snapshotId: second.id,
		trustAnchor: id(issuer),
		context: "query",
		index: 1,
		expiresAt: fixture.now + 10,
	};
	await b.saveCursor("live", cursor);
	const refreshed = { ...first, id: "refreshed" };
	await a.publish(refreshed);
	assert.deepEqual(await b.current(id(issuer)), refreshed);
	assert.deepEqual(await b.current(id(other)), secondAnchor);
	assert.equal(await a.snapshot(second.id), undefined);
	assert.deepEqual(await a.cursor("live"), cursor);
	await assert.rejects(a.publish(second), /unique/);
	await assert.rejects(b.saveCursor("next", cursor), EntityCollectionCursorCapacityError);
	assert.deepEqual(await a.cursor("live"), cursor);
	fixture.now += 10;
	await a.saveCursor("next", { ...cursor, snapshotId: refreshed.id, expiresAt: fixture.now + 10 });
	assert.equal(await b.cursor("live"), undefined);
	assert.equal((await b.cursor("next"))?.snapshotId, refreshed.id);
}

/** Check the nine persistent payload shapes without assuming a database client's API. */
export function verifyStoragePayloadSchemas(): void {
	const snapshot = { id: "snapshot", trustAnchor: id(issuer), lastUpdated: 1000, entries: [] };
	const key = "a".repeat(64);
	const eventId = JSON.stringify([issuer, member]);
	const rows = [
		["subordinate", member, record, { ...record, entityId: id(other) }],
		[
			"event",
			eventId,
			{ events: [{ iat: 1000, event: "registration", custom: { accepted: true } }] },
			{ events: [{ iat: 1000, event: "" }] },
		],
		["mark", key, [mark], [{ ...mark, active: "true" }]],
		["markRevision", "", "2", "02"],
		[
			"collectionSnapshot",
			snapshot.id,
			{ value: snapshot, order: "1" },
			{ value: snapshot, order: "0" },
		],
		["collectionCurrent", issuer, snapshot.id, null],
		[
			"collectionCursor",
			"cursor",
			{
				id: "cursor",
				value: {
					expiresAt: 2000,
					snapshotId: snapshot.id,
					trustAnchor: id(issuer),
					index: 1,
					context: "query",
				},
			},
			{ id: "other" },
		],
		["collectionSequence", "", "1", -1],
		["replay", key, { key, expiresAt: 2000 }, { key, expiresAt: "2000" }],
	] satisfies readonly (readonly [keyof StoragePayloadByKind, string, unknown, unknown])[];
	for (const [kind, id, good, bad] of rows)
		for (const operation of ["read", "write"] as const) {
			assert.deepEqual(parseStoragePayload(kind, id, good, operation), good);
			assert.throws(() => parseStoragePayload(kind, id, bad, operation), InvalidStorageRecordError);
		}
}
