import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { test } from "node:test";
import {
	assertStorageCapabilities,
	assertStorageView,
	entityId,
	InvalidStorageRecordError,
	MemoryFederationStorage,
	storageTransaction,
} from "@oidfed/core";
import { Pool } from "pg";
import {
	type StorageContractFixture,
	verifyCollectionLimits,
	verifyStorageContract,
} from "../../../tests/contracts/storage-contract.js";
import { STORED_PUBLIC_JWK, storedTrustMarkToken } from "../../../tests/storage-fixtures.js";
import { provisionPostgresStorage } from "../postgres.js";
import { openTestStorage, postgresUrl } from "./backend.js";

const durableCapabilities = [
	"subordinate:read",
	"subordinate:write",
	"subordinateEvent:read",
	"subordinateEvent:write",
	"trustMark:read",
	"trustMark:write",
	"transaction",
	"snapshot",
	"entityCollection",
	"replay",
	"namespace",
] as const;

test("PostgreSQL preserves long exact namespace and record identities", async () => {
	assert.ok(postgresUrl);
	const long = Array.from({ length: 1400 }, (_, i) =>
		String.fromCodePoint(0x4e00 + ((i * 7919) % 18000)),
	).join("");
	const namespace = randomUUID() + long;
	const subject = entityId(`https://member.example/${long}`);
	const otherSubject = entityId(`${subject}x`);
	const record = {
		entityId: subject,
		jwks: { keys: [STORED_PUBLIC_JWK] },
		entityTypes: ["openid_provider"],
		createdAt: 10,
		updatedAt: 10,
	};
	const memory = new MemoryFederationStorage({ namespace, capabilities: durableCapabilities });
	await using first = await openTestStorage(postgresUrl, namespace);
	await using second = await openTestStorage(postgresUrl, `${namespace}x`);
	assertStorageCapabilities(memory, ["subordinate:read", "subordinate:write"]);
	for (const storage of [memory, first.storage, second.storage]) {
		await storage.subordinate.register(record);
		assert.deepEqual(await storage.subordinate.fetch(subject), record);
		assert.equal(await storage.subordinate.fetch(otherSubject), undefined);
	}
	await first.storage.subordinate.register({ ...record, entityId: otherSubject });
	assert.equal(await second.storage.subordinate.fetch(otherSubject), undefined);
	const listed = await first.storage.subordinate.list();
	assert.deepEqual(
		listed.items.map(({ entityId }) => entityId),
		[subject, otherSubject],
	);
});

test("opportunistic cleanup failure preserves independent writes and explicit errors", async () => {
	assert.ok(postgresUrl);
	let clockReads = 0;
	const warnings: string[] = [];
	await using db = await openTestStorage(postgresUrl, randomUUID(), {
		now() {
			clockReads++;
			return NaN;
		},
		logger: {
			debug() {},
			info() {},
			warn(message) {
				warnings.push(message);
				throw new Error("Logger unavailable");
			},
			error() {},
		},
	});
	const record = {
		entityId: entityId("https://member.example"),
		jwks: { keys: [STORED_PUBLIC_JWK] },
		createdAt: 10,
		updatedAt: 10,
	};
	await db.storage.subordinate.register(record);
	assert.deepEqual(await db.storage.subordinate.fetch(record.entityId), record);
	assert.deepEqual(warnings, ["Could not prune expired PostgreSQL storage records"]);
	await assert.rejects(db.storage.subordinate.register(record), /Subordinate already exists/);
	assert.equal(clockReads, 1, "cleanup is attempted only once per interval");
	await assert.rejects(db.storage.pruneExpired(), /Invalid expired-record cleanup clock/);
	assert.equal(clockReads, 2);
});

test("guarded replay and bounded expiry cleanup preserve live records across clients", async () => {
	assert.ok(postgresUrl);
	const namespace = randomUUID();
	let now = 1000;
	const options = { now: () => now, cleanupIntervalSeconds: 0, maxReplayEntries: 2 };
	await using a = await openTestStorage(postgresUrl, namespace, options);
	await using b = await openTestStorage(postgresUrl, namespace, options);
	await using other = await openTestStorage(postgresUrl, `${namespace}-other`, options);
	const claim = { issuer: "issuer", audience: "receiver", expiresAt: 1010 };
	const claims = await Promise.allSettled(
		[a, b, a].map((client, index) =>
			client.storage.replay?.useJti({ ...claim, jti: String(index) }),
		),
	);
	assert.equal(claims.filter((result) => result.status === "fulfilled" && result.value).length, 2);
	assert.equal(claims.filter((result) => result.status === "rejected").length, 1);
	assert.equal(await other.storage.replay?.useJti({ ...claim, jti: "other" }), true);
	const anchor = entityId("https://anchor.example");
	const cursor = {
		snapshotId: "snapshot",
		trustAnchor: anchor,
		context: "query",
		index: 1,
		expiresAt: 1010,
	};
	await a.storage.entityCollection.saveCursor("expired", cursor);
	await a.storage.entityCollection.saveCursor("live", { ...cursor, expiresAt: 1100 });
	const accepted = claims.findIndex((result) => result.status === "fulfilled" && result.value);
	now = 1010;
	const renewed = { ...claim, jti: String(accepted), expiresAt: 1100 };
	assert.equal(
		await b.storage.replay?.useJti(renewed),
		true,
		"reuse an expired key before pruning",
	);
	assert.deepEqual(
		await Promise.all([a.storage.pruneExpired(1), b.storage.pruneExpired(1)]),
		[1, 1],
	);
	assert.equal(await a.storage.pruneExpired(1), 0);
	assert.equal(await other.storage.pruneExpired(1), 1, "cleanup is scoped to the exact namespace");
	await using reopened = await openTestStorage(postgresUrl, namespace, options);
	assert.equal(await reopened.storage.replay?.useJti(renewed), false);
	assert.equal(await reopened.storage.entityCollection.cursor("expired"), undefined);
	assert.equal((await reopened.storage.entityCollection.cursor("live"))?.expiresAt, 1100);
});

test("expiry cleanup leaves capacity for cursors while expired replay claims remain", async () => {
	assert.ok(postgresUrl);
	const namespace = randomUUID();
	let now = 1000;
	const options = { now: () => now, cleanupIntervalSeconds: 0 };
	await using db = await openTestStorage(postgresUrl, namespace, options);
	await using replica = await openTestStorage(postgresUrl, namespace, options);
	await using other = await openTestStorage(postgresUrl, `${namespace}-other`, options);
	const anchor = entityId("https://anchor.example");
	const cursor = {
		snapshotId: "snapshot",
		trustAnchor: anchor,
		context: "query",
		index: 0,
		expiresAt: 1005,
	};
	await db.storage.entityCollection.saveCursor("oldest", cursor);
	await db.storage.entityCollection.saveCursor("expired", { ...cursor, expiresAt: 1020 });
	await db.storage.entityCollection.saveCursor("live", { ...cursor, expiresAt: 1100 });
	await other.storage.entityCollection.saveCursor("expired", cursor);
	for (let i = 0; i < 5; i++) {
		assert.equal(
			await db.storage.replay?.useJti({
				issuer: "issuer",
				audience: "receiver",
				jti: String(i),
				expiresAt: 1010 + i,
			}),
			true,
		);
	}
	now = 1030;
	assert.equal(await db.storage.pruneExpired(1), 1);
	await db.seedRaw("collectionCursor", "oldest", {
		id: "oldest",
		value: { ...cursor, expiresAt: 1100 },
	});
	assert.equal(await replica.storage.pruneExpired(2), 2);
	await db.seedRaw("collectionCursor", "expired", {
		id: "expired",
		value: { ...cursor, expiresAt: 1100 },
	});
	assert.equal(await db.storage.pruneExpired(9), 4, "unused cursor allowance goes to replay");
	assert.equal(await other.storage.pruneExpired(9), 1);
	assert.equal((await db.storage.entityCollection.cursor("live"))?.expiresAt, 1100);
});

test("provisioning reports an earlier layout without altering it", async (t) => {
	assert.ok(postgresUrl);
	const admin = new Pool({ connectionString: postgresUrl });
	t.after(() => admin.end());
	const database = `legacy_${randomUUID().replaceAll("-", "")}`;
	await admin.query(`CREATE DATABASE ${database}`);
	const url = new URL(postgresUrl);
	url.pathname = `/${database}`;
	const legacy = new Pool({ connectionString: url.toString() });
	t.after(() => legacy.end());
	await legacy.query(`CREATE SCHEMA oidfed;
		CREATE TABLE oidfed.oidfed_storage_guard (namespace text PRIMARY KEY);
		INSERT INTO oidfed.oidfed_storage_guard VALUES ('existing')`);
	await assert.rejects(provisionPostgresStorage(legacy), /requires migration/);
	assert.deepEqual((await legacy.query("SELECT * FROM oidfed.oidfed_storage_guard")).rows, [
		{ namespace: "existing" },
	]);
});

test("PostgreSQL meets its declared storage contract", { timeout: 45_000 }, async (t) => {
	const url = postgresUrl;
	assert.ok(url, "Launch the PostgreSQL example database before running the suite");
	const clients: AsyncDisposable[] = [];
	const disconnect = async () => {
		await Promise.all(clients.splice(0).map((client) => client[Symbol.asyncDispose]()));
	};
	t.after(disconnect);
	let provisioned = false;
	const connect = async (namespace: string, options?: Parameters<typeof openTestStorage>[2]) => {
		const client = await openTestStorage(url, namespace, options, !provisioned);
		clients.push(client);
		provisioned = true;
		return client.storage;
	};
	const fixture: StorageContractFixture = {
		now: 1000,
		disconnect,
		connect: (namespace) => connect(namespace, { now: () => fixture.now, maxReplayEntries: 2 }),
	};
	const sections = await verifyStorageContract(fixture, durableCapabilities, true);
	const limits = {
		now: fixture.now,
		connect: (namespace: string) =>
			connect(namespace, {
				now: () => limits.now,
				collection: { maxSnapshots: 2, maxCursors: 1, retentionSeconds: 10 },
			}),
	};
	await verifyCollectionLimits(limits);

	const live = await connect(randomUUID());
	assertStorageCapabilities(live, ["replay", "entityCollection", "namespace"]);
	const now = Date.now() / 1000;
	const expired = {
		issuer: "test-issuer",
		audience: "test-receiver",
		jti: "clock",
		expiresAt: now - 1,
	};
	assert.equal(await live.replay.useJti(expired), false);
	assert.equal(await live.replay.useJti({ ...expired, expiresAt: now + 60 }), true);
	assert.equal(await live.replay.useJti({ ...expired, expiresAt: now + 60 }), false);

	const same = live.withNamespace(live.namespace);
	const other = live.withNamespace(randomUUID());
	const anchor = entityId("https://anchor.example");
	const snapshot = { id: "original", trustAnchor: anchor, lastUpdated: now, entries: [] };
	await live.entityCollection.publish(snapshot);
	assert.deepEqual(await same.entityCollection?.current(anchor), snapshot);
	assert.equal(await other.entityCollection?.current(anchor), undefined);
	assert.equal(other[Symbol.asyncDispose], undefined);
	await using corrupt = await openTestStorage(url, randomUUID(), undefined, false);
	assertStorageCapabilities(corrupt.storage, ["replay"]);
	const key = "a".repeat(64);
	await assert.rejects(corrupt.seedRaw("replay", key, { key, expiresAt: String(now + 60) }), {
		code: "23514",
	});
	await corrupt.seedRaw("collectionCurrent", anchor, { id: snapshot.id });
	await assert.rejects(corrupt.storage.entityCollection.current(anchor), InvalidStorageRecordError);
	const secondAnchor = entityId("https://other-anchor.example");
	assertStorageCapabilities(corrupt.storage, ["entityCollection", "subordinate:write"]);
	const otherSnapshot = { ...snapshot, id: "other-snapshot", trustAnchor: secondAnchor };
	await corrupt.storage.entityCollection.publish(otherSnapshot);
	const wrongAnchor = entityId("https://wrong-anchor.example");
	await corrupt.seedRaw("collectionCurrent", wrongAnchor, otherSnapshot.id);
	await assert.rejects(
		corrupt.storage.entityCollection.current(wrongAnchor),
		InvalidStorageRecordError,
	);
	await assert.rejects(
		corrupt.storage.entityCollection.publish({
			...snapshot,
			id: "replacement",
			trustAnchor: wrongAnchor,
		}),
		InvalidStorageRecordError,
	);
	assert.deepEqual(await corrupt.storage.entityCollection.current(secondAnchor), otherSnapshot);
	const badSubject = entityId("https://invalid-key.example");
	await corrupt.seedRaw("subordinate", badSubject, {
		entityId: badSubject,
		jwks: { keys: [] },
		createdAt: 1000,
		updatedAt: 1000,
	});
	await assert.rejects(
		corrupt.storage.subordinate.update(badSubject, { jwks: { keys: [STORED_PUBLIC_JWK] } }, 1100),
		InvalidStorageRecordError,
	);

	const enlarged = await connect(randomUUID(), { maxCompactBytes: 800_000 });
	assertStorageCapabilities(enlarged, ["trustMark:write", "subordinate:write"]);
	const issuer = "https://issuer.example";
	const subject = entityId("https://mark-subject.example");
	const mark = {
		subject,
		trustMarkType: "example",
		issuedAt: 1000,
		expiresAt: 2000,
		active: true,
	};
	const jwt = storedTrustMarkToken(mark, issuer, "a".repeat(410_000));
	await enlarged.subordinate.register({
		entityId: subject,
		jwks: { keys: [STORED_PUBLIC_JWK] },
		createdAt: 1000,
		updatedAt: 1000,
	});
	await enlarged.trustMark.issue({ ...mark, jwt });
	assert.deepEqual(
		(await enlarged.subordinate.list({ trustMarked: true, validAt: 1001 })).items.map(
			(record) => record.entityId,
		),
		[subject],
	);
	assert.equal((await enlarged.trustMark.candidates({ issuer })).length, 1);
	assert.equal((await enlarged.trustMark.valid(mark.trustMarkType, subject, 1001))?.jwt, jwt);
	await enlarged.trustMark.revoke(mark.trustMarkType, subject, 1100, issuer);
	assert.equal((await enlarged.trustMark.status(jwt))?.active, false);
	t.diagnostic(sections.join(", "));
});

test("scoped operations commit in order and stop before releasing the client", async () => {
	assert.ok(postgresUrl);
	await using database = await openTestStorage(postgresUrl, randomUUID());
	const { storage } = database;
	const issuer = entityId("https://authority.example");
	const subject = entityId("https://member.example");
	const record = {
		entityId: subject,
		jwks: { keys: [STORED_PUBLIC_JWK] },
		createdAt: 1000,
		updatedAt: 1000,
	};
	await storage.subordinate.register(record);
	await storageTransaction(storage, async (view) => {
		assertStorageView(view, ["subordinate:write", "subordinateEvent:write"], "Transaction test");
		await Promise.all([
			view.subordinate.update(subject, { isIntermediate: true }, 1100),
			view.subordinate.update(subject, { extensions: { patched: true } }, 1200),
			view.subordinateEvent.append(issuer, subject, [{ event: "first", iat: 1100 }]),
			view.subordinateEvent.append(issuer, subject, [{ event: "second", iat: 1100 }]),
		]);
	});
	assert.deepEqual(await storage.subordinateEvent.history(issuer, subject), [
		{ event: "first", iat: 1100 },
		{ event: "second", iat: 1100 },
	]);
	assert.deepEqual(await storage.subordinate.fetch(subject), {
		...record,
		isIntermediate: true,
		extensions: { patched: true },
		updatedAt: 1200,
	});

	const rolledBack = entityId("https://rolled-back.example");
	const rejected = entityId("https://rejected.example");
	await assert.rejects(
		storage.transaction(async (view) => {
			assertStorageView(view, ["subordinate:write"], "Rollback test");
			await view.subordinate.register({ ...record, entityId: rolledBack });
			await assert.rejects(
				view.subordinate.register({
					...record,
					entityId: rejected,
					extensions: { text: String.fromCharCode(0) },
				}),
				{ code: "22P05" },
			);
			return "callback completed";
		}),
		/rolled back/,
	);
	assert.equal(await storage.subordinate.fetch(rolledBack), undefined);

	const pending = entityId("https://pending.example");
	const queued = entityId("https://queued.example");
	let activeSettled = false;
	let queuedResult: "pending" | "resolved" | "rejected" = "pending";
	await assert.rejects(
		storage.transaction(async (view) => {
			assertStorageView(view, ["subordinate:write"], "Pending work test");
			const active = view.subordinate.register({ ...record, entityId: pending });
			void active.then(
				() => {
					activeSettled = true;
				},
				() => {
					activeSettled = true;
				},
			);
			void view.subordinate.register({ ...record, entityId: queued }).then(
				() => {
					queuedResult = "resolved";
				},
				() => {
					queuedResult = "rejected";
				},
			);
		}),
		/await its repository operations/,
	);
	assert.equal(activeSettled, true);
	assert.equal(queuedResult, "rejected");
	assert.equal(await storage.subordinate.fetch(pending), undefined);
	assert.equal(await storage.subordinate.fetch(queued), undefined);
});

test("replay samples the deadline again after database work", async () => {
	assert.ok(postgresUrl);
	let samples = 0;
	await using database = await openTestStorage(postgresUrl, randomUUID(), {
		now: () => (samples++ === 0 ? 1000 : 1001),
	});
	const { storage } = database;
	assertStorageCapabilities(storage, ["replay"]);
	const claim = {
		issuer: "issuer",
		audience: "audience",
		jti: "during-transaction",
		expiresAt: 1001,
	};
	assert.equal(await storage.replay.useJti(claim), false);
	assert.equal(samples, 2);
	assert.equal(await storage.replay.useJti({ ...claim, expiresAt: 1100 }), true);
	assert.equal(await storage.replay.useJti({ ...claim, expiresAt: 1100 }), false);
});

test("indexed listings match memory across sparse batches, Unicode cursors, and issuers", {
	timeout: 45_000,
}, async () => {
	assert.ok(postgresUrl);
	await using database = await openTestStorage(postgresUrl, randomUUID());
	const postgres = database.storage;
	const memory = new MemoryFederationStorage({ namespace: "listing-reference" });
	assertStorageCapabilities(memory, ["subordinate:read", "trustMark:write"]);
	const base = "https://member.example/";
	const prefix = "x".repeat(140);
	const supplementary = entityId(`${base}${prefix}/${String.fromCodePoint(0x10000)}`);
	const bmp = entityId(`${base}${prefix}/${String.fromCodePoint(0xe000)}`);
	const subjects = [
		...Array.from({ length: 130 }, (_, index) =>
			entityId(`${base}${String(index).padStart(3, "0")}`),
		),
		bmp,
		supplementary,
	];
	const issuer = entityId("https://issuer.example");
	const otherIssuer = entityId("https://other-issuer.example");
	const markType = "https://mark.example/example";
	const at = 2000;
	for (const storage of [postgres, memory]) {
		await storageTransaction(storage, async (view) => {
			assertStorageView(view, ["subordinate:write", "trustMark:write"], "Listing test fixtures");
			for (const [index, subject] of subjects.entries()) {
				const intermediate = index % 2 === 0;
				await view.subordinate.register({
					entityId: subject,
					jwks: { keys: [STORED_PUBLIC_JWK] },
					createdAt: 1000,
					updatedAt: 1000 + index,
					entityTypes: [intermediate ? "federation_entity" : "oauth_client"],
					...(intermediate ? { isIntermediate: true } : {}),
				});
				const mark = {
					subject,
					trustMarkType: markType,
					issuedAt: 1000,
					expiresAt: index < 130 ? 1500 : 3000,
					active: true,
				};
				await view.trustMark.issue({ ...mark, jwt: storedTrustMarkToken(mark, issuer) });
				if (subject === supplementary) {
					const newer = { ...mark, issuedAt: 1200 };
					await view.trustMark.issue({ ...newer, jwt: storedTrustMarkToken(newer, otherIssuer) });
					await view.trustMark.revoke(markType, subject, 1800, otherIssuer);
				}
			}
		});
	}
	const marks = { trustMarkType: markType, validAt: at };
	const first = await postgres.subordinate.list(marks, { limit: 1 });
	assert.deepEqual(first, await memory.subordinate.list(marks, { limit: 1 }));
	assert.deepEqual(
		first.items.map((record) => record.entityId),
		[supplementary],
	);
	assert.equal(first.nextCursor, bmp);
	assert.deepEqual(
		await postgres.subordinate.list(marks, { cursor: bmp, limit: 1 }),
		await memory.subordinate.list(marks, { cursor: bmp, limit: 1 }),
	);
	assert.deepEqual(
		await postgres.subordinate.list(
			{ entityTypes: ["oauth_client"], intermediate: false },
			{ updatedAfter: 1030, updatedBefore: 1040 },
		),
		await memory.subordinate.list(
			{ entityTypes: ["oauth_client"], intermediate: false },
			{ updatedAfter: 1030, updatedBefore: 1040 },
		),
	);
	assert.deepEqual(await postgres.subordinate.list(), await memory.subordinate.list());

	const markPage = await postgres.trustMark.listSubjects(markType, at, { limit: 1 });
	assert.deepEqual(markPage, await memory.trustMark.listSubjects(markType, at, { limit: 1 }));
	assert.equal(markPage.items[0]?.subject, supplementary);
	assert.equal(markPage.nextCursor, bmp);
	assert.deepEqual(
		await postgres.trustMark.listSubjects(markType, at, { cursor: bmp, limit: 1 }),
		await memory.trustMark.listSubjects(markType, at, { cursor: bmp, limit: 1 }),
	);
	const [revoked] = await postgres.trustMark.candidates({
		issuer: otherIssuer,
		subject: supplementary,
		trustMarkType: markType,
	});
	assert.equal(revoked?.active, false);
	assert.deepEqual(
		await postgres.trustMark.forSubject(supplementary, at),
		await memory.trustMark.forSubject(supplementary, at),
	);
	assert.deepEqual(
		await postgres.withNamespace(randomUUID()).trustMark?.candidates({ issuer }),
		[],
	);
});
