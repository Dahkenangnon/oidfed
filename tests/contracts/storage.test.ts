import assert from "node:assert/strict";
import { test } from "node:test";
import {
	assertStorageCapabilities,
	assertStorageView,
	entityId,
	InvalidStorageRecordError,
	MemoryFederationStorage,
	parseStoragePayload,
	parseStoredSubordinateEvents,
	parseStoredTrustMark,
	parseSubordinateRecord,
	storageSnapshot,
	storageTransaction,
	TrustMarkRecordSchema,
} from "@oidfed/core";
import { encodeBase64url, utf8Encode } from "@oidfed/crypto";
import { algorithmRegistry } from "../../docs/examples/custom-crypto.js";
import { STORED_PUBLIC_JWK, storedTrustMarkToken } from "../storage-fixtures.js";
import {
	type StorageContractFixture,
	verifyCollectionLimits,
	verifyStorageContract,
	verifyStoragePayloadSchemas,
} from "./storage-contract.js";

test("memory implementation satisfies all storage capability groups", async (t) => {
	const storage = new MemoryFederationStorage({
		namespace: "contract",
		clock: { now: () => fixture.now },
		maxReplayEntries: 2,
	});
	const fixture: StorageContractFixture = {
		now: 1000,
		async connect(namespace) {
			if (!storage.withNamespace) throw new Error("Expected namespace support");
			return storage.withNamespace(namespace);
		},
	};
	const sections = await verifyStorageContract(
		fixture,
		[
			"subordinate:read",
			"subordinate:write",
			"subordinateEvent:read",
			"subordinateEvent:write",
			"trustMark:read",
			"trustMark:write",
			"snapshot",
			"transaction",
			"entityCollection",
			"replay",
			"cache",
			"namespace",
		],
		false,
	);
	t.diagnostic(sections.join(", "));
});

test("memory Collection preserves cursors and current anchors at capacity", async () => {
	const storage = new MemoryFederationStorage({
		namespace: "collection-limits",
		clock: { now: () => fixture.now },
		collection: { maxSnapshots: 2, maxCursors: 1, retentionSeconds: 10 },
	});
	const fixture: StorageContractFixture = {
		now: 1000,
		async connect(namespace) {
			if (!storage.withNamespace) throw new Error("Expected namespace support");
			return storage.withNamespace(namespace);
		},
	};
	await verifyCollectionLimits(fixture);
});

test("the durable payload layout validates all nine kinds", verifyStoragePayloadSchemas);

test("record parsing preserves JSON extensions and rejects accessors, sparse data, and invalid public keys", async () => {
	const member = entityId("https://member.example");
	const record = {
		entityId: member,
		jwks: { keys: [STORED_PUBLIC_JWK] },
		createdAt: 1000,
		updatedAt: 1000,
	};
	assert.throws(
		() => parseSubordinateRecord({ ...record, constraints: { custom: new Date(0) } }),
		InvalidStorageRecordError,
	);
	assert.throws(
		() =>
			parseSubordinateRecord({
				...record,
				metadata: { oauth_client: { jwks: { keys: [{ ...STORED_PUBLIC_JWK, d: "private" }] } } },
			}),
		InvalidStorageRecordError,
	);
	const withConstraints = { ...record, constraints: { custom: { tier: 1 } } };
	assert.deepEqual(parseSubordinateRecord(withConstraints), withConstraints);
	let reads = 0;
	const event = {
		event: "example",
		iat: 1000,
		get note() {
			reads++;
			return "unread";
		},
	};
	assert.throws(() => parseStoredSubordinateEvents([event], "append"), InvalidStorageRecordError);
	assert.equal(reads, 0);
	assert.throws(
		() => parseStoredSubordinateEvents(new Array(1), "append"),
		InvalidStorageRecordError,
	);
	assert.throws(
		() => parseStoragePayload("mark", "a".repeat(64), new Array(1), "write"),
		InvalidStorageRecordError,
	);
	assert.deepEqual(
		parseStoredSubordinateEvents(
			[{ iat: 1000, event: "custom", event_description: undefined, note: ["kept"] }],
			"append",
		),
		[{ iat: 1000, event: "custom", note: ["kept"] }],
	);
	const storage = new MemoryFederationStorage({
		namespace: "cursor-input",
		clock: { now: () => 1000 },
	});
	assertStorageCapabilities(storage, ["entityCollection"]);
	await assert.rejects(
		storage.entityCollection.saveCursor("", {
			snapshotId: "snapshot",
			trustAnchor: member,
			context: "query",
			index: 1,
			expiresAt: 2000,
		}),
		InvalidStorageRecordError,
	);
});

test("stored Trust Marks apply signed syntax, framework profiles and delegation identity", () => {
	const subject = entityId("https://member.example");
	const mark = { subject, trustMarkType: "example", issuedAt: 1000, expiresAt: 2000, active: true };
	const [header, payload, signature] = storedTrustMarkToken(mark).split(".");
	const encode = (value: unknown) => encodeBase64url(utf8Encode(JSON.stringify(value)));
	assert.throws(
		() => parseStoredTrustMark({ ...mark, jwt: [header, payload, ""].join(".") }),
		InvalidStorageRecordError,
	);
	const withHeader = (header: unknown) => ({
		...mark,
		jwt: [encode(header), payload, signature].join("."),
	});
	assert.throws(
		() => parseStoredTrustMark(withHeader({ alg: "ES256", typ: "trust-mark+jwt" })),
		InvalidStorageRecordError,
	);
	const custom = withHeader({ alg: "ES256", typ: "profile-mark+jwt", kid: "key" });
	assert.equal(TrustMarkRecordSchema.safeParse(custom).success, false);
	assert.throws(() => parseStoredTrustMark(custom), InvalidStorageRecordError);
	assert.deepEqual(
		parseStoredTrustMark(custom, {
			trustMarkProfiles: [{ typ: "profile-mark+jwt", trustMarkTypes: ["example"] }],
		}),
		custom,
	);
	const wrongDelegation = [header, payload, signature].join(".");
	const delegated = {
		...mark,
		jwt: [
			header,
			encode({
				iss: "https://issuer.example",
				sub: subject,
				trust_mark_type: mark.trustMarkType,
				iat: mark.issuedAt,
				exp: mark.expiresAt,
				delegation: wrongDelegation,
			}),
			signature,
		].join("."),
	};
	assert.throws(() => parseStoredTrustMark(delegated), InvalidStorageRecordError);
});

test("scoped helpers keep the configured registry and return only prepared public material", async () => {
	const storage = new MemoryFederationStorage({
		namespace: "custom-keys",
		algorithmRegistry,
		capabilities: ["subordinate:read", "subordinate:write", "transaction"],
	});
	const member = entityId("https://member.example");
	const key = {
		...STORED_PUBLIC_JWK,
		kty: "urn:example:jwk:profile-p256",
		u: STORED_PUBLIC_JWK.x,
		v: STORED_PUBLIC_JWK.y,
		privateFixtureMember: "not part of the public key",
	};
	await storageTransaction(storage, async (view) => {
		assertStorageView(view, ["subordinate:write"], "register test key");
		await view.subordinate.register({
			entityId: member,
			jwks: { keys: [key] },
			createdAt: 1000,
			updatedAt: 1000,
		});
	});
	const stored = await storageSnapshot(storage, async (view) => view.subordinate?.fetch(member), {
		allowTransaction: true,
	});
	assert.ok(stored);
	assert.equal(Object.hasOwn(stored.jwks.keys[0] ?? {}, "privateFixtureMember"), false);
	assert.equal(stored.jwks.keys[0]?.kty, key.kty);
});

test("Collection sorts detached snapshots and rejects unbound mark evidence", async () => {
	const storage = new MemoryFederationStorage({ namespace: "collection-evidence" });
	assertStorageCapabilities(storage, ["entityCollection"]);
	const trustAnchor = entityId("https://anchor.example");
	const a = entityId("https://a.example");
	const z = entityId("https://z.example");
	const expiresAt = 2000;
	const snapshot = {
		id: "ordered",
		trustAnchor,
		lastUpdated: 1000,
		entries: [
			{ entity: { entity_id: z }, expiresAt, verifiedMarks: [] },
			{ entity: { entity_id: a }, expiresAt, verifiedMarks: [] },
		],
	};
	await storage.entityCollection.publish(snapshot);
	assert.deepEqual(
		snapshot.entries.map((entry) => entry.entity.entity_id),
		[z, a],
	);
	assert.deepEqual(
		(await storage.entityCollection.current(trustAnchor))?.entries.map(
			(entry) => entry.entity.entity_id,
		),
		[a, z],
	);
	await assert.rejects(
		storage.entityCollection.publish({
			...snapshot,
			id: "unbound-mark",
			entries: [
				{
					entity: { entity_id: a },
					expiresAt,
					verifiedMarks: [
						{
							type: "example",
							jwt: storedTrustMarkToken({
								subject: a,
								trustMarkType: "example",
								issuedAt: 1000,
								expiresAt,
							}),
							expiresAt,
						},
					],
				},
			],
		}),
		InvalidStorageRecordError,
	);
});
