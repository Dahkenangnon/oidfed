import type QUnit from "qunit";
import {
	type AuthorityConfig,
	Intermediate,
	TrustAnchor,
} from "../../../packages/authority/src/index.js";
import {
	assertPositiveTtlSeconds,
	buildEntityConfigurationPayload,
	composeEntityMetadata,
	decodeEntityStatement,
	type EntityRole,
	entityId,
	isStoredTrustMarkEligible,
	signTrustMark,
	signTrustMarkDelegation,
	type TrustMarkRecord,
} from "../../../packages/core/src/index.js";
import { Leaf } from "../../../packages/leaf/src/index.js";
import {
	OAuthClientRole,
	OAuthResourceRole,
	OidcProviderRole,
} from "../../../packages/oidc/src/index.js";
import { WalletProviderRole } from "../../../packages/wallet/src/index.js";
import { memoryStorage } from "../../storage-fixtures.js";
import {
	FixtureCrypto,
	fixtureHostConfig,
	generateSigningKey,
	PurposeBindingsFixture,
	SigningEntryFixture,
	testEngine,
} from "../fixtures/software-crypto.js";

const prototypeName = "__proto__";
const subject = entityId("https://subject.example");
const anchor = entityId("https://anchor.example");
function deferred() {
	let resolve!: () => void;
	const promise = new Promise<void>((done) => {
		resolve = done;
	});
	return { promise, resolve };
}
async function signing() {
	const keys = await generateSigningKey("ES256");
	const signer = new SigningEntryFixture({ ...keys.privateKey, kid: "ownership" });
	const publicJwk = { ...keys.publicKey, kid: "ownership" };
	return { signer, publicJwk, crypto: new FixtureCrypto({ signer, publicJwk }) };
}
function metadata() {
	return {
		federation_entity: {
			federation_fetch_endpoint: `${anchor}/fetch`,
			federation_list_endpoint: `${anchor}/list`,
		},
		example: { nested: { values: ["original"] }, shared: "host" },
	};
}

export default (q: QUnit) => {
	q.module("configuration ownership", () => {
		q.test(
			"queued subordinate writes capture inputs and preserve transactional semantics",
			async (t) => {
				const { publicJwk } = await signing();
				const storage = memoryStorage({ engine: testEngine });
				const gate = deferred();
				const entered = deferred();
				const blocking = storage.transaction(async () => {
					entered.resolve();
					await gate.promise;
				});
				await entered.promise;
				const record = {
					entityId: subject,
					jwks: { keys: [publicJwk] },
					createdAt: 1,
					updatedAt: 1,
					metadata: { example: { values: ["captured"] } },
				};
				const added = storage.subordinate.register(record);
				record.entityId = "invalid" as typeof subject;
				record.metadata.example.values.push("later");
				const updates = { metadata: { example: { values: ["update"] } } };
				const updated = storage.subordinate.update(subject, updates, 1500);
				updates.metadata.example.values.push("later");
				gate.resolve();
				await Promise.all([blocking, added, updated]);
				t.deepEqual((await storage.subordinate.fetch(subject))?.metadata, {
					example: { values: ["update"] },
				});
				t.notOk(await storage.subordinate.fetch("invalid" as typeof subject));
				await t.rejects(storage.subordinate.register(record), /Entity Identifier/);
				await t.rejects(
					storage.subordinate.register({ ...record, entityId: subject }),
					/already exists/,
				);
				await t.rejects(storage.subordinate.update(anchor, {}, 1500), /not found/);
				await t.rejects(
					storage.transaction(async (tx) => {
						await tx.subordinate.remove(subject);
						throw new Error("rollback");
					}),
					/rollback/,
				);
				t.ok(await storage.subordinate.fetch(subject), "rollback preserves the record");
				await storage.subordinate.update(
					subject,
					{ metadata: { example: { repaired: true } } },
					1500,
				);
				t.deepEqual(
					(await storage.subordinate.fetch(subject))?.metadata,
					{ example: { repaired: true } },
					"queue continues after errors",
				);
			},
		);

		q.test("both Trust Mark adapters capture queued issuance and retain idempotency", async (t) => {
			const { signer } = await signing();
			const jwt = await signTrustMark({
				issuer: anchor,
				subject,
				trustMarkType: "example",
				signer,
				noExpiry: true,
				clock: { now: () => 1 },
			});
			for (const store of [
				memoryStorage({ trustMarks: true }),
				memoryStorage({ engine: testEngine, trustMarks: true }),
			]) {
				const gate = deferred();
				const entered = deferred();
				const blocking = store.transaction(async () => {
					entered.resolve();
					await gate.promise;
				});
				await entered.promise;
				const record = { jwt, subject, trustMarkType: "example", issuedAt: 1, active: true };
				const issued = store.trustMark!.issue!(record);
				record.active = false;
				gate.resolve();
				await Promise.all([blocking, issued]);
				t.true((await store.trustMark!.status(jwt))!.active);
				await store.trustMark!.issue!(record);
				t.true(
					(await store.trustMark!.status(jwt))!.active,
					"duplicate issue does not replace the record",
				);
			}
		});

		q.test("composition keeps open property names and replaces whole parameter values", (t) => {
			const before = Object.getOwnPropertyDescriptors(Object.prototype);
			const base = JSON.parse(
				'{"__proto__":{"constructor":{"values":[1]}},"toString":{"value":1}}',
			);
			const result = composeEntityMetadata(base, { toString: { value: { replacement: true } } });
			base[prototypeName].constructor.values.push(2);
			t.true(Object.hasOwn(result, "__proto__"));
			t.equal(
				JSON.stringify(result[prototypeName]),
				JSON.stringify({ constructor: { values: [1] } }),
			);
			t.equal(JSON.stringify(result.toString), JSON.stringify({ value: { replacement: true } }));
			const after = Object.getOwnPropertyDescriptors(Object.prototype);
			t.deepEqual(Object.keys(after), Object.keys(before));
			for (const name of Object.keys(before)) {
				for (const field of [
					"value",
					"get",
					"set",
					"enumerable",
					"configurable",
					"writable",
				] as const)
					t.strictEqual(after[name]?.[field], before[name]?.[field]);
			}
			t.throws(() => composeEntityMetadata({ invalid: [] }), /must be an object/);
			t.deepEqual(composeEntityMetadata(Object.create({ inherited: { value: true } })), {});
		});

		q.test("hosts own metadata and initialize each role once before composition", async (t) => {
			const { crypto } = await signing();
			for (const kind of ["leaf", "anchor", "intermediate"] as const) {
				const supplied = kind === "leaf" ? { example: metadata().example } : metadata();
				const original = structuredClone(supplied);
				let initialized = 0;
				const role: EntityRole = {
					type: "example",
					metadata: { shared: "role" },
					initialize() {
						initialized++;
						this.metadata.generated = ["ready"];
					},
				};
				const config = {
					entityId: anchor,
					crypto,
					metadata: supplied,
					roles: [role],
					authorityHints: [subject] as const,
					storage: memoryStorage({ engine: testEngine }),
				};
				const host =
					kind === "leaf"
						? await Leaf.create(fixtureHostConfig(config))
						: kind === "anchor"
							? await TrustAnchor.create(fixtureHostConfig(config as AuthorityConfig))
							: await Intermediate.create(
									fixtureHostConfig({
										...config,
										metadata: supplied as AuthorityConfig["metadata"],
									}),
								);
				t.deepEqual(supplied, original, "construction leaves caller metadata unchanged");
				supplied.example.nested.values.push("changed");
				role.metadata.generated = ["changed"];
				const decoded = decodeEntityStatement(await host.getEntityConfiguration());
				if (!decoded.ok) throw new Error(decoded.error.description);
				t.deepEqual(decoded.value.payload.metadata?.example, {
					nested: { values: ["original"] },
					shared: "role",
					generated: ["ready"],
				});
				t.equal(initialized, 1);
			}
		});

		q.test("Leaf publishes special entity type and role names as own properties", async (t) => {
			const { crypto } = await signing();
			const input = JSON.parse(
				'{"__proto__":{"retained":true},"constructor":{"retained":true},"toString":{"retained":true},"hasOwnProperty":{"retained":true}}',
			);
			const leaf = await Leaf.create(
				fixtureHostConfig({
					entityId: subject,
					authorityHints: [anchor],
					crypto,
					metadata: input,
					roles: [{ type: "__proto__", metadata: { role: true } }],
				}),
			);
			const decoded = decodeEntityStatement(await leaf.getEntityConfiguration());
			if (!decoded.ok) throw new Error(decoded.error.description);
			for (const name of Object.keys(input))
				t.true(Object.hasOwn(decoded.value.payload.metadata!, name));
			t.deepEqual(decoded.value.payload.metadata?.[prototypeName], { retained: true, role: true });
		});

		q.test("OIDC and wallet roles detach metadata and resource keys", async (t) => {
			const { signer, publicJwk, crypto } = await signing();
			const input = { custom: { values: ["original"] } };
			const client = new OAuthClientRole({
				metadata: input,
				signing: new PurposeBindingsFixture({ requestObjectSigner: signer }),
			});
			const wallet = new WalletProviderRole({ metadata: input });
			const jwks = { keys: [publicJwk] };
			const resource = new OAuthResourceRole({ metadata: input, jwks });
			input.custom.values.push("changed");
			jwks.keys.length = 0;
			for (const role of [client, wallet, resource])
				t.deepEqual(role.metadata.custom, { values: ["original"] });
			t.equal((resource.metadata.jwks as typeof jwks).keys.length, 1);
			const opInput = { client_registration_types_supported: ["explicit"] };
			const op = new OidcProviderRole({
				metadata: opInput,
				trustAnchors: new Map([[anchor, { jwks: { keys: [publicJwk] } }]]),
			});
			const host = await Leaf.create(
				fixtureHostConfig({
					entityId: subject,
					authorityHints: [anchor],
					crypto,
					metadata: {},
					roles: [op],
				}),
			);
			t.notOk(Object.hasOwn(opInput, "federation_registration_endpoint"));
			const decoded = decodeEntityStatement(await host.getEntityConfiguration());
			if (!decoded.ok) throw new Error(decoded.error.description);
			t.equal(
				decoded.value.payload.metadata?.openid_provider?.federation_registration_endpoint,
				`${subject}/registration`,
			);
		});

		q.test(
			"statement TTLs fail at construction while finite fractional lifetimes remain available",
			async (t) => {
				const { crypto, publicJwk, signer } = await signing();
				for (const value of [0, -1, NaN, Infinity, -Infinity, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
					await t.rejects(
						(async () =>
							await Leaf.create(
								fixtureHostConfig({
									entityId: subject,
									authorityHints: [anchor],
									crypto,
									metadata: { example: {} },
									entityConfigurationTtlSeconds: value,
								}),
							))(),
						/positive.*safe integer/,
					);
					for (const field of ["entityConfigurationTtlSeconds", "subordinateStatementTtlSeconds"])
						await t.rejects(
							(async () =>
								await TrustAnchor.create(
									fixtureHostConfig({
										entityId: anchor,
										crypto,
										storage: memoryStorage({ engine: testEngine }),
										metadata: metadata(),
										[field]: value,
									}),
								))(),
							/positive.*safe integer/,
						);
				}
				for (const value of [0, -1, NaN, Infinity, -Infinity]) {
					for (const field of ["trustMarkTtlSeconds", "subordinateEventsTtlSeconds"])
						await t.rejects(
							(async () =>
								await TrustAnchor.create(
									fixtureHostConfig({
										entityId: anchor,
										crypto,
										storage: memoryStorage({ engine: testEngine }),
										metadata: metadata(),
										[field]: value,
									}),
								))(),
							/positive and finite/,
						);
				}
				assertPositiveTtlSeconds(0.5, "ttl", "finite");
				await TrustAnchor.create(
					fixtureHostConfig({
						entityId: anchor,
						crypto,
						storage: memoryStorage({ engine: testEngine }),
						metadata: metadata(),
						trustMarkTtlSeconds: 0.5,
						subordinateEventsTtlSeconds: 0.5,
					}),
				);
				const jwt = await signTrustMark({
					issuer: anchor,
					subject,
					trustMarkType: "example",
					signer,
					ttlSeconds: 0.5,
					clock: { now: () => 1 },
				});
				const decoded = decodeEntityStatement(jwt);
				if (!decoded.ok) throw new Error(decoded.error.description);
				t.equal(decoded.value.payload.exp, 1.5);
				t.throws(
					() =>
						buildEntityConfigurationPayload({
							entityId: subject,
							metadata: {},
							jwks: { keys: [publicJwk] },
							issuedAt: Number.MAX_VALUE,
							ttlSeconds: 1,
						}),
					/expiration/,
				);
			},
		);

		q.test(
			"core and authority storage agree on delegation eligibility before newest selection",
			async (t) => {
				const { signer, publicJwk } = await signing();
				const authority = memoryStorage({ engine: testEngine, trustMarks: true });
				const standalone = memoryStorage({ trustMarks: true });
				await authority.subordinate.register({
					entityId: subject,
					jwks: { keys: [publicJwk] },
					createdAt: 1,
					updatedAt: 1,
				});
				const delegation = await signTrustMarkDelegation({
					issuer: anchor,
					subject: anchor,
					trustMarkType: "example",
					signer,
					clock: { now: () => 2 },
					ttlSeconds: 8,
				});
				const oldJwt = await signTrustMark({
					issuer: anchor,
					subject,
					trustMarkType: "example",
					signer,
					clock: { now: () => 1 },
					ttlSeconds: 100,
				});
				const newJwt = await signTrustMark({
					issuer: anchor,
					subject,
					trustMarkType: "example",
					signer,
					clock: { now: () => 2 },
					ttlSeconds: 100,
					delegation,
				});
				const old: TrustMarkRecord = {
					jwt: oldJwt,
					issuedAt: 1,
					expiresAt: 101,
					active: true,
					subject,
					trustMarkType: "example",
				};
				const replacement: TrustMarkRecord = { ...old, jwt: newJwt, issuedAt: 2, expiresAt: 102 };
				for (const store of [standalone.trustMark, authority.trustMark!]) {
					await store.issue(old);
					await store.issue(replacement);
				}
				for (const [at, expected] of [
					[0, false],
					[1, true],
					[2, true],
					[10, true],
					[101, false],
				] as const) {
					t.equal(await standalone.trustMark!.hasAny(subject, at), expected);
					t.equal(
						(await authority.subordinate.list({ trustMarked: true, validAt: at })).items.length > 0,
						expected,
					);
				}
				t.false(
					isStoredTrustMarkEligible(replacement, 1.5),
					"future issuance/delegation is ineligible",
				);
				t.false(isStoredTrustMarkEligible({ ...old, active: false }, 10));
				for (const store of [standalone.trustMark, authority.trustMark!]) {
					t.equal(
						(await store.valid("example", subject, 2))?.jwt,
						newJwt,
						"eligible newer mark is selected",
					);
					t.equal(
						(await store.valid("example", subject, 10))?.jwt,
						oldJwt,
						"expired newer delegation does not hide the older mark",
					);
				}
			},
		);
	});
};
