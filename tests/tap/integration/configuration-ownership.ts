import type QUnit from "qunit";
import {
	type AuthorityConfig,
	Intermediate,
	MemoryStorageAdapter,
	TrustAnchor,
} from "../../../packages/authority/src/index.js";
import {
	composeEntityMetadata,
	decodeEntityStatement,
	type EntityRole,
	entityId,
	generateSigningKey,
	JwkSigner,
	MemoryFederationKeyProvider,
	MemoryTrustMarkStore,
	signTrustMark,
} from "../../../packages/core/src/index.js";
import { Leaf } from "../../../packages/leaf/src/index.js";
import {
	OAuthClientRole,
	OAuthResourceRole,
	OidcProviderRole,
	StaticProtocolSigningKeyProvider,
} from "../../../packages/oidc/src/index.js";
import { WalletProviderRole } from "../../../packages/wallet/src/index.js";

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
	const signer = new JwkSigner({ ...keys.privateKey, kid: "ownership" });
	const publicJwk = { ...keys.publicKey, kid: "ownership" };
	return { signer, publicJwk, keyProvider: new MemoryFederationKeyProvider({ signer, publicJwk }) };
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
				const storage = new MemoryStorageAdapter();
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
				const added = storage.subordinates.add(record);
				record.entityId = "invalid" as typeof subject;
				record.metadata.example.values.push("later");
				const updates = { metadata: { example: { values: ["update"] } } };
				const updated = storage.subordinates.update(subject, updates);
				updates.metadata.example.values.push("later");
				gate.resolve();
				await Promise.all([blocking, added, updated]);
				t.deepEqual((await storage.subordinates.get(subject))?.metadata, {
					example: { values: ["update"] },
				});
				t.notOk(await storage.subordinates.get("invalid" as typeof subject));
				await t.rejects(storage.subordinates.add(record), /Entity Identifier/);
				await t.rejects(
					storage.subordinates.add({ ...record, entityId: subject }),
					/already exists/,
				);
				await t.rejects(storage.subordinates.update(anchor, {}), /not found/);
				await t.rejects(
					storage.transaction(async (tx) => {
						await tx.subordinates.remove(subject);
						throw new Error("rollback");
					}),
					/rollback/,
				);
				t.ok(await storage.subordinates.get(subject), "rollback preserves the record");
				await storage.subordinates.update(subject, { metadata: { example: { repaired: true } } });
				t.deepEqual(
					(await storage.subordinates.get(subject))?.metadata,
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
				clock: { now: () => 1 },
			});
			for (const store of [
				new MemoryTrustMarkStore(),
				new MemoryStorageAdapter({ trustMarks: true }),
			]) {
				const gate = deferred();
				const entered = deferred();
				const blocking = store.transaction(async () => {
					entered.resolve();
					await gate.promise;
				});
				await entered.promise;
				const record = { jwt, subject, trustMarkType: "example", issuedAt: 1, active: true };
				const issued = store.trustMarks!.issue(record);
				record.active = false;
				gate.resolve();
				await Promise.all([blocking, issued]);
				t.true((await store.trustMarks!.getByJwt(jwt))!.active);
				await store.trustMarks!.issue(record);
				t.true(
					(await store.trustMarks!.getByJwt(jwt))!.active,
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
			const { keyProvider } = await signing();
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
					keyProvider,
					metadata: supplied,
					roles: [role],
					authorityHints: [subject],
					storage: new MemoryStorageAdapter(),
				};
				const host =
					kind === "leaf"
						? new Leaf(config)
						: kind === "anchor"
							? new TrustAnchor(config as AuthorityConfig)
							: new Intermediate(config as AuthorityConfig);
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
			const { keyProvider } = await signing();
			const input = JSON.parse(
				'{"__proto__":{"retained":true},"constructor":{"retained":true},"toString":{"retained":true},"hasOwnProperty":{"retained":true}}',
			);
			const leaf = new Leaf({
				entityId: subject,
				authorityHints: [anchor],
				keyProvider,
				metadata: input,
				roles: [{ type: "__proto__", metadata: { role: true } }],
			});
			const decoded = decodeEntityStatement(await leaf.getEntityConfiguration());
			if (!decoded.ok) throw new Error(decoded.error.description);
			for (const name of Object.keys(input))
				t.true(Object.hasOwn(decoded.value.payload.metadata!, name));
			t.deepEqual(decoded.value.payload.metadata?.[prototypeName], { retained: true, role: true });
		});

		q.test("OIDC and wallet roles detach metadata and resource keys", async (t) => {
			const { signer, publicJwk, keyProvider } = await signing();
			const input = { custom: { values: ["original"] } };
			const client = new OAuthClientRole({
				metadata: input,
				protocolKeyProvider: new StaticProtocolSigningKeyProvider({ requestObjectSigner: signer }),
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
			const host = new Leaf({
				entityId: subject,
				authorityHints: [anchor],
				keyProvider,
				metadata: {},
				roles: [op],
			});
			t.notOk(Object.hasOwn(opInput, "federation_registration_endpoint"));
			const decoded = decodeEntityStatement(await host.getEntityConfiguration());
			if (!decoded.ok) throw new Error(decoded.error.description);
			t.equal(
				decoded.value.payload.metadata?.openid_provider?.federation_registration_endpoint,
				`${subject}/registration`,
			);
		});
	});
};
