import type QUnit from "qunit";
import { MemoryStorageAdapter } from "../../../packages/authority/src/index.js";
import {
	entityId,
	generateSigningKey,
	JwkSigner,
	MemoryFederationKeyProvider,
	MemoryTrustMarkStore,
	signTrustMark,
} from "../../../packages/core/src/index.js";

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
	});
};
