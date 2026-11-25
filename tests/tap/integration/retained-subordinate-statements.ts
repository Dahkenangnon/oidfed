/** Exercise Subordinate Statement issuance and retained serving through Authority hosts. */
import type QUnit from "qunit";
import {
	type AuthorityConfig,
	Intermediate,
	TrustAnchor,
} from "../../../packages/authority/src/index.js";
import {
	type CryptoContext,
	decodeSubordinateStatement,
	entityId,
	type JWKSet,
	JwtTyp,
	MediaType,
	signEntityStatement,
} from "../../../packages/core/src/index.js";
import { memoryStorage } from "../../storage-fixtures.js";
import {
	generateSigningKey,
	SigningEntryFixture,
	testEngine,
} from "../fixtures/software-crypto.js";

const issuer = entityId("https://retained.example");
const first = entityId("https://a.retained.example");
const second = entityId("https://b.retained.example");
const listUrl = `${issuer}/extended-list`;
const claims = "subordinate_statement,iat,exp,jwks,metadata_policy,constraints,example";

/** Set up one approved store, independent published keys, and a controllable renewal clock. */
async function fixture(kind: "anchor" | "intermediate", retained: boolean) {
	const [original, next] = await Promise.all([generateSigningKey(), generateSigningKey("ES384")]);
	const oldSigner = new SigningEntryFixture(original.privateKey);
	const newSigner = new SigningEntryFixture(next.privateKey);
	let signer = oldSigner;
	let published: JWKSet = oldSigner.publishedJwks;
	let now = 1_000;
	let signerOffline = false;
	let signerReads = 0;
	let keyReads = 0;
	let algorithms = ["ES256", "ES384"];
	const selectedLifetimes: string[] = [];
	const loaded: string[] = [];
	const approved = new Map<string, string>();
	let onLoad: ((id: string) => void) | undefined;
	const crypto: CryptoContext = {
		engine: testEngine,
		keyring: {
			async entry() {
				signerReads++;
				if (signerOffline) throw new Error("Custody unavailable");
				return { signer: signer.signer, publishedJwks: published };
			},
		},
		readPublishedFederationJwks() {
			keyReads++;
			return published;
		},
	};
	const config: Omit<AuthorityConfig, "trustMarkIssuers" | "trustMarkOwners"> = {
		entityId: issuer,
		crypto,
		storage: memoryStorage(),
		options: {
			clock: { now: () => now },
			allowedAlgorithmsForArtifact: () => algorithms,
		},
		metadata: {
			federation_entity: {
				federation_fetch_endpoint: `${issuer}/fetch`,
				federation_list_endpoint: `${issuer}/list`,
				federation_extended_list_endpoint: listUrl,
			},
		},
		subordinateStatementTtlSeconds: 120,
		subordinateLifetime(record) {
			selectedLifetimes.push(record.entityId);
			return record.entityId === first ? 30 : undefined;
		},
	};
	if (retained) {
		config.loadSubordinateStatement = (record, signal) => {
			if (!Object.isFrozen(record) || !Object.isFrozen(record.jwks.keys) || signal.aborted)
				throw new Error("Expected an immutable loader snapshot and an active signal");
			loaded.push(record.entityId);
			onLoad?.(record.entityId);
			return approved.get(record.entityId);
		};
	}
	const authority =
		kind === "anchor"
			? await TrustAnchor.create(config)
			: await Intermediate.create({ ...config, authorityHints: ["https://superior.example"] });
	const record = {
		entityId: first,
		jwks: { keys: [original.publicKey, next.publicKey] },
		metadataPolicy: { openid_relying_party: { organization_name: { value: "Approved" } } },
		constraints: { max_path_length: 1 },
		additionalClaims: { example: { a: 1, b: 2 } },
	};
	await authority.registerSubordinate(record);
	await authority.registerSubordinate({ ...record, entityId: second });
	return {
		authority,
		approved,
		config,
		record,
		loaded,
		selectedLifetimes,
		signerReads: () => signerReads,
		keyReads: () => keyReads,
		setNow(value: number) {
			now = value;
		},
		setOnLoad(load: (id: string) => void) {
			onLoad = load;
		},
		setSignerOffline(offline: boolean) {
			signerOffline = offline;
		},
		setAlgorithms(allowed: string[]) {
			algorithms = allowed;
		},
		rotate(overlap: boolean) {
			signer = newSigner;
			published = overlap
				? { keys: [original.publicKey, next.publicKey] }
				: newSigner.publishedJwks;
		},
		flagOldKeyRevoked() {
			published = {
				keys: [{ ...original.publicKey, revoked: { revoked_at: now } }, next.publicKey],
			};
		},
		fetch: (id = first) =>
			authority.handleRequest(new Request(`${issuer}/fetch?${new URLSearchParams({ sub: id })}`)),
		list: (requested: string, limit = "2") =>
			authority.handleRequest(
				new Request(
					`${listUrl}?${new URLSearchParams({ claims: requested, limit, audit_timestamps: "true" })}`,
				),
			),
		signFixture: (
			payload: Record<string, unknown>,
			key = oldSigner,
			typ: string = JwtTyp.EntityStatement,
		) => signEntityStatement(payload, key, { typ }),
		unrelatedSigner: async () => new SigningEntryFixture((await generateSigningKey()).privateKey),
	};
}

/** Decode the shape of a JWT produced by a real Authority fixture. */
function statement(jwt: string) {
	const decoded = decodeSubordinateStatement(jwt);
	if (!decoded.ok) throw new Error(decoded.error.description);
	return decoded.value.payload;
}

/** Extract the listing rows produced by a real Authority response. */
async function rows(response: Response): Promise<Record<string, unknown>[]> {
	const body = (await response.json()) as {
		immediate_subordinate_entities: Record<string, unknown>[];
	};
	return body.immediate_subordinate_entities;
}

export default function retainedSubordinateTests(qunit: QUnit): void {
	const { module, test } = qunit;
	module("integration / Retained Subordinate Statements", () => {
		for (const kind of ["anchor", "intermediate"] as const) {
			test(`${kind} uses per-record lifetimes for on-demand issuance and listing`, async (assert) => {
				const f = await fixture(kind, false);
				const fetched = await f.fetch();
				assert.strictEqual(fetched.status, 200);
				assert.strictEqual(statement(await fetched.text()).exp, 1_030);
				assert.strictEqual(statement(await (await f.fetch(second)).text()).exp, 1_120);
				f.selectedLifetimes.length = 0;
				const list = await f.list("subordinate_statement,iat,exp");
				assert.strictEqual(list.status, 200);
				for (const row of await rows(list)) {
					const payload = statement(String(row.subordinate_statement));
					assert.strictEqual(row.iat, payload.iat);
					assert.strictEqual(row.exp, payload.exp);
					assert.strictEqual(row.exp, row.id === first ? 1_030 : 1_120);
				}
				assert.deepEqual(f.selectedLifetimes, [first, second]);
			});

			test(`${kind} serves one approved artifact and can issue a replacement explicitly`, async (assert) => {
				const f = await fixture(kind, true);
				const saved = await f.authority.getSubordinateStatement(first);
				const payload = statement(saved);
				f.approved.set(first, saved);
				f.setNow(1_010);
				f.setSignerOffline(true);
				const before = f.signerReads();
				assert.strictEqual(await (await f.fetch()).text(), saved);
				const response = await f.list(claims, "1");
				assert.strictEqual(response.status, 200);
				const [row] = await rows(response);
				assert.deepEqual(row, {
					id: first,
					registered: 1_000,
					updated: 1_000,
					subordinate_statement: saved,
					iat: payload.iat,
					exp: payload.exp,
					jwks: payload.jwks,
					metadata_policy: payload.metadata_policy,
					constraints: payload.constraints,
					example: payload.example,
				});
				assert.deepEqual(f.loaded, [first, first], "load once for all requested listing claims");
				const [dates] = await rows(await f.list("iat,exp", "1"));
				assert.deepEqual(dates, {
					id: first,
					registered: 1_000,
					updated: 1_000,
					iat: 1_000,
					exp: 1_030,
				});
				assert.strictEqual(f.signerReads(), before, "public reads do not reach custody");
				const loads = f.loaded.length;
				assert.strictEqual((await f.list("")).status, 200);
				assert.strictEqual((await f.list("trust_marks")).status, 200);
				assert.strictEqual(f.loaded.length, loads);
				await assert.rejects(f.authority.getSubordinateStatement(first), /Custody unavailable/);
				f.setSignerOffline(false);
				const renewed = await f.authority.getSubordinateStatement(first);
				assert.strictEqual(statement(renewed).iat, 1_010);
				assert.strictEqual(
					await (await f.fetch()).text(),
					saved,
					"issuing does not activate the artifact",
				);
				f.approved.set(first, renewed);
				assert.strictEqual(await (await f.fetch()).text(), renewed);
			});
		}

		test("rejects expired, invalid, stale, and withdrawn retained publications", async (assert) => {
			const f = await fixture("anchor", true);
			const saved = await f.authority.getSubordinateStatement(first);
			const original = statement(saved);
			const before = f.signerReads();
			const unavailable = async () => {
				const response = await f.fetch();
				assert.strictEqual(response.status, 503);
				assert.strictEqual(response.headers.get("content-type"), "application/json");
				assert.strictEqual(
					((await response.json()) as { error: string }).error,
					"temporarily_unavailable",
				);
				assert.strictEqual((await f.list("iat", "1")).status, 503);
			};
			await unavailable();
			const other = await f.unrelatedSigner();
			for (const jwt of [
				"malformed",
				await f.signFixture(original, other),
				await f.signFixture(original, undefined, JwtTyp.JwkSet),
				await f.signFixture({ ...original, iss: "https://other-authority.example" }),
				await f.signFixture({ ...original, sub: second }),
				await f.signFixture({ ...original, iat: 1_001 }),
				await f.signFixture({ ...original, iat: 900, exp: 1_000 }),
				await f.signFixture({ ...original, example: { a: 4, b: 5 } }),
			]) {
				f.approved.set(first, jwt);
				await unavailable();
			}
			const reordered = await f.signFixture({
				...original,
				example: { b: 2, a: 1 },
				jwks: { keys: [...original.jwks.keys].reverse() },
			});
			f.approved.set(first, reordered);
			const permitted = await f.fetch();
			assert.strictEqual(permitted.headers.get("content-type"), MediaType.EntityStatement);
			assert.strictEqual(await permitted.text(), reordered);
			await f.authority.updateSubordinate(first, {
				metadataPolicy: { openid_relying_party: { organization_name: { value: "Tightened" } } },
			});
			await unavailable();
			await f.authority.updateSubordinate(first, {
				metadataPolicy: f.record.metadataPolicy,
				jwks: { keys: other.publishedJwks.keys },
			});
			await unavailable();
			await f.authority.revokeSubordinate(first);
			assert.strictEqual((await f.fetch()).status, 404);
			f.approved.delete(first); // The loader reads the new approval generation after re-addition.
			await f.authority.registerSubordinate(f.record);
			await unavailable();
			assert.strictEqual(f.signerReads(), before);
		});

		test("checks current algorithm policy and published keys across rollover without Historical Keys", async (assert) => {
			const f = await fixture("intermediate", true);
			f.approved.set(first, await f.authority.getSubordinateStatement(first));
			f.rotate(true);
			assert.strictEqual((await f.fetch()).status, 200);
			assert.strictEqual((await f.list(claims, "1")).status, 200);
			f.setAlgorithms(["ES384"]);
			assert.strictEqual((await f.fetch()).status, 503);
			f.setAlgorithms(["ES256", "ES384"]);
			f.flagOldKeyRevoked();
			assert.strictEqual((await f.fetch()).status, 503);
			f.rotate(false);
			assert.strictEqual((await f.fetch()).status, 503);
			const replacement = await f.authority.getSubordinateStatement(first);
			f.approved.set(first, replacement);
			assert.strictEqual(await (await f.fetch()).text(), replacement);
		});

		test("withholds a listing page when an included statement expires during assembly", async (assert) => {
			const f = await fixture("anchor", true);
			for (const id of [first, second])
				f.approved.set(id, await f.authority.getSubordinateStatement(id));
			f.setNow(1_029);
			f.setOnLoad((id) => {
				if (id === second) f.setNow(1_030);
			});
			const reads = f.keyReads();
			assert.strictEqual((await f.list(claims)).status, 503);
			assert.strictEqual(f.keyReads() - reads, 1, "the page uses one published key snapshot");
			assert.strictEqual((await f.fetch()).status, 503);
			assert.strictEqual((await f.fetch(second)).status, 200);
		});

		test("retained hosting requires a public key reader independent of custody", async (assert) => {
			const f = await fixture("anchor", true);
			const { readPublishedFederationJwks: _reader, ...crypto } = f.config.crypto;
			await assert.rejects(
				TrustAnchor.create({ ...f.config, crypto }),
				/Retained Subordinate Statements require crypto.readPublishedFederationJwks/,
			);
		});
	});
}
