import type QUnit from "qunit";
import * as CorePublic from "../../../packages/core/src/index.js";
import {
	decodeEntityStatement,
	discoverEntity,
	type EntityId,
	type EntityStatementMetadata,
	entityId,
	err,
	InternalErrorCode,
	isErr,
	isOk,
	type JWK,
	JwtTyp,
	MediaType,
	ok,
	signEntityStatement,
	stripPrivateFields,
	verifyEntityStatement,
	WELL_KNOWN_OPENID_FEDERATION,
} from "../../../packages/core/src/index.js";
import * as LeafPublic from "../../../packages/leaf/src/index.js";
import { Leaf, type LeafConfig } from "../../../packages/leaf/src/index.js";
import { memoryStorage } from "../../storage-fixtures.js";
import {
	createMockFederation,
	createMockTrustAnchors,
	LEAF_ID,
	OP_ID,
	TA_ID,
} from "../fixtures/index.js";
import {
	FixtureCrypto,
	fixtureCryptoFailureAfterStartup,
	fixtureCryptoFromKeys,
	fixtureCryptoFromRead,
	fixtureHostConfig,
	fixtureSigner,
	generateSigningKey,
	instrumentSigningEntry,
	rawFixtureJwt,
	SigningEntryFixture,
	testEngine,
} from "../fixtures/software-crypto.js";

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

function createFederationSigningKey(signingKey: JWK) {
	return { signer: new SigningEntryFixture(signingKey), publicJwk: stripPrivateFields(signingKey) };
}

async function createLeafConfig(
	overrides?: Partial<LeafConfig>,
): Promise<{ config: LeafConfig; signingKey: JWK; publicKey: JWK }> {
	const { privateKey, publicKey } = await generateSigningKey("ES256");
	const signingKey = { ...privateKey, kid: privateKey.kid ?? "leaf-key-1" };
	const config: LeafConfig = {
		entityId: LEAF_ID,
		crypto: new FixtureCrypto(createFederationSigningKey(signingKey)),
		authorityHints: [TA_ID],
		metadata: {
			openid_relying_party: {
				redirect_uris: ["https://rp.example.com/callback"],
				response_types: ["code"],
				client_registration_types: ["automatic"],
			},
		} satisfies EntityStatementMetadata,
		...overrides,
	};
	return { config, signingKey, publicKey };
}

// Minimal call recorder used in place of vi.fn().
function mockFn<A extends unknown[]>() {
	const calls: A[] = [];
	const fn = (...args: A): void => {
		calls.push(args);
	};
	fn.calls = calls;
	fn.callCount = () => calls.length;
	fn.lastCall = () => calls[calls.length - 1] as A;
	return fn;
}

// ---------------------------------------------------------------------------

export default (QUnit: QUnit) => {
	const { module, test } = QUnit;
	module("leaf / historical keys", () => {
		test("serves opted-in history signed by the current federation key", async (t) => {
			const { config, signingKey } = await createLeafConfig();
			const endpoint = `${config.entityId}/history?scope=keys`;
			const inactive = await Leaf.create(config);
			t.equal((await inactive.handleRequest(new Request(endpoint))).status, 404);

			const crypto = FixtureCrypto.fromJWK(signingKey);
			const leaf = await Leaf.create({
				...config,
				crypto,
				metadata: { federation_entity: { federation_historical_keys_endpoint: endpoint } },
			});
			const publication = decodeEntityStatement(await leaf.getEntityConfiguration());
			t.true(publication.ok);
			if (publication.ok) {
				t.equal(
					publication.value.payload.metadata?.federation_entity
						?.federation_historical_keys_endpoint,
					endpoint,
				);
			}
			const replacement = await generateSigningKey("ES256");
			await crypto.keyring.publish(
				"federation",
				new SigningEntryFixture(replacement.privateKey).signer,
			);
			await leaf.refreshEntityConfiguration();
			await crypto.keyring.activate("federation", replacement.publicKey.kid!);
			await crypto.keyring.revoke("federation", signingKey.kid!, "compromised");
			t.equal((await leaf.handleRequest(new Request(`${config.entityId}/history`))).status, 404);
			t.equal((await leaf.handleRequest(new Request(endpoint, { method: "PUT" }))).status, 405);

			const current = await crypto.keyring.entry("federation");
			const result = await CorePublic.fetchHistoricalKeys(endpoint, current.publishedJwks, {
				engine: testEngine,
				expectedIssuer: leaf.entityId,
				httpClient: async (input, init) => leaf.handleRequest(new Request(input, init)),
			});
			t.true(result.ok, JSON.stringify(result));
			if (result.ok) {
				t.equal(result.value.keys.length, 1);
				t.equal(result.value.keys[0]?.kid, signingKey.kid);
				t.equal(result.value.keys[0]?.revoked?.reason, "compromised");
				t.false(Object.hasOwn(result.value.keys[0]!, "d"));
			}
			const signed = decodeEntityStatement(await leaf.getHistoricalKeys());
			t.true(signed.ok);
			if (signed.ok) t.equal(signed.value.header.kid, replacement.publicKey.kid);
		});

		test("uses the Entity Configuration signer context for Historical Keys", async (t) => {
			const { config, signingKey } = await createLeafConfig();
			const other = await generateSigningKey("ES256");
			const self = FixtureCrypto.fromJWK(signingKey);
			const fallback = FixtureCrypto.fromJWK(other.privateKey);
			const endpoint = `${config.entityId}/history`;
			const leaf = await Leaf.create({
				...config,
				crypto: {
					...self,
					keyring: {
						entry(purpose, selection) {
							const keyring =
								selection?.issuer === config.entityId && selection.subject === config.entityId
									? self.keyring
									: fallback.keyring;
							return keyring.entry(purpose, selection);
						},
					},
				},
				metadata: { federation_entity: { federation_historical_keys_endpoint: endpoint } },
			});
			const ec = decodeEntityStatement(await leaf.getEntityConfiguration());
			t.true(ec.ok);
			if (!ec.ok) return;
			t.equal(ec.value.header.kid, signingKey.kid);
			const result = await CorePublic.fetchHistoricalKeys(
				endpoint,
				ec.value.payload.jwks ?? { keys: [] },
				{
					engine: testEngine,
					expectedIssuer: leaf.entityId,
					httpClient: async (input, init) => leaf.handleRequest(new Request(input, init)),
				},
			);
			t.true(result.ok, JSON.stringify(result));
		});

		test("signs with the replacement when the previous key is revoked during the history read", async (t) => {
			const { config, signingKey } = await createLeafConfig();
			const crypto = FixtureCrypto.fromJWK(signingKey);
			const replacement = await generateSigningKey("ES256");
			await crypto.keyring.publish(
				"federation",
				new SigningEntryFixture(replacement.privateKey).signer,
			);
			const endpoint = `${config.entityId}/history`;
			const leaf = await Leaf.create({
				...config,
				crypto: {
					...crypto,
					history: {
						async getHistoricalKeys() {
							await crypto.keyring.activate("federation", replacement.publicKey.kid!);
							await crypto.keyring.revoke("federation", signingKey.kid!, "compromised");
							return crypto.history.getHistoricalKeys();
						},
					},
				},
				metadata: { federation_entity: { federation_historical_keys_endpoint: endpoint } },
			});
			const response = await leaf.handleRequest(new Request(endpoint));
			t.equal(response.status, 200);
			const jwt = await response.text();
			const signed = decodeEntityStatement(jwt);
			t.true(signed.ok);
			if (signed.ok) t.equal(signed.value.header.kid, replacement.publicKey.kid);
			const result = await CorePublic.verifyHistoricalKeysResponse(
				jwt,
				{ keys: [replacement.publicKey] },
				{
					engine: testEngine,
					expectedIssuer: leaf.entityId,
				},
			);
			t.true(result.ok, JSON.stringify(result));
			if (result.ok) {
				t.equal(result.value.keys[0]?.kid, signingKey.kid);
				t.equal(result.value.keys[0]?.revoked?.reason, "compromised");
			}
		});

		test("refuses a signer whose public key is recorded as revoked under another kid", async (t) => {
			const { config, publicKey } = await createLeafConfig();
			const endpoint = `${config.entityId}/history`;
			const leaf = await Leaf.create({
				...config,
				crypto: {
					...config.crypto,
					history: {
						getHistoricalKeys: async () => [
							{
								...publicKey,
								kid: "previous-key-id",
								exp: 1000,
								revoked: { revoked_at: 1000, reason: "compromised" },
							},
						],
					},
				},
				metadata: { federation_entity: { federation_historical_keys_endpoint: endpoint } },
			});
			await t.rejects(leaf.getHistoricalKeys(), /signer is recorded as revoked/);
			t.equal((await leaf.handleRequest(new Request(endpoint))).status, 500);
		});

		test("honors historical endpoint authentication and advertised algorithms", async (t) => {
			const { config, publicKey } = await createLeafConfig();
			const client = await generateSigningKey("ES256");
			const clientId = entityId("https://history-client.example");
			const endpoint = `${config.entityId}/history`;
			const build = async (algorithm: string) =>
				Leaf.create({
					...config,
					metadata: {
						federation_entity: {
							federation_historical_keys_endpoint: endpoint,
							federation_historical_keys_endpoint_auth_methods: ["private_key_jwt"],
							endpoint_auth_signing_alg_values_supported: [algorithm],
						},
					},
					storage: memoryStorage(),
					historicalKeysAuthentication: {
						getClientFederationJwks: async (id) =>
							id === clientId ? { keys: [client.publicKey] } : undefined,
					},
				});
			for (const algorithm of ["ES256", "RS256"]) {
				const leaf = await build(algorithm);
				t.equal((await leaf.handleRequest(new Request(endpoint))).status, 405);
				const result = await CorePublic.fetchHistoricalKeys(
					endpoint,
					{ keys: [publicKey] },
					{
						engine: testEngine,
						expectedIssuer: leaf.entityId,
						httpClient: async (input, init) => leaf.handleRequest(new Request(input, init)),
						authentication: {
							method: "private_key_jwt",
							audience: leaf.entityId,
							clientId,
							signer: new SigningEntryFixture(client.privateKey),
						},
					},
				);
				t.equal(result.ok, algorithm === "ES256", JSON.stringify(result));
			}
		});

		test("preserves role-owned history routes and rejects competing managed route configuration", async (t) => {
			const { config } = await createLeafConfig();
			const endpoint = `${config.entityId}/history`;
			const supplied = {
				...config,
				metadata: { federation_entity: { federation_historical_keys_endpoint: endpoint } },
				roles: [
					{
						type: "example_role",
						metadata: {},
						routes: new Map([["/history", async () => new Response("host route")]]),
					},
				],
			};
			const { engine, keyring } = config.crypto;
			const warn = mockFn<[string]>();
			const logger = { debug() {}, info() {}, warn, error() {} };
			const leaf = await Leaf.create({
				...supplied,
				crypto: { engine, keyring },
				options: { logger },
			});
			t.equal(await (await leaf.handleRequest(new Request(endpoint))).text(), "host route");
			t.equal(warn.callCount(), 0);
			const withHistory = await Leaf.create({ ...supplied, options: { logger } });
			t.equal(await (await withHistory.handleRequest(new Request(endpoint))).text(), "host route");
			t.true(decodeEntityStatement(await withHistory.getHistoricalKeys()).ok);
			t.equal(warn.callCount(), 0);
			await t.rejects(
				Leaf.create({ ...supplied, historicalKeysAuthentication: {} }),
				/conflicts with a role-owned route/,
			);
			await t.rejects(
				Leaf.create({
					...supplied,
					roles: [],
					resolver: {},
					metadata: {
						federation_entity: {
							...supplied.metadata.federation_entity,
							federation_resolve_endpoint: endpoint,
						},
					},
				}),
				/Resolve endpoint conflicts/,
			);

			const external = await Leaf.create({
				...supplied,
				metadata: {
					federation_entity: {
						...supplied.metadata.federation_entity,
						federation_historical_keys_endpoint_auth_methods: ["private_key_jwt"],
					},
				},
				roles: [],
				crypto: { engine, keyring },
				options: { logger },
			});
			t.equal((await external.handleRequest(new Request(endpoint))).status, 404);
			const ec = decodeEntityStatement(await external.getEntityConfiguration());
			t.true(ec.ok);
			if (ec.ok)
				t.deepEqual(
					ec.value.payload.metadata?.federation_entity
						?.federation_historical_keys_endpoint_auth_methods,
					["private_key_jwt"],
				);
			t.equal(warn.callCount(), 1);
			t.true(warn.lastCall()[0].includes("Historical Keys endpoint without a local handler"));
		});

		test("rejects managed URLs with credential query parameters", async (t) => {
			const { config } = await createLeafConfig();
			for (const name of [
				"client_id",
				"client_secret",
				"client_assertion",
				"client_assertion_type",
				"custom_token",
			]) {
				await t.rejects(
					Leaf.create({
						...config,
						metadata: {
							federation_entity: {
								federation_historical_keys_endpoint: `${config.entityId}/history?${name}=example`,
							},
						},
						historicalKeysAuthentication: {
							extensions: {
								methods: {
									example: {
										parameters: ["custom_token"],
										authenticate: () => ok({ entityId: config.entityId }),
									},
								},
							},
						},
					}),
					/query must not contain credential parameters/,
				);
			}
		});

		test("rejects role publication that differs from the managed route", async (t) => {
			const { config } = await createLeafConfig();
			const endpoint = `https://keys.example.com/history?scope=keys`;
			let publication: Record<string, unknown> = {};
			const role = {
				type: "federation_entity",
				metadata: { federation_historical_keys_endpoint: endpoint },
				publicationMetadata: async () => publication,
			};
			const leaf = await Leaf.create({ ...config, roles: [role] });
			publication = { federation_historical_keys_endpoint: `${endpoint}&other=1` };
			await t.rejects(leaf.getEntityConfiguration(), /URL must match the managed route/);
			publication = { federation_historical_keys_endpoint_auth_methods: ["private_key_jwt"] };
			await t.rejects(leaf.getEntityConfiguration(), /authentication must match the managed route/);
			publication = {};
			t.true(decodeEntityStatement(await leaf.getEntityConfiguration()).ok);
			t.equal((await leaf.handleRequest(new Request(endpoint))).status, 200);
		});

		test("rejects malformed historical keys and keeps provider data out of HTTP and logs", async (t) => {
			const { config, publicKey } = await createLeafConfig();
			const endpoint = `${config.entityId}/history`;
			const error = mockFn<[string]>();
			const logger = { debug() {}, info() {}, warn() {}, error };
			const invalidRecords = [
				{ kty: "EC", kid: "incomplete", exp: 1000 },
				{ ...publicKey, kid: "private-fixture-key", exp: 1000, d: "private-fixture" },
			];
			for (const record of invalidRecords) {
				const leaf = await Leaf.create({
					...config,
					metadata: { federation_entity: { federation_historical_keys_endpoint: endpoint } },
					crypto: { ...config.crypto, history: { getHistoricalKeys: async () => [record] } },
					options: { logger },
				});
				const response = await leaf.handleRequest(new Request(endpoint));
				t.equal(response.status, 500);
				t.deepEqual(await response.json(), {
					error: "server_error",
					error_description: "Failed to build historical keys",
				});
				t.deepEqual(error.lastCall(), [
					"Failed to build historical keys: invalid historical key record",
				]);
			}
		});

		test("reports missing history before opening the signing keyring", async (t) => {
			const { config } = await createLeafConfig();
			const entry = mockFn<[]>();
			await t.rejects(
				CorePublic.signHistoricalKeysResponse({
					entityId: entityId(config.entityId),
					crypto: {
						engine: testEngine,
						keyring: {
							async entry() {
								entry();
								throw new Error("unexpected signing key lookup");
							},
						},
					},
					options: { engine: testEngine },
				}),
				/Historical keys source is not configured/,
			);
			t.equal(entry.callCount(), 0);
		});
	});

	module("leaf / federation endpoint publication", () => {
		test("warns once for a Resolve endpoint served by the application and accepts a role route", async (t) => {
			const { config } = await createLeafConfig();
			const endpoint = "https://resolve.example/resolve";
			const warn = mockFn<[string]>();
			const supplied = {
				...config,
				metadata: {
					federation_entity: {
						federation_resolve_endpoint: endpoint,
						federation_resolve_endpoint_auth_methods: ["private_key_jwt"],
					},
				},
				options: { logger: { debug() {}, info() {}, warn, error() {} } },
			};
			const external = await Leaf.create(supplied);
			const ec = decodeEntityStatement(await external.getEntityConfiguration());
			t.true(ec.ok);
			if (ec.ok) {
				t.equal(
					ec.value.payload.metadata?.federation_entity?.federation_resolve_endpoint,
					endpoint,
				);
				t.deepEqual(
					ec.value.payload.metadata?.federation_entity?.federation_resolve_endpoint_auth_methods,
					["private_key_jwt"],
				);
			}
			t.equal((await external.handleRequest(new Request(endpoint))).status, 404);
			t.equal(warn.callCount(), 1);
			t.true(warn.lastCall()[0].includes("Resolve endpoint without a local handler"));
			const withRoute = await Leaf.create({
				...supplied,
				roles: [
					{
						type: "example_role",
						metadata: {},
						routes: new Map([["/resolve", async () => new Response(null, { status: 204 })]]),
					},
				],
			});
			t.equal(
				(await withRoute.handleRequest(new Request(endpoint, { method: "POST" }))).status,
				204,
			);
			t.equal(warn.callCount(), 1);
		});

		test("rejects endpoint auth metadata without its endpoint", async (t) => {
			const { config } = await createLeafConfig();
			for (const name of [
				"resolve",
				"collection",
				"trust_mark",
				"trust_mark_status",
				"trust_mark_list",
				"historical_keys",
			]) {
				await t.rejects(
					Leaf.create({
						...config,
						metadata: {
							federation_entity: {
								[`federation_${name}_endpoint_auth_methods`]: ["private_key_jwt"],
							},
						},
					}),
					new RegExp(`requires federation_${name}_endpoint`),
				);
			}
		});

		test("validates federation endpoint metadata after role publication callbacks", async (t) => {
			const { config } = await createLeafConfig();
			const endpoint = `${config.entityId}/resolve`;
			let publication: Record<string, unknown> = {};
			const build = () =>
				Leaf.create({
					...config,
					resolver: {},
					roles: [
						{
							type: "federation_entity",
							metadata: { federation_resolve_endpoint: endpoint },
							publicationMetadata: async () => publication,
						},
					],
				});
			publication = { federation_fetch_endpoint: `${config.entityId}/fetch` };
			await t.rejects(build(), /MUST NOT publish federation_fetch_endpoint/);
			publication = {};
			const leaf = await build();
			publication = { federation_collection_endpoint_auth_methods: ["none"] };
			await t.rejects(leaf.getEntityConfiguration(), /requires federation_collection_endpoint/);
			publication = { federation_subordinate_events_endpoint: `${config.entityId}/events` };
			await t.rejects(
				leaf.getEntityConfiguration(),
				/cannot publish federation_subordinate_events_endpoint/,
			);
			publication = { federation_collection_endpoint: `${config.entityId}/collection` };
			await t.rejects(leaf.getEntityConfiguration(), /Collection URL must match the managed route/);
			publication = { federation_resolve_endpoint: `${endpoint}?tenant=elsewhere` };
			await t.rejects(leaf.getEntityConfiguration(), /Resolve URL must match the managed route/);
			publication = { federation_resolve_endpoint_auth_methods: ["private_key_jwt"] };
			await t.rejects(
				leaf.getEntityConfiguration(),
				/Resolve authentication must match the managed route/,
			);
			publication = {};
			t.true(decodeEntityStatement(await leaf.getEntityConfiguration()).ok);
		});

		test("rejects credential parameters in a managed Resolve URL", async (t) => {
			const { config } = await createLeafConfig();
			await t.rejects(
				Leaf.create({
					...config,
					resolver: {},
					metadata: {
						federation_entity: {
							federation_resolve_endpoint: `${config.entityId}/resolve?client_assertion_type=fixture`,
						},
					},
				}),
				/Resolve endpoint query must not contain credential parameters/,
			);
		});
	});

	module("leaf / supplied discovery and managed marks", () => {
		test("supplied-chain discovery uses configured anchors and permits per-call overrides without fetching", async (t) => {
			const f = await createMockFederation();
			const { config } = await createLeafConfig({
				trustAnchors: f.trustAnchors,
				options: {
					...f.options,
					maxTotalFetches: 0,
					httpClient: async () => {
						throw new Error("supplied evidence must not fetch");
					},
				},
			});
			const leaf = await Leaf.create(fixtureHostConfig(config));
			const chain = [f.opEcJwt, f.taSubStatementForOp, f.taEcJwt];
			const discovered = await leaf.discoverEntityFromChain(OP_ID, chain);
			t.true(discovered.ok, JSON.stringify(discovered));
			if (discovered.ok) {
				t.equal(discovered.value.entityId, OP_ID);
				t.equal(discovered.value.trustChain.trustAnchorId, TA_ID);
			}
			t.false((await leaf.discoverEntityFromChain(OP_ID, chain, { trustAnchors: new Map() })).ok);
			const unconfigured = await Leaf.create(
				fixtureHostConfig({ ...config, trustAnchors: undefined }),
			);
			t.false((await unconfigured.discoverEntityFromChain(OP_ID, chain)).ok);
			t.true(
				(await unconfigured.discoverEntityFromChain(OP_ID, chain, { trustAnchors: f.trustAnchors }))
					.ok,
			);
		});

		test("fetching a mark validates issuer trust and holder binding before publishing", async (t) => {
			const clock = { now: () => 1000 };
			const { config, publicKey } = await createLeafConfig({ options: { clock } });
			const leaf = await Leaf.create(fixtureHostConfig(config));
			const issuer = "https://accreditor.example";
			const type = "urn:example:accreditation";
			const key = await generateSigningKey("ES256");
			const signer = new SigningEntryFixture(key.privateKey);
			const jwks = { keys: [key.publicKey] };
			const ec = await signEntityStatement(
				{
					iss: issuer,
					sub: issuer,
					iat: 1000,
					exp: 2000,
					jwks,
					trust_mark_issuers: { [type]: [issuer] },
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: `${issuer}/fetch`,
							federation_list_endpoint: `${issuer}/list`,
							federation_trust_mark_endpoint: `${issuer}/marks`,
						},
					},
				},
				signer,
				{ typ: JwtTyp.EntityStatement },
			);
			const jwt = await CorePublic.signTrustMark({
				issuer,
				subject: leaf.entityId,
				trustMarkType: type,
				signer,
				clock,
				ttlSeconds: 100,
			});
			const wrongHolder = await CorePublic.signTrustMark({
				issuer,
				subject: "https://other.example",
				trustMarkType: type,
				signer,
				clock,
				ttlSeconds: 100,
			});
			let mode = "valid";
			const input = {
				issuer,
				trustMarkType: type,
				trustAnchors: CorePublic.createTrustAnchorSet([{ entityId: issuer, jwks }]),
				options: {
					clock,
					httpClient: async (url: Parameters<CorePublic.HttpClient>[0]) => {
						const target = new URL(String(url));
						if (target.pathname === WELL_KNOWN_OPENID_FEDERATION)
							return new Response(ec, { headers: { "content-type": MediaType.EntityStatement } });
						t.equal(target.pathname, "/marks");
						t.equal(target.searchParams.get("sub"), leaf.entityId);
						t.equal(target.searchParams.get("trust_mark_type"), type);
						return new Response(mode === "wrong-holder" ? wrongHolder : jwt, {
							status: mode === "unavailable" ? 503 : 200,
							headers: { "content-type": MediaType.TrustMark },
						});
					},
				},
			};
			await leaf.fetchAndAttachTrustMark(input);
			t.deepEqual(leaf.getTrustMarks(), [{ trust_mark_type: type, trust_mark: jwt }]);
			const published = await leaf.getEntityConfiguration();
			const checked = await verifyEntityStatement(
				published,
				{ keys: [publicKey] },
				{ engine: testEngine, clock },
			);
			t.true(checked.ok);
			if (checked.ok) t.deepEqual(checked.value.payload.trust_marks, leaf.getTrustMarks());
			for (mode of ["unavailable", "wrong-holder"]) {
				await t.rejects(leaf.fetchAndAttachTrustMark(input));
				t.equal(
					await leaf.getEntityConfiguration(),
					published,
					"failed retrieval preserves publication",
				);
				t.equal(leaf.getTrustMarks().length, 1);
			}
		});

		test("managed issuance lists eligible records and uses replaced owner delegations", async (t) => {
			const clock = { now: () => 1000 };
			const { config, publicKey } = await createLeafConfig({ options: { clock } });
			const owner = "https://owner.example";
			const ownerKey = await generateSigningKey("ES256");
			const type = "urn:example:accreditation";
			const subject = "https://member.example";
			const leaf = await Leaf.create(
				fixtureHostConfig({
					...config,
					storage: memoryStorage({ trustMarks: true }),
					trustMarkIssuer: {
						issuerEvidence: [
							{
								kind: "out-of-band",
								issuer: String(config.entityId),
								allowedTrustMarkTypes: [type],
								keys: { keys: [publicKey] },
								trustMarkOwners: { [type]: { sub: owner, jwks: { keys: [ownerKey.publicKey] } } },
							},
						],
					},
				}),
			);
			const delegate = (ttlSeconds: number) =>
				CorePublic.signTrustMarkDelegation({
					issuer: owner,
					subject: leaf.entityId,
					trustMarkType: type,
					signer: new SigningEntryFixture(ownerKey.privateKey),
					clock,
					ttlSeconds,
				});
			await t.rejects(leaf.issueTrustMark(subject, type), /delegation/i);
			const first = await delegate(100);
			const delegations = { [type]: first };
			await leaf.setTrustMarkDelegations(delegations);
			delegations[type] = "caller mutation";
			const jwt = await leaf.issueTrustMark(subject, type);
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (decoded.ok) t.equal(decoded.value.payload.delegation, first);
			const records = await leaf.listTrustMarksForSubject(subject);
			t.equal(records.length, 1);
			t.equal(records[0]?.jwt, jwt);
			records.pop();
			t.equal((await leaf.listTrustMarksForSubject(subject)).length, 1);
			t.deepEqual(await leaf.listTrustMarkedEntities(type), [subject]);
			t.deepEqual(await leaf.listTrustMarkedEntities(type, "https://other.example"), []);
			await t.rejects(
				leaf.setTrustMarkDelegations({ [type]: 42 } as unknown as Record<string, string>),
				/Invalid Trust Mark delegations/,
			);
			const preserved = decodeEntityStatement(
				await leaf.issueTrustMark(subject, type, { renewal: "renew" }),
			);
			t.true(preserved.ok);
			if (preserved.ok) t.equal(preserved.value.payload.delegation, first);
			const replacement = await delegate(200);
			await leaf.setTrustMarkDelegations({ [type]: replacement });
			const renewed = decodeEntityStatement(
				await leaf.issueTrustMark(subject, type, { renewal: "renew" }),
			);
			t.true(renewed.ok);
			if (renewed.ok) t.equal(renewed.value.payload.delegation, replacement);
			await leaf.revokeTrustMark(type, subject);
			t.deepEqual(await leaf.listTrustMarksForSubject(subject), []);
			t.deepEqual(await leaf.listTrustMarkedEntities(type), []);
			const disabled = await Leaf.create(fixtureHostConfig(config));
			await t.rejects(disabled.listTrustMarksForSubject(subject), /not configured/);
			await t.rejects(disabled.listTrustMarkedEntities(type), /not configured/);
			await t.rejects(disabled.setTrustMarkDelegations({}), /not configured/);
		});
	});
	module("leaf / configurable trust establishment", () => {
		test("Leaf Collection matches its advertised routing query for GET and POST", async (t) => {
			const { config } = await createLeafConfig({
				metadata: {
					federation_entity: { federation_collection_endpoint: `${LEAF_ID}/collect?version=1` },
				},
				storage: memoryStorage({ collections: true }),
				collection: { trustAnchors: new Map() },
			});
			const leaf = await Leaf.create(fixtureHostConfig(config));
			for (const method of ["GET", "POST"]) {
				for (const [query, expected] of [
					["", 404],
					["?version=2", 404],
					["?version=1", 200],
				] as const) {
					const result = await leaf.handleRequest(
						new Request(`${LEAF_ID}/collect${query}`, {
							method,
							...(method === "POST" ? { body: new URLSearchParams() } : {}),
						}),
					);
					t.equal(result.status, expected);
					await result.body?.cancel();
				}
			}
		});

		test("authenticated Leaf Resolve validates the form and caches equivalent fixed anchor lists", async (t) => {
			const f = await createMockFederation();
			const client = await generateSigningKey("ES256");
			const endpoint = `${LEAF_ID}/resolve?tenant=academic&trust_anchor=${encodeURIComponent(TA_ID)}`;
			let keyLookups = 0;
			const { config } = await createLeafConfig({
				metadata: {
					federation_entity: {
						federation_resolve_endpoint: endpoint,
						federation_resolve_endpoint_auth_methods: ["none", "private_key_jwt"],
					},
				},
				storage: memoryStorage({}),
				trustAnchors: f.trustAnchors,
				options: { httpClient: f.httpClient },
				resolver: {
					authentication: {
						methods: ["none", "private_key_jwt"],
						getClientFederationJwks: async () => {
							keyLookups++;
							return { keys: [client.publicKey] };
						},
					},
				},
			});
			const leaf = await Leaf.create(fixtureHostConfig(config));
			const form = new URLSearchParams({
				client_assertion_type: CorePublic.JWT_BEARER_CLIENT_ASSERTION_TYPE,
				client_assertion: await CorePublic.createClientAssertion(
					entityId(OP_ID),
					entityId(LEAF_ID),
					new SigningEntryFixture(client.privateKey),
					{ engine: testEngine },
				),
			});
			const url = `${endpoint}&sub=${encodeURIComponent(OP_ID)}`;
			const missing = await leaf.handleRequest(new Request(url, { method: "POST", body: form }));
			t.equal(missing.status, 400);
			t.equal(((await missing.json()) as { error: string }).error, "invalid_request");
			form.set("sub", OP_ID);
			form.set("trust_anchor", "https://wrong-anchor.example");
			const conflict = await leaf.handleRequest(new Request(url, { method: "POST", body: form }));
			t.equal(conflict.status, 400);
			await conflict.body?.cancel();
			t.equal(keyLookups, 0);
			form.set("trust_anchor", TA_ID);
			form.append("trust_anchor", TA_ID);
			const matched = await leaf.handleRequest(new Request(url, { method: "POST", body: form }));
			t.equal(matched.status, 200);
			const result = decodeEntityStatement(await matched.text());
			t.true(result.ok);
			if (result.ok) t.equal(result.value.payload.aud, OP_ID);
			t.equal(keyLookups, 1);
			t.equal((await leaf.handleRequest(new Request(url))).status, 404);
			await leaf.resolver?.primeAnonymousResolve({ subject: OP_ID, trustAnchor: TA_ID });
			const cached = await leaf.handleRequest(new Request(url));
			t.equal(cached.status, 200);
			const decoded = decodeEntityStatement(await cached.text());
			t.true(decoded.ok);
			if (decoded.ok) t.strictEqual(decoded.value.payload.aud, undefined);
		});

		test("Leaf hosts Resolve independently and forwards selection defaults", async (t) => {
			const f = await createMockFederation();
			let calls = 0;
			const { config } = await createLeafConfig({
				metadata: {
					federation_entity: { federation_resolve_endpoint: `${LEAF_ID}/resolve?tenant=academic` },
				},
				trustAnchors: f.trustAnchors,
				options: {
					httpClient: f.httpClient,
					chainSelection: (chains) => {
						calls++;
						return chains[0]!;
					},
				},
				resolver: { requireAuthForFreshResolution: false },
			});
			const leaf = await Leaf.create(fixtureHostConfig(config));
			const assessment = await leaf.assessEntity(OP_ID);
			t.true(assessment.ok, JSON.stringify(assessment));
			t.ok(calls > 0);
			calls = 0;
			const discovered = await leaf.discoverEntity(OP_ID, {
				chainSelection: (chains) => chains[0]!,
			});
			t.true(discovered.ok);
			t.strictEqual(calls, 0, "per-call selection overrides host defaults");
			const response = await leaf.handleRequest(
				new Request(
					`${LEAF_ID}/resolve?tenant=academic&sub=${encodeURIComponent(OP_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.strictEqual(response.status, 200, await response.clone().text());
			t.strictEqual(
				(await leaf.handleRequest(new Request(`${LEAF_ID}/resolve?tenant=other`))).status,
				404,
				"fixed route selectors are enforced",
			);
			const ec = decodeEntityStatement(await leaf.getEntityConfiguration());
			t.true(ec.ok);
			if (ec.ok)
				t.strictEqual(
					ec.value.payload.metadata?.federation_entity?.federation_fetch_endpoint,
					undefined,
				);
			const collision = {
				...config,
				metadata: {
					federation_entity: {
						federation_resolve_endpoint: `${LEAF_ID}/.well-known/openid-federation`,
					},
				},
			};
			await t.rejects((async () => await Leaf.create(fixtureHostConfig(collision)))(), /conflicts/);
			await t.rejects(
				(async () =>
					await Leaf.create(
						fixtureHostConfig({
							...config,
							storage: memoryStorage(),
							metadata: {
								federation_entity: {
									federation_resolve_endpoint: `${LEAF_ID}/resolve`,
									federation_resolve_endpoint_auth_methods: ["private_key_jwt"],
									endpoint_auth_signing_alg_values_supported: ["ES256"],
								},
							},
							resolver: {
								authentication: {
									methods: ["private_key_jwt"],
									allowedAlgorithms: ["RS256"],
									getClientFederationJwks: async () => ({ keys: [f.leafPublicKey] }),
								},
							},
						}),
					))(),
				/Resolve endpoint advertises unsupported private_key_jwt algorithms/,
				"published signing algorithms cannot be bypassed by service configuration",
			);
		});
	});

	module("leaf / critical extension publication", () => {
		test("configured extensions are detached and survive EC refresh", async (t) => {
			const additionalClaims = { x_rules: { versions: [1] } };
			const crit = ["x_rules"];
			const { config } = await createLeafConfig({ additionalClaims, crit });
			const leaf = await Leaf.create(fixtureHostConfig(config));
			additionalClaims.x_rules.versions.push(2);
			crit.push("absent");
			for (const jwt of [
				await leaf.getEntityConfiguration(),
				await leaf.refreshEntityConfiguration(),
			]) {
				const result = decodeEntityStatement(jwt);
				t.true(result.ok);
				if (result.ok) {
					t.deepEqual(result.value.payload.x_rules, { versions: [1] });
					t.deepEqual(result.value.payload.crit, ["x_rules"]);
				}
			}
			for (const patch of [
				{ additionalClaims: { iss: "override" } },
				{ crit: ["missing"] },
				{ crit: [] },
			]) {
				await t.rejects(
					(async () =>
						await Leaf.create(
							fixtureHostConfig({ ...config, additionalClaims: {}, crit: undefined, ...patch }),
						))(),
					/reserved|crit/,
				);
			}
		});
	});
	module("leaf / configuration route boundaries", () => {
		test("role routes cannot replace discovery or another role", async (t) => {
			const { config } = await createLeafConfig({ entityId: "https://leaf.example/tenant" });
			const role = (path: string): CorePublic.EntityRole => ({
				type: "example_protocol",
				metadata: {},
				routes: new Map([[path, async () => new Response("role")]]),
			});
			for (const path of [
				"/tenant/.well-known/openid-federation",
				"https://leaf.example/tenant/.well-known/openid-federation",
			])
				await t.rejects(
					(async () => await Leaf.create(fixtureHostConfig({ ...config, roles: [role(path)] })))(),
					/Role route.*conflicts/,
				);
			await t.rejects(
				(async () =>
					await Leaf.create(
						fixtureHostConfig({
							...config,
							roles: [role("/register"), role("https://leaf.example/register")],
						}),
					))(),
				/Role route.*conflicts/,
			);
			const leaf = await Leaf.create(
				fixtureHostConfig({ ...config, roles: [role("/tenant//register")] }),
			);
			t.equal(
				await (
					await leaf.handleRequest(new Request("https://leaf.example/tenant//register"))
				).text(),
				"role",
			);
			t.equal(
				(
					await leaf.handleRequest(
						new Request("https://leaf.example/tenant/.well-known/openid-federation", {
							method: "POST",
						}),
					)
				).status,
				405,
			);
		});
		test("published leaf identity stays consistent across roles, claims and discovery", async (t) => {
			const { config } = await createLeafConfig();
			for (const prefix of ["https://leaf.example", "https://leaf.example:8443/tenant%2Fname"])
				for (const trailing of [0, 1, 2, 3]) {
					const raw = prefix + "/".repeat(trailing);
					let roleId: string | undefined;
					const leaf = await Leaf.create(
						fixtureHostConfig({
							...config,
							entityId: raw,
							roles: [
								{
									type: "example_protocol",
									metadata: {},
									initialize: (context) => {
										roleId = context.entityId;
									},
								},
							],
						}),
					);
					t.equal(leaf.entityId, raw);
					t.equal(roleId, raw);
					const result = await CorePublic.fetchEntityConfiguration(leaf.entityId, {
						engine: testEngine,
						httpClient: async (input) => leaf.handleRequest(new Request(String(input))),
					});
					t.true(result.ok, raw);
					if (result.ok) {
						const ec = decodeEntityStatement(result.value);
						t.true(ec.ok && ec.value.payload.iss === raw && ec.value.payload.sub === raw);
					}
				}
		});
	});
	module("leaf / managed Trust Mark lifecycle", () => {
		test("anonymous Trust Mark Status checks configured selectors and keeps locale in the URL", async (t) => {
			const { config } = await createLeafConfig();
			const endpoint = `${config.entityId}/status?locale=en&campus=north&campus=west&region=central`;
			let calls = 0;
			const leaf = await Leaf.create(
				fixtureHostConfig({
					...config,
					metadata: { federation_entity: { federation_trust_mark_status_endpoint: endpoint } },
					storage: memoryStorage({ trustMarks: true }),
					trustMarkIssuer: {
						authentication: { operationParameterNames: ["region"] },
						trustMarkRequestExtensions: {
							campus: (values) => {
								calls++;
								t.deepEqual(values, ["north", "west"]);
								return ok(undefined);
							},
						},
					},
				}),
			);
			const mark = await leaf.issueTrustMark(entityId("https://member.example"), "type");
			for (const [campuses, regions, expected] of [
				[[], ["central"], 400],
				[["west", "north"], ["central"], 400],
				[["north", "west"], [], 400],
				[["north", "west"], ["central"], 200],
			] as const) {
				const form = new URLSearchParams({ trust_mark: mark });
				for (const campus of campuses) form.append("campus", campus);
				for (const region of regions) form.append("region", region);
				const result = await leaf.handleRequest(
					new Request(endpoint, { method: "POST", body: form }),
				);
				t.equal(result.status, expected);
				await result.body?.cancel();
			}
			const jwks = (await config.crypto.keyring.entry("federation")).publishedJwks;
			const client = await CorePublic.fetchTrustMarkStatus(endpoint, mark, jwks, {
				expectedIssuer: config.entityId,
				engine: testEngine,
				additionalParameters: { campus: ["north", "west"], region: "central" },
				httpClient: (input, init) => {
					t.equal(String(input), endpoint);
					t.false(new URLSearchParams(String(init?.body)).has("locale"));
					return leaf.handleRequest(new Request(input, init));
				},
			});
			t.true(client.ok);
			t.equal(calls, 2);
		});

		test("Trust Mark endpoints enforce advertised and locally restricted authentication algorithms", async (t) => {
			const { config } = await createLeafConfig();
			const issuer = String(config.entityId),
				subject = entityId("https://member.example"),
				type = "type";
			const client = await generateSigningKey("ES256"),
				signer = new SigningEntryFixture(client.privateKey);
			for (const advertised of [["RS256"], ["RS256", "ES256"], undefined]) {
				const leaf = await Leaf.create(
					fixtureHostConfig({
						...config,
						metadata: {
							federation_entity: {
								federation_trust_mark_endpoint: `${issuer}/marks`,
								federation_trust_mark_endpoint_auth_methods: ["private_key_jwt"],
								federation_trust_mark_status_endpoint: `${issuer}/status`,
								federation_trust_mark_status_endpoint_auth_methods: ["private_key_jwt"],
								federation_trust_mark_list_endpoint: `${issuer}/list`,
								federation_trust_mark_list_endpoint_auth_methods: ["private_key_jwt"],
								...(advertised ? { endpoint_auth_signing_alg_values_supported: advertised } : {}),
							},
						},
						storage: memoryStorage({ trustMarks: true }),
						trustMarkIssuer: {
							authentication: {
								getClientFederationJwks: async () => ({ keys: [client.publicKey] }),
							},
						},
					}),
				);
				const jwt = await leaf.issueTrustMark(subject, type);
				const options = {
					httpClient: async (input: string | URL | Request, init?: RequestInit) =>
						leaf.handleRequest(new Request(input, init)),
					authentication: {
						method: "private_key_jwt" as const,
						audience: issuer,
						clientId: subject,
						signer,
					},
				};
				const fetched = await CorePublic.fetchTrustMark(
					`${issuer}/marks`,
					{ sub: subject, trustMarkType: type },
					{ ...options, engine: testEngine },
				);
				const listed = await CorePublic.fetchTrustMarkList(
					`${issuer}/list`,
					{ trustMarkType: type },
					{ ...options, engine: testEngine },
				);
				const keys = await config.crypto.keyring.entry("federation");
				const status = await CorePublic.fetchTrustMarkStatus(
					`${issuer}/status`,
					jwt,
					keys.publishedJwks,
					{ engine: testEngine, ...options, expectedIssuer: issuer },
				);
				for (const result of [fetched, listed, status])
					t.equal(result.ok, advertised?.includes("ES256") ?? true);
			}
			const build = async (allowedAlgorithms: readonly string[], advertisedAlgorithms: string[]) =>
				await Leaf.create(
					fixtureHostConfig({
						...config,
						metadata: {
							federation_entity: {
								federation_trust_mark_endpoint: `${issuer}/marks`,
								federation_trust_mark_endpoint_auth_methods: ["private_key_jwt"],
								endpoint_auth_signing_alg_values_supported: advertisedAlgorithms,
							},
						},
						storage: memoryStorage({ trustMarks: true }),
						trustMarkIssuer: {
							authentication: {
								allowedAlgorithms,
								getClientFederationJwks: async () => ({ keys: [client.publicKey] }),
							},
						},
					}),
				);
			await t.rejects(build(["PS256"], ["ES256", "RS256"]), /advertises unsupported/);
			await t.rejects(build(["RS256"], ["ES256", "RS256"]), /advertises unsupported/);
			const restricted = build(["RS256"], ["RS256"]);
			await (await restricted).issueTrustMark(subject, type);
			const response = await CorePublic.fetchTrustMark(
				`${issuer}/marks`,
				{ sub: subject, trustMarkType: type },
				{
					engine: testEngine,
					httpClient: async (input, init) =>
						(await restricted).handleRequest(new Request(input, init)),
					authentication: {
						method: "private_key_jwt",
						audience: issuer,
						clientId: subject,
						signer,
					},
				},
			);
			t.false(response.ok, "the local restriction is not broadened by metadata");
		});

		test("Leaf hosts issuer endpoints and authenticated retrieval without authority endpoints", async (t) => {
			const { config, publicKey } = await createLeafConfig();
			const issuer = String(config.entityId),
				subject = entityId("https://member.example"),
				type = "type";
			const leaf = await Leaf.create(
				fixtureHostConfig({
					...config,
					metadata: {
						federation_entity: {
							federation_trust_mark_endpoint: `${issuer}/marks`,
							federation_trust_mark_endpoint_auth_methods: ["example-auth"],
							federation_trust_mark_list_endpoint: `${issuer}/mark-list`,
							federation_trust_mark_status_endpoint: `${issuer}/mark-status`,
						},
					},
					storage: memoryStorage({ trustMarks: true }),
					trustMarkIssuer: {
						authentication: {
							extensions: {
								methods: {
									"example-auth": {
										parameters: ["proof"],
										authenticate: (input) =>
											input.parameters.proof?.[0] === "valid"
												? ok({ entityId: "https://caller.example" })
												: err({ code: "invalid_client", description: "invalid" }),
									},
								},
							},
						},
					},
				}),
			);
			const jwt = await leaf.issueTrustMark(subject, type, { noExpiry: true });
			const httpClient: CorePublic.HttpClient = async (url, init) =>
				leaf.handleRequest(new Request(url, init));
			const missing = await CorePublic.fetchTrustMark(
				`${issuer}/marks`,
				{ sub: subject, trustMarkType: type },
				{ engine: testEngine, httpClient },
			);
			t.false(missing.ok);
			const fetched = await CorePublic.fetchTrustMark(
				`${issuer}/marks`,
				{ sub: subject, trustMarkType: type },
				{
					engine: testEngine,
					httpClient,
					authentication: {
						method: "example-auth",
						audience: issuer,
						prepare: async () => ({ parameters: { proof: "valid" } }),
					},
				},
			);
			t.true(fetched.ok);
			if (fetched.ok) t.equal(fetched.value, jwt);
			const listed = await CorePublic.fetchTrustMarkList(
				`${issuer}/mark-list`,
				{ trustMarkType: type },
				{ engine: testEngine, httpClient },
			);
			t.true(listed.ok);
			if (listed.ok) t.deepEqual(listed.value, [subject]);
			const checked = await CorePublic.fetchTrustMarkStatus(
				`${issuer}/mark-status`,
				jwt,
				{ keys: [publicKey] },
				{ engine: testEngine, expectedIssuer: issuer, httpClient },
			);
			t.true(checked.ok);
			if (checked.ok) t.equal(checked.value.status, "active");
			await leaf.revokeTrustMark(type, subject);
			const revoked = await CorePublic.fetchTrustMarkStatus(
				`${issuer}/mark-status`,
				jwt,
				{ keys: [publicKey] },
				{ engine: testEngine, expectedIssuer: issuer, httpClient },
			);
			t.true(revoked.ok);
			if (revoked.ok) t.equal(revoked.value.status, "revoked");
			const ec = decodeEntityStatement(await leaf.getEntityConfiguration());
			t.true(ec.ok);
			if (ec.ok) {
				t.strictEqual(
					ec.value.payload.metadata?.federation_entity?.federation_fetch_endpoint,
					undefined,
				);
				t.strictEqual(
					ec.value.payload.metadata?.federation_entity?.federation_list_endpoint,
					undefined,
				);
			}
		});

		test("Trust Mark route selectors preserve exact extension ordering", async (t) => {
			const { config } = await createLeafConfig();
			const leaf = await Leaf.create(
				fixtureHostConfig({
					...config,
					metadata: {
						federation_entity: {
							federation_trust_mark_list_endpoint: `${config.entityId}/mark-list?extension=a&extension=b`,
						},
					},
					storage: memoryStorage({ trustMarks: true }),
					trustMarkIssuer: {},
				}),
			);
			const type = "urn:example:mark";
			for (const [query, expected] of [
				["extension=a&extension=b", 200],
				["extension=b&extension=a", 404],
				["extension=a&extension=b&extension=a", 404],
			] as const) {
				const response = await leaf.handleRequest(
					new Request(
						`${config.entityId}/mark-list?${query}&trust_mark_type=${encodeURIComponent(type)}`,
					),
				);
				t.equal(response.status, expected);
				await response.body?.cancel();
			}
		});
		test("holder attachment is validated, detached, deduplicated and rolls back when publication fails", async (t) => {
			const { config } = await createLeafConfig();
			let fail = false;
			const leaf = await Leaf.create(
				fixtureHostConfig({
					...config,
					crypto: fixtureCryptoFromRead(async () => {
						if (fail) throw new Error("signer unavailable");
						return config.crypto.keyring.entry("federation");
					}),
				}),
			);
			const key = await generateSigningKey("ES256"),
				issuer = "https://accreditor.example",
				type = "type";
			const issuerEvidence = {
				kind: "out-of-band" as const,
				issuer,
				allowedTrustMarkTypes: [type],
				keys: { keys: [key.publicKey] },
			};
			const jwt = await CorePublic.signTrustMark({
				issuer,
				subject: leaf.entityId,
				trustMarkType: type,
				signer: new SigningEntryFixture(key.privateKey),
			});
			const before = await leaf.getEntityConfiguration();
			fail = true;
			await t.rejects(
				leaf.attachTrustMark(jwt, {
					issuerEvidence,
					expectedTrustMarkType: type,
				}),
			);
			t.deepEqual(leaf.getTrustMarks(), []);
			t.equal(await leaf.getEntityConfiguration(), before);
			fail = false;
			await leaf.attachTrustMark(jwt, {
				issuerEvidence,
				expectedTrustMarkType: type,
				offline: true,
			});
			await leaf.attachTrustMark(jwt, {
				issuerEvidence,
				expectedTrustMarkType: type,
				offline: true,
			});
			t.equal(leaf.getTrustMarks().length, 1);
			leaf.getTrustMarks().pop();
			t.equal(leaf.getTrustMarks().length, 1);
			const updated = await leaf.getEntityConfiguration();
			fail = true;
			await t.rejects(leaf.removeTrustMark({ jwt }));
			t.equal(leaf.getTrustMarks().length, 1);
			t.equal(await leaf.getEntityConfiguration(), updated);
			fail = false;
			await leaf.removeTrustMark({ issuer, trustMarkType: type });
			t.deepEqual(leaf.getTrustMarks(), []);
		});
	});

	module("leaf / custom constraints", () => {
		test("discovery applies host-supplied constraint checks", async (t) => {
			const f = await createMockFederation();
			const decoded = decodeEntityStatement(f.taSubStatementForOp);
			if (!decoded.ok) throw Error("fixture");
			const ss = await signEntityStatement(
				{ ...decoded.value.payload, constraints: { custom: true } },
				new SigningEntryFixture(f.taSigningKey),
				{ typ: JwtTyp.EntityStatement },
			);
			const httpClient: typeof f.httpClient = async (input, init) => {
				const url = new URL(String(input));
				return url.origin === TA_ID && url.searchParams.get("sub") === OP_ID
					? new Response(ss, { headers: { "content-type": MediaType.EntityStatement } })
					: f.httpClient(input, init);
			};
			for (const accepted of [true, false]) {
				let calls = 0;
				const result = await CorePublic.discoverEntity(OP_ID, f.trustAnchors, {
					...f.options,
					httpClient,
					customConstraintChecks: [
						{
							name: "custom",
							check() {
								calls++;
								return accepted
									? ok(undefined)
									: err({ code: InternalErrorCode.ConstraintViolation, description: "denied" });
							},
						},
					],
				});
				t.equal(result.ok, accepted);
				t.true(calls > 0);
			}
		});
	});

	module("leaf / collection recommendation", () => {
		test("the Resolve recommendation follows successful composed publication and appears once", async (t) => {
			for (const resolve of [false, true])
				for (const throughRole of [false, true]) {
					const { config } = await createLeafConfig();
					const messages: string[] = [];
					let failing = false;
					const metadata = {
						federation_collection_endpoint: `${LEAF_ID}/collect`,
						...(resolve ? { federation_resolve_endpoint: `${LEAF_ID}/resolve` } : {}),
					};
					const leaf = await Leaf.create(
						fixtureHostConfig({
							...config,
							collection: { trustAnchors: new Map() },
							storage: memoryStorage({ collections: true }),
							metadata: {
								...config.metadata,
								...(!throughRole ? { federation_entity: metadata } : {}),
							},
							...(throughRole ? { roles: [{ type: "federation_entity", metadata }] } : {}),
							crypto: fixtureCryptoFromRead(async () => {
								if (failing) throw new Error("signing failed");
								return config.crypto.keyring.entry("federation");
							}),
							options: {
								logger: {
									debug() {},
									warn() {},
									error() {},
									info: (message) => {
										messages.push(message);
										throw new Error("Logger failed");
									},
								},
							},
						}),
					);
					failing = true;
					t.deepEqual(messages, []);
					await t.rejects(leaf.getEntityConfiguration());
					t.deepEqual(messages, []);
					failing = false;
					await leaf.getEntityConfiguration();
					await leaf.refreshEntityConfiguration();
					t.equal(
						messages.filter((message) => message.includes("SHOULD also publish")).length,
						resolve ? 0 : 1,
					);
				}
		});
	});

	module("leaf / injected logging", () => {
		test("concurrent generations report returned results while only the newest updates the cache", async (t) => {
			function gate() {
				let release!: () => void;
				const promise = new Promise<void>((resolve) => {
					release = resolve;
				});
				return { promise, release };
			}
			const { config } = await createLeafConfig();
			const firstKeys = await config.crypto.keyring.entry("federation");
			const replacement = await generateSigningKey("ES256");
			const secondKeys = await FixtureCrypto.fromJWK(replacement.privateKey).keyring.entry(
				"federation",
			);
			for (const newestFirst of [false, true])
				for (const throwingLogger of [false, true]) {
					const ready = [gate(), gate()];
					const finish = [gate(), gate()];
					const messages: unknown[][] = [];
					let calls = 0;
					let initialized = false;
					const leaf = await Leaf.create(
						fixtureHostConfig({
							...config,
							collection: { trustAnchors: new Map() },
							storage: memoryStorage({ collections: true }),
							metadata: {
								...config.metadata,
								federation_entity: { federation_collection_endpoint: `${LEAF_ID}/collect` },
							},
							crypto: fixtureCryptoFromRead(async () => {
								if (!initialized) return firstKeys;
								const index = calls++;
								const keys = index === 0 ? firstKeys : secondKeys;
								return {
									...keys,
									signer: instrumentSigningEntry(
										keys.signer,
										async (
											...args: [payload: Uint8Array, header: Readonly<Record<string, unknown>>]
										) => {
											const jwt = await rawFixtureJwt(keys.signer, ...args);
											ready[index]!.release();
											await finish[index]!.promise;
											return jwt;
										},
									).signer,
								};
							}),
							options: {
								logger: {
									debug() {},
									warn() {},
									error() {},
									info: (...args: unknown[]) => {
										messages.push(args);
										if (throwingLogger) throw new Error("Private sink error");
									},
								},
							},
						}),
					);
					initialized = true;
					try {
						const older = leaf.handleRequest(
							new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`),
						);
						await ready[0]!.promise;
						const newer = leaf.refreshEntityConfiguration();
						await ready[1]!.promise;
						let oldResponse: Response;
						let current: string;
						if (newestFirst) {
							finish[1]!.release();
							current = await newer;
							t.equal(
								messages.filter((args) => args[0] === "Entity Configuration generated").length,
								1,
							);
							finish[0]!.release();
							oldResponse = await older;
						} else {
							finish[0]!.release();
							oldResponse = await older;
							t.equal(
								messages.filter((args) => args[0] === "Entity Configuration generated").length,
								1,
							);
							finish[1]!.release();
							current = await newer;
						}
						t.equal(oldResponse.status, 200);
						const previous = await oldResponse.text();
						t.notEqual(
							previous,
							current,
							"the older caller receives its own generated configuration",
						);
						t.equal(
							await leaf.getEntityConfiguration(),
							current,
							"only the latest generation is cached",
						);
						t.equal(calls, 2);
						t.equal(
							messages.filter((args) => args[0] === "Entity Configuration generated").length,
							2,
						);
						t.equal(
							messages.filter((args) => String(args[0]).includes("SHOULD also publish")).length,
							1,
						);
						t.true(messages.every((args) => args.length === 1));
					} finally {
						for (const pending of finish) pending.release();
					}
				}
		});

		test("publication logs messages and a throwing logger cannot change HTTP responses", async (t) => {
			const messages: unknown[][] = [];
			const record = (...args: unknown[]) => {
				messages.push(args);
			};
			const logger = { debug: record, info: record, warn: record, error: record };
			const { config } = await createLeafConfig({ options: { logger } });
			const leaf = await Leaf.create(fixtureHostConfig(config));
			t.equal(
				(await leaf.handleRequest(new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`))).status,
				200,
			);
			t.true(messages.some((args) => args[0] === "Entity Configuration generated"));
			t.true(messages.every((args) => args.length === 1));
			const fail = () => {
				throw new Error("Logger failed");
			};
			const options = { logger: { debug: fail, info: fail, warn: fail, error: fail } };
			const healthy = await Leaf.create(fixtureHostConfig({ ...config, options }));
			t.equal(
				(await healthy.handleRequest(new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`)))
					.status,
				200,
			);
			const broken = await Leaf.create(
				fixtureHostConfig({
					...config,
					options,
					crypto: await fixtureCryptoFailureAfterStartup(new Error("Private signing error")),
				}),
			);
			const response = await broken.handleRequest(
				new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`),
			);
			t.equal(response.status, 500);
			t.false((await response.text()).includes("Private signing error"));
		});
	});

	test("leaf rejects authentication companions for forbidden endpoints", async (t) => {
		const { config } = await createLeafConfig();
		for (const endpoint of ["fetch", "list", "extended_list"]) {
			await t.rejects(
				(async () =>
					await Leaf.create(
						fixtureHostConfig({
							...config,
							metadata: {
								federation_entity: { [`federation_${endpoint}_endpoint_auth_methods`]: ["none"] },
							},
						}),
					))(),
				/cannot publish/,
			);
		}
	});

	module("leaf / inline metadata key publication", () => {
		test("requires use only for mixed signing and encryption sets and preserves extensions", async (t) => {
			const { config, publicKey } = await createLeafConfig();
			const other = await generateSigningKey("ES256");
			const { use: _sigUse, ...sig } = publicKey;
			const { use: _encUse, ...enc } = other.publicKey;
			const signing = { ...sig, alg: "ES256", key_ops: ["verify"] };
			const encryption = { ...enc, alg: "ECDH-ES", key_ops: ["deriveKey"] };
			const labelled = [
				{ ...signing, use: "sig" },
				{ ...encryption, use: "enc" },
			];
			for (const scenario of [
				{ keys: [signing, encryption], valid: false },
				{ keys: [{ ...signing, use: "sig" }, encryption], valid: false },
				{
					keys: [
						{ ...signing, use: "" },
						{ ...encryption, use: "enc" },
					],
					valid: false,
				},
				{ keys: labelled, valid: true },
				{
					keys: [...labelled, { ...signing, kid: "extra", use: "urn:example:other-use" }],
					valid: true,
				},
				{ keys: [signing], valid: true },
				{ keys: [encryption], valid: true },
			]) {
				const jwks = { keys: scenario.keys };
				const configured = { ...config, metadata: { openid_relying_party: { jwks } } };
				if (!scenario.valid) {
					await t.rejects(
						(async () => await Leaf.create(fixtureHostConfig(configured)))(),
						/'use'/,
					);
					continue;
				}
				const leaf = await Leaf.create(fixtureHostConfig(configured));
				const published = decodeEntityStatement(await leaf.getEntityConfiguration());
				t.true(published.ok);
				if (published.ok)
					t.deepEqual(published.value.payload.metadata?.openid_relying_party?.jwks, jwks);
			}
		});
		test("allows superiors to complete an explicit-registration endpoint", async (t) => {
			const { config } = await createLeafConfig();
			const metadata = {
				openid_provider: { issuer: LEAF_ID, client_registration_types_supported: ["explicit"] },
			};
			const leaf = await Leaf.create(fixtureHostConfig({ ...config, metadata }));
			const published = decodeEntityStatement(await leaf.getEntityConfiguration());
			t.true(published.ok);
			if (published.ok) t.deepEqual(published.value.payload.metadata, metadata);
		});
	});
	module("leaf / public root exports", () => {
		test("exports only the leaf class as a runtime entrypoint", (t) => {
			t.equal(LeafPublic.Leaf, Leaf);
			t.false("discoverEntity" in LeafPublic.Leaf);
			t.false("discoverEntity" in LeafPublic);
			t.false("createFederationSigningKey" in LeafPublic);
		});
	});

	// -------------------------------------------------------------------------
	// discovery
	// -------------------------------------------------------------------------
	module("leaf / discoverEntity", () => {
		test("returns correct entityId from valid discovery", async (t) => {
			const fed = await createMockFederation();
			const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);
			t.true(isOk(result));
			if (isOk(result)) {
				t.equal(result.value.entityId, OP_ID);
			}
		});

		test("returns resolvedMetadata from valid discovery", async (t) => {
			const fed = await createMockFederation();
			const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);
			t.true(isOk(result));
			if (isOk(result)) {
				t.ok(result.value.resolvedMetadata, "resolvedMetadata defined");
				t.ok(result.value.resolvedMetadata.openid_provider, "openid_provider defined");
			}
		});

		test("returns trustChain from valid discovery", async (t) => {
			const fed = await createMockFederation();
			const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);
			t.true(isOk(result));
			if (isOk(result)) {
				t.ok(result.value.trustChain, "trustChain defined");
				t.equal(result.value.trustChain.entityId, OP_ID);
				t.equal(result.value.trustChain.trustAnchorId, TA_ID);
				t.ok(result.value.trustChain.statements.length >= 2, "at least 2 statements");
			}
		});

		test("returns empty trustMarks array when none present", async (t) => {
			const fed = await createMockFederation();
			const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);
			t.true(isOk(result));
			if (isOk(result)) {
				t.deepEqual(result.value.trustMarks, []);
			}
		});

		test("fails when no trust chain can be resolved", async (t) => {
			const fed = await createMockFederation();
			const unknownEntity = entityId("https://unknown.example.com");
			const result = await discoverEntity(unknownEntity, fed.trustAnchors, fed.options);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(
					result.error.description.includes("No trust chains resolved"),
					result.error.description,
				);
			}
		});

		test("error message includes chain resolution details when no chains resolve", async (t) => {
			const fed = await createMockFederation();
			const unknownEntity = entityId("https://unknown.example.com");
			const result = await discoverEntity(unknownEntity, fed.trustAnchors, fed.options);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(
					/No trust chains resolved for entity/.test(result.error.description),
					result.error.description,
				);
			}
		});

		test("fails with validation details when all chains fail validation", async (t) => {
			const fed = await createMockFederation();
			const wrongTrustAnchors = createMockTrustAnchors(TA_ID, fed.opPublicKey);
			const result = await discoverEntity(OP_ID, wrongTrustAnchors, fed.options);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(
					/No valid trust chains for entity:/.test(result.error.description),
					result.error.description,
				);
			}
		});

		test("discovers leaf entity through federation", async (t) => {
			const fed = await createMockFederation();
			const result = await discoverEntity(LEAF_ID, fed.trustAnchors, fed.options);
			t.true(isOk(result));
			if (isOk(result)) {
				t.equal(result.value.entityId, LEAF_ID);
				t.equal(result.value.trustChain.trustAnchorId, TA_ID);
			}
		});

		test("selects shortest chain when multiple valid chains exist", async (t) => {
			const fed = await createMockFederation();
			const result = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);
			t.true(isOk(result));
			if (isOk(result)) {
				t.ok(result.value.trustChain.statements.length >= 2, "at least 2 statements");
			}
		});
	});

	// -------------------------------------------------------------------------
	// Leaf — validation
	// -------------------------------------------------------------------------
	module("leaf / Leaf / validation", () => {
		test("rejects empty metadata — requires at least one Entity Type", async (t) => {
			const { config } = await createLeafConfig({ metadata: {} as never });
			await t.rejects(
				(async () => await Leaf.create(fixtureHostConfig(config)))(),
				/metadata MUST contain at least one Entity Type/,
			);
		});

		test("throws on empty authorityHints", async (t) => {
			const { config } = await createLeafConfig({
				authorityHints: [] as unknown as [EntityId, ...EntityId[]],
			});
			await t.rejects(
				(async () => await Leaf.create(fixtureHostConfig(config)))(),
				/authorityHints/,
			);
		});

		test("rejects non-HTTPS authorityHint — requires valid Entity Identifiers", async (t) => {
			const { config } = await createLeafConfig({
				authorityHints: ["http://ta.example.com" as EntityId],
			});
			await t.rejects(
				(async () => await Leaf.create(fixtureHostConfig(config)))(),
				/authorityHint/,
			);
		});

		test("throws on empty trustAnchorHints", async (t) => {
			const { config } = await createLeafConfig({
				trustAnchorHints: [],
			});
			await t.rejects(
				(async () => await Leaf.create(fixtureHostConfig(config)))(),
				/trustAnchorHints/,
			);
		});

		test("rejects non-HTTPS trustAnchorHint — requires valid Entity Identifiers", async (t) => {
			const { config } = await createLeafConfig({
				trustAnchorHints: ["http://ta.example.com" as EntityId],
			});
			await t.rejects(
				(async () => await Leaf.create(fixtureHostConfig(config)))(),
				/trustAnchorHint/,
			);
		});

		test("throws when crypto is missing", async (t) => {
			const { config } = await createLeafConfig({ crypto: undefined });
			await t.rejects((async () => await Leaf.create(fixtureHostConfig(config)))(), /crypto/);
		});

		test("throws on signer key without kid", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const keyWithoutKid = { ...privateKey } as Record<string, unknown>;
			delete keyWithoutKid.kid;
			t.throws(() => new SigningEntryFixture(keyWithoutKid as unknown as JWK), /kid/);
		});

		test("throws when metadata includes federation_fetch_endpoint", async (t) => {
			const { config } = await createLeafConfig({
				metadata: {
					openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
					federation_entity: { federation_fetch_endpoint: "https://rp.example.com/fetch" },
				} as never,
			});
			await t.rejects(
				(async () => await Leaf.create(fixtureHostConfig(config)))(),
				/Leaf entities MUST NOT publish federation_fetch_endpoint/,
			);
		});

		test("throws when metadata includes federation_list_endpoint", async (t) => {
			const { config } = await createLeafConfig({
				metadata: {
					openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
					federation_entity: { federation_list_endpoint: "https://rp.example.com/list" },
				} as never,
			});
			await t.rejects(
				(async () => await Leaf.create(fixtureHostConfig(config)))(),
				/Leaf entities MUST NOT publish federation_list_endpoint/,
			);
		});

		test("rejects extended listing endpoint metadata directly and through roles", async (t) => {
			const endpoint = { federation_extended_list_endpoint: "https://rp.example.com/extended" };
			for (const overrides of [
				{ metadata: { federation_entity: endpoint } },
				{ roles: [{ type: "federation_entity", metadata: endpoint }] },
			]) {
				const { config } = await createLeafConfig(overrides);
				await t.rejects(
					(async () => await Leaf.create(fixtureHostConfig(config)))(),
					/Leaf entities MUST NOT publish federation_extended_list_endpoint/,
				);
			}
		});

		test("throws on duplicate kid values", async (t) => {
			const { privateKey: key1 } = await generateSigningKey("ES256");
			const { privateKey: key2 } = await generateSigningKey("ES256");
			const key2WithSameKid = { ...key2, kid: key1.kid } as unknown as JWK;
			await t.rejects(
				(async () =>
					await fixtureCryptoFromKeys([
						createFederationSigningKey(key1),
						createFederationSigningKey(key2WithSameKid),
					]))(),
				/identifiers cannot be reused/,
			);
		});

		test("rejects symmetric key (kty 'oct') — requires asymmetric keys", async (t) => {
			t.throws(
				() =>
					new SigningEntryFixture({ kty: "oct", kid: "sym-1", k: "c2VjcmV0" } as unknown as JWK),
				/private key material/,
			);
		});

		test("rejects private material in the published federation JWK", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			t.throws(
				() =>
					new FixtureCrypto({
						signer: new SigningEntryFixture(privateKey),
						publicJwk: privateKey,
					}),
				/public JWK/,
			);
		});

		test("rejects a federation public JWK whose kid differs from the signer", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			t.throws(
				() =>
					new FixtureCrypto({
						signer: new SigningEntryFixture(privateKey),
						publicJwk: { ...stripPrivateFields(privateKey), kid: "different-key" },
					}),
				/selected signer/,
			);
		});

		test("rejects non-HTTPS entityId — requires https scheme", async (t) => {
			const { config } = await createLeafConfig({
				entityId: "http://rp.example.com" as EntityId,
			});
			await t.rejects((async () => await Leaf.create(fixtureHostConfig(config)))(), /HTTPS URL/);
		});

		test("rejects entityId with query parameter", async (t) => {
			const { config } = await createLeafConfig({
				entityId: "https://rp.example.com?foo=bar" as EntityId,
			});
			await t.rejects((async () => await Leaf.create(fixtureHostConfig(config)))(), /HTTPS URL/);
		});

		test("rejects entityId with fragment", async (t) => {
			const { config } = await createLeafConfig({
				entityId: "https://rp.example.com#frag" as EntityId,
			});
			await t.rejects((async () => await Leaf.create(fixtureHostConfig(config)))(), /HTTPS URL/);
		});

		test("rejects empty entityId", async (t) => {
			const { config } = await createLeafConfig({ entityId: "" as EntityId });
			await t.rejects((async () => await Leaf.create(fixtureHostConfig(config)))());
		});

		test("rejects ttlSeconds of 0", async (t) => {
			const { config } = await createLeafConfig({ entityConfigurationTtlSeconds: 0 });
			await t.rejects(
				(async () => await Leaf.create(fixtureHostConfig(config)))(),
				/entityConfigurationTtlSeconds must be positive/,
			);
		});

		test("rejects negative ttlSeconds", async (t) => {
			const { config } = await createLeafConfig({ entityConfigurationTtlSeconds: -1 });
			await t.rejects(
				(async () => await Leaf.create(fixtureHostConfig(config)))(),
				/entityConfigurationTtlSeconds must be positive/,
			);
		});
	});

	// -------------------------------------------------------------------------
	// Leaf — entity ID preservation
	// -------------------------------------------------------------------------
	module("leaf / Leaf / entity ID preservation", () => {
		test("preserves trailing slash in iss/sub", async (t) => {
			const { config } = await createLeafConfig({
				entityId: "https://rp.example.com/" as EntityId,
			});
			const entity = await Leaf.create(fixtureHostConfig(config));
			t.equal(entity.entityId, "https://rp.example.com/");
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.iss, "https://rp.example.com/");
			t.equal(decoded.value.payload.sub, "https://rp.example.com/");
		});

		test("preserves entityId without trailing slash", async (t) => {
			const { config } = await createLeafConfig({
				entityId: "https://rp.example.com" as EntityId,
			});
			const entity = await Leaf.create(fixtureHostConfig(config));
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.iss, "https://rp.example.com");
		});
	});

	// -------------------------------------------------------------------------
	// Leaf — getEntityConfiguration
	// -------------------------------------------------------------------------
	module("leaf / Leaf / getEntityConfiguration", () => {
		test("returns a valid signed JWT", async (t) => {
			const { config, publicKey } = await createLeafConfig();
			const entity = await Leaf.create(fixtureHostConfig(config));
			const jwt = await entity.getEntityConfiguration();
			t.equal(jwt.split(".").length, 3);
			const result = await verifyEntityStatement(
				jwt,
				{ keys: [publicKey] },
				{ engine: testEngine },
			);
			t.true(result.ok);
		});

		test("has iss === sub === entityId", async (t) => {
			const { config } = await createLeafConfig();
			const entity = await Leaf.create(fixtureHostConfig(config));
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.iss, LEAF_ID);
			t.equal(decoded.value.payload.sub, LEAF_ID);
		});

		test("includes typ: entity-statement+jwt", async (t) => {
			const { config } = await createLeafConfig();
			const entity = await Leaf.create(fixtureHostConfig(config));
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.header.typ, JwtTyp.EntityStatement);
		});

		test("contains public keys only in jwks (no d field)", async (t) => {
			const { config } = await createLeafConfig();
			const entity = await Leaf.create(fixtureHostConfig(config));
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const jwks = decoded.value.payload.jwks;
			t.ok(jwks, "jwks present");
			if (!jwks) return;
			t.ok(jwks.keys.length > 0, "has keys");
			for (const key of jwks.keys) {
				const k = key as Record<string, unknown>;
				t.equal(k.d, undefined, "no d");
				t.equal(k.p, undefined, "no p");
				t.equal(k.q, undefined, "no q");
				t.equal(k.dp, undefined, "no dp");
				t.equal(k.dq, undefined, "no dq");
				t.equal(k.qi, undefined, "no qi");
			}
		});

		test("includes authority_hints", async (t) => {
			const { config } = await createLeafConfig();
			const entity = await Leaf.create(fixtureHostConfig(config));
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.deepEqual(p.authority_hints, [TA_ID]);
		});

		test("includes trust_anchor_hints when configured", async (t) => {
			const trustAnchorHint = entityId("https://preferred-ta.example.com");
			const { config } = await createLeafConfig({ trustAnchorHints: [trustAnchorHint] });
			const entity = await Leaf.create(fixtureHostConfig(config));
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.deepEqual(p.trust_anchor_hints, [trustAnchorHint]);
		});

		test("includes metadata", async (t) => {
			const { config } = await createLeafConfig();
			const entity = await Leaf.create(fixtureHostConfig(config));
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.deepEqual(
				decoded.value.payload.metadata,
				config.metadata as Record<string, Record<string, unknown>>,
			);
		});

		test("includes trust_marks when configured", async (t) => {
			const trustMarks = [{ trust_mark_type: "https://example.com/tm1", trust_mark: "jwt-value" }];
			const { config } = await createLeafConfig({ trustMarks });
			const entity = await Leaf.create(fixtureHostConfig(config));
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.deepEqual(p.trust_marks, trustMarks);
		});

		test("omits trust_marks when not configured", async (t) => {
			const { config } = await createLeafConfig();
			const entity = await Leaf.create(fixtureHostConfig(config));
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const p = decoded.value.payload as Record<string, unknown>;
			t.equal(p.trust_marks, undefined);
		});

		test("sets exp = iat + ttlSeconds (default 86400)", async (t) => {
			const { config } = await createLeafConfig();
			const entity = await Leaf.create(fixtureHostConfig(config));
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const { iat, exp } = decoded.value.payload;
			t.equal(exp - iat, 86400);
		});

		test("respects custom entityConfigurationTtlSeconds", async (t) => {
			const { config } = await createLeafConfig({ entityConfigurationTtlSeconds: 3600 });
			const entity = await Leaf.create(fixtureHostConfig(config));
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const { iat, exp } = decoded.value.payload;
			t.equal(exp - iat, 3600);
		});

		test("caches the signed JWT", async (t) => {
			const { config } = await createLeafConfig();
			const entity = await Leaf.create(fixtureHostConfig(config));
			const jwt1 = await entity.getEntityConfiguration();
			const jwt2 = await entity.getEntityConfiguration();
			t.equal(jwt1, jwt2);
		});

		test("includes all public keys for multi-key config", async (t) => {
			const { privateKey: key1 } = await generateSigningKey("ES256");
			const { privateKey: key2 } = await generateSigningKey("ES256");
			const { config } = await createLeafConfig({
				crypto: await fixtureCryptoFromKeys([
					createFederationSigningKey(key1),
					createFederationSigningKey(key2),
				]),
			});
			const entity = await Leaf.create(fixtureHostConfig(config));
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.jwks?.keys.length, 2);
			t.equal(decoded.value.header.kid, key2.kid);
		});

		test("concurrent calls share one signing operation (stampede protection)", async (t) => {
			const { config: baseConfig } = await createLeafConfig();
			let providerCalls = 0;
			const keySet = await baseConfig.crypto.keyring.entry("federation");
			const { config } = await createLeafConfig({
				crypto: fixtureCryptoFromRead(async () => {
					providerCalls++;
					return keySet;
				}),
			});
			const entity = await Leaf.create(fixtureHostConfig(config));
			providerCalls = 0;
			const [jwt1, jwt2] = await Promise.all([
				entity.getEntityConfiguration(),
				entity.getEntityConfiguration(),
			]);
			t.equal(jwt1, jwt2);
			t.equal(providerCalls, 1);
		});

		test("propagates key provider rejection", async (t) => {
			const { config } = await createLeafConfig({
				crypto: await fixtureCryptoFailureAfterStartup(new Error("key provider failure")),
			});
			const entity = await Leaf.create(fixtureHostConfig(config));
			try {
				await entity.getEntityConfiguration();
				t.ok(false, "should have thrown");
			} catch (e) {
				t.ok((e as Error).message.includes("key provider failure"), (e as Error).message);
			}
		});
	});

	// -------------------------------------------------------------------------
	// Leaf — isEntityConfigurationExpired
	// -------------------------------------------------------------------------
	module("leaf / Leaf / isEntityConfigurationExpired", () => {
		test("returns false for fresh EC", async (t) => {
			const { config } = await createLeafConfig();
			const entity = await Leaf.create(fixtureHostConfig(config));
			await entity.getEntityConfiguration();
			t.false(entity.isEntityConfigurationExpired());
		});

		test("returns true when no EC has been generated", async (t) => {
			const { config } = await createLeafConfig();
			const entity = await Leaf.create(fixtureHostConfig(config));
			t.true(entity.isEntityConfigurationExpired());
		});

		test("returns true at exact expiry boundary (now === exp)", async (t) => {
			const ttl = 3600;
			let nowMs = Date.now();
			const clock = { now: () => Math.floor(nowMs / 1000) };
			const { config } = await createLeafConfig({
				entityConfigurationTtlSeconds: ttl,
				options: { clock },
			});
			const entity = await Leaf.create(fixtureHostConfig(config));
			await entity.getEntityConfiguration();
			nowMs += ttl * 1000;
			t.true(entity.isEntityConfigurationExpired());
		});
	});

	// -------------------------------------------------------------------------
	// Leaf — cache expiry
	// -------------------------------------------------------------------------
	module("leaf / Leaf / cache expiry", () => {
		test("rebuilds EC after TTL expires", async (t) => {
			const ttl = 60;
			let nowMs = Date.now();
			const clock = { now: () => Math.floor(nowMs / 1000) };
			const { config } = await createLeafConfig({
				entityConfigurationTtlSeconds: ttl,
				options: { clock },
			});
			const entity = await Leaf.create(fixtureHostConfig(config));
			const jwt1 = await entity.getEntityConfiguration();
			nowMs += (ttl + 1) * 1000;
			const jwt2 = await entity.getEntityConfiguration();
			t.notEqual(jwt1, jwt2, "rebuilt after TTL");
		});
	});

	// -------------------------------------------------------------------------
	// Leaf — refreshEntityConfiguration
	// -------------------------------------------------------------------------
	module("leaf / Leaf / refreshEntityConfiguration", () => {
		test("produces a new JWT", async (t) => {
			const { config } = await createLeafConfig();
			const entity = await Leaf.create(fixtureHostConfig(config));
			await entity.getEntityConfiguration();
			const jwt2 = await entity.refreshEntityConfiguration();
			t.equal(typeof jwt2, "string");
			t.equal(jwt2.split(".").length, 3);
		});

		test("replaces the cached EC", async (t) => {
			const { config } = await createLeafConfig();
			const entity = await Leaf.create(fixtureHostConfig(config));
			await entity.getEntityConfiguration();
			const refreshed = await entity.refreshEntityConfiguration();
			const cached = await entity.getEntityConfiguration();
			t.equal(cached, refreshed);
		});
	});

	// -------------------------------------------------------------------------
	// Leaf — handleRequest
	// -------------------------------------------------------------------------
	module("leaf / Leaf / handleRequest", () => {
		test("responds 200 with entity-statement+jwt on /.well-known/openid-federation", async (t) => {
			const { config } = await createLeafConfig();
			const entity = await Leaf.create(fixtureHostConfig(config));
			const request = new Request("https://rp.example.com/.well-known/openid-federation");
			const response = await entity.handleRequest(request);
			t.equal(response.status, 200);
			t.equal(response.headers.get("content-type"), "application/entity-statement+jwt");
			const body = await response.text();
			t.equal(body.split(".").length, 3);
		});

		test("serves descriptive federation entity metadata at the well-known endpoint", async (t) => {
			const descriptiveMetadata = {
				organization_name: "Leaf Federation Entity",
				contacts: ["ops@rp.example.com"],
				organization_uri: "https://rp.example.com/about",
			};
			const { config } = await createLeafConfig({
				metadata: {
					federation_entity: descriptiveMetadata,
				},
			});
			const entity = await Leaf.create(fixtureHostConfig(config));
			const response = await entity.handleRequest(
				new Request("https://rp.example.com/.well-known/openid-federation"),
			);
			t.equal(response.status, 200);
			t.equal(response.headers.get("content-type"), MediaType.EntityStatement);
			const decoded = decodeEntityStatement(await response.text());
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			t.deepEqual(decoded.value.payload.metadata?.federation_entity, descriptiveMetadata);
		});

		test("merges role metadata without mutating caller metadata", async (t) => {
			const inputMetadata = {
				federation_entity: { organization_name: "Leaf" },
			};
			const role = {
				type: "openid_relying_party",
				metadata: { client_name: "Role RP" },
			};
			const { config } = await createLeafConfig({
				metadata: inputMetadata,
				roles: [role],
			});
			const entity = await Leaf.create(fixtureHostConfig(config));

			t.false(Object.hasOwn(inputMetadata, "openid_relying_party"));
			const jwt = await entity.getEntityConfiguration();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			t.deepEqual(decoded.value.payload.metadata?.federation_entity, {
				organization_name: "Leaf",
			});
			t.deepEqual(decoded.value.payload.metadata?.openid_relying_party, {
				client_name: "Role RP",
			});
		});

		test("serves path-based Entity Identifier at derived well-known path", async (t) => {
			const pathEntityId = entityId("https://rp.example.com/tenant");
			const { config } = await createLeafConfig({ entityId: pathEntityId });
			const entity = await Leaf.create(fixtureHostConfig(config));
			const response = await entity.handleRequest(
				new Request(`${pathEntityId}${WELL_KNOWN_OPENID_FEDERATION}`),
			);
			t.equal(response.status, 200);
			const jwt = await response.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			t.equal(decoded.value.payload.iss, pathEntityId);
			t.equal(decoded.value.payload.sub, pathEntityId);
		});

		test("preserves port and path when serving the well-known endpoint", async (t) => {
			const { config } = await createLeafConfig({
				entityId: "https://rp.example.com:8443/tenant/" as EntityId,
			});
			const entity = await Leaf.create(fixtureHostConfig(config));
			t.equal(entity.entityId, "https://rp.example.com:8443/tenant/");
			const response = await entity.handleRequest(
				new Request("https://rp.example.com:8443/tenant/.well-known/openid-federation"),
			);
			t.equal(response.status, 200);
			const decoded = decodeEntityStatement(await response.text());
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			t.equal(decoded.value.payload.iss, "https://rp.example.com:8443/tenant/");
			t.equal(decoded.value.payload.sub, "https://rp.example.com:8443/tenant/");
		});

		test("preserves the identifier and removes the slash from the well-known route", async (t) => {
			const { config } = await createLeafConfig({
				entityId: "https://rp.example.com/tenant/" as EntityId,
			});
			const entity = await Leaf.create(fixtureHostConfig(config));
			t.equal(entity.entityId, "https://rp.example.com/tenant/");
			const response = await entity.handleRequest(
				new Request("https://rp.example.com/tenant/.well-known/openid-federation"),
			);
			t.equal(response.status, 200);
			const rootResponse = await entity.handleRequest(
				new Request("https://rp.example.com/.well-known/openid-federation"),
			);
			t.equal(rootResponse.status, 404);
		});

		test("returns 405 for POST to well-known path", async (t) => {
			const { config } = await createLeafConfig();
			const entity = await Leaf.create(fixtureHostConfig(config));
			const response = await entity.handleRequest(
				new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`, { method: "POST" }),
			);
			t.equal(response.status, 405);
		});

		test("returns 404 for unknown paths", async (t) => {
			const { config } = await createLeafConfig();
			const entity = await Leaf.create(fixtureHostConfig(config));
			const response = await entity.handleRequest(new Request(`${LEAF_ID}/unknown-path`));
			t.equal(response.status, 404);
		});

		test("returns 500 when getEntityConfiguration throws", async (t) => {
			const originalError = new Error("signing failure");
			const { config } = await createLeafConfig({
				crypto: await fixtureCryptoFailureAfterStartup(originalError),
			});
			const entity = await Leaf.create(fixtureHostConfig(config));
			const response = await entity.handleRequest(
				new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`),
			);
			t.equal(response.status, 500);
			const body = (await response.json()) as Record<string, unknown>;
			t.equal(body.error, "server_error");
		});

		test("500 body does NOT contain internal error message (no info leak)", async (t) => {
			const secretMessage = "database password is hunter2";
			const { config } = await createLeafConfig({
				crypto: await fixtureCryptoFailureAfterStartup(new Error(secretMessage)),
			});
			const entity = await Leaf.create(fixtureHostConfig(config));
			const response = await entity.handleRequest(
				new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`),
			);
			const text = await response.text();
			t.notOk(text.includes(secretMessage), "secret not in response");
		});

		test("logs a safe error message on 500", async (t) => {
			const originalError = new Error("signing failure");
			const errorFn = mockFn<[string, Record<string, unknown>]>();
			const { config } = await createLeafConfig({
				crypto: await fixtureCryptoFailureAfterStartup(originalError),
				options: {
					logger: {
						debug: mockFn(),
						info: mockFn(),
						warn: mockFn(),
						error: errorFn,
					},
				},
			});
			const entity = await Leaf.create(fixtureHostConfig(config));
			await entity.handleRequest(new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`));
			t.equal(errorFn.callCount(), 1);
			const [msg, ctx] = errorFn.lastCall();
			t.equal(msg, "Failed to serve entity configuration");
			t.equal(ctx, undefined, "error objects are not logged");
		});

		test("404 response has error and error_description fields", async (t) => {
			const { config } = await createLeafConfig();
			const entity = await Leaf.create(fixtureHostConfig(config));
			const response = await entity.handleRequest(new Request(`${LEAF_ID}/unknown`));
			const body = (await response.json()) as Record<string, unknown>;
			t.equal(body.error, "not_found");
			t.equal(body.error_description, "Unknown endpoint");
		});

		test("405 response has error field", async (t) => {
			const { config } = await createLeafConfig();
			const entity = await Leaf.create(fixtureHostConfig(config));
			const response = await entity.handleRequest(
				new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`, { method: "POST" }),
			);
			const body = (await response.json()) as Record<string, unknown>;
			t.equal(body.error, "method_not_allowed");
		});

		test("500 response has error and error_description fields", async (t) => {
			const { config } = await createLeafConfig({
				crypto: await fixtureCryptoFailureAfterStartup(new Error("fail")),
			});
			const entity = await Leaf.create(fixtureHostConfig(config));
			const response = await entity.handleRequest(
				new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`),
			);
			const body = (await response.json()) as Record<string, unknown>;
			t.equal(body.error, "server_error");
			t.equal(body.error_description, "An internal error occurred");
		});
	});

	// -------------------------------------------------------------------------
	// integration
	// -------------------------------------------------------------------------
	module("leaf / integration", () => {
		test("end-to-end: EC generation + handler serving", async (t) => {
			const fed = await createMockMockFederation();
			const config: LeafConfig = {
				entityId: LEAF_ID,
				crypto: new FixtureCrypto(createFederationSigningKey(fed.leafSigningKey)),
				authorityHints: [TA_ID],
				metadata: {
					openid_relying_party: {
						redirect_uris: ["https://rp.example.com/callback"],
						response_types: ["code"],
						client_registration_types: ["automatic"],
					},
				},
			};
			const entity = await Leaf.create(fixtureHostConfig(config));
			const response = await entity.handleRequest(
				new Request(`${LEAF_ID}${WELL_KNOWN_OPENID_FEDERATION}`),
			);
			t.equal(response.status, 200);
			t.equal(response.headers.get("Content-Type"), MediaType.EntityStatement);
			const jwt = await response.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal(decoded.value.payload.iss, LEAF_ID);
			t.equal(decoded.value.payload.sub, LEAF_ID);
			const p = decoded.value.payload as Record<string, unknown>;
			t.deepEqual(p.authority_hints, [TA_ID]);
		});

		test("end-to-end: discover OP through mock federation", async (t) => {
			const fed = await createMockMockFederation();
			const config: LeafConfig = {
				entityId: LEAF_ID,
				crypto: new FixtureCrypto(createFederationSigningKey(fed.leafSigningKey)),
				authorityHints: [TA_ID],
				metadata: {
					openid_relying_party: {
						redirect_uris: ["https://rp.example.com/callback"],
						response_types: ["code"],
					},
				},
			};
			await Leaf.create(fixtureHostConfig(config));
			const discovery = await discoverEntity(OP_ID, fed.trustAnchors, fed.options);
			t.true(isOk(discovery));
			if (isOk(discovery)) {
				t.equal(discovery.value.entityId, OP_ID);
				t.ok(discovery.value.resolvedMetadata.openid_provider, "openid_provider present");
				t.equal(discovery.value.trustChain.trustAnchorId, TA_ID);
			}
		});

		test("EC caching and refresh cycle", async (t) => {
			const fed = await createMockMockFederation();
			const config: LeafConfig = {
				entityId: LEAF_ID,
				crypto: new FixtureCrypto(createFederationSigningKey(fed.leafSigningKey)),
				authorityHints: [TA_ID],
				metadata: {
					openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] },
				},
			};
			const entity = await Leaf.create(fixtureHostConfig(config));
			t.true(entity.isEntityConfigurationExpired());
			const ec1 = await entity.getEntityConfiguration();
			t.false(entity.isEntityConfigurationExpired());
			const ec2 = await entity.getEntityConfiguration();
			t.equal(ec1, ec2);
			const ec3 = await entity.refreshEntityConfiguration();
			t.equal(typeof ec3, "string");
			const ec4 = await entity.getEntityConfiguration();
			t.equal(ec4, ec3);
		});
	});
	module("leaf / overlapping configuration refresh", () => {
		test("explicit refresh publishes provider changes through every rollover stage", async (t) => {
			let nowMs = 1000000;
			const original = await generateSigningKey("ES256");
			const next = await generateSigningKey("ES256");
			const provider = FixtureCrypto.fromJWK(original.privateKey, {
				nowMs: () => nowMs,
			});
			const { config } = await createLeafConfig({
				crypto: provider,
				options: { clock: { now: () => Math.floor(nowMs / 1000) } },
			});
			const leaf = await Leaf.create(fixtureHostConfig(config));
			let cached = await leaf.getEntityConfiguration();
			await provider.keyring.publish(
				"federation",
				fixtureSigner(createFederationSigningKey(next.privateKey)),
			);
			t.equal(await leaf.getEntityConfiguration(), cached);
			cached = await leaf.refreshEntityConfiguration();
			let decoded = decodeEntityStatement(cached);
			t.true(decoded.ok);
			if (decoded.ok) {
				t.equal(decoded.value.header.kid, original.publicKey.kid);
				t.equal(decoded.value.payload.jwks?.keys.length, 2);
			}
			await provider.keyring.activate("federation", next.privateKey.kid!);
			t.equal(await leaf.getEntityConfiguration(), cached);
			cached = await leaf.refreshEntityConfiguration();
			decoded = decodeEntityStatement(cached);
			t.true(decoded.ok);
			if (decoded.ok) {
				t.equal(decoded.value.header.kid, next.publicKey.kid);
				t.equal(decoded.value.payload.jwks?.keys.length, 2);
			}
			nowMs += 1000;
			await provider.keyring.retire("federation", original.privateKey.kid!);
			t.equal(await leaf.getEntityConfiguration(), cached);
			decoded = decodeEntityStatement(await leaf.refreshEntityConfiguration());
			t.true(decoded.ok);
			if (decoded.ok)
				t.deepEqual(
					decoded.value.payload.jwks?.keys.map((key) => key.kid),
					[next.publicKey.kid],
				);
		});

		test("an older build cannot overwrite the refreshed configuration", async (t) => {
			const { config } = await createLeafConfig();
			const old = await config.crypto.keyring.entry("federation");
			const next = await generateSigningKey("ES256");
			let entered!: () => void, release!: () => void;
			const started = new Promise<void>((r) => {
				entered = r;
			});
			const gate = new Promise<void>((r) => {
				release = r;
			});
			let current = {
				...old,
				signer: instrumentSigningEntry(
					old.signer,
					async (...args: [payload: Uint8Array, header: Readonly<Record<string, unknown>>]) => {
						entered();
						await gate;
						return rawFixtureJwt(old.signer, ...args);
					},
				).signer,
			};
			const leaf = await Leaf.create(
				fixtureHostConfig({
					...config,
					crypto: fixtureCryptoFromRead(async () => current),
				}),
			);
			const pending = leaf.getEntityConfiguration();
			await started;
			current = {
				signer: new SigningEntryFixture(next.privateKey).signer,
				publishedJwks: { keys: [next.publicKey] },
			};
			const refreshed = await leaf.refreshEntityConfiguration();
			release();
			await pending;
			t.equal(await leaf.getEntityConfiguration(), refreshed);
			const decoded = decodeEntityStatement(refreshed);
			t.true(decoded.ok);
			if (decoded.ok) t.equal(decoded.value.header.kid, next.publicKey.kid);
		});
		test("old failures cannot clear the current in-flight refresh", async (t) => {
			const { config } = await createLeafConfig();
			const set = await config.crypto.keyring.entry("federation");
			let failOld!: () => void, releaseNew!: () => void, started!: () => void;
			const oldGate = new Promise<void>((_, reject) => {
				failOld = () => reject(new Error("old signing failed"));
			});
			const newGate = new Promise<void>((r) => {
				releaseNew = r;
			});
			const entered = new Promise<void>((r) => {
				started = r;
			});
			let calls = 0;
			const leaf = await Leaf.create(
				fixtureHostConfig({
					...config,
					crypto: fixtureCryptoFromRead(async () => ({
						...set,
						signer: instrumentSigningEntry(
							set.signer,
							async (...args: [payload: Uint8Array, header: Readonly<Record<string, unknown>>]) => {
								calls++;
								if (calls === 1) {
									started();
									await oldGate;
								} else await newGate;
								return rawFixtureJwt(set.signer, ...args);
							},
						).signer,
					})),
				}),
			);
			const old = leaf.getEntityConfiguration();
			const rejected = t.rejects(old, /old signing failed/);
			await entered;
			const refreshed = leaf.refreshEntityConfiguration();
			failOld();
			await rejected;
			const concurrent = leaf.getEntityConfiguration();
			releaseNew();
			t.equal(await concurrent, await refreshed);
			t.equal(calls, 2, "get reuses the current refresh rather than starting another build");
		});
	});
};

async function createMockMockFederation() {
	return createMockFederation();
}
