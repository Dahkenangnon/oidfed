/** Verify artifact-specific key selection and algorithm policy through the public federation APIs. */
import type { KeyringEntry } from "@oidfed/crypto";
import { createWebCryptoEngine } from "@oidfed/crypto/web";
import type QUnit from "qunit";
import { TrustAnchor } from "../../../packages/authority/src/index.js";
import {
	bindFederationOptions,
	type CryptoContext,
	createClientAssertion,
	createTrustAnchorSet,
	decodeEntityStatement,
	entityId,
	type FederationArtifact,
	type FederationOptions,
	fetchSignedJwkSet,
	fetchSubordinateEvents,
	fetchSubordinateStatement,
	jwtResponse,
	MediaType,
	signEntityStatement,
	signProtocolJwkSet,
	signTrustMark,
	validateSignedJwkSetSpecHygiene,
	validateTrustChain,
	validateTrustMark,
	verifyEntityStatement,
	verifyHistoricalKeysResponse,
	verifyResolveResponse,
	verifySignedJwkSet,
	verifyTrustMarkStatusResponse,
} from "../../../packages/core/src/index.js";
import { Leaf } from "../../../packages/leaf/src/index.js";
import { memoryStorage } from "../../storage-fixtures.js";
import { cryptoFixture } from "../fixtures/crypto.js";
import {
	generateSigningKey,
	SigningEntryFixture,
	testEngine,
} from "../fixtures/software-crypto.js";

import resolvePolicyTests from "./resolve-policy.js";

const issuer = entityId("https://artifact-authority.example");
const subject = entityId("https://artifact-leaf.example");
const markType = "https://artifact-authority.example/marks/member";
const secondaryArtifacts: readonly FederationArtifact[] = [
	"subordinate-statement",
	"subordinate-events",
	"historical-keys",
	"resolve-response",
	"trust-mark-delegation",
	"trust-mark-status",
];
const algorithms = ["ES256", "ES384"];
const policy = (artifact: FederationArtifact) =>
	secondaryArtifacts.includes(artifact) ? ["ES384"] : ["ES256"];

export default function artifactSigningTests(qunit: QUnit): void {
	const { module, test } = qunit;
	resolvePolicyTests(qunit);
	module("integration / Federation artifact signing", () => {
		for (const algorithm of ["RS384", "RS512"] as const)
			test(`${algorithm} requires both engine support and explicit Federation approval`, async (assert) => {
				const key = await cryptoFixture(algorithm);
				const entry = { signer: key.signer, publishedJwks: { keys: [key.publicJwk] } };
				const payload = { iss: issuer, sub: issuer };
				await assert.rejects(signEntityStatement(payload, entry), /outside the configured policy/);
				const allowedFederationAlgorithms = [algorithm];
				const jwt = await signEntityStatement(payload, entry, { allowedFederationAlgorithms });
				const engine = createWebCryptoEngine(undefined, { algorithms: [algorithm] });
				assert.false((await verifyEntityStatement(jwt, entry.publishedJwks, { engine })).ok);
				assert.false(
					(
						await verifyEntityStatement(jwt, entry.publishedJwks, {
							engine: testEngine,
							allowedFederationAlgorithms,
						})
					).ok,
				);
				assert.true(
					(
						await verifyEntityStatement(jwt, entry.publishedJwks, {
							engine,
							allowedFederationAlgorithms,
						})
					).ok,
				);
			});

		test("signed protocol JWKS round-trips through the public verifier and fetcher", async (assert) => {
			const [federation, protocol] = await Promise.all([
				generateSigningKey(),
				generateSigningKey(),
			]);
			const signer = new SigningEntryFixture(federation.privateKey);
			const crypto = { engine: testEngine, keyring: { entry: async () => signer } };
			const { kid: _kid, ...key } = protocol.publicKey;
			const jwks = { keys: [key] };
			const clock = { now: () => 10_000 };
			const input = { issuer, jwks, crypto, options: { clock } };
			const verify = { engine: testEngine, expectedIssuer: issuer, expectedOwner: issuer, clock };
			const minimal = await signProtocolJwkSet(input);
			const parsed = await verifySignedJwkSet(minimal, signer.publishedJwks, verify);
			assert.true(parsed.ok);
			if (!parsed.ok) return;
			assert.deepEqual(parsed.value, { iss: issuer, sub: issuer, keys: [key] });
			assert.true(validateSignedJwkSetSpecHygiene(parsed.value).ok);
			assert.false((await verifySignedJwkSet(minimal, { keys: [protocol.publicKey] }, verify)).ok);

			const withDate = await signProtocolJwkSet({ ...input, issuedAt: 9_999 });
			const dated = await verifySignedJwkSet(withDate, signer.publishedJwks, verify);
			assert.true(dated.ok && dated.value.iat === 9_999 && dated.value.exp === undefined);

			const jwt = await signProtocolJwkSet({ ...input, owner: subject, ttlSeconds: 60 });
			assert.false((await verifySignedJwkSet(jwt, signer.publishedJwks, verify)).ok);
			const wrongIssuer = { ...verify, expectedOwner: subject, expectedIssuer: subject };
			assert.false((await verifySignedJwkSet(jwt, signer.publishedJwks, wrongIssuer)).ok);
			const route = `${issuer}/keys`;
			const fetched = await fetchSignedJwkSet(route, signer.publishedJwks, {
				...verify,
				expectedOwner: subject,
				httpClient(input, init) {
					const request = new Request(input, init);
					assert.strictEqual(request.method, "GET");
					assert.strictEqual(request.url, route);
					return Promise.resolve(jwtResponse(jwt, MediaType.JwkSet));
				},
			});
			assert.true(fetched.ok);
			if (!fetched.ok) return;
			assert.strictEqual(fetched.value.sub, subject);
			assert.strictEqual(fetched.value.iat, 10_000);
			assert.strictEqual(fetched.value.exp, 10_060);
			assert.false(validateSignedJwkSetSpecHygiene(fetched.value).ok);
			const wrongMediaType = await fetchSignedJwkSet(route, signer.publishedJwks, {
				...verify,
				expectedOwner: subject,
				httpClient: async () => jwtResponse(jwt, MediaType.EntityStatement),
			});
			assert.false(wrongMediaType.ok);
		});

		test("signed protocol JWKS rejects unsafe inputs before selecting a Federation signer", async (assert) => {
			const key = await generateSigningKey();
			let selections = 0;
			const crypto = {
				engine: testEngine,
				keyring: {
					async entry() {
						selections++;
						return new SigningEntryFixture(key.privateKey);
					},
				},
			};
			const input = { issuer, jwks: { keys: [key.publicKey] }, crypto };
			await assert.rejects(
				signProtocolJwkSet({ ...input, jwks: { keys: [key.privateKey] } }),
				/invalid public JWK Set structure/,
			);
			const { use: _use, ...signingKey } = key.publicKey;
			await assert.rejects(
				signProtocolJwkSet({
					...input,
					jwks: { keys: [signingKey, { ...key.publicKey, use: "enc" }] },
				}),
				/signing and encryption keys/,
			);
			await assert.rejects(
				signProtocolJwkSet({ ...input, jwks: { keys: [{ ...key.publicKey, x: "invalid" }] } }),
				/expected.*octets|base64url/,
			);
			await assert.rejects(signProtocolJwkSet({ ...input, ttlSeconds: 0 }), /ttlSeconds/);
			await assert.rejects(signProtocolJwkSet({ ...input, issuedAt: Infinity }), /iat/);
			await assert.rejects(
				signProtocolJwkSet({ ...input, issuedAt: Number.MAX_VALUE, ttlSeconds: Number.MAX_VALUE }),
				/expiry/,
			);
			assert.strictEqual(selections, 0);
			const unrelated = (await generateSigningKey()).publicKey;
			await assert.rejects(
				signProtocolJwkSet({
					...input,
					crypto: { ...crypto, readPublishedFederationJwks: () => ({ keys: [unrelated] }) },
				}),
				/absent from the issuer's published Federation JWKS/,
			);
			await assert.rejects(
				signProtocolJwkSet({ ...input, options: { allowedAlgorithmsForArtifact: () => [] } }),
				/outside the configured policy/,
			);
		});

		test("hosts select artifact bindings that verify against each issuer's published keys", async (assert) => {
			const [regular, separate, leafKey, ownerKey] = await Promise.all([
				generateSigningKey("ES256"),
				generateSigningKey("ES384"),
				generateSigningKey("ES256"),
				generateSigningKey("ES384"),
			]);
			const primary = new SigningEntryFixture(regular.privateKey);
			const secondary = new SigningEntryFixture(separate.privateKey);
			const leafEntry = new SigningEntryFixture(leafKey.privateKey);
			const ownerEntry = new SigningEntryFixture(ownerKey.privateKey);
			const publishedJwks = { keys: [regular.publicKey, separate.publicKey] };
			const seen: FederationArtifact[] = [];
			const crypto: CryptoContext = {
				engine: testEngine,
				history: { getHistoricalKeys: async () => [] },
				keyring: {
					async entry(purpose, context) {
						assert.strictEqual(purpose, "federation");
						if (!context?.artifact) throw new Error("Missing Federation artifact");
						seen.push(context.artifact);
						if (context.artifact === "trust-mark-delegation") return ownerEntry;
						const entry = secondaryArtifacts.includes(context.artifact) ? secondary : primary;
						return { signer: entry.signer, publishedJwks };
					},
				},
			};
			const base = {
				engine: testEngine,
				allowedFederationAlgorithms: algorithms,
				allowedAlgorithmsForArtifact: policy,
			};
			const trustAnchors = createTrustAnchorSet([{ entityId: issuer, jwks: publishedJwks }]);
			const leaf = await Leaf.create({
				entityId: subject,
				authorityHints: [issuer],
				metadata: { federation_entity: {} },
				crypto: {
					engine: testEngine,
					keyring: {
						async entry(_purpose, context) {
							assert.strictEqual(context?.artifact, "entity-configuration");
							return leafEntry;
						},
					},
				},
				options: base,
			});
			const leafEc = await leaf.getEntityConfiguration();
			const httpClient: FederationOptions["httpClient"] = (input, init) => {
				const request = new Request(input, init);
				return (new URL(request.url).origin === subject ? leaf : authority).handleRequest(request);
			};
			const authority = await TrustAnchor.create({
				entityId: issuer,
				crypto,
				storage: memoryStorage({ subordinateEvents: true, trustMarks: true }),
				trustAnchors,
				trustMarkOwners: { [markType]: { sub: issuer, jwks: ownerEntry.publishedJwks } },
				options: { ...base, httpClient },
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${issuer}/fetch`,
						federation_list_endpoint: `${issuer}/list`,
						federation_historical_keys_endpoint: `${issuer}/history`,
						federation_subordinate_events_endpoint: `${issuer}/events`,
						federation_resolve_endpoint: `${issuer}/resolve`,
						federation_trust_mark_status_endpoint: `${issuer}/mark-status`,
					},
				},
			});
			await authority.registerSubordinate({ entityId: subject, jwks: leafEntry.publishedJwks });
			const ec = await authority.getEntityConfiguration();
			const decoded = decodeEntityStatement(ec);
			assert.true(decoded.ok);
			if (!decoded.ok || !decoded.value.payload.jwks) return;
			const issuerKeys = decoded.value.payload.jwks;
			assert.true(
				(await verifyEntityStatement(ec, issuerKeys, { ...base, artifact: "entity-configuration" }))
					.ok,
			);
			assert.true(
				(
					await verifyEntityStatement(leafEc, leafEntry.publishedJwks, {
						...base,
						artifact: "entity-configuration",
					})
				).ok,
			);

			const fetched = await fetchSubordinateStatement(`${issuer}/fetch`, subject, {
				...base,
				issuer,
				httpClient,
			});
			assert.true(fetched.ok);
			if (!fetched.ok) return;
			const chain = await validateTrustChain([leafEc, fetched.value, ec], trustAnchors, {
				...base,
				entityConfigurations: new Map([[subject, leafEc]]),
			});
			assert.true(chain.valid, JSON.stringify(chain.valid ? undefined : chain.errors));
			assert.true(
				(
					await fetchSubordinateEvents(`${issuer}/events`, subject, {
						...base,
						httpClient,
						issuer,
						issuerJwks: issuerKeys,
					})
				).ok,
			);

			const history = await authority.handleRequest(new Request(`${issuer}/history`));
			assert.strictEqual(history.status, 200);
			assert.true(
				(
					await verifyHistoricalKeysResponse(await history.text(), issuerKeys, {
						...base,
						expectedIssuer: issuer,
					})
				).ok,
			);

			const resolved = await authority.resolveEntity(subject, issuer);
			const resolveVerify = { ...base, expectedIssuer: issuer, expectedSubject: subject };
			assert.true((await verifyResolveResponse(resolved, issuerKeys, resolveVerify)).ok);
			const resolveUrl = new URL(`${issuer}/resolve`);
			resolveUrl.search = new URLSearchParams({ sub: subject, trust_anchor: issuer }).toString();
			const cached = await authority.handleRequest(new Request(resolveUrl));
			assert.strictEqual(cached.status, 200);
			assert.true((await verifyResolveResponse(await cached.text(), issuerKeys, resolveVerify)).ok);
			assert.strictEqual(seen.filter((artifact) => artifact === "resolve-response").length, 2);

			assert.false(issuerKeys.keys.some((key) => key.kid === ownerKey.publicKey.kid));
			const mark = await authority.issueTrustMark(subject, `${markType}/direct`);
			assert.true(
				(
					await validateTrustMark(mark, { [`${markType}/direct`]: [issuer] }, issuerKeys, {
						...base,
						expectedSubject: subject,
					})
				).ok,
			);
			const delegation = await authority.issueTrustMarkDelegation(subject, markType);
			const delegated = await signTrustMark({
				issuer: subject,
				subject: issuer,
				trustMarkType: markType,
				signer: leafEntry,
				delegation,
				allowedAlgorithmsForArtifact: policy,
			});
			const delegatedCheck = await validateTrustMark(
				delegated,
				{ [markType]: [subject] },
				leafEntry.publishedJwks,
				{
					...base,
					expectedSubject: issuer,
					trustMarkOwners: { [markType]: { sub: issuer, jwks: ownerEntry.publishedJwks } },
				},
			);
			assert.true(
				delegatedCheck.ok,
				JSON.stringify(delegatedCheck.ok ? undefined : delegatedCheck.error),
			);
			const status = await authority.handleRequest(
				new Request(`${issuer}/mark-status`, {
					method: "POST",
					body: new URLSearchParams({ trust_mark: mark }),
				}),
			);
			assert.strictEqual(status.status, 200);
			assert.true(
				(
					await verifyTrustMarkStatusResponse(await status.text(), issuerKeys, {
						...base,
						expectedIssuer: issuer,
						expectedTrustMark: mark,
					})
				).ok,
			);

			const signedSet = await signProtocolJwkSet({
				issuer,
				owner: subject,
				jwks: { keys: [leafKey.publicKey] },
				crypto,
				options: base,
			});
			assert.true(
				(
					await verifySignedJwkSet(signedSet, issuerKeys, {
						...base,
						expectedIssuer: issuer,
						expectedOwner: subject,
					})
				).ok,
			);
			const wrongProfile = await verifyHistoricalKeysResponse(signedSet, issuerKeys, {
				...base,
				expectedIssuer: issuer,
			});
			assert.false(wrongProfile.ok);
			if (!wrongProfile.ok) assert.strictEqual(wrongProfile.error.code, "ERR_UNSUPPORTED_ALG");
			assert.deepEqual(
				new Set(seen),
				new Set<FederationArtifact>([
					"entity-configuration",
					"subordinate-statement",
					"subordinate-events",
					"historical-keys",
					"resolve-response",
					"trust-mark",
					"trust-mark-delegation",
					"trust-mark-status",
					"signed-protocol-jwks",
				]),
			);
		});

		test("Authority rejects an unpublished signer and a publication with the same kid on a different key", async (assert) => {
			const [current, next] = await Promise.all([generateSigningKey(), generateSigningKey()]);
			const currentEntry = new SigningEntryFixture(current.privateKey);
			const nextEntry = new SigningEntryFixture(next.privateKey);
			let signatures = 0;
			const historySigner = {
				...nextEntry.signer,
				sign(input: Uint8Array) {
					signatures++;
					return nextEntry.signer.sign(input);
				},
			};
			const config = {
				entityId: issuer,
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${issuer}/fetch`,
						federation_list_endpoint: `${issuer}/list`,
						federation_historical_keys_endpoint: `${issuer}/history`,
					},
				},
				storage: memoryStorage(),
			};
			const crypto: CryptoContext = {
				engine: testEngine,
				history: { getHistoricalKeys: async () => [] },
				keyring: {
					async entry(_purpose, context) {
						return context?.artifact === "historical-keys"
							? { signer: historySigner, publishedJwks: nextEntry.publishedJwks }
							: currentEntry;
					},
				},
			};
			const request = () => new Request(`${issuer}/history`);
			const authority = await TrustAnchor.create({ ...config, crypto });
			assert.strictEqual((await authority.handleRequest(request())).status, 500);
			assert.strictEqual(signatures, 0);

			let published = { keys: [{ ...current.publicKey, kid: nextEntry.signer.publicJwk.kid }] };
			let unavailable = false;
			const external = await TrustAnchor.create({
				...config,
				crypto: {
					...crypto,
					readPublishedFederationJwks(id) {
						assert.strictEqual(id, issuer);
						if (unavailable) throw new Error("Publication unavailable");
						return published;
					},
				},
			});
			assert.strictEqual((await external.handleRequest(request())).status, 500);
			published = {
				keys: [{ ...next.publicKey, kid: nextEntry.signer.publicJwk.kid, use: "enc" }],
			};
			assert.strictEqual((await external.handleRequest(request())).status, 500);
			published = { keys: [{ ...next.publicKey, kid: nextEntry.signer.publicJwk.kid }] };
			unavailable = true;
			assert.strictEqual((await external.handleRequest(request())).status, 500);
			assert.strictEqual(signatures, 0);
			unavailable = false;
			const response = await external.handleRequest(request());
			assert.strictEqual(response.status, 200);
			assert.true(
				(
					await verifyHistoricalKeysResponse(await response.text(), published, {
						engine: testEngine,
						expectedIssuer: issuer,
					})
				).ok,
			);
			assert.strictEqual(signatures, 1);
		});

		test("Leaf waits for its refreshed Entity Configuration before accepting a new signer", async (assert) => {
			const [current, next] = await Promise.all([generateSigningKey(), generateSigningKey()]);
			const currentEntry = new SigningEntryFixture(current.privateKey);
			const nextEntry = new SigningEntryFixture(next.privateKey);
			const overlap = { keys: [current.publicKey, next.publicKey] };
			let finishRefresh!: () => void;
			const refresh = new Promise<void>((resolve) => {
				finishRefresh = resolve;
			});
			let publishOverlap = false;
			let historicalSignatures = 0;
			const leaf = await Leaf.create({
				entityId: subject,
				authorityHints: [issuer],
				metadata: {
					federation_entity: { federation_historical_keys_endpoint: `${subject}/history` },
				},
				crypto: {
					engine: testEngine,
					history: { getHistoricalKeys: async () => [] },
					keyring: {
						async entry(_purpose, context) {
							if (context?.artifact === "historical-keys")
								return {
									publishedJwks: overlap,
									signer: {
										...nextEntry.signer,
										sign(input) {
											historicalSignatures++;
											return nextEntry.signer.sign(input);
										},
									},
								};
							if (!publishOverlap) return currentEntry;
							return {
								publishedJwks: overlap,
								signer: {
									...currentEntry.signer,
									async sign(input) {
										await refresh;
										return currentEntry.signer.sign(input);
									},
								},
							};
						},
					},
				},
			});
			await leaf.getEntityConfiguration();
			publishOverlap = true;
			const pending = leaf.refreshEntityConfiguration();
			try {
				await assert.rejects(
					leaf.getHistoricalKeys(),
					/absent from the issuer's published Federation JWKS/,
				);
				assert.strictEqual(historicalSignatures, 0);
			} finally {
				finishRefresh();
			}
			const ec = decodeEntityStatement(await pending);
			const published = ec.ok ? ec.value.payload.jwks : undefined;
			assert.ok(published);
			if (!published) return;
			const history = await leaf.getHistoricalKeys();
			assert.true(
				(
					await verifyHistoricalKeysResponse(history, published, {
						engine: testEngine,
						expectedIssuer: subject,
					})
				).ok,
			);
			assert.strictEqual(historicalSignatures, 1);
		});

		test("artifact policy intersects every layer and rejects invalid results before signing", async (assert) => {
			const key = await generateSigningKey("ES256");
			const entry = new SigningEntryFixture(key.privateKey);
			const payload = { iss: issuer, sub: issuer };
			const legacy = await signEntityStatement(payload, entry);
			assert.true(
				(await verifyEntityStatement(legacy, entry.publishedJwks, { engine: testEngine })).ok,
			);
			let signatures = 0;
			const counted: KeyringEntry = {
				...entry,
				signer: {
					publicJwk: entry.signer.publicJwk,
					sign(input) {
						signatures++;
						return entry.signer.sign(input);
					},
				},
			};
			// A role cannot widen the host policy, and a call cannot widen the role policy.
			for (const options of [
				bindFederationOptions(
					{ engine: testEngine },
					{ allowedFederationAlgorithms: ["ES384"] },
					{ allowedAlgorithmsForArtifact: () => ["ES256", "ES384"] },
				),
				bindFederationOptions(
					{ engine: testEngine },
					{ allowedAlgorithmsForArtifact: () => algorithms },
					{ allowedAlgorithmsForArtifact: () => ["ES384"] },
					{ allowedAlgorithmsForArtifact: () => algorithms },
				),
				{ engine: testEngine, allowedAlgorithmsForArtifact: () => [] },
			]) {
				await assert.rejects(
					signEntityStatement(payload, counted, { ...options, artifact: "entity-configuration" }),
					/outside the configured policy/,
				);
				assert.false(
					(
						await verifyEntityStatement(legacy, entry.publishedJwks, {
							...options,
							artifact: "entity-configuration",
						})
					).ok,
				);
			}
			for (const invalid of [
				() => ["unregistered"],
				() => "ES256",
				() => Promise.reject(new Error("async detail")),
				() => {
					throw new Error("private detail");
				},
			]) {
				const options = {
					engine: testEngine,
					artifact: "entity-configuration" as const,
					allowedAlgorithmsForArtifact: invalid as () => readonly string[],
				};
				await assert.rejects(
					signEntityStatement(payload, counted, options),
					/Invalid Federation artifact algorithm policy/,
				);
				const verification = await verifyEntityStatement(legacy, entry.publishedJwks, options);
				assert.false(verification.ok);
				if (!verification.ok)
					assert.strictEqual(
						verification.error.description,
						"Federation artifact algorithm policy could not be applied",
					);
			}
			await assert.rejects(
				signEntityStatement(payload, counted, { allowedAlgorithmsForArtifact: policy }),
				/requires an artifact/,
			);
			assert.strictEqual(signatures, 0);
		});

		test("Federation endpoint assertion policy applies at sender and receiver", async (assert) => {
			const [serverKey, clientKey, approvedKey] = await Promise.all([
				generateSigningKey(),
				generateSigningKey(),
				generateSigningKey("ES384"),
			]);
			const serverEntry = new SigningEntryFixture(serverKey.privateKey);
			const clientEntry = new SigningEntryFixture(clientKey.privateKey);
			const approvedEntry = new SigningEntryFixture(approvedKey.privateKey);
			const storage = memoryStorage({ subordinateEvents: true });
			let keyLookups = 0;
			const config = {
				entityId: issuer,
				crypto: {
					engine: testEngine,
					keyring: {
						async entry() {
							return serverEntry;
						},
					},
				},
				storage,
				clientKeyProvider: {
					async getClientFederationJwks() {
						keyLookups++;
						return { keys: [clientKey.publicKey, approvedKey.publicKey] };
					},
				},
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${issuer}/fetch`,
						federation_list_endpoint: `${issuer}/list`,
						federation_subordinate_events_endpoint: `${issuer}/events`,
						federation_fetch_endpoint_auth_methods: ["private_key_jwt"],
					},
				},
				options: {
					allowedAlgorithmsForArtifact: (artifact) =>
						artifact === "client-assertion" ? ["ES384"] : ["ES256"],
				},
			} satisfies Parameters<typeof TrustAnchor.create>[0];
			await assert.rejects(
				TrustAnchor.create({
					...config,
					metadata: {
						federation_entity: {
							...config.metadata.federation_entity,
							endpoint_auth_signing_alg_values_supported: ["ES256", "ES384"],
						},
					},
				}),
				/Fetch endpoint advertises unsupported private_key_jwt algorithms/,
			);
			await assert.rejects(
				TrustAnchor.create({
					...config,
					crypto: {
						...config.crypto,
						engine: createWebCryptoEngine(undefined, { algorithms: ["ES256"] }),
					},
				}),
				/Fetch endpoint has no usable private_key_jwt algorithm/,
			);
			let drift = false;
			const authority = await TrustAnchor.create({
				...config,
				roles: [
					{
						type: "federation_entity",
						metadata: {},
						async publicationMetadata() {
							return drift ? { endpoint_auth_signing_alg_values_supported: ["ES256"] } : {};
						},
					},
				],
				metadata: {
					federation_entity: {
						...config.metadata.federation_entity,
						endpoint_auth_signing_alg_values_supported: ["ES384"],
					},
				},
			});
			await authority.registerSubordinate({
				entityId: subject,
				jwks: { keys: [clientKey.publicKey, approvedKey.publicKey] },
			});
			let requests = 0;
			const endpoint = `${issuer}/fetch`;
			const options: FederationOptions = {
				engine: testEngine,
				httpClient: (input, init) => {
					requests++;
					return authority.handleRequest(new Request(input, init));
				},
			};
			const authentication = {
				method: "private_key_jwt" as const,
				audience: issuer,
				clientId: subject,
				signer: clientEntry,
			};
			const blocked = await fetchSubordinateStatement(endpoint, subject, {
				...options,
				issuer,
				authentication,
				allowedAlgorithmsForArtifact: () => ["ES384"],
			});
			assert.false(blocked.ok);
			assert.strictEqual(requests, 0);
			const rejected = await fetchSubordinateStatement(endpoint, subject, {
				...options,
				issuer,
				authentication,
			});
			assert.false(rejected.ok);
			assert.strictEqual(requests, 1);
			assert.strictEqual(keyLookups, 0);
			if (!rejected.ok) assert.strictEqual(rejected.error.code, "invalid_client");
			const assertion = await createClientAssertion(subject, issuer, clientEntry, {
				engine: testEngine,
			});
			for (const explicitPolicy of [
				{ allowedAlgorithmsForArtifact: () => ["ES384"] },
				{ allowedFederationAlgorithms: ["ES384"] },
			]) {
				const held = await fetchSubordinateEvents(`${issuer}/events`, subject, {
					...options,
					issuer,
					issuerJwks: serverEntry.publishedJwks,
					clientAssertion: assertion,
					...explicitPolicy,
				});
				assert.false(held.ok);
			}
			assert.strictEqual(requests, 1);
			const accepted = await fetchSubordinateStatement(endpoint, subject, {
				...options,
				issuer,
				authentication: { ...authentication, signer: approvedEntry },
				allowedAlgorithmsForArtifact(artifact) {
					assert.strictEqual(artifact, "client-assertion");
					return ["ES384"];
				},
			});
			assert.true(accepted.ok);
			assert.strictEqual(requests, 2);
			assert.strictEqual(keyLookups, 1);
			drift = true;
			await assert.rejects(
				authority.getEntityConfiguration(),
				/Published federation_fetch_endpoint authentication must match/,
			);
		});

		test("Leaf validates optional Resolve and Collection authentication against their service policy", async (assert) => {
			const key = await generateSigningKey();
			const entry = new SigningEntryFixture(key.privateKey);
			const crypto: CryptoContext = {
				engine: testEngine,
				keyring: { entry: async () => entry },
			};
			const config = {
				entityId: subject,
				authorityHints: [issuer],
				crypto,
				storage: memoryStorage({ collections: true }),
			};
			const authentication = {
				methods: ["none", "private_key_jwt"],
				getClientFederationJwks: async () => entry.publishedJwks,
			};
			const serviceOptions = {
				allowedAlgorithmsForArtifact: () => ["ES256"],
			};
			const collection = {
				trustAnchors: createTrustAnchorSet([{ entityId: issuer, jwks: entry.publishedJwks }]),
				authentication,
				options: serviceOptions,
			};
			const resolver = { authentication, options: serviceOptions };
			for (const service of ["resolve", "collection"] as const) {
				const authField = `federation_${service}_endpoint_auth_methods` as const;
				const urlField = `federation_${service}_endpoint` as const;
				const build = (advertised: string[]) =>
					Leaf.create({
						...config,
						...(service === "resolve" ? { resolver } : { collection }),
						metadata: {
							federation_entity: {
								[authField]: authentication.methods,
								[urlField]: `${subject}/${service}`,
								endpoint_auth_signing_alg_values_supported: advertised,
							},
						},
					});
				const label = service === "resolve" ? "Resolve" : "Entity Collection";
				await assert.rejects(
					build(["ES256", "ES384"]),
					new RegExp(`${label} endpoint advertises unsupported`),
				);
				await assert.rejects(build([]), new RegExp(`${label} endpoint has no usable`));
				const host = await build(["ES256"]);
				const ec = decodeEntityStatement(await host.getEntityConfiguration());
				assert.deepEqual(
					ec.ok &&
						ec.value.payload.metadata?.federation_entity
							?.endpoint_auth_signing_alg_values_supported,
					["ES256"],
				);
			}
		});
	});
}
