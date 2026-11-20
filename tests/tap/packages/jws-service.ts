import { assertStorageView } from "@oidfed/core";
import { MemoryCache } from "../../../packages/core/src/storage/cache.js";
import { cacheStorage, memoryStorage, replayStorage } from "../../storage-fixtures.js";
/** Protocol policy regressions exercised through the real injected crypto contracts. */

import { Intermediate, TrustAnchor } from "@oidfed/authority";
import {
	bindFederationOptions,
	cloneData,
	compareTrustAnchorKeys,
	decodeEntityConfiguration,
	decodeEntityStatement,
	entityId,
	fetchEntityConfiguration,
	historicalKeysFromKeyring,
	JWT_BEARER_CLIENT_ASSERTION_TYPE,
	JwsService,
	MediaType,
	parseOAuthAuthorizationServerMetadata,
	parseOAuthAuthorizationServerPublicationMetadata,
	signEntityConfiguration,
	signingPublication,
	validateJwkSetUseRequirement,
	validateTrustChain,
	validateTrustMark,
	verifyClientAssertion,
	verifyEntityStatement,
} from "@oidfed/core";
import {
	type CryptoEngine,
	CryptoError,
	createJwsAlgorithmRegistry,
	decodeCompactJws,
	encodeBase64url,
	MemoryRotatingKeyring,
	parseCompactJws,
	type Signer,
	StaticKeyring,
	utf8Decode,
} from "@oidfed/crypto";
import { createJoseEngine } from "@oidfed/crypto/jose";
import { createWebCryptoEngine } from "@oidfed/crypto/web";
import { Leaf } from "@oidfed/leaf";
import { OAuthAuthorizationServerRole, OidcRelyingPartyRole } from "@oidfed/oidc";
import { WalletProviderRole } from "@oidfed/wallet";
import type QUnit from "qunit";
import {
	algorithmRegistry,
	createProfileEngine,
	profileAlgorithm,
	profileSigner,
} from "../../../docs/examples/custom-crypto.js";
import { oidcRegistrationSchemas } from "../../../packages/oidc/src/schemas/explicit-registration.js";
import { cryptoFixture } from "../fixtures/crypto.js";
import { signProtocolFixture } from "../fixtures/protocol-jwt.js";

export default async function register(qunit: QUnit) {
	const engine = createWebCryptoEngine();
	const f = await cryptoFixture();
	const entry = await new StaticKeyring({ signers: { federation: f.signer } }).entry("federation");
	const service = new JwsService({ engine, clock: { now: () => 1500 } });
	const payload = { iss: "https://issuer.example", iat: 1000, exp: 2000 };
	qunit.module("core / injected JWT service", () => {
		qunit.test(
			"discovery and a pinned chain preserve exact slash-terminated host identities",
			async (a) => {
				const anchorId = entityId("https://exact-anchor.example/");
				const intermediateId = entityId("https://exact-intermediate.example/tenant/");
				const leafId = entityId("https://exact-leaf.example/tenant/");
				const crypto = {
					engine,
					keyring: new StaticKeyring({ signers: { federation: f.signer } }),
				};
				const authorityMetadata = (id: string) => ({
					federation_entity: {
						federation_fetch_endpoint: `${id}fetch`,
						federation_list_endpoint: `${id}list`,
					},
				});
				const anchor = await TrustAnchor.create({
					entityId: anchorId,
					crypto,
					metadata: authorityMetadata(anchorId),
					storage: memoryStorage(),
				});
				const intermediate = await Intermediate.create({
					entityId: intermediateId,
					authorityHints: [anchorId],
					crypto,
					metadata: authorityMetadata(intermediateId),
					storage: memoryStorage(),
				});
				const leaf = await Leaf.create({
					entityId: leafId,
					authorityHints: [intermediateId],
					crypto,
					metadata: { federation_entity: {} },
				});
				const jwks = { keys: [f.publicJwk] };
				await anchor.registerSubordinate({ entityId: intermediateId, jwks });
				await intermediate.registerSubordinate({ entityId: leafId, jwks });

				const retrieved: string[] = [];
				for (const [id, host] of [
					[leafId, leaf],
					[intermediateId, intermediate],
					[anchorId, anchor],
				] as const) {
					a.equal(host.entityId, id);
					const configuration = await fetchEntityConfiguration(id, {
						engine,
						httpClient: async (url) => {
							a.equal(String(url), `${id.slice(0, -1)}/.well-known/openid-federation`);
							return host.handleRequest(new Request(url));
						},
					});
					a.true(configuration.ok);
					if (!configuration.ok) return;
					const decoded = decodeEntityConfiguration(configuration.value);
					a.true(decoded.ok);
					if (!decoded.ok) return;
					a.equal(decoded.value.payload.iss, id);
					a.equal(decoded.value.payload.sub, id);
					retrieved.push(configuration.value);
				}
				const [leafEc, intermediateEc, anchorEc] = retrieved;
				if (!leafEc || !intermediateEc || !anchorEc)
					throw new Error("Missing published configuration");
				const result = await validateTrustChain(
					[
						leafEc,
						await intermediate.getSubordinateStatement(leafId),
						await anchor.getSubordinateStatement(intermediateId),
						anchorEc,
					],
					new Map([[anchorId, { jwks }]]),
					{ engine, entityConfigurations: new Map([[intermediateId, intermediateEc]]) },
				);
				a.true(result.valid, result.valid ? "chain validated" : JSON.stringify(result.errors));
				if (result.valid) a.equal(result.chain.entityId, leafId);
			},
		);

		qunit.test("protocol metadata parsers classify registered signing keys consistently", (a) => {
			const { use: _use, ...signing } = profileSigner("profile", f.signer).publicJwk;
			const encryption = { ...f.publicJwk, alg: "ECDH-ES", use: "enc" };
			const missingUse = { keys: [signing, encryption] };
			const complete = { keys: [{ ...signing, use: "sig" }, encryption] };
			const options = { algorithmRegistry };
			const issuer = "https://issuer.example";
			const as = {
				issuer,
				authorization_endpoint: `${issuer}/authorize`,
				token_endpoint: `${issuer}/token`,
				response_types_supported: ["code"],
			};
			const rp = { redirect_uris: [`${issuer}/callback`] };
			const wallet = { vp_formats_supported: { "dc+sd-jwt": {} } };

			a.true(parseOAuthAuthorizationServerMetadata({ ...as, jwks: missingUse }).success);
			for (const [index, parse] of [
				(jwks: unknown) => parseOAuthAuthorizationServerMetadata({ ...as, jwks }, options),
				(jwks: unknown) =>
					parseOAuthAuthorizationServerMetadata(
						{ ...as, jwks },
						{ ...options, profile: "openid4vci" },
					),
				(jwks: unknown) => parseOAuthAuthorizationServerPublicationMetadata({ jwks }, options),
				(jwks: unknown) => OAuthAuthorizationServerRole.parseMetadata({ ...as, jwks }, options),
				(jwks: unknown) => OidcRelyingPartyRole.parseMetadata({ ...rp, jwks }, options),
				(jwks: unknown) => OidcRelyingPartyRole.parsePublicationMetadata({ jwks }, options),
				(jwks: unknown) => WalletProviderRole.parseMetadata({ ...wallet, jwks }, options),
				(jwks: unknown) => WalletProviderRole.parsePublicationMetadata({ jwks }, options),
			].entries()) {
				const invalid = parse(missingUse);
				a.false(invalid.success, `parser ${index} requires use on each key`);
				if (!invalid.success)
					a.true(
						invalid.error.issues.some((issue) => issue.path[0] === "jwks"),
						JSON.stringify(invalid.error.issues),
					);
				a.true(parse(complete).success, `parser ${index} accepts a fully labeled set`);
			}
			const response = (jwks: unknown) => ({
				iss: issuer,
				sub: `${issuer}/client`,
				aud: `${issuer}/client`,
				iat: 1000,
				exp: 2000,
				trust_anchor: `${issuer}/anchor`,
				authority_hints: [`${issuer}/anchor`],
				metadata: { openid_relying_party: { ...rp, client_id: `${issuer}/client`, jwks } },
			});
			const schema = oidcRegistrationSchemas.responseFor(options);
			a.false(schema.safeParse(response(missingUse)).success);
			const accepted = schema.safeParse(response(complete));
			a.true(
				accepted.success,
				accepted.success ? "valid response" : JSON.stringify(accepted.error.issues),
			);
		});

		qunit.test(
			"registered key formats work through mixed Federation chains and public history",
			async (a) => {
				const customEngine = createProfileEngine(engine);
				const clock = { now: () => 1500 };
				const options = {
					engine: customEngine,
					clock,
					algorithmRegistry,
					allowedFederationAlgorithms: [profileAlgorithm, "RS256"],
					verboseErrors: true,
				};
				const anchorId = entityId("https://profile-anchor.example");
				const leafId = entityId("https://profile-leaf.example");
				const custom = profileSigner("custom", f.signer);
				const replacement = profileSigner("replacement", (await cryptoFixture("ES256")).signer);
				const ring = new MemoryRotatingKeyring(
					{ federation: custom },
					{ algorithmRegistry, nowSeconds: clock.now },
				);
				const anchor = await TrustAnchor.create({
					entityId: anchorId,
					crypto: {
						engine: customEngine,
						algorithmRegistry,
						keyring: ring,
						history: historicalKeysFromKeyring(ring, "federation", algorithmRegistry),
					},
					options,
					storage: memoryStorage({
						engine: customEngine,
						clock,
						trustMarks: true,
						algorithmRegistry,
					}),
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: `${anchorId}/fetch`,
							federation_list_endpoint: `${anchorId}/list`,
							federation_historical_keys_endpoint: `${anchorId}/history`,
						},
					},
				});
				const rsa = await cryptoFixture("RS256");
				const childRing = new StaticKeyring({ signers: { federation: rsa.signer } });
				const leaf = await Leaf.create({
					entityId: leafId,
					authorityHints: [anchorId],
					crypto: { engine: customEngine, algorithmRegistry, keyring: childRing },
					metadata: { federation_entity: {} },
					options,
				});
				await anchor.registerSubordinate({ entityId: leafId, jwks: { keys: [rsa.publicJwk] } });
				const chain = [
					await leaf.getEntityConfiguration(),
					await anchor.getSubordinateStatement(leafId),
					await anchor.getEntityConfiguration(),
				];
				const pinned = { keys: [custom.publicJwk] };
				const anchors = new Map([[anchorId, { jwks: pinned }]]);
				const verified = await validateTrustChain(chain, anchors, options);
				a.true(
					verified.valid,
					verified.valid ? "mixed chain validated" : JSON.stringify(verified.errors),
				);
				a.false(
					(
						await validateTrustChain(chain, anchors, {
							...options,
							allowedFederationAlgorithms: ["RS256"],
						})
					).valid,
				);
				a.true(
					(await compareTrustAnchorKeys(pinned, pinned, anchorId, customEngine, algorithmRegistry))
						.match,
				);
				a.throws(
					() => parseCompactJws(chain[2]!),
					CryptoError,
					"default registry does not enable the profile",
				);
				const markType = "https://marks.example/profile";
				const mark = await anchor.issueTrustMark(leafId, markType);
				const checked = await validateTrustMark(mark, { [markType]: [anchorId] }, pinned, {
					...options,
					expectedSubject: leafId,
				});
				a.true(checked.ok, checked.ok ? "custom Trust Mark" : checked.error.description);
				await ring.publish("federation", replacement);
				await ring.activate("federation", "replacement");
				await ring.retire("federation", "custom");
				await ring.revoke("federation", "custom", "test revocation");
				const history = decodeEntityStatement(await anchor.getHistoricalKeys());
				a.true(history.ok);
				if (history.ok) {
					const keys = history.value.payload.keys as readonly Record<string, unknown>[];
					a.equal(keys[0]?.u, custom.publicJwk.u);
					a.equal(keys[0]?.kid, "custom");
				}
				a.deepEqual(Reflect.ownKeys(ring), []);
			},
		);

		qunit.test(
			"federation algorithm policy stays separate from hosted OIDC and wallet keys",
			async (a) => {
				const rsa = await cryptoFixture("RS256");
				const clock = { now: () => 1500 };
				const id = entityId("https://isolated-policy.example");
				const superior = entityId("https://isolated-anchor.example");
				const options = { engine, clock, allowedFederationAlgorithms: ["RS256"] };
				const keyring = new StaticKeyring({
					signers: { federation: rsa.signer, protocol: f.signer },
				});
				const rp = new OidcRelyingPartyRole({
					signing: { requestObject: "protocol", clientAssertion: "protocol" },
					metadata: { redirect_uris: [`${id}/callback`] },
				});
				const wallet = new WalletProviderRole({
					signing: { walletAttestation: "protocol" },
					metadata: { vp_formats_supported: { "dc+sd-jwt": {} } },
				});
				const leaf = await Leaf.create({
					entityId: id,
					authorityHints: [superior],
					crypto: { engine, keyring },
					roles: [rp, wallet],
					metadata: { federation_entity: {} },
					options,
				});
				const ec = await leaf.getEntityConfiguration();
				a.equal(parseCompactJws(ec).header.alg, "RS256");
				a.true((await verifyEntityStatement(ec, { keys: [rsa.publicJwk] }, options)).ok);
				const assertion = await rp.createClientAssertion(superior);
				a.equal(parseCompactJws(assertion).header.alg, "ES256");
				a.true(
					(await verifyClientAssertion(assertion, { keys: [f.publicJwk] }, superior, options)).ok,
				);
				const attestation = await wallet.createWalletAttestation({
					subject: "wallet",
					confirmationKey: f.publicJwk,
					expiresAt: 2000,
				});
				a.true(attestation.ok);
				if (attestation.ok) a.equal(parseCompactJws(attestation.value).header.alg, "ES256");
				const authority = await TrustAnchor.create({
					entityId: superior,
					crypto: { engine, keyring },
					options,
					storage: memoryStorage({ engine, clock }),
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: `${superior}/fetch`,
							federation_list_endpoint: `${superior}/list`,
							federation_fetch_endpoint_auth_methods: ["private_key_jwt"],
						},
					},
				});
				await authority.registerSubordinate({
					entityId: id,
					jwks: { keys: [rsa.publicJwk, f.publicJwk] },
				});
				const submit = (token: string) =>
					authority.handleRequest(
						new Request(`${superior}/fetch`, {
							method: "POST",
							body: new URLSearchParams({
								sub: id,
								client_assertion: token,
								client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE,
							}),
						}),
					);
				a.equal((await submit(assertion)).status, 401);
				const signed = await new JwsService({ engine, clock }).signJwt(
					await keyring.entry("federation"),
					{ iss: id, sub: id, aud: superior, iat: 1500, exp: 1560, jti: "federation" },
					{ typ: "JWT" },
				);
				const response = await submit(signed);
				a.equal(response.status, 200);
				a.equal(response.headers.get("content-type"), MediaType.EntityStatement);
				const wrong = await Leaf.create({
					entityId: id,
					authorityHints: [superior],
					crypto: { engine, keyring: new StaticKeyring({ signers: { federation: f.signer } }) },
					metadata: { federation_entity: {} },
					options,
				});
				await a.rejects(
					wrong.getEntityConfiguration(),
					(e: unknown) => e instanceof CryptoError && e.code === "UNSUPPORTED_ALGORITHM",
				);
			},
		);

		qunit.test(
			"registry rules reject invalid definitions and signatures consistently",
			async (a) => {
				a.throws(
					() =>
						createJwsAlgorithmRegistry({
							algorithms: [
								{
									id: "ES256",
									keyType: "EC",
									validatePublicKey() {},
									signature: { byteLength: 64 },
								},
							],
						}),
					TypeError,
				);
				const custom = profileSigner("registered", f.signer);
				const snapshot = await new StaticKeyring({
					signers: { federation: custom },
					algorithmRegistry,
				}).entry("federation");
				const hostEngine = createProfileEngine(engine);
				const options = {
					engine: hostEngine,
					algorithmRegistry,
					allowedAlgorithms: [profileAlgorithm],
					clock: { now: () => 1500 },
				};
				const tokens = new JwsService(options);
				const good = await tokens.signJwt(snapshot, payload, { typ: "JWT" });
				a.true(
					(
						await tokens.verifyJwt(good, snapshot.publishedJwks, {
							typ: { expected: "JWT" },
							keyId: "required",
						})
					).ok,
				);
				const bound = bindFederationOptions(
					{ engine: hostEngine, algorithmRegistry },
					{ allowedFederationAlgorithms: ["ES256"] },
					{ allowedFederationAlgorithms: [profileAlgorithm, "ES256"] },
				);
				a.deepEqual(bound.allowedFederationAlgorithms, ["ES256"]);
				const incompleteSigner: Signer = {
					publicJwk: custom.publicJwk,
					sign: async () => new Uint8Array(63),
				};
				const short = { ...snapshot, signer: incompleteSigner };
				await a.rejects(tokens.signJwt(short, payload, { typ: "JWT" }), CryptoError);
				let calls = 0;
				const counted = new JwsService({
					...options,
					engine: {
						...hostEngine,
						verify: async (input) => {
							calls++;
							return hostEngine.verify(input);
						},
					},
				});
				const [header, body] = good.split(".");
				const result = await counted.verifyJwt(
					`${header}.${body}.${encodeBase64url(new Uint8Array(63))}`,
					snapshot.publishedJwks,
					{ typ: { expected: "JWT" }, keyId: "required" },
				);
				a.false(result.ok);
				a.equal(calls, 0);
			},
		);
		qunit.test("both adapters reject invalid NIST curve points before native use", async (a) => {
			for (const alg of ["ES256", "ES384", "ES512"] as const) {
				const key = (await cryptoFixture(alg)).publicJwk;
				const width = alg === "ES256" ? 32 : alg === "ES384" ? 48 : 66;
				const outOfRange = encodeBase64url(new Uint8Array(width).fill(255));
				const zero = encodeBase64url(new Uint8Array(width));
				for (const backend of [engine, createJoseEngine()]) {
					await backend.validatePublicKey(key, alg);
					for (const invalid of [
						{ ...key, x: outOfRange },
						{ ...key, y: outOfRange },
						{ ...key, x: zero, y: zero },
					]) {
						await a.rejects(
							backend.validatePublicKey(invalid, alg),
							(e: unknown) => e instanceof CryptoError && e.code === "MALFORMED_KEY",
						);
					}
				}
			}
		});
		qunit.test("client assertion identifiers apply to the complete published JWKS", async (a) => {
			const claims = {
				iss: "client",
				sub: "client",
				aud: "receiver",
				iat: 1400,
				exp: 2000,
				jti: "assertion",
			};
			const options = { engine, clock: { now: () => 1500 } };
			const anonymous = await signProtocolFixture(claims, entry, {
				typ: "JWT",
				extraHeaders: { kid: undefined },
			});
			const keyed = await service.signJwt(entry, claims, { typ: "JWT" });
			const unlabeled = { ...f.publicJwk };
			delete unlabeled.kid;
			a.true(
				(await verifyClientAssertion(anonymous, { keys: [unlabeled] }, "receiver", options)).ok,
			);
			a.false(
				(
					await verifyClientAssertion(
						anonymous,
						{ keys: [unlabeled, { kty: "RSA", use: "enc" }] },
						"receiver",
						options,
					)
				).ok,
			);
			a.false((await verifyClientAssertion(keyed, { keys: [unlabeled] }, "receiver", options)).ok);
			a.true((await verifyClientAssertion(keyed, entry.publishedJwks, "receiver", options)).ok);
		});
		qunit.test("Ed25519 counts as a signing algorithm in mixed-use JWKS", (a) => {
			const signing = { kty: "OKP", crv: "Ed25519", alg: "Ed25519" };
			const encryption = { kty: "RSA", use: "enc" };
			a.true(validateJwkSetUseRequirement([signing]).ok);
			a.false(validateJwkSetUseRequirement([signing, encryption]).ok);
			a.true(validateJwkSetUseRequirement([{ ...signing, use: "sig" }, encryption]).ok);
		});
		qunit.test(
			"a configured compact limit survives signing, inspection and chain validation",
			async (a) => {
				const id = entityId("https://anchor.example");
				const options = {
					engine,
					clock: { now: () => 1500 },
					maxCompactBytes: 650000,
					verboseErrors: true,
				};
				const config = {
					entityId: id,
					signer: entry,
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: `${id}/fetch`,
							federation_list_endpoint: `${id}/list`,
						},
					},
					additionalClaims: { example: "x".repeat(400000) },
					...options,
				};
				const token = await signEntityConfiguration(config);
				const anchors = new Map([[id, { jwks: entry.publishedJwks }]]);
				a.false(decodeEntityConfiguration(token).ok);
				a.true(decodeEntityConfiguration(token, { maxCompactBytes: token.length }).ok);
				a.false(decodeEntityConfiguration(token, { maxCompactBytes: token.length - 1 }).ok);
				await a.rejects(
					signEntityConfiguration({ ...config, maxCompactBytes: token.length - 1 }),
					CryptoError,
				);
				let fetches = 0;
				const fetchOptions = {
					...options,
					maxResponseBytes: token.length,
					storage: cacheStorage(new MemoryCache({ clock: options.clock })),
					httpClient: async () => {
						fetches++;
						return new Response(token, {
							headers: { "content-type": "application/entity-statement+jwt" },
						});
					},
				};
				a.true((await fetchEntityConfiguration(id, fetchOptions)).ok);
				a.true((await fetchEntityConfiguration(id, fetchOptions)).ok);
				a.equal(fetches, 1, "the cache can inspect a token above its default limit");
				a.false(
					(
						await fetchEntityConfiguration(id, {
							...fetchOptions,
							storage: cacheStorage(new MemoryCache()),
							maxResponseBytes: token.length - 1,
						})
					).ok,
				);
				const chain = await validateTrustChain([token], anchors, options);
				a.true(chain.valid, chain.valid ? "validated" : JSON.stringify(chain.errors));
				a.false(
					(
						await validateTrustChain([token], anchors, {
							...options,
							maxCompactBytes: token.length - 1,
						})
					).valid,
				);
			},
		);
		qunit.test(
			"memory storage uses its compact limit for Trust Mark reads and revocation",
			async (a) => {
				const subject = entityId("https://holder.example");
				const type = "https://marks.example/accredited";
				const jwt = await new JwsService({ engine, maxCompactBytes: 650000 }).signJwt(
					entry,
					{ ...payload, sub: subject, trust_mark_type: type, example: "x".repeat(400000) },
					{ typ: "trust-mark+jwt" },
				);
				const store = memoryStorage({ trustMarks: true, ...{ maxCompactBytes: jwt.length } });
				await store.transaction((tx) => {
					assertStorageView(tx, ["trustMark:write"], "Test issue");
					return tx.trustMark.issue({
						jwt,
						issuedAt: 1000,
						expiresAt: 2000,
						active: true,
						subject,
						trustMarkType: type,
					});
				});
				a.equal(
					(await store.readSnapshot((tx) => tx.trustMark!.candidates({ issuer: payload.iss })))
						.length,
					1,
				);
				a.true(await store.trustMark!.hasAny(subject, 1500));
				await store.transaction((tx) => {
					assertStorageView(tx, ["trustMark:write"], "Test revoke");
					return tx.trustMark.revoke(type, subject, 1500, payload.iss);
				});
				a.false(await store.trustMark!.hasAny(subject, 1500));
			},
		);
		qunit.test("a clock failure after replay storage returns a typed failure", async (a) => {
			let now = 1500;
			const token = await service.signJwt(
				entry,
				{ iss: "client", sub: "client", aud: "receiver", iat: 1400, exp: 2000, jti: "one" },
				{ typ: "JWT" },
			);
			const checked = await verifyClientAssertion(token, entry.publishedJwks, "receiver", {
				engine,
				clock: { now: () => now },
				storage: replayStorage({
					useJti: async () => {
						now = NaN;
						return true;
					},
				}),
			});
			a.false(checked.ok);
			if (!checked.ok) a.equal(checked.error.code, "ERR_INVALID_CLOCK");
		});
		qunit.test("bound options retain the host engine and narrow cryptographic policy", (a) => {
			const other = { ...engine };
			const options = bindFederationOptions(
				{ engine },
				{
					allowedAlgorithms: ["ES256", "RS256"],
					maxCompactBytes: 4096,
					maxVerificationCandidates: 4,
				},
				{
					allowedAlgorithms: ["ES256", "PS256"],
					maxCompactBytes: 8192,
					maxVerificationCandidates: 2,
					...{ engine: other },
				},
			);
			a.strictEqual(options.engine, engine);
			a.deepEqual(options.allowedAlgorithms, ["ES256"]);
			a.equal(options.maxCompactBytes, 4096);
			a.equal(options.maxVerificationCandidates, 2);
		});

		qunit.test("token types and key omission use explicit profiles", async (a) => {
			const noKid = { ...f.publicJwk };
			delete noKid.kid;
			const token = await signProtocolFixture(payload, entry, {
				extraHeaders: { kid: undefined, typ: undefined },
			});
			const profile = { typ: "absent", keyId: "allow-single-key" } as const;
			a.true((await service.verifyJwt(token, { keys: [noKid] }, profile)).ok);
			a.false(
				(await service.verifyJwt(token, { keys: [noKid, { kty: "unsupported" }] }, profile)).ok,
				"count the complete published set",
			);
			a.false(
				(await service.verifyJwt(token, { keys: [noKid] }, { typ: "absent", keyId: "required" }))
					.ok,
			);
			a.false(
				(
					await service.verifyJwt(
						token,
						{ keys: [noKid] },
						{ typ: { expected: "JWT" }, keyId: "allow-single-key" },
					)
				).ok,
			);
		});
		qunit.test(
			"duplicate identifiers try eligible candidates within a resource budget",
			async (a) => {
				const wrong = { ...f.publicJwk, x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" };
				const token = await service.signJwt(entry, payload, { typ: "JWT" });
				const profile = { typ: { expected: "JWT" }, keyId: "required" } as const;
				a.true((await service.verifyJwt(token, { keys: [wrong, f.publicJwk] }, profile)).ok);
				const limited = new JwsService({
					engine,
					clock: { now: () => 1500 },
					maxVerificationCandidates: 1,
				});
				a.false((await limited.verifyJwt(token, { keys: [wrong, f.publicJwk] }, profile)).ok);
			},
		);
		qunit.test(
			"a backend's truthy result and operational rejection never authenticate a token",
			async (a) => {
				const token = await service.signJwt(entry, payload, { typ: "JWT" });
				const profile = { typ: "any", keyId: "required" } as const;
				for (const verify of [
					async () => ({ valid: true }),
					async () => {
						throw new Error("backend unavailable");
					},
				]) {
					const faulty = new JwsService({
						engine: {
							...engine,
							verify: verify as unknown as CryptoEngine["verify"],
						},
					});
					const result = await faulty.verifyJwt(token, entry.publishedJwks, profile);
					a.false(result.ok);
					if (!result.ok) a.equal(result.error.code, "ERR_CRYPTO_OPERATION_FAILED");
				}
			},
		);
		qunit.test("finite clocks, dates, audience and deployment policy are enforced", async (a) => {
			const token = await service.signJwt(
				entry,
				{ ...payload, aud: ["receiver", "other"] },
				{ typ: "JWT" },
			);
			a.true(
				(
					await service.verifyJwt(token, entry.publishedJwks, {
						typ: "any",
						keyId: "required",
						audience: { expected: "receiver", mode: "contains" },
					})
				).ok,
			);
			a.false(
				(
					await service.verifyJwt(token, entry.publishedJwks, {
						typ: "any",
						keyId: "required",
						audience: { expected: "receiver", mode: "only" },
					})
				).ok,
			);
			a.false(
				(
					await service.verifyJwt(
						token,
						entry.publishedJwks,
						{ typ: "any", keyId: "required" },
						{ allowedAlgorithms: ["RS256"] },
					)
				).ok,
			);
			const result = await new JwsService({ engine, clock: { now: () => NaN } }).verifyJwt(
				token,
				entry.publishedJwks,
				{ typ: "any", keyId: "required" },
			);
			a.false(result.ok);
			if (!result.ok) a.equal(result.error.code, "ERR_INVALID_CLOCK");
			const malformed = await signProtocolFixture({ ...payload, exp: "2000" }, entry);
			a.false(
				(await service.verifyJwt(malformed, entry.publishedJwks, { typ: "any", keyId: "required" }))
					.ok,
			);
		});
		qunit.test(
			"inspection remains algorithm neutral and native key validation checks curve points",
			async (a) => {
				const inspected = await signProtocolFixture(payload, entry, {
					extraHeaders: { alg: "future-algorithm" },
				});
				a.equal(decodeCompactJws(inspected).header.alg, "future-algorithm");
				await engine.validatePublicKey(f.publicJwk, "ES256");
				await a.rejects(
					engine.validatePublicKey(
						{
							...f.publicJwk,
							x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
							y: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
						},
						"ES256",
					),
					CryptoError,
				);
			},
		);
		qunit.test(
			"rotation preserves captured custody and publishes only recorded withdrawn history",
			async (a) => {
				let now = 1000;
				const ring = new MemoryRotatingKeyring({ federation: f.signer }, { nowSeconds: () => now });
				const captured = await ring.entry("federation");
				const next = {
					publicJwk: { ...f.signer.publicJwk, kid: "next" },
					sign: f.signer.sign.bind(f.signer),
				};
				await ring.publish("federation", next);
				now = 1100;
				await ring.activate("federation", "next");
				const jwt = await service.signJwt(captured, { ...payload, jwks: captured.publishedJwks });
				a.equal(decodeCompactJws(jwt).header.kid, f.signer.publicJwk.kid);
				a.deepEqual(await historicalKeysFromKeyring(ring).getHistoricalKeys(), []);
				now = 1200;
				await ring.retire("federation", f.signer.publicJwk.kid);
				now = 1300;
				await ring.revoke("federation", f.signer.publicJwk.kid, "compromised");
				const [record] = await historicalKeysFromKeyring(ring).getHistoricalKeys();
				a.equal(record?.exp, 1200);
				a.equal(record?.revoked?.revoked_at, 1300);
				a.false(Object.hasOwn(record ?? {}, "iat"));
				a.false(Object.hasOwn(record ?? {}, "nbf"));
			},
		);
		qunit.test("role publication respects pinned operation entries", async (a) => {
			const ring = new StaticKeyring({ signers: { federation: f.signer } });
			const context = {
				entityId: payload.iss,
				crypto: { engine, keyring: ring },
				options: { engine },
			};
			const published = await signingPublication(
				context,
				{ requestObject: "operation" },
				new Map([["operation", entry]]),
			);
			a.deepEqual(published.jwks, entry.publishedJwks);
		});
		qunit.test(
			"portable data copies preserve graph identity, binary views and safe member names",
			(a) => {
				const shared = { value: 1 };
				const bytes = new Uint8Array([1, 2, 3]);
				const graph = {
					shared,
					alias: shared,
					map: new Map([[shared, shared]]),
					set: new Set([shared]),
					bytes,
					view: new DataView(bytes.buffer, 1, 2),
					cycle: {} as unknown,
				};
				graph.cycle = graph;
				Object.defineProperty(shared, "__proto__", { value: { polluted: true }, enumerable: true });
				const copy = cloneData(graph);
				a.notStrictEqual(copy, graph);
				a.strictEqual(copy.shared, copy.alias);
				a.strictEqual(copy.map.get(copy.shared), copy.shared);
				a.true(copy.set.has(copy.shared));
				a.strictEqual(copy.cycle, copy);
				a.strictEqual(copy.bytes.buffer, copy.view.buffer);
				a.notStrictEqual(copy.bytes.buffer, bytes.buffer);
				a.strictEqual(Object.getPrototypeOf(copy.shared), Object.prototype);
				a.true(Object.hasOwn(copy.shared, "__proto__"));
				a.throws(() => cloneData({ callback() {} }), TypeError);
				a.equal(utf8Decode(new Uint8Array([0xe2, 0x82, 0x41]), { fatal: false }), "\ufffdA");
			},
		);
	});
}
