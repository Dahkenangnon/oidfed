import { base64url, decodeJwt } from "jose";
import type QUnit from "qunit";
import {
	generateSigningKey,
	type JWK,
	JwkSigner,
	type JwtSigner,
	MemoryFederationKeyProvider,
	MemoryReplayStore,
	signEntityStatement,
} from "../../../packages/core/src/index.js";
import {
	type AttestationVerificationOptions,
	type AuthorizationRequestCreationOptions,
	CredentialIssuerRole,
	CredentialVerifierRole,
	type DcqlQuery,
	type PreparedAuthorizationRequest,
	WalletProviderRole,
} from "../../../packages/wallet/src/index.js";
import { anchorKeyPaths, trustChainPaths } from "../fixtures/trust-chain-paths.js";
import { walletFederation, walletQuery } from "../fixtures/wallet.js";

async function token(
	payload: Record<string, unknown>,
	key: JWK,
	typ: string,
	header: Record<string, unknown> = {},
) {
	return new JwkSigner(key).signJwt(new TextEncoder().encode(JSON.stringify(payload)), {
		alg: key.alg,
		typ,
		...header,
	});
}
type Fixture = Awaited<ReturnType<typeof walletFederation>>;
const attestation = (f: Fixture) => ({
	iss: f.ids.provider,
	sub: "shared-wallet-client",
	exp: 4000,
	cnf: { jwk: f.protocol.issuer.publicKey },
});
const proof = (f: Fixture) => ({
	iss: "shared-wallet-client",
	aud: f.ids.server,
	iat: 1490,
	jti: "unique-proof",
});

export default (QUnit: QUnit) => {
	const { module, test } = QUnit;
	test("request chain carriers preserve precedence and offline validation", async (t) => {
		const f = await walletFederation();
		const chain = f.chains.get(f.ids.verifier);
		for (const carrier of ["header", "payload"]) {
			const jwt = await token(
				{ ...f.requestPayload, ...(carrier === "payload" ? { trust_chain: chain } : {}) },
				f.protocol.verifier.privateKey,
				"oauth-authz-req+jwt",
				carrier === "header" ? { trust_chain: chain } : {},
			);
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id, request: jwt },
				f.anchors,
				{ clock: f.clock, offline: true },
			);
			t.true(prepared.ok, carrier);
			if (prepared.ok) {
				const result = await CredentialVerifierRole.completeAuthorizationRequest(
					prepared.value,
					jwt,
				);
				t.true(result.ok);
				if (result.ok) t.false(Object.hasOwn(result.value.request, "trust_chain"));
			}
		}
		const malformed = await token(
			{ ...f.requestPayload, trust_chain: chain },
			f.protocol.verifier.privateKey,
			"oauth-authz-req+jwt",
			{ trust_chain: null },
		);
		t.false(
			(
				await CredentialVerifierRole.prepareAuthorizationRequest(
					{ client_id: f.requestPayload.client_id, request: malformed },
					f.anchors,
					f.options,
				)
			).ok,
		);
	});

	test("object-valued wallet policy crosses an intermediate without merging key sets", async (t) => {
		const { validateTrustChain } = await import("../../../packages/core/src/index.js");
		const f = await trustChainPaths({
			openid_credential_verifier: { vp_formats_supported: { "dc+sd-jwt": {} } },
		});
		const governedKeys = { keys: [f.keys.b.publicKey] };
		const chain = await f.chain(["subject", "a", "anchor"]);
		chain[2] = await f.sign("anchor", "a", {
			metadata_policy: { openid_credential_verifier: { jwks: { value: governedKeys } } },
		});
		const valid = await validateTrustChain(chain, f.anchors, f.options);
		t.true(
			(
				await CredentialVerifierRole.discover(f.ids.subject, f.anchors, {
					...f.options,
					trustChain: chain,
					offline: true,
				})
			).ok,
		);
		t.true(valid.valid, JSON.stringify(valid.errors));
		if (valid.valid)
			t.deepEqual(valid.chain.resolvedMetadata.openid_credential_verifier?.jwks, governedKeys);
		chain[1] = await f.sign("a", "subject", {
			metadata_policy: {
				openid_credential_verifier: { jwks: { value: { keys: [f.keys.subject.publicKey] } } },
			},
		});
		const conflict = await validateTrustChain(chain, f.anchors, f.options);
		t.false(conflict.valid, "conflicting complete objects invalidate the policy");
		chain[1] = await f.sign("a", "subject");
		chain[2] = await f.sign("anchor", "a", {
			metadata_policy: { openid_credential_verifier: { jwks: { value: { keys: [] } } } },
		});
		t.false(
			(
				await CredentialVerifierRole.discover(f.ids.subject, f.anchors, {
					...f.options,
					trustChain: chain,
					offline: true,
				})
			).ok,
			"wallet effective key validation still rejects empty keys",
		);
	});
	test("invalid wallet fetch budgets return failure promises consistently", async (t) => {
		for (const maxTotalFetches of [0, -1, NaN, Infinity, 1.5]) {
			const options = { maxTotalFetches };
			const anchors = new Map();
			const calls = [
				() => WalletProviderRole.discover("https://p.example", anchors, options),
				() => CredentialIssuerRole.discover("https://i.example", anchors, options),
				() => CredentialVerifierRole.discover("https://v.example", anchors, options),
				() => CredentialIssuerRole.verifyWalletAttestation("bad", anchors, options),
				() =>
					CredentialVerifierRole.prepareAuthorizationRequest(
						{ client_id: "openid_federation:https://v.example", request: "bad" },
						anchors,
						options,
					),
			];
			for (const call of calls) {
				const promise = call();
				t.ok(promise instanceof Promise);
				const result = await promise;
				t.false(result.ok);
				if (!result.ok) t.true(result.error.description.includes("maxTotalFetches"));
			}
		}
	});
	test("JSON credential description paths start at an object and retain nested wildcards", async (t) => {
		const f = await walletFederation();
		const issuer = await CredentialIssuerRole.discover(f.ids.issuer, f.anchors, f.options);
		t.true(issuer.ok);
		if (!issuer.ok) return;
		for (const path of [[0], [null], ["names", null, "given"], ["names", 0, "given"]]) {
			const parsed = CredentialIssuerRole.parseMetadata({
				...issuer.value.metadata,
				credential_configurations_supported: {
					identity: {
						format: "dc+sd-jwt",
						vct: "https://example.com/identity",
						credential_metadata: { claims: [{ path }] },
					},
				},
			});
			t.equal(parsed.success, typeof path[0] === "string");
		}
	});
	test("present attestation audiences require an explicit recipient", async (t) => {
		const f = await walletFederation();
		for (const aud of [undefined, f.ids.server, [f.ids.server], "https://other.example", []]) {
			const jwt = await token(
				{ ...attestation(f), ...(aud === undefined ? {} : { aud }) },
				f.protocol.provider.privateKey,
				"oauth-client-attestation+jwt",
			);
			const result = await CredentialIssuerRole.verifyWalletAttestation(jwt, f.anchors, {
				...f.options,
				expectedAudience: f.ids.server,
			});
			t.equal(
				result.ok,
				aud === undefined ||
					aud === f.ids.server ||
					(Array.isArray(aud) && aud.includes(f.ids.server)),
			);
			if (aud !== undefined)
				t.false((await CredentialIssuerRole.verifyWalletAttestation(jwt, f.anchors, f.options)).ok);
		}
	});
	test("a PoP kid hint can accompany a kid-less confirmation key", async (t) => {
		const f = await walletFederation();
		const { kid: _kid, ...publicKey } = f.protocol.issuer.publicKey;
		const jwt = await token(
			{ ...attestation(f), cnf: { jwk: publicKey } },
			f.protocol.provider.privateKey,
			"oauth-client-attestation+jwt",
		);
		const pop = await token(
			proof(f),
			f.protocol.issuer.privateKey,
			"oauth-client-attestation-pop+jwt",
			{ kid: "hint" },
		);
		t.true(
			(
				await CredentialIssuerRole.authenticateWallet(jwt, pop, f.anchors, {
					...f.options,
					audience: f.ids.server,
					replayStore: new MemoryReplayStore({ clock: f.options.clock }),
					acceptWallet: () => true,
				})
			).ok,
		);
		const mismatched = await token(
			{ ...attestation(f), cnf: { jwk: { ...publicKey, kid: "other" } } },
			f.protocol.provider.privateKey,
			"oauth-client-attestation+jwt",
		);
		t.false(
			(
				await CredentialIssuerRole.authenticateWallet(mismatched, pop, f.anchors, {
					...f.options,
					audience: f.ids.server,
					replayStore: new MemoryReplayStore({ clock: f.options.clock }),
					acceptWallet: () => true,
				})
			).ok,
		);
		for (const kid of [42, null, {}, []]) {
			const invalid = await token(
				proof(f),
				f.protocol.issuer.privateKey,
				"oauth-client-attestation-pop+jwt",
				{ kid },
			);
			t.false(
				(
					await CredentialIssuerRole.authenticateWallet(jwt, invalid, f.anchors, {
						...f.options,
						audience: f.ids.server,
						replayStore: new MemoryReplayStore({ clock: f.options.clock }),
						acceptWallet: () => true,
					})
				).ok,
				"a PoP key hint must be a string",
			);
		}
	});
	module("wallet / publication and protocol boundaries", () => {
		test("publication permits superior-completed metadata while discovery requires completeness", async (t) => {
			const f = await walletFederation({ issuerMetadata: { credential_endpoint: undefined } });
			for (const Role of [WalletProviderRole, CredentialIssuerRole, CredentialVerifierRole]) {
				const role = new Role({ metadata: {} });
				role.validateMetadata(
					{},
					{
						entityId: f.ids.issuer,
						keyProvider: MemoryFederationKeyProvider.fromJWK(f.keys.issuer.privateKey),
					},
				);
				t.false(Role.parseMetadata({}).success, "effective metadata still requires its fields");
			}
			const role = new CredentialIssuerRole({});
			const context = {
				entityId: f.ids.issuer,
				keyProvider: MemoryFederationKeyProvider.fromJWK(f.keys.issuer.privateKey),
			};
			t.throws(() =>
				role.validateMetadata({ credential_endpoint: "http://insecure.example" }, context),
			);
			t.throws(() => role.validateMetadata({ credential_issuer: f.ids.provider }, context));
			t.false((await CredentialIssuerRole.discover(f.ids.issuer, f.anchors, f.options)).ok);
			const chain = f.chains.get(f.ids.issuer)!;
			const ss = await signEntityStatement(
				{
					...decodeJwt(chain[1]!),
					metadata: {
						openid_credential_issuer: { credential_endpoint: `${f.ids.issuer}/credentials` },
					},
				},
				new JwkSigner(f.keys.anchor.privateKey),
			);
			f.chains.set(f.ids.issuer, [chain[0]!, ss, chain[2]!]);
			t.true((await CredentialIssuerRole.discover(f.ids.issuer, f.anchors, f.options)).ok);
		});
		test("request scope and credential scope use their respective OAuth grammars", async (t) => {
			const f = await walletFederation();
			const { dcql_query: _, ...request } = f.requestPayload;
			for (const value of ["", " ", 'a"b', "a\\b", "é", "a  b", " a"]) {
				t.false(
					(
						await CredentialVerifierRole.createAuthorizationRequest(
							f.ids.verifier,
							{ ...request, scope: value },
							new JwkSigner(f.protocol.verifier.privateKey),
							f.options,
						)
					).ok,
					JSON.stringify(value),
				);
			}
			for (const scope of ["identity", "identity address", "https://example.com/scope"])
				t.true(
					(
						await CredentialVerifierRole.createAuthorizationRequest(
							f.ids.verifier,
							{ ...request, scope },
							new JwkSigner(f.protocol.verifier.privateKey),
							f.options,
						)
					).ok,
				);
			for (const scope of ["", "cred openid", "é", 'a"b', "identity"]) {
				const metadata = {
					...f.metadata.issuer.openid_credential_issuer,
					credential_configurations_supported: {
						identity: { format: "dc+sd-jwt", vct: "test", scope },
					},
				};
				t.equal(CredentialIssuerRole.parseMetadata(metadata).success, scope === "identity");
			}
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: request.client_id },
				f.anchors,
				f.options,
			);
			if (!prepared.ok) throw new Error(prepared.error.description);
			for (const scope of ["", 'a"b']) {
				const jwt = await token(
					{ ...request, scope },
					f.protocol.verifier.privateKey,
					"oauth-authz-req+jwt",
				);
				t.false(
					(
						await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, jwt, {
							scopeQuery: walletQuery,
						})
					).ok,
				);
			}
		});
		test("known authority identifiers and nonblank mode and format names retain extensions", async (t) => {
			const f = await walletFederation();
			for (const [type, values, expected] of [
				["openid_federation", [f.ids.anchor], true],
				["openid_federation", ["http://bad.example"], false],
				["aki", ["AQI"], true],
				["aki", ["%%%"], false],
				["aki", ["AB"], false],
				["custom", ["opaque"], true],
				["etsi_tl", ["opaque-list-id"], true],
				["", ["value"], false],
			] as const) {
				const query = {
					credentials: [
						{
							...walletQuery.credentials[0]!,
							trusted_authorities: [{ type, values: [...values] }],
						},
					],
				};
				t.equal(
					CredentialVerifierRole.parseMetadata({
						vp_formats_supported: { "dc+sd-jwt": {} },
						dcql_queries: [query],
					}).success,
					expected,
					type + values.join(),
				);
			}
			for (const name of ["", " ", "future_format"])
				t.equal(
					CredentialVerifierRole.parseMetadata({
						vp_formats_supported: { [name]: { extension: true } },
					}).success,
					name === "future_format",
				);
			for (const response_mode of ["", " ", "extension_mode"])
				t.equal(
					(
						await CredentialVerifierRole.createAuthorizationRequest(
							f.ids.verifier,
							{ ...f.requestPayload, response_mode },
							new JwkSigner(f.protocol.verifier.privateKey),
							f.options,
						)
					).ok,
					response_mode === "extension_mode",
				);
		});
		test("active formats must be advertised when effective metadata is available", async (t) => {
			const f = await walletFederation();
			const query = {
				credentials: [{ id: "mdoc", format: "mso_mdoc", meta: { doctype_value: "test" } }],
			};
			const payload = { ...f.requestPayload, dcql_query: query };
			const jwt = await token(payload, f.protocol.verifier.privateKey, "oauth-authz-req+jwt");
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: payload.client_id },
				f.anchors,
				f.options,
			);
			if (!prepared.ok) throw new Error(prepared.error.description);
			t.false((await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, jwt)).ok);
			t.false(
				(
					await CredentialVerifierRole.createAuthorizationRequest(
						f.ids.verifier,
						payload,
						new JwkSigner(f.protocol.verifier.privateKey),
						{ ...f.options, trustChain: f.chains.get(f.ids.verifier), trustAnchors: f.anchors },
					)
				).ok,
			);
			const overridden = await walletFederation({
				verifierOverride: { dcql_queries: [walletQuery] },
			});
			const prep = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: payload.client_id },
				overridden.anchors,
				overridden.options,
			);
			if (!prep.ok) throw new Error(prep.error.description);
			const ignored = await token(
				payload,
				overridden.protocol.verifier.privateKey,
				"oauth-authz-req+jwt",
			);
			t.true(
				(await CredentialVerifierRole.completeAuthorizationRequest(prep.value, ignored)).ok,
				"superior override supplies the active format",
			);
		});
		test("encryption eligibility considers usage and algorithms on the same key", async (t) => {
			const f = await walletFederation();
			for (const [changes, expected] of [
				[{ alg: "ECDH-ES", use: "sig" }, false],
				[{ alg: "ECDH-ES", key_ops: ["verify"] }, false],
				[{ alg: "ES256" }, false],
				[{ alg: "EdDSA", use: "enc" }, false],
				[{ alg: "HS256", use: "enc" }, false],
				[{ alg: "none" }, false],
				[{ alg: "ECDH-ES", use: "enc", key_ops: ["deriveBits"] }, true],
				[{ alg: "future-encryption", use: "enc" }, true],
			] as const) {
				const key = { ...f.protocol.issuer.publicKey, ...changes };
				t.equal(
					CredentialIssuerRole.parseMetadata({
						...f.metadata.issuer.openid_credential_issuer,
						credential_request_encryption: {
							jwks: { keys: [key] },
							enc_values_supported: ["A256GCM"],
							encryption_required: true,
						},
					}).success,
					expected,
					JSON.stringify(changes),
				);
			}
		});
		test("each scopeless configuration needs a capable discovered authorization server", async (t) => {
			for (const supported of [undefined, [], ["other"], ["openid_credential"]]) {
				const f = await walletFederation({
					issuerMetadata: {
						authorization_servers: ["https://issuer.example", "https://server.example"],
					},
					issuerServerMetadata: { authorization_details_types_supported: [] },
					serverMetadata: { authorization_details_types_supported: supported },
				});
				const result = await CredentialIssuerRole.discover(f.ids.issuer, f.anchors, f.options);
				t.equal(result.ok, supported?.includes("openid_credential") ?? false);
				if (!result.ok) t.equal(result.error.code, "invalid_metadata");
			}
			const scoped = { format: "dc+sd-jwt", vct: "test", scope: "credential" };
			for (const mixed of [false, true]) {
				const f = await walletFederation({
					issuerServerMetadata: { authorization_details_types_supported: undefined },
					issuerMetadata: {
						credential_configurations_supported: {
							scoped,
							...(mixed ? { unscoped: { format: "dc+sd-jwt", vct: "other" } } : {}),
						},
					},
				});
				t.equal(
					(await CredentialIssuerRole.discover(f.ids.issuer, f.anchors, f.options)).ok,
					!mixed,
				);
			}
		});
		test("expired embedded chains recover online while caller evidence and offline limits remain authoritative", async (t) => {
			const f = await walletFederation();
			const oldProvider = f.chains.get(f.ids.provider)!;
			const oldVerifier = f.chains.get(f.ids.verifier)!;
			const fresh = async (chain: readonly string[], name: "provider" | "verifier") =>
				Promise.all(
					chain.map((jwt) => {
						const payload = decodeJwt(jwt);
						return signEntityStatement(
							{ ...payload, iat: 5500, exp: 10000 },
							new JwkSigner(
								payload.iss === f.ids[name] ? f.keys[name].privateKey : f.keys.anchor.privateKey,
							),
						);
					}),
				);
			const freshProvider = await fresh(oldProvider, "provider");
			const freshVerifier = await fresh(oldVerifier, "verifier");
			for (const [name, chain] of [
				["provider", freshProvider],
				["verifier", freshVerifier],
			] as const) {
				f.routes.set(
					`${f.ids[name]}/.well-known/openid-federation`,
					() =>
						new Response(chain[0], {
							headers: { "content-type": "application/entity-statement+jwt" },
						}),
				);
				f.routes.set(
					`${f.ids.anchor}/fetch?sub=${encodeURIComponent(f.ids[name])}`,
					() =>
						new Response(chain[1], {
							headers: { "content-type": "application/entity-statement+jwt" },
						}),
				);
			}
			f.routes.set(
				`${f.ids.anchor}/.well-known/openid-federation`,
				() =>
					new Response(freshProvider[2], {
						headers: { "content-type": "application/entity-statement+jwt" },
					}),
			);
			const att = await token(
				{ ...attestation(f), exp: 9000 },
				f.protocol.provider.privateKey,
				"oauth-client-attestation+jwt",
				{ trust_chain: oldProvider },
			);
			f.setTime(6000);
			const { entityChains: _, ...online } = f.options;
			const verify = (
				options: import("../../../packages/wallet/src/index.js").WalletTrustOptions = online,
			) => CredentialIssuerRole.verifyWalletAttestation(att, f.anchors, options);
			t.true((await verify()).ok);
			t.ok(f.requests.length > 0, "expired hint leads to fresh discovery");
			f.requests.length = 0;
			t.true((await verify({ ...online, trustChain: freshProvider, offline: true })).ok);
			t.true(
				(
					await verify({
						...online,
						entityChains: new Map([[f.ids.provider, freshProvider]]),
						offline: true,
					})
				).ok,
			);
			t.false((await verify({ ...online, offline: true })).ok);
			t.false((await verify({ ...online, trustChain: oldProvider })).ok);
			t.equal(
				f.requests.length,
				0,
				"caller-supplied and offline failures do not trigger discovery",
			);
			t.false((await verify({ ...online, maxTotalFetches: 1 })).ok);
			const controller = new AbortController();
			controller.abort();
			f.requests.length = 0;
			t.false((await verify({ ...online, signal: controller.signal })).ok);
			t.equal(f.requests.length, 0);
			const malformed = await token(
				{ ...attestation(f), exp: 9000 },
				f.protocol.provider.privateKey,
				"oauth-client-attestation+jwt",
				{ trust_chain: [] },
			);
			t.false(
				(await CredentialIssuerRole.verifyWalletAttestation(malformed, f.anchors, online)).ok,
			);
			t.false((await verify({ ...online, maxChainDepth: 0 })).ok);
			t.equal(f.requests.length, 0, "malformed and oversized evidence is rejected before fetching");
			const wrongSignature = await token(
				{ ...attestation(f), exp: 9000 },
				f.protocol.issuer.privateKey,
				"oauth-client-attestation+jwt",
				{ trust_chain: freshProvider },
			);
			t.false(
				(await CredentialIssuerRole.verifyWalletAttestation(wrongSignature, f.anchors, online)).ok,
			);
			t.equal(f.requests.length, 0, "signature rejection does not cause fresh discovery");
			const malformedStatements = await token(
				{ ...attestation(f), exp: 9000 },
				f.protocol.provider.privateKey,
				"oauth-client-attestation+jwt",
				{ trust_chain: ["not-a-jwt"] },
			);
			t.true(
				(await CredentialIssuerRole.verifyWalletAttestation(malformedStatements, f.anchors, online))
					.ok,
				"unusable statements in a correctly shaped hint allow fresh discovery",
			);
			t.ok(f.requests.length > 0);
			f.requests.length = 0;
			const jwt = await token(
				{ ...f.requestPayload, iat: 5800, exp: 9000 },
				f.protocol.verifier.privateKey,
				"oauth-authz-req+jwt",
				{ trust_chain: oldVerifier },
			);
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id, request: jwt },
				f.anchors,
				online,
			);
			t.true(prepared.ok);
			if (prepared.ok)
				t.true((await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, jwt)).ok);
			f.requests.length = 0;
			t.true(
				(
					await CredentialVerifierRole.prepareAuthorizationRequest(
						{ client_id: f.requestPayload.client_id, request: jwt },
						f.anchors,
						{ ...online, trustChain: freshVerifier, offline: true },
					)
				).ok,
			);
			t.equal(f.requests.length, 0);
		});

		test("attestation creation preserves historical dates and valid delayed activation", async (t) => {
			const f = await walletFederation();
			for (const [claims, expected] of [
				[{}, true],
				[{ iat: -0.5 }, true],
				[{ iat: 1500 }, true],
				[{ iat: 1501 }, false],
				[{ nbf: 1800 }, true],
				[{ nbf: 4000 }, false],
				[{ nbf: 5000 }, false],
			] as const) {
				const result = await WalletProviderRole.createWalletAttestation(
					f.ids.provider,
					{
						subject: "wallet",
						confirmationKey: f.protocol.issuer.publicKey,
						expiresAt: 4000,
						claims,
					},
					new JwkSigner(f.protocol.provider.privateKey),
					f.options,
				);
				t.equal(result.ok, expected, JSON.stringify(claims));
				if (result.ok)
					t.equal(decodeJwt(result.value).iat, "iat" in claims ? claims.iat : undefined);
			}
		});
		test("media type equivalents work across attestations, proofs, and inline requests", async (t) => {
			const f = await walletFederation();
			for (const prefix of ["", "application/"]) {
				const att = await token(
					attestation(f),
					f.protocol.provider.privateKey,
					`${prefix}OAUTH-CLIENT-ATTESTATION+JWT`,
				);
				const pop = await token(
					proof(f),
					f.protocol.issuer.privateKey,
					`${prefix}OAUTH-CLIENT-ATTESTATION-POP+JWT`,
				);
				const auth = await CredentialIssuerRole.authenticateWallet(att, pop, f.anchors, {
					...f.options,
					audience: f.ids.server,
					replayStore: new MemoryReplayStore({ clock: f.clock }),
					acceptWallet: () => true,
				});
				t.true(auth.ok);
				const jwt = await token(
					f.requestPayload,
					f.protocol.verifier.privateKey,
					`${prefix}OAUTH-AUTHZ-REQ+JWT`,
				);
				const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
					{ client_id: f.requestPayload.client_id, request: jwt },
					f.anchors,
					f.options,
				);
				t.true(prepared.ok);
				if (prepared.ok)
					t.true(
						(await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, jwt)).ok,
					);
			}
			for (const challenge of ["", " ", "challenge"]) {
				const att = await token(
					attestation(f),
					f.protocol.provider.privateKey,
					"oauth-client-attestation+jwt",
				);
				const pop = await token(
					{ ...proof(f), challenge },
					f.protocol.issuer.privateKey,
					"oauth-client-attestation-pop+jwt",
				);
				const options = {
					...f.options,
					audience: f.ids.server,
					expectedChallenge: challenge,
					replayStore: new MemoryReplayStore({ clock: f.clock }),
					acceptWallet: () => true,
				};
				t.equal(
					(await CredentialIssuerRole.authenticateWallet(att, pop, f.anchors, options)).ok,
					challenge === "challenge",
				);
				t.false(
					(await CredentialIssuerRole.authenticateWallet(att, pop, f.anchors, options)).ok,
					"replay stays rejected",
				);
			}
		});
	});

	module("wallet / request and effective metadata safeguards", () => {
		test("wrong inline typ is rejected before discovery", async (t) => {
			const f = await walletFederation();
			const jwt = await token(f.requestPayload, f.protocol.verifier.privateKey, "JWT");
			const result = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id, request: jwt },
				f.anchors,
				{ clock: f.clock, httpClient: f.httpClient },
			);
			t.false(result.ok);
			t.equal(f.requests.length, 0);
		});
		test("received duplicate paths preserve claim-set references and strict outbound checks", async (t) => {
			const f = await walletFederation();
			const query = {
				credentials: [
					{
						...walletQuery.credentials[0]!,
						claims: [
							{ id: "first", path: ["name"], values: ["Alice"] },
							{ id: "later", path: ["name"], values: ["Bob"] },
							{ id: "age", path: ["age"] },
						],
						claim_sets: [["later", "first", "age"], []],
					},
				],
			};
			const original = structuredClone(query);
			const jwt = await token(
				{ ...f.requestPayload, dcql_query: query },
				f.protocol.verifier.privateKey,
				"oauth-authz-req+jwt",
			);
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				f.options,
			);
			if (!prepared.ok) throw new Error(prepared.error.description);
			const result = await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, jwt);
			t.true(result.ok);
			if (result.ok) {
				t.equal(result.value.effectiveQueries[0]?.credentials[0]?.claims?.length, 2);
				t.deepEqual(result.value.effectiveQueries[0]?.credentials[0]?.claims?.[0]?.values, [
					"Alice",
				]);
				t.deepEqual(result.value.effectiveQueries[0]?.credentials[0]?.claim_sets, [
					["first", "age"],
					[],
				]);
				t.deepEqual(result.value.request.dcql_query, result.value.effectiveQueries[0]);
			}
			t.deepEqual(query, original);
			const created = await CredentialVerifierRole.createAuthorizationRequest(
				f.ids.verifier,
				{ ...f.requestPayload, dcql_query: query },
				new JwkSigner(f.protocol.verifier.privateKey),
				f.options,
			);
			t.false(created.ok);
		});
		test("received duplicate paths are normalized only after contextual policy checks", async (t) => {
			const first = { id: "first", path: ["name"] };
			const duplicate = {
				...walletQuery,
				credentials: [
					{ ...walletQuery.credentials[0]!, claims: [first, { id: "later", path: ["name"] }] },
				],
			};
			const normalized = {
				...walletQuery,
				credentials: [{ ...walletQuery.credentials[0]!, claims: [first] }],
			};
			for (const allowed of [duplicate, normalized]) {
				const f = await walletFederation({ policy: { dcql_queries: { subset_of: [allowed] } } });
				const jwt = await token(
					{
						...f.requestPayload,
						dcql_query: duplicate,
						client_metadata: { dcql_query: duplicate },
					},
					f.protocol.verifier.privateKey,
					"oauth-authz-req+jwt",
				);
				const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
					{ client_id: f.requestPayload.client_id },
					f.anchors,
					f.options,
				);
				if (!prepared.ok) throw new Error(prepared.error.description);
				const result = await CredentialVerifierRole.completeAuthorizationRequest(
					prepared.value,
					jwt,
				);
				t.equal(result.ok, allowed === duplicate, "policy evaluates the original contextual query");
				if (result.ok) t.deepEqual(result.value.effectiveQueries, [normalized]);
			}
		});
		test("effective issuer encryption checks allow mixed sets and superior completion", async (t) => {
			const f = await walletFederation();
			const noAlg = { ...f.protocol.issuer.publicKey };
			delete noAlg.alg;
			const encryption = {
				jwks: { keys: [noAlg] },
				enc_values_supported: ["A256GCM"],
				encryption_required: true,
			};
			const response = {
				alg_values_supported: ["ECDH-ES"],
				enc_values_supported: ["A256GCM"],
				encryption_required: true,
			};
			const base = f.metadata.issuer.openid_credential_issuer!;
			t.false(
				CredentialIssuerRole.parseMetadata({ ...base, credential_request_encryption: encryption })
					.success,
			);
			t.false(
				CredentialIssuerRole.parseMetadata({ ...base, credential_response_encryption: response })
					.success,
			);
			const supported = {
				...encryption,
				jwks: { keys: [noAlg, { ...noAlg, kid: "encryption", alg: "ECDH-ES", use: "enc" }] },
				encryption_required: false,
			};
			t.true(
				CredentialIssuerRole.parseMetadata({
					...base,
					credential_request_encryption: supported,
					credential_response_encryption: response,
				}).success,
			);
			// Publication permits a superior to supply the request-encryption member.
			const role = new CredentialIssuerRole({
				metadata: { ...base, credential_response_encryption: response },
			});
			role.validateMetadata(role.metadata, {
				entityId: f.ids.issuer,
				keyProvider: MemoryFederationKeyProvider.fromJWK(f.keys.issuer.privateKey),
			});
			t.ok(true, "partial publication is accepted");
			const partial = await walletFederation({
				issuerMetadata: { credential_response_encryption: response },
			});
			const before = await CredentialIssuerRole.discover(
				partial.ids.issuer,
				partial.anchors,
				partial.options,
			);
			t.false(before.ok, "incomplete effective encryption metadata is rejected");
			const chain = partial.chains.get(partial.ids.issuer)!;
			const ss = decodeJwt(chain[1]!);
			const completedStatement = await signEntityStatement(
				{
					...ss,
					metadata: { openid_credential_issuer: { credential_request_encryption: supported } },
				},
				new JwkSigner(partial.keys.anchor.privateKey),
			);
			partial.chains.set(partial.ids.issuer, [chain[0]!, completedStatement, chain[2]!]);
			const after = await CredentialIssuerRole.discover(
				partial.ids.issuer,
				partial.anchors,
				partial.options,
			);
			t.true(after.ok, "superior-supplied request encryption completes effective metadata");
		});
		test("state is required only for known non-holder-bound requests outside the DC API", async (t) => {
			const f = await walletFederation();
			const query = {
				credentials: [
					{ ...walletQuery.credentials[0]!, require_cryptographic_holder_binding: false },
				],
			};
			for (const mode of ["direct_post", "dc_api", "dc_api.jwt"])
				for (const state of [undefined, "random-session-state"]) {
					const result = await CredentialVerifierRole.createAuthorizationRequest(
						f.ids.verifier,
						{
							...f.requestPayload,
							response_mode: mode,
							dcql_query: query,
							...(state ? { state } : {}),
						},
						new JwkSigner(f.protocol.verifier.privateKey),
						f.options,
					);
					t.equal(result.ok, mode !== "direct_post" || state !== undefined);
				}
			const { dcql_query: _, ...scopeRequest } = f.requestPayload;
			t.false(
				(
					await CredentialVerifierRole.createAuthorizationRequest(
						f.ids.verifier,
						{ ...scopeRequest, scope: "identity" },
						new JwkSigner(f.protocol.verifier.privateKey),
						{ ...f.options, scopeQuery: query },
					)
				).ok,
			);
			t.true(
				(
					await CredentialVerifierRole.createAuthorizationRequest(
						f.ids.verifier,
						{ ...scopeRequest, scope: "identity" },
						new JwkSigner(f.protocol.verifier.privateKey),
						f.options,
					)
				).ok,
				"opaque scope remains an application contract",
			);
			t.true(
				(
					await CredentialVerifierRole.createAuthorizationRequest(
						f.ids.verifier,
						f.requestPayload,
						new JwkSigner(f.protocol.verifier.privateKey),
						f.options,
					)
				).ok,
				"holder-bound requests keep state optional",
			);
		});
		test("queryPolicy can reject a contextual mismatch or approve a profile refinement", async (t) => {
			const f = await walletFederation({ policy: { dcql_queries: { subset_of: [walletQuery] } } });
			const requested = {
				credentials: [{ ...walletQuery.credentials[0]!, claims: [{ path: ["name"] }] }],
			};
			const jwt = await token(
				{
					...f.requestPayload,
					dcql_query: requested,
					client_metadata: { dcql_query: walletQuery },
				},
				f.protocol.verifier.privateKey,
				"oauth-authz-req+jwt",
			);
			for (const accept of [false, true]) {
				let calls = 0;
				const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
					{ client_id: f.requestPayload.client_id },
					f.anchors,
					{
						...f.options,
						queryPolicy: ({ queries, request }) => {
							calls++;
							t.deepEqual(queries, [walletQuery]);
							t.deepEqual(request.dcql_query, requested);
							return accept;
						},
					},
				);
				if (!prepared.ok) throw new Error(prepared.error.description);
				const result = await CredentialVerifierRole.completeAuthorizationRequest(
					prepared.value,
					jwt,
				);
				t.equal(result.ok, accept);
				t.equal(calls, 1);
			}
		});
	});

	module("wallet / transaction holder binding", () => {
		const bindingError =
			"Transaction data requires cryptographic holder binding for SD-JWT credentials";
		const query = (binding?: boolean, id = "identity"): DcqlQuery => ({
			credentials: [
				{
					...walletQuery.credentials[0]!,
					id,
					...(binding === undefined ? {} : { require_cryptographic_holder_binding: binding }),
				},
			],
		});
		const transaction = (...ids: string[]) =>
			base64url.encode(JSON.stringify({ type: "payment", credential_ids: ids }));

		async function check(
			t: Assert,
			f: Fixture,
			changes: Record<string, unknown>,
			valid: boolean,
			config: {
				scopeQuery?: DcqlQuery;
				withChain?: boolean;
				instance?: boolean;
				error?: string;
			} = {},
		) {
			const payload: Record<string, unknown> = {
				...f.requestPayload,
				state: "transaction-session-state",
				transaction_data: [transaction("identity")],
				...changes,
			};
			const original = structuredClone(payload);
			let transactionCalls = 0;
			let policyCalls = 0;
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				{
					...f.options,
					verifyTransactionData: () => {
						transactionCalls++;
						return true;
					},
					queryPolicy: () => {
						policyCalls++;
						return true;
					},
				},
			);
			t.true(prepared.ok, JSON.stringify(prepared));
			if (!prepared.ok) return;
			// Sign independently so a producer-side rejection cannot hide a consumer defect.
			const jwt = await token(payload, f.protocol.verifier.privateKey, "oauth-authz-req+jwt");
			const checked = await CredentialVerifierRole.completeAuthorizationRequest(
				prepared.value,
				jwt,
				{
					scopeQuery: config.scopeQuery,
				},
			);
			t.equal(checked.ok, valid, JSON.stringify(checked));
			t.equal(transactionCalls, valid && payload.transaction_data !== undefined ? 1 : 0);
			t.equal(policyCalls, valid ? 1 : 0);
			if (checked.ok) t.deepEqual(checked.value.request.transaction_data, payload.transaction_data);
			else {
				t.equal(checked.error.code, "invalid_request");
				if (config.error) t.equal(checked.error.description, config.error);
			}
			const signer = new JwkSigner(f.protocol.verifier.privateKey);
			let signatures = 0;
			let creationCallbacks = 0;
			const countingSigner: JwtSigner = {
				alg: signer.alg,
				kid: signer.kid,
				signJwt: (...args) => {
					signatures++;
					return signer.signJwt(...args);
				},
			};
			const options: AuthorizationRequestCreationOptions = {
				...f.options,
				scopeQuery: config.scopeQuery,
				...(config.withChain
					? { trustChain: f.chains.get(f.ids.verifier)!, trustAnchors: f.anchors }
					: {}),
				httpClient: async () => {
					throw new Error("Creation must use local inputs and supplied evidence");
				},
				verifyTransactionData: () => {
					creationCallbacks++;
					return false;
				},
				queryPolicy: () => {
					creationCallbacks++;
					return false;
				},
			};
			const instance = new CredentialVerifierRole({
				trustAnchors: f.anchors,
			});
			instance.initialize({
				entityId: f.ids.verifier,
				keyProvider: MemoryFederationKeyProvider.fromJWK(f.keys.verifier.privateKey),
			});
			const created = config.instance
				? await instance.createAuthorizationRequest(payload, countingSigner, options)
				: await CredentialVerifierRole.createAuthorizationRequest(
						f.ids.verifier,
						payload,
						countingSigner,
						options,
					);
			t.equal(created.ok, valid, JSON.stringify(created));
			t.equal(signatures, valid ? 1 : 0, "Rejected requests never reach the signer");
			t.equal(creationCallbacks, 0, "Creation leaves application checks to the receiving wallet");
			if (created.ok) {
				const decoded = decodeJwt(created.value);
				t.deepEqual(decoded.transaction_data, payload.transaction_data);
				t.deepEqual(decoded.dcql_query, payload.dcql_query);
				t.equal(decoded.scope, payload.scope);
				t.false(Object.hasOwn(decoded, "scopeQuery"), "Local scope mapping is not serialized");
			} else {
				t.equal(created.error.code, "invalid_request");
				if (config.error) t.equal(created.error.description, config.error);
			}
			t.deepEqual(payload, original, "Validation preserves the caller's payload");
		}

		test("rejects referenced SD-JWT binding opt-outs and preserves valid boundaries", async (t) => {
			const f = await walletFederation({
				verifierMetadata: { vp_formats_supported: { "dc+sd-jwt": {}, application_format: {} } },
			});
			await check(t, f, { dcql_query: query(false) }, false, { error: bindingError });
			for (const binding of [true, undefined])
				await check(t, f, { dcql_query: query(binding) }, true);
			await check(t, f, { dcql_query: query(false), transaction_data: undefined }, true);
			await check(
				t,
				f,
				{
					dcql_query: {
						credentials: [...query(true).credentials, ...query(false, "unrelated").credentials],
					},
				},
				true,
			);
			await check(
				t,
				f,
				{
					dcql_query: {
						credentials: [
							{
								id: "identity",
								format: "application_format",
								meta: {},
								require_cryptographic_holder_binding: false,
							},
						],
					},
				},
				true,
			);
		});

		test("checks every transaction and credential reference", async (t) => {
			const f = await walletFederation();
			const dcql_query = {
				credentials: [...query(true).credentials, ...query(false, "second").credentials],
			};
			for (const transaction_data of [
				[transaction("identity"), transaction("second")],
				[transaction("identity", "second")],
			])
				await check(t, f, { dcql_query, transaction_data }, false, { error: bindingError });
		});

		test("uses effective superior queries before inspecting overridden request queries", async (t) => {
			for (const binding of [true, false]) {
				const f = await walletFederation({ verifierOverride: { dcql_queries: [query(binding)] } });
				for (const dcql_query of [query(!binding), { invalid: "ignored query" }]) {
					await check(t, f, { dcql_query }, binding, {
						withChain: true,
						error: binding ? undefined : bindingError,
					});
				}
				await check(t, f, { dcql_query: undefined, scope: "identity_scope" }, binding, {
					withChain: true,
					instance: true,
					error: binding ? undefined : bindingError,
				});
			}
		});

		test("keeps selected request queries separate from published scenarios", async (t) => {
			for (const binding of [true, false]) {
				const f = await walletFederation({ verifierMetadata: { dcql_queries: [query(!binding)] } });
				await check(t, f, { dcql_query: query(binding) }, binding, {
					withChain: true,
					error: binding ? undefined : bindingError,
				});
			}
		});

		test("checks all superior scenarios sharing a credential ID regardless of order", async (t) => {
			for (const dcql_queries of [
				[query(true), query(false)],
				[query(false), query(true)],
			]) {
				const f = await walletFederation({ verifierOverride: { dcql_queries } });
				await check(t, f, {}, false, { withChain: true, error: bindingError });
			}
			const f = await walletFederation({
				verifierOverride: { dcql_queries: [query(true), query(false, "unrelated")] },
			});
			await check(t, f, {}, true, { withChain: true });
		});

		test("validates scope mappings for static and instance transaction creation", async (t) => {
			const f = await walletFederation();
			const scoped = { dcql_query: undefined, scope: "identity_scope" };
			for (const instance of [false, true]) {
				for (const binding of [false, true, undefined]) {
					await check(t, f, scoped, binding !== false, {
						scopeQuery: query(binding),
						instance,
						error: binding === false ? bindingError : undefined,
					});
				}
				for (const scopeQuery of [undefined, {} as DcqlQuery]) {
					await check(t, f, scoped, false, {
						scopeQuery,
						instance,
						error: "Scope-to-DCQL mapping must be provided by the application",
					});
				}
			}
			await check(t, f, { dcql_query: query(false) }, false, {
				scopeQuery: query(true),
				error: bindingError,
			});
			await check(t, f, { dcql_query: query(true) }, true, { scopeQuery: query(false) });
			const created = await CredentialVerifierRole.createAuthorizationRequest(
				f.ids.verifier,
				{ ...f.requestPayload, ...scoped },
				new JwkSigner(f.protocol.verifier.privateKey),
				f.options,
			);
			t.true(created.ok, "Scope creation without transactions needs no local mapping");
		});

		test("rejects malformed transaction data and unbound IDs before signing", async (t) => {
			const f = await walletFederation();
			for (const transaction_data of [
				null,
				[],
				{},
				[123],
				["bad"],
				[transaction("unknown")],
				...[
					{},
					{ type: "payment" },
					{ type: "payment", credential_ids: [] },
					{ type: 123, credential_ids: ["identity"] },
				].map((data) => [base64url.encode(JSON.stringify(data))]),
			]) {
				await check(t, f, { transaction_data }, false, {
					error:
						!Array.isArray(transaction_data) || !transaction_data.length
							? "Unsupported transaction_data"
							: "Malformed or unbound transaction data",
				});
			}
		});

		test("rejects sparse transaction arrays before signing", async (t) => {
			const f = await walletFederation();
			const encoded = transaction("identity");
			for (const transaction_data of [
				new Array<string>(1),
				Object.assign(new Array<string>(2), { 0: encoded }),
				Object.assign(new Array<string>(2), { 1: encoded }),
			]) {
				await check(t, f, { transaction_data }, false, {
					error: "Malformed or unbound transaction data",
				});
			}
		});

		test("preserves encoded transaction strings and extension fields", async (t) => {
			const f = await walletFederation();
			const encoded = base64url.encode(
				'{ "custom": { "amount": 12 }, "credential_ids": ["identity"], "type": "application_payment" }',
			);
			await check(t, f, { transaction_data: [encoded] }, true);
			let received: unknown;
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				{
					...f.options,
					verifyTransactionData: ({ data }) => {
						received = data;
						return true;
					},
				},
			);
			t.true(prepared.ok);
			if (!prepared.ok) return;
			const jwt = await token(
				{ ...f.requestPayload, transaction_data: [encoded] },
				f.protocol.verifier.privateKey,
				"oauth-authz-req+jwt",
			);
			t.true((await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, jwt)).ok);
			t.deepEqual(received, [
				{ custom: { amount: 12 }, credential_ids: ["identity"], type: "application_payment" },
			]);
		});
	});
	module("wallet / provider attestation keys", () => {
		for (const source of ["jwks", "jwks_uri", "signed_jwks_uri"] as const) {
			test(`verifies attestation signatures with resolved ${source} keys`, async (t) => {
				const { compactVerify, importJWK } = await import("jose");
				const uri = "https://provider.example/keys";
				const f = await walletFederation(
					source === "jwks" ? {} : { providerMetadata: { jwks: undefined, [source]: uri } },
				);
				const keys = [f.protocol.provider.publicKey];
				const signed = await token(
					{ iss: f.ids.provider, sub: f.ids.provider, keys },
					f.keys.provider.privateKey,
					"jwk-set+jwt",
					{ kid: f.keys.provider.publicKey.kid },
				);
				f.routes.set(
					uri,
					() =>
						new Response(source === "signed_jwks_uri" ? signed : JSON.stringify({ keys }), {
							headers: {
								"content-type":
									source === "signed_jwks_uri" ? "application/jwk-set+jwt" : "application/json",
							},
						}),
				);
				for (const Role of [CredentialIssuerRole, CredentialVerifierRole]) {
					for (const valid of [true, false]) {
						let calls = 0;
						const jwt = await token(
							attestation(f),
							valid ? f.protocol.provider.privateKey : f.keys.provider.privateKey,
							"custom-attestation+jwt",
						);
						const result = await Role.verifyProviderAttestation(jwt, f.ids.provider, f.anchors, {
							...f.options,
							offline: source === "jwks",
							verifyAttestation: async ({ attestation: input, keys: resolved }) => {
								calls++;
								t.deepEqual(resolved.keys, keys);
								await compactVerify(input as string, await importJWK(resolved.keys[0]!));
								return true;
							},
						});
						t.equal(
							result.ok,
							valid,
							"the callback verifies against protocol keys, not federation signing keys",
						);
						t.equal(calls, 1);
					}
				}
				t.deepEqual(f.requests, source === "jwks" ? [] : [uri, uri, uri, uri]);
			});
		}
		test("key resolution failures prevent format callbacks", async (t) => {
			for (const scenario of ["unavailable", "malformed", "bad-signature", "offline"] as const) {
				const source = scenario === "bad-signature" ? "signed_jwks_uri" : "jwks_uri";
				const uri = "https://provider.example/keys";
				const f = await walletFederation({ providerMetadata: { jwks: undefined, [source]: uri } });
				if (scenario === "malformed") f.routes.set(uri, () => Response.json({ keys: [] }));
				if (scenario === "bad-signature") {
					const signed = await token(
						{ iss: f.ids.provider, sub: f.ids.provider, keys: [f.protocol.provider.publicKey] },
						f.protocol.provider.privateKey,
						"jwk-set+jwt",
						{ kid: f.keys.provider.publicKey.kid },
					);
					f.routes.set(
						uri,
						() => new Response(signed, { headers: { "content-type": "application/jwk-set+jwt" } }),
					);
				}
				for (const Role of [CredentialIssuerRole, CredentialVerifierRole]) {
					let calls = 0;
					const result = await Role.verifyProviderAttestation("custom", f.ids.provider, f.anchors, {
						...f.options,
						offline: scenario === "offline",
						verifyAttestation: () => {
							calls++;
							return true;
						},
					});
					t.false(result.ok, scenario);
					t.equal(calls, 0);
					if (!result.ok)
						t.false(
							result.error.description.includes("Verification policy"),
							"failure originates in key resolution",
						);
				}
				t.deepEqual(f.requests, scenario === "offline" ? [] : [uri, uri]);
			}
		});
		test("uses superior replacement keys when verifying provider attestations", async (t) => {
			const { compactVerify, importJWK } = await import("jose");
			const f = await walletFederation();
			const replacement = await generateSigningKey();
			const original = f.chains.get(f.ids.provider)!;
			const statement = await token(
				{
					iss: f.ids.anchor,
					sub: f.ids.provider,
					iat: 1000,
					exp: 5000,
					jwks: { keys: [f.keys.provider.publicKey] },
					metadata: { openid_wallet_provider: { jwks: { keys: [replacement.publicKey] } } },
				},
				f.keys.anchor.privateKey,
				"entity-statement+jwt",
				{ kid: f.keys.anchor.publicKey.kid },
			);
			f.chains.set(f.ids.provider, [original[0]!, statement, original[2]!]);
			for (const Role of [CredentialIssuerRole, CredentialVerifierRole]) {
				for (const valid of [true, false]) {
					let calls = 0;
					const jwt = await token(
						attestation(f),
						valid ? replacement.privateKey : f.protocol.provider.privateKey,
						"custom-attestation+jwt",
					);
					const result = await Role.verifyProviderAttestation(jwt, f.ids.provider, f.anchors, {
						...f.options,
						offline: true,
						verifyAttestation: async ({ attestation: input, keys }) => {
							calls++;
							t.deepEqual(keys.keys, [replacement.publicKey]);
							await compactVerify(input as string, await importJWK(keys.keys[0]!));
							return true;
						},
					});
					t.equal(result.ok, valid);
					t.equal(calls, 1);
				}
			}
		});
		test("preserves callback rejection, cancellation, deadlines, and evidence expiry", async (t) => {
			for (const scenario of [
				"missing",
				"reject",
				"throw",
				"cancel",
				"timeout",
				"expire",
			] as const) {
				const f = await walletFederation();
				const controller = new AbortController();
				let calls = 0;
				const verify: AttestationVerificationOptions["verifyAttestation"] = () => {
					calls++;
					if (scenario === "throw") throw new Error("bad signature");
					if (scenario === "reject") return false;
					if (scenario === "cancel") controller.abort();
					if (scenario === "timeout") return new Promise(() => {});
					if (scenario === "expire") f.setTime(5000);
					return true;
				};
				const result = await CredentialIssuerRole.verifyProviderAttestation(
					"custom",
					f.ids.provider,
					f.anchors,
					{
						...f.options,
						httpTimeoutMs: 100,
						signal: controller.signal,
						verifyAttestation:
							scenario === "missing" ? (undefined as unknown as typeof verify) : verify,
					},
				);
				t.false(result.ok, scenario);
				t.equal(calls, scenario === "missing" ? 0 : 1);
			}
		});
		test("keeps alternative credential verification available without published keys", async (t) => {
			const f = await walletFederation({ issuerMetadata: { jwks: undefined } });
			for (const accepted of [true, false]) {
				let calls = 0;
				const result = await CredentialVerifierRole.verifyCredential(
					"credential",
					f.ids.issuer,
					f.anchors,
					{
						...f.options,
						offline: true,
						verifyCredential: ({ keys }) => {
							calls++;
							t.strictEqual(keys, undefined);
							return accepted;
						},
					},
				);
				t.equal(result.ok, accepted);
				t.equal(calls, 1);
			}
		});
		test("requires federation-resolved keys before calling a format verifier", async (t) => {
			const { compactVerify, importJWK } = await import("jose");
			const f = await walletFederation({ providerMetadata: { jwks: undefined } });
			const jwt = await token(
				attestation(f),
				f.protocol.provider.privateKey,
				"custom-attestation+jwt",
			);
			const applicationKey = await importJWK(f.protocol.provider.publicKey);
			await compactVerify(jwt, applicationKey);
			for (const Role of [CredentialIssuerRole, CredentialVerifierRole]) {
				for (const offline of [false, true]) {
					let calls = 0;
					const result = await Role.verifyProviderAttestation(jwt, f.ids.provider, f.anchors, {
						...f.options,
						offline,
						verifyAttestation: async ({ attestation: input }) => {
							calls++;
							await compactVerify(input as string, applicationKey);
							return true;
						},
					});
					t.false(result.ok, "an application-held key cannot replace federation key resolution");
					t.equal(calls, 0);
					if (!result.ok)
						t.true(
							result.error.description.includes(
								offline ? "Offline verification" : "no JWK Set representation",
							),
						);
				}
			}
			t.equal(f.requests.length, 0);
			t.true(
				(await WalletProviderRole.discover(f.ids.provider, f.anchors, f.options)).ok,
				"discovery remains available without published protocol keys",
			);
		});
	});
	module("wallet / protocol key identifiers", () => {
		test("accepts optional and shared identifiers for issuer and provider protocol keys", async (t) => {
			const ec = await generateSigningKey();
			const rsa = await generateSigningKey("RS256");
			const anonymous = { ...ec.publicKey };
			delete anonymous.kid;
			for (const keys of [
				[anonymous],
				[ec.publicKey],
				[ec.publicKey, { ...rsa.publicKey, kid: ec.publicKey.kid }],
			]) {
				const f = await walletFederation({
					issuerMetadata: { jwks: { keys } },
					providerMetadata: { jwks: { keys } },
				});
				for (const [Role, name] of [
					[CredentialIssuerRole, "issuer"],
					[WalletProviderRole, "provider"],
				] as const) {
					t.true(Role.parseMetadata(f.metadata[name][new Role().type]).success);
					const result = await Role.discover(f.ids[name], f.anchors, {
						...f.options,
						offline: true,
					});
					t.true(result.ok, JSON.stringify(result));
					if (result.ok) t.deepEqual(result.value.metadata.jwks, { keys });
				}
				const jwt = await token(
					attestation(f),
					ec.privateKey,
					"oauth-client-attestation+jwt",
					keys[0]?.kid ? { kid: keys[0].kid } : {},
				);
				const verified = await CredentialIssuerRole.verifyWalletAttestation(jwt, f.anchors, {
					...f.options,
					offline: true,
				});
				t.true(verified.ok, JSON.stringify(verified));
			}
		});
		test("rejects empty sets and private material in issuer and provider metadata", async (t) => {
			const f = await walletFederation();
			for (const keys of [[], [f.protocol.issuer.privateKey]]) {
				t.false(
					CredentialIssuerRole.parseMetadata({
						...f.metadata.issuer.openid_credential_issuer,
						jwks: { keys },
					}).success,
				);
				t.false(
					WalletProviderRole.parseMetadata({
						...f.metadata.provider.openid_wallet_provider,
						jwks: { keys },
					}).success,
				);
			}
		});
		for (const source of ["jwks", "jwks_uri", "signed_jwks_uri"] as const) {
			test(`uses protocol keys without identifiers from ${source}`, async (t) => {
				const signing = await generateSigningKey();
				const anonymous = { ...signing.publicKey };
				delete anonymous.kid;
				const keys = { keys: [anonymous] };
				const uri = "https://keys.example/protocol";
				const metadata = source === "jwks" ? { jwks: keys } : { jwks: undefined, [source]: uri };
				const f = await walletFederation({ issuerMetadata: metadata, providerMetadata: metadata });
				for (const name of ["issuer", "provider"] as const) {
					const signed = await token(
						{ iss: f.ids[name], sub: f.ids[name], ...keys },
						f.keys[name].privateKey,
						"jwk-set+jwt",
						{ kid: f.keys[name].publicKey.kid },
					);
					f.routes.set(uri, () =>
						source === "signed_jwks_uri"
							? new Response(signed, { headers: { "content-type": "application/jwk-set+jwt" } })
							: Response.json(keys),
					);
					if (name === "issuer") {
						let calls = 0;
						const result = await CredentialVerifierRole.verifyCredential(
							"credential",
							f.ids.issuer,
							f.anchors,
							{
								...f.options,
								offline: source === "jwks",
								verifyCredential: ({ issuer, keys: resolved }) => {
									calls++;
									t.equal(issuer.entityId, f.ids.issuer);
									t.deepEqual(resolved, keys);
									return true;
								},
							},
						);
						t.true(result.ok, JSON.stringify(result));
						t.equal(calls, 1);
					} else {
						for (const valid of [true, false]) {
							// The external provider omits kid in both the public JWK and JWT header.
							const jwt = await token(
								attestation(f),
								valid ? signing.privateKey : f.protocol.provider.privateKey,
								"oauth-client-attestation+jwt",
							);
							const result = await CredentialIssuerRole.verifyWalletAttestation(jwt, f.anchors, {
								...f.options,
								offline: source === "jwks",
							});
							t.equal(result.ok, valid, JSON.stringify(result));
							if (!result.ok) t.true(result.error.description.includes("JWT signature or claims"));
						}
					}
				}
			});
		}
		test("retains the use requirement for mixed issuer and provider protocol keys", async (t) => {
			const signing = await generateSigningKey();
			const publicKey = { ...signing.publicKey };
			delete publicKey.kid;
			delete publicKey.use;
			for (const valid of [true, false]) {
				const keys = [
					{ ...publicKey, ...(valid ? { use: "sig" } : {}) },
					{ ...publicKey, alg: "ECDH-ES", use: "enc" },
				];
				const f = await walletFederation({
					issuerMetadata: { jwks: { keys } },
					providerMetadata: { jwks: { keys } },
				});
				for (const [Role, name] of [
					[CredentialIssuerRole, "issuer"],
					[WalletProviderRole, "provider"],
				] as const) {
					const result = await Role.discover(f.ids[name], f.anchors, {
						...f.options,
						offline: true,
					});
					t.equal(result.ok, valid, JSON.stringify(result));
					if (!result.ok) t.true(result.error.description.includes("use"));
				}
				const uri = "https://issuer.example/keys";
				const remote = await walletFederation({
					issuerMetadata: { jwks: undefined, jwks_uri: uri },
				});
				remote.routes.set(uri, () => Response.json({ keys }));
				let calls = 0;
				const result = await CredentialVerifierRole.verifyCredential(
					"credential",
					remote.ids.issuer,
					remote.anchors,
					{
						...remote.options,
						verifyCredential: ({ keys: resolved }) => {
							calls++;
							t.deepEqual(resolved, { keys });
							return true;
						},
					},
				);
				t.equal(result.ok, valid, JSON.stringify(result));
				t.equal(calls, valid ? 1 : 0);
				if (!result.ok) t.true(result.error.description.includes("use"));
			}
		});
		test("retains verifier and credential encryption identifier requirements", async (t) => {
			const f = await walletFederation();
			const anonymous = { ...f.protocol.verifier.publicKey };
			delete anonymous.kid;
			for (const keys of [
				[f.protocol.verifier.publicKey],
				[anonymous],
				[f.protocol.verifier.publicKey, f.protocol.verifier.publicKey],
			]) {
				const valid = keys.length === 1 && keys[0]?.kid !== undefined;
				t.equal(
					CredentialVerifierRole.parseMetadata({
						...f.metadata.verifier.openid_credential_verifier,
						jwks: { keys },
					}).success,
					valid,
				);
				t.equal(
					CredentialIssuerRole.parseMetadata({
						...f.metadata.issuer.openid_credential_issuer,
						credential_request_encryption: {
							jwks: { keys: keys.map((key) => ({ ...key, use: "enc", alg: "ECDH-ES" })) },
							enc_values_supported: ["A256GCM"],
							encryption_required: false,
						},
					}).success,
					valid,
				);
			}
		});
		for (const source of ["jwks_uri", "signed_jwks_uri"] as const) {
			test(`checks verifier identifiers after resolving ${source}`, async (t) => {
				const uri = "https://verifier.example/keys";
				const f = await walletFederation({ verifierMetadata: { jwks: undefined, [source]: uri } });
				const anonymous = { ...f.protocol.verifier.publicKey };
				delete anonymous.kid;
				const request = await token(
					f.requestPayload,
					f.protocol.verifier.privateKey,
					"oauth-authz-req+jwt",
					{ kid: f.protocol.verifier.publicKey.kid },
				);
				for (const keys of [
					[f.protocol.verifier.publicKey],
					[anonymous],
					[f.protocol.verifier.publicKey, f.protocol.verifier.publicKey],
				]) {
					const valid = keys.length === 1 && keys[0]?.kid !== undefined;
					const signed = await token(
						{ iss: f.ids.verifier, sub: f.ids.verifier, keys },
						f.keys.verifier.privateKey,
						"jwk-set+jwt",
						{ kid: f.keys.verifier.publicKey.kid },
					);
					f.routes.set(
						uri,
						() =>
							new Response(source === "signed_jwks_uri" ? signed : JSON.stringify({ keys }), {
								headers: {
									"content-type":
										source === "signed_jwks_uri" ? "application/jwk-set+jwt" : "application/json",
								},
							}),
					);
					const checked = await CredentialVerifierRole.prepareAuthorizationRequest(
						{ client_id: f.requestPayload.client_id, request },
						f.anchors,
						f.options,
					);
					t.equal(
						checked.ok,
						valid,
						checked.ok ? "valid verifier keys" : checked.error.description,
					);
				}
			});
		}
	});
	module("wallet / anchor self-signature", () => {
		test("rejects inconsistent anchor keys before attestation verification", async (t) => {
			const protocol = await generateSigningKey();
			const f = await anchorKeyPaths({
				openid_wallet_provider: {
					vp_formats_supported: { "dc+sd-jwt": {} },
					jwks: { keys: [protocol.publicKey] },
				},
			});
			for (const publication of ["overlap", "missing-signer", "wrong-material"] as const) {
				let calls = 0;
				const trustChain = await f.anchorKeyChain(publication);
				const result = await CredentialIssuerRole.verifyProviderAttestation(
					"custom",
					f.ids.subject,
					f.anchors,
					{
						...f.options,
						trustChain,
						offline: true,
						verifyAttestation: () => {
							calls++;
							return true;
						},
					},
				);
				const valid = publication === "overlap";
				t.equal(result.ok, valid);
				t.equal(calls, valid ? 1 : 0);
				if (!result.ok) t.true(result.error.description.includes("TA EC self-signature invalid"));
			}
		});
	});
	module("wallet / chain loops", () => {
		test("rejects cyclic provider evidence before attestation verification", async (t) => {
			const protocol = await generateSigningKey();
			const f = await trustChainPaths({
				openid_wallet_provider: {
					vp_formats_supported: { "dc+sd-jwt": {} },
					jwks: { keys: [protocol.publicKey] },
				},
			});
			for (const cyclic of [false, true]) {
				let calls = 0;
				const trustChain = await f.chain(
					cyclic ? ["subject", "a", "b", "a", "anchor"] : ["subject", "a", "b", "anchor"],
				);
				const result = await CredentialIssuerRole.verifyProviderAttestation(
					"custom",
					f.ids.subject,
					f.anchors,
					{
						...f.options,
						trustChain,
						offline: true,
						verifyAttestation: () => {
							calls++;
							return true;
						},
					},
				);
				t.equal(result.ok, !cyclic);
				t.equal(calls, cyclic ? 0 : 1);
				if (!result.ok) t.true(result.error.description.includes("Loop detected"));
			}
		});
	});

	module("wallet / metadata", () => {
		test("applies URL rules according to each wallet metadata field", async (t) => {
			const f = await walletFederation();
			const credentials = ["user@", "user:secret@", ":secret@", "@", ":@", "%75ser:%73ecret@"];
			for (const [role, metadata, fields] of [
				[
					WalletProviderRole,
					f.metadata.provider.openid_wallet_provider,
					["jwks_uri", "signed_jwks_uri"],
				],
				[
					CredentialIssuerRole,
					f.metadata.issuer.openid_credential_issuer,
					[
						"credential_issuer",
						"authorization_servers",
						"credential_endpoint",
						"nonce_endpoint",
						"deferred_credential_endpoint",
						"notification_endpoint",
						"jwks_uri",
						"signed_jwks_uri",
					],
				],
				[
					CredentialVerifierRole,
					f.metadata.verifier.openid_credential_verifier,
					["request_uris", "response_uris", "redirect_uris", "jwks_uri", "signed_jwks_uri"],
				],
			] as const) {
				for (const field of fields) {
					const array = field.endsWith("_uris") || field === "authorization_servers";
					for (const credential of credentials) {
						const uri = `https://${credential}verifier.example/path`;
						t.false(
							role.parseMetadata({ ...metadata, [field]: array ? [uri] : uri }).success,
							`${field} rejects userinfo`,
						);
					}
				}
			}
			const base = f.metadata.verifier.openid_credential_verifier;
			for (const uri of [
				"\u0000https://@verifier.example/path",
				"https:@verifier.example/path",
				"https:\\@verifier.example/path",
				"https://\t@verifier.example/path",
			])
				t.false(
					CredentialVerifierRole.parseMetadata({ ...base, request_uris: [uri] }).success,
					"rejects empty userinfo in forms accepted by the URL parser",
				);
			for (const suffix of ["#fragment", "#"]) {
				const uri = `https://verifier.example/path${suffix}`;
				t.false(CredentialVerifierRole.parseMetadata({ ...base, response_uris: [uri] }).success);
				for (const field of ["redirect_uris", "request_uris", "jwks_uri", "signed_jwks_uri"])
					t.true(
						CredentialVerifierRole.parseMetadata({
							...base,
							[field]: field.endsWith("_uris") ? [uri] : uri,
						}).success,
						`${field} permits fragments`,
					);
			}
			for (const uri of [
				"HTTPS://verifier.example/path",
				"https://verifier.example/path%23part?email=a@b",
				"https://verifier.example/@path?value=1",
			]) {
				const parsed = CredentialVerifierRole.parseMetadata({ ...base, response_uris: [uri] });
				t.true(parsed.success);
				if (parsed.success)
					t.deepEqual(parsed.data.response_uris, [uri], "preserves the registered string");
			}
			for (const field of [
				"credential_endpoint",
				"nonce_endpoint",
				"deferred_credential_endpoint",
				"notification_endpoint",
			])
				t.true(
					CredentialIssuerRole.parseMetadata({
						...f.metadata.issuer.openid_credential_issuer,
						[field]: "https://issuer.example/path#fragment",
					}).success,
					`${field} keeps its existing fragment handling`,
				);
		});
		test("validates issuer claim paths according to their credential format", async (t) => {
			const f = await walletFederation();
			const configuration = (format: string, paths: unknown[][]) => ({
				...f.metadata.issuer.openid_credential_issuer,
				credential_configurations_supported: {
					one: {
						format,
						doctype: "example.id",
						vct: "https://example.com/identity",
						credential_metadata: { claims: paths.map((path) => ({ path })) },
					},
				},
			});
			for (const paths of [
				[["namespace", "element", -1]],
				[
					["namespace", "element", -1],
					["namespace", "element", "name"],
					["namespace", "element", 0],
				],
				[["namespace", "element", null, "name"]],
				[
					["namespace", "element", 0],
					["namespace", "element", 1],
				],
			])
				t.true(
					CredentialIssuerRole.parseMetadata(configuration("mso_mdoc", paths)).success,
					JSON.stringify(paths),
				);
			for (const paths of [
				[["namespace"]],
				[["namespace", 0]],
				[[0, "element"]],
				[["namespace", "element", -0.5]],
				[
					["namespace", "element", -1],
					["namespace", "element", -1],
				],
				[
					["namespace", "element", null],
					["namespace", "element", 0],
				],
				[
					["namespace", "element", null],
					["namespace", "element", "name"],
				],
				[
					["namespace", "element", -1],
					["namespace", "element", null],
				],
			])
				t.false(
					CredentialIssuerRole.parseMetadata(configuration("mso_mdoc", paths)).success,
					JSON.stringify(paths),
				);
			t.false(
				CredentialIssuerRole.parseMetadata(configuration("dc+sd-jwt", [["name", -1]])).success,
			);
			const query = (path: unknown[]) => ({
				vp_formats_supported: {},
				dcql_queries: [
					{
						credentials: [
							{
								id: "mdoc",
								format: "mso_mdoc",
								meta: { doctype_value: "example.id" },
								claims: [{ path }],
							},
						],
					},
				],
			});
			t.true(CredentialVerifierRole.parseMetadata(query(["namespace", "element"])).success);
			t.false(CredentialVerifierRole.parseMetadata(query(["namespace", "element", -1])).success);
			t.false(
				CredentialVerifierRole.parseMetadata({
					vp_formats_supported: {},
					dcql_queries: [
						{ credentials: [{ ...walletQuery.credentials[0], claims: [{ path: ["name", -1] }] }] },
					],
				}).success,
			);
			const discovered = await walletFederation({
				issuerMetadata: configuration("mso_mdoc", [["namespace", "element", -1]]),
			});
			t.true(
				(
					await CredentialIssuerRole.discover(discovered.ids.issuer, discovered.anchors, {
						...discovered.options,
						offline: true,
					})
				).ok,
			);
		});
		test("allows empty claim-set alternatives while retaining credential-set and reference rules", async (t) => {
			const f = await walletFederation();
			const credential = {
				...walletQuery.credentials[0]!,
				claims: [{ id: "name", path: ["name"] }],
				claim_sets: [["name"], []],
			};
			const query = { credentials: [credential] };
			t.true(
				CredentialVerifierRole.parseMetadata({ vp_formats_supported: {}, dcql_queries: [query] })
					.success,
			);
			for (const invalid of [
				{ credentials: [{ ...credential, claim_sets: [] }] },
				{ credentials: [{ ...credential, claim_sets: [["missing"], []] }] },
				{ credentials: [{ ...credential, claims: undefined }] },
				{ credentials: [{ ...credential, claims: [{ path: ["name"] }] }] },
				{ ...query, credential_sets: [{ options: [[]] }] },
			])
				t.false(
					CredentialVerifierRole.parseMetadata({
						vp_formats_supported: {},
						dcql_queries: [invalid],
					}).success,
					JSON.stringify(invalid),
				);
			const signed = await CredentialVerifierRole.createAuthorizationRequest(
				f.ids.verifier,
				{ ...f.requestPayload, dcql_query: query },
				new JwkSigner(f.protocol.verifier.privateKey),
				f.options,
			);
			t.true(signed.ok, JSON.stringify(signed));
			if (!signed.ok) return;
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				f.options,
			);
			t.true(prepared.ok);
			if (!prepared.ok) return;
			t.true(
				(await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, signed.value))
					.ok,
			);
		});
		test("preserves BCP47 locales and optional claim display names while rejecting contradictory descriptions", async (t) => {
			const f = await walletFederation();
			const issuer = f.metadata.issuer.openid_credential_issuer!;
			const configuration = (credential_metadata: Record<string, unknown>) => ({
				...issuer,
				credential_configurations_supported: { one: { format: "custom", credential_metadata } },
			});
			for (const locale of ["en-US", "x-private", "i-klingon"]) {
				t.true(
					CredentialIssuerRole.parseMetadata(
						configuration({
							display: [{ name: "Identity", locale }],
							claims: [{ path: ["name"], display: [{ locale }] }],
						}),
					).success,
					locale,
				);
			}
			for (const credential_metadata of [
				{
					display: [
						{ name: "one", locale: "en" },
						{ name: "two", locale: "EN" },
					],
				},
				{ claims: [{ path: ["name"], display: [{ locale: "en" }, { locale: "EN" }] }] },
				{ claims: [{ path: ["name"] }, { path: ["name"] }] },
				{ claims: [{ path: ["names", null, "given"] }, { path: ["names", 0, "given"] }] },
				{ claims: [{ path: ["names", "given"] }, { path: ["names", 0] }] },
			])
				t.false(
					CredentialIssuerRole.parseMetadata(configuration(credential_metadata)).success,
					JSON.stringify(credential_metadata),
				);
			t.true(
				CredentialIssuerRole.parseMetadata(
					configuration({
						claims: [{ path: ["names", 0] }, { path: ["names", 1] }, { path: ["family"] }],
					}),
				).success,
			);
			t.true(
				CredentialIssuerRole.parseMetadata({
					...issuer,
					credential_configurations_supported: {
						vc: {
							format: "jwt_vc_json",
							credential_definition: { type: ["VerifiableCredential"] },
						},
					},
				}).success,
			);
			t.false(
				CredentialIssuerRole.parseMetadata({
					...issuer,
					credential_configurations_supported: {
						vc: { format: "ldp_vc", credential_definition: { type: ["VerifiableCredential"] } },
					},
				}).success,
			);
		});
		test("requires role capabilities and preserves extensions", async (t) => {
			const f = await walletFederation();
			for (const [Role, name] of [
				[WalletProviderRole, "provider"],
				[CredentialIssuerRole, "issuer"],
				[CredentialVerifierRole, "verifier"],
			] as const) {
				t.false(Role.parseMetadata({}).success);
				const metadata = Object.values(f.metadata[name])[0]!;
				const result = Role.parseMetadata({ ...metadata, custom: { extension: true } });
				t.true(result.success, name);
				if (result.success) t.deepEqual(result.data.custom, { extension: true });
			}
		});
		test("rejects malformed verifier keys, endpoint lists, and query references", async (t) => {
			const f = await walletFederation();
			const metadata = f.metadata.verifier.openid_credential_verifier!;
			for (const invalid of [
				{ request_uris: [] },
				{ request_uris: ["http://bad.example"] },
				{ request_uris: ["not-a-url"] },
				{ redirect_uris: [] },
				{ redirect_uris: [""] },
				{ response_uris: [] },
				{ response_uris: ["not-a-url"] },
				{ jwks: { keys: [f.protocol.verifier.privateKey] } },
				{ jwks: { keys: [f.protocol.verifier.publicKey, f.protocol.verifier.publicKey] } },
				{ dcql_queries: [] },
				{ dcql_queries: [{}] },
				{
					dcql_queries: [{ credentials: [walletQuery.credentials[0], walletQuery.credentials[0]] }],
				},
				{ dcql_queries: [{ ...walletQuery, credential_sets: [{ options: [["missing"]] }] }] },
				{
					dcql_queries: [
						{ credentials: [{ ...walletQuery.credentials[0], claims: [{ path: [-1] }] }] },
					],
				},
				{
					dcql_queries: [
						{
							credentials: [
								{
									...walletQuery.credentials[0],
									claims: [{ path: ["name"] }],
									claim_sets: [["missing"]],
								},
							],
						},
					],
				},
				{
					dcql_queries: [
						{
							credentials: [
								{ id: "mdoc", format: "mso_mdoc", meta: {}, claims: [{ path: ["one"] }] },
							],
						},
					],
				},
				{ dcql_queries: [{ credentials: [{ id: "w3c", format: "jwt_vc_json", meta: {} }] }] },
				{ dcql_queries: [{ credentials: [{ id: "sd", format: "dc+sd-jwt", meta: {} }] }] },
			])
				t.false(
					CredentialVerifierRole.parseMetadata({ ...metadata, ...invalid }).success,
					JSON.stringify(invalid),
				);
		});
		test("keeps optional keys and extensible formats optional", (t) => {
			t.true(
				CredentialVerifierRole.parseMetadata({
					vp_formats_supported: { future_format: { custom: true } },
				}).success,
			);
			t.true(
				WalletProviderRole.parseMetadata({
					vp_formats_supported: {},
					client_id_prefixes_supported: ["custom_prefix"],
				}).success,
			);
			t.false(
				WalletProviderRole.parseMetadata({
					vp_formats_supported: {},
					client_id_prefixes_supported: [],
				}).success,
			);
		});
		test("validates issuer URL, encryption, batch, proof, and format conditions", async (t) => {
			const f = await walletFederation();
			const metadata = f.metadata.issuer.openid_credential_issuer!;
			for (const invalid of [
				{ credential_issuer: `${f.ids.issuer}?` },
				{ credential_issuer: `${f.ids.issuer}#` },
				{ credential_issuer: "http://issuer.example" },
				{ authorization_servers: [] },
				{ credential_request_encryption: {} },
				{ credential_response_encryption: {} },
				{ batch_credential_issuance: { batch_size: 1 } },
				{ display: [{ locale: "en" }, { locale: "en" }] },
				{ display: [{ locale: "invalid tag" }] },
				{ credential_configurations_supported: { one: { format: "dc+sd-jwt" } } },
				{ credential_configurations_supported: { one: { format: "mso_mdoc" } } },
				{ credential_configurations_supported: { one: { format: "jwt_vc_json" } } },
				{
					credential_configurations_supported: {
						one: { format: "custom", cryptographic_binding_methods_supported: ["jwk"] },
					},
				},
				{
					credential_configurations_supported: {
						one: { format: "custom", proof_types_supported: {} },
					},
				},
			])
				t.false(
					CredentialIssuerRole.parseMetadata({ ...metadata, ...invalid }).success,
					JSON.stringify(invalid),
				);
			t.true(
				CredentialIssuerRole.parseMetadata({
					...metadata,
					credential_endpoint: `${f.ids.issuer}/endpoint?version=1`,
				}).success,
			);
		});
	});
	module("wallet / discovery and adapters", () => {
		test("rejects wrong-subject, missing-role, malformed-role, and unavailable discovery evidence", async (t) => {
			const f = await walletFederation();
			t.false(
				(
					await WalletProviderRole.discover(f.ids.issuer, f.anchors, {
						...f.options,
						trustChain: f.chains.get(f.ids.provider),
					})
				).ok,
			);
			t.false((await WalletProviderRole.discover(f.ids.issuer, f.anchors, f.options)).ok);
			const malformed = await walletFederation({
				providerMetadata: { vp_formats_supported: undefined },
			});
			t.false(
				(
					await WalletProviderRole.discover(
						malformed.ids.provider,
						malformed.anchors,
						malformed.options,
					)
				).ok,
			);
			t.false(
				(
					await WalletProviderRole.discover(f.ids.provider, f.anchors, {
						clock: f.clock,
						httpClient: async () => new Response(null, { status: 404 }),
					})
				).ok,
			);
			const controller = new AbortController();
			controller.abort();
			t.false(
				(
					await WalletProviderRole.discover(f.ids.provider, f.anchors, {
						...f.options,
						signal: controller.signal,
					})
				).ok,
			);
			const budget = await WalletProviderRole.discover(f.ids.provider, f.anchors, {
				...f.options,
				maxTotalFetches: 0,
			});
			t.false(budget.ok);
			if (!budget.ok) t.true(budget.error.description.includes("positive safe integer"));
		});
		test("resolves URI protocol keys through core with the shared fetch budget", async (t) => {
			const f = await walletFederation({
				providerMetadata: { jwks: undefined, jwks_uri: "https://provider.example/protocol-keys" },
			});
			f.routes.set(
				"https://provider.example/protocol-keys",
				() =>
					new Response(JSON.stringify({ keys: [f.protocol.provider.publicKey] }), {
						headers: { "content-type": "application/json" },
					}),
			);
			const jwt = await token(
				attestation(f),
				f.protocol.provider.privateKey,
				"oauth-client-attestation+jwt",
			);
			t.true((await CredentialIssuerRole.verifyWalletAttestation(jwt, f.anchors, f.options)).ok);
			t.deepEqual(f.requests, ["https://provider.example/protocol-keys"]);
			f.routes.delete("https://provider.example/protocol-keys");
			t.false((await CredentialIssuerRole.verifyWalletAttestation(jwt, f.anchors, f.options)).ok);
		});
		test("discovers all roles with supplied evidence and no local identity", async (t) => {
			const f = await walletFederation();
			for (const [Role, name] of [
				[WalletProviderRole, "provider"],
				[CredentialIssuerRole, "issuer"],
				[CredentialVerifierRole, "verifier"],
			] as const) {
				const result = await Role.discover(f.ids[name], f.anchors, { ...f.options, offline: true });
				t.true(result.ok, JSON.stringify(result));
				if (result.ok) t.equal(result.value.entityId, f.ids[name]);
			}
			t.equal(f.requests.length, 0);
		});
		test("discovers through core HTTP resolution and enforces work and offline limits", async (t) => {
			const f = await walletFederation();
			const options = { clock: f.clock, httpClient: f.httpClient, clockSkewSeconds: 0 };
			t.true((await WalletProviderRole.discover(f.ids.provider, f.anchors, options)).ok);
			t.true(f.requests.length > 0);
			t.false(
				(
					await WalletProviderRole.discover(f.ids.provider, f.anchors, {
						...options,
						maxTotalFetches: 1,
					})
				).ok,
			);
			t.false((await WalletProviderRole.discover(f.ids.provider, f.anchors, { offline: true })).ok);
			t.false((await WalletProviderRole.discover("http://invalid.example", f.anchors, options)).ok);
			t.false((await WalletProviderRole.discover(f.ids.provider, new Map(), f.options)).ok);
		});
		test("validates external authorization-server federation evidence", async (t) => {
			const f = await walletFederation({
				issuerMetadata: { authorization_servers: ["https://server.example"] },
			});
			const result = await CredentialIssuerRole.discover(f.ids.issuer, f.anchors, {
				...f.options,
				offline: true,
			});
			t.true(result.ok, JSON.stringify(result));
			if (result.ok) t.equal(result.value.authorizationServers[0]?.entityId, f.ids.server);
			const chains = new Map(f.chains);
			chains.delete(f.ids.server);
			t.false(
				(
					await CredentialIssuerRole.discover(f.ids.issuer, f.anchors, {
						...f.options,
						offline: true,
						entityChains: chains,
					})
				).ok,
			);
		});
		test("passes authenticated issuer/provider evidence and keys to format adapters", async (t) => {
			const f = await walletFederation();
			let calls = 0;
			const accepted = await CredentialVerifierRole.verifyCredential(
				"credential",
				f.ids.issuer,
				f.anchors,
				{
					...f.options,
					offline: true,
					verifyCredential: ({ credential, issuer, keys }) => {
						calls++;
						t.equal(credential, "credential");
						t.equal(issuer.entityId, f.ids.issuer);
						t.equal(keys?.keys[0]?.kid, f.protocol.issuer.publicKey.kid);
						return true;
					},
				},
			);
			t.true(accepted.ok);
			t.equal(calls, 1);
			t.false(
				(
					await CredentialVerifierRole.verifyCredential("bad", f.ids.issuer, f.anchors, {
						...f.options,
						verifyCredential: () => false,
					})
				).ok,
			);
			t.false(
				(
					await CredentialVerifierRole.verifyCredential("bad", f.ids.issuer, f.anchors, {
						...f.options,
						verifyCredential: () => {
							throw new Error("bad signature");
						},
					})
				).ok,
			);
			t.true(
				(
					await CredentialIssuerRole.verifyProviderAttestation(
						"custom",
						f.ids.provider,
						f.anchors,
						{
							...f.options,
							verifyAttestation: ({ keys }) =>
								keys?.keys[0]?.kid === f.protocol.provider.publicKey.kid,
						},
					)
				).ok,
			);
			t.false(
				(
					await CredentialIssuerRole.verifyProviderAttestation(
						"custom",
						f.ids.provider,
						f.anchors,
						{ ...f.options, verifyAttestation: () => false },
					)
				).ok,
			);
		});
		test("cancellation and deadlines release a stalled format verifier", async (t) => {
			const f = await walletFederation();
			const controller = new AbortController();
			const pending = CredentialVerifierRole.verifyCredential(
				"credential",
				f.ids.issuer,
				f.anchors,
				{
					...f.options,
					signal: controller.signal,
					verifyCredential: () => {
						controller.abort();
						return new Promise(() => {});
					},
				},
			);
			t.false((await pending).ok);
			t.false(
				(
					await CredentialVerifierRole.verifyCredential("credential", f.ids.issuer, f.anchors, {
						...f.options,
						httpTimeoutMs: 5,
						verifyCredential: () => new Promise(() => {}),
					})
				).ok,
			);
		});
	});
	module("wallet / Wallet Attestations", () => {
		test("bounds signing, cancellation, serialization, and final token size", async (t) => {
			const f = await walletFederation();
			const signer = new JwkSigner(f.protocol.provider.privateKey);
			const params = {
				subject: "wallet",
				confirmationKey: f.protocol.issuer.publicKey,
				expiresAt: 4000,
			};
			const stalled = {
				kid: signer.kid,
				alg: signer.alg,
				signJwt: () => new Promise<string>(() => {}),
			};
			t.false(
				(
					await WalletProviderRole.createWalletAttestation(f.ids.provider, params, stalled, {
						...f.options,
						httpTimeoutMs: 5,
					})
				).ok,
			);
			const controller = new AbortController();
			const cancelled = {
				kid: signer.kid,
				alg: signer.alg,
				signJwt: async () => {
					controller.abort();
					return "unused";
				},
			};
			t.false(
				(
					await WalletProviderRole.createWalletAttestation(f.ids.provider, params, cancelled, {
						...f.options,
						signal: controller.signal,
					})
				).ok,
			);
			t.false(
				(
					await WalletProviderRole.createWalletAttestation(
						f.ids.provider,
						{ ...params, claims: { invalid: 1n } },
						signer,
						f.options,
					)
				).ok,
			);
			const oversized = { kid: signer.kid, alg: signer.alg, signJwt: async () => "x".repeat(2000) };
			t.false(
				(
					await WalletProviderRole.createWalletAttestation(f.ids.provider, params, oversized, {
						...f.options,
						maxResponseBytes: 1024,
					})
				).ok,
			);
		});
		test("rejects unsupported JWT algorithms, unknown key ids, and keys with incompatible use", async (t) => {
			const f = await walletFederation();
			const { base64url } = await import("jose");
			const unsigned = `${base64url.encode(JSON.stringify({ typ: "oauth-client-attestation+jwt", alg: "none" }))}.${base64url.encode(JSON.stringify(attestation(f)))}.AA`;
			t.false(
				(await CredentialIssuerRole.verifyWalletAttestation(unsigned, f.anchors, f.options)).ok,
			);
			const unknown = await token(
				attestation(f),
				f.protocol.provider.privateKey,
				"oauth-client-attestation+jwt",
				{ kid: "unknown" },
			);
			t.false(
				(await CredentialIssuerRole.verifyWalletAttestation(unknown, f.anchors, f.options)).ok,
			);
			for (const change of [{ use: "enc" }, { key_ops: ["encrypt"] }, { alg: "ES384" }]) {
				const constrained = await walletFederation({
					providerMetadata: { jwks: { keys: [{ ...f.protocol.provider.publicKey, ...change }] } },
				});
				const jwt = await token(
					attestation(constrained),
					f.protocol.provider.privateKey,
					"oauth-client-attestation+jwt",
				);
				t.false(
					(
						await CredentialIssuerRole.verifyWalletAttestation(
							jwt,
							constrained.anchors,
							constrained.options,
						)
					).ok,
				);
			}
		});
		test("attestation creation rejects unsupported confirmation key types before signing", async (t) => {
			const pair = await generateSigningKey();
			const delegate = new JwkSigner(pair.privateKey);
			let signatures = 0;
			const signer: JwtSigner = {
				alg: delegate.alg,
				kid: delegate.kid,
				signJwt: async (payload, header) => {
					signatures++;
					return delegate.signJwt(payload, header);
				},
			};
			for (const confirmationKey of [
				{ kty: "oct" },
				{ kty: "oct", k: "secret" },
				{ kty: "FutureKey", future_public: "opaque" },
				pair.privateKey,
			]) {
				const result = await WalletProviderRole.createWalletAttestation(
					"https://provider.example",
					{ subject: "wallet", confirmationKey, expiresAt: 4000 },
					signer,
					{ clock: { now: () => 1500 } },
				);
				t.false(result.ok, JSON.stringify(confirmationKey.kty));
			}
			t.equal(signatures, 0, "invalid keys never reach the signer");
			const confirmationKey = { ...pair.publicKey };
			delete confirmationKey.kid;
			const valid = await WalletProviderRole.createWalletAttestation(
				"https://provider.example",
				{ subject: "wallet", confirmationKey, expiresAt: 4000 },
				signer,
				{ clock: { now: () => 1500 } },
			);
			t.true(valid.ok);
			t.equal(signatures, 1);
			if (valid.ok) t.deepEqual(decodeJwt(valid.value).cnf, { jwk: confirmationKey });
		});
		test("validates chains when attaching them and rejects invalid signing inputs", async (t) => {
			const f = await walletFederation();
			const signer = new JwkSigner(f.protocol.provider.privateKey);
			const params = {
				subject: "wallet",
				confirmationKey: f.protocol.issuer.publicKey,
				expiresAt: 4000,
			};
			const options = {
				...f.options,
				trustChain: f.chains.get(f.ids.provider)!,
				trustAnchors: f.anchors,
			};
			const signed = await WalletProviderRole.createWalletAttestation(
				f.ids.provider,
				params,
				signer,
				options,
			);
			t.true(signed.ok, JSON.stringify(signed));
			if (signed.ok)
				t.true(
					(
						await CredentialIssuerRole.verifyWalletAttestation(signed.value, f.anchors, {
							clock: f.clock,
							offline: true,
						})
					).ok,
				);
			t.false(
				(
					await WalletProviderRole.createWalletAttestation(f.ids.provider, params, signer, {
						...f.options,
						trustChain: options.trustChain,
					})
				).ok,
			);
			t.false(
				(
					await WalletProviderRole.createWalletAttestation(
						"http://invalid.example",
						params,
						signer,
						f.options,
					)
				).ok,
			);
			t.false(
				(
					await WalletProviderRole.createWalletAttestation(
						f.ids.provider,
						{ ...params, expiresAt: 1400 },
						signer,
						f.options,
					)
				).ok,
			);
			t.false(
				(
					await WalletProviderRole.createWalletAttestation(
						f.ids.provider,
						{ ...params, confirmationKey: f.protocol.issuer.privateKey },
						signer,
						f.options,
					)
				).ok,
			);
			t.false(
				(
					await WalletProviderRole.createWalletAttestation(
						f.ids.provider,
						params,
						{
							kid: signer.kid,
							alg: signer.alg,
							signJwt: async () => {
								throw new Error("signer unavailable");
							},
						},
						f.options,
					)
				).ok,
			);
			t.false(
				(
					await WalletProviderRole.createWalletAttestation(f.ids.provider, params, signer, {
						...f.options,
						maxResponseBytes: 10,
					})
				).ok,
			);
			t.false(
				(await WalletProviderRole.createWalletAttestation(f.ids.issuer, params, signer, options))
					.ok,
			);
		});
		test("rejects malformed chains, missing protocol keys, and unavailable offline keys", async (t) => {
			for (const providerMetadata of [
				{ jwks: undefined },
				{ jwks: undefined, jwks_uri: "https://provider.example/keys" },
			]) {
				const f = await walletFederation({ providerMetadata });
				const jwt = await token(
					attestation(f),
					f.protocol.provider.privateKey,
					"oauth-client-attestation+jwt",
				);
				t.false(
					(
						await CredentialIssuerRole.verifyWalletAttestation(jwt, f.anchors, {
							...f.options,
							offline: true,
						})
					).ok,
				);
				t.equal(f.requests.length, 0);
			}
			const f = await walletFederation();
			const jwt = await token(
				attestation(f),
				f.protocol.provider.privateKey,
				"oauth-client-attestation+jwt",
				{ trust_chain: 42 },
			);
			t.false((await CredentialIssuerRole.verifyWalletAttestation(jwt, f.anchors, f.options)).ok);
			t.false(
				(
					await WalletProviderRole.discover(f.ids.provider, f.anchors, {
						...f.options,
						trustChain: [],
					})
				).ok,
			);
			t.false(
				(
					await WalletProviderRole.discover(f.ids.provider, f.anchors, {
						...f.options,
						trustChain: ["bad"],
					})
				).ok,
			);
		});
		test("accepts client/audience/challenge bindings and rejects invalid local authentication policy", async (t) => {
			const f = await walletFederation();
			const jwt = await token(
				attestation(f),
				f.protocol.provider.privateKey,
				"oauth-client-attestation+jwt",
			);
			const pop = await token(
				{
					...proof(f),
					aud: [f.ids.server, "https://other.example"],
					challenge: "expected",
					exp: 1600,
				},
				f.protocol.issuer.privateKey,
				"oauth-client-attestation-pop+jwt",
			);
			const options = {
				...f.options,
				audience: f.ids.server,
				clientId: "shared-wallet-client",
				expectedChallenge: "expected",
				replayStore: new MemoryReplayStore({ clock: f.clock }),
				acceptWallet: () => true,
			};
			t.true((await CredentialIssuerRole.authenticateWallet(jwt, pop, f.anchors, options)).ok);
			for (const change of [
				{ clientId: "different" },
				{ audience: "invalid-url" },
				{ maxProofAgeSeconds: -1 },
				{ clockSkewSeconds: -1 },
			])
				t.false(
					(
						await CredentialIssuerRole.authenticateWallet(jwt, pop, f.anchors, {
							...options,
							...change,
						})
					).ok,
				);
			const wrongKey = await token(
				{ ...proof(f), challenge: "expected" },
				f.protocol.verifier.privateKey,
				"oauth-client-attestation-pop+jwt",
			);
			t.false(
				(await CredentialIssuerRole.authenticateWallet(jwt, wrongKey, f.anchors, options)).ok,
			);
		});
		test("bounds stalled replay storage and rechecks expiry after storage completes", async (t) => {
			const f = await walletFederation();
			const jwt = await token(
				attestation(f),
				f.protocol.provider.privateKey,
				"oauth-client-attestation+jwt",
			);
			const pop = await token(
				proof(f),
				f.protocol.issuer.privateKey,
				"oauth-client-attestation-pop+jwt",
			);
			const options = { ...f.options, audience: f.ids.server, acceptWallet: () => true };
			t.false(
				(
					await CredentialIssuerRole.authenticateWallet(jwt, pop, f.anchors, {
						...options,
						httpTimeoutMs: 5,
						replayStore: { useJti: () => new Promise(() => {}) },
					})
				).ok,
			);
			t.false(
				(
					await CredentialIssuerRole.authenticateWallet(jwt, pop, f.anchors, {
						...options,
						replayStore: {
							useJti: async () => {
								f.setTime(1900);
								return true;
							},
						},
					})
				).ok,
			);
		});
		test("creates and verifies an attestation with separate protocol keys", async (t) => {
			const f = await walletFederation();
			const created = await WalletProviderRole.createWalletAttestation(
				f.ids.provider,
				{
					subject: "shared-wallet-client",
					confirmationKey: f.protocol.issuer.publicKey,
					expiresAt: 4000,
					claims: { wallet_name: "Example", custom: true },
				},
				new JwkSigner(f.protocol.provider.privateKey),
				f.options,
			);
			t.true(created.ok);
			if (!created.ok) return;
			const checked = await CredentialIssuerRole.verifyWalletAttestation(created.value, f.anchors, {
				...f.options,
				offline: true,
			});
			t.true(checked.ok, JSON.stringify(checked));
			if (checked.ok) {
				t.equal(checked.value.attestation.sub, "shared-wallet-client");
				t.true(checked.value.attestation.custom);
			}
		});
		test("accepts optional kid and absent PoP exp, then rejects replay atomically", async (t) => {
			const f = await walletFederation();
			const jwt = await token(
				attestation(f),
				f.protocol.provider.privateKey,
				"oauth-client-attestation+jwt",
			);
			const pop = await token(
				proof(f),
				f.protocol.issuer.privateKey,
				"oauth-client-attestation-pop+jwt",
			);
			const options = {
				...f.options,
				audience: f.ids.server,
				replayStore: new MemoryReplayStore({ clock: f.clock }),
				acceptWallet: () => true,
			};
			const results = await Promise.all([
				CredentialIssuerRole.authenticateWallet(jwt, pop, f.anchors, options),
				CredentialIssuerRole.authenticateWallet(jwt, pop, f.anchors, options),
			]);
			t.equal(results.filter((result) => result.ok).length, 1);
		});
		test("rejects malformed, expired, mistyped, and incorrectly signed attestations", async (t) => {
			const f = await walletFederation();
			for (const [claims, key, typ] of [
				[
					{ ...attestation(f), exp: 1400 },
					f.protocol.provider.privateKey,
					"oauth-client-attestation+jwt",
				],
				[
					{ ...attestation(f), nbf: 1700 },
					f.protocol.provider.privateKey,
					"oauth-client-attestation+jwt",
				],
				[
					{ ...attestation(f), cnf: { jwk: f.protocol.issuer.privateKey } },
					f.protocol.provider.privateKey,
					"oauth-client-attestation+jwt",
				],
				[attestation(f), f.keys.provider.privateKey, "oauth-client-attestation+jwt"],
				[attestation(f), f.protocol.provider.privateKey, "entity-statement+jwt"],
			] as const)
				t.false(
					(
						await CredentialIssuerRole.verifyWalletAttestation(
							await token(claims, key, typ),
							f.anchors,
							f.options,
						)
					).ok,
				);
			t.false(
				(await CredentialIssuerRole.verifyWalletAttestation("not-a-jwt", f.anchors, f.options)).ok,
			);
			const jwt = await token(
				attestation(f),
				f.protocol.provider.privateKey,
				"oauth-client-attestation+jwt",
			);
			t.false(
				(
					await CredentialIssuerRole.verifyWalletAttestation(jwt, f.anchors, {
						...f.options,
						maxResponseBytes: 10,
					})
				).ok,
			);
		});
		test("rejects bad PoP binding, audience, challenge, dates, and optional expiry", async (t) => {
			const f = await walletFederation();
			const jwt = await token(
				attestation(f),
				f.protocol.provider.privateKey,
				"oauth-client-attestation+jwt",
			);
			for (const change of [
				{ iss: "other" },
				{ aud: f.ids.issuer },
				{ iat: 1100 },
				{ iat: 1600 },
				{ iat: undefined },
				{ jti: undefined },
				{ exp: 1400 },
				{ nbf: 1800 },
				{ challenge: "wrong" },
			]) {
				const pop = await token(
					{ ...proof(f), challenge: "expected", ...change },
					f.protocol.issuer.privateKey,
					"oauth-client-attestation-pop+jwt",
				);
				t.false(
					(
						await CredentialIssuerRole.authenticateWallet(jwt, pop, f.anchors, {
							...f.options,
							audience: f.ids.server,
							expectedChallenge: "expected",
							replayStore: new MemoryReplayStore({ clock: f.clock }),
							acceptWallet: () => true,
						})
					).ok,
					JSON.stringify(change),
				);
			}
		});
		test("rejects verification-policy and replay-store failure without consuming invalid proofs", async (t) => {
			const f = await walletFederation();
			let claims = 0;
			const jwt = await token(
				attestation(f),
				f.protocol.provider.privateKey,
				"oauth-client-attestation+jwt",
			);
			const pop = await token(
				proof(f),
				f.protocol.issuer.privateKey,
				"oauth-client-attestation-pop+jwt",
			);
			const replayStore = {
				useJti: async () => {
					claims++;
					return true;
				},
			};
			t.false(
				(
					await CredentialIssuerRole.authenticateWallet(jwt, pop, f.anchors, {
						...f.options,
						audience: f.ids.server,
						replayStore,
						acceptWallet: () => false,
					})
				).ok,
			);
			t.equal(claims, 0);
			t.true(
				(
					await CredentialIssuerRole.authenticateWallet(jwt, pop, f.anchors, {
						...f.options,
						audience: f.ids.server,
						replayStore,
						acceptWallet: () => true,
					})
				).ok,
			);
			t.equal(claims, 1);
			t.false(
				(
					await CredentialIssuerRole.authenticateWallet(jwt, pop, f.anchors, {
						...f.options,
						audience: f.ids.server,
						replayStore: {
							useJti: async () => {
								throw new Error("unavailable");
							},
						},
						acceptWallet: () => true,
					})
				).ok,
			);
		});
		test("checks freshness again after framework policy and supports explicit window overrides", async (t) => {
			const f = await walletFederation();
			const jwt = await token(
				attestation(f),
				f.protocol.provider.privateKey,
				"oauth-client-attestation+jwt",
			);
			const pop = await token(
				{ ...proof(f), iat: 1200 },
				f.protocol.issuer.privateKey,
				"oauth-client-attestation-pop+jwt",
			);
			const options = {
				...f.options,
				audience: f.ids.server,
				replayStore: new MemoryReplayStore({ clock: f.clock }),
				acceptWallet: () => true,
			};
			t.false((await CredentialIssuerRole.authenticateWallet(jwt, pop, f.anchors, options)).ok);
			t.true(
				(
					await CredentialIssuerRole.authenticateWallet(jwt, pop, f.anchors, {
						...options,
						maxProofAgeSeconds: 301,
					})
				).ok,
			);
			const next = await token(
				{ ...proof(f), jti: "next" },
				f.protocol.issuer.privateKey,
				"oauth-client-attestation-pop+jwt",
			);
			t.false(
				(
					await CredentialIssuerRole.authenticateWallet(jwt, next, f.anchors, {
						...options,
						acceptWallet: () => {
							f.setTime(1800);
							return true;
						},
					})
				).ok,
			);
		});
	});
	module("wallet / federation-backed requests", () => {
		test("validates selected queries and scope mappings even when metadata supplies scenarios", async (t) => {
			for (const config of [
				{ verifierMetadata: { dcql_queries: [walletQuery] } },
				{ policy: { dcql_queries: { value: [walletQuery] } } },
			]) {
				const f = await walletFederation(config);
				let policies = 0;
				const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
					{ client_id: f.requestPayload.client_id },
					f.anchors,
					{
						...f.options,
						queryPolicy: () => {
							policies++;
							return true;
						},
					},
				);
				t.true(prepared.ok, JSON.stringify(prepared));
				if (!prepared.ok) continue;
				const sign = (changes: Record<string, unknown>) =>
					token(
						{ ...f.requestPayload, ...changes },
						f.protocol.verifier.privateKey,
						"oauth-authz-req+jwt",
					);
				for (const dcql_query of [{}, null, { credentials: [] }]) {
					t.false(
						(
							await CredentialVerifierRole.completeAuthorizationRequest(
								prepared.value,
								await sign({ dcql_query }),
							)
						).ok,
						JSON.stringify(dcql_query),
					);
				}
				const scoped = await sign({ dcql_query: undefined, scope: "identity_scope" });
				t.false(
					(await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, scoped)).ok,
				);
				t.equal(policies, 0, "Invalid active queries do not reach framework policy");
				t.true(
					(
						await CredentialVerifierRole.completeAuthorizationRequest(
							prepared.value,
							await sign({}),
						)
					).ok,
				);
				t.true(
					(
						await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, scoped, {
							scopeQuery: walletQuery,
						})
					).ok,
				);
				t.equal(policies, 2);
			}
		});
		test("binds transaction data to the active query without widening it to published scenarios", async (t) => {
			const { base64url } = await import("jose");
			const education = { credentials: [{ ...walletQuery.credentials[0]!, id: "education" }] };
			for (const superior of [false, true]) {
				const f = await walletFederation(
					superior
						? { verifierOverride: { dcql_queries: [walletQuery] } }
						: { verifierMetadata: { dcql_queries: [walletQuery, education] } },
				);
				let calls = 0;
				const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
					{ client_id: f.requestPayload.client_id },
					f.anchors,
					{
						...f.options,
						verifyTransactionData: ({ queries }) => {
							calls++;
							t.deepEqual(queries, superior ? [walletQuery] : [education]);
							return true;
						},
					},
				);
				t.true(prepared.ok);
				if (!prepared.ok) continue;
				for (const id of ["identity", "education"]) {
					const jwt = await token(
						{
							...f.requestPayload,
							dcql_query: superior ? "ignored" : education,
							transaction_data: [
								base64url.encode(JSON.stringify({ type: "payment", credential_ids: [id] })),
							],
						},
						f.protocol.verifier.privateKey,
						"oauth-authz-req+jwt",
					);
					const checked = await CredentialVerifierRole.completeAuthorizationRequest(
						prepared.value,
						jwt,
					);
					t.equal(
						checked.ok,
						id === (superior ? "identity" : "education"),
						`${superior ? "superior" : "leaf"}: ${id}`,
					);
				}
				t.equal(calls, 1, "Unrequested credential IDs never reach the callback");
			}
		});
		test("uses the mapped scope query for transaction binding even with published metadata", async (t) => {
			const { base64url } = await import("jose");
			const f = await walletFederation({ verifierMetadata: { dcql_queries: [walletQuery] } });
			const selected = { credentials: [{ ...walletQuery.credentials[0]!, id: "selected" }] };
			let calls = 0;
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				{
					...f.options,
					verifyTransactionData: ({ queries }) => {
						calls++;
						t.deepEqual(queries, [selected]);
						return true;
					},
				},
			);
			t.true(prepared.ok);
			if (!prepared.ok) return;
			const sign = (dcql_query: unknown, scope: string | undefined) =>
				token(
					{
						...f.requestPayload,
						dcql_query,
						scope,
						transaction_data: [
							base64url.encode(JSON.stringify({ type: "payment", credential_ids: ["selected"] })),
						],
					},
					f.protocol.verifier.privateKey,
					"oauth-authz-req+jwt",
				);
			const scoped = await sign(undefined, "identity_scope");
			t.false(
				(await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, scoped)).ok,
			);
			t.equal(calls, 0);
			t.true(
				(
					await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, scoped, {
						scopeQuery: selected,
					})
				).ok,
			);
			t.true(
				(
					await CredentialVerifierRole.completeAuthorizationRequest(
						prepared.value,
						await sign(selected, undefined),
					)
				).ok,
			);
			t.false(
				(
					await CredentialVerifierRole.completeAuthorizationRequest(
						prepared.value,
						await sign({}, undefined),
					)
				).ok,
			);
			t.equal(calls, 2);
		});
		test("rejects overflowing NumericDates while accepting finite fractional dates", async (t) => {
			const f = await walletFederation();
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				f.options,
			);
			if (!prepared.ok) {
				t.true(prepared.ok);
				return;
			}
			const payload = JSON.stringify(f.requestPayload).replace('"exp":2000', '"exp":1e309');
			const jwt = await new JwkSigner(f.protocol.verifier.privateKey).signJwt(
				new TextEncoder().encode(payload),
				{ typ: "oauth-authz-req+jwt", alg: "ES256" },
			);
			t.false((await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, jwt)).ok);
			const valid = await token(
				{ ...f.requestPayload, exp: 2000.5 },
				f.protocol.verifier.privateKey,
				"oauth-authz-req+jwt",
			);
			t.true((await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, valid)).ok);
		});
		test("keeps a leaf-published scenario list separate from the selected request query", async (t) => {
			const selected = { credentials: [{ ...walletQuery.credentials[0]!, id: "education" }] };
			const f = await walletFederation({
				verifierMetadata: { dcql_queries: [walletQuery, selected] },
			});
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				f.options,
			);
			if (!prepared.ok) {
				t.true(prepared.ok);
				return;
			}
			const jwt = await token(
				{ ...f.requestPayload, dcql_query: selected },
				f.protocol.verifier.privateKey,
				"oauth-authz-req+jwt",
			);
			const checked = await CredentialVerifierRole.completeAuthorizationRequest(
				prepared.value,
				jwt,
			);
			t.true(checked.ok, JSON.stringify(checked));
			if (!checked.ok) return;
			t.equal(checked.value.querySource, "verifier_metadata");
			t.deepEqual(checked.value.request.dcql_query, selected);
			t.deepEqual(checked.value.effectiveQueries, [walletQuery, selected]);
		});
		test("creates chain-carrying requests with contextual policy without weakening chain validation", async (t) => {
			const f = await walletFederation({ policy: { dcql_queries: { essential: true } } });
			const signer = new JwkSigner(f.protocol.verifier.privateKey);
			const options = {
				...f.options,
				trustChain: f.chains.get(f.ids.verifier)!,
				trustAnchors: f.anchors,
			};
			const request = { ...f.requestPayload, client_metadata: { dcql_query: walletQuery } };
			t.true(
				(
					await CredentialVerifierRole.createAuthorizationRequest(
						f.ids.verifier,
						request,
						signer,
						options,
					)
				).ok,
			);
			t.false(
				(
					await CredentialVerifierRole.createAuthorizationRequest(
						f.ids.verifier,
						f.requestPayload,
						signer,
						options,
					)
				).ok,
			);
			t.false(
				(
					await CredentialVerifierRole.createAuthorizationRequest(
						f.ids.verifier,
						{ ...request, client_metadata: { dcql_query: {} } },
						signer,
						options,
					)
				).ok,
			);
			t.false(
				(
					await CredentialVerifierRole.createAuthorizationRequest(f.ids.verifier, request, signer, {
						...f.options,
						trustChain: options.trustChain,
					})
				).ok,
			);
			t.false(
				(
					await CredentialVerifierRole.createAuthorizationRequest(f.ids.verifier, request, signer, {
						...options,
						trustChain: ["bad"],
					})
				).ok,
			);
			t.false(
				(
					await CredentialVerifierRole.createAuthorizationRequest(
						"http://bad.example",
						request,
						signer,
						options,
					)
				).ok,
			);
		});
		test("rejects incomplete verifier policy, invalid role metadata, and missing offline evidence during preparation", async (t) => {
			for (const config of [
				{ policy: { required_endpoint: { essential: true } } },
				{ verifierMetadata: { vp_formats_supported: undefined } },
			]) {
				const f = await walletFederation(config);
				t.false(
					(
						await CredentialVerifierRole.prepareAuthorizationRequest(
							{ client_id: f.requestPayload.client_id },
							f.anchors,
							f.options,
						)
					).ok,
				);
			}
			const f = await walletFederation();
			t.false(
				(
					await CredentialVerifierRole.prepareAuthorizationRequest(
						{ client_id: f.requestPayload.client_id },
						f.anchors,
						{ offline: true },
					)
				).ok,
			);
		});
		test("rejects malformed query creation and expiry during query authorization", async (t) => {
			const f = await walletFederation();
			const signer = new JwkSigner(f.protocol.verifier.privateKey);
			for (const change of [
				{ nonce: undefined },
				{ dcql_query: undefined },
				{ scope: "also" },
				{ dcql_query: {} },
			])
				t.false(
					(
						await CredentialVerifierRole.createAuthorizationRequest(
							f.ids.verifier,
							{ ...f.requestPayload, ...change },
							signer,
							f.options,
						)
					).ok,
				);
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				{
					...f.options,
					queryPolicy: () => {
						f.setTime(5000);
						return true;
					},
				},
			);
			if (!prepared.ok) {
				t.true(prepared.ok);
				return;
			}
			const jwt = await token(
				f.requestPayload,
				f.protocol.verifier.privateKey,
				"oauth-authz-req+jwt",
			);
			t.false((await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, jwt)).ok);
		});
		test("rejects invalid response parameters before signing and in independently signed requests", async (t) => {
			const f = await walletFederation();
			const signer = new JwkSigner(f.protocol.verifier.privateKey);
			let signatures = 0;
			let requests = 0;
			const countingSigner = {
				alg: signer.alg,
				kid: signer.kid,
				signJwt: (...args: Parameters<typeof signer.signJwt>) => {
					signatures++;
					return signer.signJwt(...args);
				},
			};
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				f.options,
			);
			t.true(prepared.ok);
			if (!prepared.ok) return;
			const invalid: [Record<string, unknown>, string][] = [];
			for (const field of ["response_uri", "redirect_uri"] as const) {
				for (const suffix of ["#fragment", "#", "?query=value#"]) {
					invalid.push([
						{
							response_uri: undefined,
							response_mode: field === "response_uri" ? "direct_post" : "fragment",
							[field]: `https://verifier.example/path${suffix}`,
						},
						`${field} must not contain a fragment`,
					]);
				}
				for (const userinfo of ["user:secret@", "@", ":@"]) {
					invalid.push([
						{
							response_uri: undefined,
							response_mode: field === "response_uri" ? "direct_post" : "fragment",
							[field]: `https://${userinfo}verifier.example/path`,
						},
						`${field} must be an HTTPS URL`,
					]);
				}
			}
			for (const mode of ["direct_post", "direct_post.jwt"]) {
				invalid.push([
					{ response_mode: mode, response_uri: undefined },
					`${mode} response mode requires response_uri`,
				]);
				for (const uri of ["", "not-a-url", "http://verifier.example/response"])
					invalid.push([
						{ response_mode: mode, response_uri: uri },
						"response_uri must be an HTTPS URL",
					]);
				invalid.push([
					{ response_mode: mode, redirect_uri: `${f.ids.verifier}/done`, response_uri: undefined },
					`${mode} requests cannot include redirect_uri`,
				]);
			}
			for (const mode of ["direct_post", "direct_post.jwt", "fragment", "custom"])
				invalid.push([
					{ response_mode: mode, redirect_uri: `${f.ids.verifier}/done` },
					"response_uri and redirect_uri cannot appear together",
				]);
			invalid.push([
				{ response_mode: "fragment", response_uri: undefined },
				"fragment response mode requires redirect_uri",
			]);
			for (const uri of ["", "not-a-url", "http://verifier.example/done"])
				invalid.push([
					{ response_mode: "fragment", response_uri: undefined, redirect_uri: uri },
					"redirect_uri must be an HTTPS URL",
				]);
			for (const [change, description] of invalid) {
				const payload = { ...f.requestPayload, ...change };
				for (const trustChain of [undefined, ["invalid chain must not be inspected"]]) {
					const created = await CredentialVerifierRole.createAuthorizationRequest(
						f.ids.verifier,
						payload,
						countingSigner,
						{
							...f.options,
							trustChain,
							trustAnchors: f.anchors,
							httpClient: async () => {
								requests++;
								throw new Error("Unexpected discovery");
							},
						},
					);
					t.false(created.ok, description);
					if (!created.ok) {
						t.equal(created.error.code, "invalid_request");
						t.equal(created.error.description, description);
					}
				}
				const jwt = await token(payload, f.protocol.verifier.privateKey, "oauth-authz-req+jwt");
				const checked = await CredentialVerifierRole.completeAuthorizationRequest(
					prepared.value,
					jwt,
				);
				t.false(checked.ok, description);
				if (!checked.ok) {
					t.equal(checked.error.code, "invalid_request");
					t.equal(checked.error.description, description);
				}
			}
			t.equal(signatures, 0, "invalid requests never reach the signer");
			t.equal(requests, 0, "invalid requests never trigger discovery");
		});

		test("response parameter checks preserve supported modes, exact endpoints, and later redirects", async (t) => {
			const f = await walletFederation();
			const signer = new JwkSigner(f.protocol.verifier.privateKey);
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				f.options,
			);
			t.true(prepared.ok);
			if (!prepared.ok) return;
			for (const change of [
				{},
				{ response_mode: "direct_post.jwt" },
				{
					response_mode: "fragment",
					response_uri: undefined,
					redirect_uri: `${f.ids.verifier}/done`,
				},
				{ response_mode: "custom", response_uri: undefined },
				{ response_mode: "custom" },
				{
					response_mode: "custom",
					response_uri: undefined,
					redirect_uri: `${f.ids.verifier}/done`,
				},
			]) {
				const payload = { ...f.requestPayload, ...change };
				const created = await CredentialVerifierRole.createAuthorizationRequest(
					f.ids.verifier,
					payload,
					signer,
					{
						clock: f.clock,
						httpClient: async () => {
							throw new Error("Unexpected discovery");
						},
					},
				);
				t.true(created.ok, JSON.stringify(change));
				if (!created.ok) continue;
				const checked = await CredentialVerifierRole.completeAuthorizationRequest(
					prepared.value,
					created.value,
				);
				t.true(checked.ok, JSON.stringify(checked));
				if (!checked.ok) continue;
				t.equal(checked.value.request.response_uri, payload.response_uri);
				t.equal(checked.value.request.redirect_uri, payload.redirect_uri);
				if (payload.response_mode.startsWith("direct_post")) {
					t.true(
						CredentialVerifierRole.validateResponseRedirect(checked.value, `${f.ids.verifier}/done`)
							.ok,
					);
					t.false(
						CredentialVerifierRole.validateResponseRedirect(
							checked.value,
							`${f.ids.verifier}/done/`,
						).ok,
					);
				}
			}
			for (const change of [
				{ response_uri: `${f.ids.verifier}/response/` },
				{
					response_mode: "fragment",
					response_uri: undefined,
					redirect_uri: `${f.ids.verifier}/done/`,
				},
			]) {
				const created = await CredentialVerifierRole.createAuthorizationRequest(
					f.ids.verifier,
					{ ...f.requestPayload, ...change },
					signer,
					f.options,
				);
				t.true(created.ok, "creation validates syntax without claiming endpoint authorization");
				if (!created.ok) continue;
				const checked = await CredentialVerifierRole.completeAuthorizationRequest(
					prepared.value,
					created.value,
				);
				t.false(checked.ok, "receiving wallet enforces the exact registered endpoint");
				if (!checked.ok) t.true(checked.error.description.includes("Endpoint is not registered"));
			}
		});

		test("preserves Request Object hashes and registered post-submission fragments", async (t) => {
			const requestUri = "https://verifier.example/request#content-hash";
			const redirectUri = "https://verifier.example/done#session";
			for (const responseUri of [
				"HTTPS://verifier.example/response",
				"https://verifier.example/@response%23part?email=a@b",
			]) {
				const f = await walletFederation({
					verifierMetadata: {
						request_uris: [requestUri],
						response_uris: [responseUri],
						redirect_uris: [redirectUri],
					},
				});
				const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
					{ client_id: f.requestPayload.client_id, request_uri: requestUri },
					f.anchors,
					f.options,
				);
				t.true(prepared.ok, JSON.stringify(prepared));
				if (!prepared.ok) continue;
				t.equal(prepared.value.requestUri, requestUri);
				const created = await CredentialVerifierRole.createAuthorizationRequest(
					f.ids.verifier,
					{ ...f.requestPayload, response_uri: responseUri },
					new JwkSigner(f.protocol.verifier.privateKey),
					f.options,
				);
				t.true(created.ok);
				if (!created.ok) continue;
				const checked = await CredentialVerifierRole.completeAuthorizationRequest(
					prepared.value,
					created.value,
				);
				t.true(checked.ok, JSON.stringify(checked));
				if (!checked.ok) continue;
				t.equal(checked.value.request.response_uri, responseUri);
				t.true(CredentialVerifierRole.validateResponseRedirect(checked.value, redirectUri).ok);
				t.false(
					CredentialVerifierRole.validateResponseRedirect(checked.value, `${redirectUri}-other`).ok,
				);
				const jwt = await token(
					{
						...f.requestPayload,
						response_mode: "fragment",
						response_uri: undefined,
						redirect_uri: redirectUri,
					},
					f.protocol.verifier.privateKey,
					"oauth-authz-req+jwt",
				);
				const invalid = await CredentialVerifierRole.completeAuthorizationRequest(
					prepared.value,
					jwt,
				);
				t.false(
					invalid.ok,
					"registration for a later redirect does not authorize a request fragment",
				);
				if (!invalid.ok)
					t.equal(invalid.error.description, "redirect_uri must not contain a fragment");
			}
		});

		test("validates endpoint URLs in effective superior metadata", async (t) => {
			for (const metadata of [
				{ response_uris: ["https://verifier.example/response#fragment"] },
				{ response_uris: ["https://verifier.example/response#"] },
				{ request_uris: ["https://@verifier.example/request"] },
				{ redirect_uris: ["https://user:secret@verifier.example/done"] },
			]) {
				const f = await walletFederation({ verifierOverride: metadata });
				const result = await CredentialVerifierRole.prepareAuthorizationRequest(
					{ client_id: f.requestPayload.client_id },
					f.anchors,
					f.options,
				);
				t.false(result.ok, "superior overrides receive endpoint validation");
				if (!result.ok) {
					t.equal(result.error.code, "ERR_TRUST_CHAIN_INVALID");
					t.true(result.error.description.includes(Object.keys(metadata)[0]!));
					t.true(/fragment|userinfo/.test(result.error.description));
					t.false(result.error.description.includes("secret"));
				}
			}
		});

		test("creates Request Objects and verifies supplied chains entirely offline", async (t) => {
			const f = await walletFederation();
			const created = await CredentialVerifierRole.createAuthorizationRequest(
				f.ids.verifier,
				f.requestPayload,
				new JwkSigner(f.protocol.verifier.privateKey),
				{
					clock: f.clock,
					trustChain: f.chains.get(f.ids.verifier),
					trustAnchors: f.anchors,
					offline: true,
				},
			);
			t.true(created.ok, JSON.stringify(created));
			if (!created.ok) return;
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id, request: created.value },
				f.anchors,
				{ clock: f.clock, offline: true },
			);
			t.true(prepared.ok, JSON.stringify(prepared));
			if (!prepared.ok) return;
			t.true(
				(await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, created.value))
					.ok,
			);
			t.false(
				(
					await CredentialVerifierRole.completeAuthorizationRequest(
						prepared.value,
						`${created.value}x`,
					)
				).ok,
			);
			t.equal(f.requests.length, 0);
		});
		test("supports dynamic wallet audience, fragment delivery, scope mapping, and query policy", async (t) => {
			const f = await walletFederation();
			const payload = {
				...f.requestPayload,
				response_mode: "fragment",
				redirect_uri: `${f.ids.verifier}/done`,
				response_uri: undefined,
				aud: "https://wallet.example",
				scope: "identity_scope",
				dcql_query: undefined,
			};
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				{
					...f.options,
					walletIssuer: "https://wallet.example",
					queryPolicy: ({ queries }) => queries[0]?.credentials[0]?.id === "identity",
				},
			);
			if (!prepared.ok) {
				t.true(prepared.ok);
				return;
			}
			const jwt = await token(payload, f.protocol.verifier.privateKey, "oauth-authz-req+jwt");
			t.false(
				(await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, jwt)).ok,
				"Scope requires the application's mapping",
			);
			t.true(
				(
					await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, jwt, {
						scopeQuery: walletQuery,
					})
				).ok,
			);
			const invalid = await token(
				{ ...payload, redirect_uri: undefined },
				f.protocol.verifier.privateKey,
				"oauth-authz-req+jwt",
			);
			t.false(
				(
					await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, invalid, {
						scopeQuery: walletQuery,
					})
				).ok,
			);
		});
		test("verifies transaction-data callbacks and rejects unbound or malformed values", async (t) => {
			const f = await walletFederation();
			const { base64url } = await import("jose");
			let calls = 0;
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				{
					...f.options,
					verifyTransactionData: ({ data }) => {
						calls++;
						return data[0]?.type === "payment";
					},
				},
			);
			if (!prepared.ok) {
				t.true(prepared.ok);
				return;
			}
			for (const [data, valid] of [
				[{ type: "payment", credential_ids: ["identity"] }, true],
				[{ type: "unsupported", credential_ids: ["identity"] }, false],
				[{ type: "payment", credential_ids: ["missing"] }, false],
			] as const) {
				const jwt = await token(
					{ ...f.requestPayload, transaction_data: [base64url.encode(JSON.stringify(data))] },
					f.protocol.verifier.privateKey,
					"oauth-authz-req+jwt",
				);
				t.equal(
					(await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, jwt)).ok,
					valid,
				);
			}
			for (const data of [[42], ["invalid-json"], []]) {
				const jwt = await token(
					{ ...f.requestPayload, transaction_data: data },
					f.protocol.verifier.privateKey,
					"oauth-authz-req+jwt",
				);
				t.false(
					(await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, jwt)).ok,
				);
			}
			t.equal(calls, 2, "Malformed or unbound data does not reach the verifier");
		});
		test("rejects altered expected nonce, invalid policy input, and expired response redirect evidence", async (t) => {
			const f = await walletFederation();
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				{ ...f.options, walletNonce: "expected" },
			);
			if (!prepared.ok) {
				t.true(prepared.ok);
				return;
			}
			const jwt = await token(
				{ ...f.requestPayload, wallet_nonce: "expected" },
				f.protocol.verifier.privateKey,
				"oauth-authz-req+jwt",
			);
			t.false(
				(
					await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, jwt, {
						walletNonce: "changed",
					})
				).ok,
			);
			const result = await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, jwt);
			t.true(result.ok);
			if (!result.ok) return;
			(result.value.verifierMetadata.redirect_uris as string[]).push("https://evil.example");
			t.false(
				CredentialVerifierRole.validateResponseRedirect(result.value, "https://evil.example").ok,
				"Returned data cannot change stored endpoint authority",
			);
			t.false(
				CredentialVerifierRole.validateResponseRedirect(
					{ ...result.value },
					`${f.ids.verifier}/done`,
				).ok,
			);
			f.setTime(5000);
			t.false(
				CredentialVerifierRole.validateResponseRedirect(result.value, `${f.ids.verifier}/done`).ok,
			);
		});
		test("prepares an endpoint and verifies a signed request without request metadata keys", async (t) => {
			const f = await walletFederation();
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{
					client_id: f.requestPayload.client_id,
					request_uri: `${f.ids.verifier}/request`,
					request_uri_method: "post",
				},
				f.anchors,
				f.options,
			);
			t.true(prepared.ok, JSON.stringify(prepared));
			if (!prepared.ok) return;
			const jwt = await token(
				{
					...f.requestPayload,
					iss: "ignored-issuer",
					wallet_nonce: "sent-nonce",
					client_metadata: { jwks: { keys: [f.keys.verifier.publicKey] } },
				},
				f.protocol.verifier.privateKey,
				"oauth-authz-req+jwt",
			);
			const checked = await CredentialVerifierRole.completeAuthorizationRequest(
				prepared.value,
				jwt,
				{ walletNonce: "sent-nonce" },
			);
			t.true(checked.ok, JSON.stringify(checked));
			if (checked.ok) {
				t.deepEqual(checked.value.effectiveQueries, [walletQuery]);
				t.notOk(checked.value.request.client_metadata);
				t.true(
					CredentialVerifierRole.validateResponseRedirect(checked.value, `${f.ids.verifier}/done`)
						.ok,
				);
				t.false(
					CredentialVerifierRole.validateResponseRedirect(checked.value, "https://evil.example").ok,
				);
			}
		});
		test("rejects unregistered endpoints before retrieval and malformed delivery", async (t) => {
			const f = await walletFederation();
			for (const input of [
				{ client_id: "unsupported:value" },
				{ client_id: f.requestPayload.client_id, request_uri: "https://evil.example/request" },
				{ client_id: f.requestPayload.client_id, request_uri_method: "post" as const },
				{
					client_id: f.requestPayload.client_id,
					request: "bad",
					request_uri: `${f.ids.verifier}/request`,
				},
			])
				t.false(
					(await CredentialVerifierRole.prepareAuthorizationRequest(input, f.anchors, f.options))
						.ok,
				);
			t.equal(f.requests.length, 0);
		});
		test("rejects Request Object type, key, audience, nonce, client, and endpoint substitution", async (t) => {
			const f = await walletFederation();
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				{ ...f.options, walletNonce: "expected" },
			);
			if (!prepared.ok) {
				t.true(prepared.ok);
				return;
			}
			for (const change of [
				{ client_id: `openid_federation:${f.ids.issuer}` },
				{ aud: f.ids.server },
				{ response_uri: "https://evil.example" },
				{ redirect_uri: `${f.ids.verifier}/done` },
				{ nonce: undefined },
				{ wallet_nonce: "wrong" },
				{ transaction_data: ["bad"] },
			]) {
				const jwt = await token(
					{ ...f.requestPayload, wallet_nonce: "expected", ...change },
					f.protocol.verifier.privateKey,
					"oauth-authz-req+jwt",
				);
				t.false(
					(await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, jwt)).ok,
					JSON.stringify(change),
				);
			}
			for (const [key, typ] of [
				[f.keys.verifier.privateKey, "oauth-authz-req+jwt"],
				[f.protocol.verifier.privateKey, "entity-statement+jwt"],
			] as const)
				t.false(
					(
						await CredentialVerifierRole.completeAuthorizationRequest(
							prepared.value,
							await token({ ...f.requestPayload, wallet_nonce: "expected" }, key, typ),
						)
					).ok,
				);
		});
		test("applies contextual DCQL policy only after signature verification", async (t) => {
			const f = await walletFederation({ policy: { dcql_queries: { essential: true } } });
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				f.options,
			);
			t.true(prepared.ok, JSON.stringify(prepared));
			if (!prepared.ok) return;
			const missing = await token(
				f.requestPayload,
				f.protocol.verifier.privateKey,
				"oauth-authz-req+jwt",
			);
			t.false(
				(await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, missing)).ok,
			);
			const jwt = await token(
				{
					...f.requestPayload,
					client_metadata: { dcql_query: walletQuery, jwks: { keys: [f.keys.verifier.publicKey] } },
				},
				f.protocol.verifier.privateKey,
				"oauth-authz-req+jwt",
			);
			const checked = await CredentialVerifierRole.completeAuthorizationRequest(
				prepared.value,
				jwt,
			);
			t.true(checked.ok, JSON.stringify(checked));
			if (checked.ok) t.deepEqual(checked.value.effectiveQueries, [walletQuery]);
		});
		test("superior overrides remove request query lists from callbacks and results", async (t) => {
			const f = await walletFederation({ verifierOverride: { dcql_queries: [walletQuery] } });
			const conflicting = [
				{
					credentials: [
						{
							id: "medical",
							format: "dc+sd-jwt",
							meta: { vct_values: ["https://example.com/medical"] },
						},
					],
				},
			];
			let calls = 0;
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				{
					...f.options,
					queryPolicy: ({ request, queries }) => {
						calls++;
						for (const field of ["dcql_query", "dcql_queries", "scope", "client_metadata"])
							t.false(Object.hasOwn(request, field), `callback omits ${field}`);
						t.deepEqual(queries, [walletQuery]);
						t.equal(request.example_extension, "retained");
						return true;
					},
				},
			);
			t.true(prepared.ok);
			if (!prepared.ok) return;
			for (const scoped of [false, true]) {
				for (const plural of [conflicting, "not-a-query-list", null, []]) {
					const jwt = await token(
						{
							...f.requestPayload,
							...(scoped ? { dcql_query: undefined, scope: "overridden_scope" } : {}),
							dcql_queries: plural,
							example_extension: "retained",
							client_metadata: { dcql_queries: conflicting },
						},
						f.protocol.verifier.privateKey,
						"oauth-authz-req+jwt",
					);
					const checked = await CredentialVerifierRole.completeAuthorizationRequest(
						prepared.value,
						jwt,
					);
					t.true(checked.ok, JSON.stringify(checked));
					if (!checked.ok) continue;
					t.equal(checked.value.querySource, "superior_metadata");
					t.deepEqual(checked.value.effectiveQueries, [walletQuery]);
					for (const field of ["dcql_query", "dcql_queries", "scope", "client_metadata"])
						t.false(Object.hasOwn(checked.value.request, field), `result omits ${field}`);
					t.equal(checked.value.request.example_extension, "retained");
				}
			}
			t.equal(calls, 8);
		});
		test("request query lists stay uninterpreted without a superior override", async (t) => {
			const conflicting = [
				{
					credentials: [
						{
							id: "medical",
							format: "dc+sd-jwt",
							meta: { vct_values: ["https://example.com/medical"] },
						},
					],
				},
			];
			for (const source of ["request", "verifier_metadata", "metadata_policy"] as const) {
				const f = await walletFederation(
					source === "request"
						? {}
						: source === "verifier_metadata"
							? { verifierMetadata: { dcql_queries: [walletQuery] } }
							: { policy: { dcql_queries: { value: [walletQuery] } } },
				);
				for (const plural of [conflicting, "not-a-query-list", null, []]) {
					let calls = 0;
					const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
						{ client_id: f.requestPayload.client_id },
						f.anchors,
						{
							...f.options,
							queryPolicy: ({ request, queries }) => {
								calls++;
								t.deepEqual(request.dcql_queries, plural);
								t.deepEqual(request.dcql_query, walletQuery);
								t.deepEqual(queries, [walletQuery]);
								return true;
							},
						},
					);
					t.true(prepared.ok);
					if (!prepared.ok) continue;
					const jwt = await token(
						{ ...f.requestPayload, dcql_queries: plural },
						f.protocol.verifier.privateKey,
						"oauth-authz-req+jwt",
					);
					const checked = await CredentialVerifierRole.completeAuthorizationRequest(
						prepared.value,
						jwt,
					);
					t.true(checked.ok, JSON.stringify(checked));
					if (!checked.ok) continue;
					t.equal(checked.value.querySource, source);
					t.deepEqual(checked.value.effectiveQueries, [walletQuery]);
					t.deepEqual(checked.value.request.dcql_queries, plural);
					t.deepEqual(checked.value.request.dcql_query, walletQuery);
					t.equal(calls, 1);
				}
			}
		});
		test("a plural query list cannot replace dcql_query or scope", async (t) => {
			for (const override of [false, true]) {
				const f = await walletFederation(
					override ? { verifierOverride: { dcql_queries: [walletQuery] } } : {},
				);
				let calls = 0;
				const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
					{ client_id: f.requestPayload.client_id },
					f.anchors,
					{
						...f.options,
						queryPolicy: () => {
							calls++;
							return true;
						},
					},
				);
				t.true(prepared.ok);
				if (!prepared.ok) continue;
				const jwt = await token(
					{ ...f.requestPayload, dcql_query: undefined, dcql_queries: [walletQuery] },
					f.protocol.verifier.privateKey,
					"oauth-authz-req+jwt",
				);
				const checked = await CredentialVerifierRole.completeAuthorizationRequest(
					prepared.value,
					jwt,
				);
				t.false(checked.ok);
				if (!checked.ok)
					t.equal(checked.error.description, "Exactly one DCQL query or scope is required");
				t.equal(calls, 0);
			}
		});
		test("superior DCQL metadata overrides even malformed request queries", async (t) => {
			const f = await walletFederation({ verifierOverride: { dcql_queries: [walletQuery] } });
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				f.options,
			);
			if (!prepared.ok) {
				t.true(prepared.ok, JSON.stringify(prepared));
				return;
			}
			const checked = await CredentialVerifierRole.completeAuthorizationRequest(
				prepared.value,
				await token(
					{ ...f.requestPayload, dcql_query: "ignored", client_metadata: { dcql_query: false } },
					f.protocol.verifier.privateKey,
					"oauth-authz-req+jwt",
				),
			);
			t.true(checked.ok, JSON.stringify(checked));
			if (checked.ok) t.deepEqual(checked.value.effectiveQueries, [walletQuery]);
		});
		test("superior query overrides do not require a scope mapping and cannot fall back after policy removal", async (t) => {
			const f = await walletFederation({
				verifierOverride: { dcql_queries: [walletQuery] },
				policy: { dcql_queries: { discard: true } },
			});
			const options = {
				...f.options,
				customPolicyOperators: [
					{
						name: "discard",
						order: 100,
						action: "modify" as const,
						apply: () => ({ ok: true as const, value: undefined, removed: true }),
						merge: (_existing: unknown, value: unknown) => ({ ok: true as const, value }),
						canCombineWith: () => true,
					},
				],
			};
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				options,
			);
			t.true(prepared.ok, JSON.stringify(prepared));
			if (prepared.ok) {
				const checked = await CredentialVerifierRole.completeAuthorizationRequest(
					prepared.value,
					await token(
						{ ...f.requestPayload, dcql_queries: [walletQuery] },
						f.protocol.verifier.privateKey,
						"oauth-authz-req+jwt",
					),
				);
				t.false(checked.ok);
				if (!checked.ok)
					t.equal(
						checked.error.description,
						"Superior DCQL metadata did not produce an effective query",
					);
			}
			const retained = await walletFederation({
				verifierOverride: { dcql_queries: [walletQuery] },
			});
			const withOverride = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: retained.requestPayload.client_id },
				retained.anchors,
				retained.options,
			);
			t.true(withOverride.ok);
			if (!withOverride.ok) return;
			const scoped = await token(
				{ ...retained.requestPayload, dcql_query: undefined, scope: "ignored_scope" },
				retained.protocol.verifier.privateKey,
				"oauth-authz-req+jwt",
			);
			const checked = await CredentialVerifierRole.completeAuthorizationRequest(
				withOverride.value,
				scoped,
			);
			t.true(checked.ok, JSON.stringify(checked));
			if (checked.ok) {
				t.deepEqual(checked.value.effectiveQueries, [walletQuery]);
				t.strictEqual(checked.value.request.scope, undefined);
			}
		});
		test("rejects fabricated or expired preparation and a failing framework query policy", async (t) => {
			const f = await walletFederation();
			t.false(
				(
					await CredentialVerifierRole.completeAuthorizationRequest(
						{} as PreparedAuthorizationRequest,
						"anything",
					)
				).ok,
			);
			const prepared = await CredentialVerifierRole.prepareAuthorizationRequest(
				{ client_id: f.requestPayload.client_id },
				f.anchors,
				{ ...f.options, queryPolicy: () => false },
			);
			if (!prepared.ok) {
				t.true(prepared.ok);
				return;
			}
			const jwt = await token(
				f.requestPayload,
				f.protocol.verifier.privateKey,
				"oauth-authz-req+jwt",
			);
			t.false((await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, jwt)).ok);
			f.setTime(5000);
			t.false((await CredentialVerifierRole.completeAuthorizationRequest(prepared.value, jwt)).ok);
		});
	});
};
