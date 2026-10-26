import type QUnit from "qunit";
import { type JWK, JwkSigner, MemoryReplayStore } from "../../../packages/core/src/index.js";
import {
	CredentialIssuerRole,
	CredentialVerifierRole,
	type PreparedAuthorizationRequest,
	WalletProviderRole,
} from "../../../packages/wallet/src/index.js";
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
	module("wallet / metadata", () => {
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
				{ redirect_uris: [] },
				{ response_uris: [] },
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
			t.throws(
				() =>
					WalletProviderRole.discover(f.ids.provider, f.anchors, {
						...f.options,
						maxTotalFetches: 0,
					}),
				/positive safe integer/,
			);
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
			if (prepared.ok)
				t.false(
					(
						await CredentialVerifierRole.completeAuthorizationRequest(
							prepared.value,
							await token(f.requestPayload, f.protocol.verifier.privateKey, "oauth-authz-req+jwt"),
						)
					).ok,
				);
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
