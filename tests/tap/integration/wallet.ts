import type QUnit from "qunit";
import {
	Intermediate,
	MemoryStorageAdapter,
	TrustAnchor,
} from "../../../packages/authority/src/index.js";
import {
	decodeEntityStatement,
	JwkSigner,
	MemoryFederationKeyProvider,
} from "../../../packages/core/src/index.js";
import { Leaf } from "../../../packages/leaf/src/index.js";
import {
	CredentialIssuerRole,
	CredentialVerifierRole,
	WalletProviderRole,
} from "../../../packages/wallet/src/index.js";
import { walletFederation } from "../fixtures/wallet.js";

export default (QUnit: QUnit) => {
	QUnit.module("Wallet role composition", () => {
		QUnit.test("instance attestation verification requires provider protocol keys", async (t) => {
			for (const published of [false, true]) {
				const f = await walletFederation(
					published ? {} : { providerMetadata: { jwks: undefined } },
				);
				for (const [Role, name] of [
					[CredentialIssuerRole, "issuer"],
					[CredentialVerifierRole, "verifier"],
				] as const) {
					const role = new Role({ trustAnchors: f.anchors });
					new Leaf({
						entityId: f.ids[name],
						authorityHints: [f.ids.anchor],
						keyProvider: MemoryFederationKeyProvider.fromJWK(f.keys[name].privateKey),
						metadata: f.metadata[name],
						roles: [role],
						options: f.options,
					});
					let calls = 0;
					const result = await role.verifyProviderAttestation("custom", f.ids.provider, {
						...f.options,
						offline: true,
						verifyAttestation: ({ keys }) => {
							calls++;
							t.deepEqual(keys.keys, [f.protocol.provider.publicKey]);
							return true;
						},
					});
					t.equal(result.ok, published);
					t.equal(calls, published ? 1 : 0);
					if (!result.ok) t.true(result.error.description.includes("Offline verification"));
				}
			}
		});
		QUnit.test(
			"instance operations use initialized host context and configured anchors",
			async (t) => {
				const f = await walletFederation();
				const provider = new WalletProviderRole({ trustAnchors: f.anchors });
				const issuer = new CredentialIssuerRole();
				const verifier = new CredentialVerifierRole();
				for (const [role, name] of [
					[provider, "provider"],
					[issuer, "issuer"],
					[verifier, "verifier"],
				] as const) {
					new Leaf({
						entityId: f.ids[name],
						authorityHints: [f.ids.anchor],
						keyProvider: MemoryFederationKeyProvider.fromJWK(f.keys[name].privateKey),
						metadata: f.metadata[name],
						roles: [role],
						trustAnchors: f.anchors,
						options: f.options,
					});
					t.true((await role.discover(f.ids[name], f.options)).ok);
				}
				for (const response_mode of ["direct_post", "direct_post.jwt", "fragment"]) {
					const invalid = await verifier.createAuthorizationRequest(
						{ ...f.requestPayload, response_mode, response_uri: undefined },
						new JwkSigner(f.protocol.verifier.privateKey),
					);
					t.false(invalid.ok, `${response_mode} requires its endpoint through instance APIs`);
					if (!invalid.ok) t.equal(invalid.error.code, "invalid_request");
				}
				const signed = await verifier.createAuthorizationRequest(
					f.requestPayload,
					new JwkSigner(f.protocol.verifier.privateKey),
				);
				t.true(signed.ok);
				if (!signed.ok) return;
				const prepared = await verifier.prepareAuthorizationRequest(
					{ client_id: f.requestPayload.client_id, request: signed.value },
					f.options,
				);
				t.true(prepared.ok);
				if (!prepared.ok) return;
				t.true((await verifier.completeAuthorizationRequest(prepared.value, signed.value)).ok);
				t.true(
					(
						await verifier.verifyCredential("credential", f.ids.issuer, {
							...f.options,
							verifyCredential: () => true,
						})
					).ok,
				);
				t.true(
					(
						await verifier.verifyProviderAttestation("attestation", f.ids.provider, {
							...f.options,
							verifyAttestation: () => true,
						})
					).ok,
				);
				const jwt = await provider.createWalletAttestation(
					{ subject: "wallet", confirmationKey: f.protocol.issuer.publicKey, expiresAt: 4000 },
					new JwkSigner(f.protocol.provider.privateKey),
				);
				t.true(jwt.ok);
				if (!jwt.ok) return;
				t.true((await issuer.verifyWalletAttestation(jwt.value, f.options)).ok);
				const proof = await new JwkSigner(f.protocol.issuer.privateKey).signJwt(
					new TextEncoder().encode(
						JSON.stringify({ iss: "wallet", aud: f.ids.server, iat: 1490, jti: "instance-proof" }),
					),
					{ alg: "ES256", typ: "oauth-client-attestation-pop+jwt" },
				);
				t.true(
					(
						await issuer.authenticateWallet(jwt.value, proof, {
							...f.options,
							audience: f.ids.server,
							replayStore: { useJti: async () => true },
							acceptWallet: () => true,
						})
					).ok,
				);
			},
		);
		QUnit.test("uninitialized instance methods require host identity or anchors", async (t) => {
			const f = await walletFederation();
			t.throws(
				() =>
					new WalletProviderRole().createWalletAttestation(
						{ subject: "wallet", confirmationKey: f.protocol.issuer.publicKey, expiresAt: 4000 },
						new JwkSigner(f.protocol.provider.privateKey),
					),
				/Attach the role/,
			);
			t.throws(
				() =>
					new CredentialVerifierRole().createAuthorizationRequest(
						f.requestPayload,
						new JwkSigner(f.protocol.verifier.privateKey),
					),
				/Attach the role/,
			);
			t.throws(() => new WalletProviderRole().discover(f.ids.provider), /Pinned trust anchors/);
		});
		for (const host of ["leaf", "intermediate", "anchor"] as const) {
			QUnit.test(
				`${host} publishes issuer and provider protocol keys without identifiers`,
				async (t) => {
					const f = await walletFederation();
					for (const [Role, name] of [
						[CredentialIssuerRole, "issuer"],
						[WalletProviderRole, "provider"],
					] as const) {
						const id = f.ids[name];
						const role = new Role();
						const publicKey = { ...f.protocol[name].publicKey };
						delete publicKey.kid;
						const metadata = { ...f.metadata[name][role.type], jwks: { keys: [publicKey] } };
						const config = {
							entityId: id,
							metadata: {
								...f.metadata[name],
								[role.type]: metadata,
								federation_entity:
									host === "leaf"
										? {}
										: {
												federation_fetch_endpoint: `${id}/fetch`,
												federation_list_endpoint: `${id}/list`,
											},
							},
							keyProvider: MemoryFederationKeyProvider.fromJWK(f.keys[name].privateKey),
							roles: [role],
							options: f.options,
						};
						const entity =
							host === "leaf"
								? new Leaf({ ...config, authorityHints: [f.ids.anchor] })
								: host === "anchor"
									? new TrustAnchor({ ...config, storage: new MemoryStorageAdapter() })
									: new Intermediate({
											...config,
											storage: new MemoryStorageAdapter(),
											authorityHints: [f.ids.anchor],
										});
						const decoded = decodeEntityStatement(await entity.getEntityConfiguration());
						t.true(decoded.ok);
						if (!decoded.ok) continue;
						t.deepEqual(decoded.value.payload.metadata?.[role.type], metadata);
						t.deepEqual(
							decoded.value.payload.jwks,
							{ keys: [f.keys[name].publicKey] },
							"federation key identifiers remain intact",
						);
					}
				},
			);
			for (const [Role, name] of [
				[WalletProviderRole, "provider"],
				[CredentialIssuerRole, "issuer"],
				[CredentialVerifierRole, "verifier"],
			] as const) {
				QUnit.test(`${host} publishes composed ${name} metadata`, async (t) => {
					const f = await walletFederation(
						name === "issuer"
							? {
									issuerMetadata: {
										credential_configurations_supported: {
											identity: {
												format: "mso_mdoc",
												doctype: "example.id",
												credential_metadata: {
													claims: [
														{ path: ["namespace", "element", -1] },
														{ path: ["namespace", "entries", null, "name"] },
													],
												},
											},
										},
									},
								}
							: name === "verifier"
								? {
										verifierMetadata: {
											dcql_queries: [
												{
													credentials: [
														{
															id: "identity",
															format: "dc+sd-jwt",
															meta: { vct_values: ["https://example.com/identity"] },
															claims: [{ path: ["names", null, "given"] }],
														},
													],
												},
											],
										},
									}
								: {},
					);
					const id = f.ids[name];
					const role = new Role();
					const keyProvider = MemoryFederationKeyProvider.fromJWK(f.keys[name].privateKey);
					const federationMetadata =
						host === "leaf"
							? {}
							: {
									federation_fetch_endpoint: `${id}/fetch`,
									federation_list_endpoint: `${id}/list`,
								};
					const config = {
						entityId: id,
						metadata: { federation_entity: federationMetadata, ...f.metadata[name] },
						keyProvider,
						roles: [role],
						trustAnchors: f.anchors,
						options: f.options,
					};
					const entity =
						host === "leaf"
							? new Leaf({ ...config, authorityHints: [f.ids.anchor] })
							: host === "anchor"
								? new TrustAnchor({ ...config, storage: new MemoryStorageAdapter() })
								: new Intermediate({
										...config,
										authorityHints: [f.ids.anchor],
										storage: new MemoryStorageAdapter(),
									});
					const decoded = decodeEntityStatement(await entity.getEntityConfiguration());
					t.true(decoded.ok);
					if (!decoded.ok) return;
					const metadata = decoded.value.payload.metadata?.[role.type];
					t.deepEqual(metadata, f.metadata[name][role.type]);
					if (role instanceof WalletProviderRole) {
						const signed = await role.createWalletAttestation(
							{
								subject: "wallet-client",
								confirmationKey: f.protocol.issuer.publicKey,
								expiresAt: 4000,
							},
							new JwkSigner(f.protocol.provider.privateKey),
						);
						t.true(signed.ok);
					}
				});
			}
			QUnit.test(`${host} rejects invalid wallet endpoint URLs`, async (t) => {
				const f = await walletFederation();
				for (const responseUri of [
					"https://verifier.example/response#",
					"https://verifier.example/response#part",
					"https://@verifier.example/response",
					"https://user:secret@verifier.example/response",
				]) {
					const config = {
						entityId: f.ids.verifier,
						metadata: {
							federation_entity:
								host === "leaf"
									? {}
									: {
											federation_fetch_endpoint: `${f.ids.verifier}/fetch`,
											federation_list_endpoint: `${f.ids.verifier}/list`,
										},
							openid_credential_verifier: {
								...f.metadata.verifier.openid_credential_verifier,
								response_uris: [responseUri],
							},
						},
						keyProvider: MemoryFederationKeyProvider.fromJWK(f.keys.verifier.privateKey),
						roles: [new CredentialVerifierRole()],
						options: f.options,
					};
					t.throws(
						() =>
							host === "leaf"
								? new Leaf({ ...config, authorityHints: [f.ids.anchor] })
								: host === "anchor"
									? new TrustAnchor({ ...config, storage: new MemoryStorageAdapter() })
									: new Intermediate({
											...config,
											authorityHints: [f.ids.anchor],
											storage: new MemoryStorageAdapter(),
										}),
						/response_uris/,
					);
				}
			});
			QUnit.test(`${host} rejects invalid host-supplied wallet metadata`, async (t) => {
				const f = await walletFederation();
				const federationMetadata =
					host === "leaf"
						? {}
						: {
								federation_fetch_endpoint: `${f.ids.issuer}/fetch`,
								federation_list_endpoint: `${f.ids.issuer}/list`,
							};
				const config = {
					entityId: f.ids.issuer,
					metadata: {
						federation_entity: federationMetadata,
						openid_credential_issuer: {
							...f.metadata.issuer.openid_credential_issuer,
							credential_issuer: "https://other.example",
						},
					},
					keyProvider: MemoryFederationKeyProvider.fromJWK(f.keys.issuer.privateKey),
					roles: [new CredentialIssuerRole()],
					options: f.options,
				};
				t.throws(
					() =>
						host === "leaf"
							? new Leaf({ ...config, authorityHints: [f.ids.anchor] })
							: host === "anchor"
								? new TrustAnchor({ ...config, storage: new MemoryStorageAdapter() })
								: new Intermediate({
										...config,
										authorityHints: [f.ids.anchor],
										storage: new MemoryStorageAdapter(),
									}),
					/credential_issuer/,
				);
			});
		}
		QUnit.test("role configuration overrides host metadata before validation", async (t) => {
			const f = await walletFederation();
			const role = new CredentialIssuerRole({
				metadata: f.metadata.issuer.openid_credential_issuer,
			});
			const entity = new Leaf({
				entityId: f.ids.issuer,
				authorityHints: [f.ids.anchor],
				keyProvider: MemoryFederationKeyProvider.fromJWK(f.keys.issuer.privateKey),
				metadata: { openid_credential_issuer: { credential_issuer: "wrong" } },
				roles: [role],
				options: f.options,
			});
			t.true(decodeEntityStatement(await entity.getEntityConfiguration()).ok);
			t.throws(
				() =>
					new Leaf({
						entityId: f.ids.issuer,
						authorityHints: [f.ids.anchor],
						keyProvider: MemoryFederationKeyProvider.fromJWK(f.keys.issuer.privateKey),
						metadata: {},
						roles: [role],
					}),
				/separate wallet role/,
			);
		});
	});
};
