import { type KeyringEntry, StaticKeyring } from "@oidfed/crypto";
import type QUnit from "qunit";
import {
	algorithmRegistry,
	createProfileEngine,
	profileAlgorithm,
	profileSigner,
} from "../../../../docs/examples/custom-crypto.js";
import * as C from "../../../../packages/core/src/index.js";
import { MemoryReplayStore } from "../../../../packages/core/src/storage/replay-memory.js";
import {
	OAuthAuthorizationServerRole,
	OAuthClientRole,
	OidcProviderRole,
	OidcRelyingPartyRole,
	type PushedAuthorizationProof,
} from "../../../../packages/oidc/src/index.js";
import { processAutomaticRegistration } from "../../../../packages/oidc/src/registration/automatic-server.js";
import { processPushedAuthorizationRequest } from "../../../../packages/oidc/src/registration/pushed.js";
import { replayStorage } from "../../../storage-fixtures.js";
import {
	FixtureCrypto,
	fixtureRoleContext,
	generateSigningKey,
	instrumentSigningEntry,
	PurposeBindingsFixture,
	SigningEntryFixture,
	testEngine,
} from "../../fixtures/software-crypto.js";
import { trustChainPaths } from "../../fixtures/trust-chain-paths.js";

async function fixture(
	oidc: boolean,
	settings: {
		profileEntry?: KeyringEntry;
		clientAssertionSigner?: (entry: KeyringEntry) => KeyringEntry;
		client?: Record<string, unknown>;
		server?: Record<string, unknown>;
		role?: Partial<ConstructorParameters<typeof OAuthAuthorizationServerRole>[0]> & {
			storage?: C.FederationStorage;
		};
	} = {},
) {
	const f = await trustChainPaths();
	const protocolEntry = settings.profileEntry ?? new SigningEntryFixture(f.keys.b.privateKey);
	const engine = settings.profileEntry ? createProfileEngine(testEngine) : testEngine;
	const profileOptions = settings.profileEntry
		? {
				algorithmRegistry,
				allowedAlgorithms: [profileAlgorithm],
			}
		: {};
	const clientType = oidc ? "openid_relying_party" : "oauth_client",
		serverType = oidc ? "openid_provider" : "oauth_authorization_server";
	const certificate = "aG9zdC12ZXJpZmllZC10bHMtY2VydGlmaWNhdGU=";
	const clientMetadata: Record<string, unknown> = {
		redirect_uris: [`${f.ids.subject}/callback`],
		client_registration_types: ["automatic"],
		jwks: settings.profileEntry?.publishedJwks ?? {
			keys: [{ ...f.keys.b.publicKey, x5c: [certificate] }],
		},
		token_endpoint_auth_methods_supported: [
			"private_key_jwt",
			"self_signed_tls_client_auth",
			"attest_jwt_client_auth",
		],
		...settings.client,
	};
	const serverMetadata: Record<string, unknown> = {
		issuer: f.ids.a,
		authorization_endpoint: `${f.ids.a}/authorize`,
		token_endpoint: `${f.ids.a}/token`,
		response_types_supported: ["code"],
		subject_types_supported: ["public"],
		id_token_signing_alg_values_supported: ["RS256"],
		jwks: { keys: [f.keys.a.publicKey] },
		client_registration_types_supported: ["automatic", "explicit"],
		federation_registration_endpoint: `${f.ids.a}/registration`,
		pushed_authorization_request_endpoint: `${f.ids.a}/par`,
		token_endpoint_auth_methods_supported: clientMetadata.token_endpoint_auth_methods_supported,
		client_attestation_signing_alg_values_supported: ["ES256"],
		client_attestation_pop_signing_alg_values_supported: ["ES256"],
		...settings.server,
	};
	const clientChain = await f.chain(["subject", "anchor"], {
		subjectClaims: { metadata: { [clientType]: clientMetadata } },
	});
	const serverChain = await f.chain(["a", "anchor"], {
		subjectClaims: { metadata: { [serverType]: serverMetadata } },
	});
	const docs = new Map([
		[`${f.ids.subject}/.well-known/openid-federation`, clientChain[0]!],
		[`${f.ids.a}/.well-known/openid-federation`, serverChain[0]!],
		[`${f.ids.anchor}/.well-known/openid-federation`, clientChain[2]!],
		[`${f.ids.anchor}/fetch?sub=${encodeURIComponent(f.ids.subject)}`, clientChain[1]!],
		[`${f.ids.anchor}/fetch?sub=${encodeURIComponent(f.ids.a)}`, serverChain[1]!],
	]);
	let now = 1500;
	const options: C.FederationOptions = {
		...f.options,
		...profileOptions,
		engine,
		clock: { now: () => now },
		httpClient: async (input) => {
			const url = new URL(input instanceof Request ? input.url : String(input));
			url.searchParams.delete("iss");
			const jwt = docs.get(url.href);
			return jwt
				? new Response(jwt, { headers: { "content-type": C.MediaType.EntityStatement } })
				: new Response("missing", { status: 404 });
		},
	};
	let registered = 0;
	const Server = oidc ? OidcProviderRole : OAuthAuthorizationServerRole;
	const {
		storage = replayStorage(new MemoryReplayStore({ engine: testEngine, clock: options.clock })),
		...rolePolicy
	} = settings.role ?? {};
	const server = new Server({
		metadata: serverMetadata,
		onRegistration: async () => {
			registered++;
		},
		...rolePolicy,
	});
	await server.initialize(
		fixtureRoleContext(server, {
			entityId: f.ids.a,
			storage,
			crypto: { ...FixtureCrypto.fromJWK(f.keys.a.privateKey), engine, ...profileOptions },
			trustAnchors: f.anchors,
			options,
		}),
	);
	const Client = oidc ? OidcRelyingPartyRole : OAuthClientRole;
	const client = new Client({
		metadata: clientMetadata,
		signing: new PurposeBindingsFixture({
			requestObjectSigner: protocolEntry,
			clientAssertionSigner: settings.clientAssertionSigner?.(protocolEntry),
		}),
	});
	await client.initialize(
		fixtureRoleContext(client, {
			entityId: f.ids.subject,
			authorityHints: [f.ids.anchor],
			crypto: { ...FixtureCrypto.fromJWK(f.keys.subject.privateKey), engine, ...profileOptions },
			trustAnchors: f.anchors,
			options,
		}),
	);
	const discovery = await C.discoverEntity(f.ids.a, f.anchors, options);
	if (!discovery.ok) throw new Error(discovery.error.description);
	return {
		...f,
		client,
		server,
		discovery: discovery.value,
		options,
		certificate,
		registered: () => registered,
		serverMetadata,
		clientChain,
		protocolEntry,
		setNow: (value: number) => {
			now = value;
		},
	};
}
async function signedRequest(
	f: Awaited<ReturnType<typeof fixture>>,
	claims: Record<string, unknown> = {},
): Promise<Request> {
	const signed = await C.signApplicationJwt(
		{
			iss: f.ids.subject,
			client_id: f.ids.subject,
			aud: f.ids.a,
			iat: 1500,
			exp: 3000,
			jti: globalThis.crypto.randomUUID(),
			response_type: "code",
			redirect_uri: `${f.ids.subject}/callback`,
			...claims,
		},
		"oauth-authz-req+jwt",
		f.protocolEntry,
		f.options,
		f.clientChain,
	);
	if (!signed.ok) throw new Error(signed.error.description);
	return new Request(`${f.ids.a}/par`, {
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ client_id: f.ids.subject, request: signed.value }),
	});
}
async function assertionRequest(f: Awaited<ReturnType<typeof fixture>>): Promise<Request> {
	return new Request(`${f.ids.a}/par`, {
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			client_id: f.ids.subject,
			response_type: "code",
			redirect_uri: `${f.ids.subject}/callback`,
			client_assertion_type: C.JWT_BEARER_CLIENT_ASSERTION_TYPE,
			client_assertion: await C.createClientAssertion(
				f.ids.subject,
				f.ids.a,
				f.protocolEntry,
				f.options,
			),
		}),
	});
}
export default (Q: QUnit) => {
	Q.module("oidc / pushed authorization proof modes", () => {
		Q.test(
			"adapters see the same effective client metadata on every registration path",
			async (t) => {
				for (const oidc of [true, false]) {
					const clientType = oidc ? "openid_relying_party" : "oauth_client";
					const seen: string[] = [];
					let reject = false;
					const f = await fixture(oidc, {
						client: {
							token_endpoint_auth_method: "private_key_jwt",
							client_registration_types: ["automatic", "explicit"],
						},
						role: {
							registrationProtocolAdapter: {
								validateClientMetadata(metadata, context) {
									t.equal(context.clientMetadataType, clientType);
									t.deepEqual(metadata[clientType]?.redirect_uris, [`${f.ids.subject}/callback`]);
									seen.push(context.flow);
									return reject
										? C.err({
												code: C.FederationErrorCode.InvalidMetadata,
												description: "Rejected by host",
											})
										: C.ok(undefined);
								},
								enrichResponseMetadata(metadata, _chain, context) {
									t.equal(context.flow, "explicit");
									return {
										...metadata,
										[clientType]: { ...metadata[clientType], registration_profile: "test" },
									};
								},
							},
						},
					});
					const [ec, ...superiors] = f.clientChain;
					if (!ec) throw new Error("Missing client configuration");
					const decoded = C.decodeEntityStatement(ec);
					if (!decoded.ok) throw new Error(decoded.error.description);
					const explicitJwt = await C.signEntityStatement(
						{ ...decoded.value.payload, aud: f.ids.a },
						new SigningEntryFixture(f.keys.subject.privateKey),
						{ typ: C.JwtTyp.EntityStatement },
					);
					const explicit = () =>
						f.server.processExplicitRegistration(
							new Request(`${f.ids.a}/registration`, {
								method: "POST",
								headers: { "content-type": C.MediaType.TrustChain },
								body: JSON.stringify([explicitJwt, ...superiors]),
							}),
						);
					const automatic = async () => {
						const form = new URLSearchParams(await (await signedRequest(f)).text());
						return f.server.processAutomaticRegistration(form.get("request")!);
					};
					const par = async () =>
						f.server.processPushedAuthorizationRequest(await signedRequest(f));

					const response = await explicit();
					const responseBody = await response.text();
					t.equal(
						response.status,
						200,
						response.status === 200 ? "Explicit registration succeeds" : responseBody,
					);
					const responseJwt = C.decodeEntityStatement(responseBody);
					t.true(responseJwt.ok);
					if (responseJwt.ok) {
						t.equal(responseJwt.value.payload.metadata?.[clientType]?.client_id, f.ids.subject);
						t.equal(responseJwt.value.payload.metadata?.[clientType]?.registration_profile, "test");
					}
					t.true((await automatic()).ok);
					t.true((await par()).ok);
					t.deepEqual(seen, ["explicit", "automatic", "par"]);
					t.equal(f.registered(), 3);
					reject = true;
					t.equal((await explicit()).status, 400);
					t.false((await automatic()).ok);
					t.false((await par()).ok);
					t.equal(f.registered(), 3);
				}
			},
		);
		Q.test(
			"registered protocol algorithms work in OIDC registration and PAR independently of federation policy",
			async (t) => {
				const p256 = new SigningEntryFixture((await generateSigningKey()).privateKey);
				const profile = profileSigner("oidc-profile", p256.signer);
				const profileEntry = await new StaticKeyring({
					algorithmRegistry,
					signers: { protocol: profile },
				}).entry("protocol");
				const f = await fixture(true, {
					profileEntry,
					server: {
						request_object_signing_alg_values_supported: [profileAlgorithm],
						token_endpoint_auth_signing_alg_values_supported: [profileAlgorithm],
					},
				});
				const request = await signedRequest(f);
				const form = new URLSearchParams(await request.clone().text());
				const automatic = await f.server.processAutomaticRegistration(form.get("request")!);
				t.true(
					automatic.ok,
					automatic.ok ? "registered Request Object" : automatic.error.description,
				);
				const assertion = await f.server.processPushedAuthorizationRequest(
					await assertionRequest(f),
				);
				t.true(
					assertion.ok,
					assertion.ok ? "registered client assertion" : assertion.error.description,
				);
			},
		);
		Q.test(
			"automatic PAR uses the signed Request Object when the provider excludes the assertion algorithm",
			async (t) => {
				for (const oidc of [false, true]) {
					for (const advertised of [undefined, ["ES256"], ["RS256"]]) {
						const f = await fixture(oidc, {
							server: advertised
								? { token_endpoint_auth_signing_alg_values_supported: advertised }
								: {},
						});
						const useAssertion = advertised?.includes("ES256") ?? true;
						const params = {
							response_type: "code",
							redirect_uri: `${f.ids.subject}/callback`,
							...(oidc ? { scope: "openid" } : {}),
						};
						let posts = 0;
						const httpClient: C.HttpClient = async (input, init) => {
							const request = new Request(input, init);
							if (request.url !== `${f.ids.a}/par`) return f.options.httpClient!(input, init);
							posts++;
							const form = new URLSearchParams(await request.clone().text());
							t.true(form.has("request"));
							t.equal(form.has("client_assertion"), useAssertion);
							t.equal(form.has("client_assertion_type"), useAssertion);
							const processed = await f.server.processPushedAuthorizationRequest(request);
							t.true(
								processed.ok,
								processed.ok ? "receiver accepts the request" : processed.error.description,
							);
							return Response.json(
								{ request_uri: "urn:example:par", expires_in: 60 },
								{ status: 201 },
							);
						};
						const explicit = await f.client.createPushedAuthorizationRequest(
							f.discovery,
							params,
							{ mode: "private_key_jwt" },
							{ httpClient },
						);
						t.equal(explicit.ok, useAssertion);
						if (!explicit.ok)
							t.equal(
								explicit.error.description,
								"Server does not support the client assertion algorithm",
							);
						t.equal(posts, 0);
						const automatic = await f.client.createAuthorizationRequest(
							f.discovery,
							params,
							f.anchors,
							{ requestDelivery: "par", httpClient },
						);
						t.true(automatic.ok, automatic.ok ? "PAR completed" : automatic.error.description);
						t.equal(posts, 1);
					}
				}
			},
		);

		Q.test("automatic PAR surfaces assertion signing failures before posting", async (t) => {
			let calls = 0;
			const f = await fixture(false, {
				server: { token_endpoint_auth_signing_alg_values_supported: ["ES256"] },
				clientAssertionSigner: (entry) =>
					instrumentSigningEntry(entry, async () => {
						calls++;
						throw new Error("signing failed");
					}),
			});
			let posts = 0;
			const result = await f.client.createAuthorizationRequest(
				f.discovery,
				{ response_type: "code", redirect_uri: `${f.ids.subject}/callback` },
				f.anchors,
				{
					requestDelivery: "par",
					httpClient: async (input, init) => {
						const url = new Request(input, init).url;
						if (url !== `${f.ids.a}/par`) return f.options.httpClient!(input, init);
						posts++;
						return new Response(null, { status: 500 });
					},
				},
			);
			t.false(result.ok);
			if (!result.ok) t.equal(result.error.code, C.FederationErrorCode.ServerError);
			t.equal(calls, 1);
			t.equal(posts, 0);
		});

		Q.test(
			"Request Object and assertion algorithms must satisfy both local and published policy",
			async (t) => {
				const f = await fixture(false, {
					server: { request_object_signing_alg_values_supported: ["RS256"] },
				});
				const request = await signedRequest(f);
				const form = new URLSearchParams(await request.text());
				const rejected = await f.server.processAutomaticRegistration(form.get("request")!, {
					allowedAlgorithms: ["ES256", "RS256"],
				});
				t.false(rejected.ok);
				t.equal(f.registered(), 0);

				const protocol = await generateSigningKey("ES384");
				const par = await fixture(false, {
					client: { jwks: { keys: [protocol.publicKey] } },
					server: { token_endpoint_auth_signing_alg_values_supported: ["ES384", "ES256"] },
				});
				const assertion = await C.createClientAssertion(
					par.ids.subject,
					par.ids.a,
					new SigningEntryFixture(protocol.privateKey),
					par.options,
				);
				const params = new URLSearchParams(await (await assertionRequest(par)).text());
				params.set("client_assertion", assertion);
				const submit = (allowedAlgorithms: string[]) =>
					par.server.processPushedAuthorizationRequest(
						new Request(`${par.ids.a}/par`, {
							method: "POST",
							headers: { "content-type": "application/x-www-form-urlencoded" },
							body: params,
						}),
						{ allowedAlgorithms },
					);
				t.false((await submit(["ES256"])).ok);
				t.equal(par.registered(), 0);
				const accepted = await submit(["ES256", "ES384"]);
				t.true(accepted.ok, accepted.ok ? "both policies allow ES384" : accepted.error.description);
			},
		);
		Q.test(
			"OIDC and OAuth typing policies apply to authorization and PAR without consuming rejected proofs",
			async (t) => {
				for (const oidc of [false, true]) {
					const f = await fixture(oidc, { role: { requestObjectTyping: "compatible" } });
					for (const delivery of ["authorization", "par"] as const) {
						for (const typ of ["JWT", undefined]) {
							const original = await signedRequest(f);
							const form = new URLSearchParams(await original.text());
							const decoded = C.decodeEntityStatement(form.get("request")!);
							if (!decoded.ok) throw new Error("fixture");
							const jwt = await new SigningEntryFixture(f.keys.b.privateKey).signJwt(
								new TextEncoder().encode(JSON.stringify(decoded.value.payload)),
								{ ...decoded.value.header, typ },
							);
							const run = (requestObjectTyping?: "strict" | "compatible") => {
								const options = requestObjectTyping ? { requestObjectTyping } : {};
								return delivery === "authorization"
									? f.server.processAutomaticRegistration(jwt, options)
									: f.server.processPushedAuthorizationRequest(
											new Request(`${f.ids.a}/par`, {
												method: "POST",
												headers: { "content-type": "application/x-www-form-urlencoded" },
												body: new URLSearchParams({ client_id: f.ids.subject, request: jwt }),
											}),
											options,
										);
							};
							const before = f.registered();
							t.false((await run("strict")).ok, "per-call strict overrides compatible role policy");
							t.equal(f.registered(), before, "rejected policy has no persistence side effect");
							t.true((await run()).ok, "the same proof works under configured compatibility");
							t.false((await run()).ok, "compatibility retains one-time replay enforcement");
						}
					}
					const strict = await fixture(oidc);
					const original = await signedRequest(strict);
					const decoded = C.decodeEntityStatement(
						new URLSearchParams(await original.text()).get("request")!,
					);
					if (!decoded.ok) throw new Error("fixture");
					const jwt = await new SigningEntryFixture(strict.keys.b.privateKey).signJwt(
						new TextEncoder().encode(JSON.stringify(decoded.value.payload)),
						{ ...decoded.value.header, typ: "JWT" },
					);
					t.false(
						(await strict.server.processAutomaticRegistration(jwt)).ok,
						"default role policy remains strict",
					);
					t.true(
						(
							await strict.server.processAutomaticRegistration(jwt, {
								requestObjectTyping: "compatible",
							})
						).ok,
						"per-call compatibility is available without configuring the role",
					);
				}
			},
		);
		Q.test(
			"PAR retains JSON claims and repeated resource parameters for both profiles",
			async (t) => {
				for (const oidc of [false, true]) {
					const f = await fixture(oidc);
					const parameters = {
						...JSON.parse('{"__proto__":{"safe":true},"constructor":{"extension":true}}'),
						response_type: "code",
						redirect_uri: `${f.ids.subject}/callback`,
						max_age: 0,
						claims: { id_token: { email: { essential: true } } },
						authorization_details: [{ type: "example" }],
						resource: ["https://api.example/one", "urn:example:two"],
					};
					for (const mode of ["request_object", "private_key_jwt"] as const) {
						const prepared = await f.client.createPushedAuthorizationRequest(
							f.discovery,
							parameters,
							{ mode },
						);
						t.true(prepared.ok, JSON.stringify(prepared));
						if (!prepared.ok) continue;
						t.true(prepared.value.parameters instanceof URLSearchParams);
						if (mode === "private_key_jwt")
							t.deepEqual(prepared.value.parameters.getAll("resource"), parameters.resource);
						const result = await f.server.processPushedAuthorizationRequest(
							new Request(prepared.value.endpoint, {
								method: "POST",
								headers: prepared.value.headers,
								body: prepared.value.parameters,
							}),
						);
						t.true(result.ok, JSON.stringify(result));
						if (!result.ok) continue;
						t.deepEqual(result.value.parameters.resource, parameters.resource);
						t.deepEqual(
							result.value.parameters.claims,
							mode === "request_object" ? parameters.claims : JSON.stringify(parameters.claims),
						);
						t.strictEqual(result.value.parameters.max_age, mode === "request_object" ? 0 : "0");
						t.true(Object.hasOwn(result.value.parameters, "__proto__"));
						t.equal(Object.getPrototypeOf(result.value.parameters), Object.prototype);
						t.equal(result.value.authenticationExpiresAt, mode === "request_object" ? 1800 : 1560);
					}
					for (const bad of [
						{ resource: ["https://api.example/#fragment"] },
						{ resource: [] },
						{ number: NaN },
						{ object: new Date() },
						{ request_uri: "https://request.example" },
					])
						t.false(
							(
								await f.client.createPushedAuthorizationRequest(f.discovery, bad, {
									mode: "request_object",
								})
							).ok,
						);
					const cyclic: Record<string, unknown> = {};
					cyclic.self = cyclic;
					t.false(
						(
							await f.client.createPushedAuthorizationRequest(f.discovery, cyclic, {
								mode: "request_object",
							})
						).ok,
					);
				}
			},
		);
		Q.test(
			"effective client and server policies require signed PAR without disabling permitted alternatives",
			async (t) => {
				for (const oidc of [false, true])
					for (const location of ["client", "server"] as const) {
						const f = await fixture(oidc, { [location]: { require_signed_request_object: true } });
						for (const proof of [
							{ mode: "private_key_jwt" } as const,
							{ mode: "self_signed_tls_client_auth", certificate: f.certificate } as const,
						])
							t.false((await f.client.createPushedAuthorizationRequest(f.discovery, {}, proof)).ok);
						t.false(
							(await f.server.processPushedAuthorizationRequest(await assertionRequest(f))).ok,
						);
						const unsigned = new Request(`${f.ids.a}/par`, {
							method: "POST",
							headers: { "content-type": "application/x-www-form-urlencoded" },
							body: new URLSearchParams({ client_id: f.ids.subject, response_type: "code" }),
						});
						t.false(
							(
								await f.server.processPushedAuthorizationRequest(unsigned, {
									clientCertificate: () => f.certificate,
								})
							).ok,
						);
						t.equal(f.registered(), 0);
						t.true((await f.server.processPushedAuthorizationRequest(await signedRequest(f))).ok);
						t.equal(f.registered(), 1);
					}
			},
		);
		Q.test(
			"Request Object algorithm declarations constrain producers and both receiving paths",
			async (t) => {
				for (const oidc of [false, true])
					for (const location of ["client", "server"] as const) {
						const f = await fixture(oidc, {
							[location]:
								location === "client"
									? { request_object_signing_alg: "RS256" }
									: { request_object_signing_alg_values_supported: ["RS256"] },
						});
						t.false(
							(
								await f.client.createPushedAuthorizationRequest(
									f.discovery,
									{},
									{ mode: "request_object" },
								)
							).ok,
						);
						const request = await signedRequest(f);
						const form = new URLSearchParams(await request.clone().text());
						t.false((await f.server.processAutomaticRegistration(form.get("request")!)).ok);
						t.false((await f.server.processPushedAuthorizationRequest(request)).ok);
						t.equal(f.registered(), 0);
					}
				const f = await fixture(false, {
					client: { request_object_signing_alg: "ES256" },
					server: { request_object_signing_alg_values_supported: ["ES256"] },
				});
				t.true((await f.server.processPushedAuthorizationRequest(await signedRequest(f))).ok);
			},
		);
		Q.test("forbidden PAR parameters fail before claiming replay state", async (t) => {
			let claims = 0;
			const f = await fixture(false, {
				role: {
					storage: replayStorage({
						useJti: async () => {
							claims++;
							return true;
						},
					}),
				},
			});
			for (const name of ["request", "request_uri"]) {
				const request = await signedRequest(f, { [name]: "https://nested.example" });
				const form = new URLSearchParams(await request.clone().text());
				t.false((await f.server.processAutomaticRegistration(form.get("request")!)).ok);
				t.false((await f.server.processPushedAuthorizationRequest(request)).ok);
			}
			for (const [name, value] of [
				["scope", "example"],
				["client_id", f.ids.subject],
				["client_assertion_type", C.JWT_BEARER_CLIENT_ASSERTION_TYPE],
			]) {
				const original = await signedRequest(f, { scope: "example" });
				const body = new URLSearchParams(await original.text());
				if (name === "client_assertion_type") body.append(name!, value!);
				body.append(name!, value!);
				t.false(
					(
						await f.server.processPushedAuthorizationRequest(
							new Request(original.url, { method: "POST", headers: original.headers, body }),
						)
					).ok,
				);
			}
			t.false(
				(
					await f.server.processPushedAuthorizationRequest(
						await signedRequest(f, { redirect_uri: "https://wrong.example" }),
					)
				).ok,
			);
			t.equal(claims, 0);
			t.equal(f.registered(), 0);
			t.true((await f.server.processPushedAuthorizationRequest(await signedRequest(f))).ok);
			t.equal(claims, 1);
		});
		Q.test("authentication expiry is rechecked after policy replay and adapter work", async (t) => {
			for (const stage of ["policy", "replay", "adapter"] as const) {
				let advance = () => {};
				const f = await fixture(false, {
					role: {
						beforeRegistration: async () => {
							if (stage === "policy") advance();
							return C.ok(undefined);
						},
						storage: replayStorage({
							useJti: async () => {
								if (stage === "replay") advance();
								return true;
							},
						}),
						registrationProtocolAdapter: {
							validateClientMetadata: () => {
								if (stage === "adapter") advance();
								return C.ok(undefined);
							},
						},
					},
				});
				advance = () => f.setNow(1502);
				const result = await f.server.processPushedAuthorizationRequest(
					await signedRequest(f, { exp: 1501 }),
				);
				t.false(result.ok, stage);
				t.equal(f.registered(), 0);
				f.setNow(1500);
				advance = () => {};
				t.true(
					(await f.server.processPushedAuthorizationRequest(await signedRequest(f, { exp: 1501 })))
						.ok,
				);
				t.equal(f.registered(), 1);
			}
		});
		Q.test(
			"pending replay and policy callbacks respect deadlines and observe late rejection",
			async (t) => {
				for (const stage of ["replay", "policy"] as const) {
					let reject: (reason: Error) => void = () => {};
					const pending = new Promise<never>((_, no) => {
						reject = no;
					});
					const f = await fixture(false, {
						role:
							stage === "replay"
								? { storage: replayStorage({ useJti: () => pending }) }
								: { beforeRegistration: () => pending },
					});
					const request = await signedRequest(f);
					let timer: ReturnType<typeof setTimeout> | undefined;
					const result = await Promise.race([
						f.server.processPushedAuthorizationRequest(request, { httpTimeoutMs: 100 }),
						new Promise<undefined>((resolve) => {
							timer = setTimeout(() => resolve(undefined), 1500);
						}),
					]);
					clearTimeout(timer);
					t.ok(result, "settled without waiting for the host");
					if (result) t.false(result.ok);
					t.equal(f.registered(), 0);
					reject(new Error("late rejection"));
					await Promise.resolve();
				}
			},
		);

		Q.test(
			"both registration profiles accept signed requests, private-key assertions and host-verified TLS",
			async (t) => {
				for (const oidc of [true, false]) {
					const f = await fixture(oidc);
					for (const mode of [
						"request_object",
						"private_key_jwt",
						"self_signed_tls_client_auth",
					] as const) {
						const proof: PushedAuthorizationProof =
							mode === "self_signed_tls_client_auth"
								? { mode, certificate: f.certificate }
								: { mode };
						const prepared = await f.client.createPushedAuthorizationRequest(
							f.discovery,
							{
								redirect_uri: `${f.ids.subject}/callback`,
								response_type: "code",
								...(oidc ? { scope: "openid" } : {}),
							},
							proof,
						);
						t.true(prepared.ok, JSON.stringify(prepared));
						if (!prepared.ok) continue;
						t.equal(
							typeof prepared.value.requestObjectJwt,
							mode === "request_object" ? "string" : "undefined",
						);
						const request = () =>
							new Request(prepared.value.endpoint, {
								method: "POST",
								headers: prepared.value.headers,
								body: new URLSearchParams(prepared.value.parameters),
							});
						const standalone = await processPushedAuthorizationRequest(request(), f.anchors, {
							...f.options,
							storage: undefined,
							opEntityId: f.ids.a,
							providerMetadataType: oidc ? "openid_provider" : "oauth_authorization_server",
							providerMetadata: f.serverMetadata,
							...(mode === "self_signed_tls_client_auth"
								? { clientCertificate: () => f.certificate }
								: {}),
						});
						t.equal(standalone.ok, mode === "self_signed_tls_client_auth", `storage-free ${mode}`);
						if (!standalone.ok) t.equal(standalone.error.code, C.FederationErrorCode.ServerError);
						if (prepared.value.requestObjectJwt) {
							const absent = await processAutomaticRegistration(
								prepared.value.requestObjectJwt,
								f.anchors,
								{
									...f.options,
									opEntityId: f.ids.a,
									// @ts-expect-error Standalone callers must supply replay storage.
									storage: undefined,
								},
							);
							t.false(absent.ok);
							if (!absent.ok) t.equal(absent.error.code, C.FederationErrorCode.ServerError);
						}
						const before = f.registered();
						const processed = await f.server.processPushedAuthorizationRequest(
							request(),
							mode === "self_signed_tls_client_auth"
								? { clientCertificate: () => f.certificate }
								: {},
						);
						t.true(processed.ok, JSON.stringify(processed));
						t.equal(f.registered(), before + 1);
						if (mode === "self_signed_tls_client_auth")
							t.false(
								(
									await f.server.processPushedAuthorizationRequest(request(), {
										clientCertificate: () => "unrelated",
									})
								).ok,
							);
						else
							t.false(
								(await f.server.processPushedAuthorizationRequest(request())).ok,
								"JWT proof is single-use",
							);
						t.equal(f.registered(), before + 1);
					}
				}
			},
		);
		Q.test(
			"Federation PAR requires a signed Request Object alongside attestation and verifies both",
			async (t) => {
				const f = await fixture(false);
				const attester = await generateSigningKey(),
					instance = await generateSigningKey();
				const attestation = await C.createClientAttestation(
					"trusted-attester",
					{ subject: f.ids.subject, confirmationKey: instance.publicKey, expiresAt: 4000 },
					new SigningEntryFixture(attester.privateKey),
					f.options,
				);
				const pop = await C.createClientAttestationProof(
					{ clientId: f.ids.subject, audience: f.ids.a },
					new SigningEntryFixture(instance.privateKey),
					f.options,
				);
				if (!attestation.ok || !pop.ok) throw new Error("Invalid fixture");
				const prepared = await f.client.createPushedAuthorizationRequest(
					f.discovery,
					{ response_type: "code", redirect_uri: `${f.ids.subject}/callback` },
					{ mode: "attest_jwt_client_auth", attestationJwt: attestation.value, popJwt: pop.value },
				);
				t.true(prepared.ok, JSON.stringify(prepared));
				if (!prepared.ok) return;
				t.ok(prepared.value.requestObjectJwt);
				const config = {
					clientAttestation: {
						getAttester: () => C.ok({ jwks: { keys: [attester.publicKey] } }),
						storage: replayStorage(
							new MemoryReplayStore({ engine: testEngine, clock: f.options.clock }),
						),
						acceptClient: () => true,
					},
				};
				const request = (omit: boolean) => {
					const form = new URLSearchParams(prepared.value.parameters);
					if (omit) form.delete("request");
					return new Request(prepared.value.endpoint, {
						method: "POST",
						headers: prepared.value.headers,
						body: form,
					});
				};
				t.false((await f.server.processPushedAuthorizationRequest(request(true), config)).ok);
				t.equal(f.registered(), 0);
				const mismatch = await f.server.processPushedAuthorizationRequest(request(false), {
					clientAttestation: {
						...config.clientAttestation,
						expectedChallenge: "new",
					},
				});
				t.false(mismatch.ok);
				if (!mismatch.ok) t.equal(mismatch.error.attestationError, "use_attestation_challenge");
				const expiredRequest = await signedRequest(f, { exp: 4900 });
				for (const [name, value] of prepared.value.headers) expiredRequest.headers.set(name, value);
				const stale = await f.server.processPushedAuthorizationRequest(expiredRequest, {
					clock: { now: () => 4100 },
					clientAttestation: {
						...config.clientAttestation,
						maxProofAgeSeconds: 5000,
					},
				});
				t.false(stale.ok);
				if (!stale.ok) t.equal(stale.error.attestationError, "use_fresh_attestation");
				const late = await f.server.processPushedAuthorizationRequest(request(false), {
					clientAttestation: {
						getAttester: config.clientAttestation.getAttester,
						replay: { mode: "freshness-only" },
						maxProofAgeSeconds: 5000,
						acceptClient: () => {
							f.setNow(1801);
							return true;
						},
					},
				});
				t.false(late.ok, "Request Object expiry also covers additional authentication");
				t.equal(f.registered(), 0);
				f.setNow(1500);
				const valid = await f.server.processPushedAuthorizationRequest(request(false), config);
				t.true(valid.ok, JSON.stringify(valid));
				t.equal(f.registered(), 1);
			},
		);
		Q.test(
			"additional malformed proofs and conflicting parameters cannot commit registration",
			async (t) => {
				const f = await fixture(false);
				const prepared = await f.client.createPushedAuthorizationRequest(
					f.discovery,
					{ response_type: "code", redirect_uri: `${f.ids.subject}/callback` },
					{ mode: "request_object" },
				);
				if (!prepared.ok) throw new Error(prepared.error.description);
				for (const extra of [
					{
						client_assertion: "invalid",
						client_assertion_type: C.JWT_BEARER_CLIENT_ASSERTION_TYPE,
					},
					{ redirect_uri: "https://other.example/callback" },
				]) {
					const form = new URLSearchParams(prepared.value.parameters);
					for (const [key, value] of Object.entries(extra)) form.set(key, value);
					const result = await f.server.processPushedAuthorizationRequest(
						new Request(prepared.value.endpoint, {
							method: "POST",
							headers: prepared.value.headers,
							body: form,
						}),
					);
					t.false(result.ok);
				}
				t.equal(f.registered(), 0);
			},
		);
	});
};
