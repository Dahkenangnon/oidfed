import { decodeJwt } from "jose";
import type QUnit from "qunit";
import { fetchFederationEndpoint } from "../../../../packages/core/src/endpoint-client.js";
import * as C from "../../../../packages/core/src/index.js";

export default (Q: QUnit) => {
	Q.module("core / shared client authentication", () => {
		Q.test(
			"attestation errors distinguish challenge attestation freshness and invalid proofs",
			async (t) => {
				const attester = await C.generateSigningKey(),
					instance = await C.generateSigningKey();
				let now = 1500;
				const options = { clock: { now: () => now }, clockSkewSeconds: 0 };
				const a = await C.createClientAttestation(
					"trusted-attester",
					{ subject: "client", confirmationKey: instance.publicKey, expiresAt: 1600 },
					new C.JwkSigner(attester.privateKey),
					options,
				);
				const p = await C.createClientAttestationProof(
					{ clientId: "client", audience: "https://server.example", challenge: "old" },
					new C.JwkSigner(instance.privateKey),
					options,
				);
				if (!a.ok || !p.ok) throw new Error("fixture failed");
				const config = {
					...options,
					audience: "https://server.example",
					replay: { mode: "freshness-only" } as const,
					getAttester: () => C.ok({ jwks: { keys: [attester.publicKey] } }),
					acceptClient: () => true,
				};
				const mismatch = await C.authenticateClientAttestation(a.value, p.value, {
					...config,
					expectedChallenge: "new",
				});
				t.false(mismatch.ok);
				if (!mismatch.ok) {
					t.equal(mismatch.error.attestationError, "use_attestation_challenge");
					const response = C.endpointAuthenticationErrorResponse({
						...mismatch.error,
						authenticationResponse: {
							error: mismatch.error.attestationError!,
							headers: { "OAuth-Client-Attestation-Challenge": "new" },
						},
					});
					t.equal(response.status, 400);
					t.equal(response.headers.get("OAuth-Client-Attestation-Challenge"), "new");
					t.equal(
						((await response.json()) as { error: string }).error,
						"use_attestation_challenge",
					);
				}
				t.true(
					(
						await C.authenticateClientAttestation(a.value, p.value, {
							...config,
							expectedChallenge: "old",
						})
					).ok,
				);
				now = 1601;
				for (const stale of [
					await C.verifyClientAttestation(a.value, config),
					await C.authenticateClientAttestation(a.value, p.value, config),
				]) {
					t.false(stale.ok);
					if (!stale.ok) t.equal(stale.error.attestationError, "use_fresh_attestation");
				}
				now = 1500;
				const late = await C.authenticateClientAttestation(a.value, p.value, {
					...config,
					acceptClient: async () => {
						now = 1601;
						return true;
					},
				});
				t.false(late.ok);
				if (!late.ok) t.equal(late.error.attestationError, "use_fresh_attestation");
				now = 1500;
				const wrong = await C.signApplicationJwt(
					{ ...decodeJwt(p.value), aud: "https://other.example" },
					"oauth-client-attestation-pop+jwt",
					new C.JwkSigner(instance.privateKey),
					options,
				);
				if (!wrong.ok) throw new Error("fixture failed");
				const invalid = await C.authenticateClientAttestation(a.value, wrong.value, config);
				t.false(invalid.ok);
				if (!invalid.ok) t.notEqual(invalid.error.attestationError, "use_fresh_attestation");
				const unavailable = await C.authenticateClientAttestation(a.value, p.value, {
					...config,
					getAttester: () =>
						C.err({ code: C.FederationErrorCode.ServerError, description: "unavailable" }),
				});
				t.false(unavailable.ok);
				if (!unavailable.ok) {
					t.equal(unavailable.error.code, C.FederationErrorCode.ServerError);
					t.equal(unavailable.error.attestationError, undefined);
				}
			},
		);
		Q.test("protocol JWT verification enforces application algorithm restrictions", async (t) => {
			const key = await C.generateSigningKey();
			const token = await C.signApplicationJwt(
				{ iss: "client", exp: 2000 },
				"oauth-authz-req+jwt",
				new C.JwkSigner(key.privateKey),
				{ clock: { now: () => 1500 } },
			);
			if (!token.ok) throw new Error("fixture failed");
			for (const allowedAlgorithms of [undefined, ["ES256"], ["RS256"], []]) {
				const result = await C.verifyProtocolJwt(
					token.value,
					{ keys: [key.publicKey] },
					{
						expectedTyp: "oauth-authz-req+jwt",
						clock: { now: () => 1500 },
						...(allowedAlgorithms ? { allowedAlgorithms } : {}),
					},
				);
				t.equal(result.ok, allowedAlgorithms === undefined || allowedAlgorithms.includes("ES256"));
			}
		});

		Q.test(
			"private-key assertions share valid NumericDates and reject unusable lifetimes before signing",
			async (t) => {
				const key = await C.generateSigningKey();
				const signer = new C.JwkSigner(key.privateKey);
				let calls = 0;
				const observed: C.JwtSigner = {
					alg: signer.alg,
					kid: signer.kid,
					signJwt: (...args) => {
						calls++;
						return signer.signJwt(...args);
					},
				};
				for (const expiresInSeconds of [0, -1, NaN, Infinity])
					await t.rejects(
						C.createClientAssertion("client", "https://server.example", observed, {
							clock: { now: () => 1000 },
							expiresInSeconds,
						}),
					);
				t.equal(calls, 0);
				const jwt = await C.createClientAssertion("client", "https://server.example", observed, {
					clock: { now: () => 1000.25 },
					expiresInSeconds: 0.5,
				});
				t.equal(decodeJwt(jwt).exp, 1000.75);
				t.true(
					(
						await C.verifyClientAssertion(
							jwt,
							{ keys: [key.publicKey] },
							"https://server.example",
							{ clock: { now: () => 1000.25 } },
						)
					).ok,
				);
			},
		);
		Q.test(
			"effective attestation metadata requires both algorithm lists while publication remains partial",
			(t) => {
				const metadata = {
					issuer: "https://server.example",
					authorization_endpoint: "https://server.example/auth",
					token_endpoint: "https://server.example/token",
					response_types_supported: ["code"],
					token_endpoint_auth_methods_supported: ["attest_jwt_client_auth"],
				};
				t.false(C.parseOAuthAuthorizationServerMetadata(metadata).success);
				t.true(C.parseOAuthAuthorizationServerPublicationMetadata(metadata).success);
				const complete = {
					...metadata,
					client_attestation_signing_alg_values_supported: ["ES256", "future-algorithm"],
					client_attestation_pop_signing_alg_values_supported: ["ES256"],
					challenge_endpoint: "https://server.example/challenge",
					extension: true,
				};
				t.true(C.parseOAuthAuthorizationServerMetadata(complete).success);
				for (const change of [
					{ client_attestation_signing_alg_values_supported: 42 },
					{ client_attestation_pop_signing_alg_values_supported: false },
					{ challenge_endpoint: 42 },
				])
					t.false(C.parseOAuthAuthorizationServerMetadata({ ...complete, ...change }).success);
			},
		);
		Q.test(
			"shared credential carriers select one explicit detector and never degrade to anonymous",
			async (t) => {
				let called = 0;
				const handler = C.createEndpointAuthenticatedHandler(
					{
						receiverEntityId: "https://server.example",
						methods: ["none", "basic", "bearer"],
						extensions: {
							methods: Object.fromEntries(
								["basic", "bearer"].map((method) => [
									method,
									{
										headers: ["authorization"],
										detect: (input: C.EndpointAuthenticationInput) =>
											input.headers.authorization?.startsWith(`${method} `) === true,
										authenticate: () => {
											called++;
											return C.ok({ entityId: "https://client.example" });
										},
									},
								]),
							),
						},
					},
					async () => new Response("ok"),
				);
				const request = (credential: string) =>
					new Request("https://server.example/endpoint", {
						method: "POST",
						headers: {
							authorization: credential,
							"content-type": "application/x-www-form-urlencoded",
						},
						body: "",
					});
				t.equal((await handler(request("basic credential"))).status, 200);
				t.equal(called, 1);
				t.equal((await handler(request("unknown credential"))).status, 401);
				t.equal(called, 1);
				const assertion = C.createEndpointAuthenticatedHandler(
					{
						receiverEntityId: "https://server.example",
						methods: ["client_secret_jwt"],
						extensions: {
							methods: {
								client_secret_jwt: {
									parameters: ["client_assertion", "client_assertion_type"],
									detect: (input) => input.parameters.client_assertion?.[0] === "recognized",
									authenticate: () => C.ok({ entityId: "https://client.example" }),
								},
							},
						},
					},
					async () => new Response("ok"),
				);
				t.equal(
					(
						await assertion(
							new Request("https://server.example/endpoint", {
								method: "POST",
								headers: { "content-type": "application/x-www-form-urlencoded" },
								body: "client_assertion=recognized&client_assertion_type=custom",
							}),
						)
					).status,
					200,
				);
			},
		);
		Q.test(
			"controlled authentication errors retain challenges and reject arbitrary response headers",
			async (t) => {
				const response = C.endpointAuthenticationErrorResponse({
					code: "invalid_client",
					description: "private host detail",
					authenticationResponse: {
						error: "use_attestation_challenge",
						status: 400,
						headers: { "OAuth-Client-Attestation-Challenge": "fresh" },
					},
				});
				t.equal(response.status, 400);
				t.equal(response.headers.get("OAuth-Client-Attestation-Challenge"), "fresh");
				t.equal(((await response.json()) as { error: string }).error, "use_attestation_challenge");
				const rejected = C.endpointAuthenticationErrorResponse({
					code: "invalid_client",
					description: "private",
					authenticationResponse: {
						error: "use_fresh_attestation",
						headers: { "set-cookie": "bad" },
					},
				});
				t.equal(((await rejected.json()) as { error: string }).error, "invalid_client");
				t.false(rejected.headers.has("set-cookie"));
			},
		);
		Q.test(
			"cancellation and deadlines stop pending custom preparation before transport",
			async (t) => {
				for (const abort of [true, false]) {
					const controller = new AbortController();
					let fetched = 0,
						rejectLate!: (cause: Error) => void;
					const result = fetchFederationEndpoint(
						"https://server.example/endpoint",
						new URLSearchParams(),
						{
							signal: controller.signal,
							httpTimeoutMs: 20,
							authentication: {
								method: "custom",
								audience: "https://server.example",
								prepare: () => {
									if (abort) controller.abort();
									return new Promise((_, reject) => {
										rejectLate = reject;
									});
								},
							},
							httpClient: async () => {
								fetched++;
								return new Response("unexpected");
							},
						},
					);
					t.false((await result).ok);
					t.equal(fetched, 0);
					rejectLate(new Error("late failure"));
				}
			},
		);
		Q.test(
			"generic attestation issuance and authentication preserve identity, trust expiry and replay",
			async (t) => {
				const attester = await C.generateSigningKey(),
					client = await C.generateSigningKey();
				let time = 1000;
				const options = { clock: { now: () => time }, clockSkewSeconds: 0 };
				const attestation = await C.createClientAttestation(
					"attester",
					{
						subject: "client",
						confirmationKey: client.publicKey,
						expiresAt: 2000,
						claims: JSON.parse('{"__proto__":{"safe":true},"label":"membership"}'),
					},
					new C.JwkSigner(attester.privateKey),
					options,
				);
				t.true(attestation.ok);
				if (!attestation.ok) return;
				t.false(Object.hasOwn(Object.prototype, "safe"));
				const proof = await C.createClientAttestationProof(
					{ clientId: "client", audience: "https://server.example" },
					new C.JwkSigner(client.privateKey),
					options,
				);
				t.true(proof.ok);
				if (!proof.ok) return;
				const config: C.AuthenticateClientAttestationOptions = {
					...options,
					audience: "https://server.example",
					getAttester: () => C.ok({ jwks: { keys: [attester.publicKey] }, expiresAt: 1500 }),
					replayStore: new C.MemoryReplayStore(options),
					acceptClient: () => true,
				};
				t.true((await C.authenticateClientAttestation(attestation.value, proof.value, config)).ok);
				t.false((await C.authenticateClientAttestation(attestation.value, proof.value, config)).ok);
				t.false(
					(
						await C.authenticateClientAttestation(attestation.value, proof.value, {
							...config,
							clientId: "other",
						})
					).ok,
				);
				t.false(
					(
						await C.verifyClientAttestation(attestation.value, {
							...options,
							getAttester: () => {
								time = 1501;
								return C.ok({ jwks: { keys: [attester.publicKey] }, expiresAt: 1500 });
							},
						})
					).ok,
				);
				t.false(
					(
						await C.createClientAttestation(
							"attester",
							{ subject: "client", confirmationKey: client.privateKey, expiresAt: 2000 },
							new C.JwkSigner(attester.privateKey),
							options,
						)
					).ok,
				);
			},
		);
		Q.test(
			"attestation creation binds supplied chains and controlled errors survive endpoint dispatch",
			async (t) => {
				const key = await C.generateSigningKey();
				const signer = new C.JwkSigner(key.privateKey);
				const ec = await C.signEntityStatement(
					{
						iss: "https://other.example",
						sub: "https://other.example",
						iat: 1000,
						exp: 2000,
						jwks: { keys: [key.publicKey] },
					},
					signer,
				);
				const created = await C.createClientAttestation(
					"https://attester.example",
					{ subject: "client", confirmationKey: key.publicKey, expiresAt: 2000 },
					signer,
					{ clock: { now: () => 1000 }, trustChain: [ec] },
				);
				t.false(created.ok);
				const handler = C.createEndpointAuthenticatedHandler(
					{
						receiverEntityId: "https://server.example",
						methods: ["custom"],
						extensions: {
							methods: {
								custom: {
									parameters: ["proof"],
									authenticate: () =>
										C.err({
											code: "invalid_client",
											description: "private failure",
											authenticationResponse: {
												error: "use_attestation_challenge",
												headers: { "OAuth-Client-Attestation-Challenge": "next" },
											},
										}),
								},
							},
						},
					},
					async () => new Response("should not run"),
				);
				const response = await handler(
					new Request("https://server.example/endpoint", {
						method: "POST",
						body: "proof=invalid",
						headers: { "content-type": "application/x-www-form-urlencoded" },
					}),
				);
				t.equal(response.status, 400);
				t.equal(response.headers.get("OAuth-Client-Attestation-Challenge"), "next");
				t.false((await response.text()).includes("private failure"));
			},
		);

		Q.test(
			"server challenge freshness supports atomic consumption and explicit freshness-only mode",
			async (t) => {
				const attester = await C.generateSigningKey(),
					client = await C.generateSigningKey();
				const clock = { now: () => 1000 };
				const attestation = await C.createClientAttestation(
					"attester",
					{ subject: "client", confirmationKey: client.publicKey, expiresAt: 3000 },
					new C.JwkSigner(attester.privateKey),
					{ clock },
				);
				const proof = await C.createClientAttestationProof(
					{ clientId: "client", audience: "https://server.example", challenge: "opaque" },
					new C.JwkSigner(client.privateKey),
					{ clock: { now: () => 1 } },
				);
				if (!attestation.ok || !proof.ok) throw new Error("Invalid fixture");
				let consumes = 0;
				const options: C.AuthenticateClientAttestationOptions = {
					clock,
					clockSkewSeconds: 0,
					audience: "https://server.example",
					getAttester: () => C.ok({ jwks: { keys: [attester.publicKey] } }),
					acceptClient: () => true,
					freshness: {
						mode: "challenge",
						verify: (challenge) =>
							challenge === "opaque"
								? C.ok({ issuedAt: 990, expiresAt: 1010 })
								: C.err({ code: "invalid_client", description: "Unknown challenge" }),
					},
					replay: { mode: "challenge", consume: () => ++consumes === 1 },
				};
				t.true(
					(await C.authenticateClientAttestation(attestation.value, proof.value, options)).ok,
					"server-managed time replaces old client iat",
				);
				t.false(
					(await C.authenticateClientAttestation(attestation.value, proof.value, options)).ok,
				);
				t.true(
					(
						await C.authenticateClientAttestation(attestation.value, proof.value, {
							...options,
							replay: { mode: "freshness-only" },
						})
					).ok,
				);
				t.false(
					(
						await C.authenticateClientAttestation(attestation.value, proof.value, {
							...options,
							freshness: { mode: "iat" },
						})
					).ok,
				);
			},
		);
		Q.test(
			"header and concatenated serialization reject duplicates and challenge endpoints remain host backed",
			async (t) => {
				const key = await C.generateSigningKey(),
					signer = new C.JwkSigner(key.privateKey);
				const a = await C.createClientAttestation(
					"issuer",
					{ subject: "client", confirmationKey: key.publicKey, expiresAt: 2000 },
					signer,
					{ clock: { now: () => 1000 } },
				);
				const p = await C.createClientAttestationProof(
					{ clientId: "client", audience: "https://server.example" },
					signer,
					{ clock: { now: () => 1000 } },
				);
				if (!a.ok || !p.ok) throw new Error("Invalid fixture");
				const headers = C.clientAttestationHeaders(a.value, p.value);
				if (!headers.ok) throw new Error("Invalid fixture");
				t.true(C.parseClientAttestationHeaders(headers.value).ok);
				headers.value.append("OAuth-Client-Attestation", a.value);
				t.false(C.parseClientAttestationHeaders(headers.value).ok);
				const handler = C.createAttestationChallengeHandler(() => "opaque");
				t.equal((await handler(new Request("https://server.example/challenge"))).status, 405);
				const response = await handler(
					new Request("https://server.example/challenge", { method: "POST" }),
				);
				t.equal(response.headers.get("cache-control"), "no-store");
				const challenge = await C.fetchAttestationChallenge("https://server.example/challenge", {
					httpClient: async (_url, init) => {
						t.equal(init?.method, "POST");
						return response;
					},
				});
				t.deepEqual(challenge, C.ok("opaque"));
				t.deepEqual(
					C.readAttestationChallenge(new Headers({ "OAuth-Client-Attestation-Challenge": "next" })),
					C.ok("next"),
				);
			},
		);
	});
};
