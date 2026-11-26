/** Exercise request grants, independent Resolve cache partitions, and exact Trust Mark withdrawal. */
import type QUnit from "qunit";
import { Intermediate, TrustAnchor } from "../../../packages/authority/src/index.js";
import {
	type BoundFederationOptions,
	createClientAssertion,
	createTrustAnchorSet,
	decodeEntityStatement,
	entityId,
	type HttpClient,
	type JWKSet,
	JWT_BEARER_CLIENT_ASSERTION_TYPE,
	JwtTyp,
	MediaType,
	type ResolveAssessmentCacheValue,
	type ResolverCacheOptions,
	signEntityStatement,
	signTrustMark,
	verifyResolveResponse,
	verifyTrustMarkStatusResponse,
} from "../../../packages/core/src/index.js";
import type { TrustMarkRef } from "../../../packages/core/src/schemas/trust-mark.js";
import { MemoryCache } from "../../../packages/core/src/storage/cache.js";
import type { CachedResponderEvidence } from "../../../packages/core/src/storage/cache-records.js";
import { Leaf } from "../../../packages/leaf/src/index.js";
import { memoryStorage } from "../../storage-fixtures.js";
import {
	generateSigningKey,
	SigningEntryFixture,
	testEngine,
} from "../fixtures/software-crypto.js";

const issuer = entityId("https://resolve-policy-anchor.example");
const subject = entityId("https://resolve-policy-member.example");
const callerA = entityId("https://resolve-policy-reviewer-a.example");
const callerB = entityId("https://resolve-policy-reviewer-b.example");
const alternativeAnchor = entityId("https://resolve-policy-alternative.example");
const markType = "https://resolve-policy-anchor.example/accredited";

/** Build a miniature federation with distinct caller credentials and a shared clock and storage. */
async function createFixture() {
	const [server, member, a, b, replacement] = await Promise.all(
		Array.from({ length: 5 }, () => generateSigningKey()),
	);
	if (!server || !member || !a || !b || !replacement) throw new Error("Missing fixture keys");
	const signer = new SigningEntryFixture(server.privateKey);
	const clientSigners = new Map([
		[callerA, new SigningEntryFixture(a.privateKey)],
		[callerB, new SigningEntryFixture(b.privateKey)],
	]);
	let selected = signer;
	let duringResolveSigning: (() => Promise<void>) | undefined;
	let published: JWKSet = { keys: [server.publicKey, replacement.publicKey] };
	let now = 20_000;
	const clock = { now: () => now };
	const storage = memoryStorage({ clock, trustMarks: true, collections: true });
	const crypto = {
		engine: testEngine,
		keyring: {
			async entry(_purpose?: string, context?: { readonly artifact?: string }) {
				const beforeSign = duringResolveSigning;
				if (context?.artifact === "resolve-response" && beforeSign) {
					const binding = selected.signer;
					return {
						signer: {
							publicJwk: binding.publicJwk,
							async sign(input: Uint8Array) {
								await beforeSign();
								return binding.sign(input);
							},
						},
						publishedJwks: published,
					};
				}
				return { signer: selected.signer, publishedJwks: published };
			},
		},
	};
	const trustAnchors = createTrustAnchorSet([
		{ entityId: issuer, jwks: published },
		{ entityId: alternativeAnchor, jwks: published },
	]);
	const makeMember = (trustMarks: TrustMarkRef[] = []) =>
		Leaf.create({
			entityId: subject,
			authorityHints: [issuer],
			crypto: {
				engine: testEngine,
				keyring: { entry: async () => new SigningEntryFixture(member.privateKey) },
			},
			metadata: { federation_entity: {}, oauth_resource: { resource_name: "Policy test" } },
			options: { clock },
			trustMarks,
		});
	let leaf = await makeMember();
	let anchor: TrustAnchor | undefined;
	let outbound = 0;
	const httpClient: HttpClient = (input, init) => {
		outbound++;
		const request = new Request(input, init);
		if (new URL(request.url).origin === subject) return leaf.handleRequest(request);
		if (new URL(request.url).origin === issuer && anchor) return anchor.handleRequest(request);
		throw new Error("Unknown fixture endpoint");
	};
	const install = async (
		options: BoundFederationOptions = {},
		endpoint = `${issuer}/resolve`,
		hostStorage = storage,
		onStatus?: () => void,
	) => {
		anchor = await TrustAnchor.create({
			entityId: issuer,
			crypto,
			storage: hostStorage,
			trustAnchors,
			trustMarkIssuers: { [markType]: [issuer] },
			...(onStatus
				? {
						trustMarkStatusPolicy({ baseStatus }) {
							onStatus();
							return { status: baseStatus };
						},
					}
				: {}),
			clientKeyProvider: {
				async getClientFederationJwks(id) {
					return clientSigners.get(id)?.publishedJwks;
				},
			},
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${issuer}/fetch`,
					federation_fetch_endpoint_auth_methods: ["none", "private_key_jwt"],
					federation_list_endpoint: `${issuer}/list`,
					federation_resolve_endpoint: endpoint,
					federation_resolve_endpoint_auth_methods: ["none", "private_key_jwt"],
					federation_trust_mark_status_endpoint: `${issuer}/status`,
				},
			},
			options: { clock, httpClient, ...options },
		});
		return anchor;
	};
	const host = await install();
	await host.registerSubordinate({ entityId: subject, jwks: { keys: [member.publicKey] } });
	const assertion = async (caller: typeof callerA, audience = issuer) => {
		const key = clientSigners.get(caller);
		if (!key) throw new Error("Unknown reviewer");
		return createClientAssertion(caller, audience, key, { engine: testEngine, clock });
	};
	return {
		install,
		storage,
		crypto,
		trustAnchors,
		clock,
		httpClient,
		assertion,
		readOutbound: () => outbound,
		async publishHeldMark(jwt: string) {
			leaf = await makeMember([{ trust_mark_type: markType, trust_mark: jwt }]);
		},
		beforeResolveSigning(operation?: () => Promise<void>) {
			duringResolveSigning = operation;
		},
		advance(seconds: number) {
			now += seconds;
		},
		rotate() {
			selected = new SigningEntryFixture(replacement.privateKey);
			published = { keys: [replacement.publicKey] };
			return published;
		},
	};
}

/** Send Resolve selectors in the form when sending a client assertion. */
function resolveRequest(
	receiver: string,
	jwt?: string,
	types: readonly string[] = [],
	anchor: string | readonly string[] = issuer,
	extraHeaders?: Record<string, string>,
): Request {
	const url = new URL(`${receiver}/resolve`);
	const form = new URLSearchParams({ sub: subject });
	for (const id of typeof anchor === "string" ? [anchor] : anchor) form.append("trust_anchor", id);
	for (const type of types) form.append("entity_type", type);
	if (!jwt) {
		url.search = form.toString();
		return new Request(url, extraHeaders ? { headers: extraHeaders } : {});
	}
	form.set("client_assertion_type", JWT_BEARER_CLIENT_ASSERTION_TYPE);
	form.set("client_assertion", jwt);
	return new Request(url, { method: "POST", body: form });
}

function cachePolicy(policyRevision: string): ResolverCacheOptions {
	return {
		namespace: "resolve-policy-fixture",
		policyRevision,
		scope: ({ caller, trustAnchor }) =>
			trustAnchor === issuer ? (caller ? "review" : "public") : undefined,
	};
}

/** Hold an optional cache operation until its test has checked the required response. */
function deferred() {
	let resolve!: () => void;
	const promise = new Promise<void>((done) => {
		resolve = done;
	});
	return { promise, resolve };
}

export default function resolvePolicyTests({ module, test }: QUnit): void {
	module("integration / Resolve request and Trust Mark policy", () => {
		test("HTTP Resolve observes reuse once and ignores failed observers", async (assert) => {
			const f = await createFixture();
			const results: string[] = [];
			const host = await f.install({
				resolverCache: cachePolicy("observed"),
				onResolverCacheResult(result) {
					results.push(result);
					if (result === "miss") throw new Error("synchronous observer failure");
					return Promise.reject(new Error("asynchronous observer failure"));
				},
			});
			const outbound = f.readOutbound();
			assert.strictEqual((await host.handleRequest(resolveRequest(issuer))).status, 404);
			assert.strictEqual(f.readOutbound(), outbound);
			assert.deepEqual(results, ["miss"]);
			await host.primeAnonymousResolve({ subject, trustAnchor: issuer });
			assert.deepEqual(results, ["miss"]);
			assert.strictEqual((await host.handleRequest(resolveRequest(issuer))).status, 200);
			assert.strictEqual((await host.handleRequest(new Request(`${issuer}/resolve`))).status, 400);
			assert.deepEqual(results, ["miss", "hit"]);
			const read = f.storage.cache.get.bind(f.storage.cache);
			f.storage.cache.get = async (key) => {
				if (key.startsWith("resolve:")) throw new Error("Cache unavailable");
				return read(key);
			};
			assert.strictEqual((await host.handleRequest(resolveRequest(issuer))).status, 500);
			assert.deepEqual(results, ["miss", "hit"]);
		});

		test("optional issuer refresh shares the fetch limit without losing verified held evidence", async (assert) => {
			for (const [budget, expectedStatus, replace] of [
				[2, 503, false],
				[3, 200, false],
				[4, 200, true],
			] as const) {
				const f = await createFixture();
				const owner = await f.install();
				const held = await owner.issueTrustMark(subject, markType, { ttlSeconds: 120 });
				const fresh = await owner.issueTrustMark(subject, markType, {
					ttlSeconds: 240,
					renewal: "renew",
				});
				await f.publishHeldMark(held);
				let calls = 0;
				let refreshes = 0;
				const host = await f.install({
					maxTotalFetches: budget,
					async httpClient(input, init) {
						const request = new Request(input, init);
						calls++;
						if (new URL(request.url).pathname === "/optional-issuer-lookup") {
							refreshes++;
							return new Response(fresh);
						}
						return f.httpClient(request);
					},
					async resolveTrustMarkCandidates({ verifiedHeld, candidateLimits, httpClient, signal }) {
						assert.true(Object.isFrozen(candidateLimits));
						assert.strictEqual(candidateLimits.maxCandidates, 100);
						assert.true(candidateLimits.maxBytes > held.length);
						const candidates = verifiedHeld.map(({ ref }) => ref.trust_mark);
						assert.deepEqual(candidates, [held]);
						try {
							const response = await httpClient(`${issuer}/optional-issuer-lookup`, { signal });
							if (response.ok) candidates.push(await response.text());
						} catch {
							// An unavailable optional lookup leaves the policy's approved held JWT eligible.
						}
						return candidates;
					},
				});
				const reply = await host.handleRequest(resolveRequest(issuer, await f.assertion(callerA)));
				assert.strictEqual(reply.status, expectedStatus, `budget ${budget}`);
				assert.strictEqual(calls, budget, "no fetch exceeds the shared allowance");
				assert.strictEqual(refreshes, replace ? 1 : 0);
				if (!reply.ok) continue;
				const decoded = decodeEntityStatement(await reply.text());
				assert.deepEqual(decoded.ok && decoded.value.payload.trust_marks, [
					{ trust_mark_type: markType, trust_mark: replace ? fresh : held },
				]);
			}
		});

		test("unverified held marks are assessed only when selected and only with the optional budget", async (assert) => {
			for (const [selectHeld, budget, expectedFetches] of [
				[false, 3, 3],
				[false, 4, 3],
				[true, 3, 3],
				[true, 4, 4],
			] as const) {
				const f = await createFixture();
				const held = await signTrustMark({
					issuer: callerB,
					subject,
					trustMarkType: markType,
					signer: await f.crypto.keyring.entry(),
					clock: f.clock,
					ttlSeconds: 240,
				});
				await f.publishHeldMark(held);
				const host = await f.install({
					maxTotalFetches: budget,
					...(selectHeld
						? {
								resolveTrustMarkCandidates({ held: candidates, verifiedHeld }) {
									assert.deepEqual(candidates, [held]);
									assert.deepEqual(verifiedHeld, []);
									return candidates;
								},
							}
						: {}),
				});
				await host.setTrustMarkIssuers({ [markType]: [issuer, callerB] });
				const before = f.readOutbound();
				const result = await host.handleRequest(resolveRequest(issuer, await f.assertion(callerA)));
				assert.strictEqual(result.status, 200);
				assert.strictEqual(f.readOutbound() - before, expectedFetches);
				const decoded = decodeEntityStatement(await result.text());
				assert.true(decoded.ok && decoded.value.payload.sub === subject);
				assert.true(decoded.ok && decoded.value.payload.trust_marks === undefined);
			}
		});

		test("an optional candidate needing more verification cannot discard a selected held mark", async (assert) => {
			const f = await createFixture();
			const owner = await f.install();
			const held = await owner.issueTrustMark(subject, markType, { ttlSeconds: 120 });
			const candidate = await signTrustMark({
				issuer: callerB,
				subject,
				trustMarkType: markType,
				signer: await f.crypto.keyring.entry(),
				clock: f.clock,
				ttlSeconds: 240,
			});
			await f.publishHeldMark(held);
			const host = await f.install({
				maxTotalFetches: 3,
				resolveTrustMarkCandidates: ({ verifiedHeld }) => [
					candidate,
					...verifiedHeld.map(({ ref }) => ref.trust_mark),
				],
			});
			await host.setTrustMarkIssuers({ [markType]: [issuer, callerB] });
			const outbound = f.readOutbound();
			const reply = await host.handleRequest(resolveRequest(issuer, await f.assertion(callerA)));
			assert.strictEqual(reply.status, 200);
			assert.strictEqual(f.readOutbound() - outbound, 3);
			const decoded = decodeEntityStatement(await reply.text());
			assert.deepEqual(decoded.ok && decoded.value.payload.trust_marks, [
				{ trust_mark_type: markType, trust_mark: held },
			]);
		});

		test("public priming uses the same cache entry for equivalent Resolve selectors", async (assert) => {
			const f = await createFixture();
			const scopeTypes: (readonly string[])[] = [];
			let assessments = 0;
			const host = await f.install({
				resolverCache: {
					...cachePolicy("memberships"),
					scope({ entityTypes }) {
						scopeTypes.push(entityTypes);
						return entityTypes.join(",");
					},
				},
				resolveTrustMarkCandidates() {
					assessments++;
					return [];
				},
			});
			const anchors = [issuer, alternativeAnchor, issuer];
			const types = ["oauth_resource", "federation_entity", "oauth_resource"];
			await host.primeAnonymousResolve({ subject, trustAnchor: anchors, entityTypes: types });
			const outbound = f.readOutbound();
			const reordered = resolveRequest(
				issuer,
				undefined,
				["federation_entity", "oauth_resource"],
				[alternativeAnchor, issuer],
			);
			assert.strictEqual((await host.handleRequest(reordered)).status, 200);
			assert.strictEqual(
				(await host.handleRequest(resolveRequest(issuer, undefined, types, anchors))).status,
				200,
			);
			assert.strictEqual(
				(await host.handleRequest(resolveRequest(issuer, undefined, ["oauth_resource"], anchors)))
					.status,
				404,
			);
			assert.strictEqual(f.readOutbound(), outbound);
			assert.strictEqual(assessments, 1);
			assert.deepEqual(
				scopeTypes.slice(0, 6),
				Array.from({ length: 6 }, () => ["federation_entity", "oauth_resource"]),
			);
		});

		test("Authority and Leaf prime only the selectors allowed by their fixed Resolve route", async (assert) => {
			const f = await createFixture();
			const resolverId = entityId("https://fixed-resolver.example");
			const fixed = new URLSearchParams({
				sub: subject,
				trust_anchor: issuer,
				entity_type: "oauth_resource",
				route: "members",
			});
			const options: BoundFederationOptions = {
				clock: f.clock,
				httpClient: f.httpClient,
				authorizeEndpointRequest({ endpoint, parameters }) {
					if (endpoint === "resolve") {
						assert.deepEqual(parameters.entity_type, ["oauth_resource"]);
						assert.strictEqual(parameters.route, undefined);
					}
					return true;
				},
			};
			const authorityUrl = `${issuer}/resolve?${fixed}`;
			const authority = await f.install(options, authorityUrl);
			const leafUrl = `${resolverId}/resolve?${fixed}`;
			const leaf = await Leaf.create({
				entityId: resolverId,
				authorityHints: [issuer],
				crypto: f.crypto,
				trustAnchors: f.trustAnchors,
				metadata: { federation_entity: { federation_resolve_endpoint: leafUrl } },
				options,
				resolver: {},
			});
			const resolver = leaf.resolver;
			if (!resolver) throw new Error("Expected the Leaf resolver");
			for (const [prime, serve, endpoint] of [
				[
					authority.primeAnonymousResolve.bind(authority),
					authority.handleRequest.bind(authority),
					authorityUrl,
				],
				[resolver.primeAnonymousResolve.bind(resolver), leaf.handleRequest.bind(leaf), leafUrl],
			] as const) {
				const outbound = f.readOutbound();
				for (const input of [
					{ subject: callerB, trustAnchor: issuer },
					{ subject, trustAnchor: alternativeAnchor },
					{ subject, trustAnchor: issuer, entityTypes: [] },
				])
					await assert.rejects(prime(input), /HTTP 400 invalid_request.*fixed selectors/);
				assert.strictEqual(f.readOutbound(), outbound);
				await prime({ subject, trustAnchor: [issuer, issuer] });
				assert.strictEqual((await serve(new Request(endpoint))).status, 200);
			}
		});

		test("policy diagnostics and priming errors keep the failure categories and hide internal details", async (assert) => {
			const f = await createFixture();
			const logs: string[] = [];
			const record = (message: string) => logs.push(message);
			const policy = { mode: "deny" };
			const options: BoundFederationOptions = {
				logger: { debug: () => {}, info: () => {}, warn: record, error: record },
				httpTimeoutMs: 15,
				authorizeEndpointRequest() {
					if (policy.mode === "throw") throw new Error("internal policy detail");
					if (policy.mode === "invalid") return undefined as unknown as boolean;
					if (policy.mode === "timeout") return new Promise<boolean>(() => {});
					return policy.mode === "allow";
				},
			};
			let host = await f.install(options);
			const input = { subject, trustAnchor: issuer };
			await assert.rejects(
				host.primeAnonymousResolve(input),
				/HTTP 401 invalid_client.*Endpoint access denied/,
			);
			assert.deepEqual(logs, []);
			policy.mode = "throw";
			await assert.rejects(
				host.primeAnonymousResolve(input),
				/HTTP 500 server_error.*Endpoint authorization failed/,
			);
			policy.mode = "invalid";
			await assert.rejects(host.primeAnonymousResolve(input), /HTTP 500 server_error/);
			policy.mode = "timeout";
			await assert.rejects(host.primeAnonymousResolve(input), /HTTP 503 temporarily_unavailable/);
			assert.deepEqual(logs, [
				"Authorization policy failed for resolve",
				"Authorization policy returned a non-boolean result for resolve",
				"Authorization policy timed out for resolve",
			]);
			policy.mode = "allow";
			host = await f.install({
				...options,
				httpTimeoutMs: 5000,
				resolverCache: { ...cachePolicy("skipped"), scope: () => undefined },
			});
			await assert.rejects(
				host.primeAnonymousResolve(input),
				/HTTP 404 not_found.*cache policy declined/,
			);
			const set = f.storage.cache.set.bind(f.storage.cache);
			f.storage.cache.set = async (key, value, ttl) => {
				if (key.startsWith("resolve:")) throw new Error("internal storage detail");
				await set(key, value, ttl);
			};
			host = await f.install({ ...options, httpTimeoutMs: 5000 });
			await assert.rejects(
				host.primeAnonymousResolve(input),
				/HTTP 503 temporarily_unavailable.*Could not store public resolution/,
			);
		});

		test("Resolve enforces the chain length guard with candidate disclosure enabled", async (assert) => {
			const f = await createFixture();
			let assessments = 0;
			const host = await f.install({
				maxChainLength: 1,
				resolveTrustMarkCandidates() {
					assessments++;
					return [];
				},
			});
			const response = await host.handleRequest(resolveRequest(issuer, await f.assertion(callerA)));
			assert.strictEqual(response.status, 400);
			assert.strictEqual(
				((await response.json()) as { error: string }).error,
				"invalid_trust_chain",
			);
			assert.strictEqual(assessments, 0);
		});

		test("refreshing optional evidence cannot evict a shared subject assessment", async (assert) => {
			const f = await createFixture();
			const anchor = await f.install();
			const responder = entityId("https://bounded-resolver.example");
			await anchor.registerSubordinate({
				entityId: responder,
				jwks: (await f.crypto.keyring.entry()).publishedJwks,
			});
			const bounded = new MemoryCache({ maxEntries: 2, clock: f.clock });
			const get = f.storage.cache.get.bind(f.storage.cache);
			const set = f.storage.cache.set.bind(f.storage.cache);
			const resolveEntry = (key: string) =>
				key.startsWith("resolve:v2:") || key.startsWith("resolve-responder:");
			f.storage.cache.get = (key) => (resolveEntry(key) ? bounded.get(key) : get(key));
			f.storage.cache.set = (key, value, ttl) =>
				resolveEntry(key) ? bounded.set(key, value, ttl) : set(key, value, ttl);
			let leaf: Leaf | undefined;
			leaf = await Leaf.create({
				entityId: responder,
				authorityHints: [issuer],
				crypto: f.crypto,
				storage: f.storage,
				trustAnchors: f.trustAnchors,
				metadata: { federation_entity: { federation_resolve_endpoint: `${responder}/resolve` } },
				options: {
					clock: f.clock,
					resolveResponderEvidenceBudgetMs: 200,
					httpClient(input, init) {
						const request = new Request(input, init);
						if (leaf && new URL(request.url).origin === responder)
							return leaf.handleRequest(request);
						return f.httpClient(request);
					},
				},
				resolver: {},
			});
			const resolver = leaf.resolver;
			if (!resolver) throw new Error("Expected the bounded-cache Resolver");
			for (const generation of [0, 1]) {
				f.advance(generation);
				await resolver.primeAnonymousResolve({ subject, trustAnchor: issuer });
				const outbound = f.readOutbound();
				let included = false;
				for (let attempt = 0; attempt < 10 && !included; attempt++) {
					const response = await leaf.handleRequest(resolveRequest(responder));
					assert.strictEqual(response.status, 200);
					const decoded = decodeEntityStatement(await response.text());
					included = decoded.ok && Object.hasOwn(decoded.value.header, "trust_chain");
				}
				assert.true(included, "the refreshed subject and its optional evidence remain available");
				assert.strictEqual(f.readOutbound(), outbound);
			}
		});

		test("primed multi-hop responder evidence is verified offline and expires independently", async (assert) => {
			const f = await createFixture();
			const host = await f.install();
			const issuerKeys = (await f.crypto.keyring.entry()).publishedJwks;
			const superior = entityId("https://cache-header-superior.example");
			const responder = entityId("https://cache-header-resolver.example");
			const intermediate = await Intermediate.create({
				entityId: superior,
				authorityHints: [issuer],
				crypto: f.crypto,
				storage: memoryStorage({ clock: f.clock }),
				trustAnchors: f.trustAnchors,
				options: { clock: f.clock },
				entityConfigurationTtlSeconds: 8,
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${superior}/fetch`,
						federation_list_endpoint: `${superior}/list`,
					},
				},
			});
			await host.registerSubordinate({ entityId: superior, jwks: issuerKeys });
			await intermediate.registerSubordinate({ entityId: responder, jwks: issuerKeys });
			let leaf: Leaf | undefined;
			let outbound = 0;
			const proofCache = new MemoryCache({ clock: f.clock });
			const makeLeaf = (
				options: BoundFederationOptions = {},
				resolverOptions?: BoundFederationOptions,
			) =>
				Leaf.create({
					entityId: responder,
					authorityHints: [superior],
					entityConfigurationTtlSeconds: 12,
					crypto: f.crypto,
					storage: f.storage,
					trustAnchors: f.trustAnchors,
					metadata: { federation_entity: { federation_resolve_endpoint: `${responder}/resolve` } },
					options: {
						clock: f.clock,
						resolverCache: cachePolicy("shared-responder"),
						resolveResponderEvidenceCache: proofCache,
						httpClient: (input, init) => {
							outbound++;
							const request = new Request(input, init);
							const origin = new URL(request.url).origin;
							if (leaf && origin === responder) return leaf.handleRequest(request);
							if (origin === superior) return intermediate.handleRequest(request);
							return f.httpClient(input, init);
						},
						...options,
					},
					resolver: resolverOptions ? { options: resolverOptions } : {},
				});
			leaf = await makeLeaf();
			const set = f.storage.cache.set.bind(f.storage.cache);
			const get = f.storage.cache.get.bind(f.storage.cache);
			const setProof = proofCache.set.bind(proofCache);
			const getProof = proofCache.get.bind(proofCache);
			let key: string | undefined;
			let proofKey: string | undefined;
			const blockedProofWrite = deferred();
			const proofWriteStarted = deferred();
			let proofWriteFinished = deferred();
			let proofWrites = 0;
			let proofFailure: Error | undefined;
			let proofReadDelay = 0;
			let stalledRead: Promise<void> | undefined;
			const reads: string[] = [];
			f.storage.cache.set = async (entryKey, value, ttl) => {
				if (entryKey.startsWith("resolve:v2:")) key = entryKey;
				await set(entryKey, value, ttl);
			};
			proofCache.set = async (entryKey, value, ttl) => {
				proofKey = entryKey;
				const finished = proofWriteFinished;
				try {
					if (++proofWrites === 1) {
						proofWriteStarted.resolve();
						await blockedProofWrite.promise;
						throw new Error("Optional evidence storage unavailable");
					}
					await setProof(entryKey, value, ttl);
				} finally {
					finished.resolve();
				}
			};
			f.storage.cache.get = async (entryKey) => {
				reads.push(entryKey);
				return get(entryKey);
			};
			proofCache.get = async (entryKey) => {
				reads.push(entryKey);
				if (entryKey === proofKey) {
					if (proofFailure) throw proofFailure;
					if (proofReadDelay > 0)
						await new Promise<void>((done) => setTimeout(done, proofReadDelay));
					await stalledRead;
				}
				return getProof(entryKey);
			};
			const resolver = leaf.resolver;
			if (!resolver) throw new Error("Expected the Leaf resolver");
			await assert.rejects(
				makeLeaf({ resolveResponderEvidenceCache: f.storage.cache }),
				/a cache separate from subject assessments/,
			);
			assert.strictEqual((await leaf.handleRequest(resolveRequest(responder))).status, 404);
			assert.true(reads.length === 1 && reads[0]?.startsWith("resolve:v2:"));
			await resolver.primeAnonymousResolve({ subject, trustAnchor: issuer });
			await proofWriteStarted.promise;
			assert.ok(key && (await get(key)), "subject is stored while the optional write is stalled");
			await resolver.primeAnonymousResolve({ subject, trustAnchor: issuer });
			assert.strictEqual(proofWrites, 1, "a stalled write prevents further optional writes");
			blockedProofWrite.resolve();
			await proofWriteFinished.promise;
			proofWriteFinished = deferred();
			await resolver.primeAnonymousResolve({ subject, trustAnchor: issuer });
			await proofWriteFinished.promise;
			let before = outbound;
			if (!key || !proofKey) throw new Error("Expected subject and responder cache keys");
			const record = await get<ResolveAssessmentCacheValue>(key);
			const responderEvidence = await getProof<CachedResponderEvidence>(proofKey);
			if (!record || !responderEvidence) throw new Error("Expected a cached assessment and proof");
			assert.deepEqual(Object.keys(record).sort(), [
				"headers",
				"payload",
				"reuseUntil",
				"trustAnchor",
			]);
			assert.deepEqual(record.headers, {});
			assert.strictEqual(record.reuseUntil, f.clock.now() + 12);
			assert.strictEqual(responderEvidence.expiresAt, f.clock.now() + 8);
			assert.deepEqual(
				responderEvidence.entityConfigurations.map(([id]) => id),
				[superior],
			);
			assert.true(record.payload.exp > record.reuseUntil);

			const expectHeader = async (expected: readonly string[] | undefined, receiving = leaf) => {
				reads.length = 0;
				const cached = await receiving.handleRequest(resolveRequest(responder));
				assert.strictEqual(cached.status, 200);
				const decoded = decodeEntityStatement(await cached.text());
				if (!decoded.ok) throw new Error("Expected a signed Resolve Response");
				assert.deepEqual(decoded.value.header.trust_chain, expected);
				assert.deepEqual(decoded.value.payload.trust_chain, record.payload.trust_chain);
				assert.false(Object.hasOwn(decoded.value.payload, "aud"));
				assert.strictEqual(outbound, before);
				assert.deepEqual(reads, [key, proofKey]);
			};
			await expectHeader(responderEvidence.statements);
			for (const invalid of [
				{ ...responderEvidence, statements: ["malformed"] },
				{ ...responderEvidence, statements: record.payload.trust_chain },
				{ ...responderEvidence, entityConfigurations: [] },
			]) {
				await setProof(proofKey, invalid, 12);
				await expectHeader(undefined);
			}

			await proofCache.delete(proofKey);
			await set(key, { ...record, headers: { trust_chain: responderEvidence.statements } }, 12);
			await expectHeader(undefined);
			await set(key, record, 12);
			await setProof(proofKey, responderEvidence, 8);
			const proofDiagnostics: string[] = [];
			const logger = {
				debug(message: string) {
					if (
						message.includes("optional Resolve responder evidence") ||
						message.includes("Optional Resolve responder evidence")
					)
						proofDiagnostics.push(message);
				},
				info() {},
				warn() {},
				error() {},
			};
			const defaultBudget = await makeLeaf({ httpTimeoutMs: 500, logger });
			const largerBudget = await makeLeaf({
				httpTimeoutMs: 30,
				resolveResponderEvidenceBudgetMs: 300,
				logger,
			});
			const smallerBudget = await makeLeaf(
				{ resolveResponderEvidenceBudgetMs: 25, logger },
				{ resolveResponderEvidenceBudgetMs: 300 },
			);
			for (const invalid of [0, -5, 1.5, Infinity, 2_147_483_648])
				await assert.rejects(
					makeLeaf({ resolveResponderEvidenceBudgetMs: invalid }),
					/resolveResponderEvidenceBudgetMs must be an integer/,
				);
			proofFailure = new DOMException("Cache adapter's own timeout", "TimeoutError");
			await expectHeader(undefined, defaultBudget);
			assert.deepEqual(proofDiagnostics.splice(0), [
				"Could not read optional Resolve responder evidence",
			]);
			proofFailure = undefined;
			proofReadDelay = 45;
			await expectHeader(undefined, defaultBudget);
			assert.deepEqual(proofDiagnostics.splice(0), [
				"Optional Resolve responder evidence budget expired",
			]);
			await expectHeader(undefined, smallerBudget);
			assert.deepEqual(proofDiagnostics.splice(0), [
				"Optional Resolve responder evidence budget expired",
			]);
			await expectHeader(responderEvidence.statements, largerBudget);
			assert.deepEqual(proofDiagnostics, []);
			proofReadDelay = 0;
			const blocker = deferred();
			stalledRead = blocker.promise;
			await expectHeader(undefined, defaultBudget);
			assert.deepEqual(proofDiagnostics.splice(0), [
				"Optional Resolve responder evidence budget expired",
			]);
			stalledRead = undefined;
			blocker.resolve();

			const keySet = await f.crypto.keyring.entry();
			const subjectOnly = await signEntityStatement(record.payload, keySet, {
				typ: JwtTyp.ResolveResponse,
			});
			const messages: string[] = [];
			const limited = await makeLeaf({
				maxCompactBytes: subjectOnly.length,
				logger: {
					debug(message) {
						if (!message.startsWith("Omitted Resolve responder chain")) return;
						messages.push(message);
						throw new Error("Logger unavailable");
					},
					info() {},
					warn() {},
					error() {},
				},
			});
			const reply = await limited.handleRequest(resolveRequest(responder));
			assert.strictEqual(reply.status, 200);
			const decoded = decodeEntityStatement(await reply.text());
			assert.true(decoded.ok && !Object.hasOwn(decoded.value.header, "trust_chain"));
			assert.deepEqual(decoded.ok && decoded.value.payload.trust_chain, record.payload.trust_chain);
			assert.deepEqual(messages, ["Omitted Resolve responder chain to fit the JWS size limit"]);
			assert.strictEqual(outbound, before);

			const limitedResolver = limited.resolver;
			if (!limitedResolver) throw new Error("Expected the size-limited Resolver");
			const writesBefore = proofWrites;
			const fresh = await limitedResolver.resolve(resolveRequest(responder));
			assert.strictEqual(fresh.status, 200);
			const freshJwt = decodeEntityStatement(await fresh.text());
			assert.true(freshJwt.ok && !Object.hasOwn(freshJwt.value.header, "trust_chain"));
			assert.deepEqual(
				freshJwt.ok && freshJwt.value.payload.trust_chain,
				record.payload.trust_chain,
			);
			await limitedResolver.primeAnonymousResolve({ subject, trustAnchor: issuer });
			const primed = await get<ResolveAssessmentCacheValue>(key);
			assert.ok(
				primed && primed.reuseUntil > record.reuseUntil,
				"omitted chain does not shorten subject reuse",
			);
			assert.strictEqual(proofWrites, writesBefore, "oversized optional evidence is not written");
			assert.strictEqual(
				messages.length,
				3,
				"cached, fresh and primed signing all report the fallback",
			);
			await set(key, record, 12);
			before = outbound;

			let failedSignatures = 0;
			f.beforeResolveSigning(async () => {
				failedSignatures++;
				throw new Error("Signing unavailable");
			});
			assert.strictEqual((await leaf.handleRequest(resolveRequest(responder))).status, 500);
			assert.strictEqual(failedSignatures, 1);

			let signingCalls = 0;
			f.beforeResolveSigning(async () => {
				signingCalls++;
				if (signingCalls === 1) f.advance(8);
			});
			await expectHeader(undefined);
			assert.strictEqual(signingCalls, 2);
			f.beforeResolveSigning();
			f.advance(record.reuseUntil - f.clock.now() - 1.02);
			proofReadDelay = 45;
			await expectHeader(undefined, largerBudget);
			assert.deepEqual(proofDiagnostics.splice(0), [
				"Optional Resolve responder evidence budget expired",
			]);
			proofReadDelay = 0;
			f.advance(record.reuseUntil - f.clock.now() - 1);
			reads.length = 0;
			const nearExpiry = await largerBudget.handleRequest(resolveRequest(responder));
			assert.strictEqual(nearExpiry.status, 200);
			assert.deepEqual(reads, [key], "the remaining second is reserved for the subject response");
			f.advance(1);
			reads.length = 0;
			assert.strictEqual((await leaf.handleRequest(resolveRequest(responder))).status, 404);
			assert.deepEqual(reads, [key]);
			assert.strictEqual(outbound, before);
		});

		test("fresh Resolve only sends a responder chain that authenticates its actual signer", async (assert) => {
			const f = await createFixture();
			const host = await f.install();
			const responder = entityId("https://rollover-resolver.example");
			const [oldKey, newKey] = await Promise.all([generateSigningKey(), generateSigningKey()]);
			const previous = new SigningEntryFixture(oldKey.privateKey);
			const current = new SigningEntryFixture({ ...newKey.privateKey, kid: previous.kid });
			await host.registerSubordinate({ entityId: responder, jwks: previous.publishedJwks });
			let published: Leaf | undefined;
			const cacheResults: string[] = [];
			const proofCache = new MemoryCache({ clock: f.clock });
			const written = deferred();
			const setProof = proofCache.set.bind(proofCache);
			proofCache.set = async (cacheKey, value, ttl) => {
				await setProof(cacheKey, value, ttl);
				written.resolve();
			};
			const makeLeaf = (key: SigningEntryFixture, revision = "rollover") =>
				Leaf.create({
					entityId: responder,
					authorityHints: [issuer],
					crypto: { engine: testEngine, keyring: { entry: async () => key } },
					storage: f.storage,
					trustAnchors: f.trustAnchors,
					metadata: { federation_entity: { federation_resolve_endpoint: `${responder}/resolve` } },
					options: {
						clock: f.clock,
						resolverCache: cachePolicy(revision),
						resolveResponderEvidenceCache: proofCache,
						onResolverCacheResult(result) {
							cacheResults.push(result);
						},
						httpClient(input, init) {
							const request = new Request(input, init);
							return new URL(request.url).origin === responder && published
								? published.handleRequest(request)
								: f.httpClient(input, init);
						},
					},
					resolver: { requireAuthForFreshResolution: false },
				});
			published = await makeLeaf(previous);
			const original = await published.handleRequest(resolveRequest(responder));
			const decoded = decodeEntityStatement(await original.text());
			assert.true(decoded.ok && Array.isArray(decoded.value.header.trust_chain));
			await written.promise;

			const cached = await makeLeaf(current);
			const repeat = await cached.handleRequest(resolveRequest(responder));
			assert.strictEqual(repeat.status, 200);
			const repeated = decodeEntityStatement(await repeat.text());
			assert.true(repeated.ok && !Object.hasOwn(repeated.value.header, "trust_chain"));
			assert.deepEqual(cacheResults, ["miss", "hit"]);

			const live = await makeLeaf(current, "rollover-fresh");
			const rotated = await live.handleRequest(resolveRequest(responder));
			assert.strictEqual(rotated.status, 200);
			const jwt = await rotated.text();
			const reply = decodeEntityStatement(jwt);
			assert.true(reply.ok && !Object.hasOwn(reply.value.header, "trust_chain"));
			assert.true(
				(
					await verifyResolveResponse(jwt, current.publishedJwks, {
						engine: testEngine,
						clock: f.clock,
						expectedIssuer: responder,
						expectedSubject: subject,
					})
				).ok,
			);
		});

		test("withdrawals during signing or an assessment cache write prevent delivery", async (assert) => {
			const f = await createFixture();
			let mark = "";
			const host = await f.install({
				resolverCache: cachePolicy("revocation-race"),
				resolveTrustMarkCandidates: () => [mark],
			});
			const set = f.storage.cache.set.bind(f.storage.cache);
			let assessmentWrites = 0;
			let withdrawOnWrite = false;
			f.storage.cache.set = async (key, value, ttl) => {
				await set(key, value, ttl);
				if (key.startsWith("resolve:")) {
					assessmentWrites++;
					if (withdrawOnWrite) await host.revokeTrustMarkExact(mark);
				}
			};
			const prime = () => host.primeAnonymousResolve({ subject, trustAnchor: issuer });
			mark = await host.issueTrustMark(subject, markType, { ttlSeconds: 120 });
			f.beforeResolveSigning(() => host.revokeTrustMarkExact(mark));
			await assert.rejects(
				prime(),
				/HTTP 503 temporarily_unavailable.*Local Trust Mark evidence changed/,
			);
			assert.strictEqual(assessmentWrites, 0);
			f.beforeResolveSigning();
			f.advance(1);
			mark = await host.issueTrustMark(subject, markType, { ttlSeconds: 120, renewal: "renew" });
			withdrawOnWrite = true;
			await assert.rejects(prime(), /HTTP 503 temporarily_unavailable/);
			assert.strictEqual(assessmentWrites, 1);
			assert.strictEqual((await host.handleRequest(resolveRequest(issuer))).status, 404);
		});

		test("authorized Resolve is caller-scoped, survives reconstruction and primes public evidence independently", async (assert) => {
			const f = await createFixture();
			let evaluations = 0;
			let allow = true;
			let failPolicy = false;
			let workflow = "initial workflow";
			const cacheStages: string[] = [];
			const options: BoundFederationOptions = {
				resolverCache: {
					...cachePolicy("r1"),
					scope({ caller, subject: requested, trustAnchor, entityTypes }) {
						cacheStages.push(`${caller ?? "anonymous"}:${trustAnchor}:${entityTypes.join(",")}`);
						assert.strictEqual(requested, subject);
						return workflow;
					},
				},
				authorizeEndpointRequest({ endpoint, parameters, receiverEntityId, caller }) {
					assert.strictEqual(receiverEntityId, issuer);
					if (endpoint === "list") return caller === undefined;
					if (endpoint === "fetch") return caller === undefined || parameters.sub?.[0] === subject;
					if (endpoint !== "resolve") return true;
					assert.true(Object.isFrozen(parameters));
					assert.deepEqual(parameters.sub, [subject]);
					assert.notOk(parameters.client_assertion);
					assert.notOk(parameters.client_assertion_type);
					if (failPolicy) throw new Error("private diagnostics");
					return allow;
				},
				resolveTrustMarkCandidates() {
					evaluations++;
					return [];
				},
			};
			let host = await f.install(options);
			const fetchAsReviewer = async (requested: string) =>
				host.handleRequest(
					new Request(`${issuer}/fetch`, {
						method: "POST",
						body: new URLSearchParams({
							sub: requested,
							client_assertion: await f.assertion(callerA),
							client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE,
							client_id: callerA,
						}),
					}),
				);
			assert.strictEqual((await fetchAsReviewer(subject)).status, 200);
			assert.strictEqual((await fetchAsReviewer(callerA)).status, 401);
			const run = async (caller?: typeof callerA, types?: string[]) =>
				host.handleRequest(
					resolveRequest(issuer, caller ? await f.assertion(caller) : undefined, types),
				);
			const cold = f.readOutbound();
			assert.strictEqual((await run()).status, 404);
			assert.strictEqual(f.readOutbound(), cold, "a cold public miss does not discover");
			const firstJwt = await f.assertion(callerA);
			const first = await host.handleRequest(resolveRequest(issuer, firstJwt));
			assert.strictEqual(first.status, 200);
			assert.true(
				(
					await verifyResolveResponse(
						await first.text(),
						(
							await f.crypto.keyring.entry()
						).publishedJwks,
						{
							engine: testEngine,
							clock: f.clock,
							expectedIssuer: issuer,
							expectedSubject: subject,
							expectedAudience: callerA,
						},
					)
				).ok,
			);
			assert.strictEqual(evaluations, 1);
			const requestsBeforeReplay = cacheStages.length;
			assert.strictEqual((await host.handleRequest(resolveRequest(issuer, firstJwt))).status, 401);
			assert.strictEqual(
				(await host.handleRequest(resolveRequest(issuer, "not-a-jwt"))).status,
				401,
			);
			assert.strictEqual(cacheStages.length, requestsBeforeReplay);
			assert.strictEqual((await run(callerA)).status, 200);
			assert.strictEqual(evaluations, 1);
			const second = await run(callerB);
			assert.strictEqual(second.status, 200);
			const decoded = decodeEntityStatement(await second.text());
			assert.strictEqual(decoded.ok && decoded.value.payload.aud, callerB);
			assert.strictEqual(evaluations, 2);
			const forgedHeader = { "X-Authenticated-Entity": callerA };
			assert.strictEqual(
				(await host.handleRequest(resolveRequest(issuer, undefined, [], issuer, forgedHeader)))
					.status,
				404,
			);
			assert.strictEqual(evaluations, 2);
			assert.strictEqual((await run(callerA, ["oauth_resource"])).status, 200);
			assert.strictEqual((await run(callerA, ["oauth_resource"])).status, 200);
			assert.strictEqual(evaluations, 3);

			allow = false;
			const beforeDenied = cacheStages.length;
			assert.strictEqual((await run(callerA)).status, 401);
			assert.strictEqual(
				cacheStages.length,
				beforeDenied,
				"denied requests never select or access a cache partition",
			);
			failPolicy = true;
			assert.strictEqual((await run(callerA)).status, 500);
			assert.strictEqual(cacheStages.length, beforeDenied);
			allow = true;
			failPolicy = false;

			await host.primeAnonymousResolve({ subject, trustAnchor: issuer });
			assert.strictEqual(evaluations, 4);
			host = await f.install(options);
			const publicReply = await run();
			assert.strictEqual(publicReply.status, 200);
			const publicResult = decodeEntityStatement(await publicReply.text());
			assert.true(publicResult.ok && !Object.hasOwn(publicResult.value.payload, "aud"));
			assert.strictEqual((await run(callerA)).status, 200);
			assert.strictEqual(evaluations, 4);
			const newKeys = f.rotate();
			const afterRollover = await run(callerA);
			assert.true(
				(
					await verifyResolveResponse(await afterRollover.text(), newKeys, {
						engine: testEngine,
						clock: f.clock,
						expectedIssuer: issuer,
						expectedSubject: subject,
						expectedAudience: callerA,
					})
				).ok,
			);
			assert.strictEqual(evaluations, 4);
			workflow = "separate workflow";
			assert.strictEqual((await run(callerA)).status, 200);
			assert.strictEqual(evaluations, 5);
			const extraAnchor = await host.handleRequest(
				resolveRequest(issuer, await f.assertion(callerA), [], [issuer, alternativeAnchor]),
			);
			assert.strictEqual(extraAnchor.status, 200);
			assert.strictEqual(evaluations, 6);
			assert.true(cacheStages.some((entry) => entry === `${callerA}:${alternativeAnchor}:`));
			host = await f.install({ ...options, resolverCache: cachePolicy("r2") });
			assert.strictEqual((await run()).status, 404);
		});

		test("a matching revision from a replacement issuer store cannot revive a withdrawn cached mark", async (assert) => {
			const f = await createFixture();
			let mark = "";
			const options: BoundFederationOptions = {
				resolverCache: cachePolicy("issuer-restart"),
				resolveTrustMarkCandidates: () => [mark],
			};
			let host = await f.install(options);
			mark = await host.issueTrustMark(subject, markType, { ttlSeconds: 120 });
			const revision = await f.storage.trustMark.revision();
			await host.primeAnonymousResolve({ subject, trustAnchor: issuer });

			host = await f.install(options);
			const reused = await host.handleRequest(resolveRequest(issuer));
			assert.strictEqual(reused.status, 200, "restarting over the same store retains valid reuse");
			await host.revokeTrustMarkExact(mark);

			const replacementStore = {
				...memoryStorage({ clock: f.clock, trustMarks: true, collections: true }),
				cache: f.storage.cache,
			};
			host = await f.install(options, undefined, replacementStore);
			await host.issueTrustMark(callerA, markType, { ttlSeconds: 120 });
			assert.strictEqual(await replacementStore.trustMark.revision(), revision);
			assert.strictEqual(await replacementStore.trustMark.status(mark), undefined);
			const outbound = f.readOutbound();
			assert.strictEqual((await host.handleRequest(resolveRequest(issuer))).status, 404);
			assert.strictEqual(f.readOutbound(), outbound, "the rejected public hit does no discovery");
		});

		test("holder verification and chain selection survive a disclosure policy that withholds marks", async (assert) => {
			const f = await createFixture();
			const host = await f.install();
			const mark = await host.issueTrustMark(subject, markType, { ttlSeconds: 120 });
			await f.publishHeldMark(mark);
			let statusChecks = 0;
			for (const disclosure of ["default", "held", "withheld"] as const) {
				const resolver = await f.install(
					{
						chainSelection(chains) {
							const eligible = chains.find((chain) =>
								chain.trustMarks.some((candidate) => candidate.trustMarkType === markType),
							);
							if (!eligible) throw new Error("The chain selector did not receive a verified mark");
							return eligible;
						},
						...(disclosure === "default"
							? {}
							: {
									resolveTrustMarkCandidates({ held, verifiedHeld, chainExpiresAt }) {
										assert.deepEqual(held, [mark]);
										assert.deepEqual(verifiedHeld, [
											{
												ref: { trust_mark_type: markType, trust_mark: mark },
												mark: { issuer, expiresAt: f.clock.now() + 120 },
											},
										]);
										assert.true(Object.isFrozen(verifiedHeld[0]?.ref));
										assert.true(chainExpiresAt > f.clock.now() + 120);
										return disclosure === "held" ? held : [];
									},
								}),
					},
					undefined,
					undefined,
					() => statusChecks++,
				);
				const response = await resolver.handleRequest(
					resolveRequest(issuer, await f.assertion(callerA)),
				);
				assert.strictEqual(response.status, 200, disclosure);
				const decoded = decodeEntityStatement(await response.text());
				assert.true(decoded.ok);
				assert.deepEqual(
					decoded.ok && decoded.value.payload.trust_marks,
					disclosure === "withheld" ? undefined : [{ trust_mark_type: markType, trust_mark: mark }],
				);
			}
			assert.strictEqual(statusChecks, 3, "each request checks the held JWT once");
		});

		test("chain selection evidence alone cannot authorize a disclosure candidate under another trust context", async (assert) => {
			const f = await createFixture();
			const key = new SigningEntryFixture((await generateSigningKey()).privateKey);
			const mark = await signTrustMark({
				issuer: callerB,
				subject,
				trustMarkType: markType,
				signer: key,
				clock: f.clock,
			});
			await f.publishHeldMark(mark);
			const statusUrl = `${callerB}/status`;
			let statusChecks = 0;
			const host = await f.install({
				trustMarkVerification: {
					issuerEvidence: [
						{
							kind: "out-of-band",
							issuer: callerB,
							keys: key.publishedJwks,
							allowedTrustMarkTypes: [markType],
							metadata: { federation_trust_mark_status_endpoint: statusUrl },
						},
					],
				},
				chainSelection(chains) {
					const candidate = chains[0];
					if (!candidate) throw new Error("Missing candidate");
					assert.strictEqual(candidate.trustMarks.length, 1);
					return candidate;
				},
				resolveTrustMarkCandidates: ({ held }) => held,
				async httpClient(input, init) {
					const request = new Request(input, init);
					if (request.url !== statusUrl) return f.httpClient(input, init);
					statusChecks++;
					const jwt = await signEntityStatement(
						{ iss: callerB, iat: f.clock.now(), trust_mark: mark, status: "active" },
						key,
						{ typ: JwtTyp.TrustMarkStatusResponse },
					);
					return new Response(jwt, {
						headers: { "Content-Type": MediaType.TrustMarkStatusResponse },
					});
				},
			});
			await host.setTrustMarkIssuers({ [markType]: [callerB] });
			const response = await host.handleRequest(resolveRequest(issuer, await f.assertion(callerA)));
			assert.strictEqual(response.status, 200);
			const decoded = decodeEntityStatement(await response.text());
			assert.true(decoded.ok && decoded.value.payload.trust_marks === undefined);
			assert.strictEqual(statusChecks, 0);
		});

		test("fresh Resolve isolates local revision failures from requests without local evidence", async (assert) => {
			const f = await createFixture();
			const host = await f.install();
			const mark = await host.issueTrustMark(subject, markType, { ttlSeconds: 120 });
			let reads = 0;
			f.storage.trustMark.revision = async () => {
				reads++;
				throw new Error("local revision unavailable");
			};
			const query = async () =>
				host.handleRequest(resolveRequest(issuer, await f.assertion(callerA)));
			assert.strictEqual((await query()).status, 200);
			assert.strictEqual(reads, 0);
			await f.publishHeldMark(mark);
			await f.storage.cache.clear();
			const response = await query();
			assert.strictEqual(response.status, 200);
			const decoded = decodeEntityStatement(await response.text());
			assert.true(decoded.ok && decoded.value.payload.trust_marks === undefined);
			assert.strictEqual(reads, 1);
		});

		test("exact withdrawal invalidates warmed local evidence and preserves a replacement", async (assert) => {
			const f = await createFixture();
			let candidates: string[] = [];
			const host = await f.install({
				resolverCache: cachePolicy("marks"),
				resolveTrustMarkCandidates({ held }) {
					assert.deepEqual(held, []);
					return candidates;
				},
				resolveTrustMarkStatusMaxAge: () => 5,
			});
			const keys = (await f.crypto.keyring.entry()).publishedJwks;
			await host.setTrustMarkOwners({ [markType]: { sub: issuer, jwks: keys } });
			const firstDelegation = await host.issueTrustMarkDelegation(issuer, markType, {
				ttlSeconds: 50,
			});
			await host.setTrustMarkDelegations({ [markType]: firstDelegation });
			const older = await host.issueTrustMark(subject, markType, { ttlSeconds: 60 });
			f.advance(1);
			const nextDelegation = await host.issueTrustMarkDelegation(issuer, markType, {
				ttlSeconds: 40,
			});
			await host.setTrustMarkDelegations({ [markType]: nextDelegation });
			const replacement = await host.issueTrustMark(subject, markType, {
				ttlSeconds: 120,
				renewal: "renew",
			});
			const wrong = await host.issueTrustMark(callerA, markType, { ttlSeconds: 500 });
			candidates = [older, replacement, wrong];
			await host.primeAnonymousResolve({ subject, trustAnchor: issuer });
			const before = decodeEntityStatement(
				await (await host.handleRequest(resolveRequest(issuer))).text(),
			);
			assert.deepEqual(before.ok && before.value.payload.trust_marks, [
				{ trust_mark_type: markType, trust_mark: replacement },
			]);
			assert.strictEqual(before.ok && before.value.payload.exp, f.clock.now() + 120);

			await assert.rejects(host.revokeTrustMarkExact("unknown"), /Trust Mark not found/);
			await host.revokeTrustMarkExact(older);
			const revision = await f.storage.trustMark.revision();
			const withdrawnAt = f.clock.now();
			f.advance(1);
			await host.revokeTrustMarkExact(older);
			assert.strictEqual(await f.storage.trustMark.revision(), revision);
			assert.strictEqual((await f.storage.trustMark.status(older))?.revokedAt, withdrawnAt);
			assert.true((await f.storage.trustMark.status(replacement))?.active);
			const oldStatus = await host.handleRequest(
				new Request(`${issuer}/status`, {
					method: "POST",
					body: new URLSearchParams({ trust_mark: older }),
				}),
			);
			const checked = await verifyTrustMarkStatusResponse(
				await oldStatus.text(),
				(await f.crypto.keyring.entry()).publishedJwks,
				{
					engine: testEngine,
					clock: f.clock,
					expectedIssuer: issuer,
					expectedTrustMark: older,
				},
			);
			assert.strictEqual(checked.ok && checked.value.status, "revoked");
			const lastOutbound = f.readOutbound();
			assert.strictEqual((await host.handleRequest(resolveRequest(issuer))).status, 404);
			assert.strictEqual(f.readOutbound(), lastOutbound);
			await host.primeAnonymousResolve({ subject, trustAnchor: issuer });
			assert.strictEqual((await host.handleRequest(resolveRequest(issuer))).status, 200);
			f.advance(5);
			assert.strictEqual((await host.handleRequest(resolveRequest(issuer))).status, 404);
			f.advance(40);
			await host.primeAnonymousResolve({ subject, trustAnchor: issuer });
			const expired = decodeEntityStatement(
				await (await host.handleRequest(resolveRequest(issuer))).text(),
			);
			assert.true(expired.ok && !Object.hasOwn(expired.value.payload, "trust_marks"));
		});

		test("Leaf shares eligible cache evidence and keeps remote marks available during local revision failure", async (assert) => {
			const f = await createFixture();
			const host = await f.install();
			const resolver = entityId("https://local-mark-resolver.example");
			const key = new SigningEntryFixture((await generateSigningKey()).privateKey);
			const localStore = memoryStorage({ clock: f.clock, trustMarks: true });
			await host.registerSubordinate({ entityId: resolver, jwks: key.publishedJwks });
			await host.setTrustMarkIssuers({ [markType]: [issuer, resolver] });
			const remote = await host.issueTrustMark(subject, markType, { ttlSeconds: 120 });
			let candidates = [remote];
			let leaf: Leaf | undefined;
			const restore = (storage = localStore) =>
				Leaf.create({
					entityId: resolver,
					authorityHints: [issuer],
					crypto: { engine: testEngine, keyring: { entry: async () => key } },
					storage,
					trustAnchors: f.trustAnchors,
					metadata: { federation_entity: { federation_resolve_endpoint: `${resolver}/resolve` } },
					options: {
						clock: f.clock,
						httpClient(input, init) {
							const request = new Request(input, init);
							return new URL(request.url).origin === resolver && leaf
								? leaf.handleRequest(request)
								: f.httpClient(input, init);
						},
						resolverCache: cachePolicy("leaf-restart"),
						resolveTrustMarkCandidates: () => candidates,
					},
					resolver: {},
					trustMarkIssuer: {},
				});
			leaf = await restore();
			const local = await leaf.issueTrustMark(subject, markType, { ttlSeconds: 120 });
			const prime = () => {
				if (!leaf?.resolver) throw new Error("Missing Leaf resolver");
				return leaf.resolver.primeAnonymousResolve({ subject, trustAnchor: issuer });
			};
			const query = async () => {
				if (!leaf) throw new Error("Missing Leaf resolver");
				const response = await leaf.handleRequest(resolveRequest(resolver));
				assert.strictEqual(response.status, 200);
				const decoded = decodeEntityStatement(await response.text());
				return decoded.ok && decoded.value.payload.trust_marks;
			};
			const revision = localStore.trustMark.revision;
			let reads = 0;
			localStore.trustMark.revision = async () => {
				reads++;
				throw new Error("local revision unavailable");
			};
			const remoteRef = { trust_mark_type: markType, trust_mark: remote };
			await prime();
			assert.deepEqual(await query(), [remoteRef]);
			assert.strictEqual(reads, 0);
			candidates = [remote, local];
			await prime();
			assert.deepEqual(await query(), [remoteRef]);
			assert.strictEqual(reads, 1);

			localStore.trustMark.revision = revision;
			await prime();
			leaf = await restore();
			assert.deepEqual(await query(), [
				remoteRef,
				{ trust_mark_type: markType, trust_mark: local },
			]);
			await leaf.revokeTrustMarkExact(local);
			const replacement = {
				...memoryStorage({ clock: f.clock, trustMarks: true }),
				cache: localStore.cache,
			};
			leaf = await restore(replacement);
			await leaf.issueTrustMark(callerA, markType, { ttlSeconds: 120 });
			assert.strictEqual((await leaf.handleRequest(resolveRequest(resolver))).status, 404);
		});

		test("Leaf disclosure validates remote status for the exact mark and rejects the wrong trust context", async (assert) => {
			const f = await createFixture();
			const host = await f.install();
			const mark = await host.issueTrustMark(subject, markType, { ttlSeconds: 120 });
			const foreign = await generateSigningKey();
			const foreignMark = await signTrustMark({
				issuer: callerB,
				subject,
				trustMarkType: markType,
				signer: new SigningEntryFixture(foreign.privateKey),
				clock: f.clock,
			});
			const resolver = entityId("https://resolve-policy-leaf.example");
			const customStatus: { mode: "active" | "stale" | "wrong-jwt" } = { mode: "active" };
			let statusCalls = 0;
			let disclose = false;
			let hostAllows = true;
			let serviceAllows = true;
			const leaf = await Leaf.create({
				entityId: resolver,
				authorityHints: [issuer],
				crypto: f.crypto,
				trustAnchors: f.trustAnchors,
				metadata: { federation_entity: { federation_resolve_endpoint: `${resolver}/resolve` } },
				options: {
					clock: f.clock,
					authorizeEndpointRequest: () => hostAllows,
					httpClient: async (input, init) => {
						const request = new Request(input, init);
						const url = new URL(request.url);
						if (url.origin === resolver) return new Response(null, { status: 404 });
						if (url.href === `${issuer}/status`) {
							statusCalls++;
							if (customStatus.mode !== "active") {
								const jwt = await signEntityStatement(
									{
										iss: issuer,
										iat: f.clock.now() - (customStatus.mode === "stale" ? 6 : 0),
										trust_mark: customStatus.mode === "wrong-jwt" ? foreignMark : mark,
										status: "active",
									},
									await f.crypto.keyring.entry(),
									{ typ: JwtTyp.TrustMarkStatusResponse },
								);
								return new Response(jwt, {
									headers: { "Content-Type": MediaType.TrustMarkStatusResponse },
								});
							}
						}
						return f.httpClient(input, init);
					},
				},
				resolver: {
					requireAuthForFreshResolution: false,
					options: {
						authorizeEndpointRequest({ caller, endpoint }) {
							assert.strictEqual(caller, undefined);
							assert.strictEqual(endpoint, "resolve");
							return serviceAllows;
						},
						resolveTrustMarkCandidates: () => (disclose ? [foreignMark, mark] : []),
						resolveTrustMarkStatusMaxAge: () => 5,
					},
				},
			});
			const query = async () => {
				const response = await leaf.handleRequest(resolveRequest(resolver));
				assert.strictEqual(response.status, 200);
				const decoded = decodeEntityStatement(await response.text());
				assert.true(decoded.ok);
				return decoded.ok ? decoded.value.payload.trust_marks : undefined;
			};
			hostAllows = false;
			assert.strictEqual((await leaf.handleRequest(resolveRequest(resolver))).status, 401);
			hostAllows = true;
			serviceAllows = false;
			assert.strictEqual((await leaf.handleRequest(resolveRequest(resolver))).status, 401);
			serviceAllows = true;
			assert.strictEqual(await query(), undefined);
			assert.strictEqual(statusCalls, 0);
			disclose = true;
			assert.deepEqual(await query(), [{ trust_mark_type: markType, trust_mark: mark }]);
			assert.strictEqual(statusCalls, 1, "disqualified issuer never reaches status");
			customStatus.mode = "stale";
			assert.strictEqual(await query(), undefined);
			customStatus.mode = "wrong-jwt";
			assert.strictEqual(await query(), undefined);
		});
	});
}
