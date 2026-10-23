import type QUnit from "qunit";
import {
	type AuthorityConfig,
	Intermediate,
	MemoryStorageAdapter,
	type StorageAdapter,
	TrustAnchor,
} from "../../../packages/authority/src/index.js";
import {
	decodeEntityStatement,
	entityId,
	FederationEntityMetadataSchema,
	fetchExtendedSubordinatesList,
	fetchSubordinateEvents,
	generateSigningKey,
	type HttpClient,
	JwkSigner,
	JwtTyp,
	MediaType,
	MemoryFederationKeyProvider,
	SubordinateEventSchema,
	SubordinateEventsResponseSchema,
	signEntityStatement,
	verifySubordinateEventsResponse,
} from "../../../packages/core/src/index.js";
import { performFetch } from "../../../packages/core/src/trust-chain/fetch.js";
import { Leaf } from "../../../packages/leaf/src/index.js";

const issuer = entityId("https://authority.example/tenant");
const subject = entityId("https://subordinate.example:8443/client%20one");
const endpoint = "https://history.example:8443/events?version=1";

async function fixture(intermediate = false, authenticated = false) {
	const key = await generateSigningKey("ES256");
	const clientKey = await generateSigningKey("ES256");
	let now = 1500;
	const clock = { now: () => now };
	const storage = new MemoryStorageAdapter({ subordinateEvents: true, clock });
	const keyProvider = new MemoryFederationKeyProvider({
		signer: new JwkSigner(key.privateKey),
		publicJwk: key.publicKey,
	});
	const config: AuthorityConfig = {
		entityId: issuer,
		storage,
		keyProvider,
		options: { clock },
		metadata: {
			federation_entity: {
				federation_fetch_endpoint: `${issuer}/fetch`,
				federation_list_endpoint: `${issuer}/list`,
				federation_subordinate_events_endpoint: endpoint,
				...(authenticated
					? { federation_subordinate_events_endpoint_auth_methods: ["private_key_jwt"] }
					: {}),
			},
		},
		...(intermediate ? { authorityHints: [entityId("https://superior.example")] } : {}),
	};
	const authority = intermediate ? new Intermediate(config) : new TrustAnchor(config);
	const record = {
		entityId: subject,
		jwks: { keys: [clientKey.publicKey] },
		metadata: { openid_relying_party: { organization_name: "Client" } },
	};
	const httpClient: HttpClient = async (input, init) =>
		authority.handleRequest(new Request(String(input), init));
	const options = { issuer, issuerJwks: { keys: [key.publicKey] }, clock, httpClient };
	return {
		authority,
		storage,
		keyProvider,
		key,
		clientKey,
		record,
		config,
		options,
		clock,
		setNow: (value: number) => {
			now = value;
		},
	};
}

export default async function subordinateEventsTests(QUnit: QUnit): Promise<void> {
	QUnit.module("Subordinate Events Draft 01", () => {
		QUnit.test(
			"dedicated schemas preserve extension names, optional expiration, and NumericDates",
			(assert) => {
				const event = {
					iat: -0.5,
					event: "operator.custom",
					event_description: "Recorded observation",
					information_uri: "http://docs.example/events#details",
				};
				assert.true(SubordinateEventSchema.safeParse(event).success);
				assert.true(
					SubordinateEventsResponseSchema.safeParse({
						iss: issuer,
						sub: subject,
						iat: 1500.5,
						federation_registration_events: [event],
					}).success,
				);
				for (const invalid of [NaN, Infinity, -Infinity, "1000", null]) {
					assert.false(SubordinateEventSchema.safeParse({ ...event, iat: invalid }).success);
				}
				for (const bad of [
					{},
					{ iat: 1 },
					{ event: "registration" },
					{ iat: 1, event: 2 },
					{ ...event, event_description: 3 },
					{ ...event, information_uri: "relative" },
				]) {
					assert.false(SubordinateEventSchema.safeParse(bad).success);
				}
			},
		);

		for (const intermediate of [false, true]) {
			for (const withMetadata of [false, true]) {
				QUnit.test(
					`${intermediate ? "Intermediate" : "TrustAnchor"} snapshots pending registration ${withMetadata ? "with" : "without"} metadata`,
					async (assert) => {
						const f = await fixture(intermediate);
						let release!: () => void;
						const gate = new Promise<void>((resolve) => {
							release = resolve;
						});
						const blocker = f.storage.transaction(async () => gate);
						const { metadata, ...base } = structuredClone(f.record);
						const record = { ...base, ...(withMetadata ? { metadata } : {}) };
						const expected = structuredClone(record);
						const other = entityId("https://other.example");
						const pending = f.authority.registerSubordinate(record);
						record.entityId = other;
						record.jwks.keys.length = 0;
						if (record.metadata) record.metadata.openid_relying_party.organization_name = "Changed";
						release();
						await blocker;
						await pending;
						const stored = await f.storage.subordinates.get(subject);
						assert.deepEqual(stored?.jwks, expected.jwks);
						assert.deepEqual(stored?.metadata, expected.metadata);
						assert.strictEqual(await f.storage.subordinates.get(other), undefined);
						assert.deepEqual(await f.storage.subordinateEvents?.list(issuer, other), []);
						assert.deepEqual(
							(await f.storage.subordinateEvents?.list(issuer, subject))?.map((e) => e.event),
							["registration"],
						);
					},
				);
			}
			QUnit.test(
				`${intermediate ? "Intermediate" : "TrustAnchor"} captures changes and retains history`,
				async (assert) => {
					const f = await fixture(intermediate);
					await f.authority.registerSubordinate(f.record);
					await f.authority.updateSubordinate(subject, {
						metadata: { openid_relying_party: { organization_name: "Client" } },
					});
					assert.deepEqual(
						(await f.storage.subordinateEvents?.list(issuer, subject))?.map((e) => e.event),
						["registration"],
						"no-op update has no event",
					);
					const nextKey = await generateSigningKey("ES256");
					await f.authority.updateSubordinate(subject, {
						metadata: { openid_relying_party: { organization_name: "Renamed" } },
						metadataPolicy: { openid_relying_party: { organization_name: { value: "Policy" } } },
						jwks: { keys: [nextKey.publicKey, f.clientKey.publicKey] },
					});
					await f.authority.updateSubordinate(subject, {
						jwks: { keys: [f.clientKey.publicKey, nextKey.publicKey] },
					});
					await f.authority.recordSubordinateEvents(subject, [
						{ iat: -0.5, event: "suspension" },
						{ iat: 1500, event: "operator.custom" },
					]);
					assert.true(
						Boolean(await f.storage.subordinates.get(subject)),
						"recording suspension does not remove registration",
					);
					const history = await f.storage.subordinateEvents?.list(issuer, subject);
					assert.deepEqual(
						history?.map((e) => e.event),
						[
							"registration",
							"metadata_update",
							"metadata_policy_update",
							"jwks_update",
							"suspension",
							"operator.custom",
						],
					);
					assert.true(
						history?.slice(0, 4).every((e) => e.iat === 1500),
						"later operations retain legitimate equal timestamps",
					);
					await f.authority.revokeSubordinate(subject);
					assert.strictEqual(await f.storage.subordinates.get(subject), undefined);
					f.setNow(1600.5);
					const fetched = await fetchSubordinateEvents(endpoint, subject, f.options);
					assert.true(fetched.ok);
					if (fetched.ok) {
						assert.strictEqual(fetched.value.iat, 1600.5);
						assert.strictEqual(fetched.value.exp, undefined);
						assert.strictEqual(fetched.value.federation_registration_events[0]?.iat, 1500);
						assert.strictEqual(
							fetched.value.federation_registration_events.at(-1)?.event,
							"revocation",
						);
					}
					await f.authority.registerSubordinate(f.record);
					assert.strictEqual(
						(await f.storage.subordinateEvents?.list(issuer, subject))?.at(-1)?.event,
						"registration",
					);
				},
			);
		}

		QUnit.test(
			"authority signer rollover changes response keys without a subordinate update",
			async (assert) => {
				const f = await fixture();
				await f.authority.registerSubordinate(f.record);
				const before = await f.storage.subordinateEvents?.list(issuer, subject);
				const next = await generateSigningKey("ES256");
				const signer = new JwkSigner(next.privateKey);
				await f.keyProvider.publishKey({ signer, publicJwk: next.publicKey });
				await f.keyProvider.switchActiveKey(signer.kid);
				const jwt = await f.authority.getSubordinateEvents(subject);
				assert.true(
					(
						await verifySubordinateEventsResponse(
							jwt,
							{ keys: [next.publicKey] },
							{ issuer, subject, clock: f.clock },
						)
					).ok,
				);
				assert.false(
					(
						await verifySubordinateEventsResponse(jwt, f.options.issuerJwks, {
							issuer,
							subject,
							clock: f.clock,
						})
					).ok,
				);
				assert.deepEqual(await f.storage.subordinateEvents?.list(issuer, subject), before);
			},
		);

		QUnit.test(
			"history is detached, issuer scoped, independent of raw writes, and atomic",
			async (assert) => {
				const f = await fixture();
				await f.storage.subordinates.add({ ...f.record, createdAt: 1, updatedAt: 2 });
				let fetched = await fetchSubordinateEvents(endpoint, subject, f.options);
				assert.true(fetched.ok);
				if (fetched.ok)
					assert.deepEqual(
						fetched.value.federation_registration_events,
						[],
						"raw writes do not backfill events",
					);
				const events = f.storage.subordinateEvents;
				if (!events) throw new Error("Missing events storage");
				const input = { iat: 5, event: "registration", extra: { nested: 1 } };
				await events.append(issuer, subject, [input, input]);
				input.extra.nested = 999;
				const detached = await events.list(issuer, subject);
				const first = detached[0];
				if (!first) throw new Error("Expected a stored event");
				(first.extra as { nested: number }).nested = 42;
				assert.strictEqual(
					((await events.list(issuer, subject))[0]?.extra as { nested: number } | undefined)
						?.nested,
					1,
				);
				assert.strictEqual(
					(await events.list(issuer, subject)).length,
					2,
					"same timestamp and type are not deduplicated",
				);
				assert.deepEqual(await events.list(entityId("https://another.example"), subject), []);
				assert.deepEqual(await events.list(issuer, entityId("https://another.example")), []);
				await assert.rejects(
					f.storage.transaction(async (tx) => {
						await tx.subordinates.remove(subject);
						await tx.subordinateEvents?.append(issuer, subject, [{ iat: 6, event: "revocation" }]);
						throw new Error("rollback");
					}),
				);
				assert.true(Boolean(await f.storage.subordinates.get(subject)));
				assert.strictEqual((await events.list(issuer, subject)).length, 2);
				await f.storage.subordinates.remove(subject);
				fetched = await fetchSubordinateEvents(endpoint, subject, f.options);
				assert.true(fetched.ok, "history remains queryable after a raw removal");
				const missing = await fetchSubordinateEvents(
					endpoint,
					entityId("https://unknown.example"),
					f.options,
				);
				assert.false(missing.ok);
				if (!missing.ok) assert.strictEqual(missing.error.code, "not_found");
			},
		);

		QUnit.test(
			"missing transaction capability fails before mutation and failed appends roll back state",
			async (assert) => {
				const f = await fixture();
				const broken: StorageAdapter = {
					subordinates: f.storage.subordinates,
					subordinateEvents: f.storage.subordinateEvents,
					transaction: (operation) =>
						f.storage.transaction((tx) => operation({ subordinates: tx.subordinates })),
				};
				await assert.rejects(
					new TrustAnchor({ ...f.config, storage: broken }).registerSubordinate(f.record),
					/transaction-bound/,
				);
				assert.strictEqual(await f.storage.subordinates.get(subject), undefined);
				const failing: StorageAdapter = {
					...broken,
					transaction: (operation) =>
						f.storage.transaction((tx) =>
							operation({
								...tx,
								subordinateEvents: {
									list: async () => [],
									append: async () => {
										throw new Error("disk full");
									},
								},
							}),
						),
				};
				await assert.rejects(
					new TrustAnchor({ ...f.config, storage: failing }).registerSubordinate(f.record),
					/disk full/,
				);
				assert.strictEqual(await f.storage.subordinates.get(subject), undefined);
				assert.deepEqual(await f.storage.subordinateEvents?.list(issuer, subject), []);
			},
		);

		QUnit.test(
			"transaction retries commit only the successful attempt's events",
			async (assert) => {
				const f = await fixture();
				const retry = new Error("retry");
				let attempts = 0;
				const storage: StorageAdapter = {
					subordinates: f.storage.subordinates,
					subordinateEvents: f.storage.subordinateEvents,
					async transaction(operation) {
						try {
							await f.storage.transaction(async (tx) => {
								attempts++;
								await operation(tx);
								throw retry;
							});
						} catch (error) {
							if (error !== retry) throw error;
						}
						return f.storage.transaction((tx) => {
							attempts++;
							return operation(tx);
						});
					},
				};
				await new TrustAnchor({ ...f.config, storage }).registerSubordinate(f.record);
				assert.strictEqual(attempts, 2);
				assert.strictEqual((await f.storage.subordinateEvents?.list(issuer, subject))?.length, 1);
			},
		);

		QUnit.test(
			"authenticated POST uses Federation keys and authority identity as audience",
			async (assert) => {
				const f = await fixture(false, true);
				await f.authority.registerSubordinate(f.record);
				const assertion = (aud: string) =>
					signEntityStatement(
						{ iss: subject, sub: subject, aud, iat: 1500, exp: 1600, jti: crypto.randomUUID() },
						new JwkSigner(f.clientKey.privateKey),
						{ typ: "JWT" },
					);
				const valid = await fetchSubordinateEvents(endpoint, subject, {
					...f.options,
					clientAssertion: await assertion(issuer),
				});
				assert.true(valid.ok);
				for (const aud of [endpoint, "https://other.example"]) {
					const invalid = await fetchSubordinateEvents(endpoint, subject, {
						...f.options,
						clientAssertion: await assertion(aud),
					});
					assert.false(invalid.ok);
					if (!invalid.ok) assert.strictEqual(invalid.error.code, "invalid_client");
				}
				const get = await f.authority.handleRequest(
					new Request(`${endpoint}&sub=${encodeURIComponent(subject)}`),
				);
				assert.strictEqual(get.status, 405);
			},
		);

		QUnit.test("event capture can be enabled without publishing an HTTP route", async (assert) => {
			const f = await fixture();
			const authority = new TrustAnchor({
				...f.config,
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${issuer}/fetch`,
						federation_list_endpoint: `${issuer}/list`,
					},
				},
			});
			await authority.registerSubordinate(f.record);
			assert.strictEqual((await f.storage.subordinateEvents?.list(issuer, subject))?.length, 1);
			const response = await authority.handleRequest(
				new Request(`${endpoint}&sub=${encodeURIComponent(subject)}`),
			);
			assert.strictEqual(response.status, 404);
			const ec = decodeEntityStatement(await authority.getEntityConfiguration());
			assert.true(ec.ok);
			if (ec.ok)
				assert.strictEqual(
					ec.value.payload.metadata?.federation_entity?.federation_subordinate_events_endpoint,
					undefined,
				);
		});

		QUnit.test(
			"wire validation, advertised capability, leaf role checks, and sanitization",
			async (assert) => {
				const f = await fixture();
				for (const url of ["http://events.example", "https://events.example/#fragment"]) {
					assert.false(
						FederationEntityMetadataSchema.safeParse({
							federation_subordinate_events_endpoint: url,
						}).success,
					);
					assert.throws(
						() =>
							new TrustAnchor({
								...f.config,
								metadata: {
									federation_entity: {
										...f.config.metadata.federation_entity,
										federation_subordinate_events_endpoint: url,
									},
								},
							}),
					);
				}
				assert.throws(
					() => new TrustAnchor({ ...f.config, storage: new MemoryStorageAdapter() }),
					/subordinateEvents/,
				);
				assert.throws(
					() =>
						new TrustAnchor({
							...f.config,
							metadata: {
								federation_entity: {
									...f.config.metadata.federation_entity,
									federation_subordinate_events_endpoint: `${issuer}/list`,
								},
							},
						}),
					/route path/,
				);
				assert.throws(
					() =>
						new Leaf({
							entityId: subject,
							authorityHints: [issuer],
							keyProvider: f.keyProvider,
							metadata: { federation_entity: {} },
							roles: [
								{
									type: "federation_entity",
									metadata: { federation_subordinate_events_endpoint: endpoint },
								},
							],
						}),
					/subordinate_events/,
				);
				await f.authority.registerSubordinate({
					...f.record,
					metadata: {
						federation_entity: {
							federation_subordinate_events_endpoint: endpoint,
							federation_subordinate_events_endpoint_auth_methods: ["none"],
						},
					},
				});
				assert.strictEqual(
					(await f.storage.subordinates.get(subject))?.metadata,
					undefined,
					"operational-only metadata is omitted",
				);
				for (const query of [
					"",
					"&sub=invalid",
					`&sub=${encodeURIComponent(subject)}&sub=${encodeURIComponent(subject)}`,
				]) {
					const response = await f.authority.handleRequest(new Request(endpoint + query));
					assert.strictEqual(response.status, 400);
					assert.strictEqual(response.headers.get("content-type"), MediaType.Json);
					const error = (await response.json()) as { error: string; error_description: string };
					assert.strictEqual(error.error, "invalid_request");
					assert.strictEqual(typeof error.error_description, "string");
				}
				const ec = decodeEntityStatement(await f.authority.getEntityConfiguration());
				assert.true(ec.ok);
				if (ec.ok)
					assert.strictEqual(
						ec.value.payload.metadata?.federation_entity?.federation_subordinate_events_endpoint,
						endpoint,
					);
				const result = await fetchSubordinateEvents(endpoint, subject, {
					...f.options,
					httpClient: async (url, init) => {
						const parsed = new URL(String(url));
						assert.strictEqual(parsed.searchParams.get("version"), "1");
						assert.strictEqual(parsed.searchParams.get("sub"), subject);
						const response = await f.options.httpClient(url, init);
						assert.strictEqual(response.status, 200);
						assert.strictEqual(
							response.headers.get("content-type"),
							MediaType.EntityEventsStatement,
						);
						return response;
					},
				});
				assert.true(result.ok);
			},
		);

		QUnit.test(
			"verification binds the issuer, subject, key, JWT type, and expiration",
			async (assert) => {
				const f = await fixture();
				await f.authority.registerSubordinate(f.record);
				const jwt = await f.authority.getSubordinateEvents(subject);
				const opts = { issuer, subject, clock: f.clock, clockSkewSeconds: 0 };
				assert.true((await verifySubordinateEventsResponse(jwt, f.options.issuerJwks, opts)).ok);
				assert.false(
					(
						await verifySubordinateEventsResponse(jwt, f.options.issuerJwks, {
							...opts,
							issuer: entityId("https://other.example"),
						})
					).ok,
				);
				assert.false(
					(
						await verifySubordinateEventsResponse(jwt, f.options.issuerJwks, {
							...opts,
							subject: issuer,
						})
					).ok,
				);
				assert.false(
					(await verifySubordinateEventsResponse(jwt, { keys: [f.clientKey.publicKey] }, opts)).ok,
				);
				const payload = {
					iss: issuer,
					sub: subject,
					iat: 1400,
					federation_registration_events: [
						{ iat: -0.5, event: "custom", information_uri: "http://docs.example/#event" },
					],
				};
				for (const [body, typ, expected] of [
					[payload, JwtTyp.EntityEventsStatement, true],
					[{ ...payload, exp: 1600 }, JwtTyp.EntityEventsStatement, true],
					[{ ...payload, exp: 1499 }, JwtTyp.EntityEventsStatement, false],
					[payload, JwtTyp.EntityStatement, false],
					[
						{ ...payload, federation_registration_events: null },
						JwtTyp.EntityEventsStatement,
						false,
					],
				] as const) {
					const signed = await signEntityStatement(body, new JwkSigner(f.key.privateKey), { typ });
					assert.strictEqual(
						(await verifySubordinateEventsResponse(signed, f.options.issuerJwks, opts)).ok,
						expected,
					);
				}
				const parts = jwt.split(".");
				for (const alg of ["none", "HS256"]) {
					const header = btoa(
						JSON.stringify({ alg, typ: JwtTyp.EntityEventsStatement, kid: "untrusted" }),
					)
						.replace(/=/g, "")
						.replace(/\+/g, "-")
						.replace(/\//g, "_");
					assert.false(
						(
							await verifySubordinateEventsResponse(
								`${header}.${parts[1]}.signature`,
								f.options.issuerJwks,
								opts,
							)
						).ok,
					);
				}
				const wrongStatus = await fetchSubordinateEvents(endpoint, subject, {
					...f.options,
					httpClient: async () =>
						new Response(jwt, {
							status: 201,
							headers: { "content-type": MediaType.EntityEventsStatement },
						}),
				});
				assert.false(wrongStatus.ok, "a valid JWT with a non-200 success status is rejected");
				parts[1] = (parts[1] ?? "").replace(/^./, (c) => (c === "a" ? "b" : "a"));
				assert.false(
					(await verifySubordinateEventsResponse(parts.join("."), f.options.issuerJwks, opts)).ok,
				);
			},
		);

		QUnit.test(
			"events set a redirect rejection policy without changing existing fetch clients",
			async (assert) => {
				const f = await fixture();
				for (const clientAssertion of [undefined, "synthetic-assertion"]) {
					let calls = 0;
					const result = await fetchSubordinateEvents(endpoint, subject, {
						...f.options,
						...(clientAssertion === undefined ? {} : { clientAssertion }),
						httpClient: async (_url, init) => {
							calls++;
							assert.strictEqual(init?.redirect, "manual");
							return new Response(null, {
								status: 307,
								headers: { location: "http://127.0.0.1/history" },
							});
						},
					});
					assert.false(result.ok);
					assert.strictEqual(calls, 1);
				}
				const httpClient: HttpClient = async (_url, init) => {
					assert.strictEqual(
						init?.redirect,
						undefined,
						"legacy callers retain Fetch's default redirect policy",
					);
					return new Response("{}", { headers: { "content-type": MediaType.Json } });
				};
				assert.true((await performFetch(endpoint, { httpClient, accept: MediaType.Json })).ok);
				assert.true(
					(
						await fetchExtendedSubordinatesList(endpoint, undefined, {
							httpClient: async (url, init) => {
								await httpClient(url, init);
								return new Response('{"immediate_subordinate_entities":[]}', {
									headers: { "content-type": MediaType.Json },
								});
							},
						})
					).ok,
				);
			},
		);

		QUnit.test(
			"endpoint fragment rejection preserves encoded characters and event information URLs",
			async (assert) => {
				const f = await fixture();
				for (const field of [
					"federation_fetch_endpoint",
					"federation_list_endpoint",
					"federation_extended_list_endpoint",
					"federation_subordinate_events_endpoint",
				] as const) {
					for (const suffix of ["#", "#details"]) {
						const value = `https://history.example/path${suffix}`;
						assert.false(FederationEntityMetadataSchema.safeParse({ [field]: value }).success);
						assert.throws(
							() =>
								new TrustAnchor({
									...f.config,
									metadata: {
										federation_entity: { ...f.config.metadata.federation_entity, [field]: value },
									},
								}),
							/without fragment/,
						);
					}
					assert.true(
						FederationEntityMetadataSchema.safeParse({
							[field]: "https://history.example:8443/path%23part?value=%23&tenant=one",
						}).success,
					);
				}
				for (const suffix of ["#", "#details"]) {
					let calls = 0;
					const httpClient: HttpClient = async () => {
						calls++;
						return new Response(null);
					};
					assert.false(
						(await fetchSubordinateEvents(endpoint + suffix, subject, { ...f.options, httpClient }))
							.ok,
					);
					assert.false(
						(await fetchExtendedSubordinatesList(endpoint + suffix, undefined, { httpClient })).ok,
					);
					assert.strictEqual(calls, 0);
				}
				assert.true(
					SubordinateEventSchema.safeParse({
						iat: 1,
						event: "custom",
						information_uri: "http://info.example/#details",
					}).success,
				);
			},
		);

		QUnit.test("method errors are Federation errors only on the events route", async (assert) => {
			for (const methods of [undefined, ["private_key_jwt"], ["none", "private_key_jwt"]]) {
				const f = await fixture();
				const authority = new TrustAnchor({
					...f.config,
					metadata: {
						federation_entity: {
							...f.config.metadata.federation_entity,
							...(methods ? { federation_subordinate_events_endpoint_auth_methods: methods } : {}),
						},
					},
				});
				const allow = methods?.includes("none") ? "GET, POST" : methods ? "POST" : "GET";
				const disallowed = methods?.includes("none")
					? ["PUT"]
					: methods
						? ["GET", "PUT"]
						: ["POST", "PUT"];
				for (const method of disallowed) {
					const response = await authority.handleRequest(new Request(endpoint, { method }));
					assert.strictEqual(response.status, 405);
					assert.strictEqual(response.headers.get("allow"), allow);
					assert.strictEqual(response.headers.get("content-type"), MediaType.Json);
					assert.strictEqual(response.headers.get("cache-control"), "no-store");
					const body = (await response.json()) as { error: string; error_description: string };
					assert.strictEqual(body.error, "invalid_request");
					assert.strictEqual(typeof body.error_description, "string");
				}
				const legacy = await authority.handleRequest(
					new Request(`${issuer}/list`, { method: "PUT" }),
				);
				assert.strictEqual(legacy.status, 405);
				assert.deepEqual(await legacy.json(), { error: "method_not_allowed" });
			}
		});

		QUnit.test(
			"shared transport bounds stalled and oversized bodies and cancels discarded responses",
			async (assert) => {
				const f = await fixture();
				for (const throughEvents of [false, true]) {
					let cancelled = 0;
					const httpClient: HttpClient = async () =>
						new Response(
							new ReadableStream({
								cancel() {
									cancelled++;
								},
							}),
							{
								headers: {
									"content-type": throughEvents
										? MediaType.EntityEventsStatement
										: MediaType.EntityStatement,
								},
							},
						);
					const result = throughEvents
						? await fetchSubordinateEvents(endpoint, subject, {
								...f.options,
								httpClient,
								httpTimeoutMs: 20,
							})
						: await performFetch(endpoint, { httpClient, httpTimeoutMs: 20 });
					assert.false(result.ok);
					if (!result.ok) assert.strictEqual(result.error.code, "ERR_TIMEOUT");
					assert.strictEqual(cancelled, 1);
					const tooBig = await performFetch(endpoint, {
						maxResponseBytes: 2,
						httpClient: async () =>
							new Response("large", { headers: { "content-type": MediaType.EntityStatement } }),
					});
					assert.false(tooBig.ok);
				}
				for (const [status, type] of [
					[500, MediaType.EntityStatement],
					[200, MediaType.Json],
				] as const) {
					let cancelled = false;
					const response = await performFetch(endpoint, {
						httpClient: async () =>
							new Response(
								new ReadableStream({
									cancel() {
										cancelled = true;
										throw new Error("cancel failed");
									},
								}),
								{ status, headers: { "content-type": type } },
							),
					});
					assert.false(response.ok);
					assert.true(cancelled);
					if (!response.ok) assert.strictEqual(response.error.code, "ERR_NETWORK");
				}
			},
		);
	});
}
