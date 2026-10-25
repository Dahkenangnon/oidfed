import type QUnit from "qunit";
import { MemoryStorageAdapter, TrustAnchor } from "../../../packages/authority/src/index.js";
import {
	decodeEntityStatement,
	entityId,
	FederationEntityMetadataSchema,
	fetchExtendedSubordinatesList,
	fetchSubordinateEvents,
	generateSigningKey,
	type HttpClient,
	JwkSigner,
	MediaType,
	SubordinateEventSchema,
	signEntityStatement,
	verifySubordinateEventsResponse,
} from "../../../packages/core/src/index.js";
import { Leaf } from "../../../packages/leaf/src/index.js";
import * as SubordinateEventsFixture from "../fixtures/subordinate-events.js";

export default function integrationTests(QUnit: QUnit): void {
	{
		const { issuer, subject, endpoint, fixture } = SubordinateEventsFixture;
		QUnit.module("Subordinate Events Draft 01", () => {
			for (const intermediate of [false, true]) {
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
							await tx.subordinateEvents?.append(issuer, subject, [
								{ iat: 6, event: "revocation" },
							]);
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
							(
								await fetchSubordinateEvents(endpoint + suffix, subject, {
									...f.options,
									httpClient,
								})
							).ok,
						);
						assert.false(
							(await fetchExtendedSubordinatesList(endpoint + suffix, undefined, { httpClient }))
								.ok,
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
		});
	}
}
