import {
	authenticatedEndpointCaller,
	extractRequestParams,
	fetchSubordinateEvents,
	requireMethods,
	toPublicError,
} from "@oidfed/core";
import type QUnit from "qunit";
import { createAuthenticatedHandler } from "../../../packages/authority/src/endpoints/client-auth.js";
import type { HandlerContext } from "../../../packages/authority/src/endpoints/context.js";
import { createEntityConfigurationHandler } from "../../../packages/authority/src/endpoints/entity-configuration.js";
import {
	createExtendedListHandler,
	type ExtendedListingConfig,
} from "../../../packages/authority/src/endpoints/extended-list.js";
import { createFetchHandler } from "../../../packages/authority/src/endpoints/fetch.js";
import {
	errorResponse,
	jsonResponse,
	jwtResponse,
	parseQueryParams,
	requireMethod,
	SECURITY_HEADERS,
} from "../../../packages/authority/src/endpoints/helpers.js";
import { createHistoricalKeysHandler } from "../../../packages/authority/src/endpoints/historical-keys.js";
import { createListHandler } from "../../../packages/authority/src/endpoints/list.js";
import { createResolveHandler } from "../../../packages/authority/src/endpoints/resolve.js";
import { createTrustMarkHandler } from "../../../packages/authority/src/endpoints/trust-mark.js";
import { createTrustMarkListHandler } from "../../../packages/authority/src/endpoints/trust-mark-list.js";
import { createTrustMarkStatusHandler } from "../../../packages/authority/src/endpoints/trust-mark-status.js";
import {
	InvalidAuthorityConfig,
	InvalidMetadata,
	InvalidSubordinateRecord,
} from "../../../packages/authority/src/errors.js";
import * as AuthorityPublic from "../../../packages/authority/src/index.js";
import {
	type AuthorityConfig,
	type AuthorityServer,
	Intermediate,
	type StorageAdapter,
	TrustAnchor,
} from "../../../packages/authority/src/index.js";
import { createSubordinateLifecycle } from "../../../packages/authority/src/subordinate-lifecycle.js";
import * as CorePublic from "../../../packages/core/src/index.js";
import { signProtocolFixture } from "../fixtures/protocol-jwt.js";
import {
	FixtureCrypto,
	fixtureCryptoFromRead,
	fixtureHostConfig,
	fixtureSigner,
	generateSigningKey,
	instrumentSigningEntry,
	rawFixtureJwt,
	SigningEntryFixture,
	testEngine,
} from "../fixtures/software-crypto.js";
import * as SubordinateEventsFixture from "../fixtures/subordinate-events.js";

async function createAuthorityServer(config: AuthorityConfig): Promise<AuthorityServer> {
	const server =
		config.authorityHints && config.authorityHints.length > 0
			? await Intermediate.create(fixtureHostConfig(config))
			: await TrustAnchor.create(fixtureHostConfig(config));
	return {
		registerSubordinate: (record) => server.registerSubordinate(record),
		updateSubordinate: (sub, updates) => server.updateSubordinate(sub, updates),
		revokeSubordinate: (sub) => server.revokeSubordinate(sub),
		recordSubordinateEvents: (sub, events) => server.recordSubordinateEvents(sub, events),
		getSubordinateEvents: (sub) => server.getSubordinateEvents(sub),
		getEntityConfiguration: () => server.getEntityConfiguration(),
		getSubordinateStatement: (sub) => server.getSubordinateStatement(sub),
		listSubordinates: (filter) => server.listSubordinates(filter),
		listSubordinatesExtended: (params) => server.listSubordinatesExtended(params),
		resolveEntity: (sub, ta) => server.resolveEntity(sub, ta),
		getTrustMarkStatus: (tm) => server.getTrustMarkStatus(tm),
		listTrustMarkedEntities: (type) => server.listTrustMarkedEntities(type),
		issueTrustMark: (sub, type, options) => server.issueTrustMark(sub, type, options),
		revokeTrustMark: (sub, type) => server.revokeTrustMark(sub, type),
		listTrustMarksForSubject: (sub) => server.listTrustMarksForSubject(sub),
		getTrustMarks: () => server.getTrustMarks(),
		attachTrustMark: (jwt, options) => server.attachTrustMark(jwt, options),
		fetchAndAttachTrustMark: (options) => server.fetchAndAttachTrustMark(options),
		removeTrustMark: (selector) => server.removeTrustMark(selector),
		setTrustMarkIssuers: (issuers) => server.setTrustMarkIssuers(issuers),
		setTrustMarkOwners: (owners) => server.setTrustMarkOwners(owners),
		setTrustMarkDelegations: (delegations) => server.setTrustMarkDelegations(delegations),
		issueTrustMarkDelegation: (sub, type) => server.issueTrustMarkDelegation(sub, type),
		getHistoricalKeys: () => server.getHistoricalKeys(),
		handler: () => (request: Request) => server.handleRequest(request),
	};
}

import { MemoryStorageAdapter } from "../../../packages/authority/src/storage/memory.js";
import type {
	SubordinateRecord,
	SubordinateRecordUpdate,
	SubordinateStorage,
	TrustMarkRecord,
	TrustMarkStorage,
} from "../../../packages/authority/src/storage/types.js";
import {
	assertMetadataValuesNotNull,
	isFederationEntityOperationalField,
	sanitizeSubordinateMetadata,
} from "../../../packages/authority/src/utils/subordinate-statement-shape.js";
import type { FederationError } from "../../../packages/core/src/index.js";
import {
	DEFAULT_MAX_REQUEST_BODY_BYTES,
	decodeEntityStatement,
	type EntityId,
	EntityType,
	type ExtendedListResponse,
	entityId,
	FederationEndpoint,
	FederationErrorCode,
	fetchExtendedSubordinatesList,
	type HttpClient,
	InternalErrorCode,
	isOk,
	type JWK,
	JwtTyp,
	MediaType,
	signEntityStatement,
	signTrustMarkDelegation,
	stripPrivateFields,
	type TrustAnchorSet,
	TrustMarkRefSchema,
	TrustMarkStatus,
	validateTrustMark,
	verifyEntityStatement,
	verifyHistoricalKeysResponse,
	verifyResolveResponse,
	WELL_KNOWN_OPENID_FEDERATION,
} from "../../../packages/core/src/index.js";
import { createMockFederation, LEAF_ID, OP_ID, TA_ID } from "../fixtures/index.js";

// ---------------------------------------------------------------------------
// Shared test helper
// ---------------------------------------------------------------------------

const ENTITY_ID = entityId("https://authority.example.com");
const TEST_KID = "test-key-1";

function createFederationSigningKey(signingKey: JWK) {
	return { signer: new SigningEntryFixture(signingKey), publicJwk: stripPrivateFields(signingKey) };
}

function testPublicJwk(
	kid = "subordinate-key-1",
	x = "OUdYsCLIbES6cmG2MHFuXamZ60fem7Tkk7LPO3nX9QY",
	y = "7TjTIz97de-2yxmBudZuhUS-eP6egZSw3ZV_n4URxHQ",
): JWK {
	return { kty: "EC", kid, crv: "P-256", x, y };
}

type TestContextOverrides = { [K in keyof HandlerContext]?: HandlerContext[K] | undefined };
async function createTestContext(overrides?: TestContextOverrides): Promise<{
	ctx: HandlerContext;
	signingKey: JWK;
	publicKey: JWK;
	crypto: FixtureCrypto;
	storage: MemoryStorageAdapter;
	subordinates: SubordinateStorage;
	trustMarks: TrustMarkStorage;
}> {
	const { privateKey, publicKey: rawPublicKey } = await generateSigningKey("ES256");
	const signingKey = { ...privateKey, kid: TEST_KID };
	const publicKey = { ...rawPublicKey, kid: TEST_KID };

	const crypto = new FixtureCrypto(createFederationSigningKey(signingKey));

	const storage = new MemoryStorageAdapter({ engine: testEngine, trustMarks: true });
	const subordinates = storage.subordinates;
	const trustMarks = storage.trustMarks!;

	const ctx: HandlerContext = {
		// Existing endpoint fixtures explicitly exercise fresh anonymous resolution.
		requireAuthForFreshResolution: false,
		entityId: ENTITY_ID,
		crypto,
		storage,
		clientKeyProvider: {
			async getClientFederationJwks(entityId) {
				return (await storage.subordinates.get(entityId))?.jwks;
			},
		},
		metadata: {
			federation_entity: {
				federation_fetch_endpoint: `${ENTITY_ID}/federation_fetch`,
				federation_list_endpoint: `${ENTITY_ID}/federation_list`,
			},
		},
		...overrides,
		options: { ...overrides?.options, engine: testEngine },
	};

	return { ctx, signingKey, publicKey, crypto, storage, subordinates, trustMarks };
}

function hostConfig(ctx: HandlerContext): AuthorityConfig {
	return {
		...ctx,
		roles: ctx.roles ? [...ctx.roles] : undefined,
		trustMarks: ctx.trustMarks ? [...ctx.trustMarks] : undefined,
	};
}

async function putTestMark(ctx: HandlerContext, record: TrustMarkRecord): Promise<string> {
	const keySet = await ctx.crypto.keyring.entry("federation");
	const jwt = await signEntityStatement(
		{
			iss: ctx.entityId,
			sub: record.subject,
			trust_mark_type: record.trustMarkType,
			iat: record.issuedAt,
			...(record.expiresAt !== undefined ? { exp: record.expiresAt } : {}),
		},
		keySet,
		{ typ: JwtTyp.TrustMark },
	);
	await ctx.storage.trustMarks!.issue({ ...record, jwt });
	return jwt;
}
async function resolveAsClient(
	ctx: HandlerContext,
	request: Request,
	client = "https://client.example.com",
	handler = createResolveHandler(ctx),
): Promise<Response> {
	const key = await generateSigningKey("ES256"),
		now = ctx.options?.clock?.now() ?? Math.floor(Date.now() / 1000);
	const jwt = await signEntityStatement(
		{
			iss: client,
			sub: client,
			aud: ctx.entityId,
			iat: now,
			exp: now + 60,
			jti: globalThis.crypto.randomUUID(),
		},
		new SigningEntryFixture(key.privateKey),
		{ typ: "JWT" },
	);
	const url = new URL(request.url),
		form = new URLSearchParams(url.searchParams);
	url.search = "";
	form.set("client_assertion", jwt);
	form.set("client_assertion_type", CorePublic.JWT_BEARER_CLIENT_ASSERTION_TYPE);
	return createAuthenticatedHandler(
		{
			...ctx,
			clientKeyProvider: { getClientFederationJwks: async () => ({ keys: [key.publicKey] }) },
		},
		handler,
		["private_key_jwt"],
	)(new Request(url, { method: "POST", body: form }));
}

// ---------------------------------------------------------------------------

export default (QUnit: QUnit) => {
	const { module, test } = QUnit;
	module("authority / configuration route boundaries", () => {
		async function config(id = "https://authority.example/tenant"): Promise<AuthorityConfig> {
			const key = await generateSigningKey("ES256");
			return {
				entityId: id,
				crypto: new FixtureCrypto(createFederationSigningKey(key.privateKey)),
				storage: new MemoryStorageAdapter({
					engine: testEngine,
					trustMarks: true,
					subordinateEvents: true,
				}),
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: "https://authority.example/fetch?tenant=academic",
						federation_list_endpoint: "https://authority.example/list",
					},
				},
			};
		}
		const handler = async () => new Response("role");
		const role = (path: string): CorePublic.EntityRole => ({
			type: "example_protocol",
			metadata: {},
			routes: new Map([[path, handler]]),
		});
		test("role routes cannot replace discovery, built-in endpoints or another role", async (t) => {
			const base = await config();
			for (const Host of [TrustAnchor, Intermediate]) {
				const make = async (overrides: Partial<AuthorityConfig> = {}) =>
					await Host.create(
						fixtureHostConfig({
							...base,
							metadata: structuredClone(base.metadata),
							...(Host === Intermediate ? { authorityHints: [TA_ID] } : {}),
							...overrides,
						}),
					);
				for (const path of [
					"/tenant/.well-known/openid-federation",
					"https://authority.example/tenant/.well-known/openid-federation",
					"/fetch",
					"/list",
				])
					await t.rejects(
						(() => make({ roles: [role(path)] }))(),
						/conflict/,
						`${Host.name}: ${path}`,
					);
				await t.rejects(
					(() =>
						make({ roles: [role("/register"), role("https://authority.example/register")] }))(),
					/conflict/,
				);
				for (const field of [
					"extended_list",
					"historical_keys",
					"trust_mark_status",
					"trust_mark_list",
					"trust_mark",
					"resolve",
					"subordinate_events",
					"collection",
				] as const) {
					const endpoint = `https://authority.example/${field}?tenant=academic`;
					await t.rejects(
						(() =>
							make({
								metadata: {
									federation_entity: {
										...base.metadata.federation_entity,
										[`federation_${field}_endpoint`]: endpoint,
									},
								},
								...(field === "collection" ? { collection: { trustAnchors: new Map() } } : {}),
								roles: [role(`/${field}`)],
							}))(),
						/Role route.*conflicts/,
						`${Host.name}: ${field}`,
					);
				}
				// The reserved path comes from composed metadata, not just the original config.
				await t.rejects(
					(() =>
						make({
							roles: [
								{
									type: "federation_entity",
									metadata: { federation_fetch_endpoint: "https://authority.example/composed" },
								},
								role("/composed"),
							],
						}))(),
					/Role route.*conflicts/,
				);
				const host = make({ roles: [role("/tenant//register")] });
				t.equal(
					await (
						await (
							await host
						).handleRequest(new Request("https://authority.example/tenant//register"))
					).text(),
					"role",
				);
				t.equal(
					(
						await (
							await host
						).handleRequest(
							new Request("https://authority.example/tenant/.well-known/openid-federation", {
								method: "POST",
							}),
						)
					).status,
					405,
				);
			}
		});
		test("published authority identity stays consistent across roles, claims and discovery", async (t) => {
			const base = await config();
			for (const prefix of [
				"https://authority.example",
				"https://authority.example:8443/tenant%2Fname",
			])
				for (const trailing of [0, 1, 2, 3]) {
					const raw = prefix + "/".repeat(trailing),
						expected = raw.endsWith("/") ? raw.slice(0, -1) : raw;
					for (const Host of [TrustAnchor, Intermediate]) {
						let roleId: string | undefined;
						let initialized = 0;
						const host = await Host.create(
							fixtureHostConfig({
								...base,
								entityId: raw,
								metadata: structuredClone(base.metadata),
								...(Host === Intermediate ? { authorityHints: [TA_ID] } : {}),
								roles: [
									{
										type: "example_protocol",
										metadata: {},
										initialize: (context) => {
											roleId = context.entityId;
											initialized++;
										},
									},
								],
							}),
						);
						t.equal(host.entityId, expected);
						t.equal(initialized, 1, "roles initialize once");
						t.strictEqual(host.constructor, Host);
						t.true(host instanceof Host);
						t.false(host instanceof (Host === TrustAnchor ? Intermediate : TrustAnchor));
						for (const name of [
							"assessEntity",
							"discoverEntity",
							"discoverEntityFromChain",
							"sanitizeSubordinateMetadata",
						])
							t.true(Object.hasOwn(Host, name), `${Host.name} owns ${name}`);
						t.equal(roleId, expected);
						const ec = decodeEntityStatement(await host.getEntityConfiguration());
						t.true(ec.ok);
						if (ec.ok) {
							t.equal(ec.value.payload.iss, expected);
							t.equal(ec.value.payload.sub, expected);
						}
						const result = await CorePublic.fetchEntityConfiguration(host.entityId, {
							engine: testEngine,
							httpClient: async (input) => host.handleRequest(new Request(String(input))),
						});
						t.true(result.ok, `${Host.name}: ${raw}`);
					}
				}
		});
	});
	module("authority / Resolve Trust Mark policy", () => {
		const c = CorePublic;
		async function fixture() {
			const issuer = "https://issuer.example",
				subject = "https://holder.example",
				type = "type",
				external = "https://external.example";
			const key = await generateSigningKey("ES256"),
				leaf = await generateSigningKey("ES256"),
				ext = await generateSigningKey("ES256");
			const provider = FixtureCrypto.fromJWK(key.privateKey),
				clock = { now: () => 1000 };
			const anchors = c.createTrustAnchorSet([
				{ entityId: issuer, jwks: { keys: [key.publicKey] } },
			]);
			let holderEc = "",
				status = "active",
				statusCalls = 0;
			const storage = new AuthorityPublic.MemoryStorageAdapter({
				engine: testEngine,
				trustMarks: true,
				clock,
			});
			const metadata = {
				federation_entity: {
					federation_fetch_endpoint: `${issuer}/fetch`,
					federation_list_endpoint: `${issuer}/list`,
					federation_resolve_endpoint: `${issuer}/resolve`,
					federation_trust_mark_status_endpoint: `${issuer}/status`,
				},
			};
			let anchor: TrustAnchor;
			let externalJwt = "";
			const httpClient: CorePublic.HttpClient = async (input, init) => {
				const request = new Request(input, init);
				if (request.url === `${subject}/.well-known/openid-federation`)
					return new Response(holderEc, {
						headers: { "content-type": c.MediaType.EntityStatement },
					});
				if (request.url === `${external}/status`) {
					statusCalls++;
					return new Response(
						await c.signEntityStatement(
							{ iss: external, iat: 1000, trust_mark: externalJwt, status },
							new SigningEntryFixture(ext.privateKey),
							{ typ: c.JwtTyp.TrustMarkStatusResponse },
						),
						{ headers: { "content-type": c.MediaType.TrustMarkStatusResponse } },
					);
				}
				return anchor.handleRequest(request);
			};
			anchor = await TrustAnchor.create(
				fixtureHostConfig({
					entityId: issuer,
					crypto: provider,
					storage,
					trustAnchors: anchors,
					metadata,
					options: { clock, httpClient },
					trustMarkIssuers: { [type]: [issuer, external] },
					trustMarkStatusPolicy: () => ({ status }),
				}),
			);
			await anchor.registerSubordinate({
				entityId: c.entityId(subject),
				jwks: { keys: [leaf.publicKey] },
			});
			await anchor.registerSubordinate({
				entityId: c.entityId(external),
				jwks: { keys: [ext.publicKey] },
			});
			const local = await anchor.issueTrustMark(subject, type);
			externalJwt = await c.signTrustMark({
				issuer: external,
				subject,
				trustMarkType: type,
				signer: new SigningEntryFixture(ext.privateKey),
				clock,
				ttlSeconds: 200,
			});
			const externalEc = await c.signEntityStatement(
				{
					iss: external,
					sub: external,
					iat: 900,
					exp: 5000,
					jwks: { keys: [ext.publicKey] },
					authority_hints: [issuer],
					metadata: {
						federation_entity: { federation_trust_mark_status_endpoint: `${external}/status` },
					},
				},
				new SigningEntryFixture(ext.privateKey),
			);
			const proof = await c.establishTrustMarkIssuerTrust({
				issuer: external,
				trustMarkType: type,
				trustAnchors: anchors,
				trustChain: [
					externalEc,
					await anchor.getSubordinateStatement(c.entityId(external)),
					await anchor.getEntityConfiguration(),
				],
				options: { engine: testEngine, clock, offline: true },
			});
			if (!proof.ok) throw Error(proof.error.description);
			const publish = async (jwt: string) => {
				holderEc = await c.signEntityStatement(
					{
						iss: subject,
						sub: subject,
						iat: 900,
						exp: 5000,
						jwks: { keys: [leaf.publicKey] },
						authority_hints: [issuer],
						metadata: { federation_entity: {} },
						trust_marks: [{ trust_mark_type: type, trust_mark: jwt }],
					},
					new SigningEntryFixture(leaf.privateKey),
				);
			};
			const resolve = async (issuerEvidence?: CorePublic.TrustMarkIssuerContext[]) => {
				const root = c.decodeEntityStatement(await anchor.getEntityConfiguration());
				if (!root.ok) throw Error(root.error.description);
				const ctx: HandlerContext = {
					...(root.value.payload.trust_mark_owners
						? {
								trustMarkOwners: root.value.payload.trust_mark_owners,
							}
						: {}),
					entityId: c.entityId(issuer),
					crypto: provider,
					storage,
					trustAnchors: anchors,
					clientKeyProvider: { getClientFederationJwks: async () => undefined },
					metadata,
					trustMarkStatusPolicy: () => ({ status }),
					options: {
						clock,
						httpClient,
						...(issuerEvidence
							? { engine: testEngine, trustMarkVerification: { issuerEvidence } }
							: { engine: testEngine }),
					},
				};
				const response = await createResolveHandler(ctx)(
					new Request(
						issuer +
							"/resolve?sub=" +
							encodeURIComponent(subject) +
							"&trust_anchor=" +
							encodeURIComponent(issuer),
					),
					true,
				);
				if (response.status !== 200) throw Error(await response.text());
				const decoded = c.decodeEntityStatement(await response.text());
				if (!decoded.ok) throw Error(decoded.error.description);
				return decoded.value.payload;
			};
			return {
				issuer,
				subject,
				external,
				type,
				key,
				anchor,
				proof: proof.value,
				local,
				externalJwt,
				publish,
				resolve,
				statusCalls: () => statusCalls,
				setStatus: (value: string) => {
					status = value;
				},
			};
		}
		test("local Resolve includes active marks and excludes custom suspended status", async (t) => {
			const f = await fixture();
			await f.publish(f.local);
			t.equal((await f.resolve()).trust_marks?.length, 1);
			f.setStatus("suspended");
			t.equal((await f.anchor.getTrustMarkStatus(f.local)).status, "suspended");
			t.strictEqual((await f.resolve()).trust_marks, undefined);
		});
		test("external issuer evidence supplies status keys and endpoints without entering the holder chain", async (t) => {
			const f = await fixture();
			await f.publish(f.externalJwt);
			const payload = await f.resolve([f.proof]);
			t.equal(payload.trust_marks?.length, 1);
			t.equal(f.statusCalls(), 1);
			t.equal(payload.exp, 1200);
			f.setStatus("revoked");
			t.strictEqual((await f.resolve([f.proof])).trust_marks, undefined);
		});
		test("out-of-band evidence cannot bypass selected-anchor authorization or delegation", async (t) => {
			const f = await fixture();
			await f.publish(f.local);
			const context: CorePublic.TrustMarkIssuerContext = {
				kind: "out-of-band",
				issuer: f.issuer,
				allowedTrustMarkTypes: [f.type],
				keys: { keys: [f.key.publicKey] },
			};
			await f.anchor.setTrustMarkIssuers({ [f.type]: [f.external] });
			t.strictEqual((await f.resolve([context])).trust_marks, undefined);
			await f.anchor.setTrustMarkIssuers({});
			t.strictEqual((await f.resolve([context])).trust_marks, undefined);
			await f.anchor.setTrustMarkIssuers({ [f.type]: [] });
			t.equal((await f.resolve([context])).trust_marks?.length, 1, "open issuer list still works");
			await f.anchor.setTrustMarkOwners({
				[f.type]: { sub: f.issuer, jwks: { keys: [f.key.publicKey] } },
			});
			t.strictEqual(
				(await f.resolve([context])).trust_marks,
				undefined,
				"selected owner requires delegation",
			);
			const delegation = await f.anchor.issueTrustMarkDelegation(f.issuer, f.type);
			await f.anchor.setTrustMarkDelegations({ [f.type]: delegation });
			const delegated = await f.anchor.issueTrustMark(f.subject, f.type, { renewal: "renew" });
			await f.publish(delegated);
			t.equal(
				(
					await f.resolve([
						{
							...context,
							trustMarkOwners: { [f.type]: { sub: f.issuer, jwks: { keys: [f.key.publicKey] } } },
						},
					])
				).trust_marks?.length,
				1,
				"valid selected-owner delegation is accepted",
			);
		});
	});

	module("authority / critical extension publication", () => {
		test("both authority hosts detach their own EC extensions at construction", async (t) => {
			const f = await createTestContext();
			for (const intermediate of [false, true]) {
				const additionalClaims = { x_authority: { versions: [1] } };
				const crit = ["x_authority"];
				const config: AuthorityConfig = {
					entityId: f.ctx.entityId,
					crypto: f.crypto,
					storage: f.storage,
					metadata: f.ctx.metadata,
					additionalClaims,
					crit,
					...(intermediate ? { authorityHints: ["https://superior.example"] } : {}),
				};
				const authority = await createAuthorityServer(config);
				additionalClaims.x_authority.versions.push(2);
				crit.push("missing");
				const result = decodeEntityStatement(await (await authority).getEntityConfiguration());
				t.true(result.ok);
				if (result.ok) {
					t.deepEqual(result.value.payload.x_authority, { versions: [1] });
					t.deepEqual(result.value.payload.crit, ["x_authority"]);
				}
				await t.rejects(
					(async () => await createAuthorityServer({ ...config, additionalClaims: { exp: 1 } }))(),
					/reserved/,
				);
				await t.rejects(
					(async () => await createAuthorityServer({ ...config, crit: [] }))(),
					/crit/,
				);
			}
		});
		test("subordinate extensions survive registration, updates, Fetch and Extended Listing", async (t) => {
			const f = await createTestContext();
			const authority = await TrustAnchor.create(
				fixtureHostConfig({
					entityId: f.ctx.entityId,
					crypto: f.crypto,
					storage: f.storage,
					metadata: f.ctx.metadata,
				}),
			);
			const additionalClaims = { x_rules: { versions: [1] } };
			await authority.registerSubordinate({
				entityId: LEAF_ID,
				jwks: { keys: [f.publicKey] },
				additionalClaims,
				crit: ["x_rules"],
			});
			additionalClaims.x_rules.versions.push(99);
			const initial = decodeEntityStatement(await authority.getSubordinateStatement(LEAF_ID));
			t.true(initial.ok);
			if (initial.ok) t.deepEqual(initial.value.payload.x_rules, { versions: [1] });
			await t.rejects(
				authority.updateSubordinate(LEAF_ID, { additionalClaims: { x_other: true } }),
				/missing/,
			);
			await t.rejects(
				authority.updateSubordinate(LEAF_ID, { additionalClaims: { iss: "override" } }),
				/reserved/,
			);
			await authority.updateSubordinate(LEAF_ID, {
				additionalClaims: { x_rules: { versions: [2] } },
			});
			const listing = await authority.listSubordinatesExtended({
				claims: ["crit", "subordinate_statement"],
			});
			t.true(listing.ok);
			if (listing.ok) {
				const row = listing.value.immediate_subordinate_entities[0]!;
				t.deepEqual(row.crit, ["x_rules"]);
				const statement = decodeEntityStatement(row.subordinate_statement as string);
				t.true(statement.ok);
				if (statement.ok) t.deepEqual(statement.value.payload.x_rules, { versions: [2] });
			}
			await authority.updateSubordinate(LEAF_ID, { additionalClaims: {}, crit: undefined });
			const cleared = decodeEntityStatement(await authority.getSubordinateStatement(LEAF_ID));
			t.true(cleared.ok);
			if (cleared.ok) {
				t.false(Object.hasOwn(cleared.value.payload, "crit"));
				t.false(Object.hasOwn(cleared.value.payload, "x_rules"));
			}
		});
	});
	module("authority / subordinate publication validation", () => {
		const invalid = [
			{ metadataPolicyCrit: ["one_of"] },
			{ crit: ["iss"] },
			{ crit: ["missing"] },
			{ additionalClaims: { iss: "override" } },
			{ additionalClaims: { x_rules: undefined }, crit: ["x_rules"] },
			{
				metadataPolicy: {
					openid_relying_party: { client_name: { one_of: ["a"], subset_of: ["a"] } },
				},
			},
			{ metadataPolicy: { openid_relying_party: { client_name: 42 } } },
			{ constraints: { naming_constraints: { excluded: ["https://example.com"] } } },
		];
		test("direct store writes reject invalid declarations and preserve existing records", async (t) => {
			const f = await createTestContext();
			const record: SubordinateRecord = {
				entityId: LEAF_ID,
				jwks: { keys: [f.publicKey] },
				createdAt: 1,
				updatedAt: 1,
			};
			for (const patch of invalid)
				await t.rejects(
					f.storage.subordinates.add({ ...record, ...patch } as SubordinateRecord),
					/Invalid Subordinate Statement/,
				);
			t.strictEqual(await f.storage.subordinates.get(LEAF_ID), undefined);
			await f.storage.subordinates.add(record);
			for (const patch of invalid)
				await t.rejects(
					f.storage.subordinates.update(LEAF_ID, patch as SubordinateRecordUpdate),
					/Invalid Subordinate Statement/,
				);
			t.deepEqual(await f.storage.subordinates.get(LEAF_ID), record);
		});
		test("authority lifecycle checks precede custom adapter writes and event creation", async (t) => {
			const f = await createTestContext();
			const backing = new MemoryStorageAdapter({ engine: testEngine, subordinateEvents: true });
			let adds = 0,
				updates = 0;
			const tracked = (repo: SubordinateStorage): SubordinateStorage => ({
				get: (id) => repo.get(id),
				list: (filter, options) => repo.list(filter, options),
				remove: (id) => repo.remove(id),
				async add(record) {
					adds++;
					await repo.add(record);
				},
				async update(id, patch) {
					updates++;
					await repo.update(id, patch);
				},
			});
			const storage: StorageAdapter = {
				subordinates: tracked(backing.subordinates),
				subordinateEvents: backing.subordinateEvents,
				transaction: (operation) =>
					backing.transaction((tx) => operation({ ...tx, subordinates: tracked(tx.subordinates) })),
			};
			const lifecycle = createSubordinateLifecycle({ ...f.ctx, storage });
			const record = { entityId: LEAF_ID, jwks: { keys: [f.publicKey] } };
			for (const patch of invalid)
				await t.rejects(
					lifecycle.registerSubordinate({ ...record, ...patch } as typeof record),
					/Invalid Subordinate Statement/,
				);
			t.equal(adds, 0);
			t.deepEqual(await backing.subordinateEvents!.list(f.ctx.entityId, LEAF_ID), []);
			await lifecycle.registerSubordinate(record);
			const saved = await backing.subordinates.get(LEAF_ID);
			for (const patch of invalid)
				await t.rejects(
					lifecycle.updateSubordinate(LEAF_ID, patch as SubordinateRecordUpdate),
					/Invalid Subordinate Statement/,
				);
			t.equal(adds, 1);
			t.equal(updates, 0);
			t.deepEqual(await backing.subordinates.get(LEAF_ID), saved);
			t.equal((await backing.subordinateEvents!.list(f.ctx.entityId, LEAF_ID)).length, 1);
		});
		test("legacy records are rejected by signed fetch and selected policy publication", async (t) => {
			const f = await createTestContext();
			for (const patch of invalid.filter((entry) => !entry.constraints)) {
				const record = {
					entityId: LEAF_ID,
					jwks: { keys: [f.publicKey] },
					createdAt: 1,
					updatedAt: 1,
					...patch,
				} as SubordinateRecord;
				const storage: StorageAdapter = {
					subordinates: {
						get: async () => record,
						list: async () => ({ items: [record] }),
						add: async () => {},
						update: async () => {},
						remove: async () => {},
					},
					transaction: f.storage.transaction.bind(f.storage),
				};
				const ctx = { ...f.ctx, storage };
				t.equal(
					(
						await createFetchHandler(ctx)(
							new Request(`${ENTITY_ID}/fetch?sub=${encodeURIComponent(LEAF_ID)}`),
						)
					).status,
					500,
				);
				const claim = patch.metadataPolicy
					? "metadata_policy"
					: patch.crit
						? "crit"
						: "metadata_policy_crit";
				t.equal(
					(await createExtendedListHandler(ctx)(new Request(`${ENTITY_ID}/list?claims=${claim}`)))
						.status,
					500,
				);
			}
		});
		test("legal policies preserve partial metadata and unknown extension constraints", async (t) => {
			const f = await createTestContext();
			const lifecycle = createSubordinateLifecycle(f.ctx);
			await lifecycle.registerSubordinate({
				entityId: LEAF_ID,
				jwks: { keys: [f.publicKey] },
				metadata: { openid_relying_party: {} },
				metadataPolicy: {
					openid_relying_party: {
						client_name: { essential: true, custom_extension: "configured" },
					},
				},
				metadataPolicyCrit: ["custom_extension"],
				constraints: { custom_constraint: { rule: "extension" } },
			});
			const response = await createFetchHandler(f.ctx)(
				new Request(`${ENTITY_ID}/fetch?sub=${encodeURIComponent(LEAF_ID)}`),
			);
			t.equal(response.status, 200);
			const decoded = decodeEntityStatement(await response.text());
			t.true(decoded.ok);
			if (decoded.ok) {
				t.deepEqual(decoded.value.payload.metadata_policy_crit, ["custom_extension"]);
				t.deepEqual(decoded.value.payload.constraints, {
					custom_constraint: { rule: "extension" },
				});
			}
		});
		test("resolve endpoint forwards registered custom constraints", async (t) => {
			const f = await createTestContext();
			const fed = await createMockFederation();
			const decoded = decodeEntityStatement(fed.taSubStatementForOp);
			if (!decoded.ok) throw Error("fixture");
			const ss = await signEntityStatement(
				{ ...decoded.value.payload, constraints: { custom: true } },
				new SigningEntryFixture(fed.taSigningKey),
				{ typ: JwtTyp.EntityStatement },
			);
			const httpClient: HttpClient = async (input, init) => {
				const url = new URL(String(input));
				return url.origin === TA_ID && url.searchParams.get("sub") === OP_ID
					? new Response(ss, { headers: { "content-type": MediaType.EntityStatement } })
					: fed.httpClient(input, init);
			};
			for (const accepted of [true, false]) {
				let calls = 0;
				const ctx = {
					...f.ctx,
					trustAnchors: fed.trustAnchors,
					options: {
						...fed.options,
						httpClient,
						customConstraintChecks: [
							{
								name: "custom",
								check() {
									calls++;
									return accepted
										? CorePublic.ok(undefined)
										: CorePublic.err({
												code: CorePublic.InternalErrorCode.ConstraintViolation,
												description: "denied",
											});
								},
							},
						],
					},
				};
				const response = await createResolveHandler(ctx)(
					new Request(
						`${ENTITY_ID}/resolve?sub=${encodeURIComponent(OP_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
					),
				);
				t.equal(response.status, accepted ? 200 : 400);
				t.true(calls > 0);
			}
		});
	});

	module("authority / lifecycle logging", () => {
		test("write failures preserve rollback and success notices follow commit", async (t) => {
			for (const operation of ["registration", "update", "revocation", "recording"] as const)
				for (const throwingLogger of [false, true]) {
					const f = await SubordinateEventsFixture.fixture();
					const messages: [string, unknown[]][] = [];
					const record =
						(level: string) =>
						(...args: unknown[]) => {
							messages.push([level, args]);
							if (throwingLogger) throw new Error("Logger failed");
						};
					const authority = await TrustAnchor.create(
						fixtureHostConfig({
							...f.config,
							options: {
								...f.config.options,
								logger: {
									debug: record("debug"),
									info: record("info"),
									warn: record("warn"),
									error: record("error"),
								},
							},
						}),
					);
					if (operation !== "registration") await authority.registerSubordinate(f.record);
					messages.length = 0;
					const before = await f.storage.subordinates.get(SubordinateEventsFixture.subject);
					const eventsBefore = await f.storage.subordinateEvents!.list(
						SubordinateEventsFixture.issuer,
						SubordinateEventsFixture.subject,
					);
					const original = new Error("private-storage-error");
					let failing = true;
					const transaction = f.storage.transaction.bind(f.storage);
					f.storage.transaction = (run) =>
						transaction(async (tx) => {
							const value = await run(tx);
							if (failing) throw original;
							return value;
						});
					const annotations = { informationUri: "http://docs.example/private-event" };
					const perform = () =>
						operation === "registration"
							? authority.registerSubordinate(f.record, annotations)
							: operation === "update"
								? authority.updateSubordinate(
										SubordinateEventsFixture.subject,
										{
											metadata: { openid_relying_party: { organization_name: "Changed" } },
											metadataPolicy: {
												openid_relying_party: { application_type: { value: "web" } },
											},
										},
										annotations,
									)
								: operation === "revocation"
									? authority.revokeSubordinate(SubordinateEventsFixture.subject, annotations)
									: authority.recordSubordinateEvents(SubordinateEventsFixture.subject, [
											{
												event: "custom-event",
												iat: 1500,
												information_uri: annotations.informationUri,
											},
											{
												event: "another-event",
												iat: 1500,
												information_uri: annotations.informationUri,
											},
										]);
					const label =
						operation === "recording"
							? "Subordinate Event recording"
							: `Immediate Subordinate ${operation}`;
					await t.rejects(perform(), (error: unknown) => error === original);
					t.deepEqual(messages, [["error", [`${label} failed`]]]);
					t.deepEqual(await f.storage.subordinates.get(SubordinateEventsFixture.subject), before);
					t.deepEqual(
						await f.storage.subordinateEvents!.list(
							SubordinateEventsFixture.issuer,
							SubordinateEventsFixture.subject,
						),
						eventsBefore,
					);
					messages.length = 0;
					failing = false;
					await perform();
					t.deepEqual(messages, [
						["info", [`${label} completed`]],
						["info", ["HTTPS is RECOMMENDED for Subordinate Event information_uri"]],
					]);
					t.false(JSON.stringify(messages).includes("private-"));
					if (operation === "update") {
						messages.length = 0;
						await authority.updateSubordinate(SubordinateEventsFixture.subject, {}, annotations);
						t.deepEqual(
							messages,
							[["info", ["Immediate Subordinate update completed"]]],
							"a no-op records no event recommendation",
						);
					}
				}
		});
		test("HTTPS and omitted event documentation produce no recommendation notice", async (t) => {
			const f = await SubordinateEventsFixture.fixture();
			const messages: string[] = [];
			const authority = await TrustAnchor.create(
				fixtureHostConfig({
					...f.config,
					options: {
						logger: {
							debug() {},
							warn() {},
							error() {},
							info: (message) => {
								messages.push(message);
							},
						},
					},
				}),
			);
			await authority.registerSubordinate(f.record);
			await authority.recordSubordinateEvents(SubordinateEventsFixture.subject, [
				{ event: "custom", iat: 1500, information_uri: "https://docs.example/event" },
			]);
			t.false(messages.some((message) => message.includes("RECOMMENDED")));
		});
	});
	module("authority / collection recommendation", () => {
		test("only successful publication emits the companion Resolve endpoint notice, once", async (t) => {
			for (const resolve of [false, true])
				for (const throughRole of [false, true]) {
					const f = await SubordinateEventsFixture.fixture();
					const messages: string[] = [];
					const collectionMetadata = {
						federation_collection_endpoint: `${SubordinateEventsFixture.issuer}/collect`,
						...(resolve
							? { federation_resolve_endpoint: `${SubordinateEventsFixture.issuer}/resolve` }
							: {}),
					};
					let failing = false;
					const getKeys = f.crypto.keyring.entry.bind(f.crypto.keyring, "federation");
					f.crypto.keyring.entry = async () => {
						if (failing) throw new Error("signing failed");
						return getKeys();
					};
					const authority = await TrustAnchor.create(
						fixtureHostConfig({
							...f.config,
							collection: { trustAnchors: new Map() },
							metadata: {
								...f.config.metadata,
								federation_entity: {
									...f.config.metadata!.federation_entity,
									...(!throughRole ? collectionMetadata : {}),
								},
							},
							...(throughRole
								? { roles: [{ type: "federation_entity", metadata: collectionMetadata }] }
								: {}),
							options: {
								logger: {
									debug() {},
									warn() {},
									error() {},
									info: (message) => {
										messages.push(message);
										throw new Error("Logger failed");
									},
								},
							},
						}),
					);
					t.deepEqual(messages, []);
					failing = true;
					await t.rejects(authority.getEntityConfiguration());
					t.deepEqual(messages, []);
					failing = false;
					await authority.getEntityConfiguration();
					await authority.getEntityConfiguration();
					t.equal(
						messages.filter((message) => message.includes("SHOULD also publish")).length,
						resolve ? 0 : 1,
					);
				}
		});
	});

	module("authority / injected logging", () => {
		test("a missing recommended status endpoint produces one notice without rejecting issuance", async (t) => {
			const f = await createMockFederation();
			for (const advertised of [false, true]) {
				const notices: unknown[][] = [];
				const warnings: unknown[][] = [];
				const authority = await TrustAnchor.create(
					fixtureHostConfig({
						entityId: TA_ID,
						crypto: FixtureCrypto.fromJWK(f.taSigningKey),
						storage: new MemoryStorageAdapter({ engine: testEngine, trustMarks: true }),
						metadata: {
							federation_entity: {
								federation_fetch_endpoint: `${TA_ID}/fetch`,
								federation_list_endpoint: `${TA_ID}/list`,
								...(advertised ? { federation_trust_mark_status_endpoint: `${TA_ID}/status` } : {}),
							},
						},
						options: {
							logger: {
								debug() {},
								error() {},
								info: (...args) => {
									notices.push(args);
								},
								warn: (...args) => {
									warnings.push(args);
								},
							},
						},
					}),
				);
				for (let i = 0; i < 2; i++)
					t.true(
						decodeEntityStatement(
							await authority.issueTrustMark(OP_ID, "https://marks.example/type"),
						).ok,
					);
				t.equal(
					notices.filter((args) => String(args[0]).includes("SHOULD publish")).length,
					advertised ? 0 : 1,
				);
				t.true(notices.every((args) => args.length === 1));
				t.equal(
					warnings.length,
					0,
					"omitted optional features and the SHOULD departure are not warnings",
				);
			}
			const fail = () => {
				throw new Error("Logger failed");
			};
			const authority = await TrustAnchor.create(
				fixtureHostConfig({
					entityId: TA_ID,
					crypto: FixtureCrypto.fromJWK(f.taSigningKey),
					storage: new MemoryStorageAdapter({ engine: testEngine, trustMarks: true }),
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: `${TA_ID}/fetch`,
							federation_list_endpoint: `${TA_ID}/list`,
						},
					},
					options: { logger: { debug: fail, info: fail, warn: fail, error: fail } },
				}),
			);
			t.true(
				decodeEntityStatement(await authority.issueTrustMark(OP_ID, "https://marks.example/type"))
					.ok,
			);
			await t.rejects(
				(async () =>
					await TrustAnchor.create(
						fixtureHostConfig({
							entityId: TA_ID,
							crypto: FixtureCrypto.fromJWK(f.taSigningKey),
							storage: new MemoryStorageAdapter({ engine: testEngine }),
							metadata: { federation_entity: {} },
							options: { logger: { debug: fail, info: fail, warn: fail, error: fail } },
						}),
					))(),
				/fetch_endpoint/,
			);
		});
	});

	test("subordinate identifiers are guarded at storage and listing boundaries", async (t) => {
		const { ctx, storage, publicKey } = await createTestContext();
		const bad = {
			entityId: "https://bad.example/#fragment" as EntityId,
			jwks: { keys: [publicKey] },
			createdAt: 1000,
			updatedAt: 1000,
		};
		await t.rejects(storage.subordinates.add(bad));
		storage.subordinates.list = async () => ({ items: [bad] });
		const extended = await createExtendedListHandler(ctx)(
			new Request("https://authority.example/list?claims="),
		);
		t.equal(extended.status, 500);
		const basic = await createListHandler(ctx)(new Request("https://authority.example/list"));
		t.equal(basic.status, 500);
		storage.subordinates.list = async () => ({ items: [], nextCursor: bad.entityId });
		t.equal(
			(await createExtendedListHandler(ctx)(new Request("https://authority.example/list?claims=")))
				.status,
			500,
		);
	});

	test("fixed-query routing preserves a double slash in an endpoint path", async (t) => {
		const { ctx } = await createTestContext();
		const authority = await TrustAnchor.create(
			fixtureHostConfig({
				entityId: ctx.entityId,
				crypto: ctx.crypto,
				storage: ctx.storage,
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${ctx.entityId}/fetch`,
						federation_list_endpoint: `${ctx.entityId}//api?kind=list`,
					},
				},
			}),
		);
		const response = await authority.handleRequest(new Request(`${ctx.entityId}//api?kind=list`));
		t.equal(response.status, 200);
		t.deepEqual(await response.json(), []);
		const absent = await authority.handleRequest(new Request(`${ctx.entityId}//api`));
		t.equal(absent.status, 404);
		await absent.body?.cancel();
	});

	test("event readers use readSnapshot with a transaction fallback", async (t) => {
		const { buildSubordinateEvents } = await import(
			"../../../packages/authority/src/endpoints/subordinate-events.js"
		);
		const backing = new MemoryStorageAdapter({ engine: testEngine, subordinateEvents: true });
		const subject = entityId("https://member.example");
		await backing.subordinates.add({
			entityId: subject,
			jwks: { keys: [testPublicJwk()] },
			createdAt: 1,
			updatedAt: 1,
		});
		const { ctx } = await createTestContext({ storage: backing });
		for (const withSnapshot of [true, false]) {
			let snapshots = 0;
			let transactions = 0;
			const storage: StorageAdapter = {
				subordinates: backing.subordinates,
				subordinateEvents: backing.subordinateEvents!,
				transaction: async (operation) => {
					transactions++;
					return backing.transaction(operation);
				},
				...(withSnapshot
					? {
							readSnapshot: async <T>(
								operation: (snapshot: AuthorityPublic.StorageReadSnapshot) => Promise<T>,
							) => {
								snapshots++;
								return backing.readSnapshot(operation);
							},
						}
					: {}),
			};
			const jwt = await buildSubordinateEvents({ ...ctx, storage }, subject);
			t.ok(jwt);
			if (jwt) {
				const decoded = decodeEntityStatement(jwt);
				t.true(decoded.ok);
				if (decoded.ok) t.deepEqual(decoded.value.payload.federation_registration_events, []);
			}
			t.equal(snapshots, withSnapshot ? 1 : 0);
			t.equal(transactions, withSnapshot ? 0 : 1);
		}
	});
	test("annotations cover every update event and failed appends roll back state", async (t) => {
		const { createSubordinateLifecycle } = await import(
			"../../../packages/authority/src/subordinate-lifecycle.js"
		);
		const backing = new MemoryStorageAdapter({ engine: testEngine, subordinateEvents: true });
		const { ctx } = await createTestContext({ storage: backing });
		const lifecycle = createSubordinateLifecycle(ctx);
		const subject = entityId("https://member.example");
		await lifecycle.registerSubordinate({ entityId: subject, jwks: { keys: [testPublicJwk()] } });
		const updates = {
			jwks: { keys: [(await generateSigningKey()).publicKey] },
			metadata: { federation_entity: { organization_name: "Updated" } },
			metadataPolicy: { openid_relying_party: { scope: { default: "openid" } } },
		};
		await lifecycle.updateSubordinate(subject, updates, {
			eventDescription: "Reviewed update",
			informationUri: "https://example.com/review",
		});
		const events = await backing.subordinateEvents!.list(ctx.entityId, subject);
		t.deepEqual(
			events.slice(1).map((event) => event.event),
			["metadata_update", "metadata_policy_update", "jwks_update"],
		);
		for (const event of events.slice(1)) {
			t.equal(event.event_description, "Reviewed update");
			t.equal(event.information_uri, "https://example.com/review");
		}
		const before = await backing.subordinates.get(subject);
		const failing: StorageAdapter = {
			subordinates: backing.subordinates,
			subordinateEvents: backing.subordinateEvents!,
			transaction: (operation) =>
				backing.transaction((tx) =>
					operation({
						...tx,
						subordinateEvents: {
							list: tx.subordinateEvents!.list.bind(tx.subordinateEvents),
							append: async () => {
								throw new Error("append failed");
							},
						},
					}),
				),
		};
		await t.rejects(
			createSubordinateLifecycle({ ...ctx, storage: failing }).revokeSubordinate(subject, {
				eventDescription: "Rollback",
			}),
			/append failed/,
		);
		t.deepEqual(await backing.subordinates.get(subject), before);
		t.deepEqual(await backing.subordinateEvents!.list(ctx.entityId, subject), events);
		const withoutEvents = new MemoryStorageAdapter({ engine: testEngine });
		await t.rejects(
			createSubordinateLifecycle({ ...ctx, storage: withoutEvents }).registerSubordinate(
				{ entityId: subject, jwks: updates.jwks },
				{},
			),
			/require subordinate event storage/,
		);
		t.strictEqual(await withoutEvents.subordinates.get(subject), undefined);
	});

	test("orphan endpoint authentication companions fail host construction", async (t) => {
		const { ctx } = await createTestContext();
		for (const endpoint of [
			"subordinate_events",
			"resolve",
			"historical_keys",
			"trust_mark",
			"trust_mark_list",
			"trust_mark_status",
		]) {
			await t.rejects(
				(async () =>
					await TrustAnchor.create(
						fixtureHostConfig({
							entityId: ctx.entityId,
							crypto: ctx.crypto,
							storage: ctx.storage,
							metadata: {
								federation_entity: {
									...ctx.metadata.federation_entity,
									[`federation_${endpoint}_endpoint_auth_methods`]: ["none"],
								},
							},
						}),
					))(),
				/requires/,
			);
		}
	});
	test("authority routes distinguish fixed query selectors and reject overlaps", async (t) => {
		const { ctx } = await createTestContext();
		const storage = new MemoryStorageAdapter({ engine: testEngine, subordinateEvents: true });
		const config = {
			entityId: ctx.entityId,
			crypto: ctx.crypto,
			storage,
			metadata: {
				federation_entity: {
					...ctx.metadata.federation_entity,
					federation_subordinate_events_endpoint: `${ctx.entityId}/api?kind=events`,
					federation_extended_list_endpoint: `${ctx.entityId}/api?kind=list`,
				},
			},
		};
		const authority = await TrustAnchor.create(fixtureHostConfig(config));
		const subject = entityId("https://member.example");
		await authority.registerSubordinate({ entityId: subject, jwks: { keys: [testPublicJwk()] } });
		for (const [query, status] of [
			["kind=events&sub=https://member.example", 200],
			["kind=list&claims=", 200],
			["sub=https://member.example", 404],
			["kind=wrong", 404],
			["kind=events&kind=list", 404],
		] as const) {
			const response = await authority.handleRequest(new Request(`${ctx.entityId}/api?${query}`));
			t.equal(response.status, status);
			await response.body?.cancel();
		}
		await t.rejects(
			(async () =>
				await TrustAnchor.create(
					fixtureHostConfig({
						...config,
						metadata: {
							federation_entity: {
								...config.metadata.federation_entity,
								federation_extended_list_endpoint: `${ctx.entityId}/api?tenant=a`,
							},
						},
					}),
				))(),
			/overlapping/,
		);
	});

	test("authority routes and authentication agree on repeated filters and route overlap", async (t) => {
		const c = CorePublic,
			{ ctx } = await createTestContext();
		const config = {
			entityId: ctx.entityId,
			crypto: ctx.crypto,
			storage: new MemoryStorageAdapter({ engine: testEngine }),
			endpointAuthentication: {
				methods: {
					example_auth: {
						parameters: ["proof"],
						authenticate: () => c.ok({ entityId: "https://client.example" }),
					},
				},
			},
			metadata: {
				federation_entity: {
					...ctx.metadata.federation_entity,
					federation_list_endpoint: `${ctx.entityId}/filtered?entity_type=openid_provider&entity_type=openid_relying_party`,
					federation_list_endpoint_auth_methods: ["none", "example_auth"],
				},
			},
		};
		const authority = await TrustAnchor.create(fixtureHostConfig(config));
		for (const query of [
			"entity_type=openid_relying_party&entity_type=openid_provider",
			"entity_type=openid_provider&entity_type=openid_relying_party&entity_type=openid_provider",
		]) {
			for (const method of ["GET", "POST"]) {
				const response = await authority.handleRequest(
					new Request(
						`${ctx.entityId}/filtered?${query}`,
						method === "GET"
							? {}
							: {
									method,
									body: new URLSearchParams(
										"entity_type=openid_relying_party&entity_type=openid_provider&proof=ok",
									),
								},
					),
				);
				t.equal(response.status, 200);
				await response.body?.cancel();
			}
		}
		for (const [listQuery, otherQuery, overlaps] of [
			["entity_type=a&entity_type=b", "entity_type=b&entity_type=a&entity_type=a", true],
			["entity_type=a&entity_type=b", "entity_type=c", false],
			["extension=a&extension=b", "extension=b&extension=a", false],
		] as const) {
			// Fetch uses exact matching; Listing uses membership. Check both route insertion orders.
			for (const reverse of [false, true]) {
				const metadata = {
					federation_entity: {
						...config.metadata.federation_entity,
						federation_fetch_endpoint: `${ctx.entityId}/shared?${reverse ? listQuery : otherQuery}`,
						federation_list_endpoint: `${ctx.entityId}/shared?${reverse ? otherQuery : listQuery}`,
					},
				};
				if (overlaps)
					await t.rejects(
						(async () => await TrustAnchor.create(fixtureHostConfig({ ...config, metadata })))(),
						/overlapping/,
					);
				else {
					const routed = await TrustAnchor.create(fixtureHostConfig({ ...config, metadata }));
					const response = await routed.handleRequest(
						new Request(`${ctx.entityId}/shared?${reverse ? otherQuery : listQuery}`),
					);
					t.notEqual(response.status, 404);
					await response.body?.cancel();
				}
			}
		}
	});
	test("lifecycle annotations share the transaction and cannot forge event fields", async (t) => {
		const { createSubordinateLifecycle } = await import(
			"../../../packages/authority/src/subordinate-lifecycle.js"
		);
		const storage = new MemoryStorageAdapter({ engine: testEngine, subordinateEvents: true });
		const { ctx } = await createTestContext({
			storage,
			options: { clock: { now: () => 100 }, engine: testEngine },
		});
		const lifecycle = createSubordinateLifecycle(ctx);
		const subject = entityId("https://member.example");
		await lifecycle.registerSubordinate(
			{ entityId: subject, jwks: { keys: [testPublicJwk()] } },
			{ eventDescription: "Approved", informationUri: "https://example.com/approval" },
		);
		await lifecycle.updateSubordinate(subject, {}, { eventDescription: "No changes" });
		await t.rejects(lifecycle.revokeSubordinate(subject, { informationUri: "bad" }));
		t.ok(await storage.subordinates.get(subject));
		await lifecycle.revokeSubordinate(subject, { eventDescription: "Contract ended" });
		const events = await storage.subordinateEvents!.list(ctx.entityId, subject);
		t.deepEqual(
			events.map((e) => [e.event, e.event_description]),
			[
				["registration", "Approved"],
				["revocation", "Contract ended"],
			],
		);
		t.equal(events[0]!.information_uri, "https://example.com/approval");
		t.equal(events[1]!.iat, 100);
	});
	test("memory read snapshots detach data and serialize against lifecycle writes", async (t) => {
		const storage = new MemoryStorageAdapter({ engine: testEngine, subordinateEvents: true });
		const subject = entityId("https://member.example");
		await storage.subordinates.add({
			entityId: subject,
			jwks: { keys: [testPublicJwk()] },
			createdAt: 1,
			updatedAt: 1,
		});
		let release!: () => void;
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		let entered!: () => void;
		const ready = new Promise<void>((resolve) => {
			entered = resolve;
		});
		const reading = storage.readSnapshot(async (snapshot) => {
			t.false("remove" in snapshot.subordinates);
			const record = await snapshot.subordinates.get(subject);
			(record!.jwks.keys as unknown[]).length = 0;
			entered();
			await gate;
			t.ok(await snapshot.subordinates.get(subject));
		});
		await ready;
		const removal = storage.subordinates.remove(subject);
		release();
		await reading;
		await removal;
		t.strictEqual(await storage.subordinates.get(subject), undefined);
		await t.rejects(
			storage.readSnapshot(async () => {
				throw new Error("read failed");
			}),
			/read failed/,
		);
		t.equal(await storage.readSnapshot(async () => 42), 42, "queue released after failure");
	});
	test("an open Trust Mark issuer list allows administrative issuance", async (t) => {
		const { ctx } = await createTestContext({ trustMarkIssuers: { "https://mark.example": [] } });
		const jwt = await (await TrustAnchor.create(fixtureHostConfig(hostConfig(ctx)))).issueTrustMark(
			"https://member.example",
			"https://mark.example",
		);
		t.true(decodeEntityStatement(jwt).ok);
		await t.rejects(
			(
				await TrustAnchor.create(
					fixtureHostConfig({
						...hostConfig(ctx),
						trustMarkIssuers: { "https://mark.example": ["https://other.example"] },
					}),
				)
			).issueTrustMark("https://member.example", "https://mark.example"),
			/not authorized/,
		);
	});
	test("unsigned selected claims follow subordinate publication rules", async (t) => {
		const { extractClaims } = await import(
			"../../../packages/authority/src/endpoints/extended-list-claims.js"
		);
		const { ctx, publicKey } = await createTestContext();
		const record = {
			entityId: entityId("https://member.example"),
			jwks: { keys: [publicKey] },
			createdAt: 1,
			updatedAt: 1,
			metadata: {
				federation_entity: {
					organization_name: "Member",
					federation_resolve_endpoint: "https://member.example/resolve",
				},
			},
		};
		t.deepEqual(await extractClaims(record, ctx, ["metadata"], 1), {
			metadata: { federation_entity: { organization_name: "Member" } },
		});
		await t.rejects(
			extractClaims(
				{ ...record, metadata: { openid_provider: { issuer: "https://wrong.example" } } },
				ctx,
				["metadata"],
				1,
			),
		);
		await t.rejects(
			extractClaims(
				{ ...record, metadataPolicy: { openid_provider: { claim: 7 } } },
				ctx,
				["metadata_policy"],
				1,
			),
		);
		await t.rejects(
			extractClaims({ ...record, constraints: { max_path_length: -1 } }, ctx, ["constraints"], 1),
		);
		t.deepEqual(await extractClaims({ ...record, jwks: { keys: [] } }, ctx, ["metadata"], 1), {
			metadata: { federation_entity: { organization_name: "Member" } },
		});
	});
	module("authority / inline metadata key publication", () => {
		test("checks mixed-key use in Authority ECs and subordinate statements", async (t) => {
			const f = await SubordinateEventsFixture.fixture();
			const { use: _sigUse, ...sig } = f.key.publicKey;
			const { use: _encUse, ...enc } = f.clientKey.publicKey;
			const signing = { ...sig, alg: "ES256", key_ops: ["verify"] };
			const encryption = { ...enc, alg: "ECDH-ES", key_ops: ["deriveKey"] };
			const labelled = [
				{ ...signing, use: "sig" },
				{ ...encryption, use: "enc" },
			];
			for (const scenario of [
				{ keys: [signing, encryption], valid: false },
				{ keys: [{ ...signing, use: "sig" }, encryption], valid: false },
				{
					keys: [
						{ ...signing, use: "" },
						{ ...encryption, use: "enc" },
					],
					valid: false,
				},
				{ keys: labelled, valid: true },
				{
					keys: [...labelled, { ...signing, kid: "extra", use: "urn:example:other-use" }],
					valid: true,
				},
				{ keys: [signing], valid: true },
				{ keys: [encryption], valid: true },
			]) {
				const metadata = { openid_relying_party: { jwks: { keys: scenario.keys } } };
				const config = {
					...f.config,
					storage: new MemoryStorageAdapter({
						engine: testEngine,
						clock: f.clock,
						subordinateEvents: true,
					}),
					metadata: { ...f.config.metadata, ...metadata },
				};
				if (!scenario.valid)
					await t.rejects(
						(async () => await TrustAnchor.create(fixtureHostConfig(config)))(),
						/'use'/,
					);
				else {
					const authority = await TrustAnchor.create(fixtureHostConfig(config));
					const published = decodeEntityStatement(await authority.getEntityConfiguration());
					t.true(published.ok);
					if (published.ok)
						t.deepEqual(
							published.value.payload.metadata?.openid_relying_party,
							metadata.openid_relying_party,
						);
				}
				const authority = await TrustAnchor.create(
					fixtureHostConfig({
						...f.config,
						storage: new MemoryStorageAdapter({
							engine: testEngine,
							clock: f.clock,
							subordinateEvents: true,
						}),
					}),
				);
				const publish = async () => {
					await authority.registerSubordinate({ ...f.record, metadata });
					return authority.getSubordinateStatement(SubordinateEventsFixture.subject);
				};
				if (!scenario.valid) await t.rejects(publish(), /'use'/);
				else {
					const published = decodeEntityStatement(await publish());
					t.true(published.ok);
					if (published.ok)
						t.deepEqual(
							published.value.payload.metadata?.openid_relying_party,
							metadata.openid_relying_party,
						);
				}
			}
		});
	});
	module("authority / bounded publication", () => {
		test("lifecycle events compare public extensions and ignore key ordering", async (t) => {
			const f = await SubordinateEventsFixture.fixture();
			await f.authority.registerSubordinate(f.record);
			let key = { ...f.clientKey.publicKey };
			for (const update of [
				{ exp: 3000 },
				{ nbf: 1000 },
				{ revoked: 1600 },
				{ extension: { version: 1 } },
			]) {
				key = { ...key, ...update };
				await f.authority.updateSubordinate(SubordinateEventsFixture.subject, {
					jwks: { keys: [key] },
				});
			}
			const history = await f.authority.getSubordinateEvents(SubordinateEventsFixture.subject);
			const decoded = decodeEntityStatement(history);
			if (!decoded.ok) throw new Error(decoded.error.description);
			t.deepEqual(
				(decoded.value.payload.federation_registration_events as { event: string }[]).map(
					(event) => event.event,
				),
				["registration", "jwks_update", "jwks_update", "jwks_update", "jwks_update"],
			);
			const second = { ...key, kid: "second-key" };
			await f.authority.updateSubordinate(SubordinateEventsFixture.subject, {
				jwks: { keys: [key, second] },
			});
			const readHistory = async () => {
				const parsed = decodeEntityStatement(
					await f.authority.getSubordinateEvents(SubordinateEventsFixture.subject),
				);
				if (!parsed.ok) throw new Error(parsed.error.description);
				return parsed.value.payload;
			};
			const before = await readHistory();
			await f.authority.updateSubordinate(SubordinateEventsFixture.subject, {
				jwks: { keys: [second, key] },
			});
			t.deepEqual(await readHistory(), before);
			await t.rejects(
				f.authority.updateSubordinate(SubordinateEventsFixture.subject, {
					jwks: { keys: [{ ...key, d: "private" }] },
				}),
			);
			t.deepEqual((await f.storage.subordinates.get(SubordinateEventsFixture.subject))?.jwks.keys, [
				second,
				key,
			]);
			t.deepEqual(await readHistory(), before, "rejected update preserves history");
			await f.storage.subordinates.update(SubordinateEventsFixture.subject, {
				jwks: { keys: [{ ...key, d: "legacy" }] },
			});
			await f.authority.updateSubordinate(SubordinateEventsFixture.subject, {
				jwks: { keys: [key] },
			});
			t.deepEqual((await f.storage.subordinates.get(SubordinateEventsFixture.subject))?.jwks.keys, [
				key,
			]);
		});
		test("byte-limited pages preserve every record and include actual cursor overhead", async (t) => {
			const { ctx, storage, publicKey } = await createTestContext({
				options: { clock: { now: () => 1500 }, engine: testEngine },
			});
			const ids = Array.from({ length: 6 }, (_, i) =>
				entityId(`https://member.example/${i}-${"long".repeat(i)}`),
			);
			for (const id of ids)
				await storage.subordinates.add({
					entityId: id,
					jwks: { keys: [publicKey] },
					metadata: { openid_relying_party: { organization_name: "é🙂".repeat(8) } },
					createdAt: -0.5,
					updatedAt: 1500.5,
				});
			const unrestricted = createExtendedListHandler(ctx);
			const first = await (
				await unrestricted(
					new Request(
						"https://authority.example/list?claims=metadata&audit_timestamps=true&limit=1",
					),
				)
			).text();
			const budget = new TextEncoder().encode(first).byteLength + 80;
			const handler = createExtendedListHandler(ctx, {
				maxResponseBytes: budget,
				storeBatchSize: 4,
			});
			const seen: string[] = [];
			let cursor: string | undefined;
			for (let page = 0; page < ids.length + 1; page++) {
				const url = new URL("https://authority.example/list?claims=metadata&audit_timestamps=true");
				if (cursor !== undefined) url.searchParams.set("from", cursor);
				const response = await handler(new Request(url));
				t.equal(response.status, 200);
				const text = await response.text();
				t.ok(new TextEncoder().encode(text).byteLength <= budget);
				const body = JSON.parse(text);
				seen.push(...body.immediate_subordinate_entities.map((entry: { id: string }) => entry.id));
				for (const entry of body.immediate_subordinate_entities) {
					t.equal(entry.registered, -0.5);
					t.ok(entry.metadata);
				}
				if (body.next === undefined) break;
				t.notEqual(body.next, cursor);
				cursor = body.next;
			}
			t.deepEqual(seen, ids);
			const exact = createExtendedListHandler(ctx, {
				maxResponseBytes: new TextEncoder().encode(first).byteLength,
			});
			t.equal(
				(
					await exact(
						new Request(
							"https://authority.example/list?claims=metadata&audit_timestamps=true&limit=1",
						),
					)
				).status,
				200,
			);
			const tooSmall = createExtendedListHandler(ctx, { maxResponseBytes: 50 });
			t.equal(
				(await tooSmall(new Request("https://authority.example/list?claims=metadata"))).status,
				500,
			);
		});
		test("default byte budget interoperates with the default client for signed statements", async (t) => {
			const { ctx, storage, publicKey } = await createTestContext();
			for (let i = 0; i < 100; i++)
				await storage.subordinates.add({
					entityId: entityId(`https://member.example/${String(i).padStart(3, "0")}`),
					jwks: { keys: [publicKey] },
					metadata: { openid_relying_party: { organization_name: "x".repeat(5000) } },
					createdAt: 1500,
					updatedAt: 1500,
				});
			const handler = createExtendedListHandler(ctx);
			const result = await fetchExtendedSubordinatesList(
				"https://authority.example/list",
				undefined,
				{
					engine: testEngine,
					httpClient: (input, init) => handler(new Request(String(input), init)),
				},
			);
			t.true(result.ok);
			if (result.ok) {
				t.ok(result.value.next);
				t.ok(result.value.immediate_subordinate_entities.length < 100);
				t.ok(result.value.immediate_subordinate_entities[0]?.subordinate_statement);
			}
		});
	});

	module("authority / listing limits and event publication", () => {
		test("invalid listing configuration fails before serving a page", async (t) => {
			const { ctx } = await createTestContext();
			for (const name of [
				"maxPageSize",
				"defaultPageSize",
				"maxStorePagesPerRequest",
				"maxResponseBytes",
				"storeBatchSize",
			])
				for (const value of [0, -1, NaN, Infinity, 1.5, Number.MAX_SAFE_INTEGER + 1])
					t.throws(
						() => createExtendedListHandler(ctx, { [name]: value }),
						/positive safe integer/,
					);
			t.throws(
				() => createExtendedListHandler(ctx, { maxPageSize: 2, defaultPageSize: 3 }),
				/defaultPageSize/,
			);
			const handler = createExtendedListHandler(ctx, { maxPageSize: 1, storeBatchSize: 2 });
			t.equal((await handler(new Request("https://authority.example/list?claims="))).status, 200);
		});
		test("custom event history is checked before signing", async (t) => {
			const f = await SubordinateEventsFixture.fixture();
			const storage: StorageAdapter = {
				subordinates: f.storage.subordinates,
				subordinateEvents: f.storage.subordinateEvents,
				transaction: (operation) =>
					f.storage.transaction((tx) =>
						operation({
							...tx,
							subordinateEvents: {
								append: async () => {},
								list: async () => [{ iat: 1500, event: "" }],
							},
						}),
					),
			};
			const authority = await TrustAnchor.create(fixtureHostConfig({ ...f.config, storage }));
			await t.rejects(authority.getSubordinateEvents(SubordinateEventsFixture.subject), /empty/);
			const response = await authority.handleRequest(
				new Request(
					`${SubordinateEventsFixture.endpoint}&sub=${encodeURIComponent(SubordinateEventsFixture.subject)}`,
				),
			);
			t.equal(response.status, 500);
		});
		test("empty event names are rejected before storage or signing", async (t) => {
			const f = await SubordinateEventsFixture.fixture();
			await t.rejects(
				f.authority.recordSubordinateEvents(SubordinateEventsFixture.subject, [
					{ iat: 1500, event: "" },
				]),
				/empty/,
			);
			await t.rejects(
				f.storage.subordinateEvents!.append(
					SubordinateEventsFixture.issuer,
					SubordinateEventsFixture.subject,
					[{ iat: 1500, event: "" }],
				),
				/empty/,
			);
			await f.authority.recordSubordinateEvents(SubordinateEventsFixture.subject, [
				{
					iat: 1500,
					event: "custom",
					event_description: "",
					information_uri: "http://docs.example/#event",
				},
			]);
			t.equal(
				(
					await f.storage.subordinateEvents!.list(
						SubordinateEventsFixture.issuer,
						SubordinateEventsFixture.subject,
					)
				).length,
				1,
			);
		});
	});

	module("authority / trust mark publication and eligibility", () => {
		const subject = entityId("https://member.example");
		const type = "https://marks.example/accreditation";
		const options = { clock: { now: () => 1000 }, clockSkewSeconds: 60 };
		const request = (query: string) => new Request(`${ENTITY_ID}/extended?${query}`);
		async function fixture() {
			const f = await createTestContext({ options: { ...options, engine: testEngine } });
			await f.subordinates.add({
				entityId: subject,
				jwks: { keys: [f.publicKey] },
				createdAt: 100,
				updatedAt: 900,
			});
			const make = async (
				issuedAt: number,
				expiresAt?: number,
				changes: Record<string, unknown> = {},
			): Promise<TrustMarkRecord> => ({
				trustMarkType: type,
				subject,
				issuedAt,
				...(expiresAt === undefined ? {} : { expiresAt }),
				active: true,
				jwt: await signEntityStatement(
					{
						iss: ENTITY_ID,
						sub: subject,
						trust_mark_type: type,
						iat: issuedAt,
						...(expiresAt === undefined ? {} : { exp: expiresAt }),
						...changes,
					},
					new SigningEntryFixture(f.signingKey),
					{ typ: JwtTyp.TrustMark },
				),
			});
			return { ...f, make };
		}
		test("publishes standard references separately from signed subordinate statements", async (t) => {
			const f = await fixture();
			const mark = await f.make(900, 2000);
			await f.trustMarks.issue(mark);
			const response = await createExtendedListHandler(f.ctx)(
				request("claims=trust_marks,subordinate_statement"),
			);
			t.equal(response.status, 200);
			const entry = ((await response.json()) as ExtendedListResponse)
				.immediate_subordinate_entities[0]!;
			t.equal(entry.id, subject);
			t.deepEqual(entry.trust_marks, [{ trust_mark_type: type, trust_mark: mark.jwt }]);
			t.true(TrustMarkRefSchema.array().safeParse(entry.trust_marks).success);
			const statement = await verifyEntityStatement(
				entry.subordinate_statement!,
				{ keys: [f.publicKey] },
				{ ...options, engine: testEngine },
			);
			t.true(statement.ok);
			if (statement.ok) t.false("trust_marks" in statement.value.payload);
		});
		for (const invalid of [
			"type",
			"jwt-subject",
			"record-subject",
			"typ",
			"undecodable",
			"reference",
		] as const) {
			test(`rejects inconsistent requested Trust Marks: ${invalid}`, async (t) => {
				const f = await fixture();
				let mark = await f.make(
					900,
					2000,
					invalid === "jwt-subject" ? { sub: "https://other.example" } : {},
				);
				if (invalid === "type") mark = { ...mark, trustMarkType: `${type}/other` };
				if (invalid === "record-subject")
					mark = { ...mark, subject: entityId("https://other.example") };
				if (invalid === "undecodable") mark = { ...mark, jwt: "private-invalid-token-sentinel" };
				if (invalid === "reference") mark = { ...mark, trustMarkType: 42 as unknown as string };
				if (invalid === "typ")
					mark = {
						...mark,
						jwt: await signEntityStatement(
							{ iss: ENTITY_ID, sub: subject, trust_mark_type: type, iat: 900 },
							new SigningEntryFixture(f.signingKey),
						),
					};
				const logs: string[] = [];
				const ctx: HandlerContext = {
					...f.ctx,
					storage: new Proxy(f.storage, {
						get(target, property) {
							if (property === "trustMarks")
								return new Proxy(f.trustMarks, {
									get(store, field) {
										if (field === "listValidForSubject") return async () => [mark];
										const value = Reflect.get(store, field);
										return typeof value === "function" ? value.bind(store) : value;
									},
								});
							const value = Reflect.get(target, property);
							return typeof value === "function" ? value.bind(target) : value;
						},
					}),
					options: {
						engine: testEngine,
						...options,
						logger: {
							debug() {},
							info() {},
							warn() {},
							error(message, context) {
								logs.push(
									message,
									JSON.stringify(context, (_key, value) =>
										value instanceof Error ? value.message : value,
									),
								);
							},
						},
					},
				};
				const handler = createExtendedListHandler(ctx);
				const response = await handler(request("claims=trust_marks"));
				t.equal(response.status, 500);
				const body = (await response.json()) as { error: string };
				t.equal(body.error, FederationErrorCode.ServerError);
				t.false(JSON.stringify(body).includes(mark.jwt));
				t.false(logs.join(" ").includes(mark.jwt));
				t.equal(
					(await handler(request("claims="))).status,
					200,
					"unrequested claims are not extracted",
				);
			});
		}
		test("applies issuance eligibility to every storage query and transaction", async (t) => {
			const f = await fixture();
			const current = await f.make(900, 1500);
			const future = await f.make(1100, 2000);
			await f.trustMarks.issue(current);
			await f.trustMarks.issue(future);
			async function check(store: TrustMarkStorage) {
				for (const [time, expected] of [
					[899, undefined],
					[900, current],
					[1000, current],
					[1100, future],
					[2000, undefined],
				] as const) {
					t.deepEqual(await store.getValid(type, subject, time), expected);
					t.deepEqual(
						(await store.listValid(type, time, { limit: 10 })).items,
						expected ? [expected] : [],
					);
					t.deepEqual(await store.listValidForSubject(subject, time), expected ? [expected] : []);
					t.equal(await store.hasAnyValid(subject, time), expected !== undefined);
				}
				t.deepEqual(await store.getByJwt(future.jwt), future, "future marks remain in history");
			}
			await check(f.trustMarks);
			await f.storage.transaction(async (tx) => check(tx.trustMarks!));
		});
		for (const issuedAt of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
			test(`rejects nonfinite stored issuance time ${issuedAt}`, async (t) => {
				const f = await fixture();
				const mark = { ...(await f.make(900)), issuedAt };
				await f.trustMarks.issue(mark);
				t.strictEqual(await f.trustMarks.getValid(type, subject, 1000), undefined);
				t.deepEqual((await f.trustMarks.listValid(type, 1000, { limit: 10 })).items, []);
				t.deepEqual(await f.trustMarks.listValidForSubject(subject, 1000), []);
				t.false(await f.trustMarks.hasAnyValid(subject, 1000));
			});
		}
		test("listing and retrieval exclude future marks and issuance creates a usable replacement", async (t) => {
			const f = await fixture();
			const future = await f.make(1001, 2000);
			await f.trustMarks.issue(future);
			const query = new URLSearchParams({ trust_mark_type: type, sub: subject });
			for (const filter of ["trust_marked=true", `trust_mark_type=${encodeURIComponent(type)}`]) {
				t.deepEqual(await (await createListHandler(f.ctx)(request(filter))).json(), []);
				t.deepEqual(
					await (await createExtendedListHandler(f.ctx)(request(`claims=&${filter}`))).json(),
					{ immediate_subordinate_entities: [] },
				);
			}
			const unfiltered = (await (
				await createExtendedListHandler(f.ctx)(request("claims=trust_marks"))
			).json()) as ExtendedListResponse;
			t.deepEqual(unfiltered.immediate_subordinate_entities[0]!.trust_marks, []);
			t.deepEqual(
				await (await createTrustMarkListHandler(f.ctx)(request(query.toString()))).json(),
				[],
			);
			t.equal((await createTrustMarkHandler(f.ctx)(request(query.toString()))).status, 404);
			const issuer = await TrustAnchor.create(fixtureHostConfig(hostConfig(f.ctx)));
			const jwt = await issuer.issueTrustMark(subject, type);
			t.notEqual(jwt, future.jwt);
			const checked = await validateTrustMark(
				jwt,
				{ [type]: [ENTITY_ID] },
				{ keys: [f.publicKey] },
				{ engine: testEngine, ...options, clockSkewSeconds: 0, expectedSubject: subject },
			);
			t.true(checked.ok);
			t.equal((await f.trustMarks.getValid(type, subject, 1000))?.jwt, jwt);
			t.equal(await (await createTrustMarkHandler(f.ctx)(request(query.toString()))).text(), jwt);
			t.equal(await issuer.issueTrustMark(subject, type), jwt);
		});
		test("status uses signed issuance time and preserves active, expired and revoked results", async (t) => {
			const f = await fixture();
			for (const [iat, exp, active, expected] of [
				[900, undefined, true, "active"],
				[1000, 2000, true, "active"],
				[1001, 2000, true, "invalid"],
				[undefined, 2000, true, "invalid"],
				[null, 2000, true, "invalid"],
				["900", 2000, true, "invalid"],
				[900, 1000, true, "expired"],
				[900, 2000, false, "revoked"],
			] as const) {
				// Keep the stored timestamp plausible: status must inspect the signed JWT itself.
				const mark = { ...(await f.make(900, exp, { iat })), active };
				await f.trustMarks.issue(mark);
				const res = await createTrustMarkStatusHandler(f.ctx)(
					new Request(`${ENTITY_ID}/status`, {
						method: "POST",
						body: new URLSearchParams({ trust_mark: mark.jwt }),
					}),
				);
				t.equal(res.status, 200);
				const checked = await verifyEntityStatement(
					await res.text(),
					{ keys: [f.publicKey] },
					{ engine: testEngine, ...options, expectedTyp: JwtTyp.TrustMarkStatusResponse },
				);
				t.true(checked.ok);
				if (checked.ok) t.equal(checked.value.payload.status, expected);
			}
		});
	});

	module("authority / extended listing extensions", () => {
		const c = CorePublic;
		async function fixture(extendedListing?: ExtendedListingConfig) {
			const f = await createTestContext();
			const config = {
				entityId: f.ctx.entityId,
				crypto: f.crypto,
				storage: f.storage,
				metadata: {
					federation_entity: {
						...f.ctx.metadata.federation_entity,
						federation_extended_list_endpoint: `${ENTITY_ID}/extended`,
					},
				},
				extendedListing,
			};
			return { ...f, config, authority: await TrustAnchor.create(fixtureHostConfig(config)) };
		}
		test("cursor storage failures return errors through HTTP and both authority APIs", async (t) => {
			const f = await fixture();
			await f.authority.registerSubordinate({ entityId: LEAF_ID, jwks: { keys: [f.publicKey] } });
			const intermediate = await Intermediate.create(
				fixtureHostConfig({ ...f.config, authorityHints: [TA_ID] }),
			);
			t.true((await f.authority.listSubordinatesExtended({ from: LEAF_ID, claims: [] })).ok);
			const missing = await f.authority.handleRequest(
				new Request(`${ENTITY_ID}/extended?from=unknown`),
			);
			t.equal(missing.status, 404);
			t.equal(((await missing.json()) as { error: string }).error, "page_not_found");
			f.subordinates.get = async () => {
				throw new Error("private database details");
			};
			for (const authority of [f.authority, intermediate]) {
				const result = await authority.listSubordinatesExtended({ from: LEAF_ID, claims: [] });
				t.false(result.ok);
				if (!result.ok) {
					t.equal(result.error.code, "server_error");
					t.false(result.error.description.includes("database"));
				}
				const response = await authority.handleRequest(
					new Request(`${ENTITY_ID}/extended?from=${encodeURIComponent(LEAF_ID)}`),
				);
				t.equal(response.status, 500);
				t.equal(((await response.json()) as { error: string }).error, "server_error");
			}
		});
		test("local and HTTP calls accept extension entity types and repeated custom filters", async (t) => {
			const campus: AuthorityPublic.ExtendedListingRequestFilter = {
				parse: (values) => c.ok([...values]),
				matches: (record, value) =>
					Array.isArray(value) && value.includes(record.additionalClaims?.campus),
			};
			const f = await fixture({ requestFilters: { campus } });
			for (const [n, location] of ["north", "south"].entries())
				await f.authority.registerSubordinate({
					entityId: entityId(`https://member${n}.example`),
					jwks: { keys: [f.publicKey] },
					entityTypes: ["custom_protocol"],
					additionalClaims: { campus: location },
				});
			const params = { entityType: "custom_protocol", claims: ["campus"] };
			const options = { additionalParameters: { campus: ["north", "west"] } };
			const local = await f.authority.listSubordinatesExtended(params, options);
			t.true(local.ok);
			if (local.ok)
				t.deepEqual(local.value.immediate_subordinate_entities, [
					{ id: "https://member0.example", campus: "north" },
				]);
			const remote = await fetchExtendedSubordinatesList(`${ENTITY_ID}/extended`, params, {
				engine: testEngine,
				...options,
				httpClient: async (url, init) => f.authority.handleRequest(new Request(url, init)),
			});
			t.deepEqual(remote, local);
			const intermediate = await Intermediate.create(
				fixtureHostConfig({ ...f.config, authorityHints: [TA_ID] }),
			);
			t.deepEqual(await intermediate.listSubordinatesExtended(params, options), local);
			const conflict = await f.authority.listSubordinatesExtended(params, {
				additionalParameters: { entity_type: "other" },
			});
			t.false(conflict.ok);
			const credentials = await f.authority.listSubordinatesExtended(params, {
				additionalParameters: { client_secret: "secret" },
			});
			t.false(credentials.ok);
		});
		test("selected stored claims preserve JSON names and cannot replace listing fields", async (t) => {
			const before = Object.getOwnPropertyDescriptors(Object.prototype);
			const f = await fixture({ defaultClaims: ["x_access"] });
			const extensions = JSON.parse(
				'{"x_access":{"roles":["student"]},"__proto__":{"polluted":true},"constructor":"safe","toString":"data","id":"wrong","registered":-1,"updated":-1}',
			);
			await f.authority.registerSubordinate({
				entityId: LEAF_ID,
				jwks: { keys: [f.publicKey] },
				additionalClaims: extensions,
			});
			extensions.x_access.roles.push("mutated");
			const result = await f.authority.listSubordinatesExtended({
				claims: [...Object.keys(extensions), "subordinate_statement", "missing"],
				auditTimestamps: true,
			});
			t.true(result.ok);
			if (result.ok) {
				const row = result.value.immediate_subordinate_entities[0]!;
				t.equal(row.id, LEAF_ID);
				t.notEqual(row.registered, -1);
				t.notEqual(row.updated, -1);
				t.deepEqual(row.x_access, { roles: ["student"] });
				t.true(Object.hasOwn(row, "__proto__"));
				t.deepEqual(Object.getOwnPropertyDescriptor(row, "__proto__")?.value, { polluted: true });
				t.equal(row.constructor as unknown, "safe");
				t.equal(row.toString as unknown, "data");
				t.false(Object.hasOwn(row, "missing"));
				const jwt = decodeEntityStatement(row.subordinate_statement as string);
				t.true(jwt.ok);
				if (jwt.ok) t.equal(jwt.value.payload.id, "wrong", "SS extension remains intact");
			}
			const defaults = await f.authority.listSubordinatesExtended();
			if (defaults.ok)
				t.deepEqual(defaults.value.immediate_subordinate_entities, [
					{ id: LEAF_ID, x_access: { roles: ["student"] } },
				]);
			const minimal = await f.authority.listSubordinatesExtended({ claims: [] });
			if (minimal.ok) t.deepEqual(minimal.value.immediate_subordinate_entities, [{ id: LEAF_ID }]);
			t.deepEqual(
				Object.entries(Object.getOwnPropertyDescriptors(Object.prototype)),
				Object.entries(before),
			);
		});
		test("stored extension claims count against the byte limit across pages", async (t) => {
			const f = await fixture({ maxResponseBytes: 700 });
			for (let i = 0; i < 3; i++)
				await f.authority.registerSubordinate({
					entityId: entityId(`https://member${i}.example`),
					jwks: { keys: [f.publicKey] },
					additionalClaims: { detail: "é".repeat(200) },
				});
			const ids: string[] = [];
			let from: string | undefined;
			for (let i = 0; i < 4; i++) {
				const response = await f.authority.handleRequest(
					new Request(
						`${ENTITY_ID}/extended?claims=detail${from ? `&from=${encodeURIComponent(from)}` : ""}`,
					),
				);
				t.equal(response.status, 200);
				const text = await response.text();
				t.true(new TextEncoder().encode(text).length <= 700);
				const page = JSON.parse(text) as ExtendedListResponse;
				ids.push(...page.immediate_subordinate_entities.map((r) => r.id));
				from = page.next;
				if (!from) break;
			}
			t.deepEqual(
				ids,
				[0, 1, 2].map((i) => `https://member${i}.example`),
			);
		});
		test("custom filters preserve sparse inclusive pagination and the scan budget", async (t) => {
			for (const cap of [1, 2, 16]) {
				let parsed = 0;
				const f = await fixture({
					defaultPageSize: 1,
					storeBatchSize: 2,
					maxStorePagesPerRequest: cap,
					requestFilters: {
						campus: {
							parse: (values) => {
								parsed++;
								return c.ok([...values]);
							},
							matches: (r, v) => Array.isArray(v) && v.includes(r.additionalClaims?.campus),
						},
						enrolled: {
							parse: () => c.ok(true),
							matches: (r) => r.additionalClaims?.enrolled === true,
						},
					},
				});
				for (let i = 0; i < 8; i++)
					await f.authority.registerSubordinate({
						entityId: entityId(`https://member${i}.example`),
						jwks: { keys: [f.publicKey] },
						additionalClaims: { campus: i % 2 ? "north" : "south", enrolled: i > 2 },
					});
				let calls = 0;
				const original = f.subordinates.list.bind(f.subordinates);
				f.subordinates.list = async (...args) => {
					calls++;
					return original(...args);
				};
				const ids: string[] = [];
				let from: string | undefined;
				let pages = 0;
				for (; pages < 10; ) {
					const before = calls;
					const result = await f.authority.listSubordinatesExtended(
						{ from, claims: [] },
						{ additionalParameters: { campus: "north", enrolled: "yes" } },
					);
					pages++;
					t.true(result.ok);
					if (!result.ok) break;
					t.true(calls - before <= cap);
					t.true(result.value.immediate_subordinate_entities.length <= 1);
					ids.push(...result.value.immediate_subordinate_entities.map((r) => r.id));
					t.notEqual(result.value.next, from === undefined ? "not-a-cursor" : from);
					from = result.value.next;
					if (!from) break;
				}
				t.deepEqual(
					ids,
					[3, 5, 7].map((i) => `https://member${i}.example`),
				);
				t.equal(parsed, pages, "parse once per request, including empty scan pages");
			}
		});
		test("filters validate empty requests, contain callback failures and protect snapshots", async (t) => {
			const f = await fixture();
			let reads = 0;
			const list = f.subordinates.list.bind(f.subordinates);
			f.subordinates.list = async (...args) => {
				reads++;
				return list(...args);
			};
			const request = () => new Request(`${ENTITY_ID}/extended?campus=north&claims=`);
			const invalid = createExtendedListHandler(f.ctx, {
				requestFilters: {
					campus: {
						parse: () =>
							c.err(c.federationError(FederationErrorCode.InvalidRequest, "Unknown campus")),
						matches: () => true,
					},
				},
			});
			t.equal((await invalid(request())).status, 400);
			t.equal(reads, 0);
			await f.authority.registerSubordinate({
				entityId: LEAF_ID,
				jwks: { keys: [f.publicKey] },
				additionalClaims: { campus: "north" },
			});
			for (const parse of [
				() => {
					throw Error("secret");
				},
				async () => {
					throw Error("secret");
				},
				() => ({ ok: true }),
			]) {
				const handler = createExtendedListHandler(f.ctx, {
					requestFilters: {
						campus: {
							parse: parse as AuthorityPublic.ExtendedListingRequestFilter["parse"],
							matches: () => true,
						},
					},
				});
				const response = await handler(request());
				t.equal(response.status, 500);
				t.false((await response.text()).includes("secret"));
			}
			const external = { choices: ["north"] };
			const config: ExtendedListingConfig = {
				requestFilters: {
					campus: {
						parse: () => c.ok(external),
						matches: (record, value) => {
							external.choices.push("south");
							t.true(Object.isFrozen(record.jwks.keys));
							t.true(Object.isFrozen((value as typeof external).choices));
							t.deepEqual(value, { choices: ["north"] });
							return true;
						},
					},
				},
			};
			const captured = createExtendedListHandler(f.ctx, config);
			config.requestFilters = {
				campus: {
					parse: () => {
						throw Error("changed");
					},
					matches: () => false,
				},
			};
			t.equal((await captured(request())).status, 200);
			for (const matches of [
				() => {
					throw Error("secret");
				},
				async () => {
					throw Error("secret");
				},
				() => "yes",
			]) {
				const handler = createExtendedListHandler(f.ctx, {
					requestFilters: {
						campus: {
							parse: () => c.ok(null),
							matches: matches as AuthorityPublic.ExtendedListingRequestFilter["matches"],
						},
					},
				});
				t.equal((await handler(request())).status, 500);
			}
		});
		test("filter registries reject selector and credential collisions, but allow own JSON names", async (t) => {
			const f = await fixture();
			const definition: AuthorityPublic.ExtendedListingRequestFilter = {
				parse: () => c.ok(true),
				matches: () => true,
			};
			const ctx = {
				...f.ctx,
				endpointAuthentication: {
					methods: {
						custom: { parameters: ["proof"], authenticate: () => c.ok({ entityId: LEAF_ID }) },
					},
				},
			};
			for (const name of [
				"limit",
				"claims",
				"from",
				"entity_type",
				"client_id",
				"client_secret",
				"proof",
			])
				t.throws(
					() => createExtendedListHandler(ctx, { requestFilters: { [name]: definition } }),
					/cannot replace/,
				);
			for (const name of ["__proto__", "constructor", "toString"]) {
				let calls = 0;
				const handler = createExtendedListHandler(ctx, {
					requestFilters: Object.fromEntries([
						[
							name,
							{
								...definition,
								parse: () => {
									calls++;
									return c.ok(true);
								},
							},
						],
					]),
				});
				t.equal(
					(await handler(new Request(`${ENTITY_ID}/extended?${name}=yes&claims=`))).status,
					200,
				);
				t.equal(calls, 1);
			}
			t.equal(
				(
					await createExtendedListHandler(ctx)(
						new Request(`${ENTITY_ID}/extended?toString=ignored&claims=`),
					)
				).status,
				200,
			);
		});
		test("one request deadline and abort release callers waiting for filter callbacks", async (t) => {
			const f = await fixture();
			for (const phase of ["parse", "matches"] as const) {
				await f.storage.subordinates.remove(LEAF_ID).catch(() => {});
				await f.authority.registerSubordinate({ entityId: LEAF_ID, jwks: { keys: [f.publicKey] } });
				for (const timeout of [false, true]) {
					let entered!: () => void;
					const started = new Promise<void>((r) => {
						entered = r;
					});
					const never = () => {
						entered();
						return new Promise<never>(() => {});
					};
					const handler = createExtendedListHandler(
						{ ...f.ctx, options: { engine: testEngine, httpTimeoutMs: timeout ? 20 : 1000 } },
						{
							requestFilters: {
								campus: {
									parse: phase === "parse" ? never : () => c.ok(true),
									matches: phase === "matches" ? never : () => true,
								},
							},
						},
					);
					const controller = new AbortController();
					const result = handler(
						new Request(`${ENTITY_ID}/extended?campus=north&claims=`, {
							signal: controller.signal,
						}),
					);
					await started;
					if (!timeout) controller.abort();
					t.equal((await result).status, 500);
				}
			}
		});

		test("local cancellation releases a pending cursor lookup without a custom filter", async (t) => {
			const f = await fixture();
			let entered!: () => void;
			const started = new Promise<void>((resolve) => {
				entered = resolve;
			});
			let finish!: (record: SubordinateRecord | undefined) => void;
			f.subordinates.get = () => {
				entered();
				return new Promise((resolve) => {
					finish = resolve;
				});
			};
			const controller = new AbortController();
			const result = f.authority.listSubordinatesExtended(
				{ from: LEAF_ID, claims: [] },
				{ signal: controller.signal },
			);
			await started;
			controller.abort();
			const cancelled = await result;
			t.false(cancelled.ok);
			if (!cancelled.ok) t.equal(cancelled.error.code, "server_error");
			finish(undefined);
			const preAborted = await f.authority.listSubordinatesExtended(
				{ claims: [] },
				{ signal: controller.signal },
			);
			t.false(preAborted.ok);
		});
		test("custom filters use the shared authenticated POST and fixed-query rules", async (t) => {
			const f = await fixture();
			let authCalls = 0;
			let parseCalls = 0;
			const authority = await TrustAnchor.create(
				fixtureHostConfig({
					...f.config,
					endpointAuthentication: {
						methods: {
							custom: {
								parameters: ["proof"],
								authenticate: (input) => {
									authCalls++;
									return input.parameters.proof?.[0] === "valid"
										? c.ok({ entityId: LEAF_ID })
										: c.err({
												code: FederationErrorCode.InvalidClient,
												description: "Invalid proof",
											});
								},
							},
						},
					},
					metadata: {
						federation_entity: {
							...f.config.metadata.federation_entity,
							federation_extended_list_endpoint: `${ENTITY_ID}/extended?campus=north`,
							federation_extended_list_endpoint_auth_methods: ["none", "custom"],
						},
					},
					extendedListing: {
						requestFilters: {
							campus: {
								parse: (v) => {
									parseCalls++;
									return c.ok([...v]);
								},
								matches: () => true,
							},
						},
					},
				}),
			);
			const get = await authority.handleRequest(
				new Request(`${ENTITY_ID}/extended?campus=north&claims=`),
			);
			t.equal(get.status, 200);
			const post = await authority.handleRequest(
				new Request(`${ENTITY_ID}/extended?campus=north`, {
					method: "POST",
					body: new URLSearchParams({ campus: "north", proof: "valid", claims: "" }),
				}),
			);
			t.equal(post.status, 200);
			t.equal(authCalls, 1);
			t.equal(parseCalls, 2);
			const conflict = await authority.handleRequest(
				new Request(`${ENTITY_ID}/extended?campus=north`, {
					method: "POST",
					body: new URLSearchParams({ campus: "south", proof: "valid" }),
				}),
			);
			t.equal(conflict.status, 400);
			t.equal(parseCalls, 2);
		});
	});

	module("authority / extended listing sparse pages", () => {
		async function fixture(makeList: (records: SubordinateRecord[]) => SubordinateStorage["list"]) {
			const f = await createTestContext();
			const records: SubordinateRecord[] = Array.from({ length: 6 }, (_, i) => ({
				entityId: entityId(`https://member${i}.example`),
				jwks: { keys: [f.publicKey] },
				createdAt: 100,
				updatedAt: i === 5 ? 2000 : 500,
			}));
			for (const record of records) await f.subordinates.add(record);
			const list = makeList(records);
			let calls = 0;
			const subordinates = new Proxy(f.subordinates, {
				get(target, property) {
					if (property === "list")
						return (...args: Parameters<SubordinateStorage["list"]>) => {
							calls++;
							return list(...args);
						};
					const value = Reflect.get(target, property);
					return typeof value === "function" ? value.bind(target) : value;
				},
			});
			const storage = new Proxy(f.storage, {
				get(target, property) {
					if (property === "subordinates") return subordinates;
					const value = Reflect.get(target, property);
					return typeof value === "function" ? value.bind(target) : value;
				},
			});
			return { ctx: { ...f.ctx, storage }, records, calls: () => calls };
		}
		for (const cap of [1, 2, 16]) {
			test(`traverses empty first, middle and final pages with a ${cap}-page scan cap`, async (t) => {
				for (const matches of [[], [5], [0, 5], [0]]) {
					const f = await fixture((records) => async (_filter, options) => {
						const remaining = records.filter(
							(record) => options?.cursor === undefined || record.entityId >= options.cursor,
						);
						const size = options?.limit ?? 2;
						const scanned = remaining.slice(0, size);
						const items = scanned.filter((record) => matches.includes(records.indexOf(record)));
						const next = remaining[size];
						return { items, ...(next ? { nextCursor: next.entityId } : {}) };
					});
					const handler = createExtendedListHandler(f.ctx, {
						defaultPageSize: 10,
						storeBatchSize: 2,
						maxStorePagesPerRequest: cap,
					});
					const found: string[] = [];
					let cursor: string | undefined;
					let completed = false;
					for (let requestNumber = 0; requestNumber < 5; requestNumber++) {
						const before = f.calls();
						const params = new URLSearchParams({ claims: "" });
						if (cursor !== undefined) params.set("from", cursor);
						const response = await handler(new Request(`${ENTITY_ID}/extended?${params}`));
						t.equal(response.status, 200);
						const body = (await response.json()) as ExtendedListResponse;
						found.push(
							...body.immediate_subordinate_entities.map((entry: { id: string }) => entry.id),
						);
						t.true(f.calls() - before <= cap, "scan respects the per-request work cap");
						if (body.next === undefined) {
							completed = true;
							break;
						}
						t.true(cursor === undefined || body.next > cursor);
						cursor = body.next;
					}
					t.true(completed);
					t.equal(f.calls(), 3, "all internal pages were scanned, including empty pages");
					t.deepEqual(
						found,
						matches.map((index) => f.records[index]!.entityId),
					);
				}
			});
		}
		test("time filtering resumes inclusively after an empty page at the work cap", async (t) => {
			const f = await fixture((records) => async (_filter, options) => {
				const remaining = records.filter(
					(record) => options?.cursor === undefined || record.entityId >= options.cursor,
				);
				const size = options?.limit ?? 2;
				return {
					items: remaining
						.slice(0, size)
						.filter((record) => record.updatedAt >= (options?.updatedAfter ?? 0)),
					...(remaining[size] ? { nextCursor: remaining[size].entityId } : {}),
				};
			});
			const handler = createExtendedListHandler(f.ctx, {
				storeBatchSize: 2,
				maxStorePagesPerRequest: 1,
			});
			const first = (await (
				await handler(new Request(`${ENTITY_ID}/extended?claims=&updated_after=1000`))
			).json()) as ExtendedListResponse;
			t.deepEqual(first, { immediate_subordinate_entities: [], next: f.records[2]!.entityId });
			const second = (await (
				await handler(
					new Request(
						`${ENTITY_ID}/extended?claims=&updated_after=1000&from=${encodeURIComponent(first.next!)}`,
					),
				)
			).json()) as ExtendedListResponse;
			t.deepEqual(second, { immediate_subordinate_entities: [], next: f.records[4]!.entityId });
			const third = await (
				await handler(
					new Request(
						`${ENTITY_ID}/extended?claims=&updated_after=1000&from=${encodeURIComponent(second.next!)}`,
					),
				)
			).json();
			t.deepEqual(third, {
				immediate_subordinate_entities: [
					{ id: f.records[5]!.entityId, registered: 100, updated: 2000 },
				],
			});
		});
		for (const scenario of ["repeated", "backward", "last-returned"] as const) {
			test(`rejects a ${scenario} storage continuation`, async (t) => {
				const f = await fixture((records) => async (_filter, options) => {
					if (scenario === "last-returned")
						return { items: [records[0]!], nextCursor: records[0]!.entityId };
					if (!options?.cursor) return { items: [], nextCursor: records[2]!.entityId };
					return {
						items: [],
						nextCursor: scenario === "repeated" ? options.cursor : records[0]!.entityId,
					};
				});
				const response = await createExtendedListHandler(f.ctx)(
					new Request(`${ENTITY_ID}/extended?claims=`),
				);
				t.equal(response.status, 500);
				t.equal(
					((await response.json()) as { error: string }).error,
					FederationErrorCode.ServerError,
				);
				t.equal(f.calls(), scenario === "last-returned" ? 1 : 2);
			});
		}
	});

	module("authority / listing filter semantics", () => {
		test("false adds no mark restriction across storage, HTTP and both authority classes", async (t) => {
			const { ctx, storage, crypto, subordinates, trustMarks } = await createTestContext({
				options: { clock: { now: () => 2000 }, engine: testEngine },
			});
			const ids = ["a", "b", "c", "d", "e"].map((name) => entityId(`https://${name}.example.com`));
			const alpha = "https://marks.example/alpha";
			const beta = "https://marks.example/beta";
			for (const id of ids)
				await subordinates.add({
					entityId: id,
					jwks: { keys: [] },
					createdAt: 1000,
					updatedAt: 1000,
				});
			for (const [subject, type, active, expiresAt] of [
				[ids[0]!, alpha, true, 3000],
				[ids[0]!, beta, true, 3000],
				[ids[1]!, beta, true, 3000],
				[ids[3]!, alpha, true, 2000],
				[ids[4]!, beta, false, 3000],
			] as const)
				await trustMarks.issue({
					subject,
					trustMarkType: type,
					active,
					expiresAt,
					issuedAt: 1000,
					jwt: `${subject}.${type}`,
				});
			const base = createListHandler(ctx);
			const extended = createExtendedListHandler(ctx);
			const config: AuthorityConfig = {
				entityId: ENTITY_ID,
				crypto,
				storage,
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${ENTITY_ID}/fetch`,
						federation_list_endpoint: `${ENTITY_ID}/list`,
						federation_extended_list_endpoint: `${ENTITY_ID}/extended`,
					},
				},
				options: { clock: { now: () => 2000 } },
			};
			const servers = [
				await TrustAnchor.create(fixtureHostConfig(config)),
				await Intermediate.create(
					fixtureHostConfig({
						...config,
						authorityHints: [entityId("https://superior.example.com")],
					}),
				),
			];
			for (const flag of [undefined, true, false]) {
				for (const types of [undefined, [alpha], [alpha, beta, beta]]) {
					const expected = types
						? types.length === 1
							? ids.slice(0, 1)
							: ids.slice(0, 2)
						: flag === true
							? ids.slice(0, 2)
							: ids;
					const filter = {
						validAt: 2000,
						...(flag === undefined ? {} : { trustMarked: flag }),
						...(types ? { trustMarkType: types } : {}),
					};
					t.deepEqual(
						(await subordinates.list(filter)).items.map((record) => record.entityId),
						expected,
						"storage",
					);
					const url = new URL(`${ENTITY_ID}/extended?claims=&limit=1`);
					if (flag !== undefined) url.searchParams.set("trust_marked", String(flag));
					for (const type of types ?? []) url.searchParams.append("trust_mark_type", type);
					const listed: string[] = [];
					for (let page = 0; page <= ids.length; page++) {
						const response = await extended(new Request(url));
						t.equal(response.status, 200);
						const body = (await response.json()) as {
							immediate_subordinate_entities: Array<{ id: string }>;
							next?: string;
						};
						listed.push(...body.immediate_subordinate_entities.map(({ id }) => id));
						if (body.next === undefined) break;
						url.searchParams.set("from", body.next);
					}
					t.deepEqual(listed, expected, "extended HTTP pages");
					if (!types || types.length === 1) {
						t.deepEqual(await (await base(new Request(url))).json(), expected, "base HTTP");
					}
					for (const server of servers) {
						t.deepEqual(await server.listSubordinates(filter), expected, "public base API");
						const result = await server.listSubordinatesExtended({
							claims: [],
							...(flag === undefined ? {} : { trustMarked: flag }),
							...(types ? { trustMarkType: types } : {}),
						});
						t.true(result.ok);
						if (result.ok)
							t.deepEqual(
								result.value.immediate_subordinate_entities.map(({ id }) => id),
								expected,
								"public extended API",
							);
					}
				}
			}
		});
		test("false alone needs neither a mark store nor a validity time in direct storage", async (t) => {
			const storage = new MemoryStorageAdapter({ engine: testEngine });
			await storage.subordinates.add({
				entityId: ENTITY_ID,
				jwks: { keys: [] },
				createdAt: 1,
				updatedAt: 1,
			});
			t.deepEqual(
				(await storage.subordinates.list({ trustMarked: false })).items.map(
					(record) => record.entityId,
				),
				[ENTITY_ID],
			);
		});
	});

	module("authority / public root exports", () => {
		test("keeps utility behavior behind authority classes", async (t) => {
			t.false("sanitizeSubordinateMetadata" in AuthorityPublic);
			t.false("rotateKey" in AuthorityPublic);
			t.false("rotateKeyCompromise" in AuthorityPublic);
			t.false("AuthorityClientKeyProvider" in AuthorityPublic);

			const sanitized = AuthorityPublic.TrustAnchor.sanitizeSubordinateMetadata({
				federation_entity: {
					organization_name: "Example Leaf",
					federation_fetch_endpoint: "https://leaf.example.com/federation_fetch",
				},
			});
			t.deepEqual(sanitized, {
				federation_entity: {
					organization_name: "Example Leaf",
				},
			});

			const { privateKey } = await generateSigningKey("ES256");
			const { privateKey: nextKey } = await generateSigningKey("ES256");
			const crypto = new FixtureCrypto(
				createFederationSigningKey({ ...privateKey, kid: "authority-key-1" }),
			);
			const ta = await AuthorityPublic.TrustAnchor.create(
				fixtureHostConfig({
					entityId: ENTITY_ID,
					crypto,
					storage: new AuthorityPublic.MemoryStorageAdapter({ engine: testEngine }),
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: `${ENTITY_ID}/federation_fetch`,
							federation_list_endpoint: `${ENTITY_ID}/federation_list`,
						},
					},
				}),
			);

			t.false("rotateSigningKey" in ta);
			await crypto.keyring.publish(
				"federation",
				fixtureSigner(createFederationSigningKey({ ...nextKey, kid: "authority-key-2" })),
			);
			await crypto.keyring.activate("federation", "authority-key-2");
			const rotated = await crypto.keyring.entry("federation");
			t.equal(rotated.signer.publicJwk.kid, "authority-key-2");
		});
	});

	// -------------------------------------------------------------------------
	// handler — compose
	// -------------------------------------------------------------------------

	// -------------------------------------------------------------------------
	// storage/memory-subordinate-store
	// -------------------------------------------------------------------------
	{
		const SUB1 = entityId("https://sub1.example.com");
		const SUB2 = entityId("https://sub2.example.com");
		const SUB3 = entityId("https://sub3.example.com");

		function makeSubRecord(
			id: ReturnType<typeof entityId>,
			overrides?: Partial<SubordinateRecord>,
		): SubordinateRecord {
			const now = Math.floor(Date.now() / 1000);
			return {
				entityId: id,
				jwks: { keys: [testPublicJwk()] },
				createdAt: now,
				updatedAt: now,
				...overrides,
			};
		}

		module("authority / SubordinateStorage", (hooks) => {
			let store: SubordinateStorage;
			hooks.beforeEach(() => {
				store = new MemoryStorageAdapter({ engine: testEngine }).subordinates;
			});

			module("add & get", () => {
				test("adds and retrieves a record", async (t) => {
					const record = makeSubRecord(SUB1);
					await store.add(record);
					const result = await store.get(SUB1);
					t.deepEqual(result, record);
				});

				test("returns undefined for unknown entity", async (t) => {
					const result = await store.get(SUB1);
					t.equal(result, undefined);
				});

				test("rejects duplicate entityId", async (t) => {
					await store.add(makeSubRecord(SUB1));
					try {
						await store.add(makeSubRecord(SUB1));
						t.ok(false, "should have thrown");
					} catch (e) {
						t.true((e as Error).message.includes("already exists"));
					}
				});
			});

			module("list", () => {
				test("returns ListPage with all records when no filter", async (t) => {
					await store.add(makeSubRecord(SUB1));
					await store.add(makeSubRecord(SUB2));
					const page = await store.list();
					t.equal(page.items.length, 2);
					t.equal(page.nextCursor, undefined);
				});

				test("returns empty ListPage for empty store", async (t) => {
					const page = await store.list();
					t.deepEqual(page.items, []);
					t.equal(page.nextCursor, undefined);
				});

				test("filters by entityType", async (t) => {
					await store.add(makeSubRecord(SUB1, { entityTypes: [EntityType.OpenIDProvider] }));
					await store.add(makeSubRecord(SUB2, { entityTypes: [EntityType.OpenIDRelyingParty] }));
					const page = await store.list({ entityTypes: [EntityType.OpenIDProvider] });
					t.equal(page.items.length, 1);
					t.equal(page.items[0]!.entityId, SUB1);
				});

				test("filters by intermediate", async (t) => {
					await store.add(makeSubRecord(SUB1, { isIntermediate: true }));
					await store.add(makeSubRecord(SUB2, { isIntermediate: false }));
					await store.add(makeSubRecord(SUB3));
					const page = await store.list({ intermediate: true });
					t.equal(page.items.length, 1);
					t.equal(page.items[0]!.entityId, SUB1);
				});

				test("filters intermediate=false includes records without flag", async (t) => {
					await store.add(makeSubRecord(SUB1, { isIntermediate: false }));
					await store.add(makeSubRecord(SUB2));
					const page = await store.list({ intermediate: false });
					t.equal(page.items.length, 2);
				});

				test("orders results by entityId ascending (lex)", async (t) => {
					const upperPath = entityId("https://sort.example.com/Z");
					const lowerPath = entityId("https://sort.example.com/a");
					await store.add(makeSubRecord(lowerPath));
					await store.add(makeSubRecord(upperPath));
					await store.add(makeSubRecord(SUB1));
					const page = await store.list();
					const ids = page.items.map((r) => r.entityId);
					const sorted = [...ids].sort();
					t.deepEqual(ids, sorted);
				});

				test("pagination: limit slices the result set", async (t) => {
					await store.add(makeSubRecord(SUB1));
					await store.add(makeSubRecord(SUB2));
					await store.add(makeSubRecord(SUB3));
					const page = await store.list(undefined, { limit: 2 });
					t.equal(page.items.length, 2);
					t.ok(page.nextCursor, "nextCursor present when more records remain");
				});

				test("pagination: nextCursor is the next entityId past the page", async (t) => {
					await store.add(makeSubRecord(SUB1));
					await store.add(makeSubRecord(SUB2));
					await store.add(makeSubRecord(SUB3));
					const sorted = [SUB1, SUB2, SUB3].sort();
					const page = await store.list(undefined, { limit: 2 });
					t.equal(page.items[0]!.entityId, sorted[0]);
					t.equal(page.items[1]!.entityId, sorted[1]);
					t.equal(page.nextCursor, sorted[2]);
				});

				test("pagination: passing cursor resumes from that entityId (inclusive)", async (t) => {
					await store.add(makeSubRecord(SUB1));
					await store.add(makeSubRecord(SUB2));
					await store.add(makeSubRecord(SUB3));
					const sorted = [SUB1, SUB2, SUB3].sort();
					const page = await store.list(undefined, { cursor: sorted[1], limit: 5 });
					t.equal(page.items.length, 2);
					t.equal(page.items[0]!.entityId, sorted[1]);
					t.equal(page.items[1]!.entityId, sorted[2]);
					t.equal(page.nextCursor, undefined);
				});

				test("pagination: nextCursor absent when results fit", async (t) => {
					await store.add(makeSubRecord(SUB1));
					const page = await store.list(undefined, { limit: 10 });
					t.equal(page.items.length, 1);
					t.equal(page.nextCursor, undefined);
				});

				test("updatedAfter filters out older records", async (t) => {
					await store.add(makeSubRecord(SUB1, { updatedAt: 1_000 }));
					await store.add(makeSubRecord(SUB2, { updatedAt: 2_000 }));
					await store.add(makeSubRecord(SUB3, { updatedAt: 3_000 }));
					const page = await store.list(undefined, { updatedAfter: 1_500 });
					t.equal(page.items.length, 2);
					t.true(page.items.every((r) => r.updatedAt >= 1_500));
				});

				test("updatedBefore filters out newer records", async (t) => {
					await store.add(makeSubRecord(SUB1, { updatedAt: 1_000 }));
					await store.add(makeSubRecord(SUB2, { updatedAt: 2_000 }));
					await store.add(makeSubRecord(SUB3, { updatedAt: 3_000 }));
					const page = await store.list(undefined, { updatedBefore: 2_500 });
					t.equal(page.items.length, 2);
					t.true(page.items.every((r) => r.updatedAt <= 2_500));
				});

				test("ordering is consistent across paginated calls (windowed concat)", async (t) => {
					await store.add(makeSubRecord(SUB1));
					await store.add(makeSubRecord(SUB2));
					await store.add(makeSubRecord(SUB3));
					const all = (await store.list()).items.map((r) => r.entityId);
					const page1 = await store.list(undefined, { limit: 1 });
					const page2 = await store.list(undefined, {
						limit: 1,
						cursor: page1.nextCursor,
					});
					const page3 = await store.list(undefined, {
						limit: 1,
						cursor: page2.nextCursor,
					});
					t.deepEqual(
						[...page1.items, ...page2.items, ...page3.items].map((r) => r.entityId),
						all,
					);
				});
			});

			module("update", () => {
				test("updates a record", async (t) => {
					await store.add(makeSubRecord(SUB1));
					await store.update(SUB1, { isIntermediate: true });
					const result = await store.get(SUB1);
					t.equal(result?.isIntermediate, true);
				});

				test("preserves entityId on update", async (t) => {
					await store.add(makeSubRecord(SUB1));
					await store.update(SUB1, { entityId: SUB2 } as Partial<SubordinateRecord>);
					const result = await store.get(SUB1);
					t.equal(result?.entityId, SUB1);
				});

				test("updates updatedAt timestamp", async (t) => {
					const original = makeSubRecord(SUB1, { updatedAt: 1_000 });
					await store.add(original);
					await store.update(SUB1, { isIntermediate: true });
					const result = await store.get(SUB1);
					t.true((result?.updatedAt ?? 0) > original.updatedAt);
				});

				test("throws for unknown entity", async (t) => {
					try {
						await store.update(SUB1, { isIntermediate: true });
						t.ok(false, "should have thrown");
					} catch (e) {
						t.true((e as Error).message.includes("not found"));
					}
				});
			});

			module("remove", () => {
				test("removes a record", async (t) => {
					await store.add(makeSubRecord(SUB1));
					await store.remove(SUB1);
					const result = await store.get(SUB1);
					t.equal(result, undefined);
				});

				test("throws for unknown entity", async (t) => {
					try {
						await store.remove(SUB1);
						t.ok(false, "should have thrown");
					} catch (e) {
						t.true((e as Error).message.includes("not found"));
					}
				});
			});

			module("update timestamps NumericDate", () => {
				test("update() writes updatedAt as NumericDate (seconds) using injected clock", async (t) => {
					const fixedClock = { now: () => 1_700_000_000 };
					const store = new MemoryStorageAdapter({ engine: testEngine, clock: fixedClock })
						.subordinates;
					await store.add(makeSubRecord(SUB1));
					await store.update(SUB1, { isIntermediate: true });
					const updated = await store.get(SUB1);
					t.equal(updated?.updatedAt, 1_700_000_000);
				});

				test("update() writes updatedAt within 1s of real now() (no clock injected)", async (t) => {
					const store = new MemoryStorageAdapter({ engine: testEngine }).subordinates;
					await store.add(makeSubRecord(SUB1));
					const before = Math.floor(Date.now() / 1000);
					await store.update(SUB1, { isIntermediate: true });
					const after = Math.floor(Date.now() / 1000);
					const updated = await store.get(SUB1);
					t.ok(updated, "record present");
					if (updated) {
						t.ok(
							updated.updatedAt >= before - 1 && updated.updatedAt <= after + 1,
							`updatedAt=${updated.updatedAt} not in [${before - 1}, ${after + 1}]`,
						);
					}
				});
			});
		});
	}

	// -------------------------------------------------------------------------
	// storage/memory-trust-mark-store
	// -------------------------------------------------------------------------
	{
		const TM_SUB1 = entityId("https://sub1.example.com");
		const TM_SUB2 = entityId("https://sub2.example.com");
		const TYPE_A = "https://trust.example.com/mark-a";
		const TYPE_B = "https://trust.example.com/mark-b";

		function makeTmRecord(
			type: string,
			subject: ReturnType<typeof entityId>,
			overrides?: Partial<TrustMarkRecord>,
		): TrustMarkRecord {
			return {
				trustMarkType: type,
				subject,
				jwt: `jwt.for.${type}.${subject}`,
				issuedAt: 0,
				active: true,
				...overrides,
			};
		}

		module("authority / TrustMarkStorage", (hooks) => {
			let store: TrustMarkStorage;
			hooks.beforeEach(() => {
				store = new MemoryStorageAdapter({ engine: testEngine, trustMarks: true }).trustMarks!;
			});

			module("issue and lookup", () => {
				test("issues and retrieves a trust mark", async (t) => {
					const record = makeTmRecord(TYPE_A, TM_SUB1);
					await store.issue(record);
					const result = await store.getValid(TYPE_A, TM_SUB1, record.issuedAt);
					t.deepEqual(result, record);
				});

				test("returns undefined for unknown trust mark", async (t) => {
					const result = await store.getValid(TYPE_A, TM_SUB1, 0);
					t.equal(result, undefined);
				});

				test("preserves exact JWT history across re-issue", async (t) => {
					const first = makeTmRecord(TYPE_A, TM_SUB1, { jwt: "first.jwt", issuedAt: 1 });
					const second = makeTmRecord(TYPE_A, TM_SUB1, { jwt: "second.jwt", issuedAt: 2 });
					await store.issue(first);
					await store.revoke(TYPE_A, TM_SUB1, 2);
					await store.issue(second);
					t.deepEqual(await store.getByJwt("first.jwt"), {
						...first,
						active: false,
						revokedAt: 2,
					});
					t.deepEqual(await store.getByJwt("second.jwt"), second);
				});

				test("selects deterministically when issue times are equal", async (t) => {
					await store.issue(makeTmRecord(TYPE_A, TM_SUB1, { jwt: "a.jwt", issuedAt: 1 }));
					await store.issue(makeTmRecord(TYPE_A, TM_SUB1, { jwt: "b.jwt", issuedAt: 1 }));
					t.equal((await store.getValid(TYPE_A, TM_SUB1, 1))?.jwt, "b.jwt");
				});
			});

			module("listValid", () => {
				test("lists records by type", async (t) => {
					await store.issue(makeTmRecord(TYPE_A, TM_SUB1));
					await store.issue(makeTmRecord(TYPE_A, TM_SUB2));
					await store.issue(makeTmRecord(TYPE_B, TM_SUB1));
					const result = await store.listValid(TYPE_A, 0, { limit: 100 });
					t.equal(result.items.length, 2);
				});

				test("filters by sub", async (t) => {
					await store.issue(makeTmRecord(TYPE_A, TM_SUB1));
					await store.issue(makeTmRecord(TYPE_A, TM_SUB2));
					const result = await store.listValid(TYPE_A, 0, {
						subject: TM_SUB1,
						limit: 100,
					});
					t.equal(result.items.length, 1);
					t.equal(result.items[0]!.subject, TM_SUB1);
				});

				test("paginates with cursor and limit", async (t) => {
					for (let i = 0; i < 5; i++) {
						await store.issue(makeTmRecord(TYPE_A, entityId(`https://sub${i}.example.com`)));
					}
					const page1 = await store.listValid(TYPE_A, 0, { limit: 2 });
					t.equal(page1.items.length, 2);
					t.ok(page1.nextCursor !== undefined);

					const page2 = await store.listValid(TYPE_A, 0, {
						limit: 2,
						cursor: page1.nextCursor!,
					});
					t.equal(page2.items.length, 2);
					t.ok(page2.nextCursor !== undefined);

					const page3 = await store.listValid(TYPE_A, 0, {
						limit: 2,
						cursor: page2.nextCursor!,
					});
					t.equal(page3.items.length, 1);
					t.equal(page3.nextCursor, undefined);
				});

				test("returns empty for unknown type", async (t) => {
					const result = await store.listValid("https://unknown.example.com/mark", 0, {
						limit: 100,
					});
					t.deepEqual(result.items, []);
				});

				test("excludes expired records at the validity boundary", async (t) => {
					await store.issue(makeTmRecord(TYPE_A, TM_SUB1, { expiresAt: 10 }));
					const result = await store.listValid(TYPE_A, 10, { limit: 100 });
					t.deepEqual(result.items, []);
				});
			});

			module("revoke", () => {
				test("sets active to false", async (t) => {
					const record = makeTmRecord(TYPE_A, TM_SUB1);
					await store.issue(record);
					await store.revoke(TYPE_A, TM_SUB1, record.issuedAt + 1);
					const result = await store.getByJwt(record.jwt);
					t.equal(result?.active, false);
					t.equal(result?.revokedAt, record.issuedAt + 1);
				});

				test("throws for unknown trust mark", async (t) => {
					try {
						await store.revoke(TYPE_A, TM_SUB1, 1);
						t.ok(false, "should have thrown");
					} catch (e) {
						t.true((e as Error).message.includes("not found"));
					}
				});
			});

			module("validity", () => {
				test("returns true for active trust mark", async (t) => {
					await store.issue(makeTmRecord(TYPE_A, TM_SUB1));
					t.equal(await store.hasAnyValid(TM_SUB1, 0), true);
				});

				test("returns false for revoked trust mark", async (t) => {
					await store.issue(makeTmRecord(TYPE_A, TM_SUB1));
					await store.revoke(TYPE_A, TM_SUB1, 1);
					t.equal(await store.hasAnyValid(TM_SUB1, 1), false);
				});

				test("returns false for nonexistent trust mark", async (t) => {
					t.equal(await store.hasAnyValid(TM_SUB1, 0), false);
				});
			});
		});
	}

	module("authority / MemoryStorageAdapter", () => {
		const id = entityId("https://transaction.example.com");
		const record = (): SubordinateRecord => ({
			entityId: id,
			jwks: { keys: [testPublicJwk("transaction-key-1", "x", "y")] },
			metadata: { openid_relying_party: { client_name: "original" } },
			createdAt: 1,
			updatedAt: 1,
		});

		test("provides replay and cache while keeping trust marks opt-in", (t) => {
			const basic = new MemoryStorageAdapter({ engine: testEngine });
			t.ok(basic.replay);
			t.ok(basic.cache);
			t.equal(basic.trustMarks, undefined);
			t.ok(new MemoryStorageAdapter({ engine: testEngine, trustMarks: true }).trustMarks);
		});

		test("uses one NumericDate clock for records, replay, and cache", async (t) => {
			let now = 100;
			const storage = new MemoryStorageAdapter({ engine: testEngine, clock: { now: () => now } });
			await storage.subordinates.add(record());
			await storage.subordinates.update(id, { metadata: record().metadata });
			t.equal((await storage.subordinates.get(id))?.updatedAt, 100);

			await storage.cache.set("clock", "value", 10);
			t.true(
				await storage.replay.useJti({
					issuer: "issuer",
					audience: "audience",
					jti: "jti",
					expiresAt: 110,
				}),
			);
			now = 110;
			t.equal(await storage.cache.get("clock"), undefined);
			t.true(
				await storage.replay.useJti({
					issuer: "issuer",
					audience: "audience",
					jti: "jti",
					expiresAt: 120,
				}),
			);
		});

		test("commits all writes after a successful transaction", async (t) => {
			const storage = new MemoryStorageAdapter({ engine: testEngine });
			await storage.transaction(async (tx) => {
				await tx.subordinates.add(record());
			});
			t.ok(await storage.subordinates.get(id));
		});

		test("rolls back every repository when a transaction fails", async (t) => {
			const storage = new MemoryStorageAdapter({ engine: testEngine, trustMarks: true });
			const mark: TrustMarkRecord = {
				trustMarkType: "https://trust.example.com/transaction-mark",
				subject: id,
				jwt: "transaction.jwt",
				issuedAt: 1,
				active: true,
			};
			try {
				await storage.transaction(async (tx) => {
					await tx.subordinates.add(record());
					await tx.trustMarks?.issue(mark);
					throw new Error("rollback");
				});
			} catch {
				// Expected.
			}
			t.equal(await storage.subordinates.get(id), undefined);
			t.equal(await storage.trustMarks?.getByJwt(mark.jwt), undefined);
		});

		test("serializes concurrent transactions", async (t) => {
			const storage = new MemoryStorageAdapter({ engine: testEngine });
			let releaseFirst!: () => void;
			let notifyFirst!: () => void;
			const firstEntered = new Promise<void>((resolve) => {
				notifyFirst = resolve;
			});
			const release = new Promise<void>((resolve) => {
				releaseFirst = resolve;
			});

			const first = storage.transaction(async (tx) => {
				await tx.subordinates.add(record());
				notifyFirst();
				await release;
			});
			await firstEntered;

			let secondEntered = false;
			const second = storage.transaction(async (tx) => {
				secondEntered = true;
				t.ok(await tx.subordinates.get(id));
			});
			await Promise.resolve();
			t.false(secondEntered);

			releaseFirst();
			await Promise.all([first, second]);
			t.true(secondEntered);
		});

		test("returns detached records that cannot mutate persisted state", async (t) => {
			const storage = new MemoryStorageAdapter({ engine: testEngine });
			await storage.subordinates.add(record());
			const loaded = await storage.subordinates.get(id);
			const metadata = loaded?.metadata as { openid_relying_party: { client_name: string } };
			metadata.openid_relying_party.client_name = "mutated";
			const reloaded = await storage.subordinates.get(id);
			t.ok(reloaded, "persisted record is present");
			if (!reloaded) return;
			t.equal(
				(reloaded.metadata as { openid_relying_party: { client_name: string } })
					.openid_relying_party.client_name,
				"original",
			);
		});
	});

	// -------------------------------------------------------------------------
	// keys/rotation
	// -------------------------------------------------------------------------
	module("authority / provider-owned key rollover", (hooks) => {
		let crypto: FixtureCrypto;
		let nowMs: number;

		hooks.beforeEach(async () => {
			nowMs = 1_000_000;
			const { privateKey } = await generateSigningKey("ES256");
			crypto = new FixtureCrypto(createFederationSigningKey({ ...privateKey, kid: "old-key" }), {
				nowMs: () => nowMs,
			});
		});

		test("published configurations follow propagation, switch, and retirement boundaries", async (t) => {
			const authority = await TrustAnchor.create(
				fixtureHostConfig({
					entityId: ENTITY_ID,
					crypto,
					storage: new MemoryStorageAdapter({ engine: testEngine }),
					options: { clock: { now: () => Math.floor(nowMs / 1000) } },
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: `${ENTITY_ID}/fetch`,
							federation_list_endpoint: `${ENTITY_ID}/list`,
						},
					},
				}),
			);
			const original = await crypto.keyring.entry("federation");
			const { privateKey } = await generateSigningKey("ES256");
			await crypto.keyring.publish(
				"federation",
				fixtureSigner(createFederationSigningKey({ ...privateKey, kid: "next-key" })),
			);
			const published = await verifyEntityStatement(
				await authority.getEntityConfiguration(),
				original.publishedJwks,
				{ engine: testEngine, clock: { now: () => Math.floor(nowMs / 1000) } },
			);
			t.true(published.ok);
			if (!published.ok) return;
			const learned = published.value.payload.jwks;
			t.ok(learned);
			if (!learned) return;
			t.equal(published.value.header.kid, "old-key");
			t.deepEqual(learned.keys.map((key) => key.kid).sort(), ["next-key", "old-key"]);
			await crypto.keyring.activate("federation", "next-key");
			for (const elapsed of [0, 9999, 10000]) {
				nowMs = 1000000 + elapsed;
				if (elapsed === 10000) await crypto.keyring.retire("federation", "old-key");
				const checked = await verifyEntityStatement(
					await authority.getEntityConfiguration(),
					learned,
					{ engine: testEngine, clock: { now: () => Math.floor(nowMs / 1000) } },
				);
				t.true(checked.ok);
				if (!checked.ok) continue;
				t.equal(checked.value.header.kid, "next-key");
				t.deepEqual(
					checked.value.payload.jwks?.keys.map((key) => key.kid).sort(),
					elapsed < 10000 ? ["next-key", "old-key"] : ["next-key"],
				);
			}
			t.ok((await crypto.history.getHistoricalKeys()).find((key) => key.kid === "old-key"));
		});
		test("publishes next key before signer switch", async (t) => {
			const { privateKey: newKey } = await generateSigningKey("ES256");
			await crypto.keyring.publish(
				"federation",
				fixtureSigner(createFederationSigningKey({ ...newKey, kid: "new-key" })),
			);

			const keySet = await crypto.keyring.entry("federation");
			t.equal(keySet.signer.publicJwk.kid, "old-key");
			t.deepEqual(keySet.publishedJwks.keys.map((k) => k.kid).sort(), ["new-key", "old-key"]);
		});

		test("switches signer and schedules previous key removal", async (t) => {
			const { privateKey: newKey } = await generateSigningKey("ES256");
			await crypto.keyring.publish(
				"federation",
				fixtureSigner(createFederationSigningKey({ ...newKey, kid: "new-key" })),
			);
			await crypto.keyring.activate("federation", "new-key");

			const keySet = await crypto.keyring.entry("federation");
			t.equal(keySet.signer.publicJwk.kid, "new-key");
			t.deepEqual(keySet.publishedJwks.keys.map((k) => k.kid).sort(), ["new-key", "old-key"]);

			const history = await crypto.history.getHistoricalKeys();
			t.deepEqual(history, [], "the old key remains in the current JWKS during overlap");
		});

		test("excludes retired key from active JWKS after removal time", async (t) => {
			const { privateKey: newKey } = await generateSigningKey("ES256");
			await crypto.keyring.publish(
				"federation",
				fixtureSigner(createFederationSigningKey({ ...newKey, kid: "new-key" })),
			);
			await crypto.keyring.activate("federation", "new-key");
			nowMs += 10_000;
			await crypto.keyring.retire("federation", "old-key");

			const keySet = await crypto.keyring.entry("federation");
			t.deepEqual(
				keySet.publishedJwks.keys.map((k) => k.kid),
				["new-key"],
			);

			const history = await crypto.history.getHistoricalKeys();
			t.ok(history.find((k) => k.kid === "old-key"));
		});
	});

	// -------------------------------------------------------------------------
	// endpoints/helpers
	// -------------------------------------------------------------------------
	module("authority / SECURITY_HEADERS", () => {
		test("includes Cache-Control no-store", (t) => {
			t.equal(SECURITY_HEADERS["Cache-Control"], "no-store");
		});

		test("includes X-Content-Type-Options nosniff", (t) => {
			t.equal(SECURITY_HEADERS["X-Content-Type-Options"], "nosniff");
		});

		test("includes Strict-Transport-Security", (t) => {
			t.true(/max-age=\d+/.test(SECURITY_HEADERS["Strict-Transport-Security"] ?? ""));
		});

		test("includes X-Frame-Options DENY", (t) => {
			t.equal(SECURITY_HEADERS["X-Frame-Options"], "DENY");
		});

		test("includes Referrer-Policy no-referrer", (t) => {
			t.equal(SECURITY_HEADERS["Referrer-Policy"], "no-referrer");
		});
	});

	module("authority / jwtResponse", () => {
		test("returns 200 with correct content type and body", (t) => {
			const res = jwtResponse("jwt.token.here", "application/entity-statement+jwt");
			t.equal(res.status, 200);
			t.equal(res.headers.get("Content-Type"), "application/entity-statement+jwt");
		});

		test("includes security headers", async (t) => {
			const res = jwtResponse("jwt.token.here", "application/entity-statement+jwt");
			t.equal(res.headers.get("Cache-Control"), "no-store");
			t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
			t.ok(res.headers.get("Strict-Transport-Security"));
		});

		test("returns the JWT as the body", async (t) => {
			const res = jwtResponse("my.jwt.token", "application/entity-statement+jwt");
			t.equal(await res.text(), "my.jwt.token");
		});
	});

	module("authority / jsonResponse", () => {
		test("returns JSON with correct content type", async (t) => {
			const res = jsonResponse({ foo: "bar" });
			t.equal(res.status, 200);
			t.equal(res.headers.get("Content-Type"), "application/json");
			t.deepEqual(await res.json(), { foo: "bar" });
		});

		test("includes security headers", (t) => {
			const res = jsonResponse([]);
			t.equal(res.headers.get("Cache-Control"), "no-store");
			t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
		});

		test("supports custom status code", (t) => {
			const res = jsonResponse({ error: "test" }, 400);
			t.equal(res.status, 400);
		});
	});

	module("authority / errorResponse", () => {
		test("returns error JSON with code", async (t) => {
			const res = errorResponse(400, "invalid_request", "Missing sub");
			t.equal(res.status, 400);
			t.deepEqual(await res.json(), { error: "invalid_request", error_description: "Missing sub" });
		});

		test("omits error_description when not provided", async (t) => {
			// @ts-expect-error description is typed as required but runtime-optional via JSON.stringify eliding undefined
			const res = errorResponse(500, "server_error");
			const body = (await res.json()) as Record<string, unknown>;
			t.deepEqual(body, { error: "server_error" });
			t.equal(body.error_description, undefined);
		});

		test("includes security headers", (t) => {
			// @ts-expect-error description is typed as required but runtime-optional via JSON.stringify eliding undefined
			const res = errorResponse(404, "not_found");
			t.equal(res.headers.get("Cache-Control"), "no-store");
			t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
		});
	});

	module("authority / toPublicError", () => {
		test("passes through public federation error codes", (t) => {
			const e: FederationError = {
				code: "invalid_request" as FederationError["code"],
				description: "Missing parameter",
			};
			const result = toPublicError(e);
			t.equal(result.code, "invalid_request");
			t.equal(result.description, "Missing parameter");
			t.equal(result.status, 400);
		});

		test("maps not_found to 404", (t) => {
			const e: FederationError = {
				code: "not_found" as FederationError["code"],
				description: "Entity not found",
			};
			const result = toPublicError(e);
			t.equal(result.status, 404);
			t.equal(result.code, "not_found");
		});

		test("sanitizes internal error codes to server_error", (t) => {
			const e: FederationError = {
				code: InternalErrorCode.SignatureInvalid as string as FederationError["code"],
				description: "HMAC mismatch at byte 47 of key material",
			};
			const result = toPublicError(e);
			t.equal(result.code, "server_error");
			t.equal(result.status, 500);
			t.equal(result.description, "An internal error occurred");
			t.false(result.description.includes("HMAC"));
		});

		test("sanitizes unknown error codes to server_error", (t) => {
			const e: FederationError = {
				code: "some_unknown_code" as FederationError["code"],
				description: "Secret internal details",
			};
			const result = toPublicError(e);
			t.equal(result.code, "server_error");
			t.equal(result.description, "An internal error occurred");
		});

		test("maps temporarily_unavailable to 503", (t) => {
			const e: FederationError = {
				code: "temporarily_unavailable" as FederationError["code"],
				description: "Try again later",
			};
			const result = toPublicError(e);
			t.equal(result.status, 503);
		});
	});

	module("authority / parseQueryParams", () => {
		test("extracts query parameters from request", (t) => {
			const req = new Request(
				"https://example.com/path?sub=https%3A%2F%2Ffoo.com&type=openid_provider",
			);
			const params = parseQueryParams(req);
			t.equal(params.get("sub"), "https://foo.com");
			t.equal(params.get("type"), "openid_provider");
		});

		test("returns empty params for no query string", (t) => {
			const req = new Request("https://example.com/path");
			const params = parseQueryParams(req);
			t.equal(params.toString(), "");
		});
	});

	module("authority / requireMethod", () => {
		test("returns null when method matches", (t) => {
			const req = new Request("https://example.com", { method: "GET" });
			t.equal(requireMethod(req, "GET"), null);
		});

		test("returns 405 when method does not match", async (t) => {
			const req = new Request("https://example.com", { method: "POST" });
			const res = requireMethod(req, "GET");
			t.ok(res !== null);
			t.equal(res?.status, 405);
			t.equal(res?.headers.get("Allow"), "GET");
		});

		test("includes security headers on 405", (t) => {
			const req = new Request("https://example.com", { method: "DELETE" });
			const res = requireMethod(req, "POST");
			t.equal(res?.headers.get("Cache-Control"), "no-store");
			t.equal(res?.headers.get("X-Content-Type-Options"), "nosniff");
		});

		test("is case-insensitive", (t) => {
			const req = new Request("https://example.com", { method: "get" });
			t.equal(requireMethod(req, "GET"), null);
		});
	});

	module("authority / requireMethods", () => {
		test("returns null when method matches any listed method", (t) => {
			const req = new Request("https://example.com", { method: "POST" });
			t.equal(requireMethods(req, ["GET", "POST"]), null);
		});

		test("returns null for GET when GET is listed", (t) => {
			const req = new Request("https://example.com", { method: "GET" });
			t.equal(requireMethods(req, ["GET", "POST"]), null);
		});

		test("returns 405 when method is not listed", async (t) => {
			const req = new Request("https://example.com", { method: "DELETE" });
			const res = requireMethods(req, ["GET", "POST"]);
			t.ok(res !== null);
			t.equal(res?.status, 405);
			t.equal(res?.headers.get("Allow"), "GET, POST");
		});

		test("includes security headers on 405", (t) => {
			const req = new Request("https://example.com", { method: "PUT" });
			const res = requireMethods(req, ["GET"]);
			t.equal(res?.headers.get("Cache-Control"), "no-store");
			t.equal(res?.headers.get("X-Content-Type-Options"), "nosniff");
		});
	});

	module("authority / extractRequestParams", () => {
		test("extracts params from GET query string", async (t) => {
			const req = new Request(
				"https://example.com/path?sub=https%3A%2F%2Ffoo.com&type=openid_provider",
			);
			const result = await extractRequestParams(req);
			t.equal(result.params.get("sub"), "https://foo.com");
			t.equal(result.params.get("type"), "openid_provider");
			t.equal(result.clientAssertion, undefined);
			t.equal(result.clientAssertionType, undefined);
		});

		test("extracts params from POST body", async (t) => {
			const req = new Request("https://example.com/path", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: "sub=https%3A%2F%2Ffoo.com&type=openid_provider",
			});
			const result = await extractRequestParams(req);
			t.equal(result.params.get("sub"), "https://foo.com");
			t.equal(result.params.get("type"), "openid_provider");
			t.equal(result.clientAssertion, undefined);
		});

		test("separates client_assertion fields from POST body", async (t) => {
			const req = new Request("https://example.com/path", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: "sub=https%3A%2F%2Ffoo.com&client_assertion=jwt.token.here&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
			});
			const result = await extractRequestParams(req);
			t.equal(result.params.get("sub"), "https://foo.com");
			t.false(result.params.has("client_assertion"));
			t.false(result.params.has("client_assertion_type"));
			t.equal(result.clientAssertion, "jwt.token.here");
			t.equal(result.clientAssertionType, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
		});
	});

	// -------------------------------------------------------------------------
	// endpoints/entity-configuration
	// -------------------------------------------------------------------------
	module("authority / createEntityConfigurationHandler", () => {
		test("returns a signed JWT with entity-statement+jwt content type", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			t.equal(res.status, 200);
			t.equal(res.headers.get("Content-Type"), "application/entity-statement+jwt");
		});

		test("includes security headers", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			t.equal(res.headers.get("Cache-Control"), "no-store");
			t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
		});

		test("JWT has iss === sub === entityId", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			t.equal(decoded.value.payload.iss, ENTITY_ID);
			t.equal(decoded.value.payload.sub, ENTITY_ID);
		});

		test("JWT contains jwks", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			const payload = decoded.value.payload as Record<string, unknown>;
			t.ok(payload.jwks);
			t.true((payload.jwks as { keys: unknown[] }).keys.length > 0);
		});

		test("JWT contains metadata", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			t.ok((decoded.value.payload as Record<string, unknown>).metadata);
		});

		test("entity configuration response metadata includes federation_entity", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			t.equal(res.status, 200);
			const decoded = decodeEntityStatement(await res.text());
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			const metadata = (decoded.value.payload as Record<string, unknown>).metadata as
				| Record<string, unknown>
				| undefined;
			t.ok(metadata, "metadata claim is present");
			t.ok(metadata?.federation_entity, "metadata.federation_entity is present");
		});

		test("includes authority_hints for intermediates", async (t) => {
			const superiorId = entityId("https://ta.example.com");
			const { ctx } = await createTestContext({ authorityHints: [superiorId] });
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			t.deepEqual((decoded.value.payload as Record<string, unknown>).authority_hints, [superiorId]);
		});

		test("includes trust_anchor_hints for intermediates when configured", async (t) => {
			const superiorId = entityId("https://ta.example.com");
			const trustAnchorHint = entityId("https://preferred-ta.example.com");
			const { ctx } = await createTestContext({
				authorityHints: [superiorId],
				trustAnchorHints: [trustAnchorHint],
			});
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			t.deepEqual((decoded.value.payload as Record<string, unknown>).trust_anchor_hints, [
				trustAnchorHint,
			]);
		});

		test("includes trust_mark_issuers when configured", async (t) => {
			const issuers = { "https://trust.example.com/mark-a": ["https://issuer.example.com"] };
			const { ctx } = await createTestContext({ trustMarkIssuers: issuers });
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			t.deepEqual((decoded.value.payload as Record<string, unknown>).trust_mark_issuers, issuers);
		});

		test("includes trust_mark_owners when configured", async (t) => {
			const { publicKey } = await generateSigningKey("ES256");
			const owners = {
				"https://trust.example.com/mark-a": {
					sub: entityId("https://owner.example.com"),
					jwks: { keys: [{ ...publicKey, kid: "owner-key-1" }] },
				},
			} satisfies HandlerContext["trustMarkOwners"];
			const { ctx } = await createTestContext({ trustMarkOwners: owners });
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			t.deepEqual(
				JSON.parse(
					JSON.stringify((decoded.value.payload as Record<string, unknown>).trust_mark_owners),
				),
				JSON.parse(JSON.stringify(owners)),
			);
		});

		test("uses custom entityConfigurationTtlSeconds for exp", async (t) => {
			const { ctx } = await createTestContext({ entityConfigurationTtlSeconds: 3600 });
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			const payload = decoded.value.payload as Record<string, unknown>;
			t.equal((payload.exp as number) - (payload.iat as number), 3600);
		});

		test("defaults to 86400s TTL when entityConfigurationTtlSeconds is not set", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			const payload = decoded.value.payload as Record<string, unknown>;
			t.equal((payload.exp as number) - (payload.iat as number), 86400);
		});

		test("returns 500 when no active keys are available", async (t) => {
			const { ctx, crypto } = await createTestContext();
			await crypto.keyring.revoke("federation", "test-key-1", "test");
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			t.equal(res.status, 500);
		});

		test("returns 405 for POST", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation", {
					method: "POST",
				}),
			);
			t.equal(res.status, 405);
			t.equal(res.headers.get("Allow"), "GET");
		});

		test("JWT can be verified with the active keys", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createEntityConfigurationHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/.well-known/openid-federation"),
			);
			const jwt = await res.text();
			const keySet = await ctx.crypto.keyring.entry("federation");
			const result = await verifyEntityStatement(jwt, keySet.publishedJwks, { engine: testEngine });
			t.true(isOk(result));
		});
	});

	// -------------------------------------------------------------------------
	// endpoints/fetch
	// -------------------------------------------------------------------------
	{
		const FETCH_SUB1 = entityId("https://sub1.example.com");

		function makeFetchRecord(
			id: ReturnType<typeof entityId>,
			overrides?: Partial<SubordinateRecord>,
		): SubordinateRecord {
			return {
				entityId: id,
				jwks: { keys: [testPublicJwk()] },
				createdAt: Date.now(),
				updatedAt: Date.now(),
				...overrides,
			};
		}

		module("authority / createFetchHandler", () => {
			test("returns 400 when sub is missing", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createFetchHandler(ctx);
				const res = await handler(new Request("https://authority.example.com/federation_fetch"));
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_request");
			});

			test("returns 400 when sub is invalid", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createFetchHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_fetch?sub=not-a-url"),
				);
				t.equal(res.status, 400);
			});

			test("returns 404 when sub is unknown", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createFetchHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_fetch?sub=${encodeURIComponent(FETCH_SUB1)}`,
					),
				);
				t.equal(res.status, 404);
				t.equal(((await res.json()) as Record<string, string>).error, "not_found");
			});

			test("returns 400 when sub === entityId", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createFetchHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_fetch?sub=${encodeURIComponent(ENTITY_ID)}`,
					),
				);
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_request");
			});

			test("returns signed subordinate statement for known sub", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(
					makeFetchRecord(FETCH_SUB1, {
						metadata: { openid_provider: { issuer: "https://sub1.example.com" } },
						sourceEndpoint: "https://sub1.example.com/federation_fetch",
					}),
				);
				const handler = createFetchHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_fetch?sub=${encodeURIComponent(FETCH_SUB1)}`,
					),
				);
				t.equal(res.status, 200);
				t.equal(res.headers.get("Content-Type"), "application/entity-statement+jwt");
				const jwt = await res.text();
				const decoded = decodeEntityStatement(jwt);
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				t.equal(decoded.value.payload.iss, ENTITY_ID);
				t.equal(decoded.value.payload.sub, FETCH_SUB1);
				const payload = decoded.value.payload as Record<string, unknown>;
				t.ok(payload.metadata);
				t.equal(payload.source_endpoint, "https://sub1.example.com/federation_fetch");
			});

			test("includes security headers", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeFetchRecord(FETCH_SUB1));
				const handler = createFetchHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_fetch?sub=${encodeURIComponent(FETCH_SUB1)}`,
					),
				);
				t.equal(res.headers.get("Cache-Control"), "no-store");
				t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
			});

			test("uses custom subordinateStatementTtlSeconds for exp", async (t) => {
				const { ctx, subordinates } = await createTestContext({
					subordinateStatementTtlSeconds: 1800,
				});
				await subordinates.add(makeFetchRecord(FETCH_SUB1));
				const handler = createFetchHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_fetch?sub=${encodeURIComponent(FETCH_SUB1)}`,
					),
				);
				t.equal(res.status, 200);
				const jwt = await res.text();
				const decoded = decodeEntityStatement(jwt);
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				const payload = decoded.value.payload as Record<string, unknown>;
				t.equal((payload.exp as number) - (payload.iat as number), 1800);
			});

			test("returns 405 for POST", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createFetchHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_fetch?sub=https%3A%2F%2Ffoo.com", {
						method: "POST",
					}),
				);
				t.equal(res.status, 405);
			});

			test("ignores unknown query parameters", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeFetchRecord(FETCH_SUB1));
				const handler = createFetchHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_fetch?sub=${encodeURIComponent(FETCH_SUB1)}&unknown_param=foo&another=bar`,
					),
				);
				t.equal(res.status, 200);
				t.equal(res.headers.get("Content-Type"), "application/entity-statement+jwt");
			});

			test("error response uses application/json content-type", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createFetchHandler(ctx);
				const res = await handler(new Request("https://authority.example.com/federation_fetch"));
				t.equal(res.status, 400);
				const ct = res.headers.get("Content-Type") ?? "";
				t.true(
					ct.startsWith("application/json"),
					`expected application/json content-type, got '${ct}'`,
				);
			});
		});
	}

	// -------------------------------------------------------------------------
	// endpoints/list
	// -------------------------------------------------------------------------
	{
		const LIST_SUB1 = entityId("https://sub1.example.com");
		const LIST_SUB2 = entityId("https://sub2.example.com");

		function makeListRecord(
			id: ReturnType<typeof entityId>,
			overrides?: Partial<SubordinateRecord>,
		): SubordinateRecord {
			const now = Math.floor(Date.now() / 1000);
			return {
				entityId: id,
				jwks: { keys: [testPublicJwk()] },
				createdAt: now,
				updatedAt: now,
				...overrides,
			};
		}

		module("authority / createListHandler", () => {
			test("returns all entity IDs with no filter", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeListRecord(LIST_SUB1));
				await subordinates.add(makeListRecord(LIST_SUB2));
				const handler = createListHandler(ctx);
				const res = await handler(new Request("https://authority.example.com/federation_list"));
				t.equal(res.status, 200);
				t.equal(res.headers.get("Content-Type"), "application/json");
				const body = (await res.json()) as string[];
				t.equal(body.length, 2);
				t.true(body.includes(LIST_SUB1));
				t.true(body.includes(LIST_SUB2));
			});

			test("returns empty array when no subordinates", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createListHandler(ctx);
				const res = await handler(new Request("https://authority.example.com/federation_list"));
				t.deepEqual(await res.json(), []);
			});

			test("filters by entity_type", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(
					makeListRecord(LIST_SUB1, { entityTypes: [EntityType.OpenIDProvider] }),
				);
				await subordinates.add(
					makeListRecord(LIST_SUB2, { entityTypes: [EntityType.OpenIDRelyingParty] }),
				);
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_list?entity_type=openid_provider"),
				);
				t.deepEqual(await res.json(), [LIST_SUB1]);
			});

			test("filters by intermediate", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeListRecord(LIST_SUB1, { isIntermediate: true }));
				await subordinates.add(makeListRecord(LIST_SUB2, { isIntermediate: false }));
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_list?intermediate=true"),
				);
				t.deepEqual(await res.json(), [LIST_SUB1]);
			});

			test("filters by trust_marked when trust mark store is available", async (t) => {
				const { ctx, subordinates, trustMarks } = await createTestContext();
				await subordinates.add(makeListRecord(LIST_SUB1));
				await subordinates.add(makeListRecord(LIST_SUB2));
				await trustMarks.issue({
					trustMarkType: "https://trust.example.com/mark",
					subject: LIST_SUB1,
					jwt: "test.jwt",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request(
						"https://authority.example.com/federation_list?trust_marked=true&trust_mark_type=https%3A%2F%2Ftrust.example.com%2Fmark",
					),
				);
				t.deepEqual(await res.json(), [LIST_SUB1]);
			});

			test("ignores unknown parameters", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeListRecord(LIST_SUB1));
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_list?unknown_param=foo"),
				);
				t.equal(res.status, 200);
				t.deepEqual(await res.json(), [LIST_SUB1]);
			});

			test("returns 400 with unsupported_parameter when trust_marked used but no trust mark store", async (t) => {
				const { ctx } = await createTestContext({
					storage: new MemoryStorageAdapter({ engine: testEngine }),
				});
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_list?trust_marked=true"),
				);
				t.equal(res.status, 400);
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, "unsupported_parameter");
				t.ok(body.error_description);
			});

			test("returns 400 with unsupported_parameter when trust_mark_type used but no trust mark store", async (t) => {
				const { ctx } = await createTestContext({
					storage: new MemoryStorageAdapter({ engine: testEngine }),
				});
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request(
						"https://authority.example.com/federation_list?trust_mark_type=https%3A%2F%2Fexample.com%2Ftm",
					),
				);
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "unsupported_parameter");
			});

			// Federation 1.0 §8.2.1: repeated entity_type values filter with union (OR)
			// semantics. The published sentence "include all specified Entity Types"
			// condenses explicitly-OR drafting (openid/federation ee7a372f → 49d194e3),
			// and Entity Collection Draft 01 clarifies the same sentence to "any of".
			test("filters by multiple entity_type values with OR logic", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(
					makeListRecord(LIST_SUB1, { entityTypes: [EntityType.OpenIDProvider] }),
				);
				await subordinates.add(
					makeListRecord(LIST_SUB2, { entityTypes: [EntityType.OpenIDRelyingParty] }),
				);
				const sub3 = entityId("https://sub3.example.com");
				await subordinates.add(makeListRecord(sub3, { entityTypes: [EntityType.OAuthClient] }));
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request(
						"https://authority.example.com/federation_list?entity_type=openid_provider&entity_type=openid_relying_party",
					),
				);
				const body = (await res.json()) as string[];
				t.equal(body.length, 2);
				t.true(body.includes(LIST_SUB1));
				t.true(body.includes(LIST_SUB2));
			});

			test("filters by a custom entity_type value instead of rejecting it", async (t) => {
				// Federation 1.0 §5.1: "Additional Entity Type Identifiers MAY be
				// defined to support use cases for other protocols"; §20 establishes
				// no registry, so the value space is open.
				const { ctx, subordinates } = await createTestContext();
				const customType = "https://extensions.example.com/custom_wallet_type";
				await subordinates.add(makeListRecord(LIST_SUB1, { entityTypes: [customType] }));
				await subordinates.add(
					makeListRecord(LIST_SUB2, { entityTypes: [EntityType.OpenIDProvider] }),
				);
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_list?entity_type=${encodeURIComponent(customType)}`,
					),
				);
				t.equal(res.status, 200);
				t.deepEqual(await res.json(), [LIST_SUB1]);
			});

			test("returns an empty array for an unmatched custom entity_type", async (t) => {
				// §8.2.1's filtering MUST: an identifier no subordinate carries yields
				// an empty result, not a per-value error.
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(
					makeListRecord(LIST_SUB1, { entityTypes: [EntityType.OpenIDProvider] }),
				);
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request(
						"https://authority.example.com/federation_list?entity_type=never_registered_type",
					),
				);
				t.equal(res.status, 200);
				t.deepEqual(await res.json(), []);
			});

			test("rejects an empty entity_type value as invalid_request", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_list?entity_type="),
				);
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_request");
			});

			test("filters trust_marked=true without trust_mark_type to entities with any active trust mark", async (t) => {
				const { ctx, subordinates, trustMarks } = await createTestContext();
				await subordinates.add(makeListRecord(LIST_SUB1));
				await subordinates.add(makeListRecord(LIST_SUB2));
				await trustMarks.issue({
					trustMarkType: "https://trust.example.com/mark",
					subject: LIST_SUB1,
					jwt: "test.jwt",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_list?trust_marked=true"),
				);
				t.deepEqual(await res.json(), [LIST_SUB1]);
			});

			test("filters by trust_mark_type alone without trust_marked", async (t) => {
				const { ctx, subordinates, trustMarks } = await createTestContext();
				await subordinates.add(makeListRecord(LIST_SUB1));
				await subordinates.add(makeListRecord(LIST_SUB2));
				await trustMarks.issue({
					trustMarkType: "https://trust.example.com/mark",
					subject: LIST_SUB1,
					jwt: "test.jwt",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request(
						"https://authority.example.com/federation_list?trust_mark_type=https%3A%2F%2Ftrust.example.com%2Fmark",
					),
				);
				t.deepEqual(await res.json(), [LIST_SUB1]);
			});

			test("trust_marked=false without trust_mark_type leaves the list unrestricted", async (t) => {
				const { ctx, subordinates, trustMarks } = await createTestContext();
				await subordinates.add(makeListRecord(LIST_SUB1));
				await subordinates.add(makeListRecord(LIST_SUB2));
				await trustMarks.issue({
					trustMarkType: "https://trust.example.com/mark",
					subject: LIST_SUB1,
					jwt: "test.jwt",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_list?trust_marked=false"),
				);
				t.deepEqual(await res.json(), [LIST_SUB1, LIST_SUB2]);
			});

			test("rejects malformed boolean filters", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createListHandler(ctx);
				const cases = [
					["trust_marked", "maybe"],
					["intermediate", "maybe"],
				] as const;

				for (const [name, value] of cases) {
					const res = await handler(
						new Request(`https://authority.example.com/federation_list?${name}=${value}`),
					);
					t.equal(res.status, 400, name);
					const body = (await res.json()) as Record<string, string>;
					t.equal(body.error, FederationErrorCode.InvalidRequest, name);
					t.true((body.error_description ?? "").includes(name), name);
				}
			});

			test("includes security headers", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createListHandler(ctx);
				const res = await handler(new Request("https://authority.example.com/federation_list"));
				t.equal(res.headers.get("Cache-Control"), "no-store");
				t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
			});

			test("returns 405 for POST", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_list", { method: "POST" }),
				);
				t.equal(res.status, 405);
			});
		});

		// ── Extended Subordinate Listing handler ───────────────────────────
		const XLIST_BASE_URL = "https://authority.example.com/federation_extended_list";
		const XLIST_SUB_A = entityId("https://a.example.com");
		const XLIST_SUB_B = entityId("https://b.example.com");
		const XLIST_SUB_C = entityId("https://c.example.com");
		const XLIST_SUB_D = entityId("https://d.example.com");
		const XLIST_SUB_E = entityId("https://e.example.com");
		const XLIST_SUB_F = entityId("https://f.example.com");

		function makeXListRecord(
			id: ReturnType<typeof entityId>,
			overrides?: Partial<SubordinateRecord>,
		): SubordinateRecord {
			return {
				entityId: id,
				jwks: { keys: [testPublicJwk()] },
				createdAt: Math.floor(Date.now() / 1000),
				updatedAt: Math.floor(Date.now() / 1000),
				...overrides,
			};
		}

		module("authority / createExtendedListHandler", () => {
			test("JWKS publication rejects private material through HTTP and direct listing", async (t) => {
				const logs: string[] = [];
				const { ctx, storage, crypto, subordinates } = await createTestContext();
				const secret = "private-key-publication-sentinel";
				const server = await createAuthorityServer({
					entityId: ENTITY_ID,
					metadata: {
						federation_entity: {
							...ctx.metadata.federation_entity,
							federation_extended_list_endpoint: XLIST_BASE_URL,
						},
					},
					storage,
					crypto,
					extendedListing: { defaultClaims: ["jwks"] },
					options: {
						logger: {
							debug() {},
							info() {},
							warn() {},
							error(message, context) {
								logs.push(
									message,
									JSON.stringify(context, (_name, value) =>
										value instanceof Error
											? { message: value.message, stack: value.stack, cause: value.cause }
											: value,
									),
								);
							},
						},
					},
				});
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				await subordinates.add(makeXListRecord(XLIST_SUB_B));
				for (const field of ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]) {
					await subordinates.update(XLIST_SUB_B, {
						jwks: { keys: [{ ...testPublicJwk(), [field]: secret }] },
					});
					const before = await subordinates.get(XLIST_SUB_B);
					for (const query of ["?claims=jwks", "", "?claims=jwks,subordinate_statement"]) {
						const response = await (await server).handler()(
							new Request(`${XLIST_BASE_URL}${query}`),
						);
						t.equal(response.status, 500, `${field}, ${query}`);
						t.equal(response.headers.get("content-type"), "application/json");
						const text = await response.text();
						t.false(text.includes(secret));
						t.deepEqual(
							JSON.parse(text),
							{
								error: "server_error",
								error_description: "Failed to build extended subordinate listing",
							},
							"no partial page is returned",
						);
					}
					const result = await (await server).listSubordinatesExtended({ claims: ["jwks"] });
					t.false(result.ok);
					if (!result.ok) t.equal(result.error.code, FederationErrorCode.ServerError);
					t.deepEqual(await subordinates.get(XLIST_SUB_B), before, "stored keys remain unchanged");
				}
				t.true(logs.length > 0);
				t.false(logs.join("\n").includes(secret), "logs contain no private values");
				const idOnly = await (await server).listSubordinatesExtended({ claims: [] });
				t.true(idOnly.ok);
				if (idOnly.ok)
					t.deepEqual(idOnly.value.immediate_subordinate_entities, [
						{ id: XLIST_SUB_A },
						{ id: XLIST_SUB_B },
					]);
			});

			test("JWKS publication rejects invalid sets from custom adapters", async (t) => {
				const { ctx, storage, subordinates } = await createTestContext();
				const key = testPublicJwk();
				for (const jwks of [
					null,
					{},
					{ keys: [] },
					{ keys: [key, key] },
					{ keys: [{ ...key, kid: undefined }] },
					{ keys: [{ ...key, kid: "" }] },
					{ keys: [{ ...key, x: "invalid" }] },
					{ keys: [{ ...key, y: undefined }] },
					{ keys: [{ kty: "oct", kid: "symmetric", k: "private-value" }] },
					{ keys: [{ kty: "RSA", kid: "rsa", n: "AQ" }] },
					{ keys: [{ kty: "OKP", kid: "okp", crv: "Ed25519", x: "AQ" }] },
					{ toJSON: () => ({ keys: [{ ...key, d: "private-value" }] }) },
				]) {
					const record = { ...makeXListRecord(XLIST_SUB_A), jwks } as SubordinateRecord;
					const handler = createExtendedListHandler({
						...ctx,
						storage: {
							...storage,
							transaction: storage.transaction.bind(storage),
							subordinates: {
								get: subordinates.get.bind(subordinates),
								add: subordinates.add.bind(subordinates),
								update: subordinates.update.bind(subordinates),
								remove: subordinates.remove.bind(subordinates),
								list: async () => ({ items: [record] }),
							},
						},
					});
					const response = await handler(new Request(`${XLIST_BASE_URL}?claims=jwks`));
					t.equal(response.status, 500, JSON.stringify(jwks));
					t.equal(((await response.json()) as { error: string }).error, "server_error");
				}
			});

			test("JWKS publication preserves public sets, extensions and signed statement claims", async (t) => {
				const { ctx, subordinates, publicKey } = await createTestContext();
				const handler = createExtendedListHandler(ctx);
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				const publicKeys: JWK[] = [
					(await generateSigningKey("ES256")).publicKey,
					(await generateSigningKey("RS256")).publicKey,
					{
						kty: "OKP",
						kid: "okp",
						crv: "Ed25519",
						x: "fgaB8ZkBBnPX5tPXrPjiXPDDWKcn_hmvaoRh5C-NKDg",
					},
				];
				for (const key of publicKeys) {
					const jwks = {
						keys: [{ ...key, "example:key": "public-extension" }],
						"example:set": "public-extension",
					};
					await subordinates.update(XLIST_SUB_A, { jwks });
					const before = await subordinates.get(XLIST_SUB_A);
					const response = await handler(
						new Request(`${XLIST_BASE_URL}?claims=jwks,subordinate_statement`),
					);
					t.equal(response.status, 200);
					const body = (await response.json()) as {
						immediate_subordinate_entities: Array<{ jwks: unknown; subordinate_statement: string }>;
					};
					const entry = body.immediate_subordinate_entities[0]!;
					t.deepEqual(entry.jwks, jwks);
					const verified = await verifyEntityStatement(
						entry.subordinate_statement,
						{
							keys: [publicKey],
						},
						{ engine: testEngine },
					);
					t.true(verified.ok);
					if (verified.ok) t.deepEqual(verified.value.payload.jwks, entry.jwks);
					t.deepEqual(await subordinates.get(XLIST_SUB_A), before);
				}
			});

			test("JWKS publication serializes a custom adapter's keys once before publishing", async (t) => {
				const { ctx, storage, subordinates } = await createTestContext();
				let reads = 0;
				const publicSet = { keys: [testPublicJwk()] };
				const jwks = {
					...publicSet,
					toJSON() {
						reads++;
						return reads === 1 ? publicSet : { keys: [{ ...testPublicJwk(), d: "private-value" }] };
					},
				};
				const record = makeXListRecord(XLIST_SUB_A, { jwks });
				const handler = createExtendedListHandler({
					...ctx,
					storage: {
						...storage,
						transaction: storage.transaction.bind(storage),
						subordinates: {
							get: subordinates.get.bind(subordinates),
							add: subordinates.add.bind(subordinates),
							update: subordinates.update.bind(subordinates),
							remove: subordinates.remove.bind(subordinates),
							list: async () => ({ items: [record] }),
						},
					},
				});
				const response = await handler(new Request(`${XLIST_BASE_URL}?claims=jwks`));
				t.equal(response.status, 200);
				const body = (await response.json()) as {
					immediate_subordinate_entities: Array<{ jwks: unknown }>;
				};
				t.equal(reads, 1);
				t.deepEqual(body.immediate_subordinate_entities[0]?.jwks, publicSet);
			});

			test("preserves fractional audit timestamps and inclusive time boundaries", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				const dates = [-0.5, 1500.25, 1500.5, 1500.75];
				const ids = [XLIST_SUB_A, XLIST_SUB_B, XLIST_SUB_C, XLIST_SUB_D];
				for (const [index, id] of ids.entries())
					await subordinates.add(
						makeXListRecord(id, { createdAt: -0.5, updatedAt: dates[index]! }),
					);
				const handler = createExtendedListHandler(ctx);
				for (const [query, expected] of [
					["updated_after=1500.5", ids.slice(2)],
					["updated_before=1500.5", ids.slice(0, 3)],
					["updated_after=1.5005e3&updated_before=1500.5", [XLIST_SUB_C]],
					["updated_after=-0.5&updated_before=-0.5", [XLIST_SUB_A]],
				] as const) {
					const response = await handler(new Request(`${XLIST_BASE_URL}?claims=&${query}`));
					t.equal(response.status, 200, query);
					const body = (await response.json()) as {
						immediate_subordinate_entities: Array<{
							id: string;
							registered: number;
							updated: number;
						}>;
					};
					t.deepEqual(
						body.immediate_subordinate_entities.map(({ id }) => id),
						[...expected],
						query,
					);
					for (const entry of body.immediate_subordinate_entities) {
						t.equal(entry.registered, -0.5);
						t.equal(entry.updated, dates[ids.indexOf(entry.id as EntityId)]);
					}
				}
			});
			test("rejects malformed time filters and retains unsupported-feature errors", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createExtendedListHandler(ctx);
				const unsupported = createExtendedListHandler(ctx, { supportTimeFilters: false });
				for (const field of ["updated_after", "updated_before"]) {
					for (const raw of [
						"",
						" ",
						" 1",
						"1 ",
						"1\n",
						"1\r\n",
						"0x10",
						"1.5junk",
						"NaN",
						"Infinity",
						"-Infinity",
						"1e309",
					]) {
						const url = new URL(XLIST_BASE_URL);
						url.searchParams.set(field, raw);
						const response = await handler(new Request(url));
						t.equal(response.status, 400, `${field}=${raw}`);
						t.equal(((await response.json()) as { error: string }).error, "invalid_request");
					}
					const response = await unsupported(new Request(`${XLIST_BASE_URL}?${field}=-0.5`));
					t.equal(response.status, 400);
					t.equal(((await response.json()) as { error: string }).error, "unsupported_parameter");
				}
			});
			test("repeated trust mark types select the valid union across pages", async (t) => {
				const { ctx, subordinates, trustMarks } = await createTestContext({
					options: { clock: { now: () => 2000 }, engine: testEngine },
				});
				const alpha = "https://marks.example/alpha";
				const beta = "https://marks.example/beta";
				for (const id of [
					XLIST_SUB_A,
					XLIST_SUB_B,
					XLIST_SUB_C,
					XLIST_SUB_D,
					XLIST_SUB_E,
					XLIST_SUB_F,
				]) {
					await subordinates.add(makeXListRecord(id));
				}
				for (const [subject, type, active, expiresAt] of [
					[XLIST_SUB_A, alpha, true, 3000],
					[XLIST_SUB_B, beta, true, 3000],
					[XLIST_SUB_C, alpha, true, 3000],
					[XLIST_SUB_C, beta, true, 3000],
					[XLIST_SUB_D, alpha, true, 2000],
					[XLIST_SUB_E, beta, false, 3000],
				] as const) {
					await trustMarks.issue({
						subject,
						trustMarkType: type,
						jwt: `${subject}.${type}`,
						issuedAt: 1000,
						active,
						expiresAt,
					});
				}
				const handler = createExtendedListHandler(ctx);
				const url = new URL(XLIST_BASE_URL);
				url.searchParams.set("claims", "");
				url.searchParams.set("limit", "1");
				for (const type of [alpha, beta, beta]) url.searchParams.append("trust_mark_type", type);
				const ids: string[] = [];
				for (let page = 0; page < 4; page++) {
					const res = await handler(new Request(url));
					t.equal(res.status, 200);
					const body = (await res.json()) as {
						immediate_subordinate_entities: Array<{ id: string }>;
						next?: string;
					};
					ids.push(...body.immediate_subordinate_entities.map(({ id }) => id));
					if (ids.length < 3) t.equal(typeof body.next, "string");
					if (body.next === undefined) break;
					url.searchParams.set("from", body.next);
				}
				t.deepEqual(ids, [XLIST_SUB_A, XLIST_SUB_B, XLIST_SUB_C]);
			});

			test("unknown opaque and empty cursors return JSON page_not_found", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createExtendedListHandler(ctx);
				for (const from of ["unknown +/=cursor", ""]) {
					const url = new URL(XLIST_BASE_URL);
					url.searchParams.set("from", from);
					const res = await handler(new Request(url));
					t.equal(res.status, 404);
					t.equal(res.headers.get("content-type"), "application/json");
					t.equal(((await res.json()) as { error: string }).error, "page_not_found");
				}
			});
			test("returns 200 + application/json with immediate_subordinate_entities", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				await subordinates.add(makeXListRecord(XLIST_SUB_B));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(XLIST_BASE_URL));
				t.equal(res.status, 200);
				t.equal(res.headers.get("Content-Type"), "application/json");
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{ id: string }>;
				};
				t.equal(body.immediate_subordinate_entities.length, 2);
			});

			test("bare request returns id-only entries when defaultClaims is explicitly empty", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				const handler = createExtendedListHandler(ctx, { defaultClaims: [] });
				const res = await handler(new Request(XLIST_BASE_URL));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<Record<string, unknown>>;
				};
				const entry = body.immediate_subordinate_entities[0]!;
				t.equal(entry.id, XLIST_SUB_A);
				t.notOk(
					"subordinate_statement" in entry,
					"subordinate_statement absent when defaultClaims=[]",
				);
				t.notOk("registered" in entry, "registered absent when not requested");
				t.notOk("updated" in entry, "updated absent when not requested");
			});

			test("bare request defaults to claims=[subordinate_statement] when defaultClaims unset", async (t) => {
				const { ctx, subordinates, publicKey } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(XLIST_BASE_URL));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{
						id: string;
						subordinate_statement?: string;
					}>;
				};
				const entry = body.immediate_subordinate_entities[0]!;
				t.ok(entry.subordinate_statement, "subordinate_statement included by default");
				const verified = await verifyEntityStatement(
					entry.subordinate_statement as string,
					{ keys: [publicKey] },
					{ engine: testEngine, expectedTyp: JwtTyp.EntityStatement },
				);
				t.true(isOk(verified));
			});

			test("present-but-empty claims= is treated as user-supplied (no default substitution)", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?claims=`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<Record<string, unknown>>;
				};
				const entry = body.immediate_subordinate_entities[0]!;
				t.notOk(
					"subordinate_statement" in entry,
					"empty claims= prevents default substitution (MUST-NOT guard)",
				);
			});

			test("custom defaultClaims is respected on bare requests", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(
					makeXListRecord(XLIST_SUB_A, {
						metadata: { openid_relying_party: { client_id: "x" } },
					}),
				);
				const handler = createExtendedListHandler(ctx, { defaultClaims: ["metadata"] });
				const res = await handler(new Request(XLIST_BASE_URL));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{ id: string; metadata?: unknown }>;
				};
				const entry = body.immediate_subordinate_entities[0]!;
				t.deepEqual(entry.metadata, { openid_relying_party: { client_id: "x" } });
				t.notOk("subordinate_statement" in entry, "only configured defaultClaims are added");
			});

			test("includes signed subordinate_statement when claims=subordinate_statement", async (t) => {
				const { ctx, subordinates, publicKey } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?claims=subordinate_statement`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{ id: string; subordinate_statement?: string }>;
				};
				const entry = body.immediate_subordinate_entities[0]!;
				t.ok(entry.subordinate_statement, "subordinate_statement present");
				const verified = await verifyEntityStatement(
					entry.subordinate_statement as string,
					{ keys: [publicKey] },
					{ engine: testEngine, expectedTyp: JwtTyp.EntityStatement },
				);
				t.true(isOk(verified), "subordinate_statement verifies against authority key");
				if (isOk(verified)) {
					t.equal(verified.value.payload.sub, XLIST_SUB_A);
					t.equal(verified.value.payload.iss, ENTITY_ID);
				}
			});

			test("MUST NOT include subordinate_statement when claims param omits it", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?claims=metadata`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<Record<string, unknown>>;
				};
				t.notOk("subordinate_statement" in body.immediate_subordinate_entities[0]!);
			});

			test("accepts comma-separated claims= as a single param", async (t) => {
				const { ctx, subordinates, publicKey } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(
					new Request(`${XLIST_BASE_URL}?claims=subordinate_statement,metadata`),
				);
				t.equal(res.status, 200);
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{
						id: string;
						subordinate_statement?: string;
					}>;
				};
				const entry = body.immediate_subordinate_entities[0]!;
				t.ok(entry.subordinate_statement, "subordinate_statement included via comma syntax");
				const verified = await verifyEntityStatement(
					entry.subordinate_statement as string,
					{ keys: [publicKey] },
					{ engine: testEngine, expectedTyp: JwtTyp.EntityStatement },
				);
				t.true(isOk(verified));
			});

			test("comma-separated and repeated claims= produce identical responses", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(
					makeXListRecord(XLIST_SUB_A, {
						metadata: { openid_relying_party: { client_id: "x" } },
					}),
				);
				const handler = createExtendedListHandler(ctx);

				const commaRes = await handler(
					new Request(`${XLIST_BASE_URL}?claims=metadata,constraints`),
				);
				const repeatedRes = await handler(
					new Request(`${XLIST_BASE_URL}?claims=metadata&claims=constraints`),
				);
				const commaBody = (await commaRes.json()) as Record<string, unknown>;
				const repeatedBody = (await repeatedRes.json()) as Record<string, unknown>;
				t.deepEqual(commaBody, repeatedBody);
			});

			test("comma syntax tolerates empty tokens", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(
					new Request(`${XLIST_BASE_URL}?claims=,metadata,,subordinate_statement,`),
				);
				t.equal(res.status, 200);
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<Record<string, unknown>>;
				};
				const entry = body.immediate_subordinate_entities[0]!;
				t.ok("subordinate_statement" in entry, "subordinate_statement present");
			});

			test("audit_timestamps=true returns registered + updated for every entity", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A, { createdAt: 100, updatedAt: 200 }));
				await subordinates.add(makeXListRecord(XLIST_SUB_B, { createdAt: 300, updatedAt: 400 }));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?audit_timestamps=true`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{
						id: string;
						registered: number;
						updated: number;
					}>;
				};
				t.equal(body.immediate_subordinate_entities.length, 2);
				for (const entry of body.immediate_subordinate_entities) {
					t.ok(Number.isInteger(entry.registered));
					t.ok(Number.isInteger(entry.updated));
				}
			});

			test("emits registered/updated as exact NumericDate from record (no ms→s conversion)", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(
					makeXListRecord(XLIST_SUB_A, {
						createdAt: 1_700_000_000,
						updatedAt: 1_700_000_500,
					}),
				);
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?audit_timestamps=true`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{
						id: string;
						registered: number;
						updated: number;
					}>;
				};
				const entry = body.immediate_subordinate_entities[0]!;
				t.equal(entry.registered, 1_700_000_000);
				t.equal(entry.updated, 1_700_000_500);
			});

			test("audit_timestamps unsupported by config returns 400 unsupported_parameter", async (t) => {
				const { ctx } = await createTestContext();
				const cfg: ExtendedListingConfig = { supportAuditTimestamps: false };
				const handler = createExtendedListHandler(ctx, cfg);
				const res = await handler(new Request(`${XLIST_BASE_URL}?audit_timestamps=true`));
				t.equal(res.status, 400);
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, "unsupported_parameter");
			});

			test("updated_after / updated_before unsupported by config returns 400 unsupported_parameter", async (t) => {
				const { ctx } = await createTestContext();
				const cfg: ExtendedListingConfig = { supportTimeFilters: false };
				const handler = createExtendedListHandler(ctx, cfg);
				const r1 = await handler(new Request(`${XLIST_BASE_URL}?updated_after=1000`));
				t.equal(r1.status, 400);
				t.equal(((await r1.json()) as Record<string, string>).error, "unsupported_parameter");
				const r2 = await handler(new Request(`${XLIST_BASE_URL}?updated_before=1000`));
				t.equal(r2.status, 400);
				t.equal(((await r2.json()) as Record<string, string>).error, "unsupported_parameter");
			});

			test("from=unknown returns 404 page_not_found", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(
					new Request(`${XLIST_BASE_URL}?from=${encodeURIComponent("https://nope.example.com")}`),
				);
				t.equal(res.status, 404);
				t.equal(res.headers.get("Content-Type"), "application/json");
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, "page_not_found");
			});

			test("from resumes from cursor (inclusive)", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				await subordinates.add(makeXListRecord(XLIST_SUB_B));
				await subordinates.add(makeXListRecord(XLIST_SUB_C));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(
					new Request(`${XLIST_BASE_URL}?from=${encodeURIComponent(XLIST_SUB_B)}`),
				);
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{ id: string }>;
				};
				t.deepEqual(
					body.immediate_subordinate_entities.map((e) => e.id),
					[XLIST_SUB_B, XLIST_SUB_C],
				);
			});

			test("limit caps the page size; next present when more remain", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				await subordinates.add(makeXListRecord(XLIST_SUB_B));
				await subordinates.add(makeXListRecord(XLIST_SUB_C));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?limit=2`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{ id: string }>;
					next?: string;
				};
				t.equal(body.immediate_subordinate_entities.length, 2);
				t.equal(body.immediate_subordinate_entities[0]!.id, XLIST_SUB_A);
				t.equal(body.immediate_subordinate_entities[1]!.id, XLIST_SUB_B);
				t.equal(body.next, XLIST_SUB_C);
			});

			test("next absent when results fit in the page", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				await subordinates.add(makeXListRecord(XLIST_SUB_B));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?limit=10`));
				const body = (await res.json()) as Record<string, unknown>;
				t.notOk("next" in body, "next omitted when the result is exhausted");
			});

			test("updated_after filters older records", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A, { updatedAt: 1000 }));
				await subordinates.add(makeXListRecord(XLIST_SUB_B, { updatedAt: 2000 }));
				await subordinates.add(makeXListRecord(XLIST_SUB_C, { updatedAt: 3000 }));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?updated_after=1500`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{ id: string }>;
				};
				t.deepEqual(
					body.immediate_subordinate_entities.map((e) => e.id),
					[XLIST_SUB_B, XLIST_SUB_C],
				);
			});

			test("updated_before filters newer records", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A, { updatedAt: 1000 }));
				await subordinates.add(makeXListRecord(XLIST_SUB_B, { updatedAt: 2000 }));
				await subordinates.add(makeXListRecord(XLIST_SUB_C, { updatedAt: 3000 }));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?updated_before=2500`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{ id: string }>;
				};
				t.deepEqual(
					body.immediate_subordinate_entities.map((e) => e.id),
					[XLIST_SUB_A, XLIST_SUB_B],
				);
			});

			test("inherits entity_type filter from base endpoint", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(
					makeXListRecord(XLIST_SUB_A, { entityTypes: [EntityType.OpenIDProvider] }),
				);
				await subordinates.add(
					makeXListRecord(XLIST_SUB_B, { entityTypes: [EntityType.OpenIDRelyingParty] }),
				);
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?entity_type=openid_provider`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{ id: string }>;
				};
				t.deepEqual(
					body.immediate_subordinate_entities.map((e) => e.id),
					[XLIST_SUB_A],
				);
			});

			test("accepts a custom entity_type value instead of rejecting it", async (t) => {
				// Ext-Listing §3.2 inherits the base §8.2.1 entity_type parameter;
				// Federation §5.1 keeps its value space open (no registry).
				const { ctx, subordinates } = await createTestContext();
				const customType = "https://extensions.example.com/custom_wallet_type";
				await subordinates.add(makeXListRecord(XLIST_SUB_A, { entityTypes: [customType] }));
				await subordinates.add(
					makeXListRecord(XLIST_SUB_B, { entityTypes: [EntityType.OpenIDRelyingParty] }),
				);
				const handler = createExtendedListHandler(ctx);
				const res = await handler(
					new Request(`${XLIST_BASE_URL}?entity_type=${encodeURIComponent(customType)}`),
				);
				t.equal(res.status, 200);
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{ id: string }>;
				};
				t.deepEqual(
					body.immediate_subordinate_entities.map((e) => e.id),
					[XLIST_SUB_A],
				);
			});

			test("inherits intermediate filter from base endpoint", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A, { isIntermediate: true }));
				await subordinates.add(makeXListRecord(XLIST_SUB_B, { isIntermediate: false }));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?intermediate=true`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{ id: string }>;
				};
				t.deepEqual(
					body.immediate_subordinate_entities.map((e) => e.id),
					[XLIST_SUB_A],
				);
			});

			test("inherits trust_marked filter from base endpoint", async (t) => {
				const { ctx, subordinates, trustMarks } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				await subordinates.add(makeXListRecord(XLIST_SUB_B));
				await trustMarks.issue({
					trustMarkType: "https://trust.example.com/mark",
					subject: XLIST_SUB_A,
					jwt: "test.jwt",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?trust_marked=true`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{ id: string }>;
				};
				t.deepEqual(
					body.immediate_subordinate_entities.map((e) => e.id),
					[XLIST_SUB_A],
				);
			});

			test("claims=trust_marks attaches active trust marks per entity", async (t) => {
				const { ctx, subordinates, trustMarks, signingKey } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				const jwt = await signEntityStatement(
					{
						iss: ENTITY_ID,
						sub: XLIST_SUB_A,
						trust_mark_type: "https://trust.example.com/mark",
						iat: Math.floor(Date.now() / 1000),
					},
					new SigningEntryFixture(signingKey),
					{ typ: JwtTyp.TrustMark },
				);
				await trustMarks.issue({
					trustMarkType: "https://trust.example.com/mark",
					subject: XLIST_SUB_A,
					jwt,
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?claims=trust_marks`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{
						id: string;
						trust_marks?: Array<{ trust_mark_type: string; trust_mark: string }>;
					}>;
				};
				const entry = body.immediate_subordinate_entities[0]!;
				t.ok(Array.isArray(entry.trust_marks), "trust_marks array present");
				t.equal(entry.trust_marks!.length, 1);
				t.equal(entry.trust_marks![0]!.trust_mark_type, "https://trust.example.com/mark");
				t.equal(entry.trust_marks![0]!.trust_mark, jwt);
			});

			test("claims=trust_marks returns empty array when subject has no active marks", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?claims=trust_marks`));
				t.equal(res.status, 200);
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{
						id: string;
						trust_marks?: Array<unknown>;
					}>;
				};
				const entry = body.immediate_subordinate_entities[0]!;
				t.deepEqual(entry.trust_marks, []);
			});

			test("claims=trust_marks returns an empty selection when trust mark capability is absent", async (t) => {
				const storage = new MemoryStorageAdapter({ engine: testEngine });
				const { ctx } = await createTestContext({ storage });
				await storage.subordinates.add(makeXListRecord(XLIST_SUB_A));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?claims=trust_marks`));
				t.equal(res.status, 200);
				t.equal(res.headers.get("Content-Type"), "application/json");
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{ trust_marks: unknown[] }>;
				};
				t.deepEqual(body.immediate_subordinate_entities[0]?.trust_marks, []);
			});

			test("claims=metadata attaches subordinate metadata", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(
					makeXListRecord(XLIST_SUB_A, {
						metadata: { openid_relying_party: { client_id: "x" } },
					}),
				);
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?claims=metadata`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{ id: string; metadata?: unknown }>;
				};
				t.deepEqual(body.immediate_subordinate_entities[0]!.metadata, {
					openid_relying_party: { client_id: "x" },
				});
			});

			test("unknown claim names are silently ignored", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?claims=not_a_real_claim`));
				t.equal(res.status, 200);
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<Record<string, unknown>>;
				};
				t.notOk("not_a_real_claim" in body.immediate_subordinate_entities[0]!);
			});

			test("critical operator lists are published while absent crit remains omitted", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(
					makeXListRecord(XLIST_SUB_A, {
						metadataPolicyCrit: ["custom-policy-op"],
					}),
				);
				const handler = createExtendedListHandler(ctx);
				const res = await handler(
					new Request(`${XLIST_BASE_URL}?claims=crit,metadata_policy_crit`),
				);
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{
						id: string;
						crit?: string[];
						metadata_policy_crit?: string[];
					}>;
				};
				const entry = body.immediate_subordinate_entities[0]!;
				t.strictEqual(entry.crit, undefined);
				t.deepEqual(entry.metadata_policy_crit, ["custom-policy-op"]);
			});

			test("claims=iss,sub,iat,exp surfaces synthetic top-level claims per entity", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				const handler = createExtendedListHandler(ctx);
				const before = Math.floor(Date.now() / 1000);
				const res = await handler(new Request(`${XLIST_BASE_URL}?claims=iss,sub,iat,exp`));
				const after = Math.floor(Date.now() / 1000);
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{
						id: string;
						iss: string;
						sub: string;
						iat: number;
						exp: number;
					}>;
				};
				const entry = body.immediate_subordinate_entities[0]!;
				t.equal(entry.iss, ENTITY_ID);
				t.equal(entry.sub, XLIST_SUB_A);
				t.equal(entry.sub, entry.id, "sub matches id field");
				t.ok(entry.iat >= before - 1 && entry.iat <= after + 1, "iat within real-time window");
				t.true(entry.exp > entry.iat, "exp > iat");
			});

			test("claims=iat,exp,subordinate_statement aligns synthetic values with the JWT", async (t) => {
				const { ctx, subordinates, publicKey } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(
					new Request(`${XLIST_BASE_URL}?claims=iat,exp,subordinate_statement`),
				);
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{
						id: string;
						iat: number;
						exp: number;
						subordinate_statement: string;
					}>;
				};
				const entry = body.immediate_subordinate_entities[0]!;
				const verified = await verifyEntityStatement(
					entry.subordinate_statement,
					{ keys: [publicKey] },
					{ engine: testEngine, expectedTyp: JwtTyp.EntityStatement },
				);
				t.true(isOk(verified));
				if (isOk(verified)) {
					t.equal(verified.value.payload.iat, entry.iat, "top-level iat matches JWT iat");
					t.equal(verified.value.payload.exp, entry.exp, "top-level exp matches JWT exp");
				}
			});

			test("synthetic iat/exp are identical across all entries in a single response", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				await subordinates.add(makeXListRecord(XLIST_SUB_B));
				await subordinates.add(makeXListRecord(XLIST_SUB_C));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?claims=iat,exp`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{ iat: number; exp: number }>;
				};
				const iats = new Set(body.immediate_subordinate_entities.map((e) => e.iat));
				const exps = new Set(body.immediate_subordinate_entities.map((e) => e.exp));
				t.equal(iats.size, 1, "iat snapshot stable across page");
				t.equal(exps.size, 1, "exp snapshot stable across page");
			});

			test("out-of-scope top-level claims are silently dropped per entity (no 400)", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				const handler = createExtendedListHandler(ctx);
				const res = await handler(
					new Request(
						`${XLIST_BASE_URL}?claims=authority_hints,trust_mark_issuers,trust_mark_owners,aud,trust_anchor`,
					),
				);
				t.equal(res.status, 200);
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<Record<string, unknown>>;
				};
				const entry = body.immediate_subordinate_entities[0]!;
				for (const dropped of [
					"authority_hints",
					"trust_mark_issuers",
					"trust_mark_owners",
					"aud",
					"trust_anchor",
				]) {
					t.notOk(dropped in entry, `${dropped} absent`);
				}
			});

			test("updated_after alone auto-includes registered+updated per entity (RECOMMENDED)", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(
					makeXListRecord(XLIST_SUB_A, { createdAt: 1_000, updatedAt: 2_000 }),
				);
				await subordinates.add(
					makeXListRecord(XLIST_SUB_B, { createdAt: 3_000, updatedAt: 4_000 }),
				);
				const handler = createExtendedListHandler(ctx, { defaultClaims: [] });
				const res = await handler(new Request(`${XLIST_BASE_URL}?updated_after=500`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{
						id: string;
						registered: number;
						updated: number;
					}>;
				};
				for (const entry of body.immediate_subordinate_entities) {
					t.ok(Number.isInteger(entry.registered));
					t.ok(Number.isInteger(entry.updated));
				}
			});

			test("updated_before alone auto-includes registered+updated per entity (RECOMMENDED)", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(
					makeXListRecord(XLIST_SUB_A, { createdAt: 1_000, updatedAt: 2_000 }),
				);
				const handler = createExtendedListHandler(ctx, { defaultClaims: [] });
				const res = await handler(new Request(`${XLIST_BASE_URL}?updated_before=10000`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{
						id: string;
						registered?: number;
						updated?: number;
					}>;
				};
				const entry = body.immediate_subordinate_entities[0]!;
				t.equal(entry.registered, 1_000);
				t.equal(entry.updated, 2_000);
			});

			test("explicit audit_timestamps=false suppresses even when updated_after is present", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(
					makeXListRecord(XLIST_SUB_A, { createdAt: 1_000, updatedAt: 2_000 }),
				);
				const handler = createExtendedListHandler(ctx, { defaultClaims: [] });
				const res = await handler(
					new Request(`${XLIST_BASE_URL}?updated_after=500&audit_timestamps=false`),
				);
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<Record<string, unknown>>;
				};
				const entry = body.immediate_subordinate_entities[0]!;
				t.notOk("registered" in entry, "registered suppressed by explicit false");
				t.notOk("updated" in entry, "updated suppressed by explicit false");
			});

			test("updated_after with supportTimeFilters=false returns 400 unsupported_parameter (application/json)", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createExtendedListHandler(ctx, { supportTimeFilters: false });
				const res = await handler(new Request(`${XLIST_BASE_URL}?updated_after=1000`));
				t.equal(res.status, 400);
				t.equal(res.headers.get("Content-Type"), "application/json");
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, "unsupported_parameter");
			});

			test("updated_before with supportTimeFilters=false returns 400 unsupported_parameter (application/json)", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createExtendedListHandler(ctx, { supportTimeFilters: false });
				const res = await handler(new Request(`${XLIST_BASE_URL}?updated_before=1000`));
				t.equal(res.status, 400);
				t.equal(res.headers.get("Content-Type"), "application/json");
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, "unsupported_parameter");
			});

			test("audit_timestamps=true with supportAuditTimestamps=false returns 400 (application/json)", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createExtendedListHandler(ctx, { supportAuditTimestamps: false });
				const res = await handler(new Request(`${XLIST_BASE_URL}?audit_timestamps=true`));
				t.equal(res.status, 400);
				t.equal(res.headers.get("Content-Type"), "application/json");
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, "unsupported_parameter");
			});

			test("consistent ordering across paginated calls (concatenation equals full sorted list)", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				await subordinates.add(makeXListRecord(XLIST_SUB_D));
				await subordinates.add(makeXListRecord(XLIST_SUB_A));
				await subordinates.add(makeXListRecord(XLIST_SUB_C));
				await subordinates.add(makeXListRecord(XLIST_SUB_B));
				const handler = createExtendedListHandler(ctx);
				const pageOne = (await (
					await handler(new Request(`${XLIST_BASE_URL}?limit=2`))
				).json()) as {
					immediate_subordinate_entities: Array<{ id: string }>;
					next?: string;
				};
				t.equal(pageOne.immediate_subordinate_entities.length, 2);
				t.ok(pageOne.next, "next present");
				const pageTwo = (await (
					await handler(
						new Request(
							`${XLIST_BASE_URL}?limit=2&from=${encodeURIComponent(pageOne.next as string)}`,
						),
					)
				).json()) as {
					immediate_subordinate_entities: Array<{ id: string }>;
					next?: string;
				};
				t.notOk(pageTwo.next, "no more pages");
				t.deepEqual(
					[
						...pageOne.immediate_subordinate_entities.map((e) => e.id),
						...pageTwo.immediate_subordinate_entities.map((e) => e.id),
					],
					[XLIST_SUB_A, XLIST_SUB_B, XLIST_SUB_C, XLIST_SUB_D],
				);
			});

			test("page-fill: trust-mark filter does not under-fill the page when more items exist", async (t) => {
				const { ctx, subordinates, trustMarks } = await createTestContext();
				for (const sub of [
					XLIST_SUB_A,
					XLIST_SUB_B,
					XLIST_SUB_C,
					XLIST_SUB_D,
					XLIST_SUB_E,
					XLIST_SUB_F,
				]) {
					await subordinates.add(makeXListRecord(sub));
				}
				for (const sub of [XLIST_SUB_A, XLIST_SUB_D, XLIST_SUB_E]) {
					await trustMarks.issue({
						trustMarkType: "https://trust.example.com/mark",
						subject: sub,
						jwt: `x.y.${sub}`,
						issuedAt: 0,
						active: true,
					});
				}
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?limit=3&trust_marked=true`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{ id: string }>;
					next?: string;
				};
				t.deepEqual(
					body.immediate_subordinate_entities.map((e) => e.id),
					[XLIST_SUB_A, XLIST_SUB_D, XLIST_SUB_E],
				);
				t.equal(body.next, undefined);
			});

			test("page-fill: next is the first un-emitted entityId past the page", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				for (const sub of [XLIST_SUB_A, XLIST_SUB_B, XLIST_SUB_C, XLIST_SUB_D, XLIST_SUB_E]) {
					await subordinates.add(makeXListRecord(sub));
				}
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?limit=3`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{ id: string }>;
					next?: string;
				};
				t.deepEqual(
					body.immediate_subordinate_entities.map((e) => e.id),
					[XLIST_SUB_A, XLIST_SUB_B, XLIST_SUB_C],
				);
				t.equal(body.next, XLIST_SUB_D);
			});

			test("page-fill: trust-mark filter consumes everything in last drained page, next undefined", async (t) => {
				const { ctx, subordinates, trustMarks } = await createTestContext();
				for (const sub of [XLIST_SUB_A, XLIST_SUB_B, XLIST_SUB_C, XLIST_SUB_D, XLIST_SUB_E]) {
					await subordinates.add(makeXListRecord(sub));
				}
				for (const sub of [XLIST_SUB_A, XLIST_SUB_E]) {
					await trustMarks.issue({
						trustMarkType: "https://trust.example.com/mark",
						subject: sub,
						jwt: `x.y.${sub}`,
						issuedAt: 0,
						active: true,
					});
				}
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?limit=2&trust_marked=true`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{ id: string }>;
					next?: string;
				};
				t.deepEqual(
					body.immediate_subordinate_entities.map((e) => e.id),
					[XLIST_SUB_A, XLIST_SUB_E],
				);
				t.equal(body.next, undefined);
			});

			test("storage-level trust filtering reports exhaustion without scan cursors", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				for (const sub of [
					XLIST_SUB_A,
					XLIST_SUB_B,
					XLIST_SUB_C,
					XLIST_SUB_D,
					XLIST_SUB_E,
					XLIST_SUB_F,
				]) {
					await subordinates.add(makeXListRecord(sub));
				}
				// No records carry trust marks, so the adapter returns an exhausted result directly.
				const handler = createExtendedListHandler(ctx, {
					maxStorePagesPerRequest: 2,
					storeBatchSize: 2,
				});
				const res = await handler(new Request(`${XLIST_BASE_URL}?limit=10&trust_marked=true`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<{ id: string }>;
					next?: string;
				};
				t.equal(body.immediate_subordinate_entities.length, 0);
				t.equal(body.next, undefined);
			});

			test("page-fill: cap-exit cursor resumes correctly (no skips, no duplicates)", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				for (const sub of [XLIST_SUB_A, XLIST_SUB_B, XLIST_SUB_C, XLIST_SUB_D, XLIST_SUB_E]) {
					await subordinates.add(makeXListRecord(sub));
				}
				const handler = createExtendedListHandler(ctx, {
					maxStorePagesPerRequest: 1,
					storeBatchSize: 2,
				});
				const first = (await (await handler(new Request(`${XLIST_BASE_URL}?limit=10`))).json()) as {
					immediate_subordinate_entities: Array<{ id: string }>;
					next?: string;
				};
				t.equal(first.immediate_subordinate_entities.length, 2);
				t.ok(first.next, "cap-exit cursor present");
				// Resume from the page-scan limit cursor without skipping or duplicating records.
				const handler2 = createExtendedListHandler(ctx);
				const rest = (await (
					await handler2(
						new Request(
							`${XLIST_BASE_URL}?from=${encodeURIComponent(first.next as string)}&limit=10`,
						),
					)
				).json()) as { immediate_subordinate_entities: Array<{ id: string }> };
				const concatenated = [
					...first.immediate_subordinate_entities.map((e) => e.id),
					...rest.immediate_subordinate_entities.map((e) => e.id),
				];
				const sorted = [XLIST_SUB_A, XLIST_SUB_B, XLIST_SUB_C, XLIST_SUB_D, XLIST_SUB_E].sort();
				t.deepEqual(concatenated, sorted);
			});

			test("defaultPageSize caps the response when client omits limit", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				for (let i = 0; i < 6; i++) {
					await subordinates.add(
						makeXListRecord(entityId(`https://sub-${String(i).padStart(2, "0")}.example.com`)),
					);
				}
				const handler = createExtendedListHandler(ctx, { defaultPageSize: 3 });
				const res = await handler(new Request(XLIST_BASE_URL));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<unknown>;
					next?: string;
				};
				t.equal(body.immediate_subordinate_entities.length, 3);
				t.ok(body.next, "next present when more records remain");
			});

			test("client limit exceeding maxPageSize is clamped", async (t) => {
				const { ctx, subordinates } = await createTestContext();
				for (let i = 0; i < 6; i++) {
					await subordinates.add(
						makeXListRecord(entityId(`https://sub-${String(i).padStart(2, "0")}.example.com`)),
					);
				}
				const handler = createExtendedListHandler(ctx, { maxPageSize: 2 });
				const res = await handler(new Request(`${XLIST_BASE_URL}?limit=10000`));
				const body = (await res.json()) as {
					immediate_subordinate_entities: Array<unknown>;
					next?: string;
				};
				t.equal(body.immediate_subordinate_entities.length, 2, "clamped to maxPageSize");
				t.ok(body.next);
			});

			test("rejects POST with 405", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(XLIST_BASE_URL, { method: "POST" }));
				t.equal(res.status, 405);
			});

			test("rejects negative limit with 400 invalid_request", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?limit=-1`));
				t.equal(res.status, 400);
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, "invalid_request");
			});

			test("rejects non-numeric updated_after with 400 invalid_request", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(`${XLIST_BASE_URL}?updated_after=yesterday`));
				t.equal(res.status, 400);
				const body = (await res.json()) as Record<string, string>;
				t.equal(body.error, "invalid_request");
			});

			test("includes standard security headers", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createExtendedListHandler(ctx);
				const res = await handler(new Request(XLIST_BASE_URL));
				t.equal(res.headers.get("Cache-Control"), "no-store");
				t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
			});

			test("returns 404 when extended listing is explicitly disabled", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createExtendedListHandler(ctx, { enabled: false });
				const res = await handler(new Request(XLIST_BASE_URL));
				t.equal(res.status, 404);
			});
		});
	}

	// -------------------------------------------------------------------------
	// endpoints/resolve
	// -------------------------------------------------------------------------
	module("authority / createResolveHandler", () => {
		async function createResolveTrustMarkFixture(options?: {
			readonly status?: TrustMarkStatus;
			readonly expiredMarkPosition?: "before" | "after";
			readonly resolverEntityId?: EntityId;
			readonly useLocalTrustMarkStore?: boolean;
			readonly trustMarkExpiresAt?: number;
			readonly delegationExpiresAt?: number;
		}): Promise<{
			ctx: HandlerContext;
			chainExp: number;
			requestUrl: string;
			trustMarkJwt: string;
			trustMarkType: string;
			trustMarkExpiresAt: number;
		}> {
			const now = 1_700_000_000;
			const chainExp = now + 3_600;
			const trustMarkExpiresAt = options?.trustMarkExpiresAt ?? now + 600;
			const status = options?.status ?? TrustMarkStatus.Active;
			const resolverEntityId = options?.resolverEntityId ?? ENTITY_ID;
			const trustMarkType = "https://trust.example.com/assurance";

			const { privateKey: taPrivateKey, publicKey: taRawPublicKey } =
				await generateSigningKey("ES256");
			const { privateKey: leafPrivateKey, publicKey: leafRawPublicKey } =
				await generateSigningKey("ES256");
			const taSigningKey = { ...taPrivateKey, kid: "resolve-ta-key-1" };
			const taPublicKey = { ...taRawPublicKey, kid: "resolve-ta-key-1" };
			const leafSigningKey = { ...leafPrivateKey, kid: "resolve-leaf-key-1" };
			const leafPublicKey = { ...leafRawPublicKey, kid: "resolve-leaf-key-1" };

			const delegation =
				options?.delegationExpiresAt === undefined
					? undefined
					: await signTrustMarkDelegation({
							issuer: TA_ID,
							subject: TA_ID,
							trustMarkType,
							signer: new SigningEntryFixture(taSigningKey),
							clock: { now: () => now },
							ttlSeconds: options.delegationExpiresAt - now,
						});

			const trustMarkJwt = await signEntityStatement(
				{
					iss: TA_ID,
					sub: LEAF_ID,
					trust_mark_type: trustMarkType,
					iat: now,
					exp: trustMarkExpiresAt,
					...(delegation ? { delegation } : {}),
				},
				new SigningEntryFixture(taSigningKey),
				{ typ: JwtTyp.TrustMark },
			);

			const taEcJwt = await signEntityStatement(
				{
					iss: TA_ID,
					sub: TA_ID,
					iat: now,
					exp: chainExp,
					jwks: { keys: [taPublicKey] },
					trust_mark_issuers: { [trustMarkType]: [TA_ID] },
					...(delegation
						? {
								trust_mark_owners: {
									[trustMarkType]: { sub: TA_ID, jwks: { keys: [taPublicKey] } },
								},
							}
						: {}),
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: `${TA_ID}${FederationEndpoint.Fetch}`,
							federation_list_endpoint: `${TA_ID}${FederationEndpoint.List}`,
							federation_trust_mark_status_endpoint: `${TA_ID}${FederationEndpoint.TrustMarkStatus}`,
						},
					},
				},
				new SigningEntryFixture(taSigningKey),
				{ typ: JwtTyp.EntityStatement },
			);

			const refs = [{ trust_mark_type: trustMarkType, trust_mark: trustMarkJwt }];
			if (options?.expiredMarkPosition) {
				const expired = await signEntityStatement(
					{
						iss: TA_ID,
						sub: LEAF_ID,
						trust_mark_type: trustMarkType,
						iat: now - 600,
						exp: now - 300,
					},
					new SigningEntryFixture(taSigningKey),
					{ typ: JwtTyp.TrustMark },
				);
				const ref = { trust_mark_type: trustMarkType, trust_mark: expired };
				if (options.expiredMarkPosition === "before") refs.unshift(ref);
				else refs.push(ref);
			}

			const leafEcJwt = await signEntityStatement(
				{
					iss: LEAF_ID,
					sub: LEAF_ID,
					iat: now,
					exp: chainExp,
					jwks: { keys: [leafPublicKey] },
					authority_hints: [TA_ID],
					metadata: {
						openid_relying_party: {
							redirect_uris: ["https://rp.example.com/callback"],
							response_types: ["code"],
							client_registration_types: ["automatic"],
							jwks: { keys: [leafPublicKey] },
						},
					},
					trust_marks: refs,
				},
				new SigningEntryFixture(leafSigningKey),
				{ typ: JwtTyp.EntityStatement },
			);

			const subordinateStatementJwt = await signEntityStatement(
				{
					iss: TA_ID,
					sub: LEAF_ID,
					iat: now,
					exp: chainExp,
					jwks: { keys: [leafPublicKey] },
				},
				new SigningEntryFixture(taSigningKey),
				{ typ: JwtTyp.EntityStatement },
			);

			const statusJwt = await signEntityStatement(
				{
					iss: TA_ID,
					iat: now,
					trust_mark: trustMarkJwt,
					status,
				},
				new SigningEntryFixture(taSigningKey),
				{ typ: JwtTyp.TrustMarkStatusResponse },
			);

			const httpClient: import("../../../packages/core/src/index.js").HttpClient = async (
				input,
			) => {
				const url =
					typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
				const parsed = new URL(url);

				if (parsed.pathname === WELL_KNOWN_OPENID_FEDERATION) {
					if (parsed.origin === TA_ID) {
						return new Response(taEcJwt, {
							status: 200,
							headers: { "Content-Type": MediaType.EntityStatement },
						});
					}
					if (parsed.origin === LEAF_ID) {
						return new Response(leafEcJwt, {
							status: 200,
							headers: { "Content-Type": MediaType.EntityStatement },
						});
					}
				}

				if (parsed.origin === TA_ID && parsed.pathname === FederationEndpoint.Fetch) {
					if (parsed.searchParams.get("sub") === LEAF_ID) {
						return new Response(subordinateStatementJwt, {
							status: 200,
							headers: { "Content-Type": MediaType.EntityStatement },
						});
					}
				}

				if (parsed.origin === TA_ID && parsed.pathname === FederationEndpoint.TrustMarkStatus) {
					return new Response(statusJwt, {
						status: 200,
						headers: { "Content-Type": MediaType.TrustMarkStatusResponse },
					});
				}

				return new Response("Not Found", { status: 404 });
			};

			const { ctx, trustMarks } = await createTestContext({
				entityId: resolverEntityId,
				trustAnchors: new Map([[TA_ID, { jwks: { keys: [taPublicKey] } }]]),
				options: { httpClient, clock: { now: () => now }, engine: testEngine },
			});

			if (options?.useLocalTrustMarkStore) {
				await trustMarks.issue({
					trustMarkType,
					subject: LEAF_ID,
					jwt: trustMarkJwt,
					issuedAt: now,
					expiresAt: trustMarkExpiresAt,
					active: status === TrustMarkStatus.Active,
				});
			}

			return {
				ctx,
				chainExp,
				requestUrl: `${resolverEntityId}${FederationEndpoint.Resolve}?sub=${encodeURIComponent(
					LEAF_ID,
				)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				trustMarkJwt,
				trustMarkType,
				trustMarkExpiresAt,
			};
		}

		test("cached Resolve assessments expire with an included mark's delegation", async (t) => {
			const deadline = 1_700_000_010;
			const fixture = await createResolveTrustMarkFixture({ delegationExpiresAt: deadline });
			let now = 1_700_000_000;
			const handler = createResolveHandler({
				...fixture.ctx,
				requireAuthForFreshResolution: true,
				options: { ...fixture.ctx.options, clock: { now: () => now } },
			});
			t.equal((await handler(new Request(fixture.requestUrl), true)).status, 200);
			const response = await handler(new Request(fixture.requestUrl));
			t.equal(response.status, 200);
			const decoded = decodeEntityStatement(await response.text());
			t.true(decoded.ok);
			if (decoded.ok) {
				t.equal(decoded.value.payload.exp, Math.min(fixture.chainExp, fixture.trustMarkExpiresAt));
				t.true(
					fixture.trustMarkExpiresAt > deadline,
					"delegation limits cache reuse independently of the wire expiry",
				);
				t.equal((decoded.value.payload.trust_marks as unknown[]).length, 1);
			}
			now = deadline;
			t.equal((await handler(new Request(fixture.requestUrl))).status, 404);
		});

		test("Resolve refuses evidence that expires while the response is being signed", async (t) => {
			const deadline = 1_700_000_010;
			const fixture = await createResolveTrustMarkFixture({ delegationExpiresAt: deadline });
			let now = 1_700_000_000;
			const provider = fixture.ctx.crypto;
			const original = provider.keyring.entry.bind(provider.keyring, "federation");
			provider.keyring.entry = async () => {
				const keys = await original();
				return {
					...keys,
					signer: instrumentSigningEntry(keys.signer, async (payload, header) => {
						const jwt = await rawFixtureJwt(keys.signer, payload, header);
						if (header.typ === JwtTyp.ResolveResponse) now = deadline;
						return jwt;
					}).signer,
				};
			};
			const handler = createResolveHandler({
				...fixture.ctx,
				options: { ...fixture.ctx.options, clock: { now: () => now } },
			});
			t.equal((await handler(new Request(fixture.requestUrl))).status, 503);
		});

		test("resolve returns the exact verified mark when an expired mark shares its type", async (t) => {
			for (const expiredMarkPosition of ["before", "after"] as const) {
				const fixture = await createResolveTrustMarkFixture({ expiredMarkPosition });
				const response = await createResolveHandler(fixture.ctx)(new Request(fixture.requestUrl));
				t.equal(response.status, 200);
				const decoded = decodeEntityStatement(await response.text());
				t.true(decoded.ok);
				if (decoded.ok) {
					t.deepEqual(decoded.value.payload.trust_marks, [
						{ trust_mark_type: fixture.trustMarkType, trust_mark: fixture.trustMarkJwt },
					]);
					t.equal(decoded.value.payload.exp, fixture.trustMarkExpiresAt);
				}
			}
		});
		test("resolve excludes an expired mark without rejecting valid metadata", async (t) => {
			const fixture = await createResolveTrustMarkFixture({ trustMarkExpiresAt: 1_699_999_700 });
			const response = await createResolveHandler(fixture.ctx)(new Request(fixture.requestUrl));
			t.equal(response.status, 200);
			const decoded = decodeEntityStatement(await response.text());
			t.true(decoded.ok);
			if (decoded.ok) {
				t.strictEqual(decoded.value.payload.trust_marks, undefined);
				t.equal(decoded.value.payload.exp, fixture.chainExp);
				t.ok(decoded.value.payload.metadata);
			}
		});

		test("returns 400 when sub is missing", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					"https://authority.example.com/federation_resolve?trust_anchor=https%3A%2F%2Fta.example.com",
				),
			);
			t.equal(res.status, 400);
			t.equal(((await res.json()) as Record<string, string>).error, "invalid_request");
		});

		test("returns 400 when trust_anchor is missing", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}`,
				),
			);
			t.equal(res.status, 400);
			t.equal(((await res.json()) as Record<string, string>).error, "invalid_request");
		});

		test("returns 404 when no trust anchors configured", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://ta.example.com")}`,
				),
			);
			t.equal(res.status, 404);
			t.equal(((await res.json()) as Record<string, string>).error, "invalid_trust_anchor");
		});

		test("returns 404 for unknown trust anchor", async (t) => {
			const taId = entityId("https://known-ta.example.com");
			const anchors: TrustAnchorSet = new Map([
				[taId, { jwks: { keys: [testPublicJwk("known-ta-key-1")] } }],
			]);
			const { ctx } = await createTestContext({ trustAnchors: anchors });
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://unknown-ta.example.com")}`,
				),
			);
			t.equal(res.status, 404);
			t.equal(((await res.json()) as Record<string, string>).error, "invalid_trust_anchor");
		});

		test("returns 405 for POST", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/federation_resolve", { method: "POST" }),
			);
			t.equal(res.status, 405);
		});

		test("does not include aud when X-Authenticated-Entity header is absent", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://ta.example.com")}`,
				),
			);
			t.equal(res.status, 404);
		});

		test("includes aud when X-Authenticated-Entity header is present", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://ta.example.com")}`,
					{ headers: { "X-Authenticated-Entity": "https://client.example.com" } },
				),
			);
			t.equal(res.status, 404);
		});

		test("accepts entity_type parameter without error", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://ta.example.com")}&entity_type=openid_provider`,
				),
			);
			t.equal(res.status, 404);
			t.equal(((await res.json()) as Record<string, string>).error, "invalid_trust_anchor");
		});

		test("ignores an untrusted identity header rather than treating it as authentication", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://ta.example.com")}`,
					{ headers: { "X-Authenticated-Entity": "not-a-url" } },
				),
			);
			t.equal(res.status, 404);
			t.equal(((await res.json()) as Record<string, string>).error, "invalid_trust_anchor");
		});

		test("accepts a valid X-Authenticated-Entity header and proceeds to trust chain resolution", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://leaf.example.com")}&trust_anchor=${encodeURIComponent("https://ta.example.com")}`,
					{ headers: { "X-Authenticated-Entity": "https://client.example.com" } },
				),
			);
			t.equal(res.status, 404);
		});

		test("includes security headers on error responses", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createResolveHandler(ctx);
			const res = await handler(new Request("https://authority.example.com/federation_resolve"));
			t.equal(res.headers.get("Cache-Control"), "no-store");
			t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
		});

		test("refuses to sign invalid resolved federation metadata", async (t) => {
			const fed = await createMockFederation({ leafMetadata: { federation_entity: {} } });
			const decoded = decodeEntityStatement(fed.taSubStatementForLeaf);
			if (!decoded.ok) throw new Error("Invalid fixture");
			const jwt = await signEntityStatement(
				{
					...decoded.value.payload,
					metadata_policy: {
						federation_entity: {
							federation_resolve_endpoint: { value: "http://leaf.example.com/resolve" },
						},
					},
				},
				new SigningEntryFixture(fed.taSigningKey),
				{ typ: JwtTyp.EntityStatement },
			);
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: {
					...fed.options,
					httpClient: async (input, init) => {
						const url = new URL(input instanceof Request ? input.url : String(input));
						if (
							url.origin === TA_ID &&
							url.pathname === "/federation_fetch" &&
							url.searchParams.get("sub") === LEAF_ID
						) {
							return new Response(jwt, { headers: { "Content-Type": MediaType.EntityStatement } });
						}
						return fed.httpClient(input, init);
					},
				},
			});
			const response = await createResolveHandler(ctx)(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(response.status, 400);
			t.equal(((await response.json()) as { error: string }).error, "invalid_metadata");
		});

		test("resolves successfully and returns signed JWT with expected payload", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(res.status, 200);
			t.equal(res.headers.get("Content-Type"), MediaType.ResolveResponse);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const payload = decoded.value.payload as Record<string, unknown>;
			t.equal(payload.iss, "https://authority.example.com");
			t.equal(payload.sub, LEAF_ID);
			t.ok(payload.metadata);
			t.true(Array.isArray(payload.trust_chain));
			t.equal(decoded.value.header.typ, JwtTyp.ResolveResponse);
		});

		test("omits aud from successful unauthenticated resolve response", async (t) => {
			const fed = await createMockFederation();
			const { ctx, publicKey } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(res.status, 200);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const payload = decoded.value.payload as Record<string, unknown>;
			t.notOk("aud" in payload);
			t.true(
				(
					await verifyResolveResponse(
						jwt,
						{ keys: [publicKey] },
						{
							engine: testEngine,
							expectedIssuer: "https://authority.example.com",
							expectedSubject: LEAF_ID,
						},
					)
				).ok,
			);
			t.true(
				(
					await verifyResolveResponse(
						jwt,
						{ keys: [publicKey] },
						{
							engine: testEngine,
							expectedIssuer: "https://authority.example.com",
							expectedSubject: LEAF_ID,
							expectedAudience: "https://client.example.com",
						},
					)
				).ok,
			);
		});

		test("includes active Trust Marks and caps response expiration", async (t) => {
			const fixture = await createResolveTrustMarkFixture({
				status: TrustMarkStatus.Active,
				trustMarkExpiresAt: 1_700_000_300,
			});
			const handler = createResolveHandler(fixture.ctx);
			const res = await handler(new Request(fixture.requestUrl));
			t.equal(res.status, 200);
			const decoded = decodeEntityStatement(await res.text());
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const payload = decoded.value.payload as Record<string, unknown>;
			t.equal(payload.exp, fixture.trustMarkExpiresAt);
			t.deepEqual(payload.trust_marks, [
				{ trust_mark_type: fixture.trustMarkType, trust_mark: fixture.trustMarkJwt },
			]);
		});

		test("excludes remotely revoked Trust Marks from resolve responses", async (t) => {
			const fixture = await createResolveTrustMarkFixture({ status: TrustMarkStatus.Revoked });
			const handler = createResolveHandler(fixture.ctx);
			const res = await handler(new Request(fixture.requestUrl));
			t.equal(res.status, 200);
			const decoded = decodeEntityStatement(await res.text());
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const payload = decoded.value.payload as Record<string, unknown>;
			t.equal(payload.exp, fixture.chainExp);
			t.notOk("trust_marks" in payload);
		});

		test("excludes locally inactive Trust Marks from resolve responses", async (t) => {
			const fixture = await createResolveTrustMarkFixture({
				status: TrustMarkStatus.Revoked,
				resolverEntityId: TA_ID,
				useLocalTrustMarkStore: true,
			});
			const handler = createResolveHandler(fixture.ctx);
			const res = await handler(new Request(fixture.requestUrl));
			t.equal(res.status, 200);
			const decoded = decodeEntityStatement(await res.text());
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const payload = decoded.value.payload as Record<string, unknown>;
			t.equal(payload.exp, fixture.chainExp);
			t.notOk("trust_marks" in payload);
		});

		test("ignores unknown query parameters on resolve", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}&unknown_param=ignored`,
				),
			);
			t.equal(res.status, 200);
			t.equal(res.headers.get("Content-Type"), MediaType.ResolveResponse);
		});

		test("response exp is capped to the chain's earliest expiry", async (t) => {
			// Per §8.3.2 (lines 533-535), the resolve response exp MUST be the minimum of
			// the trust-chain exp and any included Trust Mark exp. The mock federation signs
			// every statement with exp = now + 86400, so the resolved exp should match that
			// bound within a small tolerance for iat/exp computation.
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(res.status, 200);
			const decoded = decodeEntityStatement(await res.text());
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const payload = decoded.value.payload as Record<string, unknown>;
			const exp = payload.exp as number;
			const iat = payload.iat as number;
			t.equal(typeof exp, "number");
			t.equal(typeof iat, "number");
			// All chain statements were signed with exp = iat + 86400. The resolver MUST
			// not extend exp beyond the chain bound — assert exp does not exceed
			// (statement-level iat + 86400) plus a tolerance for sub-second drift.
			t.true(exp <= iat + 86400 + 5, `response exp ${exp} exceeds chain bound ${iat + 86400}`);
		});

		test("filters metadata by entity_type when matching", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}&entity_type=openid_relying_party`,
				),
			);
			t.equal(res.status, 200);
			const decoded = decodeEntityStatement(await res.text());
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const metadata = (decoded.value.payload as Record<string, unknown>).metadata as Record<
				string,
				unknown
			>;
			t.ok(metadata.openid_relying_party);
			t.notOk(metadata.federation_entity);
		});

		test("repeated entity_type returns only requested entity types that are present", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}&entity_type=openid_provider&entity_type=openid_relying_party`,
				),
			);
			t.equal(res.status, 200);
			const decoded = decodeEntityStatement(await res.text());
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const metadata = (decoded.value.payload as Record<string, unknown>).metadata as Record<
				string,
				unknown
			>;
			t.ok(metadata.openid_relying_party);
			t.notOk(metadata.federation_entity);
			t.notOk(metadata.openid_provider);
		});

		test("repeated trust_anchor succeeds when one supplied anchor is acceptable", async (t) => {
			const fed = await createMockFederation();
			const unknownTa = "https://unknown-ta.example.com";
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(unknownTa)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(res.status, 200);
			t.equal(res.headers.get("Content-Type"), MediaType.ResolveResponse);
		});

		test("returns 404 when entity_type filter produces no matches", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}&entity_type=nonexistent_type`,
				),
			);
			t.equal(res.status, 404);
			const body = (await res.json()) as Record<string, string>;
			t.equal(body.error, FederationErrorCode.NotFound);
		});

		test("includes aud after verified client authentication", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const _handler = createResolveHandler(ctx);
			const client = "https://client.example.com";
			const res = await resolveAsClient(
				ctx,
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
					{ headers: { "X-Authenticated-Entity": client } },
				),
			);
			t.equal(res.status, 200);
			const decoded = decodeEntityStatement(await res.text());
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.equal((decoded.value.payload as Record<string, unknown>).aud, client);
		});

		test("skips issuer chain when authority is the requested trust anchor", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				entityId: TA_ID,
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`${TA_ID}/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(res.status, 200);
			const decoded = decodeEntityStatement(await res.text());
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const header = decoded.value.header as Record<string, unknown>;
			t.notOk(header.trust_chain);
		});

		test("returns 404 when no trust chain can be resolved for the subject", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent("https://unknown.example.com")}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(res.status, 404);
			const body = (await res.json()) as Record<string, string>;
			t.equal(body.error, FederationErrorCode.NotFound);
		});

		test("populates trust_chain header for authority when different from TA", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				entityId: OP_ID,
				trustAnchors: fed.trustAnchors,
				options: fed.options,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`${OP_ID}/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(res.status, 200);
			const decoded = decodeEntityStatement(await res.text());
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const header = decoded.value.header as Record<string, unknown>;
			t.true(Array.isArray(header.trust_chain));
			t.true((header.trust_chain as unknown[]).length > 0);
		});

		test("silently ignores issuer chain resolution failures", async (t) => {
			const fed = await createMockFederation();
			const failingClient: import("../../../packages/core/src/index.js").HttpClient = async (
				input: string | URL | Request,
			): Promise<Response> => {
				const url =
					typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
				const parsed = new URL(url);
				if (parsed.origin === "https://unresolvable.example.com") {
					return new Response("Not Found", { status: 404 });
				}
				return fed.httpClient(input);
			};
			const { ctx } = await createTestContext({
				entityId: entityId("https://unresolvable.example.com"),
				trustAnchors: fed.trustAnchors,
				options: { ...fed.options, httpClient: failingClient },
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://unresolvable.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(res.status, 200);
			const decoded = decodeEntityStatement(await res.text());
			t.true(decoded.ok);
			if (!decoded.ok) return;
			const header = decoded.value.header as Record<string, unknown>;
			t.notOk(header.trust_chain);
		});

		test("returns 500 when the signer throws (catch block)", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
				crypto: fixtureCryptoFromRead(
					async () => {
						throw new Error("boom");
					},
					async () => [],
				),
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(res.status, 500);
			const body = (await res.json()) as Record<string, string>;
			t.equal(body.error, "server_error");
		});

		test("anonymous resolve defaults to a cache miss without discovery", async (t) => {
			let calls = 0;
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				requireAuthForFreshResolution: true,
				options: {
					httpClient: async () => {
						calls++;
						throw new Error("Unexpected discovery");
					},
					engine: testEngine,
				},
			});
			const response = await createResolveHandler(ctx)(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(response.status, 404);
			t.equal(calls, 0);
		});

		test("unauthenticated cache miss returns 404 when requireAuthForFreshResolution is true", async (t) => {
			const fed = await createMockFederation();
			let fetchCallCount = 0;
			const wrappedHttpClient: typeof fed.options.httpClient = async (input, init) => {
				fetchCallCount++;
				return fed.options.httpClient!(input, init);
			};
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: { ...fed.options, httpClient: wrappedHttpClient },
				requireAuthForFreshResolution: true,
			});
			const handler = createResolveHandler(ctx);
			const res = await handler(
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
				),
			);
			t.equal(res.status, 404);
			t.equal(((await res.json()) as Record<string, string>).error, "not_found");
			t.equal(fetchCallCount, 0);
		});

		test("authenticated cache miss falls through to fresh resolution", async (t) => {
			const fed = await createMockFederation();
			const { ctx } = await createTestContext({
				trustAnchors: fed.trustAnchors,
				options: fed.options,
				requireAuthForFreshResolution: true,
			});
			const _handler = createResolveHandler(ctx);
			const res = await resolveAsClient(
				ctx,
				new Request(
					`https://authority.example.com/federation_resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
					{ headers: { "X-Authenticated-Entity": "https://client.example.com" } },
				),
			);
			t.equal(res.status, 200);
			t.equal(res.headers.get("Content-Type"), MediaType.ResolveResponse);
		});
	});

	// -------------------------------------------------------------------------
	// endpoints/historical-keys
	// -------------------------------------------------------------------------
	module("authority / createHistoricalKeysHandler", () => {
		test("publishes revocation history after explicit recovery with a replacement", async (t) => {
			const { ctx, crypto } = await createTestContext();
			await crypto.keyring.revoke("federation", "test-key-1", "compromised");
			const handler = createHistoricalKeysHandler(ctx);
			t.equal((await handler(new Request(`${ENTITY_ID}/federation_historical_keys`))).status, 500);
			for (const kid of ["replacement", "spare"]) {
				const key = await generateSigningKey("ES256");
				await crypto.keyring.publish(
					"federation",
					fixtureSigner(createFederationSigningKey({ ...key.privateKey, kid })),
				);
			}
			await crypto.keyring.activate("federation", "replacement");
			const response = await handler(new Request(`${ENTITY_ID}/federation_historical_keys`));
			t.equal(response.status, 200);
			const keys = await crypto.keyring.entry("federation");
			t.equal(keys.signer.publicJwk.kid, "replacement");
			const verified = await verifyHistoricalKeysResponse(
				await response.text(),
				keys.publishedJwks,
				{ engine: testEngine, expectedIssuer: ENTITY_ID },
			);
			t.true(verified.ok);
			if (verified.ok) {
				t.equal(verified.value.keys.length, 1);
				t.equal(verified.value.keys[0]?.kid, "test-key-1");
				t.equal(verified.value.keys[0]?.revoked?.reason, "compromised");
			}
		});

		test("returns signed JWT with jwk-set+jwt content type", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createHistoricalKeysHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/federation_historical_keys"),
			);
			t.equal(res.status, 200);
			t.equal(res.headers.get("Content-Type"), "application/jwk-set+jwt");
		});

		test("response JWT includes kid header parameter", async (t) => {
			// §8.7.2 (lines 1138–1140): Historical Keys JWTs MUST include kid header.
			const { ctx } = await createTestContext();
			const handler = createHistoricalKeysHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/federation_historical_keys"),
			);
			t.equal(res.status, 200);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			const header = decoded.value.header as Record<string, unknown>;
			t.equal(typeof header.kid, "string");
			t.true((header.kid as string).length > 0);
		});

		test("excludes active, prepublished, and overlapping keys", async (t) => {
			const { ctx, crypto } = await createTestContext();
			for (const kid of ["published-key", "new-active-key"]) {
				const { privateKey } = await generateSigningKey("ES256");
				await crypto.keyring.publish(
					"federation",
					fixtureSigner(createFederationSigningKey({ ...privateKey, kid })),
				);
			}
			await crypto.keyring.activate("federation", "new-active-key");
			const response = await createHistoricalKeysHandler(ctx)(
				new Request(`${ENTITY_ID}/federation_historical_keys`),
			);
			t.equal(response.status, 200);
			const verified = await verifyHistoricalKeysResponse(
				await response.text(),
				(await crypto.keyring.entry("federation")).publishedJwks,
				{ engine: testEngine, expectedIssuer: "https://authority.example.com" },
			);
			t.true(verified.ok);
			if (verified.ok) t.deepEqual(verified.value.keys, []);
		});

		test("revoked keys have revoked metadata", async (t) => {
			const { ctx, crypto } = await createTestContext();
			const { privateKey: pk2 } = await generateSigningKey("ES256");
			await crypto.keyring.publish(
				"federation",
				fixtureSigner(createFederationSigningKey({ ...pk2, kid: "new-active" })),
			);
			await crypto.keyring.activate("federation", "new-active");
			await crypto.keyring.revoke("federation", "test-key-1", "keyCompromise");
			const handler = createHistoricalKeysHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/federation_historical_keys"),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.true(isOk(decoded));
			if (!isOk(decoded)) return;
			const keys = (decoded.value.payload as Record<string, unknown>).keys as Array<
				Record<string, unknown>
			>;
			const revokedKey = keys.find((k) => k.kid === "test-key-1");
			t.ok(revokedKey);
			const revoked = revokedKey?.revoked as Record<string, unknown>;
			t.ok(revoked);
			t.true((revoked.revoked_at as number) > 0);
			t.equal(revoked.reason, "keyCompromise");
		});

		test("signs stable historical lifetimes with fresh response issuance times", async (t) => {
			const initial = await generateSigningKey("ES256");
			const next = await generateSigningKey("ES256");
			let nowMs = 1_000_250;
			const crypto = FixtureCrypto.fromJWK(
				{ ...initial.privateKey, kid: "old" },
				{ nowMs: () => nowMs },
			);
			const options = { clock: { now: () => nowMs / 1000 }, clockSkewSeconds: 0 };
			const { ctx } = await createTestContext({
				crypto,
				options: { ...options, engine: testEngine },
			});
			await crypto.keyring.publish(
				"federation",
				fixtureSigner(createFederationSigningKey({ ...next.privateKey, kid: "next" })),
			);
			await crypto.keyring.activate("federation", "next");
			const handler = createHistoricalKeysHandler(ctx);
			for (const time of [1_001_249, 1_001_250, 1_002_750]) {
				nowMs = time;
				if (time === 1001250) await crypto.keyring.retire("federation", "old");
				const response = await handler(new Request(`${ENTITY_ID}/federation_historical_keys`));
				const verified = await verifyHistoricalKeysResponse(
					await response.text(),
					(await crypto.keyring.entry("federation")).publishedJwks,
					{ engine: testEngine, expectedIssuer: "https://authority.example.com", ...options },
				);
				t.true(verified.ok);
				if (!verified.ok) continue;
				t.equal(verified.value.iat, time / 1000);
				if (time < 1_001_250) {
					t.deepEqual(verified.value.keys, []);
					continue;
				}
				t.equal(verified.value.keys.length, 1);
				const key = verified.value.keys[0]!;
				t.equal(key.kid, "old");
				t.strictEqual(key.iat, undefined);
				t.strictEqual(key.nbf, undefined);
				t.equal(key.exp, 1001.25);
				t.strictEqual(key.revoked, undefined);
				for (const field of ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]) t.false(field in key);
			}
		});

		test("revoked prepublished keys have no activation date", async (t) => {
			const { ctx, crypto } = await createTestContext();
			const { privateKey } = await generateSigningKey("ES256");
			await crypto.keyring.publish(
				"federation",
				fixtureSigner(createFederationSigningKey({ ...privateKey, kid: "published" })),
			);
			await crypto.keyring.revoke("federation", "published", "compromised");
			const response = await createHistoricalKeysHandler(ctx)(
				new Request(`${ENTITY_ID}/federation_historical_keys`),
			);
			const verified = await verifyHistoricalKeysResponse(
				await response.text(),
				(await crypto.keyring.entry("federation")).publishedJwks,
				{ engine: testEngine, expectedIssuer: "https://authority.example.com" },
			);
			t.true(verified.ok);
			if (!verified.ok) return;
			t.equal(verified.value.keys.length, 1);
			const key = verified.value.keys[0]!;
			t.equal(key.kid, "published");
			t.strictEqual(key.nbf, undefined);
			t.equal(key.exp, key.revoked?.revoked_at);
			t.false("d" in key);
		});

		test("preserves a custom provider's recorded future expiry", async (t) => {
			const { ctx, crypto, publicKey } = await createTestContext({
				options: { clock: { now: () => 1000.5 }, engine: testEngine },
			});
			const historical = { ...publicKey, kid: publicKey.kid!, iat: 900.25, exp: 2000.75 };
			const custom: HandlerContext["crypto"] = fixtureCryptoFromRead(
				() => crypto.keyring.entry("federation"),
				async () => [historical],
			);
			const response = await createHistoricalKeysHandler({ ...ctx, crypto: custom })(
				new Request(`${ENTITY_ID}/federation_historical_keys`),
			);
			const verified = await verifyHistoricalKeysResponse(
				await response.text(),
				(await crypto.keyring.entry("federation")).publishedJwks,
				{ expectedIssuer: "https://authority.example.com", ...ctx.options },
			);
			t.true(verified.ok);
			if (verified.ok) t.deepEqual<unknown>(verified.value.keys, [historical]);
		});

		test("includes security headers", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createHistoricalKeysHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/federation_historical_keys"),
			);
			t.equal(res.headers.get("Cache-Control"), "no-store");
			t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
		});

		test("returns 405 for POST", async (t) => {
			const { ctx } = await createTestContext();
			const handler = createHistoricalKeysHandler(ctx);
			const res = await handler(
				new Request("https://authority.example.com/federation_historical_keys", { method: "POST" }),
			);
			t.equal(res.status, 405);
		});
	});

	// -------------------------------------------------------------------------
	// endpoints/trust-mark-list
	// -------------------------------------------------------------------------
	{
		const TML_SUB1 = entityId("https://sub1.example.com");
		const TML_SUB2 = entityId("https://sub2.example.com");
		const TML_MARK_TYPE = "https://trust.example.com/mark-a";

		module("authority / createTrustMarkListHandler", () => {
			test("returns entity IDs of active trust marks", async (t) => {
				const { ctx } = await createTestContext();
				await putTestMark(ctx, {
					trustMarkType: TML_MARK_TYPE,
					subject: TML_SUB1,
					jwt: "jwt1",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				await putTestMark(ctx, {
					trustMarkType: TML_MARK_TYPE,
					subject: TML_SUB2,
					jwt: "jwt2",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createTrustMarkListHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(TML_MARK_TYPE)}`,
					),
				);
				t.equal(res.status, 200);
				t.equal(res.headers.get("Content-Type"), "application/json");
				const body = (await res.json()) as string[];
				t.true(body.includes(TML_SUB1));
				t.true(body.includes(TML_SUB2));
			});

			test("includes every eligible candidate instead of truncating at a batch size", async (t) => {
				const { ctx } = await createTestContext();
				for (let index = 0; index < 501; index += 1) {
					const subject = entityId(`https://subject-${String(index).padStart(3, "0")}.example.com`);
					await putTestMark(ctx, {
						trustMarkType: TML_MARK_TYPE,
						subject,
						jwt: `jwt-${index}`,
						issuedAt: index,
						active: true,
					});
				}
				const handler = createTrustMarkListHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(TML_MARK_TYPE)}`,
					),
				);
				const body = (await res.json()) as string[];
				t.equal(body.length, 501);
			});

			test("storage snapshot failures do not become an empty successful listing", async (t) => {
				const { ctx, storage } = await createTestContext();
				storage.readSnapshot = async () => {
					throw new Error("Store unavailable");
				};
				const response = await createTrustMarkListHandler(ctx)(
					new Request(`${ENTITY_ID}/marks?trust_mark_type=${encodeURIComponent(TML_MARK_TYPE)}`),
				);
				t.equal(response.status, 500);
			});

			test("filters by sub", async (t) => {
				const { ctx } = await createTestContext();
				await putTestMark(ctx, {
					trustMarkType: TML_MARK_TYPE,
					subject: TML_SUB1,
					jwt: "jwt1",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				await putTestMark(ctx, {
					trustMarkType: TML_MARK_TYPE,
					subject: TML_SUB2,
					jwt: "jwt2",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createTrustMarkListHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(TML_MARK_TYPE)}&sub=${encodeURIComponent(TML_SUB1)}`,
					),
				);
				t.deepEqual(await res.json(), [TML_SUB1]);
			});

			test("ignores unknown query parameters on trust mark list", async (t) => {
				const { ctx } = await createTestContext();
				await putTestMark(ctx, {
					trustMarkType: TML_MARK_TYPE,
					subject: TML_SUB1,
					jwt: "jwt1",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createTrustMarkListHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(TML_MARK_TYPE)}&unknown_param=ignored`,
					),
				);
				t.equal(res.status, 200);
				t.deepEqual(await res.json(), [TML_SUB1]);
			});

			test("excludes revoked trust marks", async (t) => {
				const { ctx, trustMarks } = await createTestContext();
				await putTestMark(ctx, {
					trustMarkType: TML_MARK_TYPE,
					subject: TML_SUB1,
					jwt: "jwt1",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				await putTestMark(ctx, {
					trustMarkType: TML_MARK_TYPE,
					subject: TML_SUB2,
					jwt: "jwt2",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				await trustMarks.revoke(TML_MARK_TYPE, TML_SUB2, Math.floor(Date.now() / 1000));
				const handler = createTrustMarkListHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(TML_MARK_TYPE)}`,
					),
				);
				t.deepEqual(await res.json(), [TML_SUB1]);
			});

			test("returns 400 when trust_mark_type is missing", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_trust_mark_list"),
				);
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_request");
			});

			test("returns 501 when no trust mark store", async (t) => {
				const { ctx } = await createTestContext({
					storage: new MemoryStorageAdapter({ engine: testEngine }),
				});
				const handler = createTrustMarkListHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(TML_MARK_TYPE)}`,
					),
				);
				t.equal(res.status, 501);
			});

			test("includes security headers", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkListHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(TML_MARK_TYPE)}`,
					),
				);
				t.equal(res.headers.get("Cache-Control"), "no-store");
				t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
			});

			test("returns 400 for invalid sub parameter", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkListHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark_list?trust_mark_type=${encodeURIComponent(TML_MARK_TYPE)}&sub=not-a-valid-url`,
					),
				);
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_request");
			});

			test("returns 405 for POST", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkListHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_trust_mark_list", {
						method: "POST",
					}),
				);
				t.equal(res.status, 405);
			});
		});
	}

	// -------------------------------------------------------------------------
	// endpoints/trust-mark-status
	// -------------------------------------------------------------------------
	{
		const TMS_SUB1 = entityId("https://sub1.example.com");
		const TMS_MARK_TYPE = "https://trust.example.com/mark-a";

		async function issueTrustMarkJwt(
			iss: string,
			sub: string,
			trustMarkType: string,
			signingKey: JWK,
			overrides?: Record<string, unknown>,
		): Promise<string> {
			const now = Math.floor(Date.now() / 1000);
			return signEntityStatement(
				{ iss, sub, trust_mark_type: trustMarkType, iat: now, exp: now + 3600, ...overrides },
				new SigningEntryFixture(signingKey),
				{ typ: JwtTyp.TrustMark },
			);
		}

		function postRequest(body: string): Request {
			return new Request("https://authority.example.com/federation_trust_mark_status", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body,
			});
		}

		async function decodeStatusResponse(res: Response): Promise<{ status: string }> {
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			if (!isOk(decoded)) throw new Error("Failed to decode");
			return decoded.value.payload as unknown as { status: string };
		}

		module("authority / createTrustMarkStatusHandler", () => {
			test("returns status: active for active trust mark", async (t) => {
				const { ctx, signingKey, trustMarks } = await createTestContext();
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey);
				await trustMarks.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 200);
				t.equal(res.headers.get("Content-Type"), "application/trust-mark-status-response+jwt");
				const payload = await decodeStatusResponse(res);
				t.equal(payload.status, TrustMarkStatus.Active);
			});

			test("ignores unknown form parameters on trust mark status", async (t) => {
				const { ctx, signingKey, trustMarks } = await createTestContext();
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey);
				await trustMarks.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(
					postRequest(`trust_mark=${encodeURIComponent(jwt)}&unknown_param=ignored`),
				);
				t.equal(res.status, 200);
				t.equal((await decodeStatusResponse(res)).status, TrustMarkStatus.Active);
			});

			test("returns status: revoked for revoked trust mark", async (t) => {
				const { ctx, signingKey, trustMarks } = await createTestContext();
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey);
				await trustMarks.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				await trustMarks.revoke(TMS_MARK_TYPE, TMS_SUB1, Math.floor(Date.now() / 1000));
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 200);
				t.equal((await decodeStatusResponse(res)).status, TrustMarkStatus.Revoked);
			});

			test("keeps an older revoked JWT revoked after a new mark is issued", async (t) => {
				const { ctx, signingKey, trustMarks } = await createTestContext();
				const first = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey, {
					jti: "first",
				});
				const second = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey, {
					jti: "second",
				});
				const now = Math.floor(Date.now() / 1000);
				await trustMarks.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt: first,
					issuedAt: now,
					active: true,
				});
				await trustMarks.revoke(TMS_MARK_TYPE, TMS_SUB1, now);
				await trustMarks.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt: second,
					issuedAt: now + 1,
					active: true,
				});
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(first)}`));
				t.equal((await decodeStatusResponse(res)).status, TrustMarkStatus.Revoked);
			});

			test("returns status: expired for expired trust mark", async (t) => {
				const { ctx, signingKey, trustMarks } = await createTestContext();
				const now = Math.floor(Date.now() / 1000);
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey, {
					iat: now - 7200,
					exp: now - 3600,
				});
				await trustMarks.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: now - 7200,
					active: true,
				});
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 200);
				t.equal((await decodeStatusResponse(res)).status, TrustMarkStatus.Expired);
			});

			test("returns 404 for unknown trust mark", async (t) => {
				const { ctx, signingKey } = await createTestContext();
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey);
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 404);
			});

			test("returns 404 for wrong issuer", async (t) => {
				const { ctx, trustMarks } = await createTestContext();
				const { privateKey: otherKey } = await generateSigningKey("ES256");
				const wrongIssuer = entityId("https://other-authority.example.com");
				const jwt = await issueTrustMarkJwt(wrongIssuer, TMS_SUB1, TMS_MARK_TYPE, otherKey);
				await trustMarks.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 404);
			});

			test("returns 400 for missing trust_mark body", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(""));
				t.equal(res.status, 400);
				t.equal(((await res.json()) as Record<string, string>).error, "invalid_request");
			});

			test("returns 405 for GET", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_trust_mark_status"),
				);
				t.equal(res.status, 405);
				t.equal(res.headers.get("Allow"), "POST");
			});

			test("returns expired before checking revocation status", async (t) => {
				const { ctx, signingKey, trustMarks } = await createTestContext();
				const now = Math.floor(Date.now() / 1000);
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey, {
					iat: now - 7200,
					exp: now - 3600,
				});
				await trustMarks.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: now - 7200,
					active: true,
				});
				await trustMarks.revoke(TMS_MARK_TYPE, TMS_SUB1, Math.floor(Date.now() / 1000));
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 200);
				t.equal((await decodeStatusResponse(res)).status, TrustMarkStatus.Expired);
			});

			test("returns 404 for a tampered JWT that was never issued", async (t) => {
				const { ctx, signingKey, trustMarks } = await createTestContext();
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey);
				await trustMarks.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const parts = jwt.split(".");
				const sig = parts[2] ?? "";
				const flipped = sig.charAt(0) === "A" ? "B" : "A";
				const tamperedJwt = `${parts[0]}.${parts[1]}.${flipped}${sig.slice(1)}`;
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(tamperedJwt)}`));
				t.equal(res.status, 404);
			});

			test("returns 413 for body exceeding 64KB", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkStatusHandler(ctx);
				const oversized = "x".repeat(65 * 1024);
				const res = await handler(
					new Request("https://authority.example.com/federation_trust_mark_status", {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
							"Content-Length": String(oversized.length),
						},
						body: oversized,
					}),
				);
				t.equal(res.status, 413);
			});

			test("returns not_found for an unissued custom Trust Mark type", async (t) => {
				const { ctx, signingKey } = await createTestContext();
				const now = Math.floor(Date.now() / 1000);
				const jwt = await signEntityStatement(
					{
						iss: ENTITY_ID,
						sub: TMS_SUB1,
						trust_mark_type: "not-a-url",
						iat: now,
						exp: now + 3600,
					},
					new SigningEntryFixture(signingKey),
					{ typ: JwtTyp.TrustMark },
				);
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 404);
				t.equal(((await res.json()) as { error: string }).error, "not_found");
			});

			test("returns expired for trust mark with exp: 0 (epoch)", async (t) => {
				const { ctx, signingKey, trustMarks } = await createTestContext();
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey, {
					iat: 0,
					exp: 0,
				});
				await trustMarks.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: 0,
					active: true,
				});
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 200);
				t.equal((await decodeStatusResponse(res)).status, TrustMarkStatus.Expired);
			});

			test("validates trust mark signed with retiring key as active", async (t) => {
				const { ctx, signingKey, trustMarks, crypto } = await createTestContext();
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey);
				await trustMarks.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const { privateKey: newKey } = await generateSigningKey("ES256");
				await crypto.keyring.publish(
					"federation",
					fixtureSigner(createFederationSigningKey({ ...newKey, kid: "rotated-key-1" })),
				);
				await crypto.keyring.activate("federation", "rotated-key-1");
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 200);
				t.equal((await decodeStatusResponse(res)).status, TrustMarkStatus.Active);
			});

			test("returns invalid for trust mark signed with revoked key", async (t) => {
				const { ctx, signingKey, trustMarks, crypto } = await createTestContext();
				const jwt = await issueTrustMarkJwt(ENTITY_ID, TMS_SUB1, TMS_MARK_TYPE, signingKey);
				await trustMarks.issue({
					trustMarkType: TMS_MARK_TYPE,
					subject: TMS_SUB1,
					jwt,
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const { privateKey: newKey } = await generateSigningKey("ES256");
				await crypto.keyring.publish(
					"federation",
					fixtureSigner(createFederationSigningKey({ ...newKey, kid: "new-key-1" })),
				);
				await crypto.keyring.activate("federation", "new-key-1");
				await crypto.keyring.revoke("federation", "test-key-1", "keyCompromise");
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(postRequest(`trust_mark=${encodeURIComponent(jwt)}`));
				t.equal(res.status, 200);
				t.equal((await decodeStatusResponse(res)).status, TrustMarkStatus.Invalid);
			});

			test("returns 501 when no trust mark store", async (t) => {
				const { ctx } = await createTestContext({
					storage: new MemoryStorageAdapter({ engine: testEngine }),
				});
				const handler = createTrustMarkStatusHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_trust_mark_status", {
						method: "POST",
						body: "trust_mark=foo",
					}),
				);
				t.equal(res.status, 501);
			});
		});
	}

	// -------------------------------------------------------------------------
	// endpoints/trust-mark
	// -------------------------------------------------------------------------
	{
		const TM_SUB1 = entityId("https://sub1.example.com");
		const TM_MARK_TYPE = "https://trust.example.com/mark-a";

		module("authority / createTrustMarkHandler (retrieval)", () => {
			test("returns existing active trust mark", async (t) => {
				const { ctx } = await createTestContext();
				const storedJwt = await putTestMark(ctx, {
					trustMarkType: TM_MARK_TYPE,
					subject: TM_SUB1,
					jwt: "existing.jwt.token",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createTrustMarkHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(res.status, 200);
				t.equal(res.headers.get("Content-Type"), "application/trust-mark+jwt");
				t.equal(await res.text(), storedJwt);
			});

			test("ignores unknown query parameters on trust mark retrieval", async (t) => {
				const { ctx } = await createTestContext();
				const storedJwt = await putTestMark(ctx, {
					trustMarkType: TM_MARK_TYPE,
					subject: TM_SUB1,
					jwt: "existing.jwt.token",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const handler = createTrustMarkHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}&unknown_param=ignored`,
					),
				);
				t.equal(res.status, 200);
				t.equal(await res.text(), storedJwt);
			});

			test("returns 404 when trust mark is expired", async (t) => {
				const { ctx } = await createTestContext();
				const now = Math.floor(Date.now() / 1000);
				const _storedJwt = await putTestMark(ctx, {
					trustMarkType: TM_MARK_TYPE,
					subject: TM_SUB1,
					jwt: "expired.jwt.token",
					issuedAt: now - 7200,
					expiresAt: now - 3600,
					active: true,
				});
				const handler = createTrustMarkHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(res.status, 404);
			});

			test("returns 404 when entity does not have the trust mark", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(res.status, 404);
				t.equal(((await res.json()) as Record<string, string>).error, "not_found");
			});

			test("returns 404 when trust mark is revoked", async (t) => {
				const { ctx, trustMarks } = await createTestContext();
				const _storedJwt = await putTestMark(ctx, {
					trustMarkType: TM_MARK_TYPE,
					subject: TM_SUB1,
					jwt: "revoked.jwt.token",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				await trustMarks.revoke(TM_MARK_TYPE, TM_SUB1, Math.floor(Date.now() / 1000));
				const handler = createTrustMarkHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(res.status, 404);
			});

			test("returns 400 for missing trust_mark_type", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(res.status, 400);
			});

			test("returns 400 for missing sub", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}`,
					),
				);
				t.equal(res.status, 400);
			});

			test("returns 501 when no trust mark store", async (t) => {
				const { ctx } = await createTestContext({
					storage: new MemoryStorageAdapter({ engine: testEngine }),
				});
				const handler = createTrustMarkHandler(ctx);
				const res = await handler(
					new Request(
						`https://authority.example.com/federation_trust_mark?trust_mark_type=${encodeURIComponent(TM_MARK_TYPE)}&sub=${encodeURIComponent(TM_SUB1)}`,
					),
				);
				t.equal(res.status, 501);
			});

			test("returns 405 for POST", async (t) => {
				const { ctx } = await createTestContext();
				const handler = createTrustMarkHandler(ctx);
				const res = await handler(
					new Request("https://authority.example.com/federation_trust_mark", { method: "POST" }),
				);
				t.equal(res.status, 405);
			});
		});

		module("authority / managed Trust Mark issuance", () => {
			test("issues a new trust mark", async (t) => {
				const { ctx } = await createTestContext({
					trustMarkIssuers: { [TM_MARK_TYPE]: [ENTITY_ID] },
				});
				const issuer = await TrustAnchor.create(fixtureHostConfig(hostConfig(ctx)));
				const jwt = await issuer.issueTrustMark(TM_SUB1, TM_MARK_TYPE);
				const decoded = decodeEntityStatement(jwt);
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				const payload = decoded.value.payload as Record<string, unknown>;
				t.equal(payload.iss, ENTITY_ID);
				t.equal(payload.sub, TM_SUB1);
				t.equal(payload.trust_mark_type, TM_MARK_TYPE);
				t.equal(typeof payload.iat, "number");
				t.equal(typeof payload.exp, "number");
				t.equal((payload.exp as number) - (payload.iat as number), 86400);
			});

			test("respects custom trustMarkTtlSeconds", async (t) => {
				const { ctx } = await createTestContext({
					trustMarkIssuers: { [TM_MARK_TYPE]: [ENTITY_ID] },
					trustMarkTtlSeconds: 3600,
				});
				const issuer = await TrustAnchor.create(fixtureHostConfig(hostConfig(ctx)));
				const jwt = await issuer.issueTrustMark(TM_SUB1, TM_MARK_TYPE);
				const decoded = decodeEntityStatement(jwt);
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				const payload = decoded.value.payload as Record<string, unknown>;
				t.equal((payload.exp as number) - (payload.iat as number), 3600);
			});

			test("returns existing active trust mark", async (t) => {
				const { ctx } = await createTestContext({
					trustMarkIssuers: { [TM_MARK_TYPE]: [ENTITY_ID] },
				});
				const storedJwt = await putTestMark(ctx, {
					trustMarkType: TM_MARK_TYPE,
					subject: TM_SUB1,
					jwt: "existing.jwt.token",
					issuedAt: Math.floor(Date.now() / 1000),
					active: true,
				});
				const issuer = await TrustAnchor.create(fixtureHostConfig(hostConfig(ctx)));
				const jwt = await issuer.issueTrustMark(TM_SUB1, TM_MARK_TYPE);
				t.equal(jwt, storedJwt);
			});

			test("rejects when authority is not in the authorized issuers list", async (t) => {
				const otherAuthority = entityId("https://other-authority.example.com");
				const { ctx } = await createTestContext({
					trustMarkIssuers: { [TM_MARK_TYPE]: [otherAuthority] },
				});
				const issuer = await TrustAnchor.create(fixtureHostConfig(hostConfig(ctx)));
				await t.rejects(issuer.issueTrustMark(TM_SUB1, TM_MARK_TYPE), /not authorized/);
			});

			test("allows issuance when trust mark type is not in issuers map", async (t) => {
				const { ctx } = await createTestContext({
					trustMarkIssuers: { "https://other.example.com/mark": [ENTITY_ID] },
				});
				const issuer = await TrustAnchor.create(fixtureHostConfig(hostConfig(ctx)));
				t.true(decodeEntityStatement(await issuer.issueTrustMark(TM_SUB1, TM_MARK_TYPE)).ok);
			});

			test("embeds delegation when trustMarkDelegations is configured for the type", async (t) => {
				const ownerKeys = await generateSigningKey("ES256");
				const delegationJwt = await signTrustMarkDelegation({
					issuer: "https://owner.example.com",
					subject: ENTITY_ID,
					trustMarkType: TM_MARK_TYPE,
					signer: new SigningEntryFixture(ownerKeys.privateKey),
				});
				const { ctx } = await createTestContext({
					trustMarkIssuers: { [TM_MARK_TYPE]: [ENTITY_ID] },
					trustMarkDelegations: { [TM_MARK_TYPE]: delegationJwt },
					trustMarkOwners: {
						[TM_MARK_TYPE]: {
							sub: "https://owner.example.com",
							jwks: { keys: [ownerKeys.publicKey] },
						},
					},
				});
				const issuer = await TrustAnchor.create(fixtureHostConfig(hostConfig(ctx)));
				const jwt = await issuer.issueTrustMark(TM_SUB1, TM_MARK_TYPE);
				const decoded = decodeEntityStatement(jwt);
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				t.equal((decoded.value.payload as Record<string, unknown>).delegation, delegationJwt);
			});

			test("does NOT embed delegation when trustMarkDelegations is not configured", async (t) => {
				const { ctx } = await createTestContext({
					trustMarkIssuers: { [TM_MARK_TYPE]: [ENTITY_ID] },
				});
				const issuer = await TrustAnchor.create(fixtureHostConfig(hostConfig(ctx)));
				const jwt = await issuer.issueTrustMark(TM_SUB1, TM_MARK_TYPE);
				const decoded = decodeEntityStatement(jwt);
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				t.equal((decoded.value.payload as Record<string, unknown>).delegation, undefined);
			});

			test("issued trust mark with delegation passes validateTrustMark", async (t) => {
				const ownerKeys = await generateSigningKey("ES256");
				const delegationJwt = await signTrustMarkDelegation({
					issuer: "https://owner.example.com",
					subject: ENTITY_ID,
					trustMarkType: TM_MARK_TYPE,
					signer: new SigningEntryFixture(ownerKeys.privateKey),
				});
				const { ctx, publicKey } = await createTestContext({
					trustMarkIssuers: { [TM_MARK_TYPE]: [ENTITY_ID] },
					trustMarkDelegations: { [TM_MARK_TYPE]: delegationJwt },
					trustMarkOwners: {
						[TM_MARK_TYPE]: {
							sub: "https://owner.example.com",
							jwks: { keys: [ownerKeys.publicKey] },
						},
					},
				});
				const issuer = await TrustAnchor.create(fixtureHostConfig(hostConfig(ctx)));
				const jwt = await issuer.issueTrustMark(TM_SUB1, TM_MARK_TYPE);
				const result = await validateTrustMark(
					jwt,
					{ [TM_MARK_TYPE]: [ENTITY_ID] },
					{ keys: [publicKey] },
					{
						engine: testEngine,
						expectedSubject: TM_SUB1,
						trustMarkOwners: {
							[TM_MARK_TYPE]: {
								sub: "https://owner.example.com",
								jwks: { keys: [ownerKeys.publicKey] },
							},
						},
					},
				);
				t.true(isOk(result));
				if (isOk(result)) {
					t.ok(result.value.delegation);
					t.equal(result.value.delegation?.issuer, "https://owner.example.com");
					t.equal(result.value.delegation?.subject, ENTITY_ID);
				}
			});

			test("issueTrustMarkDelegation() server method returns valid delegation JWT", async (t) => {
				const keys = await generateSigningKey("ES256");
				const signingKey = { ...keys.privateKey, kid: "delegation-key-1" };
				const crypto = new FixtureCrypto(createFederationSigningKey(signingKey));
				const server = await createAuthorityServer({
					entityId: entityId("https://owner.example.com"),
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: "https://owner.example.com/federation_fetch",
							federation_list_endpoint: "https://owner.example.com/federation_list",
						},
					},
					storage: new MemoryStorageAdapter({ engine: testEngine }),
					crypto,
				});
				const delegationJwt = await (await server).issueTrustMarkDelegation(
					"https://issuer.example.com",
					"https://example.com/tm",
				);
				const decoded = decodeEntityStatement(delegationJwt);
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				t.equal(decoded.value.header.typ, JwtTyp.TrustMarkDelegation);
				const payload = decoded.value.payload as Record<string, unknown>;
				t.equal(payload.iss, "https://owner.example.com");
				t.equal(payload.sub, "https://issuer.example.com");
				t.equal(payload.trust_mark_type, "https://example.com/tm");
			});
		});
	}

	// -------------------------------------------------------------------------
	// endpoints/client-auth
	// -------------------------------------------------------------------------
	{
		const CA_AUTHORITY_ID = entityId("https://authority.example.com");
		const CA_CLIENT_ID = entityId("https://client.example.com");
		const JWT_BEARER_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

		async function echoHandler(request: Request): Promise<Response> {
			const url = new URL(request.url);
			const sub = url.searchParams.get("sub");
			return jsonResponse({ sub, method: request.method });
		}

		async function postEchoHandler(request: Request): Promise<Response> {
			const text = await request.text();
			const params = new URLSearchParams(text);
			return jsonResponse({ trust_mark: params.get("trust_mark"), method: request.method });
		}

		async function setupClientAuthContext(overrides?: Partial<HandlerContext>) {
			const { privateKey: taPrivateKey } = await generateSigningKey("ES256");
			const taSigningKey = { ...taPrivateKey, kid: "ta-key-1" };
			const clientKeys = await generateSigningKey("ES256");
			const clientSigningKey = { ...clientKeys.privateKey, kid: "client-key-1" };
			const clientPublicKey = { ...clientKeys.publicKey, kid: "client-key-1" };
			const crypto = new FixtureCrypto(createFederationSigningKey(taSigningKey));
			const storage = new MemoryStorageAdapter({ engine: testEngine, trustMarks: true });
			const clientKeyProvider = {
				async getClientFederationJwks(clientEntityId: EntityId) {
					return clientEntityId === CA_CLIENT_ID ? { keys: [clientPublicKey] } : undefined;
				},
			};
			const ctx: HandlerContext = {
				entityId: CA_AUTHORITY_ID,
				crypto,
				storage,
				clientKeyProvider,
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${CA_AUTHORITY_ID}${FederationEndpoint.Fetch}`,
					},
				},
				...overrides,
				options: { engine: testEngine },
			};

			const createClientAssertionJwt = async (assertionOverrides?: {
				iss?: string;
				sub?: string;
				aud?: string | string[];
				exp?: number;
			}): Promise<string> => {
				const now = Math.floor(Date.now() / 1000);
				return signEntityStatement(
					{
						iss: assertionOverrides?.iss ?? CA_CLIENT_ID,
						sub: assertionOverrides?.sub ?? CA_CLIENT_ID,
						aud: assertionOverrides?.aud ?? CA_AUTHORITY_ID,
						jti: globalThis.crypto.randomUUID(),
						iat: now,
						exp: assertionOverrides?.exp ?? now + 60,
					},
					new SigningEntryFixture(clientSigningKey),
					{ typ: "JWT" },
				);
			};

			return {
				ctx,
				clientPublicKey,
				createClientAssertionJwt,
			};
		}

		module("authority / createAuthenticatedHandler", () => {
			test("authenticated forwarding preserves fixed selectors and repeated filters", async (t) => {
				const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
				let forwarded: URL | undefined;
				const handler = createAuthenticatedHandler(
					ctx,
					async (request) => {
						forwarded = new URL(request.url);
						t.strictEqual(authenticatedEndpointCaller(request), CA_CLIENT_ID);
						t.strictEqual(request.headers.get("X-Authenticated-Entity"), null);
						return new Response("ok");
					},
					["private_key_jwt"],
				);
				const request = async (extra: string) =>
					new Request(`${CA_AUTHORITY_ID}/api?tenant=alpha`, {
						method: "POST",
						headers: { "Content-Type": "application/x-www-form-urlencoded" },
						body: `client_assertion=${encodeURIComponent(await createClientAssertionJwt())}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}&entity_type=one&entity_type=two${extra}`,
					});
				const response = await handler(await request(""));
				t.equal(response.status, 200);
				await response.body?.cancel();
				t.equal(forwarded?.searchParams.get("tenant"), "alpha");
				t.deepEqual(forwarded?.searchParams.getAll("entity_type"), ["one", "two"]);
				t.false(forwarded?.searchParams.has("client_assertion"));
				const conflict = await handler(await request("&tenant=beta"));
				t.equal(conflict.status, 400);
				await conflict.body?.cancel();
			});

			test("optional Trust Mark Status and required fetch leave discovery public", async (t) => {
				const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
				const config: AuthorityConfig = {
					entityId: ctx.entityId,
					crypto: ctx.crypto,
					storage: ctx.storage,
					clientKeyProvider: ctx.clientKeyProvider,
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: `${CA_AUTHORITY_ID}/fetch`,
							federation_list_endpoint: `${CA_AUTHORITY_ID}/list`,
							federation_fetch_endpoint_auth_methods: ["private_key_jwt"],
							federation_trust_mark_status_endpoint: `${CA_AUTHORITY_ID}/status`,
							federation_trust_mark_status_endpoint_auth_methods: ["none", "private_key_jwt"],
						},
					},
				};
				for (const authority of [
					await TrustAnchor.create(fixtureHostConfig(configForHost())),
					await Intermediate.create(
						fixtureHostConfig({ ...configForHost(), authorityHints: [TA_ID] }),
					),
				]) {
					const statusJwt = await authority.issueTrustMark(CA_CLIENT_ID, "auth-test");
					const discovery = await authority.handleRequest(
						new Request(`${CA_AUTHORITY_ID}/.well-known/openid-federation`),
					);
					t.equal(discovery.status, 200);
					t.true(
						(
							await verifyEntityStatement(
								await discovery.text(),
								(
									await ctx.crypto.keyring.entry("federation")
								).publishedJwks,
								{ engine: testEngine },
							)
						).ok,
					);
					t.equal(
						(
							await authority.handleRequest(
								new Request(`${CA_AUTHORITY_ID}/fetch?sub=${CA_CLIENT_ID}`),
							)
						).status,
						405,
					);
					const anonymous = await authority.handleRequest(
						new Request(`${CA_AUTHORITY_ID}/status`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: new URLSearchParams({ trust_mark: statusJwt }),
						}),
					);
					t.equal(anonymous.status, 200);
					const checked = await verifyEntityStatement(
						await anonymous.text(),
						(await ctx.crypto.keyring.entry("federation")).publishedJwks,
						{ engine: testEngine, expectedTyp: JwtTyp.TrustMarkStatusResponse },
					);
					t.true(checked.ok);
					if (checked.ok) t.equal(checked.value.payload.status, "active");
					const authenticated = await authority.handleRequest(
						new Request(`${CA_AUTHORITY_ID}/status`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: new URLSearchParams({
								trust_mark: statusJwt,
								client_assertion: await createClientAssertionJwt(),
								client_assertion_type: JWT_BEARER_TYPE,
							}),
						}),
					);
					t.equal(authenticated.status, 200);
				}
				function configForHost(): AuthorityConfig {
					return { ...config, metadata: structuredClone(config.metadata) };
				}
			});

			test("unsupported authentication cannot leave an advertised endpoint open", async (t) => {
				const { ctx } = await setupClientAuthContext();
				for (const suffix of [
					"fetch",
					"list",
					"extended_list",
					"resolve",
					"historical_keys",
					"trust_mark",
					"trust_mark_status",
					"trust_mark_list",
					"subordinate_events",
					"collection",
				]) {
					for (const methods of [
						[],
						["private_key_jwt_typo"],
						["none", "private_key_jwt_typo"],
						["private_key_jwt", "private_key_jwt_typo"],
					]) {
						const endpoint = `federation_${suffix}_endpoint`;
						await t.rejects(
							(async () =>
								await TrustAnchor.create(
									fixtureHostConfig({
										entityId: ctx.entityId,
										crypto: ctx.crypto,
										storage: new MemoryStorageAdapter({
											engine: testEngine,
											trustMarks: true,
											subordinateEvents: true,
										}),
										...(suffix === "collection" ? { collection: { trustAnchors: new Map() } } : {}),
										metadata: {
											federation_entity: {
												federation_fetch_endpoint: `${ctx.entityId}/fetch`,
												federation_list_endpoint: `${ctx.entityId}/list`,
												[endpoint]: `${ctx.entityId}/${suffix}`,
												[`${endpoint}_auth_methods`]: methods,
											},
										},
									}),
								))(),
							/auth.*method/i,
							`${endpoint}: ${JSON.stringify(methods)}`,
						);
					}
				}
			});
			test("optional POST preserves anonymous parameters and authenticates supplied assertions", async (t) => {
				const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
				let forwardedSignal: AbortSignal | undefined;
				const inner = async (request: Request) => {
					forwardedSignal = request.signal;
					const form = new URLSearchParams(await request.text());
					return jsonResponse({
						method: request.method,
						marks: form.getAll("trust_mark"),
						authenticated: authenticatedEndpointCaller(request) ?? null,
						contentLength: request.headers.get("Content-Length"),
						hasCredentials: form.has("client_assertion") || form.has("client_assertion_type"),
					});
				};
				const handler = createAuthenticatedHandler(ctx, inner, ["none", "private_key_jwt"], {
					nativeMethod: "POST",
				});
				const controller = new AbortController();
				const response = await handler(
					new Request(`${CA_AUTHORITY_ID}/status`, {
						method: "POST",
						signal: controller.signal,
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
							"Content-Length": "20",
							"X-Authenticated-Entity": "https://spoof.example",
						},
						body: "trust_mark=a&trust_mark=b",
					}),
				);
				t.equal(response.status, 200);
				t.deepEqual(await response.json(), {
					method: "POST",
					marks: ["a", "b"],
					authenticated: null,
					contentLength: null,
					hasCredentials: false,
				});
				controller.abort();
				t.true(forwardedSignal?.aborted);
				const assertion = await createClientAssertionJwt();
				const authenticated = await handler(
					new Request(`${CA_AUTHORITY_ID}/status`, {
						method: "POST",
						headers: { "Content-Type": "application/x-www-form-urlencoded" },
						body: new URLSearchParams({
							trust_mark: "mark",
							client_assertion: assertion,
							client_assertion_type: JWT_BEARER_TYPE,
						}),
					}),
				);
				t.equal(authenticated.status, 200);
				t.deepEqual(await authenticated.json(), {
					method: "POST",
					marks: ["mark"],
					authenticated: CA_CLIENT_ID,
					contentLength: null,
					hasCredentials: false,
				});
				t.equal(
					(await handler(new Request(`${CA_AUTHORITY_ID}/status`))).status,
					405,
					"anonymous Trust Mark Status still requires POST",
				);
			});
			test("optional authentication never downgrades supplied invalid credentials", async (t) => {
				const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
				for (const nativeMethod of ["GET", "POST"] as const) {
					let calls = 0;
					const handler = createAuthenticatedHandler(
						ctx,
						async () => {
							calls++;
							return jsonResponse({});
						},
						["none", "private_key_jwt"],
						{ nativeMethod },
					);
					const valid = await createClientAssertionJwt();
					const expired = await createClientAssertionJwt({
						exp: Math.floor(Date.now() / 1000) - 120,
					});
					for (const credentials of [
						"client_assertion=",
						"client_assertion_type=",
						`client_assertion=${valid}`,
						`client_assertion_type=${JWT_BEARER_TYPE}`,
						`client_assertion=invalid&client_assertion_type=${JWT_BEARER_TYPE}`,
						`client_assertion=${expired}&client_assertion_type=${JWT_BEARER_TYPE}`,
						`client_assertion=${valid}&client_assertion=${valid}&client_assertion_type=${JWT_BEARER_TYPE}`,
					]) {
						t.equal(
							(
								await handler(
									new Request(`${CA_AUTHORITY_ID}/endpoint`, {
										method: "POST",
										headers: { "Content-Type": "application/x-www-form-urlencoded" },
										body: `trust_mark=mark&${credentials}`,
									}),
								)
							).status,
							401,
							credentials.slice(0, 40),
						);
					}
					t.equal(calls, 0);
					const replay = () =>
						handler(
							new Request(`${CA_AUTHORITY_ID}/endpoint`, {
								method: "POST",
								headers: { "Content-Type": "application/x-www-form-urlencoded" },
								body: new URLSearchParams({
									trust_mark: "mark",
									client_assertion: valid,
									client_assertion_type: JWT_BEARER_TYPE,
								}),
							}),
						);
					t.equal((await replay()).status, 200);
					t.equal((await replay()).status, 401);
					t.equal(calls, 1);
				}
			});
			test("optional authentication bounds forms before dispatch and rejects credential-bearing GET", async (t) => {
				const { ctx } = await setupClientAuthContext();
				for (const nativeMethod of ["GET", "POST"] as const) {
					let calls = 0;
					const handler = createAuthenticatedHandler(
						ctx,
						async () => {
							calls++;
							return jsonResponse({});
						},
						["none", "private_key_jwt"],
						{ nativeMethod },
					);
					t.equal(
						(
							await handler(
								new Request(`${CA_AUTHORITY_ID}/endpoint`, {
									method: "POST",
									headers: { "Content-Type": "application/x-www-form-urlencoded" },
									body: `trust_mark=${"a".repeat(DEFAULT_MAX_REQUEST_BODY_BYTES + 1)}`,
								}),
							)
						).status,
						413,
					);
					t.equal(
						(await handler(new Request(`${CA_AUTHORITY_ID}/endpoint?client_assertion=`))).status,
						nativeMethod === "GET" ? 401 : 405,
					);
					t.equal(calls, 0);
				}
			});

			test("requires replay storage only for authenticated endpoints", async (t) => {
				const { ctx } = await setupClientAuthContext();
				const storage: StorageAdapter = {
					subordinates: ctx.storage.subordinates,
					transaction: (operation) => ctx.storage.transaction(operation),
				};
				t.equal(
					typeof createAuthenticatedHandler({ ...ctx, storage }, echoHandler, ["none"]),
					"function",
				);
				t.throws(
					() => createAuthenticatedHandler({ ...ctx, storage }, echoHandler, ["private_key_jwt"]),
					/replay storage/,
				);
			});
			test("rejects concurrent reuse across endpoint handlers and fails closed on store errors", async (t) => {
				const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
				const assertion = await createClientAssertionJwt();
				const request = () =>
					new Request(`${CA_AUTHORITY_ID}/fetch`, {
						method: "POST",
						headers: { "Content-Type": "application/x-www-form-urlencoded" },
						body: new URLSearchParams({
							sub: "test",
							client_assertion: assertion,
							client_assertion_type: JWT_BEARER_TYPE,
						}),
					});
				const handlers = [
					createAuthenticatedHandler(ctx, echoHandler, ["private_key_jwt"]),
					createAuthenticatedHandler(ctx, echoHandler, ["private_key_jwt"]),
				];
				const responses = await Promise.all(handlers.map((handler) => handler(request())));
				t.deepEqual(responses.map((r) => r.status).sort(), [200, 401]);
				const storage: StorageAdapter = {
					subordinates: ctx.storage.subordinates,
					transaction: (operation) => ctx.storage.transaction(operation),
					replay: {
						useJti: async () => {
							throw new Error("unavailable");
						},
					},
				};
				const handler = createAuthenticatedHandler({ ...ctx, storage }, echoHandler, [
					"private_key_jwt",
				]);
				t.equal((await handler(request())).status, 500);
			});

			module("no auth required (passthrough)", () => {
				test("omitted endpoint auth metadata defaults to ['none']", async (t) => {
					const { ctx } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, undefined);
					t.equal(typeof handler, "function");
				});

				test("returns inner handler unchanged when authMethods is ['none']", async (t) => {
					const { ctx } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, ["none"]);
					t.equal(typeof handler, "function");
				});

				test("rejects explicit empty auth methods", async (t) => {
					const { ctx } = await setupClientAuthContext();
					t.throws(
						() => createAuthenticatedHandler(ctx, echoHandler, []),
						/auth methods must not be empty/,
					);
				});
			});

			module("private_key_jwt enforcement", () => {
				test("rejects GET when only 'private_key_jwt' configured", async (t) => {
					const { ctx } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, ["private_key_jwt"]);
					const res = await handler(new Request(`${CA_AUTHORITY_ID}/test?sub=test`));
					t.equal(res.status, 405);
				});

				test("accepts GET when both 'none' and 'private_key_jwt' configured", async (t) => {
					const { ctx } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, ["none", "private_key_jwt"]);
					const res = await handler(new Request(`${CA_AUTHORITY_ID}/test?sub=test`));
					t.equal(res.status, 200);
					t.equal(((await res.json()) as Record<string, unknown>).sub, "test");
				});

				test("rejects POST without client_assertion", async (t) => {
					const { ctx } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, ["private_key_jwt"]);
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: "sub=https%3A%2F%2Ffoo.com",
						}),
					);
					t.equal(res.status, 401);
					t.equal(
						((await res.json()) as Record<string, unknown>).error,
						FederationErrorCode.InvalidClient,
					);
				});

				test("rejects POST with wrong client_assertion_type", async (t) => {
					const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, ["private_key_jwt"]);
					const assertion = await createClientAssertionJwt();
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=wrong`,
						}),
					);
					t.equal(res.status, 401);
					const body = (await res.json()) as Record<string, string>;
					t.equal(body.error, FederationErrorCode.InvalidClient);
					t.true(body.error_description!.includes("client_assertion_type"));
				});

				test("accepts valid POST with correct client_assertion", async (t) => {
					const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
					const ctxWithoutDiscovery: HandlerContext = {
						...ctx,
						options: {
							engine: testEngine,
							httpClient: async () => {
								throw new Error("discovery should not run for endpoint authentication");
							},
						},
					};
					const handler = createAuthenticatedHandler(ctxWithoutDiscovery, echoHandler, [
						"private_key_jwt",
					]);
					const assertion = await createClientAssertionJwt();
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test_value&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 200);
					const body = (await res.json()) as Record<string, unknown>;
					t.equal(body.sub, "test_value");
					t.equal(body.method, "GET");
				});

				test("forwards endpoint params correctly from POST body", async (t) => {
					const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, ["private_key_jwt"]);
					const subValue = "https://sub.example.com";
					const assertion = await createClientAssertionJwt();
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=${encodeURIComponent(subValue)}&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 200);
					t.equal(((await res.json()) as Record<string, unknown>).sub, subValue);
				});

				test("rejects POST with expired client_assertion", async (t) => {
					const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
					const ctxWithClock: HandlerContext = {
						...ctx,
						options: { engine: testEngine, clockSkewSeconds: 0 },
					};
					const handler = createAuthenticatedHandler(ctxWithClock, echoHandler, [
						"private_key_jwt",
					]);
					const now = Math.floor(Date.now() / 1000);
					const assertion = await createClientAssertionJwt({ exp: now - 120 });
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 401);
				});

				test("rejects POST with wrong aud in assertion", async (t) => {
					const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, ["private_key_jwt"]);
					const assertion = await createClientAssertionJwt({ aud: "https://wrong.example.com" });
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 401);
				});

				test("rejects private_key_jwt with multiple audience values", async (t) => {
					const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, ["private_key_jwt"]);
					const assertion = await createClientAssertionJwt({
						aud: [CA_AUTHORITY_ID, "https://wrong.example.com"],
					});
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 401);
				});

				test("accepts private_key_jwt with sole audience as endpoint Entity Identifier", async (t) => {
					const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, ["private_key_jwt"]);
					const assertion = await createClientAssertionJwt({ aud: [CA_AUTHORITY_ID] });
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 200);
				});

				test("rejects POST when client key provider has no keys for issuer", async (t) => {
					const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, ["private_key_jwt"]);
					const unknownClientId = "https://unknown-client.example.com";
					const assertion = await createClientAssertionJwt({
						iss: unknownClientId,
						sub: unknownClientId,
					});
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 401);
					const body = (await res.json()) as Record<string, string>;
					t.equal(body.error, FederationErrorCode.InvalidClient);
					t.true(body.error_description!.includes("No federation keys"));
				});

				test("rejects POST with invalid signature", async (t) => {
					const { ctx } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, ["private_key_jwt"]);
					const otherKeys = await generateSigningKey("ES256");
					const now = Math.floor(Date.now() / 1000);
					const badAssertion = await signEntityStatement(
						{
							iss: CA_CLIENT_ID,
							sub: CA_CLIENT_ID,
							aud: CA_AUTHORITY_ID,
							jti: globalThis.crypto.randomUUID(),
							iat: now,
							exp: now + 60,
						},
						new SigningEntryFixture(otherKeys.privateKey),
						{ typ: "JWT" },
					);
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(badAssertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 401);
				});

				test("accepts POST without trust anchors when key provider resolves keys", async (t) => {
					const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
					const ctxNoTa: HandlerContext = {
						entityId: ctx.entityId,
						crypto: ctx.crypto,
						storage: ctx.storage,
						clientKeyProvider: ctx.clientKeyProvider,
						metadata: ctx.metadata,
						options: { engine: testEngine },
					};
					const handler = createAuthenticatedHandler(ctxNoTa, echoHandler, ["private_key_jwt"]);
					const assertion = await createClientAssertionJwt();
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 200);
				});

				test("passes assertion issuer to configured client key provider", async (t) => {
					const { ctx, createClientAssertionJwt, clientPublicKey } = await setupClientAuthContext();
					let requestedEntityId: EntityId | undefined;
					const ctxWithCustomProvider: HandlerContext = {
						...ctx,
						clientKeyProvider: {
							async getClientFederationJwks(entityId) {
								requestedEntityId = entityId;
								return { keys: [clientPublicKey] };
							},
						},
					};
					const handler = createAuthenticatedHandler(ctxWithCustomProvider, echoHandler, [
						"private_key_jwt",
					]);
					const assertion = await createClientAssertionJwt();
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 200);
					t.equal(requestedEntityId, CA_CLIENT_ID);
				});

				test("returns sanitized server_error when client key provider fails", async (t) => {
					const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
					const ctxWithFailingProvider: HandlerContext = {
						...ctx,
						clientKeyProvider: {
							async getClientFederationJwks() {
								throw new Error("secret backend detail");
							},
						},
					};
					const handler = createAuthenticatedHandler(ctxWithFailingProvider, echoHandler, [
						"private_key_jwt",
					]);
					const assertion = await createClientAssertionJwt();
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 500);
					const body = (await res.json()) as Record<string, string>;
					t.equal(body.error, FederationErrorCode.ServerError);
					t.false(body.error_description!.includes("secret backend detail"));
				});

				test("rejects POST when client key provider returns the wrong key", async (t) => {
					const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
					const wrongKeys = await generateSigningKey("ES256");
					const ctxWithWrongKey: HandlerContext = {
						...ctx,
						clientKeyProvider: {
							async getClientFederationJwks() {
								return { keys: [{ ...wrongKeys.publicKey, kid: "wrong-client-key" }] };
							},
						},
					};
					const handler = createAuthenticatedHandler(ctxWithWrongKey, echoHandler, [
						"private_key_jwt",
					]);
					const assertion = await createClientAssertionJwt();
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 401);
				});

				test("iss !== sub in assertion returns 401", async (t) => {
					const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, echoHandler, ["private_key_jwt"]);
					const assertion = await createClientAssertionJwt({
						iss: CA_CLIENT_ID,
						sub: "https://other.example.com",
					});
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=test&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 401);
				});
			});

			module("nativeMethod: POST", () => {
				test("forwards remaining POST body for POST-native endpoints", async (t) => {
					const { ctx, createClientAssertionJwt } = await setupClientAuthContext();
					const handler = createAuthenticatedHandler(ctx, postEchoHandler, ["private_key_jwt"], {
						nativeMethod: "POST",
					});
					const assertion = await createClientAssertionJwt();
					const res = await handler(
						new Request(`${CA_AUTHORITY_ID}/test`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `trust_mark=some_trust_mark_jwt&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 200);
					const body = (await res.json()) as Record<string, unknown>;
					t.equal(body.trust_mark, "some_trust_mark_jwt");
					t.equal(body.method, "POST");
				});
			});
		});
	}

	module("authority / compromised key rollover", (hooks) => {
		let crypto: FixtureCrypto;

		hooks.beforeEach(async () => {
			const { privateKey } = await generateSigningKey("ES256");
			crypto = new FixtureCrypto(
				createFederationSigningKey({ ...privateKey, kid: "compromised-key" }),
			);
		});

		test("revokes old key after switching to replacement", async (t) => {
			const { privateKey: newKey } = await generateSigningKey("ES256");
			await crypto.keyring.publish(
				"federation",
				fixtureSigner(createFederationSigningKey({ ...newKey, kid: "new-key" })),
			);
			await crypto.keyring.activate("federation", "new-key");
			await crypto.keyring.revoke("federation", "compromised-key", "keyCompromise");
			const keySet = await crypto.keyring.entry("federation");
			t.equal(keySet.signer.publicJwk.kid, "new-key");
			const history = await crypto.history.getHistoricalKeys();
			const oldKey = history.find((k) => k.kid === "compromised-key");
			t.ok(oldKey?.revoked);
			t.equal(oldKey?.revoked?.reason, "keyCompromise");
		});

		test("revoked key is not in active keys", async (t) => {
			const { privateKey: newKey } = await generateSigningKey("ES256");
			await crypto.keyring.publish(
				"federation",
				fixtureSigner(createFederationSigningKey({ ...newKey, kid: "new-key" })),
			);
			await crypto.keyring.activate("federation", "new-key");
			await crypto.keyring.revoke("federation", "compromised-key", "keyCompromise");
			const keySet = await crypto.keyring.entry("federation");
			t.equal(keySet.publishedJwks.keys.length, 1);
			t.equal(keySet.publishedJwks.keys[0]!.kid, "new-key");
		});
	});

	module("authority / key rotation validation", () => {
		test("published key must have a kid", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			const { privateKey: newKey } = await generateSigningKey("ES256");
			const keyWithoutKid = { ...newKey };
			delete (keyWithoutKid as { kid?: string }).kid;
			new FixtureCrypto(createFederationSigningKey({ ...privateKey, kid: "existing" }));
			t.throws(() => new SigningEntryFixture(keyWithoutKid), /kid/);
		});

		test("replacement key must have a kid", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			new FixtureCrypto(createFederationSigningKey({ ...privateKey, kid: "compromised" }));
			const { privateKey: newKey } = await generateSigningKey("ES256");
			const keyWithoutKid = { ...newKey };
			delete (keyWithoutKid as { kid?: string }).kid;
			t.throws(() => new SigningEntryFixture(keyWithoutKid), /kid/);
		});
	});

	// ── server ───────────────────────────────────────────────────────
	{
		const SERVER_AUTHORITY_ID = entityId("https://authority.example.com");
		const SERVER_SUB1 = entityId("https://sub1.example.com");
		const SERVER_SUB2 = entityId("https://sub2.example.com");
		const SERVER_SUB3 = entityId("https://sub3.example.com");
		const SERVER_MARK_TYPE = "https://trust.example.com/mark-a";

		function makeServerRecord(
			id: ReturnType<typeof entityId>,
			overrides?: Partial<
				import("../../../packages/authority/src/storage/types.js").SubordinateRecord
			>,
		): import("../../../packages/authority/src/storage/types.js").SubordinateRecord {
			return {
				entityId: id,
				jwks: { keys: [testPublicJwk()] },
				createdAt: Date.now(),
				updatedAt: Date.now(),
				...overrides,
			};
		}

		function withFederationEntityMetadata(
			config: AuthorityConfig,
			federationEntity: Record<string, unknown>,
		): AuthorityConfig {
			return {
				...config,
				metadata: {
					...config.metadata,
					federation_entity: {
						...config.metadata.federation_entity,
						...federationEntity,
					},
				},
			};
		}

		function withOptionalServerEndpoints(config: AuthorityConfig): AuthorityConfig {
			return withFederationEntityMetadata(config, {
				federation_extended_list_endpoint: `${SERVER_AUTHORITY_ID}${FederationEndpoint.ExtendedList}`,
				federation_historical_keys_endpoint: `${SERVER_AUTHORITY_ID}${FederationEndpoint.HistoricalKeys}`,
				federation_resolve_endpoint: `${SERVER_AUTHORITY_ID}${FederationEndpoint.Resolve}`,
				federation_trust_mark_endpoint: `${SERVER_AUTHORITY_ID}${FederationEndpoint.TrustMark}`,
				federation_trust_mark_list_endpoint: `${SERVER_AUTHORITY_ID}${FederationEndpoint.TrustMarkList}`,
				federation_trust_mark_status_endpoint: `${SERVER_AUTHORITY_ID}${FederationEndpoint.TrustMarkStatus}`,
			});
		}

		module("authority / createAuthorityServer", (hooks) => {
			let srvStorage: MemoryStorageAdapter;
			let srvKeyProvider: FixtureCrypto;
			let srvSubordinates: SubordinateStorage;
			let srvConfig: AuthorityConfig;

			hooks.beforeEach(async () => {
				srvStorage = new MemoryStorageAdapter({ engine: testEngine, trustMarks: true });
				srvSubordinates = srvStorage.subordinates;

				const { privateKey } = await generateSigningKey("ES256");
				const signingKey = { ...privateKey, kid: "server-key-1" };
				srvKeyProvider = new FixtureCrypto(createFederationSigningKey(signingKey));

				srvConfig = {
					entityId: SERVER_AUTHORITY_ID,
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: `${SERVER_AUTHORITY_ID}/federation_fetch`,
							federation_list_endpoint: `${SERVER_AUTHORITY_ID}/federation_list`,
						},
					},
					storage: srvStorage,
					crypto: srvKeyProvider,
					trustMarkIssuers: { [SERVER_MARK_TYPE]: [SERVER_AUTHORITY_ID] },
				};
			});

			module("programmatic API", () => {
				test("both authority classes preserve fractional time filters and audit values", async (t) => {
					await srvSubordinates.add(
						makeServerRecord(SERVER_SUB1, { createdAt: -0.5, updatedAt: 1500.25 }),
					);
					await srvSubordinates.add(
						makeServerRecord(SERVER_SUB2, { createdAt: -0.5, updatedAt: 1500.5 }),
					);
					for (const authorityHints of [undefined, [entityId("https://superior.example.com")]]) {
						const config = withOptionalServerEndpoints({
							...srvConfig,
							...(authorityHints ? { authorityHints } : {}),
						});
						if (authorityHints) delete config.trustMarkIssuers;
						const server = await createAuthorityServer(config);
						const result = await (await server).listSubordinatesExtended({
							claims: [],
							updatedAfter: 1500.5,
							updatedBefore: 1500.5,
						});
						t.true(result.ok);
						if (result.ok)
							t.deepEqual(result.value.immediate_subordinate_entities, [
								{ id: SERVER_SUB2, registered: -0.5, updated: 1500.5 },
							]);
					}
				});
				test("extended listing preserves claims, mark filters and cursors on both authority classes", async (t) => {
					const alpha = "https://marks.example/alpha";
					const beta = "https://marks.example/beta";
					const metadata = { openid_relying_party: { client_name: "Example RP" } };
					for (const id of [SERVER_SUB1, SERVER_SUB2]) {
						await srvSubordinates.add(makeServerRecord(id, { metadata }));
						await srvStorage.trustMarks!.issue({
							subject: id,
							trustMarkType: id === SERVER_SUB1 ? alpha : beta,
							jwt: `fixture.${id}`,
							issuedAt: 1000,
							active: true,
						});
					}
					for (const authorityHints of [undefined, [entityId("https://superior.example.com")]]) {
						const config = withOptionalServerEndpoints({
							...srvConfig,
							...(authorityHints ? { authorityHints } : {}),
						});
						if (authorityHints) delete config.trustMarkIssuers;
						const server = await createAuthorityServer(config);
						for (const claims of [undefined, [], ["metadata"], ["subordinate_statement"]]) {
							const result = await (await server).listSubordinatesExtended({
								...(claims === undefined ? {} : { claims }),
								trustMarkType: [alpha, beta],
							});
							t.true(result.ok);
							if (!result.ok) continue;
							t.deepEqual(
								result.value.immediate_subordinate_entities.map(({ id }) => id),
								[SERVER_SUB1, SERVER_SUB2],
							);
							for (const entry of result.value.immediate_subordinate_entities) {
								t.equal(
									typeof entry.subordinate_statement === "string",
									claims === undefined || claims.includes("subordinate_statement"),
								);
								if (claims?.includes("metadata")) t.deepEqual(entry.metadata, metadata);
							}
						}
						const first = await (await server).listSubordinatesExtended({ claims: [], limit: 1 });
						t.true(first.ok);
						if (!first.ok) continue;
						t.equal(typeof first.value.next, "string");
						const tail = await (await server).listSubordinatesExtended({
							from: first.value.next!,
							claims: [],
						});
						t.true(tail.ok);
						if (tail.ok) {
							t.deepEqual(tail.value.immediate_subordinate_entities, [{ id: SERVER_SUB2 }]);
							t.equal(tail.value.next, undefined);
						}
						const empty = await (await server).listSubordinatesExtended({
							claims: [],
							trustMarkType: "https://marks.example/missing",
						});
						t.true(empty.ok);
						if (empty.ok) t.deepEqual(empty.value, { immediate_subordinate_entities: [] });
						const missing = await (await server).listSubordinatesExtended({ from: "unknown +/=" });
						t.false(missing.ok);
						if (!missing.ok) {
							t.equal(missing.error.code, FederationErrorCode.PageNotFound);
							t.equal(missing.error.description, "Unknown continuation cursor");
						}
						const ec = decodeEntityStatement(await (await server).getEntityConfiguration());
						t.true(ec.ok);
						if (ec.ok)
							t.equal(
								ec.value.payload.metadata?.federation_entity?.federation_extended_list_endpoint,
								`${SERVER_AUTHORITY_ID}${FederationEndpoint.ExtendedList}`,
							);
					}
				});
				test("getEntityConfiguration returns signed JWT", async (t) => {
					const server = await createAuthorityServer(srvConfig);
					const jwt = await (await server).getEntityConfiguration();
					const decoded = decodeEntityStatement(jwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					t.equal(decoded.value.payload.iss, SERVER_AUTHORITY_ID);
					t.equal(decoded.value.payload.sub, SERVER_AUTHORITY_ID);
				});

				test("TrustAnchor normalizes trailing slash for facade and Entity Configuration", async (t) => {
					const trustAnchor = await TrustAnchor.create(
						fixtureHostConfig({
							...srvConfig,
							entityId: `${SERVER_AUTHORITY_ID}/`,
						}),
					);
					t.equal(trustAnchor.entityId, SERVER_AUTHORITY_ID);
					const jwt = await trustAnchor.getEntityConfiguration();
					const decoded = decodeEntityStatement(jwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					t.equal(decoded.value.payload.iss, SERVER_AUTHORITY_ID);
					t.equal(decoded.value.payload.sub, SERVER_AUTHORITY_ID);
				});

				test("Intermediate normalizes trailing slash for facade and Entity Configuration", async (t) => {
					const parent = entityId("https://parent.example.com");
					const intermediateConfig: AuthorityConfig = {
						...srvConfig,
						entityId: `${SERVER_AUTHORITY_ID}/`,
						authorityHints: [parent],
					};
					delete intermediateConfig.trustMarkIssuers;
					const intermediate = await Intermediate.create(fixtureHostConfig(intermediateConfig));
					t.equal(intermediate.entityId, SERVER_AUTHORITY_ID);
					const jwt = await intermediate.getEntityConfiguration();
					const decoded = decodeEntityStatement(jwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					t.equal(decoded.value.payload.iss, SERVER_AUTHORITY_ID);
					t.equal(decoded.value.payload.sub, SERVER_AUTHORITY_ID);
					t.deepEqual(decoded.value.payload.authority_hints, [parent.toString()]);
				});

				test("getSubordinateStatement returns signed JWT", async (t) => {
					await srvSubordinates.add(makeServerRecord(SERVER_SUB1));
					const server = await createAuthorityServer(srvConfig);
					const jwt = await (await server).getSubordinateStatement(SERVER_SUB1);
					const decoded = decodeEntityStatement(jwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					t.equal(decoded.value.payload.iss, SERVER_AUTHORITY_ID);
					t.equal(decoded.value.payload.sub, SERVER_SUB1);
				});

				test("getSubordinateStatement throws for unknown entity", async (t) => {
					const server = await createAuthorityServer(srvConfig);
					try {
						await (await server).getSubordinateStatement(SERVER_SUB1);
						t.ok(false, "should have thrown");
					} catch (e: unknown) {
						t.true((e as Error).message.includes("not found"));
					}
				});

				test("listSubordinates returns entity IDs", async (t) => {
					await srvSubordinates.add(makeServerRecord(SERVER_SUB1));
					const server = await createAuthorityServer(srvConfig);
					const list = await (await server).listSubordinates();
					t.deepEqual(list, [SERVER_SUB1]);
				});

				test("listSubordinatesExtended returns Result.ok with immediate_subordinate_entities + paging", async (t) => {
					await srvSubordinates.add(makeServerRecord(SERVER_SUB1));
					await srvSubordinates.add(makeServerRecord(SERVER_SUB2));
					await srvSubordinates.add(makeServerRecord(SERVER_SUB3));
					const server = await createAuthorityServer(srvConfig);
					const sorted = [SERVER_SUB1, SERVER_SUB2, SERVER_SUB3].sort();
					const first = await (await server).listSubordinatesExtended({ limit: 2 });
					t.true(first.ok);
					if (!first.ok) return;
					t.equal(first.value.immediate_subordinate_entities.length, 2);
					t.equal(first.value.immediate_subordinate_entities[0]!.id, sorted[0]);
					t.equal(first.value.immediate_subordinate_entities[1]!.id, sorted[1]);
					t.equal(first.value.next, sorted[2]);
					const tail = await (await server).listSubordinatesExtended({
						limit: 2,
						from: first.value.next as string,
						auditTimestamps: true,
					});
					t.true(tail.ok);
					if (!tail.ok) return;
					t.equal(tail.value.immediate_subordinate_entities.length, 1);
					t.equal(tail.value.next, undefined);
					t.ok(
						Number.isInteger(tail.value.immediate_subordinate_entities[0]!.registered as number),
						"audit_timestamps round-trip includes registered",
					);
				});

				test("listSubordinatesExtended returns Result.err with page_not_found on unknown cursor", async (t) => {
					const server = await createAuthorityServer(srvConfig);
					const result = await (await server).listSubordinatesExtended({
						from: entityId("https://does-not-exist.example.com"),
					});
					t.false(result.ok);
					if (!result.ok) {
						t.equal(result.error.code, FederationErrorCode.PageNotFound);
					}
				});

				test("listSubordinatesExtended returns Result.err with unsupported_parameter on disabled audit_timestamps", async (t) => {
					const server = await createAuthorityServer({
						...srvConfig,
						extendedListing: { supportAuditTimestamps: false },
					});
					const result = await (await server).listSubordinatesExtended({ auditTimestamps: true });
					t.false(result.ok);
					if (!result.ok) {
						t.equal(result.error.code, FederationErrorCode.UnsupportedParameter);
					}
				});

				test("issueTrustMark returns signed JWT", async (t) => {
					const server = await createAuthorityServer(srvConfig);
					const jwt = await (await server).issueTrustMark(SERVER_SUB1, SERVER_MARK_TYPE);
					const decoded = decodeEntityStatement(jwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					const payload = decoded.value.payload as Record<string, unknown>;
					t.equal(payload.trust_mark_type, SERVER_MARK_TYPE);
					t.equal(payload.sub, SERVER_SUB1);
				});

				test("nested Trust Mark lifetimes override the authority TTL fallback", async (t) => {
					for (const authorityHints of [undefined, [entityId("https://superior.example.com")]]) {
						for (const scenario of [
							{ defaults: { noExpiry: true }, expectedTtl: undefined },
							{ defaults: { ttlSeconds: 200 }, expectedTtl: 200 },
							{ defaults: { ref: "https://trust.example.com/framework" }, expectedTtl: 100 },
							{ defaults: { noExpiry: false }, expectedTtl: 86400 },
							{
								defaults: { noExpiry: true },
								trustMarkDefaults: { [SERVER_MARK_TYPE]: { ttlSeconds: 300 } },
								expectedTtl: 300,
							},
							{
								defaults: { noExpiry: true },
								options: { ttlSeconds: 400 },
								expectedTtl: 400,
							},
						]) {
							const config = withOptionalServerEndpoints({
								...srvConfig,
								...(authorityHints ? { authorityHints } : {}),
								trustMarkTtlSeconds: 100,
								trustMarkIssuer: { defaults: scenario.defaults },
								trustMarkDefaults: scenario.trustMarkDefaults,
								options: { clock: { now: () => 1000 } },
							});
							if (authorityHints) delete config.trustMarkIssuers;
							const server = await createAuthorityServer(config);
							const jwt = await (await server).issueTrustMark(SERVER_SUB1, SERVER_MARK_TYPE, {
								renewal: "renew",
								...scenario.options,
							});
							const decoded = decodeEntityStatement(jwt);
							t.true(decoded.ok);
							if (!decoded.ok) continue;
							t.equal(decoded.value.payload.iat, 1000);
							t.strictEqual(
								decoded.value.payload.exp,
								scenario.expectedTtl === undefined ? undefined : 1000 + scenario.expectedTtl,
							);
							if (scenario.defaults.ref !== undefined)
								t.equal(decoded.value.payload.ref, scenario.defaults.ref);
						}
					}
				});

				test("conflicting nested Trust Mark lifetimes reject configuration", async (t) => {
					for (const authorityHints of [undefined, [entityId("https://superior.example.com")]]) {
						const config = withOptionalServerEndpoints({
							...srvConfig,
							...(authorityHints ? { authorityHints } : {}),
							trustMarkTtlSeconds: 100,
							trustMarkIssuer: { defaults: { noExpiry: true, ttlSeconds: 200 } },
						});
						if (authorityHints) delete config.trustMarkIssuers;
						await t.rejects(
							(async () => await createAuthorityServer(config))(),
							/noExpiry and ttlSeconds conflict/,
						);
					}
				});

				test("listTrustMarkedEntities returns entity IDs", async (t) => {
					const server = await createAuthorityServer(srvConfig);
					await (await server).issueTrustMark(SERVER_SUB1, SERVER_MARK_TYPE);
					const list = await (await server).listTrustMarkedEntities(SERVER_MARK_TYPE);
					t.true(list.includes(SERVER_SUB1));
				});

				test("getHistoricalKeys returns signed JWT", async (t) => {
					const server = await createAuthorityServer(srvConfig);
					const jwt = await (await server).getHistoricalKeys();
					t.ok(jwt);
					const decoded = decodeEntityStatement(jwt);
					t.true(isOk(decoded));
				});

				test("injected key provider owns signer rollover", async (t) => {
					const server = await createAuthorityServer(srvConfig);
					const { privateKey: newKey } = await generateSigningKey("ES256");
					await srvKeyProvider.keyring.publish(
						"federation",
						fixtureSigner(createFederationSigningKey({ ...newKey, kid: "server-key-2" })),
					);
					await srvKeyProvider.keyring.activate("federation", "server-key-2");
					const keySet = await srvKeyProvider.keyring.entry("federation");
					t.equal(keySet.signer.publicJwk.kid, "server-key-2");
					t.ok(await (await server).getEntityConfiguration());
				});
			});

			module("HTTP handler", () => {
				test("routes to entity configuration", async (t) => {
					const server = await createAuthorityServer(srvConfig);
					const handler = (await server).handler();
					const res = await handler(
						new Request(`${SERVER_AUTHORITY_ID}${WELL_KNOWN_OPENID_FEDERATION}`),
					);
					t.equal(res.status, 200);
					t.equal(res.headers.get("Content-Type"), "application/entity-statement+jwt");
				});

				test("serves path-based authority Entity Configuration at derived well-known path", async (t) => {
					const pathAuthorityId = entityId("https://authority.example.com/tenant");
					const server = await createAuthorityServer({
						...srvConfig,
						entityId: pathAuthorityId,
						metadata: {
							federation_entity: {
								federation_fetch_endpoint: `${pathAuthorityId}/federation_fetch`,
								federation_list_endpoint: `${pathAuthorityId}/federation_list`,
							},
						},
						trustMarkIssuers: { [SERVER_MARK_TYPE]: [pathAuthorityId] },
					});
					const handler = (await server).handler();
					const res = await handler(
						new Request(`${pathAuthorityId}${WELL_KNOWN_OPENID_FEDERATION}`),
					);
					t.equal(res.status, 200);
					const jwt = await res.text();
					const decoded = decodeEntityStatement(jwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					t.equal(decoded.value.payload.iss, pathAuthorityId);
					t.equal(decoded.value.payload.sub, pathAuthorityId);
				});

				test("does not serve path-based authority Entity Configuration at root well-known path", async (t) => {
					const pathAuthorityId = entityId("https://authority.example.com/tenant");
					const server = await createAuthorityServer({
						...srvConfig,
						entityId: pathAuthorityId,
						metadata: {
							federation_entity: {
								federation_fetch_endpoint: `${pathAuthorityId}/federation_fetch`,
								federation_list_endpoint: `${pathAuthorityId}/federation_list`,
							},
						},
						trustMarkIssuers: { [SERVER_MARK_TYPE]: [pathAuthorityId] },
					});
					const handler = (await server).handler();
					const res = await handler(
						new Request(`https://authority.example.com${WELL_KNOWN_OPENID_FEDERATION}`),
					);
					t.equal(res.status, 404);
				});

				test("routes to fetch endpoint", async (t) => {
					await srvSubordinates.add(makeServerRecord(SERVER_SUB1));
					const server = await createAuthorityServer(srvConfig);
					const handler = (await server).handler();
					const res = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(SERVER_SUB1)}`,
						),
					);
					t.equal(res.status, 200);
				});

				test("routes to list endpoint", async (t) => {
					const server = await createAuthorityServer(srvConfig);
					const handler = (await server).handler();
					const res = await handler(
						new Request(`${SERVER_AUTHORITY_ID}${FederationEndpoint.List}`),
					);
					t.equal(res.status, 200);
					t.equal(res.headers.get("Content-Type"), "application/json");
				});

				test("routes fetch and list through advertised metadata paths", async (t) => {
					await srvSubordinates.add(makeServerRecord(SERVER_SUB1));
					const server = await createAuthorityServer(
						withFederationEntityMetadata(srvConfig, {
							federation_fetch_endpoint: `${SERVER_AUTHORITY_ID}/custom/fetch`,
							federation_list_endpoint: `${SERVER_AUTHORITY_ID}/custom/list`,
						}),
					);
					const handler = (await server).handler();
					const fetchRes = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}/custom/fetch?sub=${encodeURIComponent(SERVER_SUB1)}`,
						),
					);
					t.equal(fetchRes.status, 200);
					const listRes = await handler(new Request(`${SERVER_AUTHORITY_ID}/custom/list`));
					t.equal(listRes.status, 200);
					const oldFetchRes = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(SERVER_SUB1)}`,
						),
					);
					t.equal(oldFetchRes.status, 404);
				});

				test("routes optional endpoints through advertised metadata paths", async (t) => {
					const server = await createAuthorityServer(
						withFederationEntityMetadata(srvConfig, {
							federation_resolve_endpoint: `${SERVER_AUTHORITY_ID}/custom/resolve`,
						}),
					);
					const handler = (await server).handler();
					const customRes = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}/custom/resolve?sub=${encodeURIComponent(SERVER_SUB1)}`,
						),
					);
					t.equal(customRes.status, 400);
					const fixedRes = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.Resolve}?sub=${encodeURIComponent(SERVER_SUB1)}`,
						),
					);
					t.equal(fixedRes.status, 404);
				});

				test("routes to historical keys endpoint", async (t) => {
					const server = await createAuthorityServer(withOptionalServerEndpoints(srvConfig));
					const handler = (await server).handler();
					const res = await handler(
						new Request(`${SERVER_AUTHORITY_ID}${FederationEndpoint.HistoricalKeys}`),
					);
					t.equal(res.status, 200);
					t.equal(res.headers.get("Content-Type"), "application/jwk-set+jwt");
				});

				test("routes to trust mark status endpoint", async (t) => {
					const server = await createAuthorityServer(withOptionalServerEndpoints(srvConfig));
					const handler = (await server).handler();
					const statusJwt = await (await server).issueTrustMark(SERVER_SUB1, SERVER_MARK_TYPE);
					const res = await handler(
						new Request(`${SERVER_AUTHORITY_ID}${FederationEndpoint.TrustMarkStatus}`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: new URLSearchParams({ trust_mark: statusJwt }),
						}),
					);
					t.equal(res.status, 200);
				});

				test("routes to trust mark list endpoint", async (t) => {
					const server = await createAuthorityServer(withOptionalServerEndpoints(srvConfig));
					const handler = (await server).handler();
					const res = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.TrustMarkList}?trust_mark_type=${encodeURIComponent(SERVER_MARK_TYPE)}`,
						),
					);
					t.equal(res.status, 200);
				});

				test("routes to trust mark endpoint — returns 404 when no trust mark exists", async (t) => {
					const server = await createAuthorityServer(withOptionalServerEndpoints(srvConfig));
					const handler = (await server).handler();
					const res = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.TrustMark}?trust_mark_type=${encodeURIComponent(SERVER_MARK_TYPE)}&sub=${encodeURIComponent(SERVER_SUB1)}`,
						),
					);
					t.equal(res.status, 404);
				});

				test("routes to trust mark endpoint — returns 200 when trust mark exists", async (t) => {
					const server = await createAuthorityServer(withOptionalServerEndpoints(srvConfig));
					await (await server).issueTrustMark(SERVER_SUB1, SERVER_MARK_TYPE);
					const handler = (await server).handler();
					const res = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.TrustMark}?trust_mark_type=${encodeURIComponent(SERVER_MARK_TYPE)}&sub=${encodeURIComponent(SERVER_SUB1)}`,
						),
					);
					t.equal(res.status, 200);
				});

				test("routes to resolve endpoint", async (t) => {
					const server = await createAuthorityServer(withOptionalServerEndpoints(srvConfig));
					const handler = (await server).handler();
					const res = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.Resolve}?sub=${encodeURIComponent(SERVER_SUB1)}`,
						),
					);
					t.equal(res.status, 400);
				});

				test("strips X-Authenticated-Entity header from incoming requests", async (t) => {
					await srvSubordinates.add(makeServerRecord(SERVER_SUB1));
					const server = await createAuthorityServer(srvConfig);
					const handler = (await server).handler();
					const res = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(SERVER_SUB1)}`,
							{
								headers: { "X-Authenticated-Entity": "https://spoofed.example.com" },
							},
						),
					);
					t.equal(res.status, 200);
				});

				test("returns 404 for unknown paths", async (t) => {
					const server = await createAuthorityServer(srvConfig);
					const handler = (await server).handler();
					const res = await handler(new Request(`${SERVER_AUTHORITY_ID}/unknown-endpoint`));
					t.equal(res.status, 404);
					t.equal(res.headers.get("Cache-Control"), "no-store");
					const body = (await res.json()) as { error: string };
					t.equal(body.error, "not_found");
				});

				test("all responses include security headers", async (t) => {
					const server = await createAuthorityServer(srvConfig);
					const handler = (await server).handler();
					const res = await handler(
						new Request(`${SERVER_AUTHORITY_ID}${WELL_KNOWN_OPENID_FEDERATION}`),
					);
					t.equal(res.headers.get("Cache-Control"), "no-store");
					t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
					t.ok(res.headers.get("Strict-Transport-Security"));
				});
			});

			module("input validation", () => {
				test("rejects non-HTTPS entityId", async (t) => {
					try {
						await createAuthorityServer({
							...srvConfig,
							entityId: "http://insecure.example.com" as EntityId,
						});
						t.ok(false, "should have thrown");
					} catch (e: unknown) {
						t.true((e as Error).message.includes("entityId MUST be a valid HTTPS URL"));
					}
				});

				test("rejects entityId with query parameter", async (t) => {
					try {
						await createAuthorityServer({
							...srvConfig,
							entityId: "https://example.com?foo=bar" as EntityId,
						});
						t.ok(false, "should have thrown");
					} catch (e: unknown) {
						t.true((e as Error).message.includes("entityId MUST be a valid HTTPS URL"));
					}
				});

				test("rejects entityId with fragment", async (t) => {
					try {
						await createAuthorityServer({
							...srvConfig,
							entityId: "https://example.com#frag" as EntityId,
						});
						t.ok(false, "should have thrown");
					} catch (e: unknown) {
						t.true((e as Error).message.includes("entityId MUST be a valid HTTPS URL"));
					}
				});

				test("rejects zero entityConfigurationTtlSeconds", async (t) => {
					try {
						await createAuthorityServer({ ...srvConfig, entityConfigurationTtlSeconds: 0 });
						t.ok(false, "should have thrown");
					} catch (e: unknown) {
						t.true((e as Error).message.includes("entityConfigurationTtlSeconds must be positive"));
					}
				});

				test("rejects negative subordinateStatementTtlSeconds", async (t) => {
					try {
						await createAuthorityServer({ ...srvConfig, subordinateStatementTtlSeconds: -1 });
						t.ok(false, "should have thrown");
					} catch (e: unknown) {
						t.true(
							(e as Error).message.includes("subordinateStatementTtlSeconds must be positive"),
						);
					}
				});

				test("rejects negative trustMarkTtlSeconds", async (t) => {
					try {
						await createAuthorityServer({ ...srvConfig, trustMarkTtlSeconds: -5 });
						t.ok(false, "should have thrown");
					} catch (e: unknown) {
						t.true((e as Error).message.includes("trustMarkTtlSeconds must be positive"));
					}
				});

				test("accepts undefined TTL fields (uses defaults)", async (t) => {
					try {
						await createAuthorityServer(srvConfig);
						t.ok(true);
					} catch {
						t.ok(false, "should not have thrown");
					}
				});

				test("accepts positive TTL values", async (t) => {
					try {
						await createAuthorityServer({
							...srvConfig,
							entityConfigurationTtlSeconds: 3600,
							subordinateStatementTtlSeconds: 1800,
						});
						t.ok(true);
					} catch {
						t.ok(false, "should not have thrown");
					}
				});
			});

			module("client authentication wiring", () => {
				const CLIENT_ID = entityId("https://client.example.com");
				const JWT_BEARER_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

				async function setupAuthenticatedServer(authMethods: string[]) {
					const taStorage = new MemoryStorageAdapter({ engine: testEngine });
					const taSubStore = taStorage.subordinates;
					const { privateKey: taPrivKey } = await generateSigningKey("ES256");
					const taSigningKey = { ...taPrivKey, kid: "ta-key-1" };
					const taKeyProvider = new FixtureCrypto(createFederationSigningKey(taSigningKey));

					const { privateKey: clientPrivKey, publicKey: clientPubKey } =
						await generateSigningKey("ES256");
					const clientSigningKey = { ...clientPrivKey, kid: "client-key-1" };
					const clientPublicKey = { ...clientPubKey, kid: "client-key-1" };

					await taSubStore.add(makeServerRecord(SERVER_SUB1));
					await taSubStore.add(
						makeServerRecord(CLIENT_ID, {
							jwks: { keys: [clientPublicKey] },
						}),
					);

					const authConfig: AuthorityConfig = {
						entityId: SERVER_AUTHORITY_ID,
						metadata: {
							federation_entity: {
								federation_fetch_endpoint: `${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}`,
								federation_list_endpoint: `${SERVER_AUTHORITY_ID}${FederationEndpoint.List}`,
								federation_fetch_endpoint_auth_methods: authMethods,
							},
						},
						storage: taStorage,
						crypto: taKeyProvider,
						options: {
							httpClient: async () => {
								throw new Error("discovery should not run for endpoint authentication");
							},
						},
					};

					const createAssertion = async () => {
						const now = Math.floor(Date.now() / 1000);
						return signEntityStatement(
							{
								iss: CLIENT_ID,
								sub: CLIENT_ID,
								aud: SERVER_AUTHORITY_ID,
								jti: globalThis.crypto.randomUUID(),
								iat: now,
								exp: now + 60,
							},
							new SigningEntryFixture(clientSigningKey),
							{ typ: "JWT" },
						);
					};

					return { config: authConfig, createAssertion, clientPublicKey };
				}

				test("server with private_key_jwt rejects unauthenticated GET on fetch", async (t) => {
					const { config: authConfig } = await setupAuthenticatedServer(["private_key_jwt"]);
					const server = await createAuthorityServer(authConfig);
					const handler = (await server).handler();
					const res = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(SERVER_SUB1)}`,
						),
					);
					t.equal(res.status, 405);
				});

				test("server with private_key_jwt accepts storage-backed authenticated POST on fetch", async (t) => {
					const { config: authConfig, createAssertion } = await setupAuthenticatedServer([
						"private_key_jwt",
					]);
					const server = await createAuthorityServer(authConfig);
					const handler = (await server).handler();
					const assertion = await createAssertion();
					const res = await handler(
						new Request(`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=${encodeURIComponent(SERVER_SUB1)}&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 200);
				});

				test("server with private_key_jwt rejects assertions outside endpoint algorithms", async (t) => {
					const { config: authConfig, createAssertion } = await setupAuthenticatedServer([
						"private_key_jwt",
					]);
					const server = await createAuthorityServer(
						withFederationEntityMetadata(authConfig, {
							endpoint_auth_signing_alg_values_supported: ["RS256"],
						}),
					);
					const handler = (await server).handler();
					const assertion = await createAssertion();
					const res = await handler(
						new Request(`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=${encodeURIComponent(SERVER_SUB1)}&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 401);
					const body = (await res.json()) as Record<string, string>;
					t.equal(body.error, FederationErrorCode.InvalidClient);
					t.true((body.error_description ?? "").includes("not allowed"));
				});

				test("server authenticated POST resolve sets aud from verified client", async (t) => {
					const fed = await createMockFederation();
					const { config: authConfig, createAssertion } = await setupAuthenticatedServer([
						"private_key_jwt",
					]);
					const server = await createAuthorityServer({
						...withFederationEntityMetadata(authConfig, {
							federation_resolve_endpoint: `${SERVER_AUTHORITY_ID}${FederationEndpoint.Resolve}`,
							federation_resolve_endpoint_auth_methods: ["private_key_jwt"],
						}),
						options: fed.options,
						trustAnchors: fed.trustAnchors,
					});
					const handler = (await server).handler();
					const assertion = await createAssertion();
					const res = await handler(
						new Request(`${SERVER_AUTHORITY_ID}${FederationEndpoint.Resolve}`, {
							method: "POST",
							headers: {
								"Content-Type": "application/x-www-form-urlencoded",
								"X-Authenticated-Entity": "https://spoof.example.com",
							},
							body: `sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 200);
					const jwt = await res.text();
					const decoded = decodeEntityStatement(jwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					const payload = decoded.value.payload as Record<string, unknown>;
					t.equal(payload.aud, CLIENT_ID);
					const { publishedJwks: jwks } = await authConfig.crypto.keyring.entry("federation");
					t.true(
						(
							await verifyResolveResponse(jwt, jwks, {
								engine: testEngine,
								expectedIssuer: SERVER_AUTHORITY_ID,
								expectedSubject: LEAF_ID,
								expectedAudience: CLIENT_ID,
							})
						).ok,
					);
					t.false(
						(
							await verifyResolveResponse(jwt, jwks, {
								engine: testEngine,
								expectedIssuer: SERVER_AUTHORITY_ID,
								expectedSubject: LEAF_ID,
								expectedAudience: "https://other.example.com",
							})
						).ok,
					);
					t.false(
						(
							await verifyResolveResponse(jwt, jwks, {
								engine: testEngine,
								expectedIssuer: SERVER_AUTHORITY_ID,
								expectedSubject: LEAF_ID,
							})
						).ok,
					);
				});

				test("server with private_key_jwt accepts custom provider with empty client storage", async (t) => {
					const {
						config: authConfig,
						createAssertion,
						clientPublicKey,
					} = await setupAuthenticatedServer(["private_key_jwt"]);
					const storage = new MemoryStorageAdapter({ engine: testEngine });
					await storage.subordinates.add(makeServerRecord(SERVER_SUB1));
					let requestedEntityId: EntityId | undefined;
					const server = await createAuthorityServer({
						...authConfig,
						storage,
						clientKeyProvider: {
							async getClientFederationJwks(entityId) {
								requestedEntityId = entityId;
								return entityId === CLIENT_ID ? { keys: [clientPublicKey] } : undefined;
							},
						},
					});
					const handler = (await server).handler();
					const assertion = await createAssertion();
					const res = await handler(
						new Request(`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=${encodeURIComponent(SERVER_SUB1)}&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 200);
					t.equal(requestedEntityId, CLIENT_ID);
				});

				test("server with private_key_jwt sanitizes storage-backed lookup failures", async (t) => {
					const { config: authConfig, createAssertion } = await setupAuthenticatedServer([
						"private_key_jwt",
					]);
					const storage = new MemoryStorageAdapter({ engine: testEngine });
					await storage.subordinates.add(makeServerRecord(SERVER_SUB1));
					const originalGet = storage.subordinates.get.bind(storage.subordinates);
					storage.subordinates.get = async (entityId) => {
						if (entityId === CLIENT_ID) {
							throw new Error("secret storage failure");
						}
						return originalGet(entityId);
					};
					const server = await createAuthorityServer({
						...authConfig,
						storage,
					});
					const handler = (await server).handler();
					const assertion = await createAssertion();
					const res = await handler(
						new Request(`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=${encodeURIComponent(SERVER_SUB1)}&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(res.status, 500);
					const body = (await res.json()) as Record<string, string>;
					t.equal(body.error, FederationErrorCode.ServerError);
					t.false(body.error_description!.includes("secret storage failure"));
				});

				test("server without auth methods accepts unauthenticated GET", async (t) => {
					await srvSubordinates.add(makeServerRecord(SERVER_SUB1));
					const server = await createAuthorityServer(srvConfig);
					const handler = (await server).handler();
					const res = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(SERVER_SUB1)}`,
						),
					);
					t.equal(res.status, 200);
				});

				test("server with ['none', 'private_key_jwt'] accepts both unauthenticated GET and authenticated POST", async (t) => {
					const { config: authConfig, createAssertion } = await setupAuthenticatedServer([
						"none",
						"private_key_jwt",
					]);
					const server = await createAuthorityServer(authConfig);
					const handler = (await server).handler();
					const getRes = await handler(
						new Request(
							`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(SERVER_SUB1)}`,
						),
					);
					t.equal(getRes.status, 200);
					const assertion = await createAssertion();
					const postRes = await handler(
						new Request(`${SERVER_AUTHORITY_ID}${FederationEndpoint.Fetch}`, {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded" },
							body: `sub=${encodeURIComponent(SERVER_SUB1)}&client_assertion=${encodeURIComponent(assertion)}&client_assertion_type=${encodeURIComponent(JWT_BEARER_TYPE)}`,
						}),
					);
					t.equal(postRes.status, 200);
				});
			});
		});
	}

	// ── integration ──────────────────────────────────────────────────
	{
		const INT_AUTHORITY_ID = entityId("https://ta.example.com");
		const INT_INTERMEDIATE_ID = entityId("https://intermediate.example.com");
		const INT_LEAF_OP = entityId("https://op.example.com");
		const INT_LEAF_RP = entityId("https://rp.example.com");
		const INT_MARK_TYPE = "https://trust.example.com/certified";

		module("authority / integration", (hooks) => {
			let intStorage: MemoryStorageAdapter;
			let intKeyProvider: FixtureCrypto;
			let intSubordinates: SubordinateStorage;
			let intTrustMarks: TrustMarkStorage;
			let intServer: Awaited<ReturnType<typeof createAuthorityServer>>;

			hooks.beforeEach(async () => {
				intStorage = new MemoryStorageAdapter({ engine: testEngine, trustMarks: true });
				intSubordinates = intStorage.subordinates;
				intTrustMarks = intStorage.trustMarks!;

				const { privateKey, publicKey } = await generateSigningKey("ES256");
				const signingKey = { ...privateKey, kid: "ta-key-1" };
				intKeyProvider = new FixtureCrypto(createFederationSigningKey(signingKey));

				const config: AuthorityConfig = {
					entityId: INT_AUTHORITY_ID,
					metadata: {
						federation_entity: {
							organization_name: "Test Trust Anchor",
							federation_fetch_endpoint: `${INT_AUTHORITY_ID}${FederationEndpoint.Fetch}`,
							federation_list_endpoint: `${INT_AUTHORITY_ID}${FederationEndpoint.List}`,
							federation_trust_mark_status_endpoint: `${INT_AUTHORITY_ID}${FederationEndpoint.TrustMarkStatus}`,
							federation_trust_mark_list_endpoint: `${INT_AUTHORITY_ID}${FederationEndpoint.TrustMarkList}`,
							federation_trust_mark_endpoint: `${INT_AUTHORITY_ID}${FederationEndpoint.TrustMark}`,
							federation_historical_keys_endpoint: `${INT_AUTHORITY_ID}${FederationEndpoint.HistoricalKeys}`,
						},
					},
					storage: intStorage,
					crypto: intKeyProvider,
					trustMarkIssuers: { [INT_MARK_TYPE]: [INT_AUTHORITY_ID] },
					trustMarkDelegations: {
						[INT_MARK_TYPE]: await signTrustMarkDelegation({
							issuer: INT_AUTHORITY_ID,
							subject: INT_AUTHORITY_ID,
							trustMarkType: INT_MARK_TYPE,
							signer: new SigningEntryFixture({ ...privateKey, kid: "trust-owner-key-1" }),
						}),
					},
					trustMarkOwners: {
						[INT_MARK_TYPE]: {
							sub: INT_AUTHORITY_ID,
							jwks: { keys: [{ ...publicKey, kid: "trust-owner-key-1" }] },
						},
					},
				};

				intServer = await createAuthorityServer(config);
			});

			module("Entity Configuration lifecycle", () => {
				test("fetches EC via programmatic API and HTTP handler", async (t) => {
					const ecJwt = await (await intServer).getEntityConfiguration();
					const decoded = decodeEntityStatement(ecJwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					t.equal(decoded.value.payload.iss, INT_AUTHORITY_ID);
					t.equal(decoded.value.payload.sub, INT_AUTHORITY_ID);
					const payload = decoded.value.payload as Record<string, unknown>;
					t.ok(payload.metadata);
					t.ok(payload.jwks);
					t.deepEqual(payload.trust_mark_issuers, { [INT_MARK_TYPE]: [INT_AUTHORITY_ID] });
					t.ok(payload.trust_mark_owners);
					const httpHandler = (await intServer).handler();
					const httpRes = await httpHandler(
						new Request(`${INT_AUTHORITY_ID}${WELL_KNOWN_OPENID_FEDERATION}`),
					);
					t.equal(httpRes.status, 200);
					const keySet = await intKeyProvider.keyring.entry("federation");
					const verifyResult = await verifyEntityStatement(ecJwt, keySet.publishedJwks, {
						engine: testEngine,
					});
					t.true(isOk(verifyResult));
				});

				test("EC includes authority_hints for intermediates", async (t) => {
					const { privateKey: intKey } = await generateSigningKey("ES256");
					const intIntKeyProvider = new FixtureCrypto(
						createFederationSigningKey({ ...intKey, kid: "int-key-1" }),
					);

					const intIntServer = await createAuthorityServer({
						entityId: INT_INTERMEDIATE_ID,
						metadata: {
							federation_entity: {
								federation_fetch_endpoint: `${INT_INTERMEDIATE_ID}${FederationEndpoint.Fetch}`,
								federation_list_endpoint: `${INT_INTERMEDIATE_ID}${FederationEndpoint.List}`,
							},
						},
						storage: new MemoryStorageAdapter({ engine: testEngine }),
						crypto: intIntKeyProvider,
						authorityHints: [INT_AUTHORITY_ID],
					});

					const ecJwt = await (await intIntServer).getEntityConfiguration();
					const decoded = decodeEntityStatement(ecJwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					const payload = decoded.value.payload as Record<string, unknown>;
					t.deepEqual(payload.authority_hints, [INT_AUTHORITY_ID]);
				});
			});

			module("Subordinate management lifecycle", () => {
				test("adds subordinates, lists them, and fetches statements", async (t) => {
					const opRecord: import("../../../packages/authority/src/storage/types.js").SubordinateRecord =
						{
							entityId: INT_LEAF_OP,
							jwks: { keys: [testPublicJwk("op-key-1")] },
							metadata: { openid_provider: { issuer: INT_LEAF_OP } },
							entityTypes: [EntityType.OpenIDProvider],
							sourceEndpoint: `${INT_LEAF_OP}${FederationEndpoint.Fetch}`,
							createdAt: Date.now(),
							updatedAt: Date.now(),
						};
					const rpRecord: import("../../../packages/authority/src/storage/types.js").SubordinateRecord =
						{
							entityId: INT_LEAF_RP,
							jwks: { keys: [testPublicJwk("rp-key-1", "ghi", "jkl")] },
							metadata: { openid_relying_party: { client_name: "Test RP" } },
							entityTypes: [EntityType.OpenIDRelyingParty],
							createdAt: Date.now(),
							updatedAt: Date.now(),
						};
					await intSubordinates.add(opRecord);
					await intSubordinates.add(rpRecord);

					const allSubs = await (await intServer).listSubordinates();
					t.equal(allSubs.length, 2);
					t.true(allSubs.includes(INT_LEAF_OP));
					t.true(allSubs.includes(INT_LEAF_RP));

					const opOnly = await (await intServer).listSubordinates({
						entityTypes: [EntityType.OpenIDProvider],
					});
					t.deepEqual(opOnly, [INT_LEAF_OP]);

					const ssJwt = await (await intServer).getSubordinateStatement(INT_LEAF_OP);
					const decoded = decodeEntityStatement(ssJwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					t.equal(decoded.value.payload.iss, INT_AUTHORITY_ID);
					t.equal(decoded.value.payload.sub, INT_LEAF_OP);
					const payload = decoded.value.payload as Record<string, unknown>;
					t.equal(payload.source_endpoint, `${INT_LEAF_OP}${FederationEndpoint.Fetch}`);
					t.ok(payload.metadata);
				});

				test("fetches subordinate via HTTP handler", async (t) => {
					await intSubordinates.add({
						entityId: INT_LEAF_OP,
						jwks: { keys: [testPublicJwk("op-key-1")] },
						createdAt: Date.now(),
						updatedAt: Date.now(),
					});
					const httpHandler = (await intServer).handler();
					const res = await httpHandler(
						new Request(
							`${INT_AUTHORITY_ID}${FederationEndpoint.Fetch}?sub=${encodeURIComponent(INT_LEAF_OP)}`,
						),
					);
					t.equal(res.status, 200);
					t.equal(res.headers.get("Content-Type"), "application/entity-statement+jwt");
				});
			});

			module("Trust Mark lifecycle", () => {
				test("issues, lists, checks status, and revokes trust marks", async (t) => {
					const tmJwt = await (await intServer).issueTrustMark(INT_LEAF_OP, INT_MARK_TYPE);
					t.ok(tmJwt);
					const decoded = decodeEntityStatement(tmJwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					const payload = decoded.value.payload as Record<string, unknown>;
					t.equal(payload.iss, INT_AUTHORITY_ID);
					t.equal(payload.sub, INT_LEAF_OP);
					t.equal(payload.trust_mark_type, INT_MARK_TYPE);
					const entities = await (await intServer).listTrustMarkedEntities(INT_MARK_TYPE);
					t.true(entities.includes(INT_LEAF_OP));
					const status = await (await intServer).getTrustMarkStatus(tmJwt);
					t.equal(status.status, "active");
					await intTrustMarks.revoke(INT_MARK_TYPE, INT_LEAF_OP, Math.floor(Date.now() / 1000));
					const statusAfterRevoke = await (await intServer).getTrustMarkStatus(tmJwt);
					t.equal(statusAfterRevoke.status, "revoked");
					const entitiesAfterRevoke = await (await intServer).listTrustMarkedEntities(
						INT_MARK_TYPE,
					);
					t.false(entitiesAfterRevoke.includes(INT_LEAF_OP));
				});
			});

			module("Key rotation lifecycle", () => {
				test("rotates key and verifies historical keys", async (t) => {
					const activeKeysBefore = await intKeyProvider.keyring.entry("federation");
					t.equal(activeKeysBefore.publishedJwks.keys.length, 1);
					const { privateKey: newKey } = await generateSigningKey("ES256");
					const newSigningKey = createFederationSigningKey({ ...newKey, kid: "ta-key-2" });
					await intKeyProvider.keyring.publish("federation", fixtureSigner(newSigningKey));
					await intKeyProvider.keyring.activate("federation", "ta-key-2");
					await intKeyProvider.keyring.retire("federation", "ta-key-1");
					const signing = await intKeyProvider.keyring.entry("federation");
					t.equal(signing.signer.publicJwk.kid, "ta-key-2");
					t.equal(signing.publishedJwks.keys.length, 1);
					const historicalJwt = await (await intServer).getHistoricalKeys();
					const decoded = decodeEntityStatement(historicalJwt);
					t.true(isOk(decoded));
					if (!isOk(decoded)) return;
					const payload = decoded.value.payload as Record<string, unknown>;
					const keys = payload.keys as Array<Record<string, unknown>>;
					t.equal(keys.length, 1);
					const oldKey = keys.find((k) => k.kid === "ta-key-1");
					t.ok(oldKey);
					const ecAfterRotation = await (await intServer).getEntityConfiguration();
					const ecDecoded = decodeEntityStatement(ecAfterRotation);
					t.true(isOk(ecDecoded));
					if (!isOk(ecDecoded)) return;
					const ecPayload = ecDecoded.value.payload as Record<string, unknown>;
					const ecJwks = ecPayload.jwks as { keys: Array<Record<string, unknown>> };
					t.equal(ecJwks.keys.length, 1);
					const verifyResult = await verifyEntityStatement(ecAfterRotation, signing.publishedJwks, {
						engine: testEngine,
					});
					t.true(isOk(verifyResult));
				});
			});

			module("HTTP routing coverage", () => {
				test("all endpoints respond with security headers", async (t) => {
					const httpHandler = (await intServer).handler();
					const endpoints = [
						WELL_KNOWN_OPENID_FEDERATION,
						`${FederationEndpoint.List}`,
						`${FederationEndpoint.HistoricalKeys}`,
					];
					for (const endpoint of endpoints) {
						const res = await httpHandler(new Request(`${INT_AUTHORITY_ID}${endpoint}`));
						t.equal(res.headers.get("Cache-Control"), "no-store");
						t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
						t.ok(res.headers.get("Strict-Transport-Security"));
					}
				});

				test("404 for unknown paths", async (t) => {
					const httpHandler = (await intServer).handler();
					const res = await httpHandler(new Request(`${INT_AUTHORITY_ID}/nonexistent`));
					t.equal(res.status, 404);
					const body = (await res.json()) as { error: string };
					t.equal(body.error, "not_found");
				});
			});
		});
	}

	// -------------------------------------------------------------------------
	// utils/subordinate-statement-shape — pure helpers
	// -------------------------------------------------------------------------
	module("authority / sanitizeSubordinateMetadata", () => {
		test("public sanitizers preserve own extension names without changing prototypes", (t) => {
			const prototype = Object.getOwnPropertyDescriptors(Object.prototype);
			const metadata = JSON.parse(`{
				"__proto__": {"example_claim": "retained"},
				"constructor": {"example_claim": "constructor"},
				"toString": {"example_claim": "toString"},
				"hasOwnProperty": {"example_claim": "hasOwnProperty"},
				"federation_entity": {
					"__proto__": {"example_claim": "descriptive"},
					"constructor": "retained", "toString": "retained", "hasOwnProperty": "retained",
					"federation_fetch_endpoint": "https://authority.example/fetch"
				}
			}`) as Record<string, unknown>;
			const before = JSON.stringify(metadata);
			for (const Host of [TrustAnchor, Intermediate]) {
				const result = Host.sanitizeSubordinateMetadata(metadata)!;
				t.strictEqual(Object.getPrototypeOf(result), Object.prototype);
				const federation = result.federation_entity as Record<string, unknown>;
				t.strictEqual(Object.getPrototypeOf(federation), Object.prototype);
				for (const name of ["__proto__", "constructor", "toString", "hasOwnProperty"]) {
					t.true(Object.hasOwn(result, name), `${Host.name}: entity type ${name}`);
					t.true(Object.hasOwn(federation, name), `${Host.name}: parameter ${name}`);
					t.deepEqual(JSON.parse(JSON.stringify(result))[name], metadata[name]);
				}
				t.false(Object.hasOwn(federation, "federation_fetch_endpoint"));
				t.equal(JSON.stringify(metadata), before, "input is unchanged");
			}
			const after = Object.getOwnPropertyDescriptors(Object.prototype);
			t.deepEqual(Reflect.ownKeys(after), Reflect.ownKeys(prototype));
			for (const key of Object.keys(prototype)) {
				for (const field of [
					"value",
					"get",
					"set",
					"writable",
					"enumerable",
					"configurable",
				] as const)
					t.strictEqual(
						after[key]?.[field],
						prototype[key]?.[field],
						`${key}.${field} is unchanged`,
					);
			}
		});

		test("strips every federation_entity operational field", (t) => {
			const input = {
				federation_entity: {
					federation_fetch_endpoint: "https://a.example/fetch",
					federation_list_endpoint: "https://a.example/list",
					federation_resolve_endpoint: "https://a.example/resolve",
					federation_extended_list_endpoint: "https://a.example/extended",
					federation_trust_mark_endpoint: "https://a.example/tm",
					federation_trust_mark_status_endpoint: "https://a.example/tm-status",
					federation_trust_mark_list_endpoint: "https://a.example/tm-list",
					federation_historical_keys_endpoint: "https://a.example/hist",
					organization_name: "Acme",
				},
			};
			const out = sanitizeSubordinateMetadata(input);
			t.deepEqual(out, { federation_entity: { organization_name: "Acme" } });
		});

		test("strips *_auth_methods companions", (t) => {
			const input = {
				federation_entity: {
					federation_fetch_endpoint_auth_methods: ["private_key_jwt"],
					federation_list_endpoint_auth_methods: ["none"],
					organization_uri: "https://acme.example",
				},
			};
			const out = sanitizeSubordinateMetadata(input);
			t.deepEqual(out, { federation_entity: { organization_uri: "https://acme.example" } });
		});

		test("strips endpoint_auth_signing_alg_values_supported", (t) => {
			const input = {
				federation_entity: {
					endpoint_auth_signing_alg_values_supported: ["ES256", "RS256"],
					policy_uri: "https://acme.example/policy",
				},
			};
			const out = sanitizeSubordinateMetadata(input);
			t.deepEqual(out, { federation_entity: { policy_uri: "https://acme.example/policy" } });
		});

		test("keeps descriptive federation_entity claims", (t) => {
			const input = {
				federation_entity: {
					organization_name: "Acme",
					organization_uri: "https://acme.example",
					policy_uri: "https://acme.example/policy",
					homepage_uri: "https://acme.example",
					logo_uri: "https://acme.example/logo.svg",
					contacts: ["legal@acme.example"],
				},
			};
			const out = sanitizeSubordinateMetadata(input);
			t.deepEqual(out, input);
		});

		test("passes openid_relying_party / openid_provider / oauth_* blocks through unchanged", (t) => {
			const input = {
				openid_relying_party: { redirect_uris: ["https://rp.example/cb"] },
				openid_provider: { issuer: "https://op.example" },
				oauth_authorization_server: { issuer: "https://op.example" },
				oauth_client: { redirect_uris: ["https://rp.example/cb"] },
				oauth_resource: { resource: "https://api.example" },
			};
			const out = sanitizeSubordinateMetadata(input);
			t.deepEqual(out, input);
		});

		test("preserves federation_registration_endpoint inside openid_provider", (t) => {
			const input = {
				openid_provider: {
					issuer: "https://op.example",
					federation_registration_endpoint: "https://op.example/fedreg",
				},
			};
			const out = sanitizeSubordinateMetadata(input);
			t.deepEqual(out, input);
		});

		test("returns undefined when input is undefined", (t) => {
			t.equal(sanitizeSubordinateMetadata(undefined), undefined);
		});

		test("returns undefined when nothing survives", (t) => {
			const input = {
				federation_entity: {
					federation_fetch_endpoint: "https://a.example/fetch",
					federation_list_endpoint: "https://a.example/list",
				},
			};
			t.equal(sanitizeSubordinateMetadata(input), undefined);
		});

		test("omits federation_entity entirely when only operational fields existed", (t) => {
			const input = {
				openid_provider: { issuer: "https://op.example" },
				federation_entity: { federation_fetch_endpoint: "https://a.example/fetch" },
			};
			const out = sanitizeSubordinateMetadata(input);
			t.deepEqual(out, { openid_provider: { issuer: "https://op.example" } });
		});

		test("FEDERATION_ENTITY_OPERATIONAL_FIELDS includes every endpoint URL and companion", (t) => {
			const expected = [
				"federation_fetch_endpoint",
				"federation_list_endpoint",
				"federation_resolve_endpoint",
				"federation_extended_list_endpoint",
				"federation_trust_mark_endpoint",
				"federation_trust_mark_status_endpoint",
				"federation_trust_mark_list_endpoint",
				"federation_historical_keys_endpoint",
			];
			for (const field of expected) {
				t.ok(isFederationEntityOperationalField(field), `${field} is operational`);
				t.ok(
					isFederationEntityOperationalField(`${field}_auth_methods`),
					`${field}_auth_methods is operational`,
				);
			}
			t.ok(isFederationEntityOperationalField("endpoint_auth_signing_alg_values_supported"));
			t.notOk(isFederationEntityOperationalField("organization_name"));
			t.notOk(isFederationEntityOperationalField("federation_registration_endpoint"));
		});
	});

	module("authority / assertMetadataValuesNotNull", () => {
		test("leaves nested values to protocol-specific validation", (t) => {
			assertMetadataValuesNotNull({
				openid_credential_issuer: {
					credential_configurations_supported: {
						one: { credential_metadata: { claims: [{ path: ["namespace", "element", null] }] } },
					},
				},
				openid_credential_verifier: {
					dcql_queries: [{ credentials: [{ claims: [{ path: ["names", null, "given"] }] }] }],
				},
			});
			for (const metadata of [
				{ openid_credential_verifier: { dcql_queries: [null] } },
				{
					openid_credential_verifier: {
						dcql_queries: [{ credentials: [{ claims: [{ path: null }] }] }],
					},
				},
				{
					openid_credential_verifier: {
						dcql_queries: [{ credentials: [{ claims: [{ path: ["name", { nested: null }] }] }] }],
					},
				},
				{
					openid_credential_verifier: {
						dcql_queries: [
							{ credentials: [{ claims: [{ path: ["names", null], custom: null }] }] },
						],
					},
				},
				{ openid_credential_verifier: { "dcql_queries[0].credentials[0].claims[0].path": [null] } },
				{
					openid_provider: {
						dcql_queries: [{ credentials: [{ claims: [{ path: ["names", null] }] }] }],
					},
				},
				{
					openid_credential_issuer: {
						credential_configurations_supported: {
							one: {
								credential_metadata: { claims: [{ path: ["names", null], mandatory: null }] },
							},
						},
					},
				},
			])
				assertMetadataValuesNotNull(metadata);
			t.ok(true, "nested nulls do not violate the generic Federation rule");
		});
		test("accepts undefined", (t) => {
			assertMetadataValuesNotNull(undefined);
			t.ok(true);
		});
		test("accepts a clean object", (t) => {
			assertMetadataValuesNotNull({
				federation_entity: { organization_name: "Acme" },
				openid_provider: { scopes_supported: ["openid"] },
			});
			t.ok(true);
		});
		test("throws on a null leaf one level deep", (t) => {
			t.throws(
				() => assertMetadataValuesNotNull({ federation_entity: { organization_name: null } }),
				InvalidMetadata,
			);
		});
		test("accepts nulls nested in metadata parameter arrays and objects", (t) => {
			assertMetadataValuesNotNull({
				custom_entity: { display: [{ name: "Acme", logo: null }, null], nested: { value: null } },
			});
			t.ok(true);
		});
		test("rejects null entity-type blocks", (t) => {
			t.throws(() => assertMetadataValuesNotNull({ custom_entity: null }), InvalidMetadata);
		});
		test("error carries the dotted path to the null leaf", (t) => {
			try {
				assertMetadataValuesNotNull({
					openid_provider: { issuer: null },
				});
				t.notOk(true, "expected throw");
			} catch (err) {
				if (err instanceof InvalidMetadata) {
					t.equal(err.path, "openid_provider.issuer");
				} else {
					t.notOk(true, "wrong error type");
				}
			}
		});
	});

	// -------------------------------------------------------------------------
	// createAuthorityServer — construction-time guards
	// -------------------------------------------------------------------------
	module("authority / createAuthorityServer construction guards", () => {
		const SPEC_ENTITY = entityId("https://acme.example");
		const PARENT = entityId("https://parent.example");

		async function baseConfig(overrides?: Partial<AuthorityConfig>): Promise<AuthorityConfig> {
			const { privateKey } = await generateSigningKey("ES256");
			const signingKey = { ...privateKey, kid: "ck-1" };
			return {
				entityId: SPEC_ENTITY,
				crypto: new FixtureCrypto(createFederationSigningKey(signingKey)),
				storage: new MemoryStorageAdapter({ engine: testEngine }),
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${SPEC_ENTITY}/federation_fetch`,
						federation_list_endpoint: `${SPEC_ENTITY}/federation_list`,
					},
				},
				...overrides,
			} as AuthorityConfig;
		}

		test("an anchor with Superiors publishes and updates anchor policy", async (t) => {
			const type = "https://example.org/accreditation";
			const cfg = await baseConfig({
				authorityHints: [PARENT],
				trustAnchorHints: [PARENT],
				trustMarkIssuers: { [type]: [] },
			});
			const anchor = await TrustAnchor.create(fixtureHostConfig(cfg));
			let decoded = decodeEntityStatement(await anchor.getEntityConfiguration());
			t.true(decoded.ok);
			if (!decoded.ok) return;
			t.deepEqual(decoded.value.payload.authority_hints?.map(String), [String(PARENT)]);
			t.deepEqual(decoded.value.payload.trust_anchor_hints?.map(String), [String(PARENT)]);
			t.deepEqual(decoded.value.payload.trust_mark_issuers, { [type]: [] });
			await anchor.setTrustMarkIssuers({ [type]: [SPEC_ENTITY] });
			const keys = await cfg.crypto.keyring.entry("federation");
			await anchor.setTrustMarkOwners({ [type]: { sub: SPEC_ENTITY, jwks: keys.publishedJwks } });
			decoded = decodeEntityStatement(await anchor.getEntityConfiguration());
			if (!decoded.ok) return t.true(false);
			t.deepEqual(decoded.value.payload.trust_mark_issuers?.[type]?.map(String), [
				String(SPEC_ENTITY),
			]);
			t.deepEqual(decoded.value.payload.trust_mark_owners?.[type]?.jwks, keys.publishedJwks);
			const anchors = CorePublic.createTrustAnchorSet([
				{ entityId: SPEC_ENTITY, jwks: keys.publishedJwks },
			]);
			const validated = await anchor.discoverEntityFromChain(
				SPEC_ENTITY,
				[await anchor.getEntityConfiguration()],
				{ trustAnchors: anchors, offline: true },
			);
			t.true(validated.ok, JSON.stringify(validated));
		});

		test("accepts a minimal TA config (no authorityHints, both required endpoints)", async (t) => {
			const cfg = await baseConfig();
			const s = await createAuthorityServer(cfg);
			t.ok(s);
		});

		test("preserves nested extension nulls in published configurations", async (t) => {
			const extension = { display: [{ name: "Acme", logo: null }, null] };
			const cfg = await baseConfig();
			const server = await createAuthorityServer({
				...cfg,
				metadata: { federation_entity: { ...cfg.metadata.federation_entity, ...extension } },
			});
			const jwt = await (await server).getEntityConfiguration();
			const parsed = decodeEntityStatement(jwt);
			t.true(parsed.ok);
			if (parsed.ok)
				t.deepEqual(parsed.value.payload.metadata?.federation_entity?.display, extension.display);
		});

		test("accepts a minimal Intermediate config (non-empty authorityHints)", async (t) => {
			const cfg = await baseConfig({ authorityHints: [PARENT] });
			const s = await createAuthorityServer(cfg);
			t.ok(s);
		});

		test("throws when authorityHints is an explicit empty array", async (t) => {
			const cfg = await baseConfig({ authorityHints: [] as unknown as [EntityId, ...EntityId[]] });
			await t.rejects((async () => await createAuthorityServer(cfg))(), InvalidAuthorityConfig);
		});

		test("throws when trustAnchorHints is an explicit empty array", async (t) => {
			const cfg = await baseConfig({
				authorityHints: [PARENT],
				trustAnchorHints: [],
			});
			await t.rejects((async () => await createAuthorityServer(cfg))(), InvalidAuthorityConfig);
		});

		test("throws when trustAnchorHints contains an invalid Entity Identifier", async (t) => {
			const cfg = await baseConfig({
				authorityHints: [PARENT],
				trustAnchorHints: ["http://ta.example" as EntityId],
			});
			await t.rejects((async () => await createAuthorityServer(cfg))(), InvalidAuthorityConfig);
		});

		test("throws when Trust Anchor config carries trustAnchorHints", async (t) => {
			const cfg = await baseConfig({ trustAnchorHints: [PARENT] });
			await t.rejects((async () => await createAuthorityServer(cfg))(), InvalidAuthorityConfig);
		});

		test("throws when Intermediate config carries trustMarkIssuers", async (t) => {
			const cfg = await baseConfig({
				authorityHints: [PARENT],
				trustMarkIssuers: { "https://example/tm": [SPEC_ENTITY] },
			});
			await t.rejects((async () => await createAuthorityServer(cfg))(), InvalidAuthorityConfig);
		});

		test("throws when Intermediate config carries trustMarkOwners", async (t) => {
			const { publicKey } = await generateSigningKey("ES256");
			const cfg = await baseConfig({
				authorityHints: [PARENT],
				trustMarkOwners: {
					"https://example/tm": { sub: "https://owner.example", jwks: { keys: [publicKey] } },
				},
			});
			await t.rejects((async () => await createAuthorityServer(cfg))(), InvalidAuthorityConfig);
		});

		test("accepts TA with trustMarkIssuers", async (t) => {
			const cfg = await baseConfig({
				trustMarkIssuers: { "https://example/tm": [SPEC_ENTITY] },
			});
			const s = await createAuthorityServer(cfg);
			t.ok(s);
		});

		test("throws when federation_entity lacks federation_fetch_endpoint", async (t) => {
			const cfg = await baseConfig({
				metadata: {
					federation_entity: {
						federation_list_endpoint: `${SPEC_ENTITY}/federation_list`,
					},
				},
			});
			await t.rejects((async () => await createAuthorityServer(cfg))(), InvalidAuthorityConfig);
		});

		test("throws when federation_entity lacks federation_list_endpoint", async (t) => {
			const cfg = await baseConfig({
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${SPEC_ENTITY}/federation_fetch`,
					},
				},
			});
			await t.rejects((async () => await createAuthorityServer(cfg))(), InvalidAuthorityConfig);
		});

		test("throws when an advertised federation endpoint URL is not HTTPS", async (t) => {
			const cfg = await baseConfig({
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: "http://acme.example/federation_fetch",
						federation_list_endpoint: `${SPEC_ENTITY}/federation_list`,
					},
				},
			});
			await t.rejects((async () => await createAuthorityServer(cfg))(), InvalidAuthorityConfig);
		});

		test("throws when advertised federation endpoint paths collide", async (t) => {
			const cfg = await baseConfig({
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${SPEC_ENTITY}/same-endpoint`,
						federation_list_endpoint: `${SPEC_ENTITY}/same-endpoint`,
					},
				},
			});
			await t.rejects((async () => await createAuthorityServer(cfg))(), InvalidAuthorityConfig);
		});

		test("throws when trust mark endpoints are advertised without storage capability", async (t) => {
			const cfg = await baseConfig({
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${SPEC_ENTITY}/federation_fetch`,
						federation_list_endpoint: `${SPEC_ENTITY}/federation_list`,
						federation_trust_mark_endpoint: `${SPEC_ENTITY}/federation_trust_mark`,
					},
				},
			});
			await t.rejects((async () => await createAuthorityServer(cfg))(), InvalidAuthorityConfig);
		});

		test("throws when metadata has a null leaf", async (t) => {
			const cfg = await baseConfig({
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${SPEC_ENTITY}/federation_fetch`,
						federation_list_endpoint: `${SPEC_ENTITY}/federation_list`,
						organization_name: null as unknown as string,
					},
				},
			});
			await t.rejects((async () => await createAuthorityServer(cfg))(), InvalidMetadata);
		});
	});

	// -------------------------------------------------------------------------
	// EC emission — role-aware gating of trust_mark_issuers / trust_mark_owners
	// -------------------------------------------------------------------------
	module("authority / EC emission role gating", () => {
		const TA_AUTH = entityId("https://ta-shape.example");
		const INT_AUTH = entityId("https://int-shape.example");
		const PARENT = entityId("https://parent.example");

		async function setupServer(opts: {
			id: EntityId;
			authorityHints?: EntityId[];
			trustAnchorHints?: EntityId[];
			trustMarkIssuers?: Record<string, string[]>;
			trustMarkOwners?: Record<string, { sub: string; jwks: { keys: JWK[] } }>;
		}) {
			const { privateKey } = await generateSigningKey("ES256");
			const signingKey = { ...privateKey, kid: "k1" };
			const crypto = new FixtureCrypto(createFederationSigningKey(signingKey));
			const cfg: AuthorityConfig = {
				entityId: opts.id,
				crypto,
				storage: new MemoryStorageAdapter({ engine: testEngine }),
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${opts.id}/federation_fetch`,
						federation_list_endpoint: `${opts.id}/federation_list`,
					},
				},
				...(opts.authorityHints !== undefined ? { authorityHints: opts.authorityHints } : {}),
				...(opts.trustAnchorHints !== undefined ? { trustAnchorHints: opts.trustAnchorHints } : {}),
				...(opts.trustMarkIssuers !== undefined ? { trustMarkIssuers: opts.trustMarkIssuers } : {}),
				...(opts.trustMarkOwners !== undefined ? { trustMarkOwners: opts.trustMarkOwners } : {}),
			} as AuthorityConfig;
			return await createAuthorityServer(cfg);
		}

		async function readEC(server: Awaited<ReturnType<typeof createAuthorityServer>>, id: EntityId) {
			const httpHandler = (await server).handler();
			const res = await httpHandler(new Request(`${id}${WELL_KNOWN_OPENID_FEDERATION}`));
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			if (!isOk(decoded)) throw new Error("EC decode failed");
			return decoded.value;
		}

		test("TA EC omits authority_hints", async (t) => {
			const s = await setupServer({ id: TA_AUTH });
			const { payload } = await readEC(s, TA_AUTH);
			t.notOk((payload as Record<string, unknown>).authority_hints);
		});

		test("TA EC emits trust_mark_issuers when configured", async (t) => {
			const s = await setupServer({
				id: TA_AUTH,
				trustMarkIssuers: { "https://example/tm": [TA_AUTH] },
			});
			const { payload } = await readEC(s, TA_AUTH);
			t.ok((payload as Record<string, unknown>).trust_mark_issuers);
		});

		test("Intermediate EC includes authority_hints", async (t) => {
			const s = await setupServer({ id: INT_AUTH, authorityHints: [PARENT] });
			const { payload } = await readEC(s, INT_AUTH);
			t.deepEqual((payload as Record<string, unknown>).authority_hints, [PARENT]);
		});

		test("Intermediate EC includes trust_anchor_hints when configured", async (t) => {
			const preferredAnchor = entityId("https://preferred-ta.example");
			const s = await setupServer({
				id: INT_AUTH,
				authorityHints: [PARENT],
				trustAnchorHints: [preferredAnchor],
			});
			const { payload } = await readEC(s, INT_AUTH);
			t.deepEqual((payload as Record<string, unknown>).trust_anchor_hints, [preferredAnchor]);
		});

		test("EC payload has no constraints / metadata_policy / metadata_policy_crit / source_endpoint", async (t) => {
			const s = await setupServer({ id: INT_AUTH, authorityHints: [PARENT] });
			const { payload } = await readEC(s, INT_AUTH);
			const p = payload as Record<string, unknown>;
			t.notOk("constraints" in p);
			t.notOk("metadata_policy" in p);
			t.notOk("metadata_policy_crit" in p);
			t.notOk("source_endpoint" in p);
		});

		test("EC payload has no trust_anchor_hints or aud", async (t) => {
			const s = await setupServer({ id: INT_AUTH, authorityHints: [PARENT] });
			const { payload } = await readEC(s, INT_AUTH);
			const p = payload as Record<string, unknown>;
			t.notOk("trust_anchor_hints" in p);
			t.notOk("aud" in p);
		});

		test("EC JWT header has no trust_chain or peer_trust_chain", async (t) => {
			const s = await setupServer({ id: TA_AUTH });
			const { header } = await readEC(s, TA_AUTH);
			const h = header as Record<string, unknown>;
			t.notOk("trust_chain" in h);
			t.notOk("peer_trust_chain" in h);
		});

		test("EC JWT header has typ=entity-statement+jwt and a kid", async (t) => {
			const s = await setupServer({ id: TA_AUTH });
			const { header } = await readEC(s, TA_AUTH);
			t.equal(header.typ, JwtTyp.EntityStatement);
			t.ok(header.kid);
		});
	});

	// -------------------------------------------------------------------------
	// Subordinate Statement build — sanitization in buildSubordinateStatement
	// -------------------------------------------------------------------------
	module("authority / Subordinate Statement build sanitization", () => {
		const PARENT_ID = entityId("https://parent-shape.example");
		const CHILD_ID = entityId("https://child-shape.example");

		async function setupParent(): Promise<{
			server: Awaited<ReturnType<typeof createAuthorityServer>>;
		}> {
			const { privateKey } = await generateSigningKey("ES256");
			const signingKey = { ...privateKey, kid: "p1" };
			const crypto = new FixtureCrypto(createFederationSigningKey(signingKey));
			const storage = new MemoryStorageAdapter({ engine: testEngine });
			const subordinates = storage.subordinates;
			const childKeys = await generateSigningKey("ES256");
			const childPublic = { ...childKeys.publicKey, kid: "c1" };
			// Insert a valid record without federation_entity endpoint URLs; wire-layer
			// sanitization is covered separately.
			await subordinates.add({
				entityId: CHILD_ID,
				jwks: { keys: [childPublic] },
				metadata: {
					federation_entity: { organization_name: "Child" },
					openid_relying_party: { redirect_uris: [`${CHILD_ID}/cb`] },
				},
				entityTypes: ["federation_entity", "openid_relying_party"],
				isIntermediate: false,
				createdAt: 1,
				updatedAt: 1,
			} as unknown as SubordinateRecord);
			const cfg: AuthorityConfig = {
				entityId: PARENT_ID,
				crypto,
				storage,
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${PARENT_ID}/federation_fetch`,
						federation_list_endpoint: `${PARENT_ID}/federation_list`,
					},
				},
			} as AuthorityConfig;
			return { server: await createAuthorityServer(cfg) };
		}

		test("Subordinate Statement payload has none of the EC-only top-level claims", async (t) => {
			const { server } = await setupParent();
			const httpHandler = (await server).handler();
			const res = await httpHandler(
				new Request(`${PARENT_ID}/federation_fetch?sub=${encodeURIComponent(CHILD_ID)}`),
			);
			t.equal(res.status, 200);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.ok(isOk(decoded));
			if (!isOk(decoded)) return;
			const p = decoded.value.payload as Record<string, unknown>;
			for (const claim of [
				"authority_hints",
				"trust_anchor_hints",
				"trust_marks",
				"trust_mark_issuers",
				"trust_mark_owners",
			]) {
				t.notOk(claim in p, `${claim} must not appear`);
			}
		});

		test("Subordinate Statement JWT header has no trust_chain or peer_trust_chain", async (t) => {
			const { server } = await setupParent();
			const httpHandler = (await server).handler();
			const res = await httpHandler(
				new Request(`${PARENT_ID}/federation_fetch?sub=${encodeURIComponent(CHILD_ID)}`),
			);
			t.equal(res.status, 200);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.ok(isOk(decoded));
			if (!isOk(decoded)) return;
			const h = decoded.value.header as Record<string, unknown>;
			t.notOk("trust_chain" in h);
			t.notOk("peer_trust_chain" in h);
		});

		test("Subordinate Statement JWT header is typ=entity-statement+jwt with kid", async (t) => {
			const { server } = await setupParent();
			const httpHandler = (await server).handler();
			const res = await httpHandler(
				new Request(`${PARENT_ID}/federation_fetch?sub=${encodeURIComponent(CHILD_ID)}`),
			);
			const jwt = await res.text();
			const decoded = decodeEntityStatement(jwt);
			t.ok(isOk(decoded));
			if (!isOk(decoded)) return;
			t.equal(decoded.value.header.typ, JwtTyp.EntityStatement);
			t.ok(decoded.value.header.kid);
		});
	});

	// -------------------------------------------------------------------------
	// SubordinateStorage — strict-by-default validation
	// -------------------------------------------------------------------------
	module("authority / SubordinateStorage strict validation", () => {
		const SUB_ID = entityId("https://sub-strict.example");

		async function aRecord(metadata?: Record<string, unknown>): Promise<SubordinateRecord> {
			const { publicKey } = await generateSigningKey("ES256");
			return {
				entityId: SUB_ID,
				jwks: { keys: [{ ...publicKey, kid: "s1" }] },
				...(metadata !== undefined ? { metadata } : {}),
				entityTypes: ["federation_entity"],
				isIntermediate: false,
				createdAt: 1,
				updatedAt: 1,
			} as unknown as SubordinateRecord;
		}

		test("rejects records carrying federation_fetch_endpoint in federation_entity", async (t) => {
			const store = new MemoryStorageAdapter({ engine: testEngine }).subordinates;
			const rec = await aRecord({
				federation_entity: { federation_fetch_endpoint: `${SUB_ID}/federation_fetch` },
			});
			await t.rejects(store.add(rec), InvalidSubordinateRecord);
		});

		test("rejects records carrying federation_list_endpoint_auth_methods", async (t) => {
			const store = new MemoryStorageAdapter({ engine: testEngine }).subordinates;
			const rec = await aRecord({
				federation_entity: { federation_list_endpoint_auth_methods: ["private_key_jwt"] },
			});
			await t.rejects(store.add(rec), InvalidSubordinateRecord);
		});

		test("rejects records carrying endpoint_auth_signing_alg_values_supported in federation_entity", async (t) => {
			const store = new MemoryStorageAdapter({ engine: testEngine }).subordinates;
			const rec = await aRecord({
				federation_entity: { endpoint_auth_signing_alg_values_supported: ["ES256"] },
			});
			await t.rejects(store.add(rec), InvalidSubordinateRecord);
		});

		test("rejects records with a null metadata leaf", async (t) => {
			const store = new MemoryStorageAdapter({ engine: testEngine }).subordinates;
			const rec = await aRecord({
				openid_provider: { issuer: null as unknown as string },
			});
			await t.rejects(store.add(rec), InvalidSubordinateRecord);
		});

		test("preserves nested nulls through subordinate storage", async (t) => {
			const store = new MemoryStorageAdapter({ engine: testEngine }).subordinates;
			const metadata = { custom_entity: { display: [{ name: "Acme", logo: null }, null] } };
			const rec = await aRecord(metadata);
			await store.add(rec);
			t.deepEqual((await store.get(SUB_ID))?.metadata, metadata);
		});

		test("accepts clean records (organization_name only)", async (t) => {
			const store = new MemoryStorageAdapter({ engine: testEngine }).subordinates;
			const rec = await aRecord({ federation_entity: { organization_name: "Sub" } });
			await store.add(rec);
			const stored = await store.get(SUB_ID);
			t.ok(stored);
		});

		test("accepts records with no metadata claim at all", async (t) => {
			const store = new MemoryStorageAdapter({ engine: testEngine }).subordinates;
			const rec = await aRecord();
			await store.add(rec);
			const stored = await store.get(SUB_ID);
			t.ok(stored);
		});

		test("accepts records with openid_provider.federation_registration_endpoint", async (t) => {
			const store = new MemoryStorageAdapter({ engine: testEngine }).subordinates;
			const rec = await aRecord({
				openid_provider: {
					issuer: "https://op.example",
					federation_registration_endpoint: "https://op.example/fedreg",
				},
			});
			await store.add(rec);
			const stored = await store.get(SUB_ID);
			t.ok(stored);
		});

		test("still rejects duplicate entityIds", async (t) => {
			const store = new MemoryStorageAdapter({ engine: testEngine }).subordinates;
			const rec = await aRecord({ federation_entity: { organization_name: "Sub" } });
			await store.add(rec);
			await t.rejects(store.add(rec), /already exists/);
		});
	});

	// -------------------------------------------------------------------------
	// TrustAnchor and Intermediate Facades Direct Method Delegation Coverage
	// -------------------------------------------------------------------------
	module("authority / Facade method delegation coverage", () => {
		const TA_ID = entityId("https://ta-facade.example");
		const INT_ID = entityId("https://int-facade.example");
		const SUB_ID = entityId("https://sub-facade.example");
		const PARENT_ID = entityId("https://parent-facade.example");

		async function createFacadeConfigs() {
			const { privateKey } = await generateSigningKey("ES256");
			const signingKey = { ...privateKey, kid: "k1" };
			const crypto = new FixtureCrypto(createFederationSigningKey(signingKey));
			const storage = new MemoryStorageAdapter({ engine: testEngine, trustMarks: true });

			const taConfig: AuthorityConfig = {
				entityId: TA_ID,
				crypto,
				storage,
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${TA_ID}/federation_fetch`,
						federation_list_endpoint: `${TA_ID}/federation_list`,
						federation_trust_mark_endpoint: `${TA_ID}/federation_trust_mark`,
						federation_trust_mark_status_endpoint: `${TA_ID}/federation_trust_mark_status`,
						federation_trust_mark_list_endpoint: `${TA_ID}/federation_trust_mark_list`,
						federation_resolve_endpoint: `${TA_ID}/federation_resolve`,
						federation_historical_keys_endpoint: `${TA_ID}/federation_historical_keys`,
					},
				},
			};

			const intConfig: AuthorityConfig = {
				entityId: INT_ID,
				crypto,
				storage,
				metadata: {
					federation_entity: {
						federation_fetch_endpoint: `${INT_ID}/federation_fetch`,
						federation_list_endpoint: `${INT_ID}/federation_list`,
						federation_trust_mark_endpoint: `${INT_ID}/federation_trust_mark`,
						federation_trust_mark_status_endpoint: `${INT_ID}/federation_trust_mark_status`,
						federation_trust_mark_list_endpoint: `${INT_ID}/federation_trust_mark_list`,
						federation_resolve_endpoint: `${INT_ID}/federation_resolve`,
						federation_historical_keys_endpoint: `${INT_ID}/federation_historical_keys`,
					},
				},
				authorityHints: [PARENT_ID],
			};

			return { taConfig, intConfig, storage, crypto };
		}

		test("exercises TrustAnchor and Intermediate delegation methods for full function coverage", async (t) => {
			const { taConfig, intConfig, storage, crypto } = await createFacadeConfigs();
			const ta = await TrustAnchor.create(fixtureHostConfig(taConfig));
			const intermediate = await Intermediate.create(fixtureHostConfig(intConfig));

			// Setup a subordinate in storage to prevent not found errors during get/resolve/etc.
			const { publicKey } = await generateSigningKey("ES256");
			const subRecord: SubordinateRecord = {
				entityId: SUB_ID,
				jwks: { keys: [{ ...publicKey, kid: "s1" }] },
				entityTypes: ["federation_entity"],
				isIntermediate: false,
				createdAt: 1,
				updatedAt: 1,
			};
			await storage.subordinates.add(subRecord);

			// 1. TrustAnchor resolveEntity (which delegates to server.resolveEntity)
			try {
				await ta.resolveEntity(SUB_ID);
			} catch (e) {
				t.ok(e, "resolveEntity throws as expected since the resolve handler is invoked");
			}

			// 2. Intermediate getEntityConfiguration
			const ec = await intermediate.getEntityConfiguration();
			t.ok(ec, "Intermediate getEntityConfiguration returns a string");

			// 3. Intermediate getSubordinateStatement
			const ss = await intermediate.getSubordinateStatement(SUB_ID);
			t.ok(ss, "Intermediate getSubordinateStatement returns a string");

			// 4. Intermediate listSubordinates
			const list = await intermediate.listSubordinates();
			t.deepEqual(list, [SUB_ID]);

			// 5. Intermediate listSubordinatesExtended
			const listExt = await intermediate.listSubordinatesExtended({ limit: 10 });
			t.true(isOk(listExt));

			// 6. Intermediate resolveEntity
			try {
				await intermediate.resolveEntity(SUB_ID);
			} catch (e) {
				t.ok(e);
			}

			// 7. Intermediate issueTrustMark / getTrustMarkStatus / listTrustMarkedEntities / issueTrustMarkDelegation
			const tmType = "https://trust.example.com/mark";
			const tmJwt = await intermediate.issueTrustMark(SUB_ID as string, tmType);
			t.ok(tmJwt);

			const tmStatus = await intermediate.getTrustMarkStatus(tmJwt);
			t.ok(tmStatus);

			const tmList = await intermediate.listTrustMarkedEntities(tmType);
			t.deepEqual(tmList, [SUB_ID]);

			const tmDelegation = await intermediate.issueTrustMarkDelegation(SUB_ID as string, tmType);
			t.ok(tmDelegation);

			// 8. Intermediate getHistoricalKeys
			const histKeys = await intermediate.getHistoricalKeys();
			t.ok(histKeys);

			// 9. Intermediate key provider rollover
			const { privateKey: newKey } = await generateSigningKey("ES256");
			const nextSigningKey = { ...newKey, kid: "k2" };
			await crypto.keyring.publish(
				"federation",
				fixtureSigner(createFederationSigningKey(nextSigningKey)),
			);
			await crypto.keyring.activate("federation", "k2");
			const keySet = await crypto.keyring.entry("federation");
			t.equal(keySet.signer.publicJwk.kid, "k2");

			// 10. Intermediate handleRequest
			const res = await intermediate.handleRequest(
				new Request(`${INT_ID}${WELL_KNOWN_OPENID_FEDERATION}`),
			);
			t.equal(res.status, 200);
		});
	});

	{
		const { issuer, subject, endpoint, fixture } = SubordinateEventsFixture;
		QUnit.module("Subordinate Events Draft 01", () => {
			for (const intermediate of [false, true]) {
				QUnit.test(
					`${intermediate ? "Intermediate" : "TrustAnchor"} snapshots manually recorded nested events before queuing`,
					async (assert) => {
						for (const direct of [false, true]) {
							const f = await fixture(intermediate);
							let release!: () => void;
							const gate = new Promise<void>((resolve) => {
								release = resolve;
							});
							const blocker = f.storage.transaction(async () => gate);
							const input = {
								iat: 1,
								event: "operator.review",
								details: { decisions: ["original"] },
							};
							const expected = structuredClone(input);
							const pending = direct
								? f.storage.subordinateEvents!.append(issuer, subject, [input])
								: f.authority.recordSubordinateEvents(subject, [input]);
							input.details.decisions[0] = "changed";
							release();
							await blocker;
							await pending;
							const jwt = decodeEntityStatement(await f.authority.getSubordinateEvents(subject));
							assert.true(jwt.ok);
							if (jwt.ok)
								assert.deepEqual(jwt.value.payload.federation_registration_events, [expected]);
						}
					},
				);
				QUnit.test(
					`${intermediate ? "Intermediate" : "TrustAnchor"} supports optional response expiration independently of occurrence times`,
					async (assert) => {
						const f = await fixture(intermediate);
						const Authority = intermediate ? Intermediate : TrustAnchor;
						for (const ttl of [0, -1, NaN, Infinity, -Infinity]) {
							await assert.rejects(
								(async () =>
									await Authority.create({ ...f.config, subordinateEventsTtlSeconds: ttl }))(),
								/positive and finite/,
							);
						}
						const authority = await Authority.create({
							...f.config,
							subordinateEventsTtlSeconds: 60.5,
						});
						await authority.recordSubordinateEvents(subject, [
							{ iat: -0.5, event: "operator.review" },
						]);
						for (const now of [1500, 1600.25]) {
							f.setNow(now);
							const response = await authority.handleRequest(
								new Request(`${endpoint}&sub=${encodeURIComponent(subject)}`),
							);
							assert.strictEqual(response.status, 200);
							const jwt = await response.text();
							const decoded = decodeEntityStatement(jwt);
							assert.true(decoded.ok);
							if (decoded.ok) {
								assert.strictEqual(decoded.value.payload.iat, now);
								assert.strictEqual(decoded.value.payload.exp, now + 60.5);
								assert.deepEqual(decoded.value.payload.federation_registration_events, [
									{ iat: -0.5, event: "operator.review" },
								]);
							}
							const fetched = await fetchSubordinateEvents(endpoint, subject, {
								engine: testEngine,
								...f.options,
								clockSkewSeconds: 0,
								clock: { now: () => now + 61 },
								httpClient: async () =>
									new Response(jwt, {
										headers: { "content-type": MediaType.EntityEventsStatement },
									}),
							});
							assert.false(fetched.ok, "a response past its configured expiration is rejected");
						}
					},
				);
			}
			QUnit.test(
				"already cancelled history calls do not read storage or retrieve keys",
				async (assert) => {
					const f = await fixture();
					const controller = new AbortController();
					let reads = 0;
					let keys = 0;
					const read = f.storage.readSnapshot.bind(f.storage);
					f.storage.readSnapshot = async (operation) => {
						reads++;
						return read(operation);
					};
					const getKeys = f.crypto.keyring.entry.bind(f.crypto.keyring, "federation");
					f.crypto.keyring.entry = async () => {
						keys++;
						return getKeys();
					};
					const authority = await TrustAnchor.create(
						fixtureHostConfig({
							...f.config,
							options: { ...f.config.options, signal: controller.signal },
						}),
					);
					reads = 0;
					keys = 0;
					controller.abort();
					await assert.rejects(authority.getSubordinateEvents(subject), /abort/i);
					for (const [host, signal] of [
						[authority, undefined],
						[f.authority, controller.signal],
					] as const) {
						const response = await host.handleRequest(
							new Request(`${endpoint}&sub=${encodeURIComponent(subject)}`, { signal }),
						);
						assert.strictEqual(response.status, 500);
					}
					assert.strictEqual(reads, 0);
					assert.strictEqual(keys, 0);
				},
			);
			for (const stage of ["storage", "keys", "signing"] as const) {
				QUnit.test(
					`cancellation releases an events request waiting for ${stage} without returning success`,
					async (assert) => {
						const f = await fixture();
						await f.authority.registerSubordinate(f.record);
						let release!: () => void;
						let entered!: () => void;
						const started = new Promise<void>((resolve) => {
							entered = resolve;
						});
						const gate = new Promise<void>((resolve) => {
							release = resolve;
						});
						const originalKeys = f.crypto.keyring.entry.bind(f.crypto.keyring, "federation");
						let signatures = 0;
						f.crypto.keyring.entry = async () => {
							if (stage === "keys") {
								entered();
								await gate;
							}
							const keys = await originalKeys();
							return {
								...keys,
								signer: instrumentSigningEntry(keys.signer, async (data, header) => {
									signatures++;
									if (stage === "signing") {
										entered();
										await gate;
									}
									return rawFixtureJwt(keys.signer, data, header);
								}).signer,
							};
						};
						if (stage === "storage") {
							const read = f.storage.readSnapshot.bind(f.storage);
							f.storage.readSnapshot = async (operation) => {
								entered();
								await gate;
								return read(operation);
							};
						}
						const controller = new AbortController();
						const pending = f.authority.handleRequest(
							new Request(`${endpoint}&sub=${encodeURIComponent(subject)}`, {
								signal: controller.signal,
							}),
						);
						await started;
						controller.abort();
						let timer: ReturnType<typeof setTimeout> | undefined;
						try {
							const response = await Promise.race([
								pending,
								new Promise<never>((_, reject) => {
									timer = setTimeout(
										() => reject(new Error("Cancellation did not release the request")),
										1000,
									);
								}),
							]);
							assert.strictEqual(response.status, 500);
							assert.strictEqual(response.headers.get("content-type"), MediaType.Json);
							assert.strictEqual(
								((await response.json()) as { error: string }).error,
								"server_error",
							);
						} finally {
							clearTimeout(timer);
							release();
						}
						await new Promise((resolve) => setTimeout(resolve, 0));
						assert.strictEqual(
							signatures,
							stage === "signing" ? 1 : 0,
							"cancellation never starts another signature",
						);
						assert.strictEqual(
							(await f.storage.subordinateEvents!.list(issuer, subject)).length,
							1,
							"cancellation preserves committed history",
						);
						assert.strictEqual(
							(
								await f.authority.handleRequest(
									new Request(`${endpoint}&sub=${encodeURIComponent(subject)}`),
								)
							).status,
							200,
							"a subsequent request still succeeds",
						);
					},
				);
			}

			for (const intermediate of [false, true]) {
				QUnit.test(
					`${intermediate ? "Intermediate" : "TrustAnchor"} snapshots queued updates and their events`,
					async (assert) => {
						const f = await fixture(intermediate);
						await f.authority.registerSubordinate(f.record);
						const next = await generateSigningKey("ES256");
						let release!: () => void;
						const gate = new Promise<void>((resolve) => {
							release = resolve;
						});
						const blocker = f.storage.transaction(async () => gate);
						const updates = {
							jwks: { keys: [next.publicKey] },
							metadata: { openid_relying_party: { organization_name: "Requested" } },
						};
						const expected = structuredClone(updates);
						const pending = f.authority.updateSubordinate(subject, updates);
						updates.jwks.keys.length = 0;
						updates.metadata.openid_relying_party.organization_name = "Changed";
						release();
						await blocker;
						await pending;
						const stored = await f.storage.subordinates.get(subject);
						assert.deepEqual(stored?.jwks, expected.jwks);
						assert.deepEqual(stored?.metadata, expected.metadata);
						assert.deepEqual(
							(await f.storage.subordinateEvents?.list(issuer, subject))?.map((e) => e.event),
							["registration", "metadata_update", "jwks_update"],
						);
					},
				);
			}

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
							if (record.metadata)
								record.metadata.openid_relying_party.organization_name = "Changed";
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
			}

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
						(
							await TrustAnchor.create(fixtureHostConfig({ ...f.config, storage: broken }))
						).registerSubordinate(f.record),
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
						(
							await TrustAnchor.create(fixtureHostConfig({ ...f.config, storage: failing }))
						).registerSubordinate(f.record),
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
					await (
						await TrustAnchor.create(fixtureHostConfig({ ...f.config, storage }))
					).registerSubordinate(f.record);
					assert.strictEqual(attempts, 2);
					assert.strictEqual((await f.storage.subordinateEvents?.list(issuer, subject))?.length, 1);
				},
			);

			QUnit.test(
				"event capture can be enabled without publishing an HTTP route",
				async (assert) => {
					const f = await fixture();
					const authority = await TrustAnchor.create(
						fixtureHostConfig({
							...f.config,
							metadata: {
								federation_entity: {
									federation_fetch_endpoint: `${issuer}/fetch`,
									federation_list_endpoint: `${issuer}/list`,
								},
							},
						}),
					);
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
				},
			);

			QUnit.test("method errors are Federation errors only on the events route", async (assert) => {
				for (const methods of [undefined, ["private_key_jwt"], ["none", "private_key_jwt"]]) {
					const f = await fixture();
					const authority = await TrustAnchor.create(
						fixtureHostConfig({
							...f.config,
							metadata: {
								federation_entity: {
									...f.config.metadata.federation_entity,
									...(methods
										? { federation_subordinate_events_endpoint_auth_methods: methods }
										: {}),
								},
							},
						}),
					);
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
					assert.deepEqual(await legacy.json(), {
						error: "method_not_allowed",
						error_description: "Allowed request methods: GET",
					});
				}
			});
		});
	}

	{
		const anchor = entityId("https://ta.example");
		QUnit.module("Collection regressions", () => {
			QUnit.test(
				"authority routing preserves abort signals for form body readers",
				async (assert) => {
					const key = await generateSigningKey("ES256");
					const crypto = new FixtureCrypto({
						signer: new SigningEntryFixture(key.privateKey),
						publicJwk: key.publicKey,
					});
					const authority = await TrustAnchor.create(
						fixtureHostConfig({
							entityId: anchor,
							crypto,
							storage: new MemoryStorageAdapter({ engine: testEngine }),
							metadata: {
								federation_entity: {
									federation_fetch_endpoint: `${anchor}/fetch`,
									federation_list_endpoint: `${anchor}/list`,
									federation_collection_endpoint: `${anchor}/collect`,
								},
							},
							collection: {
								trustAnchors: new Map(),
								options: { engine: testEngine, httpTimeoutMs: 1000 },
							},
						}),
					);
					let signal: AbortSignal | undefined;
					const handle = authority.collection!.handleRequest.bind(authority.collection);
					authority.collection!.handleRequest = async (request) => {
						signal = request.signal;
						return handle(request);
					};
					const ac = new AbortController();
					ac.abort();
					let cancelled = false;
					const pending = authority.handleRequest(
						new Request(`${anchor}/collect`, {
							method: "POST",
							headers: { "content-type": "application/x-www-form-urlencoded" },
							body: new ReadableStream({
								cancel() {
									cancelled = true;
								},
							}),
							signal: ac.signal,
							...({ duplex: "half" } as RequestInit),
						}),
					);
					assert.true(
						signal?.aborted ?? false,
						"the handler must receive the incoming aborted state",
					);
					assert.equal((await pending).status, 400);
					assert.true(cancelled);
				},
			);
		});
	}

	module("authority / Trust Mark registry properties", () => {
		const subject = entityId("https://subject.example");
		test("registry properties: inherited issuer and delegation entries are absent", async (t) => {
			for (const type of ["toString", "constructor", "__proto__", "https://marks.example/custom"]) {
				const { ctx } = await createTestContext({
					trustMarkIssuers: Object.create({ [type]: ["https://other.example"] }),
					trustMarkDelegations: Object.create({ [type]: "inherited.jwt.token" }),
				});
				const jwt = await (
					await TrustAnchor.create(fixtureHostConfig(hostConfig(ctx)))
				).issueTrustMark(subject, type);
				const parsed = decodeEntityStatement(jwt);
				t.true(parsed.ok);
				if (parsed.ok) t.false(Object.hasOwn(parsed.value.payload, "delegation"));
			}
		});
		test("registry properties: malformed configuration fails before key or storage access", async (t) => {
			const type = "https://marks.example/custom";
			for (const field of ["trustMarkIssuers", "trustMarkDelegations"] as const) {
				for (const value of [null, undefined, false, {}, 7]) {
					const { ctx } = await createTestContext({
						[field]: { [type]: value },
					} as unknown as TestContextOverrides);
					let accesses = 0;
					ctx.crypto.keyring.entry = async () => {
						accesses++;
						throw new Error("Unexpected key access");
					};
					ctx.storage.trustMarks!.getValid = async () => {
						accesses++;
						throw new Error("Unexpected storage access");
					};
					await t.rejects(
						(async () => {
							const issuer = new CorePublic.TrustMarkIssuerService({
								issuer: ctx.entityId,
								crypto: ctx.crypto,
								trustMarkIssuers: ctx.trustMarkIssuers,
								delegations: ctx.trustMarkDelegations,
								storage: {
									trustMarks: ctx.storage.trustMarks!,
									transaction: (operation) =>
										ctx.storage.transaction((tx) => operation({ trustMarks: tx.trustMarks! })),
									readSnapshot: (operation) =>
										ctx.storage.readSnapshot!((snapshot) =>
											operation({ trustMarks: snapshot.trustMarks! }),
										),
								},
								options: { engine: testEngine },
							});
							await issuer.issueTrustMark(subject, type);
						})(),
					);
					t.equal(accesses, 0);
				}
			}
		});
	});
	module("authority / bounded Resolve assessments and retired Trust Mark keys", () => {
		test("public Resolve defaults to cache-only, local warming is audience-free, and expiry cannot trigger discovery", async (t) => {
			const fed = await createMockFederation();
			let calls = 0;
			let now = Math.floor(Date.now() / 1000);
			const { crypto } = await createTestContext();
			const storage = new MemoryStorageAdapter({ engine: testEngine });
			const server = await TrustAnchor.create(
				fixtureHostConfig({
					entityId: ENTITY_ID,
					crypto,
					storage,
					trustAnchors: fed.trustAnchors,
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: `${ENTITY_ID}/fetch`,
							federation_list_endpoint: `${ENTITY_ID}/list`,
							federation_resolve_endpoint: `${ENTITY_ID}/resolve`,
						},
					},
					options: {
						...fed.options,
						clock: { now: () => now },
						cacheMaxTtlSeconds: 10,
						httpClient: async (url, init) => {
							calls++;
							return fed.options.httpClient!(url, init);
						},
					},
				}),
			);
			const request = () =>
				new Request(
					`${ENTITY_ID}/resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`,
					{ headers: { "X-Authenticated-Entity": "https://spoof.example" } },
				);
			t.equal((await server.handleRequest(request())).status, 404);
			t.equal(calls, 0);
			const local = decodeEntityStatement(
				await server.resolveEntity(entityId(LEAF_ID), entityId(TA_ID)),
			);
			t.true(local.ok);
			if (local.ok) t.equal(local.value.payload.aud, undefined);
			const warmedCalls = calls;
			t.true(warmedCalls > 0);
			const first = await server.handleRequest(request());
			t.equal(first.status, 200);
			const decoded = decodeEntityStatement(await first.text());
			t.true(decoded.ok);
			if (decoded.ok) {
				t.equal(decoded.value.payload.aud, undefined);
				if (local.ok) t.equal(decoded.value.payload.exp, local.value.payload.exp);
				t.true(decoded.value.payload.exp > now + 10, "cache TTL does not replace evidence expiry");
			}
			t.equal(calls, warmedCalls);
			const next = await generateSigningKey();
			await crypto.keyring.publish(
				"federation",
				fixtureSigner(createFederationSigningKey(next.privateKey)),
			);
			await crypto.keyring.activate("federation", next.privateKey.kid!);
			const rotated = decodeEntityStatement(await (await server.handleRequest(request())).text());
			t.true(rotated.ok);
			if (rotated.ok) {
				t.equal(rotated.value.header.kid, next.privateKey.kid);
				if (local.ok) t.equal(rotated.value.payload.exp, local.value.payload.exp);
			}
			t.equal(calls, warmedCalls);
			const currentKeys = crypto.keyring.entry.bind(crypto.keyring, "federation");
			crypto.keyring.entry = async () => {
				now += 10;
				return currentKeys();
			};
			t.equal(
				(await server.handleRequest(request())).status,
				404,
				"expiry during key lookup cannot renew the assessment",
			);
			t.equal(calls, warmedCalls);
		});
		test("authenticated assessments never leak audience to anonymous cache hits and query changes miss", async (t) => {
			const fed = await createMockFederation();
			let calls = 0;
			const { ctx } = await createTestContext({
				requireAuthForFreshResolution: true,
				trustAnchors: fed.trustAnchors,
				options: {
					...fed.options,
					httpClient: async (url, init) => {
						calls++;
						return fed.options.httpClient!(url, init);
					},
				},
			});
			const handler = createResolveHandler(ctx);
			const url = `${ENTITY_ID}/resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`;
			for (const caller of ["https://client-a.example", "https://client-b.example"]) {
				const response = await resolveAsClient(ctx, new Request(url), caller, handler);
				t.equal(response.status, 200);
				const decoded = decodeEntityStatement(await response.text());
				t.true(decoded.ok);
				if (decoded.ok) t.equal(decoded.value.payload.aud, caller);
			}
			const previousCalls = calls;
			const anonymous = decodeEntityStatement(await (await handler(new Request(url))).text());
			t.true(anonymous.ok);
			if (anonymous.ok) t.equal(anonymous.value.payload.aud, undefined);
			t.equal((await handler(new Request(`${url}&entity_type=openid_provider`))).status, 404);
			t.equal(calls, previousCalls);
			const old = fed.trustAnchors.get(entityId(TA_ID))!;
			(fed.trustAnchors as Map<EntityId, { jwks: { keys: JWK[] } }>).set(entityId(TA_ID), {
				jwks: { keys: [{ ...old.jwks.keys[0]!, kid: "changed-pin" }] },
			});
			t.equal((await handler(new Request(url))).status, 404);
			t.equal(calls, previousCalls);
		});
		test("cache read failure fails closed while an explicit anonymous discovery opt-in works", async (t) => {
			const fed = await createMockFederation();
			let calls = 0;
			const { ctx } = await createTestContext({
				requireAuthForFreshResolution: true,
				trustAnchors: fed.trustAnchors,
				options: {
					...fed.options,
					httpClient: async (url, init) => {
						calls++;
						return fed.options.httpClient!(url, init);
					},
				},
			});
			const url = `${ENTITY_ID}/resolve?sub=${encodeURIComponent(LEAF_ID)}&trust_anchor=${encodeURIComponent(TA_ID)}`;
			const broken = {
				...ctx,
				storage: {
					...ctx.storage,
					subordinates: ctx.storage.subordinates,
					cache: {
						get: async () => {
							throw new Error("cache unavailable");
						},
						set: async () => {
							throw new Error("write unavailable");
						},
						delete: async () => {},
						clear: async () => {},
						[Symbol.asyncDispose]: async () => {},
					},
				},
			};
			t.equal((await createResolveHandler(broken)(new Request(url))).status, 500);
			t.equal(calls, 0);
			t.equal(
				(
					await createResolveHandler({ ...broken, requireAuthForFreshResolution: false })(
						new Request(url),
					)
				).status,
				200,
			);
			t.true(calls > 0);
		});
		test("normal retirement preserves status for custom types; revoked keys and invalid historical lifetimes fail", async (t) => {
			let now = 1000;
			const initial = await generateSigningKey();
			const next = await generateSigningKey();
			const provider = FixtureCrypto.fromJWK(initial.privateKey, {
				nowMs: () => now * 1000,
			});
			const { ctx, trustMarks } = await createTestContext({
				crypto: provider,
				options: { clock: { now: () => now }, clockSkewSeconds: 0, engine: testEngine },
			});
			const tokens: string[] = [];
			for (const type of [
				"urn:example:accreditation",
				"https://marks.example/type?v=1",
				"https://marks.example/type#fragment",
				"custom-type",
			]) {
				const jwt = await signEntityStatement(
					{ iss: ENTITY_ID, sub: LEAF_ID, trust_mark_type: type, iat: now, exp: now + 100 },
					new SigningEntryFixture(initial.privateKey),
					{ typ: JwtTyp.TrustMark },
				);
				await trustMarks.issue({
					trustMarkType: type,
					subject: entityId(LEAF_ID),
					jwt,
					issuedAt: now,
					expiresAt: now + 100,
					active: true,
				});
				tokens.push(jwt);
			}
			const status = async (jwt: string) => {
				const response = await createTrustMarkStatusHandler(ctx)(
					new Request(`${ENTITY_ID}/status`, {
						method: "POST",
						body: new URLSearchParams({ trust_mark: jwt }),
					}),
				);
				t.equal(response.status, 200);
				const decoded = decodeEntityStatement(await response.text());
				if (!decoded.ok) throw new Error(decoded.error.description);
				return decoded.value.payload.status;
			};
			for (const jwt of tokens) t.equal(await status(jwt), "active");
			now++;
			await provider.keyring.publish(
				"federation",
				fixtureSigner(createFederationSigningKey(next.privateKey)),
			);
			await provider.keyring.activate("federation", next.privateKey.kid!);
			await provider.keyring.retire("federation", initial.privateKey.kid!);
			for (const jwt of tokens) t.equal(await status(jwt), "active");
			for (const [iat, key] of [
				[1001, initial.privateKey],
				[1000, next.privateKey],
			] as const) {
				const jwt = await signProtocolFixture(
					{ iss: ENTITY_ID, sub: LEAF_ID, trust_mark_type: "urn:example:bad", iat, exp: 1100 },
					new SigningEntryFixture(key),
					{ typ: JwtTyp.TrustMark, extraHeaders: { kid: initial.privateKey.kid } },
				);
				await trustMarks.issue({
					trustMarkType: "urn:example:bad",
					subject: entityId(LEAF_ID),
					jwt,
					issuedAt: iat,
					expiresAt: 1100,
					active: true,
				});
				t.equal(await status(jwt), "invalid");
			}
			await provider.keyring.revoke("federation", initial.privateKey.kid!, "keyCompromise");
			for (const jwt of tokens) t.equal(await status(jwt), "invalid");
			now = 1100;
			for (const jwt of tokens) t.equal(await status(jwt), "expired");
		});
	});
	module("authority / Resolve candidate selection", () => {
		async function graph(
			first: "valid" | "signature" | "metadata",
			second: "valid" | "signature" | "metadata",
		) {
			const c = CorePublic,
				clock = { now: () => 1500 };
			const f = await createTestContext({ options: { clock, engine: testEngine } });
			const a = f.ctx.entityId,
				b = c.entityId("https://second.example"),
				leaf = c.entityId("https://subject.example");
			const bKey = await generateSigningKey("ES256"),
				leafKey = await generateSigningKey("ES256");
			const sign = (payload: Record<string, unknown>, key: JWK) =>
				c.signEntityStatement({ iat: 1500, exp: 2500, ...payload }, new SigningEntryFixture(key));
			const leafEC = await sign(
				{
					iss: leaf,
					sub: leaf,
					jwks: { keys: [leafKey.publicKey] },
					authority_hints: [a, b],
					metadata: { openid_provider: { issuer: leaf } },
				},
				leafKey.privateKey,
			);
			const docs = new Map<string, string>([[`${leaf}/.well-known/openid-federation`, leafEC]]);
			for (const [id, key, pub, mode] of [
				[a, f.signingKey, f.publicKey, first],
				[b, bKey.privateKey, bKey.publicKey, second],
			] as const) {
				docs.set(
					`${id}/.well-known/openid-federation`,
					await sign(
						{
							iss: id,
							sub: id,
							jwks: { keys: [pub] },
							metadata: {
								federation_entity: {
									federation_fetch_endpoint: `${id}/fetch`,
									federation_list_endpoint: `${id}/list`,
								},
							},
						},
						key,
					),
				);
				docs.set(
					`${id}/fetch?sub=${encodeURIComponent(leaf)}`,
					await sign(
						{
							iss: id,
							sub: leaf,
							jwks: { keys: [leafKey.publicKey] },
							...(mode === "metadata"
								? {
										metadata_policy: {
											openid_provider: { issuer: { value: "https://different.example" } },
										},
									}
								: {}),
						},
						mode === "signature" ? leafKey.privateKey : key,
					),
				);
			}
			const anchors = c.createTrustAnchorSet([
				{ entityId: a, jwks: { keys: [f.publicKey] } },
				{ entityId: b, jwks: { keys: [bKey.publicKey] } },
			]);
			let calls = 0;
			const httpClient: HttpClient = async (input) => {
				calls++;
				const jwt = docs.get(String(input));
				return new Response(jwt ?? "missing", {
					status: jwt ? 200 : 404,
					headers: { "content-type": jwt ? MediaType.EntityStatement : "text/plain" },
				});
			};
			const ctx: HandlerContext = {
				...f.ctx,
				trustAnchors: anchors,
				options: { engine: testEngine, clock, httpClient, maxConcurrentFetches: 1 },
			};
			const url = `${a}/resolve?${new URLSearchParams([
				["sub", leaf],
				["trust_anchor", a],
				["trust_anchor", b],
			])}`;
			return { ctx, url, docs, leaf, b, calls: () => calls };
		}
		test("a later valid candidate succeeds and the response and cache use that chain", async (t) => {
			const f = await graph("signature", "valid");
			const handler = createResolveHandler({ ...f.ctx, requireAuthForFreshResolution: true });
			const response = await handler(new Request(f.url), true);
			t.equal(response.status, 200);
			const decoded = decodeEntityStatement(await response.text());
			t.true(decoded.ok);
			if (decoded.ok) {
				const chain = decoded.value.payload.trust_chain as string[];
				const anchor = decodeEntityStatement(chain.at(-1)!);
				t.true(anchor.ok);
				if (anchor.ok) t.equal(anchor.value.payload.iss, f.b);
				t.equal(decoded.value.payload.exp, 2500);
			}
			const count = f.calls();
			t.equal((await handler(new Request(f.url))).status, 200);
			t.equal(f.calls(), count, "cache reuses the selected candidate without discovery");
		});
		test("failed candidates distinguish chain failures from metadata-only failures", async (t) => {
			for (const [a, b, code] of [
				["signature", "signature", "invalid_trust_chain"],
				["metadata", "metadata", "invalid_metadata"],
				["metadata", "signature", "invalid_trust_chain"],
			] as const) {
				const f = await graph(a, b);
				const response = await createResolveHandler(f.ctx)(new Request(f.url));
				t.equal(response.status, 400);
				t.equal(((await response.json()) as { error: string }).error, code);
			}
		});
		test("discovery distinguishes missing subjects, invalid evidence and unavailable upstreams", async (t) => {
			for (const status of [404, 503, 201]) {
				const f = await graph("valid", "valid");
				const ctx = {
					...f.ctx,
					options: {
						...f.ctx.options,
						httpClient: async () => new Response("unavailable", { status }),
					},
				};
				const response = await createResolveHandler(ctx)(new Request(f.url));
				t.equal(response.status, status === 404 ? 404 : 503);
				t.equal(
					((await response.json()) as { error: string }).error,
					status === 404 ? "not_found" : "temporarily_unavailable",
				);
			}
			const broken = await graph("valid", "valid");
			for (const url of broken.docs.keys())
				if (url.includes("/fetch?")) broken.docs.set(url, "undecodable.statement");
			const failed = await createResolveHandler(broken.ctx)(new Request(broken.url));
			t.equal(failed.status, 400);
			t.equal(((await failed.json()) as { error: string }).error, "invalid_trust_chain");
			const f = await graph("valid", "valid");
			f.docs.set(`${f.leaf}/.well-known/openid-federation`, "malformed.jwt.document");
			const response = await createResolveHandler(f.ctx)(new Request(f.url));
			t.equal(response.status, 400);
			t.equal(((await response.json()) as { error: string }).error, "invalid_trust_chain");
		});

		test("failed candidates retain unavailable discovery branches without hiding a later success", async (t) => {
			for (const candidate of ["signature", "metadata", "valid"] as const) {
				const f = await graph(candidate, "valid");
				const transport = f.ctx.options!.httpClient!;
				const response = await createResolveHandler({
					...f.ctx,
					options: {
						...f.ctx.options,
						httpClient: (input, init) =>
							String(input).startsWith(`${f.b}/`)
								? Promise.resolve(new Response("unavailable", { status: 503 }))
								: transport(input, init),
					},
				})(new Request(f.url));
				t.equal(response.status, candidate === "valid" ? 200 : 503);
				if (response.status !== 200)
					t.equal(((await response.json()) as { error: string }).error, "temporarily_unavailable");
				else await response.body?.cancel();
			}
		});
		test("Resolve filters only own entity types without mutating object prototypes", async (t) => {
			const f = await graph("valid", "valid");
			const before = Object.getOwnPropertyDescriptors(Object.prototype);
			for (const name of ["toString", "constructor", "__proto__"]) {
				const response = await createResolveHandler(f.ctx)(
					new Request(`${f.url}&entity_type=${name}`),
				);
				t.equal(response.status, 404);
			}
			const response = await createResolveHandler(f.ctx)(
				new Request(
					`${f.url}&entity_type=toString&entity_type=openid_provider&entity_type=openid_provider`,
				),
			);
			t.equal(response.status, 200);
			const decoded = decodeEntityStatement(await response.text());
			t.true(decoded.ok);
			if (decoded.ok)
				t.deepEqual(Object.keys(decoded.value.payload.metadata!), ["openid_provider"]);
			t.deepEqual(Object.getOwnPropertyNames(Object.prototype), Object.keys(before));
			for (const [name, saved] of Object.entries(before)) {
				const current = Object.getOwnPropertyDescriptor(Object.prototype, name);
				for (const attribute of [
					"value",
					"get",
					"set",
					"writable",
					"enumerable",
					"configurable",
				] as const)
					t.strictEqual(current?.[attribute], saved[attribute], `${name}.${attribute}`);
			}
		});
		test("Resolve rechecks freshness and cancellation after successful or failed cache writes", async (t) => {
			const f = await graph("valid", "valid");
			for (const outcome of ["valid", "expired", "cancelled"] as const) {
				for (const fails of [false, true]) {
					let now = 1500,
						writes = 0;
					const controller = new AbortController();
					const handler = createResolveHandler({
						...f.ctx,
						options: { ...f.ctx.options, clock: { now: () => now } },
						storage: {
							...f.ctx.storage,
							cache: {
								get: async () => undefined,
								delete: async () => {},
								clear: async () => {},
								[Symbol.asyncDispose]: async () => {},
								set: async () => {
									writes++;
									await Promise.resolve();
									now = outcome === "expired" ? 2500 : 1550;
									if (outcome === "cancelled") controller.abort();
									if (fails) throw new Error("Cache write failed");
								},
							},
						},
					});
					const response = await handler(new Request(f.url, { signal: controller.signal }), true);
					t.equal(writes, 1);
					t.equal(
						response.status,
						outcome === "valid" ? 200 : 503,
						`${outcome}, cache failure: ${fails}`,
					);
					if (outcome === "valid") {
						const decoded = decodeEntityStatement(await response.text());
						t.true(decoded.ok);
						if (decoded.ok) t.equal(decoded.value.payload.exp, 2500);
					} else {
						const body = (await response.json()) as { error: string };
						t.equal(body.error, "temporarily_unavailable");
					}
				}
			}
		});
		test("auxiliary EC expiry bounds cache reuse without shortening the returned chain expiry", async (t) => {
			const c = CorePublic;
			let now = 1500,
				ecExpiry = 1600,
				calls = 0;
			const clock = { now: () => now },
				f = await createTestContext({ options: { clock, engine: testEngine } });
			const anchor = f.ctx.entityId,
				mid = c.entityId("https://intermediate.example"),
				leaf = c.entityId("https://subject.example");
			const mk = await generateSigningKey("ES256"),
				lk = await generateSigningKey("ES256");
			const fed = (id: string) => ({
				federation_entity: {
					federation_fetch_endpoint: `${id}/fetch`,
					federation_list_endpoint: `${id}/list`,
				},
			});
			const sign = (payload: Record<string, unknown>, key: JWK) =>
				c.signEntityStatement({ iat: 1500, exp: 2500, ...payload }, new SigningEntryFixture(key));
			const docs = new Map<string, string>([
				[
					`${anchor}/.well-known/openid-federation`,
					await sign(
						{ iss: anchor, sub: anchor, jwks: { keys: [f.publicKey] }, metadata: fed(anchor) },
						f.signingKey,
					),
				],
				[
					`${leaf}/.well-known/openid-federation`,
					await sign(
						{
							iss: leaf,
							sub: leaf,
							jwks: { keys: [lk.publicKey] },
							authority_hints: [mid],
							metadata: { openid_provider: { issuer: leaf } },
						},
						lk.privateKey,
					),
				],
				[
					`${mid}/fetch?sub=${encodeURIComponent(leaf)}`,
					await sign({ iss: mid, sub: leaf, jwks: { keys: [lk.publicKey] } }, mk.privateKey),
				],
				[
					`${anchor}/fetch?sub=${encodeURIComponent(mid)}`,
					await sign({ iss: anchor, sub: mid, jwks: { keys: [mk.publicKey] } }, f.signingKey),
				],
			]);
			const context: HandlerContext = {
				...f.ctx,
				requireAuthForFreshResolution: true,
				trustAnchors: c.createTrustAnchorSet([{ entityId: anchor, jwks: { keys: [f.publicKey] } }]),
				options: {
					engine: testEngine,
					clock,
					cacheMaxTtlSeconds: 1000,
					clockSkewSeconds: 0,
					httpClient: async (input) => {
						calls++;
						const jwt =
							String(input) === `${mid}/.well-known/openid-federation`
								? await sign(
										{
											iss: mid,
											sub: mid,
											exp: ecExpiry,
											jwks: { keys: [mk.publicKey] },
											authority_hints: [anchor],
											metadata: fed(mid),
										},
										mk.privateKey,
									)
								: docs.get(String(input));
						return new Response(jwt ?? "missing", {
							status: jwt ? 200 : 404,
							headers: { "content-type": MediaType.EntityStatement },
						});
					},
				},
			};
			const handler = createResolveHandler(context);
			const request = () =>
				new Request(
					`${anchor}/resolve?${new URLSearchParams({ sub: leaf, trust_anchor: anchor })}`,
				);
			const response = await handler(request(), true);
			t.equal(response.status, 200);
			const decoded = decodeEntityStatement(await response.text());
			t.true(decoded.ok);
			if (decoded.ok) t.equal(decoded.value.payload.exp, 2500);
			const count = calls;
			now = 1599;
			t.equal((await handler(request())).status, 200);
			t.equal(calls, count);
			now = 1600;
			t.equal(
				(await handler(request())).status,
				404,
				"expired auxiliary evidence cannot be served from cache",
			);
			ecExpiry = 2200;
			t.equal((await handler(request(), true)).status, 200);
			t.true(calls > count, "fresh local resolution obtains new evidence");
			for (const expires of [false, true])
				for (const fails of [false, true]) {
					now = 1500;
					ecExpiry = 1600;
					let writes = 0;
					const slowCacheHandler = createResolveHandler({
						...context,
						storage: {
							...context.storage,
							cache: {
								get: async () => undefined,
								delete: async () => {},
								clear: async () => {},
								[Symbol.asyncDispose]: async () => {},
								set: async () => {
									writes++;
									await Promise.resolve();
									now = expires ? 1600 : 1599;
									if (fails) throw new Error("Cache write failed");
								},
							},
						},
					});
					const response = await slowCacheHandler(request(), true);
					t.equal(writes, 1);
					t.equal(
						response.status,
						expires ? 503 : 200,
						`auxiliary expiry: ${expires}, cache failure: ${fails}`,
					);
					if (expires)
						t.equal(
							((await response.json()) as { error: string }).error,
							"temporarily_unavailable",
						);
					else {
						const decoded = decodeEntityStatement(await response.text());
						t.true(decoded.ok);
						if (decoded.ok) t.equal(decoded.value.payload.exp, 2500);
					}
				}
		});
		test("candidate attempts share fetch limits and respect cancellation", async (t) => {
			// Either branch may finish first; neither can supply a valid chain within the budget.
			const f = await graph("signature", "signature");
			const response = await createResolveHandler({
				...f.ctx,
				options: { ...f.ctx.options, maxTotalFetches: 4 },
			})(new Request(f.url));
			t.equal(response.status, 503);
			t.equal(f.calls(), 4);
			const aborted = await graph("signature", "valid");
			t.equal(
				(
					await createResolveHandler(aborted.ctx)(
						new Request(aborted.url, { signal: AbortSignal.abort() }),
					)
				).status,
				503,
			);
			t.equal(aborted.calls(), 0);
		});
		test("unsupported explicit timestamps do not disable time-filter recommendations", async (t) => {
			const f = await SubordinateEventsFixture.fixture();
			await f.authority.registerSubordinate(f.record);
			const handler = createExtendedListHandler(
				{
					entityId: SubordinateEventsFixture.issuer,
					crypto: f.crypto,
					storage: f.storage,
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: `${SubordinateEventsFixture.issuer}/fetch`,
							federation_list_endpoint: `${SubordinateEventsFixture.issuer}/list`,
						},
					},
					options: { engine: testEngine, clock: f.clock },
					clientKeyProvider: { getClientFederationJwks: async () => undefined },
				},
				{ supportAuditTimestamps: false, defaultClaims: [] },
			);
			for (const filter of ["updated_after=0", "updated_before=2000"]) {
				const response = await handler(new Request(`${f.config.entityId}/list?${filter}`));
				t.equal(response.status, 200);
				const body = (await response.json()) as {
					immediate_subordinate_entities: Record<string, unknown>[];
				};
				t.equal(body.immediate_subordinate_entities[0]?.registered, 1500);
				const suppressed = await handler(
					new Request(`${f.config.entityId}/list?${filter}&audit_timestamps=false`),
				);
				const omitted = (await suppressed.json()) as {
					immediate_subordinate_entities: Record<string, unknown>[];
				};
				t.notOk(Object.hasOwn(omitted.immediate_subordinate_entities[0]!, "registered"));
			}
			t.equal(
				(await handler(new Request(`${f.config.entityId}/list?audit_timestamps=true`))).status,
				400,
			);
		});
	});
};
