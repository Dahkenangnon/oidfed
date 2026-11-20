import { Intermediate, TrustAnchor } from "../../../packages/authority/src/index.js";
import {
	createTrustAnchorSet,
	type EntityCollectionRequestParams,
	type EntityCollectionResponse,
	EntityCollectionResponseSchema,
	EntityCollectionService,
	type EntityCollectionSnapshot,
	entityId,
	type HttpClient,
	MediaType,
	signEntityStatement,
} from "../../../packages/core/src/index.js";
import { MemoryEntityCollectionStore } from "../../../packages/core/src/storage/collection-memory.js";
import { Leaf } from "../../../packages/leaf/src/index.js";
import { collectionOptions, memoryStorage, storedTrustMarkToken } from "../../storage-fixtures.js";
import {
	FixtureCrypto,
	fixtureHostConfig,
	generateSigningKey,
	SigningEntryFixture,
	testEngine,
} from "./software-crypto.js";

export const anchor = entityId("https://anchor.example");

export const other = entityId("https://other.example");

export const leafId = entityId("https://leaf.example");

export const endpoint = "https://collection.example:8443/tenant/collect?version=1";

export const now = 1500;

export async function seed() {
	let time = now;
	const clock = { now: () => time };
	const key = await generateSigningKey("ES256");
	const trustAnchors = createTrustAnchorSet([
		{ entityId: anchor, jwks: { keys: [key.publicKey] } },
	]);
	const store = new MemoryEntityCollectionStore({ clock });
	const snapshot: EntityCollectionSnapshot = {
		id: "first",
		trustAnchor: anchor,
		lastUpdated: -0.5,
		entries: ["a", "b", "c"].map((name, index) => {
			const subject = entityId(`https://${name}.example`);
			const verifiedMarks = (index === 0 ? ["one", "two"] : ["one"]).map((type) => {
				const expiresAt = type === "one" ? 2000 : 3000;
				return {
					type,
					expiresAt,
					jwt: storedTrustMarkToken({ subject, trustMarkType: type, issuedAt: 1000, expiresAt }),
				};
			});
			return {
				entity: {
					entity_id: EntityCollectionResponseSchema.parse({ entities: [{ entity_id: subject }] })
						.entities[0]!.entity_id,
					entity_types: [index === 1 ? "custom_type" : "openid_provider", "federation_entity"],
					entity_infos: {
						openid_provider: {
							display_name: name.toUpperCase(),
							"display_name#en-US": `${name} English`,
							"display_name#de": `${name} Deutsch`,
							description: "Example",
						},
						federation_entity: { organization_name: "Organization" },
					},
					trust_marks: verifiedMarks.map(({ type, jwt }) => ({
						trust_mark_type: type,
						trust_mark: jwt,
					})),
				},
				expiresAt: 5000,
				chainExpiresAt: 5000,
				verifiedMarks,
			};
		}),
	};
	await store.publish(snapshot);
	const service = new EntityCollectionService({
		trustAnchors,

		endpoint,
		responder: { entityId: anchor, isTrustAnchor: true },
		options: collectionOptions({ engine: testEngine, clock }, store),
		maxPageSize: 2,
	});
	return {
		clock,
		key,
		trustAnchors,
		store,
		snapshot,
		service,
		setNow: (value: number) => {
			time = value;
		},
	};
}

export async function query(
	service: EntityCollectionService,
	params: EntityCollectionRequestParams = {},
): Promise<EntityCollectionResponse> {
	const result = await service.query(params);
	if (!result.ok) throw new Error(`${result.error.code}: ${result.error.description}`);
	return result.value;
}

export async function federation(
	markMode:
		| "none"
		| "valid"
		| "expired"
		| "wrong-subject"
		| "wrong-type"
		| "unauthorized"
		| "invalid-signature"
		| "malformed" = "none",
) {
	const rootKey = await generateSigningKey("ES256");
	const middleKey = await generateSigningKey("ES256");
	const leafKey = await generateSigningKey("ES256");
	const middleId = entityId("https://middle.example");
	const issuerId = entityId("https://issuer.example");
	const issuerKey = await generateSigningKey("ES256");
	const clock = { now: () => now };
	const provider = (key: typeof rootKey) =>
		new FixtureCrypto({
			signer: new SigningEntryFixture(key.privateKey),
			publicJwk: key.publicKey,
		});
	const trustAnchors = createTrustAnchorSet([
		{ entityId: anchor, jwks: { keys: [rootKey.publicKey] } },
	]);
	const storage = memoryStorage({ engine: testEngine, collections: true, clock });
	const middleStorage = memoryStorage({ engine: testEngine, collections: true, clock });
	let requests = 0;
	let failedHost = "";
	const httpClient: HttpClient = async (input, init) => {
		requests++;
		const request = new Request(String(input), init);
		const host = new URL(request.url).hostname;
		if (host === failedHost) throw new Error("Offline");
		if (host === "anchor.example") {
			if (markMode !== "none" && new URL(request.url).pathname === "/list")
				return new Response(JSON.stringify([middleId]), {
					headers: { "content-type": MediaType.Json },
				});
			return root.handleRequest(request);
		}
		if (host === "issuer.example") return issuer.handleRequest(request);
		if (host === "middle.example") return middle.handleRequest(request);
		if (host === "leaf.example") return leaf.handleRequest(request);
		return new Response(null, { status: 404 });
	};
	const diagnostics: unknown[] = [];
	const collection = {
		trustAnchors,
		options: {
			engine: testEngine,
			clock,
			httpClient,
			logger: {
				debug: (message: string, context?: Record<string, unknown>) => {
					diagnostics.push({ message, context });
				},
				info() {},
				warn() {},
				error() {},
			},
		},
	};
	const root = await TrustAnchor.create(
		fixtureHostConfig({
			entityId: anchor,
			storage,
			crypto: provider(rootKey),
			...(markMode !== "none"
				? {
						trustMarkIssuers: {
							one: markMode === "unauthorized" ? ["https://unauthorized.example"] : [issuerId],
						},
					}
				: {}),
			options: { clock },
			collection,
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${anchor}/fetch`,
					federation_list_endpoint: `${anchor}/list`,
					federation_collection_endpoint: `${anchor}/collect?version=1`,
				},
			},
		}),
	);
	const middle = await Intermediate.create(
		fixtureHostConfig({
			entityId: middleId,
			authorityHints: [anchor],
			storage: middleStorage,
			crypto: provider(middleKey),
			options: { clock },
			collection,
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${middleId}/fetch`,
					federation_list_endpoint: `${middleId}/list`,
					federation_collection_endpoint: `${middleId}/collect`,
				},
			},
		}),
	);
	const issuer = await Leaf.create(
		fixtureHostConfig({
			entityId: issuerId,
			authorityHints: [anchor],
			crypto: provider(issuerKey),
			options: { clock },
			metadata: { federation_entity: { display_name: "External issuer" } },
		}),
	);
	const mark = await signEntityStatement(
		{
			iss: issuerId,
			sub: markMode === "wrong-subject" ? middleId : leafId,
			iat: 1000,
			exp: markMode === "expired" ? 1100 : 3000,
			trust_mark_type: markMode === "wrong-type" ? "two" : "one",
		},
		new SigningEntryFixture(
			markMode === "invalid-signature" ? leafKey.privateKey : issuerKey.privateKey,
		),
		{ typ: "trust-mark+jwt" },
	);
	const leaf = await Leaf.create(
		fixtureHostConfig({
			entityId: leafId,
			authorityHints: [middleId],
			crypto: provider(leafKey),
			...(markMode !== "none"
				? {
						trustMarks: [
							{ trust_mark_type: "one", trust_mark: markMode === "malformed" ? "not-a-jwt" : mark },
						],
					}
				: {}),
			options: { clock },
			collection,
			storage: memoryStorage({ collections: true, clock }),
			metadata: {
				federation_entity: { federation_collection_endpoint: `${leafId}/collect` },
				oauth_resource: {
					resource: leafId,
					resource_name: "API",
					"resource_name#en": "English API",
				},
			},
		}),
	);
	if (markMode !== "none")
		await storage.subordinate.register({
			entityId: issuerId,
			jwks: { keys: [issuerKey.publicKey] },
			createdAt: now,
			updatedAt: now,
		});
	await storage.subordinate.register({
		entityId: middleId,
		jwks: { keys: [middleKey.publicKey] },
		isIntermediate: true,
		createdAt: now,
		updatedAt: now,
	});
	await middleStorage.subordinate.register({
		entityId: leafId,
		jwks: { keys: [leafKey.publicKey] },
		createdAt: now,
		updatedAt: now,
	});
	return {
		root,
		middle,
		leaf,
		storage,
		middleStorage,
		collection,
		rootKey,
		diagnostics,
		leafKey,
		httpClient,
		requests: () => requests,
		fail: (host: string) => {
			failedHost = host;
		},
	};
}
