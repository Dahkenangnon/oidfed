import type { AuthorityConfig, SubordinateRecord } from "@oidfed/authority";
import {
	Intermediate,
	MemoryStorageAdapter,
	sanitizeSubordinateMetadata,
	TrustAnchor,
} from "@oidfed/authority";
import type { EntityType, FederationKeyProvider, JWK, TrustAnchorSet } from "@oidfed/core";
import {
	entityId,
	generateSigningKey,
	JwkSigner,
	MemoryFederationKeyProvider,
	stripPrivateFields,
} from "@oidfed/core";
import { Leaf } from "@oidfed/leaf";
import type { OidcProtocolKeyProvider } from "@oidfed/oidc";
import { StaticOidcProtocolKeyProvider } from "@oidfed/oidc";
import type { Express } from "express";
import { createAuthorityApp } from "../participants/authority-app.js";
import {
	createLeafApp,
	createRequestObjectStore,
	type RequestObjectStore,
} from "../participants/leaf-app.js";
import { createOpenIDProviderApp } from "../participants/openid-provider-app.js";
import type { EntityDefinition, TopologyDefinition } from "../topologies/types.js";
import {
	createAndStartFederationTestServer,
	type FederationServerOptions,
	type FederationTestServer,
} from "./federation-server.js";

export interface LaunchOptions extends FederationServerOptions {}

export function federationSigningKey(signingKey: JWK) {
	return { signer: new JwkSigner(signingKey), publicJwk: stripPrivateFields(signingKey) };
}

export interface EntityInstance {
	server: TrustAnchor | Intermediate | Leaf;
	keys: {
		signing: JWK;
		public: JWK;
		protocolSigning: JWK;
		protocolPublic: JWK;
	};
	keyProvider: FederationKeyProvider;
	oidcProtocolKeyProvider: OidcProtocolKeyProvider;
	storage?: MemoryStorageAdapter;
}

export interface FederationTestBed {
	server: FederationTestServer;
	entities: Map<string, EntityInstance>;
	trustAnchors: TrustAnchorSet;
	/**
	 * Per-RP single-use request-object stores, keyed by the *original* RP
	 * entity id (e.g. `https://rp.ofed.test`). Scenario tests seed these to
	 * exercise the OP's `?request_uri=` fetch path.
	 */
	requestObjectStores: ReadonlyMap<string, RequestObjectStore>;
	close(): Promise<void>;
}

export async function launchFederation(
	topology: TopologyDefinition,
	options?: LaunchOptions,
): Promise<FederationTestBed> {
	const testServer = await createAndStartFederationTestServer(options);
	const port = testServer.port;

	// Rewrite URLs to include ephemeral port
	const rewriteUrl = (url: string): string =>
		url.replace(/https:\/\/([^/]+)/g, `https://$1:${port}`);

	const rewriteMetadata = (
		metadata: Record<string, Record<string, unknown>>,
	): Record<string, Record<string, unknown>> => {
		const result: Record<string, Record<string, unknown>> = {};
		for (const [type, values] of Object.entries(metadata)) {
			const rewritten: Record<string, unknown> = {};
			for (const [k, v] of Object.entries(values)) {
				if (typeof v === "string" && v.startsWith("https://")) {
					rewritten[k] = rewriteUrl(v);
				} else if (Array.isArray(v)) {
					rewritten[k] = v.map((item) =>
						typeof item === "string" && item.startsWith("https://") ? rewriteUrl(item) : item,
					);
				} else {
					rewritten[k] = v;
				}
			}
			result[type] = rewritten;
		}
		return result;
	};

	// 1. Generate keys for all entities. Federation and OIDC protocol keys are distinct.
	const entityKeys = new Map<
		string,
		{ signing: JWK; public: JWK; protocolSigning: JWK; protocolPublic: JWK }
	>();
	for (const entity of topology.entities) {
		const key = await generateSigningKey("ES256");
		const protocolKey = await generateSigningKey("ES256");
		entityKeys.set(entity.id, {
			signing: key.privateKey as JWK,
			public: key.publicKey as JWK,
			protocolSigning: protocolKey.privateKey as JWK,
			protocolPublic: protocolKey.publicKey as JWK,
		});
	}

	const getKeys = (id: string) => {
		const k = entityKeys.get(id);
		if (!k) throw new Error(`No keys for entity ${id}`);
		return k;
	};

	const addProtocolJwks = (
		entity: EntityDefinition,
		metadata: Record<string, Record<string, unknown>>,
		keys: ReturnType<typeof getKeys>,
	): Record<string, Record<string, unknown>> => {
		if (entity.protocolRole !== "rp") return metadata;
		const rpMetadata = metadata.openid_relying_party;
		if (!rpMetadata) return metadata;
		if (rpMetadata.jwks || rpMetadata.jwks_uri || rpMetadata.signed_jwks_uri) return metadata;
		return {
			...metadata,
			openid_relying_party: {
				...rpMetadata,
				jwks: { keys: [keys.protocolPublic] },
			},
		};
	};

	// 2. Build trust anchor set
	const taEntities = topology.entities.filter((e) => e.role === "trust-anchor");
	const trustAnchors: TrustAnchorSet = new Map(
		taEntities.map((ta) => [
			entityId(rewriteUrl(ta.id)),
			{ jwks: { keys: [getKeys(ta.id).public] } },
		]),
	);

	const entities = new Map<string, EntityInstance>();
	const authorityStorages = new Map<string, MemoryStorageAdapter>();
	const apps = new Map<string, Express>();
	const requestObjectStores = new Map<string, RequestObjectStore>();

	// Server-controlled allowlist of hostnames the OPs are willing to fetch a
	// by-reference Request Object from. Built from every RP in the topology
	// before any HTTP request is processed.
	const rpEntities = topology.entities.filter((e) => e.role === "leaf" && e.protocolRole === "rp");
	const allowedRequestUriHosts: ReadonlySet<string> = new Set(
		rpEntities.map((rp) => new URL(rewriteUrl(rp.id)).hostname),
	);

	// 3. Create authority entities (TA, intermediate) — OPs are leaves, handled in step 4.
	for (const entity of topology.entities) {
		const isAuthority = entity.role === "trust-anchor" || entity.role === "intermediate";
		if (!isAuthority) continue;

		const eid = rewriteUrl(entity.id);
		const keys = getKeys(entity.id);
		const metadata = addProtocolJwks(entity, rewriteMetadata(entity.metadata), keys);
		const storage = new MemoryStorageAdapter({ trustMarks: true });
		authorityStorages.set(entity.id, storage);

		const authorityHints = entity.authorityHints?.map((h) => entityId(rewriteUrl(h)));

		const keyProvider = new MemoryFederationKeyProvider(federationSigningKey(keys.signing));
		const oidcProtocolKeyProvider = new StaticOidcProtocolKeyProvider({
			requestObjectSigner: new JwkSigner(keys.protocolSigning),
			clientAssertionSigner: new JwkSigner(keys.protocolSigning),
		});

		// eslint-disable-next-line -- dynamic config assembly for test setup
		const authorityConfig: Record<string, unknown> = {
			entityId: entityId(eid),
			keyProvider,
			metadata: {
				federation_entity: (metadata.federation_entity as Record<string, string>) ?? {},
				...Object.fromEntries(Object.entries(metadata).filter(([k]) => k !== "federation_entity")),
			},
			storage,
			trustAnchors,
		};
		if (authorityHints) authorityConfig.authorityHints = authorityHints;
		if (entity.trustMarkIssuers) {
			authorityConfig.trustMarkIssuers = Object.fromEntries(
				Object.entries(entity.trustMarkIssuers).map(([tmType, issuers]) => [
					rewriteUrl(tmType),
					issuers.map(rewriteUrl),
				]),
			);
		}
		if (entity.trustMarks) authorityConfig.trustMarks = entity.trustMarks;
		if (entity.trustMarkOwners) authorityConfig.trustMarkOwners = entity.trustMarkOwners;
		if (entity.trustMarkDelegations)
			authorityConfig.trustMarkDelegations = entity.trustMarkDelegations;
		if (entity.entityConfigurationTtlSeconds !== undefined) {
			authorityConfig.entityConfigurationTtlSeconds = entity.entityConfigurationTtlSeconds;
		}
		const authority =
			authorityConfig.authorityHints && (authorityConfig.authorityHints as any).length > 0
				? new Intermediate(authorityConfig as unknown as AuthorityConfig)
				: new TrustAnchor(authorityConfig as unknown as AuthorityConfig);

		entities.set(entity.id, {
			server: authority,
			keys,
			keyProvider,
			oidcProtocolKeyProvider,
			storage,
		});
		apps.set(entity.id, createAuthorityApp(authority as any, eid));
	}

	// 4. Create leaf entities — both RPs and OPs are wired through the leaf phase here.
	for (const entity of topology.entities) {
		if (entity.role !== "leaf") continue;

		const eid = rewriteUrl(entity.id);
		const keys = getKeys(entity.id);
		const metadata = addProtocolJwks(entity, rewriteMetadata(entity.metadata), keys);
		const keyProvider = new MemoryFederationKeyProvider(federationSigningKey(keys.signing));
		const oidcProtocolKeyProvider = new StaticOidcProtocolKeyProvider({
			requestObjectSigner: new JwkSigner(keys.protocolSigning),
			clientAssertionSigner: new JwkSigner(keys.protocolSigning),
		});

		const authorityHints = entity.authorityHints?.map((h) => entityId(rewriteUrl(h))) ?? [];

		const leafConfig: Record<string, unknown> = {
			entityId: entityId(eid),
			keyProvider,
			authorityHints,
			metadata: metadata as Record<string, Record<string, unknown>>,
		};
		if (entity.trustMarks) leafConfig.trustMarks = entity.trustMarks;
		if (entity.entityConfigurationTtlSeconds !== undefined) {
			leafConfig.entityConfigurationTtlSeconds = entity.entityConfigurationTtlSeconds;
		}
		const leaf = new Leaf(leafConfig as unknown as ConstructorParameters<typeof Leaf>[0]);

		entities.set(entity.id, { server: leaf, keys, keyProvider, oidcProtocolKeyProvider });

		if (entity.protocolRole === "op") {
			apps.set(
				entity.id,
				createOpenIDProviderApp({
					leaf,
					entityId: eid,
					trustAnchors,
					federationKeyProvider: keyProvider,
					oidcSigningKey: keys.protocolSigning,
					allowedRequestUriHosts,
				}),
			);
		} else {
			const store = createRequestObjectStore();
			requestObjectStores.set(entity.id, store);
			apps.set(entity.id, createLeafApp(leaf, eid, { requestObjectStore: store }));
		}
	}

	// 5. Register subordinates in parent authority stores
	for (const entity of topology.entities) {
		if (!entity.authorityHints) continue;

		for (const parentId of entity.authorityHints) {
			const storage = authorityStorages.get(parentId);
			if (!storage) continue;

			const keys = getKeys(entity.id);
			const eid = rewriteUrl(entity.id);
			const metadata = addProtocolJwks(entity, rewriteMetadata(entity.metadata), keys);
			// Strip the subordinate's own operational federation_entity claims —
			// those belong only in its own Entity Configuration, not in the parent's
			// Subordinate Statement.
			const subordinateMetadata = sanitizeSubordinateMetadata(metadata as Record<string, unknown>);

			// Parent's constraints apply to all subordinate statements it issues
			const parentEntity = topology.entities.find((e) => e.id === parentId);
			const parentConstraints = parentEntity?.constraints;

			const record: SubordinateRecord = {
				entityId: entityId(eid),
				jwks: { keys: [keys.public] },
				...(subordinateMetadata !== undefined ? { metadata: subordinateMetadata } : {}),
				...(entity.metadataPolicy !== undefined ? { metadataPolicy: entity.metadataPolicy } : {}),
				...(parentConstraints !== undefined ? { constraints: parentConstraints } : {}),
				entityTypes: getEntityTypes(entity) as EntityType[],
				isIntermediate: entity.role === "intermediate" || entity.protocolRole === "op",
				createdAt: Date.now() / 1000,
				updatedAt: Date.now() / 1000,
			};

			await storage.subordinates.add(record);
		}
	}

	// 6. Add all apps to vhost server
	for (const [id, app] of apps) {
		testServer.addEntity(rewriteUrl(id), app);
	}

	return {
		server: testServer,
		entities,
		trustAnchors,
		requestObjectStores,
		async close() {
			await testServer.close();
		},
	};
}

export function getEntity(entities: Map<string, EntityInstance>, id: string): EntityInstance {
	const entity = entities.get(id);
	if (!entity) throw new Error(`Entity ${id} not found in test bed`);
	return entity;
}

function getEntityTypes(entity: EntityDefinition): string[] {
	return Object.keys(entity.metadata).length > 0
		? Object.keys(entity.metadata)
		: ["federation_entity"];
}
