import type { AuthorityConfig, AuthorityServer, SubordinateRecord } from "@oidfed/authority";
import {
	createAuthorityServer,
	MemoryKeyStore,
	MemorySubordinateStore,
	MemoryTrustMarkStore,
} from "@oidfed/authority";
import type { EntityType, JWK, TrustAnchorSet } from "@oidfed/core";
import { entityId, generateSigningKey } from "@oidfed/core";
import type { LeafEntity } from "@oidfed/leaf";
import { createLeafEntity } from "@oidfed/leaf";
import type { Express } from "express";
import { createAuthorityApp } from "../participants/authority-app.js";
import { createLeafApp } from "../participants/leaf-app.js";
import { createOpenIDProviderApp } from "../participants/openid-provider-app.js";
import type { EntityDefinition, TopologyDefinition } from "../topologies/types.js";
import {
	createAndStartFederationTestServer,
	type FederationServerOptions,
	type FederationTestServer,
} from "./federation-server.js";

export interface LaunchOptions extends FederationServerOptions {}

export interface EntityInstance {
	server: AuthorityServer | LeafEntity;
	keys: { signing: JWK; public: JWK };
	keyStore?: MemoryKeyStore;
	trustMarkStore?: MemoryTrustMarkStore;
}

export interface FederationTestBed {
	server: FederationTestServer;
	entities: Map<string, EntityInstance>;
	trustAnchors: TrustAnchorSet;
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

	// 1. Generate keys for all entities
	const entityKeys = new Map<string, { signing: JWK; public: JWK }>();
	for (const entity of topology.entities) {
		const key = await generateSigningKey("ES256");
		entityKeys.set(entity.id, {
			signing: key.privateKey as JWK,
			public: key.publicKey as JWK,
		});
	}

	const getKeys = (id: string) => {
		const k = entityKeys.get(id);
		if (!k) throw new Error(`No keys for entity ${id}`);
		return k;
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
	const subordinateStores = new Map<string, MemorySubordinateStore>();
	const apps = new Map<string, Express>();

	// 3. Create authority entities (TA, intermediate, OP)
	for (const entity of topology.entities) {
		const isAuthority =
			entity.role === "trust-anchor" ||
			entity.role === "intermediate" ||
			entity.protocolRole === "op";
		if (!isAuthority) continue;

		const eid = rewriteUrl(entity.id);
		const keys = getKeys(entity.id);
		const metadata = rewriteMetadata(entity.metadata);
		const subordinateStore = new MemorySubordinateStore();
		subordinateStores.set(entity.id, subordinateStore);

		const authorityHints = entity.authorityHints?.map((h) => entityId(rewriteUrl(h)));

		const trustMarkStore = new MemoryTrustMarkStore();
		const keyStore = new MemoryKeyStore(keys.signing);

		// eslint-disable-next-line -- dynamic config assembly for test setup
		const authorityConfig: Record<string, unknown> = {
			entityId: entityId(eid),
			signingKeys: [keys.signing],
			metadata: {
				federation_entity: (metadata.federation_entity as Record<string, string>) ?? {},
				...Object.fromEntries(Object.entries(metadata).filter(([k]) => k !== "federation_entity")),
			},
			subordinateStore,
			keyStore,
			trustMarkStore,
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
		const authority = createAuthorityServer(authorityConfig as unknown as AuthorityConfig);

		entities.set(entity.id, { server: authority, keys, keyStore, trustMarkStore });

		if (entity.protocolRole === "op") {
			apps.set(
				entity.id,
				createOpenIDProviderApp({
					authority,
					entityId: eid,
					trustAnchors,
				}),
			);
		} else {
			apps.set(entity.id, createAuthorityApp(authority, eid));
		}
	}

	// 4. Create leaf entities (non-OP)
	for (const entity of topology.entities) {
		if (entity.protocolRole === "op") continue;
		if (entity.role !== "leaf") continue;

		const eid = rewriteUrl(entity.id);
		const keys = getKeys(entity.id);
		const metadata = rewriteMetadata(entity.metadata);

		const authorityHints = entity.authorityHints?.map((h) => entityId(rewriteUrl(h))) ?? [];

		const leafConfig: Record<string, unknown> = {
			entityId: entityId(eid),
			signingKeys: [keys.signing],
			authorityHints,
			metadata: metadata as Record<string, Record<string, unknown>>,
		};
		if (entity.trustMarks) leafConfig.trustMarks = entity.trustMarks;
		if (entity.entityConfigurationTtlSeconds !== undefined) {
			leafConfig.entityConfigurationTtlSeconds = entity.entityConfigurationTtlSeconds;
		}
		const leaf = createLeafEntity(leafConfig as unknown as Parameters<typeof createLeafEntity>[0]);

		entities.set(entity.id, { server: leaf, keys });
		apps.set(entity.id, createLeafApp(leaf, eid));
	}

	// 5. Register subordinates in parent authority stores
	for (const entity of topology.entities) {
		if (!entity.authorityHints) continue;

		for (const parentId of entity.authorityHints) {
			const store = subordinateStores.get(parentId);
			if (!store) continue;

			const keys = getKeys(entity.id);
			const eid = rewriteUrl(entity.id);
			const metadata = rewriteMetadata(entity.metadata);

			// Parent's constraints apply to all subordinate statements it issues
			const parentEntity = topology.entities.find((e) => e.id === parentId);
			const parentConstraints = parentEntity?.constraints;

			const record: SubordinateRecord = {
				entityId: entityId(eid),
				jwks: { keys: [keys.public] },
				metadata,
				...(entity.metadataPolicy !== undefined ? { metadataPolicy: entity.metadataPolicy } : {}),
				...(parentConstraints !== undefined ? { constraints: parentConstraints } : {}),
				entityTypes: getEntityTypes(entity) as EntityType[],
				isIntermediate: entity.role === "intermediate" || entity.protocolRole === "op",
				createdAt: Date.now() / 1000,
				updatedAt: Date.now() / 1000,
			};

			await store.add(record);
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
