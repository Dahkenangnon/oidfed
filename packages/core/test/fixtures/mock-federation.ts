import { JwtTyp } from "../../src/constants.js";
import { generateSigningKey } from "../../src/jose/keys.js";
import { signEntityStatement } from "../../src/jose/sign.js";
import type { JWK, JWKSet } from "../../src/schemas/jwk.js";
import type { EntityId, TrustAnchorSet } from "../../src/types.js";

interface EntityConfig {
	entityId: string;
	publicKey: JWK;
	privateKey: JWK;
	ecJwt: string;
	superiorId?: string;
	ssJwt?: string; // Subordinate statement signed by superior
	metadata?: Record<string, Record<string, unknown>>;
	metadataPolicy?: Record<string, Record<string, unknown>>;
	constraints?: Record<string, unknown>;
	authorityHints?: string[];
	trustMarkIssuers?: Record<string, string[]>;
}

export class MockFederationBuilder {
	private entities = new Map<string, EntityConfig>();
	private buildOrder: string[] = [];

	async addTrustAnchor(
		entityId: string,
		options?: {
			metadata?: Record<string, Record<string, unknown>>;
			trustMarkIssuers?: Record<string, string[]>;
		},
	): Promise<this> {
		const keys = await generateSigningKey("ES256");
		const payload: Record<string, unknown> = {
			iss: entityId,
			sub: entityId,
			iat: Math.floor(Date.now() / 1000),
			exp: Math.floor(Date.now() / 1000) + 86400,
			jwks: { keys: [keys.publicKey] },
		};
		if (options?.metadata) payload.metadata = options.metadata;
		if (options?.trustMarkIssuers) payload.trust_mark_issuers = options.trustMarkIssuers;

		// Add default federation_entity metadata with fetch endpoint
		if (!payload.metadata) {
			payload.metadata = {};
		}
		const md = payload.metadata as Record<string, Record<string, unknown>>;
		if (!md.federation_entity) {
			md.federation_entity = {};
		}
		if (!md.federation_entity.federation_fetch_endpoint) {
			md.federation_entity.federation_fetch_endpoint = `${entityId}/federation_fetch`;
		}

		const ecJwt = await signEntityStatement(payload, keys.privateKey, {
			typ: JwtTyp.EntityStatement,
		});

		this.entities.set(entityId, {
			entityId,
			publicKey: keys.publicKey,
			privateKey: keys.privateKey,
			ecJwt,
			metadata: options?.metadata,
			trustMarkIssuers: options?.trustMarkIssuers,
		});
		this.buildOrder.push(entityId);
		return this;
	}

	async addIntermediate(
		entityId: string,
		superiorId: string,
		options?: {
			metadata?: Record<string, Record<string, unknown>>;
			metadataPolicy?: Record<string, Record<string, unknown>>;
			constraints?: Record<string, unknown>;
		},
	): Promise<this> {
		const keys = await generateSigningKey("ES256");
		const superior = this.entities.get(superiorId);
		if (!superior) throw new Error(`Superior '${superiorId}' not found`);

		const now = Math.floor(Date.now() / 1000);

		// Entity Configuration
		const ecPayload: Record<string, unknown> = {
			iss: entityId,
			sub: entityId,
			iat: now,
			exp: now + 86400,
			jwks: { keys: [keys.publicKey] },
			authority_hints: [superiorId],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${entityId}/federation_fetch`,
				},
				...(options?.metadata ?? {}),
			},
		};

		const ecJwt = await signEntityStatement(ecPayload, keys.privateKey, {
			typ: JwtTyp.EntityStatement,
		});

		// Subordinate Statement (signed by superior)
		const ssPayload: Record<string, unknown> = {
			iss: superiorId,
			sub: entityId,
			iat: now,
			exp: now + 86400,
			jwks: { keys: [keys.publicKey] },
		};
		if (options?.metadataPolicy) ssPayload.metadata_policy = options.metadataPolicy;
		if (options?.constraints) ssPayload.constraints = options.constraints;

		const ssJwt = await signEntityStatement(ssPayload, superior.privateKey, {
			typ: JwtTyp.EntityStatement,
		});

		this.entities.set(entityId, {
			entityId,
			publicKey: keys.publicKey,
			privateKey: keys.privateKey,
			ecJwt,
			superiorId,
			ssJwt,
			metadata: options?.metadata,
			metadataPolicy: options?.metadataPolicy,
			constraints: options?.constraints,
			authorityHints: [superiorId],
		});
		this.buildOrder.push(entityId);
		return this;
	}

	async addLeaf(
		entityId: string,
		superiorId: string,
		options?: {
			metadata?: Record<string, Record<string, unknown>>;
			trustMarks?: Array<{ trust_mark_type: string; trust_mark: string }>;
		},
	): Promise<this> {
		const keys = await generateSigningKey("ES256");
		const superior = this.entities.get(superiorId);
		if (!superior) throw new Error(`Superior '${superiorId}' not found`);

		const now = Math.floor(Date.now() / 1000);

		// Entity Configuration
		const ecPayload: Record<string, unknown> = {
			iss: entityId,
			sub: entityId,
			iat: now,
			exp: now + 86400,
			jwks: { keys: [keys.publicKey] },
			authority_hints: [superiorId],
		};
		if (options?.metadata) ecPayload.metadata = options.metadata;
		if (options?.trustMarks) ecPayload.trust_marks = options.trustMarks;

		const ecJwt = await signEntityStatement(ecPayload, keys.privateKey, {
			typ: JwtTyp.EntityStatement,
		});

		// Subordinate Statement (signed by superior)
		const ssPayload: Record<string, unknown> = {
			iss: superiorId,
			sub: entityId,
			iat: now,
			exp: now + 86400,
			jwks: { keys: [keys.publicKey] },
		};

		const ssJwt = await signEntityStatement(ssPayload, superior.privateKey, {
			typ: JwtTyp.EntityStatement,
		});

		this.entities.set(entityId, {
			entityId,
			publicKey: keys.publicKey,
			privateKey: keys.privateKey,
			ecJwt,
			superiorId,
			ssJwt,
			metadata: options?.metadata,
			authorityHints: [superiorId],
		});
		this.buildOrder.push(entityId);
		return this;
	}

	build(): {
		trustAnchors: TrustAnchorSet;
		httpClient: (url: string | URL | Request, init?: RequestInit) => Promise<Response>;
		entities: ReadonlyMap<string, EntityConfig>;
	} {
		// Build trust anchors map
		const trustAnchors: Map<EntityId, { jwks: JWKSet }> = new Map();
		for (const [id, entity] of this.entities) {
			if (!entity.superiorId) {
				// Trust anchor (no superior)
				trustAnchors.set(id as EntityId, {
					jwks: { keys: [entity.publicKey] },
				});
			}
		}

		// Build response map
		const responses = new Map<string, string>();
		for (const [id, entity] of this.entities) {
			// Entity configuration at well-known
			responses.set(`${id}/.well-known/openid-federation`, entity.ecJwt);

			// Subordinate statements via fetch endpoint
			if (entity.superiorId) {
				const _superior = this.entities.get(entity.superiorId);
				// The superior's fetch endpoint serves this entity's SS
				const fetchUrl = `${entity.superiorId}/federation_fetch?sub=${encodeURIComponent(id)}`;
				responses.set(fetchUrl, entity.ssJwt as string);
			}
		}

		const httpClient = async (
			url: string | URL | Request,
			_init?: RequestInit,
		): Promise<Response> => {
			const urlStr = url.toString();
			const body = responses.get(urlStr);
			if (body) {
				return new Response(body, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			}
			return new Response("Not found", { status: 404 });
		};

		return {
			trustAnchors,
			httpClient,
			entities: this.entities,
		};
	}
}
