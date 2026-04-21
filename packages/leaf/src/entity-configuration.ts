/** Leaf entity factory: Entity Configuration serving with caching and trust chain discovery. */
import {
	DEFAULT_ENTITY_STATEMENT_TTL_SECONDS,
	type EntityId,
	type FederationMetadata,
	type FederationOptions,
	isValidEntityId,
	type JWK,
	JwtTyp,
	nowSeconds,
	signEntityStatement,
	stripPrivateFields,
	type TrustMarkRef,
} from "@oidfed/core";
import { createLeafHandler } from "./handler.js";

export interface LeafConfig {
	entityId: EntityId;
	signingKeys: JWK[];
	authorityHints: EntityId[];
	metadata: FederationMetadata;
	trustMarks?: TrustMarkRef[];
	entityConfigurationTtlSeconds?: number;
	options?: FederationOptions;
}

export interface LeafEntity {
	getEntityConfiguration(): Promise<string>;
	isEntityConfigurationExpired(): boolean;
	refreshEntityConfiguration(): Promise<string>;
	handler(): (request: Request) => Promise<Response>;
}

/** Creates a leaf entity that serves its Entity Configuration and supports trust chain discovery. */
export function createLeafEntity(config: LeafConfig): LeafEntity {
	if (!config.metadata || Object.keys(config.metadata).length === 0) {
		throw new Error("metadata MUST contain at least one Entity Type Identifier");
	}
	if (!config.authorityHints || config.authorityHints.length === 0) {
		throw new Error("authorityHints MUST NOT be empty for leaf entities");
	}
	for (const hint of config.authorityHints) {
		if (!isValidEntityId(hint)) {
			throw new Error(
				`authorityHint '${hint}' is not a valid Entity Identifier — MUST be HTTPS URL without query or fragment`,
			);
		}
	}
	if (!config.signingKeys || config.signingKeys.length === 0) {
		throw new Error("signingKeys MUST NOT be empty");
	}
	const kids = new Set<string>();
	for (const key of config.signingKeys) {
		if (!key.kid) {
			throw new Error("Every signing key MUST have a kid (Key ID) value");
		}
		if (kids.has(key.kid)) {
			throw new Error(`Duplicate kid '${key.kid}' found — every JWK MUST have a unique kid`);
		}
		// Symmetric keys have no public/private distinction; publishing would expose the secret.
		if ((key as Record<string, unknown>).kty === "oct") {
			throw new Error("Symmetric keys (kty 'oct') cannot be used as signing keys");
		}
		kids.add(key.kid);
	}

	const fedEntity = config.metadata?.federation_entity as Record<string, unknown> | undefined;
	if (fedEntity) {
		if ("federation_fetch_endpoint" in fedEntity) {
			throw new Error("Leaf entities MUST NOT publish federation_fetch_endpoint");
		}
		if ("federation_list_endpoint" in fedEntity) {
			throw new Error("Leaf entities MUST NOT publish federation_list_endpoint");
		}
	}

	const entityId = config.entityId.endsWith("/")
		? (config.entityId.slice(0, -1) as EntityId)
		: config.entityId;

	if (!isValidEntityId(entityId)) {
		throw new Error("entityId MUST be a valid HTTPS URL without query or fragment");
	}

	const ttlSeconds = config.entityConfigurationTtlSeconds ?? DEFAULT_ENTITY_STATEMENT_TTL_SECONDS;

	// exp <= iat produces immediately-invalid JWT.
	if (ttlSeconds <= 0) {
		throw new Error("entityConfigurationTtlSeconds must be positive");
	}

	// Safe: validated non-empty above.
	const signingKey = config.signingKeys[0] as JWK;

	// Precompute public keys once — avoids re-stripping on every build.
	const publicKeys = config.signingKeys.map(stripPrivateFields);

	let cachedJwt: string | null = null;
	let cachedExp: number | null = null;
	let inflight: Promise<string> | null = null;

	async function buildEntityConfiguration(): Promise<string> {
		const now = nowSeconds();
		const exp = now + ttlSeconds;

		const payload: Record<string, unknown> = {
			iss: entityId,
			sub: entityId,
			iat: now,
			exp,
			jwks: { keys: publicKeys },
			authority_hints: config.authorityHints,
			metadata: config.metadata,
		};

		if (config.trustMarks && config.trustMarks.length > 0) {
			payload.trust_marks = config.trustMarks;
		}

		const jwt = await signEntityStatement(payload, signingKey, {
			kid: signingKey.kid as string,
			typ: JwtTyp.EntityStatement,
		});

		cachedJwt = jwt;
		cachedExp = exp;
		return jwt;
	}

	const entity: LeafEntity = {
		async getEntityConfiguration(): Promise<string> {
			if (cachedJwt && !entity.isEntityConfigurationExpired()) {
				return cachedJwt;
			}
			// Cache stampede protection: concurrent callers share one signing operation.
			if (inflight) return inflight;
			inflight = buildEntityConfiguration().finally(() => {
				inflight = null;
			});
			return inflight;
		},

		isEntityConfigurationExpired(): boolean {
			if (cachedExp === null) return true;
			const now = nowSeconds();
			return now >= cachedExp;
		},

		async refreshEntityConfiguration(): Promise<string> {
			// Invalidate any in-progress build so its result won't overwrite ours.
			inflight = null;
			return buildEntityConfiguration();
		},

		handler(): (request: Request) => Promise<Response> {
			return createLeafHandler(entity, config.options);
		},
	};

	return entity;
}
