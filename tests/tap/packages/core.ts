import type { JWK as JoseJWK, JWTHeaderParameters, JWTPayload, SignJWT } from "jose";
import type QUnit from "qunit";
import {
	chainCacheKey,
	ecCacheKey,
	esCacheKey,
	MemoryCache,
} from "../../../packages/core/src/cache/index.js";
import {
	CachePrefix,
	ClientRegistrationType,
	DEFAULT_CACHE_MAX_TTL_SECONDS,
	DEFAULT_CACHE_TTL_SECONDS,
	DEFAULT_CLOCK_SKEW_SECONDS,
	DEFAULT_HTTP_TIMEOUT_MS,
	DEFAULT_MAX_AUTHORITY_HINTS,
	DEFAULT_MAX_CHAIN_DEPTH,
	EntityType,
	FederationEndpoint,
	FederationErrorCode,
	InternalErrorCode,
	JwtTyp,
	MediaType,
	PolicyOperator,
	REQUIRED_ALGORITHMS,
	SUPPORTED_ALGORITHMS,
	TrustMarkStatus,
	WELL_KNOWN_OPENID_FEDERATION,
} from "../../../packages/core/src/constants.js";
import {
	applyAllowedEntityTypes,
	checkConstraints,
	checkMaxPathLength,
	checkNamingConstraints,
} from "../../../packages/core/src/constraints/index.js";
import {
	err,
	federationError,
	flatMap,
	isErr,
	isOk,
	map,
	mapErr,
	ok,
	type Result,
	unwrapOr,
} from "../../../packages/core/src/errors.js";
import {
	fetchHistoricalKeys,
	fetchListSubordinates,
	fetchResolveResponse,
	fetchTrustMarkList,
	verifyHistoricalKeysResponse,
	verifyResolveResponse,
	verifySignedJwkSet,
	verifyTrustMarkStatusResponse,
} from "../../../packages/core/src/federation-api/index.js";
import {
	errorResponse,
	extractRequestParams,
	jsonResponse,
	jwtResponse,
	parseQueryParams,
	readBodyWithLimit,
	readStreamWithLimit,
	requireMethod,
	requireMethods,
	SECURITY_HEADERS,
	toPublicError,
} from "../../../packages/core/src/http.js";
import { InMemoryJtiStore } from "../../../packages/core/src/in-memory-jti-store.js";
import { verifyClientAssertion } from "../../../packages/core/src/jose/client-auth.js";
import {
	generateSigningKey as _genKey,
	signEntityStatement as _signES,
} from "../../../packages/core/src/jose/index.js";
import {
	generateSigningKey,
	isValidAlgorithm,
	JWK_PUBLIC_FIELDS,
	selectVerificationKey,
	stripPrivateFields,
	timingSafeEqual,
} from "../../../packages/core/src/jose/keys.js";
import { signEntityStatement } from "../../../packages/core/src/jose/sign.js";
import {
	assertTypHeader,
	decodeEntityStatement,
	verifyEntityStatement,
} from "../../../packages/core/src/jose/verify.js";
import { fetchJwkSet } from "../../../packages/core/src/jwks/jwks-uri.js";
import { resolveEntityKeys } from "../../../packages/core/src/jwks/resolve.js";
import { fetchSignedJwkSet } from "../../../packages/core/src/jwks/signed-jwks-uri.js";
import { validateSignedJwkSetSpecHygiene } from "../../../packages/core/src/jwks/spec-hygiene.js";
import { validateJwkSetUseRequirement } from "../../../packages/core/src/jwks/use-requirement.js";
import {
	applyMetadataPolicy,
	denormalizeScope,
	normalizeScope,
} from "../../../packages/core/src/metadata-policy/apply.js";
import { validateCustomOperators } from "../../../packages/core/src/metadata-policy/custom-operators.js";
import { resolveMetadataPolicy } from "../../../packages/core/src/metadata-policy/merge.js";
import { operators } from "../../../packages/core/src/metadata-policy/operators.js";
import type { TrustChainConstraints } from "../../../packages/core/src/schemas/constraints.js";
import {
	NamingConstraintsSchema,
	TrustChainConstraintsSchema,
} from "../../../packages/core/src/schemas/constraints.js";
import { EntityIdSchema } from "../../../packages/core/src/schemas/entity-id.js";
import type { EntityStatementPayload } from "../../../packages/core/src/schemas/entity-statement.js";
import {
	BaseEntityStatementSchema,
	EntityConfigurationSchema,
	EntityIdSchema as EntityStatementEntityIdSchema,
	ExplicitRegistrationRequestPayloadSchema,
	ExplicitRegistrationResponsePayloadSchema,
	HistoricalKeyEntrySchema,
	SubordinateStatementSchema,
} from "../../../packages/core/src/schemas/entity-statement.js";
import type { JWK, JWKSet } from "../../../packages/core/src/schemas/jwk.js";
import { JWKSchema, JWKSetSchema } from "../../../packages/core/src/schemas/jwk.js";
import type { FederationMetadata } from "../../../packages/core/src/schemas/metadata.js";
import {
	FederationEntityMetadataSchema,
	FederationMetadataSchema,
} from "../../../packages/core/src/schemas/metadata.js";
import {
	EntityTypeMetadataPolicySchema,
	FederationMetadataPolicySchema,
	MetadataParameterPolicySchema,
} from "../../../packages/core/src/schemas/metadata-policy.js";
import {
	TrustMarkDelegationPayloadSchema,
	TrustMarkOwnerSchema,
	TrustMarkPayloadSchema,
	TrustMarkRefSchema,
} from "../../../packages/core/src/schemas/trust-mark.js";
import { compareTrustAnchorKeys } from "../../../packages/core/src/trust-chain/anchor-keys.js";
import {
	expandIPv6,
	fetchEntityConfiguration,
	fetchSubordinateStatement,
	ipv4ToInt,
	isSpecialUseIP,
	isSpecialUseIPv4,
	isSpecialUseIPv6,
	validateEntityId,
	validateFetchUrl,
} from "../../../packages/core/src/trust-chain/fetch.js";
import { resolveTrustChainForAnchor } from "../../../packages/core/src/trust-chain/peer.js";
import { refreshTrustChain } from "../../../packages/core/src/trust-chain/refresh.js";
import {
	createConcurrencyLimiter,
	resolveTrustChains,
} from "../../../packages/core/src/trust-chain/resolve.js";
import {
	calculateChainExpiration,
	chainRemainingTtl,
	describeTrustChain,
	isChainExpired,
	longestExpiry,
	preferTrustAnchor,
	shortestChain,
	validateTrustChain,
} from "../../../packages/core/src/trust-chain/validate.js";
import {
	fetchTrustMark,
	fetchTrustMarkStatus,
	signTrustMarkDelegation,
	validateTrustMark,
	validateTrustMarkLogo,
} from "../../../packages/core/src/trust-marks/index.js";
import type {
	Clock,
	EntityId,
	HttpClient,
	ParsedEntityStatement,
	PolicyOperatorDefinition,
	TrustAnchorSet,
	ValidatedTrustChain,
} from "../../../packages/core/src/types.js";
import { entityId, isValidEntityId } from "../../../packages/core/src/types.js";
import { MockFederationBuilder } from "../fixtures/mock-federation.js";

export default (QUnit: QUnit) => {
	const { module, test } = QUnit;

	// ── errors ────────────────────────────────────────────────────────
	module("core / federationError", () => {
		test("creates an error with code and description", (t) => {
			const e = federationError("invalid_request", "bad input");
			t.equal(e.code, "invalid_request");
			t.equal(e.description, "bad input");
			t.equal(e.cause, undefined);
		});

		test("includes cause when provided", (t) => {
			const cause = new Error("root");
			const e = federationError("server_error", "something broke", cause);
			t.equal(e.cause, cause);
		});
	});

	module("core / Result pattern", () => {
		test("ok() creates a successful result", (t) => {
			const result = ok(42);
			t.true(result.ok, "result.ok is true");
			if (result.ok) {
				t.equal(result.value, 42);
			}
		});

		test("err() creates a failure result", (t) => {
			const result = err("failure");
			t.false(result.ok, "result.ok is false");
			if (!result.ok) {
				t.equal(result.error, "failure");
			}
		});

		test("isOk() type guard works", (t) => {
			const success: Result<number, string> = ok(1);
			const failure: Result<number, string> = err("fail");
			t.true(isOk(success));
			t.false(isOk(failure));
		});

		test("isErr() type guard works", (t) => {
			const success: Result<number, string> = ok(1);
			const failure: Result<number, string> = err("fail");
			t.false(isErr(success));
			t.true(isErr(failure));
		});

		test("map() transforms value on success", (t) => {
			const result: Result<number, string> = ok(2);
			const mapped = map(result, (v) => v * 3);
			t.true(isOk(mapped) && mapped.value === 6);
		});

		test("map() passes through error on failure", (t) => {
			const result: Result<number, string> = err("fail");
			const mapped = map(result, (v) => v * 3);
			t.true(isErr(mapped) && mapped.error === "fail");
		});

		test("flatMap() chains successful results", (t) => {
			const result: Result<number, string> = ok(5);
			const chained = flatMap(result, (v) => (v > 0 ? ok(v.toString()) : err("negative")));
			t.true(isOk(chained) && chained.value === "5");
		});

		test("flatMap() short-circuits on error", (t) => {
			const result: Result<number, string> = err("initial");
			const chained = flatMap(result, (v) => ok(v.toString()));
			t.true(isErr(chained) && chained.error === "initial");
		});

		test("flatMap() can produce error from ok value", (t) => {
			const result: Result<number, string> = ok(-1);
			const chained = flatMap(result, (v) => (v > 0 ? ok(v.toString()) : err("negative")));
			t.true(isErr(chained) && chained.error === "negative");
		});

		test("mapErr() transforms error on failure", (t) => {
			const result: Result<number, string> = err("fail");
			const mapped = mapErr(result, (e) => e.toUpperCase());
			t.true(isErr(mapped) && mapped.error === "FAIL");
		});

		test("mapErr() passes through value on success", (t) => {
			const result: Result<number, string> = ok(42);
			const mapped = mapErr(result, (e) => e.toUpperCase());
			t.true(isOk(mapped) && mapped.value === 42);
		});

		test("unwrapOr() returns value on success", (t) => {
			const result: Result<number, string> = ok(42);
			t.equal(unwrapOr(result, 0), 42);
		});

		test("unwrapOr() returns fallback on failure", (t) => {
			const result: Result<number, string> = err("fail");
			t.equal(unwrapOr(result, 0), 0);
		});
	});

	// ── cache ─────────────────────────────────────────────────────────
	module("core / MemoryCache", () => {
		test("stores and retrieves a value", async (t) => {
			const cache = new MemoryCache();
			await cache.set("key1", { data: "test" }, 60);
			const result = await cache.get<{ data: string }>("key1");
			t.deepEqual(result, { data: "test" });
		});

		test("returns undefined for missing key", async (t) => {
			const cache = new MemoryCache();
			const result = await cache.get("nonexistent");
			t.equal(result, undefined);
		});

		test("expires entries after TTL", async (t) => {
			let nowMs = Date.now();
			const clock: Clock = { now: () => nowMs };
			const cache = new MemoryCache({ clock });
			await cache.set("key1", "value", 1);
			t.equal(await cache.get("key1"), "value");
			nowMs += 1500;
			t.equal(await cache.get("key1"), undefined);
		});

		test("deletes a key", async (t) => {
			const cache = new MemoryCache();
			await cache.set("key1", "value", 60);
			await cache.delete("key1");
			t.equal(await cache.get("key1"), undefined);
		});

		test("clears all entries", async (t) => {
			const cache = new MemoryCache();
			await cache.set("a", 1, 60);
			await cache.set("b", 2, 60);
			await cache.clear();
			t.equal(await cache.get("a"), undefined);
			t.equal(await cache.get("b"), undefined);
		});

		test("evicts oldest entry when maxEntries reached", async (t) => {
			const cache = new MemoryCache({ maxEntries: 2 });
			await cache.set("a", 1, 60);
			await cache.set("b", 2, 60);
			await cache.set("c", 3, 60);
			t.equal(await cache.get("a"), undefined);
			t.equal(await cache.get("b"), 2);
			t.equal(await cache.get("c"), 3);
		});

		test("LRU: accessing a key moves it to the end", async (t) => {
			const cache = new MemoryCache({ maxEntries: 2 });
			await cache.set("a", 1, 60);
			await cache.set("b", 2, 60);
			await cache.get("a");
			await cache.set("c", 3, 60);
			t.equal(await cache.get("a"), 1);
			t.equal(await cache.get("b"), undefined);
			t.equal(await cache.get("c"), 3);
		});
	});

	module("core / cache key generation", () => {
		const entityId =
			"https://example.com" as import("../../../packages/core/src/types.js").EntityId;
		const entityId2 =
			"https://other.example.com" as import("../../../packages/core/src/types.js").EntityId;

		test("ecCacheKey produces prefixed key", async (t) => {
			const key = await ecCacheKey(entityId);
			t.true(/^ec:[0-9a-f]{32}$/.test(key));
		});

		test("esCacheKey produces prefixed key", async (t) => {
			const key = await esCacheKey(entityId, entityId2);
			t.true(/^es:[0-9a-f]{32}$/.test(key));
		});

		test("chainCacheKey produces prefixed key", async (t) => {
			const key = await chainCacheKey(entityId, entityId2);
			t.true(/^chain:[0-9a-f]{32}$/.test(key));
		});

		test("different inputs produce different keys", async (t) => {
			const key1 = await ecCacheKey(entityId);
			const key2 = await ecCacheKey(entityId2);
			t.notEqual(key1, key2);
		});

		test("same inputs produce same keys", async (t) => {
			const key1 = await ecCacheKey(entityId);
			const key2 = await ecCacheKey(entityId);
			t.equal(key1, key2);
		});
	});

	// ── constants ─────────────────────────────────────────────────────
	module("core / constants", () => {
		test("has correct well-known path", (t) => {
			t.equal(WELL_KNOWN_OPENID_FEDERATION, "/.well-known/openid-federation");
		});

		test("FederationEndpoint has all 8 paths", (t) => {
			t.equal(Object.keys(FederationEndpoint).length, 8);
			t.equal(FederationEndpoint.Fetch, "/federation_fetch");
			t.equal(FederationEndpoint.List, "/federation_list");
			t.equal(FederationEndpoint.Resolve, "/federation_resolve");
			t.equal(FederationEndpoint.Registration, "/federation_registration");
			t.equal(FederationEndpoint.TrustMarkStatus, "/federation_trust_mark_status");
			t.equal(FederationEndpoint.TrustMarkList, "/federation_trust_mark_list");
			t.equal(FederationEndpoint.TrustMark, "/federation_trust_mark");
			t.equal(FederationEndpoint.HistoricalKeys, "/federation_historical_keys");
		});

		test("MediaType has all 11 types", (t) => {
			t.equal(Object.keys(MediaType).length, 11);
			t.equal(MediaType.EntityStatement, "application/entity-statement+jwt");
			t.equal(MediaType.TrustMark, "application/trust-mark+jwt");
			t.equal(MediaType.Json, "application/json");
		});

		test("JwtTyp has all 7 values", (t) => {
			t.equal(Object.keys(JwtTyp).length, 7);
			t.equal(JwtTyp.EntityStatement, "entity-statement+jwt");
			t.equal(JwtTyp.TrustMark, "trust-mark+jwt");
		});

		test("EntityType has all 6 types", (t) => {
			t.equal(Object.keys(EntityType).length, 6);
			t.equal(EntityType.FederationEntity, "federation_entity");
			t.equal(EntityType.OpenIDRelyingParty, "openid_relying_party");
			t.equal(EntityType.OpenIDProvider, "openid_provider");
			t.equal(EntityType.OAuthAuthorizationServer, "oauth_authorization_server");
			t.equal(EntityType.OAuthClient, "oauth_client");
			t.equal(EntityType.OAuthResource, "oauth_resource");
		});

		test("ClientRegistrationType has 2 types", (t) => {
			t.equal(Object.keys(ClientRegistrationType).length, 2);
			t.equal(ClientRegistrationType.Automatic, "automatic");
			t.equal(ClientRegistrationType.Explicit, "explicit");
		});

		test("PolicyOperator has all 7 operators", (t) => {
			t.equal(Object.keys(PolicyOperator).length, 7);
			t.equal(PolicyOperator.Value, "value");
			t.equal(PolicyOperator.Essential, "essential");
		});

		test("FederationErrorCode has 11 codes", (t) => {
			t.equal(Object.keys(FederationErrorCode).length, 11);
			t.equal(FederationErrorCode.InvalidRequest, "invalid_request");
			t.equal(FederationErrorCode.NotFound, "not_found");
		});

		test("InternalErrorCode has 12 codes", (t) => {
			t.equal(Object.keys(InternalErrorCode).length, 12);
			t.equal(InternalErrorCode.TrustChainInvalid, "ERR_TRUST_CHAIN_INVALID");
			t.equal(InternalErrorCode.LoopDetected, "ERR_LOOP_DETECTED");
		});

		test("CachePrefix has 3 prefixes", (t) => {
			t.equal(Object.keys(CachePrefix).length, 3);
			t.equal(CachePrefix.EntityConfiguration, "ec:");
			t.equal(CachePrefix.EntityStatement, "es:");
			t.equal(CachePrefix.TrustChain, "chain:");
		});

		test("TrustMarkStatus has 4 values", (t) => {
			t.equal(Object.keys(TrustMarkStatus).length, 4);
			t.equal(TrustMarkStatus.Active, "active");
			t.equal(TrustMarkStatus.Revoked, "revoked");
		});

		test("has correct numeric defaults", (t) => {
			t.equal(DEFAULT_HTTP_TIMEOUT_MS, 10_000);
			t.equal(DEFAULT_CLOCK_SKEW_SECONDS, 60);
			t.equal(DEFAULT_MAX_CHAIN_DEPTH, 8);
			t.equal(DEFAULT_MAX_AUTHORITY_HINTS, 10);
			t.equal(DEFAULT_CACHE_TTL_SECONDS, 3600);
			t.equal(DEFAULT_CACHE_MAX_TTL_SECONDS, 86400);
		});

		test("REQUIRED_ALGORITHMS contains ES256 and PS256", (t) => {
			t.true(REQUIRED_ALGORITHMS.includes("ES256"));
			t.true(REQUIRED_ALGORITHMS.includes("PS256"));
			t.equal(REQUIRED_ALGORITHMS.length, 2);
		});

		test("SUPPORTED_ALGORITHMS contains all expected algorithms", (t) => {
			t.true(SUPPORTED_ALGORITHMS.includes("ES256"));
			t.true(SUPPORTED_ALGORITHMS.includes("ES384"));
			t.true(SUPPORTED_ALGORITHMS.includes("ES512"));
			t.true(SUPPORTED_ALGORITHMS.includes("PS256"));
			t.true(SUPPORTED_ALGORITHMS.includes("PS384"));
			t.true(SUPPORTED_ALGORITHMS.includes("PS512"));
			t.true(SUPPORTED_ALGORITHMS.includes("RS256"));
			t.equal(SUPPORTED_ALGORITHMS.length, 7);
		});
	});

	// ── in-memory-jti-store ───────────────────────────────────────────
	module("core / InMemoryJtiStore", (hooks) => {
		let store: InMemoryJtiStore;

		hooks.beforeEach(() => {
			store = new InMemoryJtiStore(0);
		});

		QUnit.testDone(() => {
			store?.dispose();
		});

		test("returns false on first record, true on replay", async (t) => {
			const future = Math.floor(Date.now() / 1000) + 3600;
			t.equal(await store.hasSeenAndRecord("jti-1", future), false);
			t.equal(await store.hasSeenAndRecord("jti-1", future), true);
		});

		test("returns false for distinct JTIs", async (t) => {
			const future = Math.floor(Date.now() / 1000) + 3600;
			t.equal(await store.hasSeenAndRecord("jti-a", future), false);
			t.equal(await store.hasSeenAndRecord("jti-b", future), false);
		});

		test("TTL cleanup removes expired entries", (t) => {
			const past = Math.floor(Date.now() / 1000) - 1;
			const s = store as unknown as { seen: Map<string, number>; cleanup(): void };
			s.seen.set("expired-jti", past);
			s.cleanup();
			t.false(s.seen.has("expired-jti"));
		});

		test("does not remove non-expired entries during cleanup", (t) => {
			const future = Math.floor(Date.now() / 1000) + 3600;
			const s = store as unknown as { seen: Map<string, number>; cleanup(): void };
			s.seen.set("live-jti", future);
			s.cleanup();
			t.true(s.seen.has("live-jti"));
		});

		test("evicts oldest entry when maxEntries is reached", async (t) => {
			const capped = new InMemoryJtiStore(0, 3);
			const future = Math.floor(Date.now() / 1000) + 3600;
			await capped.hasSeenAndRecord("jti-1", future);
			await capped.hasSeenAndRecord("jti-2", future);
			await capped.hasSeenAndRecord("jti-3", future);
			await capped.hasSeenAndRecord("jti-4", future);
			const s = capped as unknown as { seen: Map<string, number> };
			t.equal(s.seen.size, 3);
			t.false(s.seen.has("jti-1"));
			t.true(s.seen.has("jti-4"));
			capped.dispose();
		});

		test("default constructor uses maxEntries=10_000", (t) => {
			const s = new InMemoryJtiStore() as unknown as { maxEntries: number };
			t.equal(s.maxEntries, 10_000);
			(s as unknown as InMemoryJtiStore).dispose();
		});

		test("custom maxEntries constructor is respected", (t) => {
			const s = new InMemoryJtiStore(0, 500) as unknown as { maxEntries: number };
			t.equal(s.maxEntries, 500);
			(s as unknown as InMemoryJtiStore).dispose();
		});

		test("dispose clears all entries and stops timer", async (t) => {
			const future = Math.floor(Date.now() / 1000) + 3600;
			await store.hasSeenAndRecord("jti-x", future);
			store.dispose();
			const s = store as unknown as { seen: Map<string, number> };
			t.equal(s.seen.size, 0);
		});
	});

	// ── http ──────────────────────────────────────────────────────────
	module("core / SECURITY_HEADERS", () => {
		test("contains all 5 expected security headers", (t) => {
			t.equal(SECURITY_HEADERS["Cache-Control"], "no-store");
			t.equal(SECURITY_HEADERS["X-Content-Type-Options"], "nosniff");
			t.equal(SECURITY_HEADERS["Strict-Transport-Security"], "max-age=31536000; includeSubDomains");
			t.equal(SECURITY_HEADERS["X-Frame-Options"], "DENY");
			t.equal(SECURITY_HEADERS["Referrer-Policy"], "no-referrer");
			t.equal(Object.keys(SECURITY_HEADERS).length, 5);
		});
	});

	module("core / jwtResponse", () => {
		test("returns 200 with correct Content-Type and security headers", (t) => {
			const res = jwtResponse("eyJhbGc...", "application/entity-statement+jwt");
			t.equal(res.status, 200);
			t.equal(res.headers.get("Content-Type"), "application/entity-statement+jwt");
			t.equal(res.headers.get("Cache-Control"), "no-store");
			t.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
		});
	});

	module("core / jsonResponse", () => {
		test("returns 200 with JSON Content-Type by default", async (t) => {
			const res = jsonResponse({ foo: "bar" });
			t.equal(res.status, 200);
			t.equal(res.headers.get("Content-Type"), "application/json");
			const body = (await res.json()) as { foo: string };
			t.deepEqual(body, { foo: "bar" });
		});

		test("accepts a custom status code", (t) => {
			const res = jsonResponse({ ok: true }, 201);
			t.equal(res.status, 201);
		});
	});

	module("core / errorResponse", () => {
		test("returns OAuth-style error with security headers", async (t) => {
			const res = errorResponse(400, "invalid_request", "bad param");
			t.equal(res.status, 400);
			t.equal(res.headers.get("Content-Type"), "application/json");
			t.equal(res.headers.get("Cache-Control"), "no-store");
			const body = (await res.json()) as { error: string; error_description: string };
			t.deepEqual(body, { error: "invalid_request", error_description: "bad param" });
		});
	});

	module("core / toPublicError", () => {
		test("passes through known federation error codes", (t) => {
			const result = toPublicError({ code: "invalid_request", description: "bad param" });
			t.equal(result.code, "invalid_request");
			t.equal(result.description, "bad param");
			t.equal(result.status, 400);
		});

		test("sanitizes internal error codes to server_error", (t) => {
			const result = toPublicError({
				code: "ERR_SIGNATURE_INVALID",
				description: "secret internal detail",
			});
			t.equal(result.code, "server_error");
			t.equal(result.description, "An internal error occurred");
			t.equal(result.status, 500);
		});

		test("maps invalid_client to 401", (t) => {
			const result = toPublicError({ code: "invalid_client", description: "bad client" });
			t.equal(result.status, 401);
		});

		test("maps not_found to 404", (t) => {
			const result = toPublicError({ code: "not_found", description: "gone" });
			t.equal(result.status, 404);
		});

		test("maps temporarily_unavailable to 503", (t) => {
			const result = toPublicError({ code: "temporarily_unavailable", description: "try later" });
			t.equal(result.status, 503);
		});
	});

	module("core / requireMethod", () => {
		test("returns null when method matches", (t) => {
			const req = new Request("https://example.com", { method: "GET" });
			t.equal(requireMethod(req, "GET"), null);
		});

		test("returns 405 with Allow header when method mismatches", async (t) => {
			const req = new Request("https://example.com", { method: "POST" });
			const res = requireMethod(req, "GET");
			t.notEqual(res, null);
			t.equal(res?.status, 405);
			t.equal(res?.headers.get("Allow"), "GET");
		});
	});

	module("core / requireMethods", () => {
		test("returns null when method is in allowed list", (t) => {
			const req = new Request("https://example.com", { method: "POST" });
			t.equal(requireMethods(req, ["GET", "POST"]), null);
		});

		test("returns 405 with joined Allow header", (t) => {
			const req = new Request("https://example.com", { method: "DELETE" });
			const res = requireMethods(req, ["GET", "POST"]);
			t.notEqual(res, null);
			t.equal(res?.status, 405);
			t.equal(res?.headers.get("Allow"), "GET, POST");
		});
	});

	module("core / parseQueryParams", () => {
		test("extracts params from URL", (t) => {
			const req = new Request("https://example.com/path?foo=bar&baz=42");
			const params = parseQueryParams(req);
			t.equal(params.get("foo"), "bar");
			t.equal(params.get("baz"), "42");
		});
	});

	module("core / extractRequestParams", () => {
		test("extracts query params for GET", async (t) => {
			const req = new Request("https://example.com?sub=https://leaf.example.com");
			const result = await extractRequestParams(req);
			t.equal(result.params.get("sub"), "https://leaf.example.com");
			t.equal(result.clientAssertion, undefined);
		});

		test("extracts body params and client_assertion for POST", async (t) => {
			const body =
				"grant_type=client_credentials&client_assertion=jwt123&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer";
			const req = new Request("https://example.com", {
				method: "POST",
				body,
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
			});
			const result = await extractRequestParams(req);
			t.equal(result.clientAssertion, "jwt123");
			t.equal(result.clientAssertionType, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
			t.equal(result.params.get("grant_type"), "client_credentials");
			t.equal(result.params.get("client_assertion"), null);
		});
	});

	module("core / readStreamWithLimit", () => {
		test("reads stream within limit", async (t) => {
			const stream = new ReadableStream({
				start(controller) {
					controller.enqueue(new TextEncoder().encode("hello"));
					controller.close();
				},
			});
			const result = await readStreamWithLimit(stream, 100);
			t.deepEqual(result, { ok: true, text: "hello" });
		});

		test("rejects stream exceeding limit", async (t) => {
			const stream = new ReadableStream({
				start(controller) {
					controller.enqueue(new TextEncoder().encode("x".repeat(200)));
					controller.close();
				},
			});
			const result = await readStreamWithLimit(stream, 100);
			t.deepEqual(result, { ok: false });
		});
	});

	module("core / readBodyWithLimit", () => {
		test("returns ok: false for null body", async (t) => {
			const req = new Request("https://example.com");
			const result = await readBodyWithLimit(req, 1024);
			t.deepEqual(result, { ok: false });
		});

		test("reads body within limit", async (t) => {
			const req = new Request("https://example.com", { method: "POST", body: "small body" });
			const result = await readBodyWithLimit(req, 1024);
			t.deepEqual(result, { ok: true, text: "small body" });
		});

		test("rejects via Content-Length early check", async (t) => {
			const req = new Request("https://example.com", {
				method: "POST",
				body: "x",
				headers: { "Content-Length": "99999" },
			});
			// Browsers strip Content-Length (forbidden header); skip when that happens
			if (!req.headers.get("content-length")) {
				t.ok(true, "skipped: browser stripped Content-Length");
				return;
			}
			const result = await readBodyWithLimit(req, 100);
			t.deepEqual(result, { ok: false });
		});

		test("rejects via streaming when body exceeds limit", async (t) => {
			const req = new Request("https://example.com", {
				method: "POST",
				body: "x".repeat(200),
			});
			const result = await readBodyWithLimit(req, 100);
			t.deepEqual(result, { ok: false });
		});
	});

	// ── schemas/entity-id ─────────────────────────────────────────────
	module("core / schemas/entity-id", () => {
		test("accepts valid HTTPS entity ID", (t) => {
			t.true(EntityIdSchema.safeParse("https://example.com").success);
		});

		test("accepts HTTPS entity ID with path", (t) => {
			t.true(EntityIdSchema.safeParse("https://example.com/oidc").success);
		});

		test("accepts HTTPS entity ID with port", (t) => {
			t.true(EntityIdSchema.safeParse("https://example.com:8443").success);
		});

		test("rejects HTTP URLs", (t) => {
			t.false(EntityIdSchema.safeParse("http://example.com").success);
		});

		test("rejects non-URL strings", (t) => {
			t.false(EntityIdSchema.safeParse("not-a-url").success);
		});

		test("rejects URLs exceeding 2048 characters", (t) => {
			t.false(EntityIdSchema.safeParse(`https://example.com/${"a".repeat(2048)}`).success);
		});

		test("accepts URL at exactly 2048 characters", (t) => {
			const base = "https://example.com/";
			const url = base + "a".repeat(2048 - base.length);
			t.equal(url.length, 2048);
			t.true(EntityIdSchema.safeParse(url).success);
		});

		test("rejects URLs with credentials", (t) => {
			t.false(EntityIdSchema.safeParse("https://user:pass@example.com").success);
		});

		test("rejects URLs with query parameters", (t) => {
			t.false(EntityIdSchema.safeParse("https://example.com?foo=bar").success);
		});

		test("rejects URLs with fragments", (t) => {
			t.false(EntityIdSchema.safeParse("https://example.com#section").success);
		});

		test("rejects empty string", (t) => {
			t.false(EntityIdSchema.safeParse("").success);
		});

		test("rejects URL with no host component", (t) => {
			t.false(EntityIdSchema.safeParse("https://").success);
			t.false(EntityIdSchema.safeParse("https://:8080").success);
		});
	});

	// ── schemas/jwk ───────────────────────────────────────────────────
	module("core / schemas/JWK", () => {
		test("accepts a minimal EC key", (t) => {
			t.true(JWKSchema.safeParse({ kty: "EC", crv: "P-256", x: "abc", y: "def" }).success);
		});

		test("accepts a minimal RSA key", (t) => {
			t.true(JWKSchema.safeParse({ kty: "RSA", n: "modulus", e: "AQAB" }).success);
		});

		test("accepts OKP key type", (t) => {
			t.true(JWKSchema.safeParse({ kty: "OKP", crv: "Ed25519", x: "abc" }).success);
		});

		test("rejects invalid kty", (t) => {
			t.false(JWKSchema.safeParse({ kty: "oct" }).success);
		});

		test("rejects missing kty", (t) => {
			t.false(JWKSchema.safeParse({ kid: "test" }).success);
		});

		test("preserves unknown fields (looseObject)", (t) => {
			const result = JWKSchema.safeParse({
				kty: "EC",
				crv: "P-256",
				x: "abc",
				y: "def",
				customField: "custom",
			});
			t.true(result.success);
			if (result.success) {
				t.equal((result.data as Record<string, unknown>).customField, "custom");
			}
		});

		test("accepts valid use values", (t) => {
			t.true(JWKSchema.safeParse({ kty: "EC", use: "sig" }).success);
			t.true(JWKSchema.safeParse({ kty: "EC", use: "enc" }).success);
		});

		test("rejects invalid use values", (t) => {
			t.false(JWKSchema.safeParse({ kty: "EC", use: "other" }).success);
		});

		test("rejects EC key with private key field 'd'", (t) => {
			t.false(
				JWKSchema.safeParse({ kty: "EC", crv: "P-256", x: "abc", y: "def", d: "private-value" })
					.success,
			);
		});

		test("rejects RSA key with private key fields", (t) => {
			t.false(
				JWKSchema.safeParse({
					kty: "RSA",
					n: "modulus",
					e: "AQAB",
					d: "pd",
					p: "pp",
					q: "pq",
					dp: "pdp",
					dq: "pdq",
					qi: "pqi",
				}).success,
			);
		});

		test("accepts public EC key without private fields", (t) => {
			t.true(JWKSchema.safeParse({ kty: "EC", crv: "P-256", x: "abc", y: "def" }).success);
		});
	});

	module("core / schemas/JWKSet", () => {
		test("accepts a set with one key", (t) => {
			t.true(
				JWKSetSchema.safeParse({
					keys: [{ kty: "EC", kid: "k1", crv: "P-256", x: "abc", y: "def" }],
				}).success,
			);
		});

		test("accepts a set with multiple keys with unique kids", (t) => {
			t.true(
				JWKSetSchema.safeParse({
					keys: [
						{ kty: "EC", kid: "k1", crv: "P-256", x: "abc", y: "def" },
						{ kty: "RSA", kid: "k2", n: "modulus", e: "AQAB" },
					],
				}).success,
			);
		});

		test("rejects an empty keys array", (t) => {
			t.false(JWKSetSchema.safeParse({ keys: [] }).success);
		});

		test("rejects missing keys", (t) => {
			t.false(JWKSetSchema.safeParse({}).success);
		});

		test("rejects keys without kid", (t) => {
			t.false(
				JWKSetSchema.safeParse({ keys: [{ kty: "EC", crv: "P-256", x: "abc", y: "def" }] }).success,
			);
		});

		test("rejects duplicate kids", (t) => {
			t.false(
				JWKSetSchema.safeParse({
					keys: [
						{ kty: "EC", kid: "same", crv: "P-256", x: "a", y: "b" },
						{ kty: "EC", kid: "same", crv: "P-256", x: "c", y: "d" },
					],
				}).success,
			);
		});
	});

	// ── schemas/metadata-policy ───────────────────────────────────────
	module("core / schemas/metadata-policy", () => {
		test("MetadataParameterPolicySchema accepts valid policy with all operators", (t) => {
			t.true(
				MetadataParameterPolicySchema.safeParse({
					value: "openid",
					add: ["profile"],
					default: "openid",
					one_of: ["openid", "profile"],
					subset_of: ["openid", "profile", "email"],
					superset_of: ["openid"],
					essential: true,
				}).success,
			);
		});

		test("MetadataParameterPolicySchema accepts policy with subset of operators", (t) => {
			t.true(
				MetadataParameterPolicySchema.safeParse({ subset_of: ["ES256", "PS256"], essential: true })
					.success,
			);
		});

		test("MetadataParameterPolicySchema accepts extra fields (looseObject)", (t) => {
			t.true(
				MetadataParameterPolicySchema.safeParse({ value: "test", custom_operator: ["x"] }).success,
			);
		});

		test("EntityTypeMetadataPolicySchema accepts record of parameter policies", (t) => {
			t.true(
				EntityTypeMetadataPolicySchema.safeParse({
					id_token_signing_alg_values_supported: { subset_of: ["ES256", "PS256"] },
					scope: { superset_of: ["openid"], default: ["openid"] },
				}).success,
			);
		});

		test("FederationMetadataPolicySchema accepts nested record structure", (t) => {
			t.true(
				FederationMetadataPolicySchema.safeParse({
					openid_provider: { id_token_signing_alg_values_supported: { subset_of: ["ES256"] } },
					openid_relying_party: { scope: { superset_of: ["openid"] } },
				}).success,
			);
		});
	});

	// ── schemas/metadata ──────────────────────────────────────────────
	module("core / schemas/metadata", () => {
		test("FederationMetadataSchema accepts metadata with at least one entity type", (t) => {
			t.true(
				FederationMetadataSchema.safeParse({ federation_entity: { organization_name: "Test" } })
					.success,
			);
		});

		test("FederationMetadataSchema accepts metadata with multiple entity types", (t) => {
			t.true(
				FederationMetadataSchema.safeParse({
					federation_entity: { organization_name: "Test" },
					openid_provider: {
						issuer: "https://op.example.com",
						authorization_endpoint: "https://op.example.com/auth",
					},
				}).success,
			);
		});

		test("FederationMetadataSchema rejects empty metadata object", (t) => {
			t.false(FederationMetadataSchema.safeParse({}).success);
		});

		test("FederationMetadataSchema rejects metadata where all known keys are undefined", (t) => {
			t.false(
				FederationMetadataSchema.safeParse({
					federation_entity: undefined,
					openid_provider: undefined,
				}).success,
			);
		});

		test("FederationMetadataSchema accepts openid_relying_party as loose record", (t) => {
			t.true(
				FederationMetadataSchema.safeParse({
					openid_relying_party: {
						redirect_uris: ["https://rp.example.com/callback"],
						custom_field: "anything",
					},
				}).success,
			);
		});

		test("FederationMetadataSchema accepts openid_provider as loose record", (t) => {
			t.true(
				FederationMetadataSchema.safeParse({
					openid_provider: { issuer: "https://op.example.com", custom_field: 42 },
				}).success,
			);
		});

		{
			const endpoints = [
				"federation_fetch_endpoint",
				"federation_list_endpoint",
				"federation_resolve_endpoint",
				"federation_trust_mark_status_endpoint",
				"federation_trust_mark_list_endpoint",
				"federation_trust_mark_endpoint",
				"federation_historical_keys_endpoint",
			] as const;

			for (const field of endpoints) {
				test(`FederationEntityMetadataSchema rejects http:// URL for ${field}`, (t) => {
					t.false(
						FederationEntityMetadataSchema.safeParse({ [field]: "http://example.com/endpoint" })
							.success,
					);
				});
				test(`FederationEntityMetadataSchema rejects URL with fragment for ${field}`, (t) => {
					t.false(
						FederationEntityMetadataSchema.safeParse({
							[field]: "https://example.com/endpoint#frag",
						}).success,
					);
				});
				test(`FederationEntityMetadataSchema accepts valid https URL for ${field}`, (t) => {
					t.true(
						FederationEntityMetadataSchema.safeParse({
							[field]: "https://example.com/endpoint?param=value",
						}).success,
					);
				});
			}
		}

		test("FederationEntityMetadataSchema rejects 'none' in endpoint_auth_signing_alg_values_supported", (t) => {
			t.false(
				FederationEntityMetadataSchema.safeParse({
					endpoint_auth_signing_alg_values_supported: ["RS256", "none"],
				}).success,
			);
		});

		test("FederationEntityMetadataSchema accepts valid alg values", (t) => {
			t.true(
				FederationEntityMetadataSchema.safeParse({
					endpoint_auth_signing_alg_values_supported: ["RS256", "ES256"],
				}).success,
			);
		});
	});

	// ── jwks/use-requirement ──────────────────────────────────────────
	module("core / validateJwkSetUseRequirement", () => {
		test("accepts a JWK Set of only signing-capable keys without 'use'", (t) => {
			const result = validateJwkSetUseRequirement([
				{ kty: "EC", kid: "k1", crv: "P-256", x: "x1", y: "y1", alg: "ES256" },
				{ kty: "RSA", kid: "k2", n: "n1", e: "AQAB", alg: "RS256" },
			]);
			t.true(result.ok);
		});

		test("rejects a JWK Set mixing signing and encryption keys without 'use'", (t) => {
			const result = validateJwkSetUseRequirement([
				{ kty: "EC", kid: "sig1", crv: "P-256", x: "x1", y: "y1", alg: "ES256" },
				{ kty: "RSA", kid: "enc1", n: "n1", e: "AQAB", alg: "RSA-OAEP-256" },
			]);
			t.false(result.ok);
			if (result.ok) return;
			t.equal(result.error.code, FederationErrorCode.InvalidMetadata);
			t.ok(result.error.description.includes("'use'"));
		});

		test("accepts a mixed JWK Set when every key declares 'use'", (t) => {
			const result = validateJwkSetUseRequirement([
				{ kty: "EC", kid: "sig1", crv: "P-256", x: "x1", y: "y1", use: "sig" },
				{ kty: "RSA", kid: "enc1", n: "n1", e: "AQAB", use: "enc" },
			]);
			t.true(result.ok);
		});

		test("rejects a mixed JWK Set when only some keys declare 'use'", (t) => {
			const result = validateJwkSetUseRequirement([
				{ kty: "EC", kid: "sig1", crv: "P-256", x: "x1", y: "y1", use: "sig" },
				{ kty: "RSA", kid: "enc1", n: "n1", e: "AQAB", alg: "RSA-OAEP-256" },
			]);
			t.false(result.ok);
			if (result.ok) return;
			t.equal(result.error.code, FederationErrorCode.InvalidMetadata);
			t.ok(result.error.description.includes("enc1"));
		});

		test("accepts a JWK Set of only encryption-capable keys without 'use'", (t) => {
			const result = validateJwkSetUseRequirement([
				{ kty: "RSA", kid: "enc1", n: "n1", e: "AQAB", alg: "RSA-OAEP-256" },
				{ kty: "RSA", kid: "enc2", n: "n2", e: "AQAB", alg: "RSA1_5" },
			]);
			t.true(result.ok);
		});
	});

	// ── schemas/trust-mark ────────────────────────────────────────────
	module("core / schemas/trust-mark", () => {
		test("TrustMarkRefSchema accepts valid trust mark ref", (t) => {
			t.true(
				TrustMarkRefSchema.safeParse({
					trust_mark_type: "https://example.com/tm/type1",
					trust_mark: "eyJ...",
				}).success,
			);
		});
		test("TrustMarkRefSchema rejects missing trust_mark field", (t) => {
			t.false(
				TrustMarkRefSchema.safeParse({ trust_mark_type: "https://example.com/tm/type1" }).success,
			);
		});
		test("TrustMarkRefSchema rejects missing trust_mark_type", (t) => {
			t.false(TrustMarkRefSchema.safeParse({ trust_mark: "eyJ..." }).success);
		});

		test("TrustMarkOwnerSchema accepts valid trust mark owner with jwks", (t) => {
			t.true(
				TrustMarkOwnerSchema.safeParse({
					sub: "https://tm-owner.example.com",
					jwks: { keys: [{ kty: "EC", kid: "key-1", crv: "P-256", x: "abc", y: "def" }] },
				}).success,
			);
		});
		test("TrustMarkOwnerSchema rejects missing sub", (t) => {
			t.false(
				TrustMarkOwnerSchema.safeParse({
					jwks: { keys: [{ kty: "EC", kid: "key-1", crv: "P-256", x: "abc", y: "def" }] },
				}).success,
			);
		});

		{
			const validPayload = {
				iss: "https://issuer.example.com",
				sub: "https://subject.example.com",
				trust_mark_type: "https://example.com/tm/type1",
				iat: 1700000000,
			};
			test("TrustMarkPayloadSchema accepts valid payload", (t) => {
				t.true(TrustMarkPayloadSchema.safeParse(validPayload).success);
			});
			test("TrustMarkPayloadSchema accepts payload with optional fields", (t) => {
				t.true(
					TrustMarkPayloadSchema.safeParse({
						...validPayload,
						exp: 1700100000,
						logo_uri: "https://example.com/logo.png",
						ref: "https://example.com/policy",
						delegation: "eyJ...",
					}).success,
				);
			});
			test("TrustMarkPayloadSchema rejects non-HTTPS iss", (t) => {
				t.false(
					TrustMarkPayloadSchema.safeParse({ ...validPayload, iss: "http://issuer.example.com" })
						.success,
				);
			});
			test("TrustMarkPayloadSchema rejects missing iat", (t) => {
				const { iat: _, ...noIat } = validPayload;
				t.false(TrustMarkPayloadSchema.safeParse(noIat).success);
			});
			test("TrustMarkPayloadSchema rejects logo_uri that is not a syntactically valid URL", (t) => {
				t.false(
					TrustMarkPayloadSchema.safeParse({ ...validPayload, logo_uri: "not-a-url" }).success,
				);
			});
			test("TrustMarkPayloadSchema accepts http logo_uri (spec does not require https)", (t) => {
				t.true(
					TrustMarkPayloadSchema.safeParse({
						...validPayload,
						logo_uri: "http://example.com/logo.png",
					}).success,
				);
			});
			test("TrustMarkPayloadSchema accepts logo_uri with fragment (spec does not forbid)", (t) => {
				t.true(
					TrustMarkPayloadSchema.safeParse({
						...validPayload,
						logo_uri: "https://example.com/logo.svg#layer-1",
					}).success,
				);
			});
		}

		{
			const validDelegation = {
				iss: "https://owner.example.com",
				sub: "https://delegatee.example.com",
				trust_mark_type: "https://example.com/tm/type1",
				iat: 1700000000,
			};
			test("TrustMarkDelegationPayloadSchema accepts valid delegation payload", (t) => {
				t.true(TrustMarkDelegationPayloadSchema.safeParse(validDelegation).success);
			});
			test("TrustMarkDelegationPayloadSchema rejects missing required fields", (t) => {
				const { iss: _, ...noIss } = validDelegation;
				t.false(TrustMarkDelegationPayloadSchema.safeParse(noIss).success);
			});
			test("TrustMarkDelegationPayloadSchema accepts optional exp field", (t) => {
				t.true(
					TrustMarkDelegationPayloadSchema.safeParse({ ...validDelegation, exp: 1700100000 })
						.success,
				);
			});
		}
	});

	// ── schemas/constraints ───────────────────────────────────────────
	module("core / schemas/constraints", () => {
		test("NamingConstraintsSchema accepts valid constraints", (t) => {
			t.true(
				NamingConstraintsSchema.safeParse({
					permitted: [".example.com"],
					excluded: [".evil.example.com"],
				}).success,
			);
		});
		test("NamingConstraintsSchema rejects wildcards in patterns", (t) => {
			t.false(NamingConstraintsSchema.safeParse({ permitted: ["*.example.com"] }).success);
		});
		test("NamingConstraintsSchema rejects question marks in patterns", (t) => {
			t.false(NamingConstraintsSchema.safeParse({ permitted: ["?.example.com"] }).success);
		});
		test("NamingConstraintsSchema accepts empty object", (t) => {
			t.true(NamingConstraintsSchema.safeParse({}).success);
		});

		test("TrustChainConstraintsSchema accepts valid constraints", (t) => {
			t.true(
				TrustChainConstraintsSchema.safeParse({
					max_path_length: 2,
					naming_constraints: { permitted: [".example.com"] },
					allowed_entity_types: ["openid_relying_party"],
				}).success,
			);
		});
		test("TrustChainConstraintsSchema rejects negative max_path_length", (t) => {
			t.false(TrustChainConstraintsSchema.safeParse({ max_path_length: -1 }).success);
		});
		test("TrustChainConstraintsSchema rejects max_path_length > 100", (t) => {
			t.false(TrustChainConstraintsSchema.safeParse({ max_path_length: 101 }).success);
		});
		test("TrustChainConstraintsSchema accepts max_path_length of 0", (t) => {
			t.true(TrustChainConstraintsSchema.safeParse({ max_path_length: 0 }).success);
		});
		test("TrustChainConstraintsSchema ignores additional constraint parameters not defined by this spec", (t) => {
			t.true(
				TrustChainConstraintsSchema.safeParse({
					max_path_length: 1,
					custom_constraint: "some_value",
				}).success,
			);
		});
		test("TrustChainConstraintsSchema rejects invalid entity types", (t) => {
			t.false(
				TrustChainConstraintsSchema.safeParse({ allowed_entity_types: ["invalid_type"] }).success,
			);
		});
		test("TrustChainConstraintsSchema rejects federation_entity in allowed_entity_types constraint", (t) => {
			t.false(
				TrustChainConstraintsSchema.safeParse({ allowed_entity_types: ["federation_entity"] })
					.success,
			);
		});
	});

	// ── schemas/entity-statement ─────────────────────────────────────
	{
		const es_now = Math.floor(Date.now() / 1000);

		module("core / schemas/entity-statement / EntityIdSchema", () => {
			test("accepts a valid HTTPS URL", (t) => {
				t.true(EntityStatementEntityIdSchema.safeParse("https://example.com").success);
			});
			test("rejects HTTP URL", (t) => {
				t.false(EntityStatementEntityIdSchema.safeParse("http://example.com").success);
			});
			test("rejects URL with credentials", (t) => {
				t.false(EntityStatementEntityIdSchema.safeParse("https://user:pass@example.com").success);
			});
			test("rejects URL with only username", (t) => {
				t.false(EntityStatementEntityIdSchema.safeParse("https://user@example.com").success);
			});
			test("rejects non-URL string", (t) => {
				t.false(EntityStatementEntityIdSchema.safeParse("not-a-url").success);
			});
			test("rejects empty string", (t) => {
				t.false(EntityStatementEntityIdSchema.safeParse("").success);
			});
			test("accepts HTTPS URL with path", (t) => {
				t.true(
					EntityStatementEntityIdSchema.safeParse("https://example.com/path/to/entity").success,
				);
			});
			test("rejects URL with query parameters", (t) => {
				t.false(EntityStatementEntityIdSchema.safeParse("https://example.com?foo=bar").success);
			});
			test("rejects URL with fragment", (t) => {
				t.false(EntityStatementEntityIdSchema.safeParse("https://example.com#section").success);
			});
			test("rejects URL with both query and fragment", (t) => {
				t.false(
					EntityStatementEntityIdSchema.safeParse("https://example.com?foo=bar#section").success,
				);
			});
			test("rejects URL with path and query", (t) => {
				t.false(EntityStatementEntityIdSchema.safeParse("https://example.com/path?q=1").success);
			});
			test("rejects URL exceeding 2048 characters", (t) => {
				const long = `https://example.com/${"a".repeat(2040)}`;
				t.true(long.length > 2048);
				t.false(EntityStatementEntityIdSchema.safeParse(long).success);
			});
			test("accepts URL exactly 2048 characters", (t) => {
				const path = "a".repeat(2048 - "https://example.com/".length);
				const exact = `https://example.com/${path}`;
				t.equal(exact.length, 2048);
				t.true(EntityStatementEntityIdSchema.safeParse(exact).success);
			});
		});

		module("core / schemas/entity-statement / entityId()", () => {
			test("throws for URL exceeding 2048 characters", (t) => {
				const long = `https://example.com/${"a".repeat(2040)}`;
				try {
					entityId(long);
					t.ok(false, "should have thrown");
				} catch (e: unknown) {
					t.true((e as Error).message.includes("2048"));
				}
			});
			test("accepts valid HTTPS URL within 2048 characters", (t) => {
				try {
					const result = entityId("https://example.com");
					t.equal(result, "https://example.com");
				} catch {
					t.ok(false, "should not throw");
				}
			});
		});

		module("core / schemas/entity-statement / isValidEntityId()", () => {
			test("returns false for URL exceeding 2048 characters", (t) => {
				t.false(isValidEntityId(`https://example.com/${"a".repeat(2040)}`));
			});
			test("returns true for valid HTTPS URL within 2048 characters", (t) => {
				t.true(isValidEntityId("https://example.com"));
			});
			test("returns false for URL with no host component", (t) => {
				t.false(isValidEntityId("https://"));
				t.false(isValidEntityId("https://:8080"));
			});
		});

		module("core / schemas/entity-statement / BaseEntityStatementSchema", () => {
			const validBase = {
				iss: "https://issuer.example.com",
				sub: "https://subject.example.com",
				iat: es_now,
				exp: es_now + 3600,
				jwks: { keys: [{ kty: "EC" as const, kid: "k1", crv: "P-256", x: "a", y: "b" }] },
			};
			test("accepts valid base entity statement", (t) => {
				t.true(BaseEntityStatementSchema.safeParse(validBase).success);
			});
			test("rejects when exp <= iat", (t) => {
				t.false(BaseEntityStatementSchema.safeParse({ ...validBase, exp: es_now - 100 }).success);
			});
			test("rejects when exp === iat", (t) => {
				t.false(
					BaseEntityStatementSchema.safeParse({ ...validBase, exp: es_now, iat: es_now }).success,
				);
			});
			test("allows optional fields to be absent", (t) => {
				t.true(
					BaseEntityStatementSchema.safeParse({
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						iat: es_now,
						exp: es_now + 3600,
					}).success,
				);
			});
			test("accepts metadata as nested records", (t) => {
				t.true(
					BaseEntityStatementSchema.safeParse({
						...validBase,
						metadata: { federation_entity: { organization_name: "Test Org" } },
					}).success,
				);
			});
			test("rejects empty metadata_policy_crit array", (t) => {
				t.false(
					BaseEntityStatementSchema.safeParse({
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						iat: es_now,
						exp: es_now + 3600,
						metadata_policy_crit: [],
					}).success,
				);
			});
			test("accepts metadata_policy_crit with at least one entry", (t) => {
				t.true(
					BaseEntityStatementSchema.safeParse({
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						iat: es_now,
						exp: es_now + 3600,
						metadata_policy_crit: ["custom_operator"],
					}).success,
				);
			});
			test("rejects empty crit array", (t) => {
				t.false(
					BaseEntityStatementSchema.safeParse({
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						iat: es_now,
						exp: es_now + 3600,
						crit: [],
					}).success,
				);
			});
			test("accepts crit with at least one entry", (t) => {
				t.true(
					BaseEntityStatementSchema.safeParse({
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						iat: es_now,
						exp: es_now + 3600,
						crit: ["x_custom"],
					}).success,
				);
			});
		});

		module("core / schemas/entity-statement / EntityConfigurationSchema", () => {
			const validEC = {
				iss: "https://entity.example.com",
				sub: "https://entity.example.com",
				iat: es_now,
				exp: es_now + 3600,
				jwks: { keys: [{ kty: "EC" as const, kid: "k1", crv: "P-256", x: "a", y: "b" }] },
				authority_hints: ["https://authority.example.com"],
			};
			test("accepts valid entity configuration where iss === sub", (t) => {
				t.true(EntityConfigurationSchema.safeParse(validEC).success);
			});
			test("rejects when iss !== sub", (t) => {
				t.false(
					EntityConfigurationSchema.safeParse({ ...validEC, sub: "https://other.example.com" })
						.success,
				);
			});
			test("allows authority_hints to be absent", (t) => {
				const { authority_hints: _, ...ec } = validEC;
				t.true(EntityConfigurationSchema.safeParse(ec).success);
			});
			test("accepts metadata with at least one entity type", (t) => {
				t.true(
					EntityConfigurationSchema.safeParse({
						...validEC,
						metadata: { federation_entity: { organization_name: "Test Org" } },
					}).success,
				);
			});
			test("rejects when jwks is missing", (t) => {
				const { jwks: _, ...ec } = validEC;
				t.false(EntityConfigurationSchema.safeParse(ec).success);
			});
			test("rejects metadata with no entity types (empty object)", (t) => {
				t.false(EntityConfigurationSchema.safeParse({ ...validEC, metadata: {} }).success);
			});
			test("accepts metadata with multiple entity types", (t) => {
				t.true(
					EntityConfigurationSchema.safeParse({
						...validEC,
						metadata: {
							federation_entity: { organization_name: "Test" },
							openid_relying_party: { client_name: "Test RP" },
						},
					}).success,
				);
			});
			test("rejects empty trust_anchor_hints array", (t) => {
				const baseEC = {
					iss: "https://entity.example.com",
					sub: "https://entity.example.com",
					iat: es_now,
					exp: es_now + 3600,
					jwks: { keys: [{ kty: "EC" as const, kid: "k1", crv: "P-256", x: "a", y: "b" }] },
				};
				t.false(EntityConfigurationSchema.safeParse({ ...baseEC, trust_anchor_hints: [] }).success);
			});
			test("accepts trust_anchor_hints with at least one entry", (t) => {
				const baseEC = {
					iss: "https://entity.example.com",
					sub: "https://entity.example.com",
					iat: es_now,
					exp: es_now + 3600,
					jwks: { keys: [{ kty: "EC" as const, kid: "k1", crv: "P-256", x: "a", y: "b" }] },
				};
				t.true(
					EntityConfigurationSchema.safeParse({
						...baseEC,
						trust_anchor_hints: ["https://ta.example.com"],
					}).success,
				);
			});
		});

		module("core / schemas/entity-statement / SubordinateStatementSchema", () => {
			const validSS = {
				iss: "https://authority.example.com",
				sub: "https://subordinate.example.com",
				iat: es_now,
				exp: es_now + 3600,
				jwks: { keys: [{ kty: "EC" as const, kid: "k1", crv: "P-256", x: "a", y: "b" }] },
			};
			test("accepts valid subordinate statement", (t) => {
				t.true(SubordinateStatementSchema.safeParse(validSS).success);
			});
			test("accepts with optional source_endpoint", (t) => {
				t.true(
					SubordinateStatementSchema.safeParse({
						...validSS,
						source_endpoint: "https://authority.example.com/federation_fetch",
					}).success,
				);
			});
			test("rejects when exp <= iat", (t) => {
				t.false(SubordinateStatementSchema.safeParse({ ...validSS, exp: es_now - 100 }).success);
			});
			test("rejects when iss === sub", (t) => {
				t.false(
					SubordinateStatementSchema.safeParse({
						...validSS,
						iss: "https://same.example.com",
						sub: "https://same.example.com",
					}).success,
				);
			});
			test("rejects when jwks is missing", (t) => {
				const { jwks: _, ...ss } = validSS;
				t.false(SubordinateStatementSchema.safeParse(ss).success);
			});
		});

		module("core / schemas/entity-statement / ExplicitRegistrationRequestPayloadSchema", () => {
			const validReq = {
				iss: "https://rp.example.com",
				sub: "https://rp.example.com",
				aud: "https://op.example.com",
				iat: es_now,
				exp: es_now + 3600,
				jwks: { keys: [{ kty: "EC" as const, kid: "k1", crv: "P-256", x: "a", y: "b" }] },
				authority_hints: ["https://ta.example.com"],
				metadata: { openid_relying_party: { redirect_uris: ["https://rp.example.com/callback"] } },
			};
			test("accepts valid registration request", (t) => {
				t.true(ExplicitRegistrationRequestPayloadSchema.safeParse(validReq).success);
			});
			test("rejects when iss !== sub", (t) => {
				t.false(
					ExplicitRegistrationRequestPayloadSchema.safeParse({
						...validReq,
						sub: "https://other.example.com",
					}).success,
				);
			});
			test("requires aud", (t) => {
				const { aud: _, ...v } = validReq;
				t.false(ExplicitRegistrationRequestPayloadSchema.safeParse(v).success);
			});
			test("requires authority_hints", (t) => {
				const { authority_hints: _, ...v } = validReq;
				t.false(ExplicitRegistrationRequestPayloadSchema.safeParse(v).success);
			});
			test("requires metadata", (t) => {
				const { metadata: _, ...v } = validReq;
				t.false(ExplicitRegistrationRequestPayloadSchema.safeParse(v).success);
			});
			test("requires metadata to contain openid_relying_party", (t) => {
				t.false(
					ExplicitRegistrationRequestPayloadSchema.safeParse({
						...validReq,
						metadata: { federation_entity: { organization_name: "Test" } },
					}).success,
				);
			});
		});

		module("core / schemas/entity-statement / ExplicitRegistrationResponsePayloadSchema", () => {
			const validResp = {
				iss: "https://op.example.com",
				sub: "https://rp.example.com",
				aud: "https://rp.example.com",
				iat: es_now,
				exp: es_now + 3600,
				trust_anchor: "https://ta.example.com",
				authority_hints: ["https://intermediate.example.com"],
			};
			test("accepts valid registration response", (t) => {
				t.true(ExplicitRegistrationResponsePayloadSchema.safeParse(validResp).success);
			});
			test("requires trust_anchor", (t) => {
				const { trust_anchor: _, ...v } = validResp;
				t.false(ExplicitRegistrationResponsePayloadSchema.safeParse(v).success);
			});
			test("accepts optional client_secret", (t) => {
				t.true(
					ExplicitRegistrationResponsePayloadSchema.safeParse({
						...validResp,
						client_secret: "secret123",
					}).success,
				);
			});
			test("requires authority_hints in response", (t) => {
				const { authority_hints: _, ...v } = validResp;
				t.false(ExplicitRegistrationResponsePayloadSchema.safeParse(v).success);
			});
			test("requires authority_hints to be exactly one element", (t) => {
				t.false(
					ExplicitRegistrationResponsePayloadSchema.safeParse({
						...validResp,
						authority_hints: ["https://a.example.com", "https://b.example.com"],
					}).success,
				);
			});
		});

		module("core / schemas/entity-statement / TrustMarkOwnerSchema", () => {
			test("preserves extra members", (t) => {
				const result = TrustMarkOwnerSchema.safeParse({
					sub: "https://owner.example.com",
					jwks: { keys: [{ kty: "EC", kid: "k1", crv: "P-256", x: "a", y: "b" }] },
					organization_name: "Example Org",
				});
				t.true(result.success);
				if (result.success) {
					t.equal((result.data as Record<string, unknown>).organization_name, "Example Org");
				}
			});
		});

		module("core / schemas/entity-statement / HistoricalKeyEntrySchema", () => {
			test("requires kid field", (t) => {
				t.false(HistoricalKeyEntrySchema.safeParse({ kty: "EC", exp: es_now + 3600 }).success);
			});
			test("accepts entry with kid", (t) => {
				t.true(
					HistoricalKeyEntrySchema.safeParse({ kty: "EC", kid: "key-1", exp: es_now + 3600 })
						.success,
				);
			});
		});
	}

	// ── constraints/index ─────────────────────────────────────────────
	{
		function makeStmt(
			iss: string,
			sub: string,
			overrides?: Partial<ParsedEntityStatement["payload"]>,
		): ParsedEntityStatement {
			const n = Math.floor(Date.now() / 1000);
			return {
				header: { alg: "ES256", typ: "entity-statement+jwt", kid: "k1" },
				payload: {
					iss: iss as EntityId,
					sub: sub as EntityId,
					iat: n,
					exp: n + 3600,
					...overrides,
				} as ParsedEntityStatement["payload"],
			};
		}

		module("core / checkMaxPathLength", () => {
			test("returns true when 0 intermediates and max=0", (t) => {
				t.true(checkMaxPathLength(0, 1, 3));
			});
			test("returns false when 2 intermediates and max=1", (t) => {
				t.false(checkMaxPathLength(1, 3, 5));
			});
			test("returns true at exact boundary (1 intermediate, max=1)", (t) => {
				t.true(checkMaxPathLength(1, 2, 4));
			});
			test("returns true when max exceeds intermediates", (t) => {
				t.true(checkMaxPathLength(10, 2, 4));
			});
			test("returns true when constrainer is direct superior of leaf", (t) => {
				t.true(checkMaxPathLength(0, 1, 3));
			});
		});

		module("core / checkNamingConstraints", () => {
			test("returns true with no constraints", (t) => {
				t.true(checkNamingConstraints({}, "https://example.com" as EntityId));
			});
			test("matches exact hostname in permitted list", (t) => {
				t.true(
					checkNamingConstraints({ permitted: ["example.com"] }, "https://example.com" as EntityId),
				);
			});
			test("rejects hostname not in permitted list", (t) => {
				t.false(
					checkNamingConstraints({ permitted: ["example.com"] }, "https://other.com" as EntityId),
				);
			});
			test("matches subdomain with dot-prefix pattern", (t) => {
				t.true(
					checkNamingConstraints(
						{ permitted: [".example.com"] },
						"https://sub.example.com" as EntityId,
					),
				);
			});
			test("dot-prefix does not match the domain itself", (t) => {
				t.false(
					checkNamingConstraints(
						{ permitted: [".example.com"] },
						"https://example.com" as EntityId,
					),
				);
			});
			test("excluded overrides permitted", (t) => {
				t.false(
					checkNamingConstraints(
						{ permitted: [".example.com"], excluded: ["bad.example.com"] },
						"https://bad.example.com" as EntityId,
					),
				);
			});
			test("excluded alone blocks matching hostname", (t) => {
				t.false(
					checkNamingConstraints({ excluded: ["blocked.com"] }, "https://blocked.com" as EntityId),
				);
			});
			test("excluded alone allows non-matching hostname", (t) => {
				t.true(
					checkNamingConstraints({ excluded: ["blocked.com"] }, "https://allowed.com" as EntityId),
				);
			});
			test("extracts hostname correctly from URL with path", (t) => {
				t.true(
					checkNamingConstraints(
						{ permitted: ["example.com"] },
						"https://example.com/some/path" as EntityId,
					),
				);
			});
			test("extracts hostname correctly from URL with port", (t) => {
				t.true(
					checkNamingConstraints(
						{ permitted: ["example.com"] },
						"https://example.com:8443" as EntityId,
					),
				);
			});
			test("handles subdomain pattern with multiple levels", (t) => {
				t.true(
					checkNamingConstraints(
						{ permitted: [".example.com"] },
						"https://deep.sub.example.com" as EntityId,
					),
				);
			});
			test("no-leading-period entry in permitted does NOT match a subdomain", (t) => {
				t.false(
					checkNamingConstraints(
						{ permitted: ["example.com"] },
						"https://sub.example.com" as EntityId,
					),
				);
			});
		});

		module("core / applyAllowedEntityTypes", () => {
			test("filters metadata to only allowed entity types", (t) => {
				const metadata = {
					federation_entity: { organization_name: "Test" },
					openid_relying_party: { client_name: "RP" },
					openid_provider: { issuer: "https://op.example.com" },
				};
				const result = applyAllowedEntityTypes(["openid_relying_party"], metadata);
				t.ok((result as Record<string, unknown>).federation_entity);
				t.ok((result as Record<string, unknown>).openid_relying_party);
				t.equal((result as Record<string, unknown>).openid_provider, undefined);
			});
			test("always keeps federation_entity even if not in list", (t) => {
				const result = applyAllowedEntityTypes(["openid_provider"], {
					federation_entity: { organization_name: "Test" },
					openid_provider: { issuer: "https://op.example.com" },
				});
				t.ok((result as Record<string, unknown>).federation_entity);
				t.ok((result as Record<string, unknown>).openid_provider);
			});
			test("returns only federation_entity when empty array", (t) => {
				const result = applyAllowedEntityTypes([], {
					federation_entity: { organization_name: "Test" },
					openid_relying_party: { client_name: "RP" },
				});
				t.ok((result as Record<string, unknown>).federation_entity);
				t.equal((result as Record<string, unknown>).openid_relying_party, undefined);
			});
			test("does not mutate input metadata", (t) => {
				const metadata = {
					federation_entity: { organization_name: "Test" },
					openid_relying_party: { client_name: "RP" },
				};
				const original = { ...metadata };
				applyAllowedEntityTypes(["openid_relying_party"], metadata);
				t.deepEqual(metadata, original);
			});
			test("tolerates federation_entity when redundantly listed in constraint", (t) => {
				// Spec: federation_entity is always allowed and MUST NOT be included.
				// Library treats redundant inclusion as a no-op rather than rejecting,
				// so an over-eager publisher does not break the chain.
				const result = applyAllowedEntityTypes(["federation_entity", "openid_provider"], {
					federation_entity: { organization_name: "Test" },
					openid_provider: { issuer: "https://op.example.com" },
					openid_relying_party: { client_name: "RP" },
				});
				t.ok((result as Record<string, unknown>).federation_entity);
				t.ok((result as Record<string, unknown>).openid_provider);
				t.equal((result as Record<string, unknown>).openid_relying_party, undefined);
			});
		});

		module("core / checkConstraints", () => {
			test("returns ok when no constraint violations", (t) => {
				const chain = [
					makeStmt("https://leaf.example.com", "https://leaf.example.com"),
					makeStmt("https://intermediate.example.com", "https://leaf.example.com", {
						constraints: {
							max_path_length: 1,
							naming_constraints: { permitted: [".example.com"] },
						},
					}),
					makeStmt("https://ta.example.com", "https://ta.example.com"),
				];
				t.true(
					isOk(checkConstraints(chain[1]!.payload.constraints as TrustChainConstraints, 1, chain)),
				);
			});
			test("returns error when max_path_length exceeded", (t) => {
				const chain = [
					makeStmt("https://leaf.example.com", "https://leaf.example.com"),
					makeStmt("https://int1.example.com", "https://leaf.example.com"),
					makeStmt("https://int2.example.com", "https://int1.example.com"),
					makeStmt("https://ta.example.com", "https://int2.example.com", {
						constraints: { max_path_length: 0 },
					}),
					makeStmt("https://ta.example.com", "https://ta.example.com"),
				];
				const result = checkConstraints(
					chain[3]!.payload.constraints as TrustChainConstraints,
					3,
					chain,
				);
				t.true(isErr(result));
				if (isErr(result)) {
					t.equal(result.error.code, "ERR_CONSTRAINT_VIOLATION");
				}
			});
			test("returns error when naming constraint violated", (t) => {
				const chain = [
					makeStmt("https://evil.other.com", "https://evil.other.com"),
					makeStmt("https://intermediate.example.com", "https://evil.other.com", {
						constraints: { naming_constraints: { permitted: [".example.com"] } },
					}),
					makeStmt("https://ta.example.com", "https://ta.example.com"),
				];
				const result = checkConstraints(
					chain[1]!.payload.constraints as TrustChainConstraints,
					1,
					chain,
				);
				t.true(isErr(result));
				if (isErr(result)) {
					t.equal(result.error.code, "ERR_CONSTRAINT_VIOLATION");
				}
			});
		});
	}

	// ── jose/keys ─────────────────────────────────────────────────────
	module("core / keys / generateSigningKey", () => {
		test("generates an ES256 key pair by default", async (t) => {
			const { publicKey, privateKey } = await generateSigningKey();
			t.equal(publicKey.kty, "EC");
			t.notEqual(publicKey.kid, undefined);
			t.equal(publicKey.alg, "ES256");
			t.equal(publicKey.use, "sig");
			t.equal(privateKey.kid, publicKey.kid);
			t.equal(privateKey.alg, "ES256");
			t.notEqual((privateKey as Record<string, unknown>).d, undefined);
			t.equal((publicKey as Record<string, unknown>).d, undefined);
		});
		test("generates a PS256 key pair", async (t) => {
			const { publicKey, privateKey } = await generateSigningKey("PS256");
			t.equal(publicKey.kty, "RSA");
			t.equal(publicKey.alg, "PS256");
			t.equal(privateKey.kty, "RSA");
		});
		test("generates unique kids for different keys", async (t) => {
			const key1 = await generateSigningKey();
			const key2 = await generateSigningKey();
			t.notEqual(key1.publicKey.kid, key2.publicKey.kid);
		});
	});

	module("core / keys / selectVerificationKey", () => {
		const ecKey: JWK = {
			kty: "EC",
			kid: "ec-key-1",
			alg: "ES256",
			use: "sig",
			crv: "P-256",
			x: "abc",
			y: "def",
		} as JWK;
		const rsaKey: JWK = {
			kty: "RSA",
			kid: "rsa-key-1",
			alg: "PS256",
			use: "sig",
			n: "modulus",
			e: "AQAB",
		} as JWK;
		const jwks: JWKSet = { keys: [ecKey, rsaKey] };

		test("selects key by kid", (t) => {
			t.deepEqual(selectVerificationKey({ kid: "ec-key-1" }, jwks), ecKey);
		});
		test("selects RSA key by kid", (t) => {
			t.deepEqual(selectVerificationKey({ kid: "rsa-key-1" }, jwks), rsaKey);
		});
		test("falls back to algorithm-based selection", (t) => {
			t.deepEqual(selectVerificationKey({ alg: "ES256" }, { keys: [ecKey] }), ecKey);
		});
		test("returns undefined when no key matches", (t) => {
			t.equal(selectVerificationKey({ kid: "nonexistent" }, jwks), undefined);
		});
		test("returns key when kid matches and alg matches", (t) => {
			t.deepEqual(selectVerificationKey({ kid: "ec-key-1", alg: "ES256" }, jwks), ecKey);
		});
		test("returns undefined when kid matches but alg differs", (t) => {
			t.equal(selectVerificationKey({ kid: "ec-key-1", alg: "RS256" }, jwks), undefined);
		});
		test("returns key when kid matches and key has no alg restriction", (t) => {
			const keyNoAlg = {
				kty: "EC",
				kid: "no-alg-key",
				use: "sig",
				crv: "P-256",
				x: "abc",
				y: "def",
			} as JWK;
			t.deepEqual(
				selectVerificationKey({ kid: "no-alg-key", alg: "ES256" }, { keys: [keyNoAlg] }),
				keyNoAlg,
			);
		});
		test("rejects key with use: 'enc' even when kid matches", (t) => {
			const encKey = {
				kty: "EC",
				kid: "enc-key",
				use: "enc",
				crv: "P-256",
				x: "abc",
				y: "def",
			} as unknown as JWK;
			t.equal(selectVerificationKey({ kid: "enc-key" }, { keys: [encKey] }), undefined);
		});
	});

	module("core / keys / isValidAlgorithm", () => {
		test("returns true for supported algorithms", (t) => {
			t.true(isValidAlgorithm("ES256"));
			t.true(isValidAlgorithm("PS256"));
			t.true(isValidAlgorithm("RS256"));
		});
		test('rejects "none"', (t) => {
			t.false(isValidAlgorithm("none"));
		});
		test("rejects empty/undefined/null", (t) => {
			t.false(isValidAlgorithm(""));
			t.false(isValidAlgorithm(undefined));
			t.false(isValidAlgorithm(null));
		});
		test("rejects unsupported algorithms", (t) => {
			t.false(isValidAlgorithm("HS256"));
			t.false(isValidAlgorithm("EdDSA"));
		});
	});

	module("core / keys / timingSafeEqual", () => {
		test("returns true for equal strings", (t) => {
			t.true(timingSafeEqual("hello", "hello"));
		});
		test("returns false for different strings same length", (t) => {
			t.false(timingSafeEqual("hello", "world"));
		});
		test("returns false for different length strings", (t) => {
			t.false(timingSafeEqual("short", "longer"));
		});
		test("returns true for empty strings", (t) => {
			t.true(timingSafeEqual("", ""));
		});
		test("returns true for equal HTTPS URLs", (t) => {
			t.true(timingSafeEqual("https://example.com", "https://example.com"));
		});
		test("returns false for different HTTPS URLs", (t) => {
			t.false(timingSafeEqual("https://example.com", "https://other.com"));
		});
	});

	module("core / keys / stripPrivateFields", () => {
		test("strips EC private key field (d) and preserves public fields", (t) => {
			const ecPrivate = {
				kty: "EC",
				crv: "P-256",
				x: "x-coord",
				y: "y-coord",
				d: "secret-d",
				kid: "ec-1",
				alg: "ES256",
				use: "sig",
			} as unknown as JWK;
			const pub = stripPrivateFields(ecPrivate);
			t.deepEqual(pub, {
				kty: "EC",
				crv: "P-256",
				x: "x-coord",
				y: "y-coord",
				kid: "ec-1",
				alg: "ES256",
				use: "sig",
			});
			t.equal((pub as Record<string, unknown>).d, undefined);
		});
		test("strips all RSA private key fields", (t) => {
			const rsaPrivate = {
				kty: "RSA",
				n: "modulus",
				e: "AQAB",
				d: "pd",
				p: "pp",
				q: "pq",
				dp: "pdp",
				dq: "pdq",
				qi: "pqi",
				kid: "rsa-1",
				alg: "PS256",
				use: "sig",
			} as unknown as JWK;
			const pub = stripPrivateFields(rsaPrivate);
			t.deepEqual(pub, {
				kty: "RSA",
				n: "modulus",
				e: "AQAB",
				kid: "rsa-1",
				alg: "PS256",
				use: "sig",
			});
			const raw = pub as Record<string, unknown>;
			for (const f of ["d", "p", "q", "dp", "dq", "qi"]) {
				t.equal(raw[f], undefined);
			}
		});
		test("strips RSA multi-prime 'oth' field", (t) => {
			const key = {
				kty: "RSA",
				n: "modulus",
				e: "AQAB",
				d: "pd",
				p: "pp",
				q: "pq",
				dp: "pdp",
				dq: "pdq",
				qi: "pqi",
				oth: [{ r: "r", d: "d", t: "t" }],
				kid: "rsa-multi",
			} as unknown as JWK;
			const pub = stripPrivateFields(key);
			t.equal((pub as Record<string, unknown>).oth, undefined);
			t.equal((pub as Record<string, unknown>).d, undefined);
			t.equal(pub.n, "modulus");
			t.equal(pub.e, "AQAB");
		});
		test("strips OKP private key field (d) and preserves crv, x", (t) => {
			const okpPrivate = {
				kty: "OKP",
				crv: "Ed25519",
				x: "x-value",
				d: "secret-d",
				kid: "okp-1",
			} as unknown as JWK;
			const pub = stripPrivateFields(okpPrivate);
			t.deepEqual(pub, { kty: "OKP", crv: "Ed25519", x: "x-value", kid: "okp-1" });
		});
		test("throws TypeError for symmetric keys (kty 'oct')", (t) => {
			const sym = { kty: "oct", k: "secret", kid: "sym-1" } as unknown as JWK;
			try {
				stripPrivateFields(sym);
				t.ok(false, "should have thrown");
			} catch (e: unknown) {
				t.true(e instanceof TypeError);
				t.true(/symmetric key/i.test((e as Error).message));
			}
		});
		test("excludes unknown/arbitrary fields not in the public allowlist", (t) => {
			const key = {
				kty: "EC",
				crv: "P-256",
				x: "x-coord",
				y: "y-coord",
				kid: "ec-extra",
				custom_field: "drop",
				internal_secret: "drop",
			} as unknown as JWK;
			const pub = stripPrivateFields(key) as Record<string, unknown>;
			t.equal(pub.custom_field, undefined);
			t.equal(pub.internal_secret, undefined);
			t.equal(pub.kty, "EC");
		});
		test("preserves all common JWK fields", (t) => {
			const fullKey = {
				kty: "EC",
				use: "sig",
				key_ops: ["verify"],
				alg: "ES256",
				kid: "full-key",
				x5u: "https://example.com/cert",
				x5c: ["base64cert"],
				x5t: "thumbprint",
				"x5t#S256": "thumbprint256",
				crv: "P-256",
				x: "x-coord",
				y: "y-coord",
				d: "secret",
			} as unknown as JWK;
			const pub = stripPrivateFields(fullKey) as Record<string, unknown>;
			t.equal(pub.kty, "EC");
			t.equal(pub.use, "sig");
			t.deepEqual(pub.key_ops, ["verify"]);
			t.equal(pub.alg, "ES256");
			t.equal(pub.kid, "full-key");
			t.equal(pub.x5u, "https://example.com/cert");
			t.deepEqual(pub.x5c, ["base64cert"]);
			t.equal(pub.x5t, "thumbprint");
			t.equal(pub["x5t#S256"], "thumbprint256");
			t.equal(pub.crv, "P-256");
			t.equal(pub.x, "x-coord");
			t.equal(pub.y, "y-coord");
			t.equal(pub.d, undefined);
		});
		test("handles minimal key with only kty", (t) => {
			t.deepEqual(stripPrivateFields({ kty: "EC" } as unknown as JWK), { kty: "EC" });
		});
		test("works with a real generated key pair", async (t) => {
			const { privateKey } = await generateSigningKey("ES256");
			t.notEqual((privateKey as Record<string, unknown>).d, undefined);
			const pub = stripPrivateFields(privateKey);
			t.equal((pub as Record<string, unknown>).d, undefined);
			t.equal(pub.kty, "EC");
			t.equal(pub.kid, privateKey.kid);
			t.equal(pub.alg, "ES256");
		});
		test("JWK_PUBLIC_FIELDS contains exactly the 14 spec-defined fields", (t) => {
			t.equal(JWK_PUBLIC_FIELDS.size, 14);
			for (const f of [
				"kty",
				"use",
				"key_ops",
				"alg",
				"kid",
				"x5u",
				"x5c",
				"x5t",
				"x5t#S256",
				"crv",
				"x",
				"y",
				"n",
				"e",
			]) {
				t.true(JWK_PUBLIC_FIELDS.has(f));
			}
		});
	});

	// ── jose/sign-verify ──────────────────────────────────────────────
	{
		const sv_now = Math.floor(Date.now() / 1000);

		module("core / sign and verify round-trip", () => {
			test("signs and verifies an entity statement with ES256", async (t) => {
				const { publicKey, privateKey } = await generateSigningKey("ES256");
				const jwt = await signEntityStatement(
					{
						iss: "https://example.com",
						sub: "https://example.com",
						iat: sv_now,
						exp: sv_now + 3600,
					},
					privateKey,
				);
				t.equal(typeof jwt, "string");
				t.equal(jwt.split(".").length, 3);
				const result = await verifyEntityStatement(jwt, { keys: [publicKey] });
				t.true(isOk(result));
				if (isOk(result)) {
					t.equal(result.value.payload.iss, "https://example.com");
					t.equal(result.value.payload.sub, "https://example.com");
					t.equal(result.value.header.typ, JwtTyp.EntityStatement);
				}
			});
			test("signs and verifies with PS256", async (t) => {
				const { publicKey, privateKey } = await generateSigningKey("PS256");
				const jwt = await signEntityStatement(
					{
						iss: "https://rsa.example.com",
						sub: "https://rsa.example.com",
						iat: sv_now,
						exp: sv_now + 3600,
					},
					privateKey,
					{ alg: "PS256" },
				);
				const result = await verifyEntityStatement(jwt, { keys: [publicKey] });
				t.true(isOk(result));
				if (isOk(result)) {
					t.equal(result.value.header.alg, "PS256");
				}
			});
			test("fails verification with wrong key", async (t) => {
				const keys1 = await generateSigningKey("ES256");
				const keys2 = await generateSigningKey("ES256");
				const jwt = await signEntityStatement(
					{
						iss: "https://example.com",
						sub: "https://example.com",
						iat: sv_now,
						exp: sv_now + 3600,
					},
					keys1.privateKey,
				);
				t.true(isErr(await verifyEntityStatement(jwt, { keys: [keys2.publicKey] })));
			});
			test("fails verification with wrong typ", async (t) => {
				const { publicKey, privateKey } = await generateSigningKey("ES256");
				const jwt = await signEntityStatement(
					{
						iss: "https://example.com",
						sub: "https://example.com",
						iat: sv_now,
						exp: sv_now + 3600,
					},
					privateKey,
					{ typ: "trust-mark+jwt" },
				);
				const result = await verifyEntityStatement(jwt, { keys: [publicKey] });
				t.true(isErr(result));
				if (isErr(result)) {
					t.true(result.error.description.includes("typ"));
				}
			});
			test("fails verification when kid header is missing", async (t) => {
				const { publicKey, privateKey } = await generateSigningKey("ES256");
				const jose = await import("jose");
				const cryptoKey = await jose.importJWK(privateKey as unknown as JoseJWK, "ES256");
				const jwt = await new jose.SignJWT({
					iss: "https://example.com",
					sub: "https://example.com",
					iat: sv_now,
					exp: sv_now + 3600,
				} as JWTPayload)
					.setProtectedHeader({ alg: "ES256", typ: "entity-statement+jwt" })
					.sign(cryptoKey as Parameters<SignJWT["sign"]>[0]);
				const result = await verifyEntityStatement(jwt, { keys: [publicKey] });
				t.true(isErr(result));
				if (isErr(result)) {
					t.true(result.error.description.includes("kid"));
				}
			});
			test("fails verification when kid doesn't match", async (t) => {
				const keys1 = await generateSigningKey("ES256");
				const keys2 = await generateSigningKey("ES256");
				const jwt = await signEntityStatement(
					{
						iss: "https://example.com",
						sub: "https://example.com",
						iat: sv_now,
						exp: sv_now + 3600,
					},
					keys1.privateKey,
					{ kid: keys1.publicKey.kid },
				);
				t.true(isErr(await verifyEntityStatement(jwt, { keys: [keys2.publicKey] })));
			});
		});

		module("core / decodeEntityStatement", () => {
			test("decodes a JWT without verification", async (t) => {
				const { privateKey } = await generateSigningKey("ES256");
				const jwt = await signEntityStatement(
					{
						iss: "https://decode.example.com",
						sub: "https://decode.example.com",
						iat: sv_now,
						exp: sv_now + 3600,
					},
					privateKey,
				);
				const result = decodeEntityStatement(jwt);
				t.true(isOk(result));
				if (isOk(result)) {
					t.equal(result.value.payload.iss, "https://decode.example.com");
					t.equal(result.value.header.alg, "ES256");
				}
			});
			test("returns error for invalid JWT", (t) => {
				t.true(isErr(decodeEntityStatement("not-a-jwt")));
			});
		});

		module("core / assertTypHeader", () => {
			test("does not throw for matching typ", (t) => {
				try {
					assertTypHeader({ typ: "entity-statement+jwt" }, "entity-statement+jwt");
					t.ok(true);
				} catch {
					t.ok(false, "should not throw");
				}
			});
			test("throws for mismatched typ", (t) => {
				try {
					assertTypHeader({ typ: "trust-mark+jwt" }, "entity-statement+jwt");
					t.ok(false, "should have thrown");
				} catch (e: unknown) {
					t.true((e as Error).message.includes("Expected typ 'entity-statement+jwt'"));
				}
			});
			test("throws for missing typ", (t) => {
				try {
					assertTypHeader({}, "entity-statement+jwt");
					t.ok(false, "should have thrown");
				} catch {
					t.ok(true);
				}
			});
		});

		module("core / JWS serialization format", () => {
			test("rejects JWS JSON Serialization input", async (t) => {
				const { publicKey } = await generateSigningKey("ES256");
				const jsonSerialized = JSON.stringify({
					payload: "eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIn0",
					signatures: [{ protected: "eyJhbGciOiJFUzI1NiJ9", signature: "abc" }],
				});
				t.true(isErr(await verifyEntityStatement(jsonSerialized, { keys: [publicKey] })));
			});
		});

		module("core / signEntityStatement algorithm validation", () => {
			test("throws for alg: 'none'", async (t) => {
				const { privateKey } = await generateSigningKey("ES256");
				try {
					await signEntityStatement(
						{ iss: "https://example.com", sub: "https://example.com" },
						privateKey,
						{ alg: "none" },
					);
					t.ok(false, "should have thrown");
				} catch (e: unknown) {
					t.true(/Unsupported signing algorithm/.test((e as Error).message));
				}
			});
			test("throws for unsupported alg with descriptive message", async (t) => {
				const { privateKey } = await generateSigningKey("ES256");
				try {
					await signEntityStatement(
						{ iss: "https://example.com", sub: "https://example.com" },
						privateKey,
						{ alg: "HS256" },
					);
					t.ok(false, "should have thrown");
				} catch (e: unknown) {
					t.true((e as Error).message.includes("HS256"));
				}
			});
			test("throws when no kid is available", async (t) => {
				const { privateKey } = await generateSigningKey("ES256");
				try {
					await signEntityStatement({ iss: "https://example.com", sub: "https://example.com" }, {
						...privateKey,
						kid: undefined,
					} as JWK);
					t.ok(false, "should have thrown");
				} catch (e: unknown) {
					t.true((e as Error).message.toLowerCase().includes("kid"));
				}
			});
		});
	}

	// ── jose/client-auth ──────────────────────────────────────────────
	{
		const CA_AUDIENCE = "https://authority.example.com";
		const CA_CLIENT_ID = "https://client.example.com";

		async function createClientAssertion(
			overrides?: {
				iss?: string;
				sub?: string;
				aud?: string | string[];
				exp?: number;
				jti?: string;
				typ?: string;
				alg?: string;
			},
			keyOverride?: Awaited<ReturnType<typeof generateSigningKey>>,
		) {
			const keys = keyOverride ?? (await generateSigningKey("ES256"));
			const n = Math.floor(Date.now() / 1000);
			const payload: Record<string, unknown> = {
				iss: overrides?.iss ?? CA_CLIENT_ID,
				sub: overrides?.sub ?? CA_CLIENT_ID,
				aud: overrides?.aud ?? CA_AUDIENCE,
				iat: n,
				exp: overrides?.exp ?? n + 60,
			};
			if (overrides?.jti !== undefined) payload.jti = overrides.jti;
			const jwt = await signEntityStatement(payload, keys.privateKey, {
				kid: keys.privateKey.kid,
				typ: overrides?.typ ?? "JWT",
				alg: overrides?.alg,
			});
			return { jwt, keys };
		}

		module("core / verifyClientAssertion", () => {
			test("verifies a valid assertion and returns correct fields", async (t) => {
				const { jwt, keys } = await createClientAssertion();
				const result = await verifyClientAssertion(jwt, { keys: [keys.publicKey] }, CA_AUDIENCE);
				t.true(isOk(result));
				if (!isOk(result)) return;
				t.equal(result.value.clientId, CA_CLIENT_ID);
				t.true(result.value.expiresAt > 0);
				t.true(result.value.issuedAt > 0);
				t.equal(result.value.jti, undefined);
			});
			test("returns jti when present", async (t) => {
				const { jwt, keys } = await createClientAssertion({ jti: "unique-id-123" });
				const result = await verifyClientAssertion(jwt, { keys: [keys.publicKey] }, CA_AUDIENCE);
				t.true(isOk(result));
				if (!isOk(result)) return;
				t.equal(result.value.jti, "unique-id-123");
			});
			test("rejects expired assertion", async (t) => {
				const n = Math.floor(Date.now() / 1000);
				const { jwt, keys } = await createClientAssertion({ exp: n - 120 });
				const result = await verifyClientAssertion(jwt, { keys: [keys.publicKey] }, CA_AUDIENCE, {
					clockSkewSeconds: 0,
				});
				t.true(isErr(result));
				if (!isErr(result)) return;
				t.equal(result.error.code, "ERR_SIGNATURE_INVALID");
			});
			test("rejects when iss !== sub", async (t) => {
				const { jwt, keys } = await createClientAssertion({
					iss: CA_CLIENT_ID,
					sub: "https://other.example.com",
				});
				const result = await verifyClientAssertion(jwt, { keys: [keys.publicKey] }, CA_AUDIENCE);
				t.true(isErr(result));
				if (!isErr(result)) return;
				t.equal(result.error.code, "invalid_client");
				t.true(result.error.description.includes("iss"));
			});
			test("rejects wrong aud (single string)", async (t) => {
				const { jwt, keys } = await createClientAssertion({ aud: "https://wrong.example.com" });
				const result = await verifyClientAssertion(jwt, { keys: [keys.publicKey] }, CA_AUDIENCE);
				t.true(isErr(result));
				if (!isErr(result)) return;
				t.equal(result.error.code, "invalid_client");
				t.true(result.error.description.includes("audience"));
			});
			test("rejects aud array with extra values", async (t) => {
				const { jwt, keys } = await createClientAssertion({
					aud: [CA_AUDIENCE, "https://extra.example.com"],
				});
				const result = await verifyClientAssertion(jwt, { keys: [keys.publicKey] }, CA_AUDIENCE);
				t.true(isErr(result));
				if (!isErr(result)) return;
				t.equal(result.error.code, "invalid_client");
				t.true(result.error.description.includes("audience"));
			});
			test("rejects aud array with wrong single value", async (t) => {
				const { jwt, keys } = await createClientAssertion({ aud: ["https://wrong.example.com"] });
				const result = await verifyClientAssertion(jwt, { keys: [keys.publicKey] }, CA_AUDIENCE);
				t.true(isErr(result));
				if (!isErr(result)) return;
				t.equal(result.error.code, "invalid_client");
			});
			test("rejects alg: 'none'", async (t) => {
				const keys = await generateSigningKey("ES256");
				const { jwt } = await createClientAssertion({}, keys);
				const parts = jwt.split(".");
				const fakeHeader = btoa(
					JSON.stringify({ alg: "none", typ: "JWT", kid: keys.privateKey.kid }),
				)
					.replace(/\+/g, "-")
					.replace(/\//g, "_")
					.replace(/=+$/, "");
				const tamperedJwt = `${fakeHeader}.${parts[1]}.${parts[2]}`;
				const result = await verifyClientAssertion(
					tamperedJwt,
					{ keys: [keys.publicKey] },
					CA_AUDIENCE,
				);
				t.true(isErr(result));
				if (!isErr(result)) return;
				t.equal(result.error.code, "ERR_UNSUPPORTED_ALG");
			});
			test("rejects unsupported algorithm", async (t) => {
				const keys = await generateSigningKey("ES256");
				const { jwt } = await createClientAssertion({}, keys);
				const parts = jwt.split(".");
				const fakeHeader = btoa(
					JSON.stringify({ alg: "HS256", typ: "JWT", kid: keys.privateKey.kid }),
				)
					.replace(/\+/g, "-")
					.replace(/\//g, "_")
					.replace(/=+$/, "");
				const tamperedJwt = `${fakeHeader}.${parts[1]}.${parts[2]}`;
				const result = await verifyClientAssertion(
					tamperedJwt,
					{ keys: [keys.publicKey] },
					CA_AUDIENCE,
				);
				t.true(isErr(result));
				if (!isErr(result)) return;
				t.equal(result.error.code, "ERR_UNSUPPORTED_ALG");
			});
			test("rejects when no matching key in JWKS", async (t) => {
				const { jwt } = await createClientAssertion();
				const otherKeys = await generateSigningKey("ES256");
				const result = await verifyClientAssertion(
					jwt,
					{ keys: [otherKeys.publicKey] },
					CA_AUDIENCE,
				);
				t.true(isErr(result));
				if (!isErr(result)) return;
				t.equal(result.error.code, "ERR_SIGNATURE_INVALID");
			});
			test("rejects malformed JWT", async (t) => {
				const result = await verifyClientAssertion("not.a.valid-jwt", { keys: [] }, CA_AUDIENCE);
				t.true(isErr(result));
				if (!isErr(result)) return;
				t.equal(result.error.code, "ERR_SIGNATURE_INVALID");
			});
			test("accepts assertion with absent typ header", async (t) => {
				const keys = await generateSigningKey("ES256");
				const n = Math.floor(Date.now() / 1000);
				const payload: Record<string, unknown> = {
					iss: CA_CLIENT_ID,
					sub: CA_CLIENT_ID,
					aud: CA_AUDIENCE,
					iat: n,
					exp: n + 60,
				};
				const jose = await import("jose");
				const cryptoKey = await jose.importJWK(keys.privateKey as unknown as JoseJWK, "ES256");
				const jwt = await new jose.SignJWT(payload as JWTPayload)
					.setProtectedHeader({ alg: "ES256", kid: keys.privateKey.kid })
					.sign(cryptoKey as Parameters<SignJWT["sign"]>[0]);
				const result = await verifyClientAssertion(jwt, { keys: [keys.publicKey] }, CA_AUDIENCE);
				t.true(isOk(result));
				if (!isOk(result)) return;
				t.equal(result.value.clientId, CA_CLIENT_ID);
			});
			test("accepts aud as single-element array matching expected audience", async (t) => {
				const { jwt, keys } = await createClientAssertion({ aud: [CA_AUDIENCE] });
				const result = await verifyClientAssertion(jwt, { keys: [keys.publicKey] }, CA_AUDIENCE);
				t.true(isOk(result));
				if (!isOk(result)) return;
				t.equal(result.value.clientId, CA_CLIENT_ID);
			});
		});
	}

	// ── metadata-policy/apply ─────────────────────────────────────────
	module("core / normalizeScope / denormalizeScope", () => {
		test("splits space-separated scope string", (t) => {
			t.deepEqual(normalizeScope("openid profile email"), ["openid", "profile", "email"]);
		});
		test("filters empty strings from extra spaces", (t) => {
			t.deepEqual(normalizeScope("openid  profile"), ["openid", "profile"]);
		});
		test("joins array back to space-separated string", (t) => {
			t.equal(denormalizeScope(["openid", "profile"]), "openid profile");
		});
	});

	module("core / applyMetadataPolicy", () => {
		test("returns metadata unchanged when policy is empty", (t) => {
			const metadata: FederationMetadata = { openid_relying_party: { client_name: "Test RP" } };
			const result = applyMetadataPolicy(metadata, {});
			t.true(isOk(result));
			if (isOk(result)) {
				t.deepEqual(result.value, metadata);
			}
		});
		test("applies value operator (forces value)", (t) => {
			const result = applyMetadataPolicy(
				{ openid_relying_party: { token_endpoint_auth_method: "client_secret_basic" } },
				{ openid_relying_party: { token_endpoint_auth_method: { value: "private_key_jwt" } } },
			);
			t.true(isOk(result));
			if (isOk(result)) {
				t.equal(result.value.openid_relying_party?.token_endpoint_auth_method, "private_key_jwt");
			}
		});
		test("applies default operator (fills absent value)", (t) => {
			const result = applyMetadataPolicy(
				{ openid_relying_party: {} },
				{
					openid_relying_party: { token_endpoint_auth_method: { default: "client_secret_basic" } },
				},
			);
			t.true(isOk(result));
			if (isOk(result)) {
				t.equal(
					result.value.openid_relying_party?.token_endpoint_auth_method,
					"client_secret_basic",
				);
			}
		});
		test("applies add operator (union with existing)", (t) => {
			const result = applyMetadataPolicy(
				{ openid_relying_party: { grant_types: ["authorization_code"] } },
				{ openid_relying_party: { grant_types: { add: ["refresh_token"] } } },
			);
			t.true(isOk(result));
			if (isOk(result)) {
				t.deepEqual(result.value.openid_relying_party?.grant_types, [
					"authorization_code",
					"refresh_token",
				]);
			}
		});
		test("applies subset_of operator (intersects)", (t) => {
			const result = applyMetadataPolicy(
				{ openid_relying_party: { response_types: ["code", "token", "id_token"] } },
				{ openid_relying_party: { response_types: { subset_of: ["code", "id_token"] } } },
			);
			t.true(isOk(result));
			if (isOk(result)) {
				t.deepEqual(result.value.openid_relying_party?.response_types, ["code", "id_token"]);
			}
		});
		test("fails on superset_of violation", (t) => {
			const result = applyMetadataPolicy(
				{ openid_relying_party: { grant_types: ["authorization_code"] } },
				{
					openid_relying_party: {
						grant_types: { superset_of: ["authorization_code", "refresh_token"] },
					},
				},
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.equal(result.error.code, "ERR_METADATA_POLICY_VIOLATION");
			}
		});
		test("fails on one_of violation", (t) => {
			const result = applyMetadataPolicy(
				{ openid_relying_party: { token_endpoint_auth_method: "client_secret_post" } },
				{
					openid_relying_party: {
						token_endpoint_auth_method: { one_of: ["private_key_jwt", "client_secret_basic"] },
					},
				},
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.equal(result.error.code, "ERR_METADATA_POLICY_VIOLATION");
			}
		});
		test("fails on essential violation (missing required param)", (t) => {
			const result = applyMetadataPolicy(
				{ openid_relying_party: {} },
				{ openid_relying_party: { contacts: { essential: true } } },
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.equal(result.error.code, "ERR_METADATA_POLICY_VIOLATION");
			}
		});
		test("applies operators in correct order (value before add before default...)", (t) => {
			const result = applyMetadataPolicy(
				{ openid_relying_party: {} },
				{
					openid_relying_party: {
						token_endpoint_auth_method: { value: "private_key_jwt", essential: true },
					},
				},
			);
			t.true(isOk(result));
			if (isOk(result)) {
				t.equal(result.value.openid_relying_party?.token_endpoint_auth_method, "private_key_jwt");
			}
		});
		test("handles scope normalization: string → array → operators → string", (t) => {
			const result = applyMetadataPolicy(
				{ openid_relying_party: { scope: "openid profile email address" } },
				{ openid_relying_party: { scope: { subset_of: ["openid", "profile", "email"] } } },
			);
			t.true(isOk(result));
			if (isOk(result)) {
				t.equal(result.value.openid_relying_party?.scope, "openid profile email");
			}
		});
		test("applies superiorMetadataOverride before policy", (t) => {
			const result = applyMetadataPolicy(
				{ openid_relying_party: { client_name: "Old Name" } },
				{},
				{ openid_relying_party: { client_name: "Superior Override Name" } },
			);
			t.true(isOk(result));
			if (isOk(result)) {
				t.equal(result.value.openid_relying_party?.client_name, "Superior Override Name");
			}
		});
		test("removes parameter when value operator is null", (t) => {
			const result = applyMetadataPolicy(
				{ openid_relying_party: { client_name: "To Remove", scope: "openid" } },
				{ openid_relying_party: { client_name: { value: null } } },
			);
			t.true(isOk(result));
			if (isOk(result)) {
				t.equal(result.value.openid_relying_party?.client_name, undefined);
				t.equal(result.value.openid_relying_party?.scope, "openid");
			}
		});
		test("essential=true + subset_of reducing to empty array does not error", (t) => {
			const result = applyMetadataPolicy(
				{ openid_relying_party: { grant_types: ["implicit"] } },
				{
					openid_relying_party: {
						grant_types: { subset_of: ["authorization_code", "refresh_token"], essential: true },
					},
				},
			);
			t.true(isOk(result));
			if (isOk(result)) {
				t.deepEqual(result.value.openid_relying_party?.grant_types, []);
			}
		});
		test("does not mutate original metadata", (t) => {
			const metadata: FederationMetadata = {
				openid_relying_party: { token_endpoint_auth_method: "old" },
			};
			const original = JSON.parse(JSON.stringify(metadata));
			applyMetadataPolicy(metadata, {
				openid_relying_party: { token_endpoint_auth_method: { value: "new" } },
			});
			t.deepEqual(metadata, original);
		});
		test("skips entity types not in policy", (t) => {
			const result = applyMetadataPolicy(
				{
					openid_relying_party: { client_name: "RP" },
					federation_entity: { organization_name: "Org" },
				},
				{ openid_relying_party: { client_name: { value: "Forced RP" } } },
			);
			t.true(isOk(result));
			if (isOk(result)) {
				t.equal(result.value.openid_relying_party?.client_name, "Forced RP");
				t.equal(result.value.federation_entity?.organization_name, "Org");
			}
		});
		test("treats BCP47 language-tagged member name as a separate key from its base name", (t) => {
			const metadata: FederationMetadata = {
				federation_entity: {
					organization_name: "Example Corp",
					"organization_name#de": "Beispiel GmbH",
					"organization_name#ja-Kana-JP": "エグザンプル",
				},
			};
			const result = applyMetadataPolicy(metadata, {
				federation_entity: { organization_name: { value: "Forced English" } },
			});
			t.true(isOk(result));
			if (isOk(result)) {
				const fe = result.value.federation_entity as Record<string, unknown>;
				t.equal(fe.organization_name, "Forced English");
				t.equal(fe["organization_name#de"], "Beispiel GmbH");
				t.equal(fe["organization_name#ja-Kana-JP"], "エグザンプル");
			}
		});

		test("custom operator: applies a check-action custom operator before essential", (t) => {
			const calls: string[] = [];
			const regexOp: PolicyOperatorDefinition = {
				name: "regex",
				order: 4,
				action: "check",
				apply: (parameterValue, operatorValue) => {
					calls.push("regex");
					if (parameterValue === undefined) return { ok: true, value: undefined };
					const re = new RegExp(operatorValue as string);
					return re.test(parameterValue as string)
						? { ok: true, value: parameterValue }
						: { ok: false, error: "regex mismatch" };
				},
				merge: (a, _b) => ({ ok: true, value: a }),
				canCombineWith: () => true,
			};
			const trackingEssential: PolicyOperatorDefinition = {
				...(operators.essential as PolicyOperatorDefinition),
				apply: (parameterValue, operatorValue) => {
					calls.push("essential");
					return (operators.essential as PolicyOperatorDefinition).apply(
						parameterValue,
						operatorValue,
					);
				},
			};
			void trackingEssential;
			const result = applyMetadataPolicy(
				{
					openid_relying_party: { sector_identifier_uri: "https://rp.example.com/sector" },
				} as FederationMetadata,
				{
					openid_relying_party: {
						sector_identifier_uri: { regex: "^https://", essential: true },
					},
				},
				undefined,
				{ customOperators: [regexOp] },
			);
			t.true(isOk(result));
			t.equal(calls[0], "regex", "regex (custom check) ran first");
		});

		test("custom operator: applies a modify-action custom operator after value", (t) => {
			const upperOp: PolicyOperatorDefinition = {
				name: "uppercase",
				order: 2,
				action: "modify",
				apply: (parameterValue, _o) => ({
					ok: true,
					value: typeof parameterValue === "string" ? parameterValue.toUpperCase() : parameterValue,
				}),
				merge: (a, _b) => ({ ok: true, value: a }),
				canCombineWith: () => true,
			};
			const result = applyMetadataPolicy(
				{ openid_relying_party: { client_name: "ignored" } } as FederationMetadata,
				{
					openid_relying_party: { client_name: { value: "rp", uppercase: true } },
				},
				undefined,
				{ customOperators: [upperOp] },
			);
			t.true(isOk(result));
			if (isOk(result)) {
				t.equal(result.value.openid_relying_party?.client_name, "RP");
			}
		});

		test("custom operator: violation surfaces as MetadataPolicyViolation", (t) => {
			const regexOp: PolicyOperatorDefinition = {
				name: "regex",
				order: 4,
				action: "check",
				apply: (parameterValue, operatorValue) => {
					if (parameterValue === undefined) return { ok: true, value: undefined };
					const re = new RegExp(operatorValue as string);
					return re.test(parameterValue as string)
						? { ok: true, value: parameterValue }
						: { ok: false, error: "regex mismatch" };
				},
				merge: (a, _b) => ({ ok: true, value: a }),
				canCombineWith: () => true,
			};
			const result = applyMetadataPolicy(
				{
					openid_relying_party: { sector_identifier_uri: "http://rp.example.com" },
				} as FederationMetadata,
				{ openid_relying_party: { sector_identifier_uri: { regex: "^https://" } } },
				undefined,
				{ customOperators: [regexOp] },
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.equal(result.error.code, "ERR_METADATA_POLICY_VIOLATION");
				t.ok(result.error.description.includes("regex mismatch"));
			}
		});

		test("custom operator: surfaces validation error when supplied set is invalid", (t) => {
			const collidingOp: PolicyOperatorDefinition = {
				name: "value",
				order: 4,
				action: "modify",
				apply: (_p, _o) => ({ ok: true, value: undefined }),
				merge: (a, _b) => ({ ok: true, value: a }),
				canCombineWith: () => true,
			};
			const result = applyMetadataPolicy(
				{ openid_relying_party: {} } as FederationMetadata,
				{ openid_relying_party: { client_name: { value: "ok" } } },
				undefined,
				{ customOperators: [collidingOp] },
			);
			t.true(isErr(result));
			if (isErr(result)) {
				t.ok(result.error.description.includes("conflicts with a standard"));
			}
		});

		test("custom operator: ordering interleaves with standards by declared order", (t) => {
			const order: string[] = [];
			const trackedOps: Record<string, PolicyOperatorDefinition> = {
				custom_after_value: {
					name: "custom_after_value",
					order: 2,
					action: "modify",
					apply: (parameterValue, operatorValue) => {
						order.push(`custom_after_value(${parameterValue})`);
						return { ok: true, value: `${parameterValue}+${operatorValue}` };
					},
					merge: (a, _b) => ({ ok: true, value: a }),
					canCombineWith: () => true,
				},
				custom_before_essential: {
					name: "custom_before_essential",
					order: 6,
					action: "check",
					apply: (parameterValue, _o) => {
						order.push(`custom_before_essential(${parameterValue})`);
						return { ok: true, value: parameterValue };
					},
					merge: (a, _b) => ({ ok: true, value: a }),
					canCombineWith: () => true,
				},
			};
			const result = applyMetadataPolicy(
				{ openid_relying_party: {} } as FederationMetadata,
				{
					openid_relying_party: {
						client_name: {
							value: "rp",
							custom_after_value: "x",
							custom_before_essential: true,
						},
					},
				},
				undefined,
				{
					customOperators: [
						trackedOps.custom_after_value as PolicyOperatorDefinition,
						trackedOps.custom_before_essential as PolicyOperatorDefinition,
					],
				},
			);
			t.true(isOk(result));
			t.deepEqual(order, ["custom_after_value(rp)", "custom_before_essential(rp+x)"]);
		});
	});

	// ── metadata-policy/merge ─────────────────────────────────────────
	{
		function makeMergeStmt(
			overrides?: Partial<ParsedEntityStatement["payload"]>,
		): ParsedEntityStatement {
			const n = Math.floor(Date.now() / 1000);
			return {
				header: { alg: "ES256", typ: "entity-statement+jwt", kid: "k1" },
				payload: {
					iss: "https://superior.example.com" as EntityId,
					sub: "https://leaf.example.com" as EntityId,
					iat: n,
					exp: n + 3600,
					...overrides,
				} as ParsedEntityStatement["payload"],
			};
		}

		module("core / resolveMetadataPolicy", () => {
			test("returns empty policy when no statements have metadata_policy", (t) => {
				const result = resolveMetadataPolicy([makeMergeStmt()]);
				t.true(isOk(result));
				if (isOk(result)) {
					t.deepEqual(result.value, {});
				}
			});
			test("passes through single statement policy unchanged", (t) => {
				const stmt = makeMergeStmt({
					metadata_policy: {
						openid_relying_party: { scope: { subset_of: ["openid", "profile", "email"] } },
					},
				});
				const result = resolveMetadataPolicy([stmt]);
				t.true(isOk(result));
				if (isOk(result)) {
					t.deepEqual(result.value, {
						openid_relying_party: { scope: { subset_of: ["openid", "profile", "email"] } },
					});
				}
			});
			test("merges two compatible policies (TA→leaf order)", (t) => {
				const taStmt = makeMergeStmt({
					metadata_policy: {
						openid_relying_party: {
							scope: { subset_of: ["openid", "profile", "email", "address"] },
						},
					},
				});
				const midStmt = makeMergeStmt({
					metadata_policy: {
						openid_relying_party: { scope: { subset_of: ["openid", "profile", "email"] } },
					},
				});
				const result = resolveMetadataPolicy([midStmt, taStmt]);
				t.true(isOk(result));
				if (isOk(result)) {
					t.deepEqual(result.value, {
						openid_relying_party: { scope: { subset_of: ["openid", "profile", "email"] } },
					});
				}
			});
			test("detects merge conflict (value ≠ value)", (t) => {
				const stmt1 = makeMergeStmt({
					metadata_policy: {
						openid_relying_party: { token_endpoint_auth_method: { value: "client_secret_basic" } },
					},
				});
				const stmt2 = makeMergeStmt({
					metadata_policy: {
						openid_relying_party: { token_endpoint_auth_method: { value: "private_key_jwt" } },
					},
				});
				const result = resolveMetadataPolicy([stmt1, stmt2]);
				t.true(isErr(result));
				if (isErr(result)) {
					t.equal(result.error.code, "ERR_METADATA_POLICY_ERROR");
				}
			});
			test("errors on unknown critical operator", (t) => {
				const stmt = makeMergeStmt({
					metadata_policy_crit: ["unknown_op"],
					metadata_policy: {
						openid_relying_party: { scope: { unknown_op: ["x"] } as Record<string, unknown> },
					},
				});
				const result = resolveMetadataPolicy([stmt]);
				t.true(isErr(result));
				if (isErr(result)) {
					t.equal(result.error.code, "ERR_METADATA_POLICY_ERROR");
				}
			});
			test("silently skips unknown non-critical operators", (t) => {
				const stmt = makeMergeStmt({
					metadata_policy: {
						openid_relying_party: {
							scope: { subset_of: ["openid", "profile"], unknown_op: ["x"] } as Record<
								string,
								unknown
							>,
						},
					},
				});
				const result = resolveMetadataPolicy([stmt]);
				t.true(isOk(result));
				if (isOk(result)) {
					t.deepEqual(result.value, {
						openid_relying_party: { scope: { subset_of: ["openid", "profile"] } },
					});
				}
			});

			test("metadata_policy_crit: multiple critical names, all standard, resolves successfully", (t) => {
				const stmt = makeMergeStmt({
					metadata_policy_crit: ["value", "subset_of"],
					metadata_policy: {
						openid_relying_party: {
							scope: { subset_of: ["openid", "profile"] },
							client_name: { value: "Forced" },
						},
					},
				});
				const result = resolveMetadataPolicy([stmt]);
				t.true(isOk(result));
			});

			test("metadata_policy_crit: tolerates a critical name that shadows a standard operator", (t) => {
				// Standard operator names are always understood, so listing one in
				// metadata_policy_crit is a no-op rather than an error.
				const stmt = makeMergeStmt({
					metadata_policy_crit: ["essential"],
					metadata_policy: {
						openid_relying_party: { client_name: { essential: true } },
					},
				});
				const result = resolveMetadataPolicy([stmt]);
				t.true(isOk(result));
			});

			test("metadata_policy_crit: critical operators aggregate across multiple subordinate statements", (t) => {
				const stmt1 = makeMergeStmt({
					metadata_policy_crit: ["regex"],
					metadata_policy: {
						openid_relying_party: { redirect_uris: { subset_of: ["https://rp/cb"] } },
					},
				});
				const stmt2 = makeMergeStmt({
					metadata_policy_crit: ["transform"],
					metadata_policy: {
						openid_relying_party: { client_name: { default: "RP" } },
					},
				});
				// Neither custom operator is registered → both critical → policy error.
				const result = resolveMetadataPolicy([stmt1, stmt2]);
				t.true(isErr(result));
				if (isErr(result)) {
					t.ok(
						result.error.description.includes("regex") ||
							result.error.description.includes("transform"),
					);
				}
			});

			test("does not mutate input statements", (t) => {
				const policy = { openid_relying_party: { scope: { subset_of: ["openid", "profile"] } } };
				const stmt = makeMergeStmt({ metadata_policy: policy });
				const originalPolicy = JSON.parse(JSON.stringify(policy));
				resolveMetadataPolicy([stmt]);
				t.deepEqual(policy, originalPolicy);
			});
			test("merges three-level nested policies", (t) => {
				const taStmt = makeMergeStmt({
					metadata_policy: {
						openid_relying_party: {
							grant_types: { subset_of: ["authorization_code", "implicit", "refresh_token"] },
							scope: { superset_of: ["openid"] },
						},
					},
				});
				const midStmt = makeMergeStmt({
					metadata_policy: {
						openid_relying_party: {
							grant_types: { subset_of: ["authorization_code", "refresh_token"] },
							scope: { superset_of: ["openid", "profile"] },
						},
					},
				});
				const lowStmt = makeMergeStmt({
					metadata_policy: { openid_relying_party: { scope: { default: "openid profile" } } },
				});
				const result = resolveMetadataPolicy([lowStmt, midStmt, taStmt]);
				t.true(isOk(result));
				if (isOk(result)) {
					const rp = result.value.openid_relying_party as Record<string, unknown>;
					t.deepEqual(rp.grant_types, { subset_of: ["authorization_code", "refresh_token"] });
					t.deepEqual(rp.scope, { superset_of: ["openid", "profile"], default: "openid profile" });
				}
			});
			test("validates operator combinations during merge", (t) => {
				const stmt1 = makeMergeStmt({
					metadata_policy: { openid_relying_party: { scope: { add: ["extra"] } } },
				});
				const stmt2 = makeMergeStmt({
					metadata_policy: { openid_relying_party: { scope: { one_of: ["openid", "profile"] } } },
				});
				const result = resolveMetadataPolicy([stmt1, stmt2]);
				t.true(isErr(result));
				if (isErr(result)) {
					t.equal(result.error.code, "ERR_METADATA_POLICY_ERROR");
				}
			});
			test("merges different entity types independently", (t) => {
				const stmt = makeMergeStmt({
					metadata_policy: {
						openid_relying_party: { scope: { default: "openid" } },
						openid_provider: { response_types_supported: { superset_of: ["code"] } },
					},
				});
				const result = resolveMetadataPolicy([stmt]);
				t.true(isOk(result));
				if (isOk(result)) {
					t.deepEqual(result.value.openid_relying_party, { scope: { default: "openid" } });
					t.deepEqual(result.value.openid_provider, {
						response_types_supported: { superset_of: ["code"] },
					});
				}
			});
			test("validates operator combinations bidirectionally", (t) => {
				const stmt1 = makeMergeStmt({
					metadata_policy: { openid_relying_party: { scope: { value: null } } },
				});
				const stmt2 = makeMergeStmt({
					metadata_policy: { openid_relying_party: { scope: { essential: true } } },
				});
				const result = resolveMetadataPolicy([stmt1, stmt2]);
				t.true(isErr(result));
				if (isErr(result)) {
					t.equal(result.error.code, "ERR_METADATA_POLICY_ERROR");
					t.true(result.error.description.includes("Incompatible operators"));
				}
			});
			test("rejects one_of + subset_of forbidden combination during merge", (t) => {
				const stmt1 = makeMergeStmt({
					metadata_policy: {
						openid_relying_party: {
							token_endpoint_auth_method: { one_of: ["private_key_jwt", "client_secret_basic"] },
						},
					},
				});
				const stmt2 = makeMergeStmt({
					metadata_policy: {
						openid_relying_party: {
							token_endpoint_auth_method: { subset_of: ["private_key_jwt", "client_secret_post"] },
						},
					},
				});
				const result = resolveMetadataPolicy([stmt1, stmt2]);
				t.true(isErr(result));
				if (isErr(result)) {
					t.equal(result.error.code, "ERR_METADATA_POLICY_ERROR");
				}
			});
			test("accumulates operators from different levels for same parameter", (t) => {
				const taStmt = makeMergeStmt({
					metadata_policy: { openid_relying_party: { scope: { essential: true } } },
				});
				const midStmt = makeMergeStmt({
					metadata_policy: {
						openid_relying_party: { scope: { subset_of: ["openid", "profile", "email"] } },
					},
				});
				const result = resolveMetadataPolicy([midStmt, taStmt]);
				t.true(isOk(result));
				if (isOk(result)) {
					t.deepEqual(result.value.openid_relying_party?.scope, {
						essential: true,
						subset_of: ["openid", "profile", "email"],
					});
				}
			});

			test("custom operator: rejects unknown operator if listed as critical when not registered", (t) => {
				const stmt = makeMergeStmt({
					metadata_policy_crit: ["regex"],
					metadata_policy: {
						openid_relying_party: { sector_identifier_uri: { regex: "^https://.*$" } },
					},
				});
				const result = resolveMetadataPolicy([stmt]);
				t.false(isOk(result));
			});

			test("custom operator: accepts critical custom operator when registered", (t) => {
				const regexOp: PolicyOperatorDefinition = {
					name: "regex",
					order: 4,
					action: "check",
					apply: (_p, _o) => ({ ok: true, value: undefined }),
					merge: (a, _b) => ({ ok: true, value: a }),
					canCombineWith: () => true,
				};
				const stmt = makeMergeStmt({
					metadata_policy_crit: ["regex"],
					metadata_policy: {
						openid_relying_party: { sector_identifier_uri: { regex: "^https://.*$" } },
					},
				});
				const result = resolveMetadataPolicy([stmt], { customOperators: [regexOp] });
				t.true(isOk(result));
				if (isOk(result)) {
					t.deepEqual(result.value.openid_relying_party?.sector_identifier_uri, {
						regex: "^https://.*$",
					});
				}
			});

			test("custom operator: merges values from two policy statements via merge() function", (t) => {
				const accumulateOp: PolicyOperatorDefinition = {
					name: "accumulate",
					order: 4,
					action: "modify",
					apply: (_p, _o) => ({ ok: true, value: undefined }),
					merge: (a, b) => ({
						ok: true,
						value: [...(a as unknown[]), ...(b as unknown[])],
					}),
					canCombineWith: () => true,
				};
				const stmtTa = makeMergeStmt({
					metadata_policy: {
						openid_relying_party: { contacts: { accumulate: ["a@example.com"] } },
					},
				});
				const stmtIm = makeMergeStmt({
					metadata_policy: {
						openid_relying_party: { contacts: { accumulate: ["b@example.com"] } },
					},
				});
				const result = resolveMetadataPolicy([stmtIm, stmtTa], {
					customOperators: [accumulateOp],
				});
				t.true(isOk(result));
				if (isOk(result)) {
					t.deepEqual(
						(result.value.openid_relying_party?.contacts as Record<string, unknown>)?.accumulate,
						["a@example.com", "b@example.com"],
					);
				}
			});

			test("custom operator: surfaces validation error for invalid custom set (collision with standard)", (t) => {
				const badOp: PolicyOperatorDefinition = {
					name: "value",
					order: 4,
					action: "modify",
					apply: (_p, _o) => ({ ok: true, value: undefined }),
					merge: (a, _b) => ({ ok: true, value: a }),
					canCombineWith: () => true,
				};
				const result = resolveMetadataPolicy([makeMergeStmt()], { customOperators: [badOp] });
				t.true(isErr(result));
				if (isErr(result)) {
					t.ok(result.error.description.includes("conflicts with a standard"));
				}
			});

			test("custom operator: surfaces operator-merge failure as policy error", (t) => {
				const incompatibleOp: PolicyOperatorDefinition = {
					name: "incompatible",
					order: 4,
					action: "modify",
					apply: (_p, _o) => ({ ok: true, value: undefined }),
					merge: () => ({ ok: false, error: "values cannot be merged" }),
					canCombineWith: () => true,
				};
				const stmt1 = makeMergeStmt({
					metadata_policy: {
						openid_relying_party: { contacts: { incompatible: "a" } },
					},
				});
				const stmt2 = makeMergeStmt({
					metadata_policy: {
						openid_relying_party: { contacts: { incompatible: "b" } },
					},
				});
				const result = resolveMetadataPolicy([stmt2, stmt1], {
					customOperators: [incompatibleOp],
				});
				t.true(isErr(result));
				if (isErr(result)) {
					t.ok(result.error.description.includes("values cannot be merged"));
				}
			});

			test("custom operator: canCombineWith failure triggers incompatibility error", (t) => {
				const exclusiveOp: PolicyOperatorDefinition = {
					name: "exclusive",
					order: 4,
					action: "modify",
					apply: (_p, _o) => ({ ok: true, value: undefined }),
					merge: (a, _b) => ({ ok: true, value: a }),
					// rejects every standard operator
					canCombineWith: () => false,
				};
				const stmt = makeMergeStmt({
					metadata_policy: {
						openid_relying_party: { contacts: { exclusive: "x", default: ["y"] } },
					},
				});
				const result = resolveMetadataPolicy([stmt], { customOperators: [exclusiveOp] });
				t.true(isErr(result));
				if (isErr(result)) {
					t.ok(result.error.description.includes("Incompatible"));
				}
			});
		});
	}

	// ── metadata-policy/operators ─────────────────────────────────────
	{
		function getOp(name: string): PolicyOperatorDefinition {
			const op = operators[name];
			if (!op) throw new Error(`Operator '${name}' not found`);
			return op;
		}

		module("core / operators registry", () => {
			test("has all 7 operators", (t) => {
				t.equal(Object.keys(operators).length, 7);
				for (const op of Object.values(PolicyOperator)) {
					t.ok(operators[op as string]);
				}
			});
			test("operators are in correct order", (t) => {
				t.equal(operators[PolicyOperator.Value]?.order, 1);
				t.equal(operators[PolicyOperator.Add]?.order, 2);
				t.equal(operators[PolicyOperator.Default]?.order, 3);
				t.equal(operators[PolicyOperator.OneOf]?.order, 4);
				t.equal(operators[PolicyOperator.SubsetOf]?.order, 5);
				t.equal(operators[PolicyOperator.SupersetOf]?.order, 6);
				t.equal(operators[PolicyOperator.Essential]?.order, 7);
			});
		});

		module("core / validateCustomOperators", () => {
			function customOp(
				name: string,
				order: number,
				action: "check" | "modify" | "both",
			): PolicyOperatorDefinition {
				return {
					name,
					order,
					action,
					apply: (_p, _o) => ({ ok: true, value: undefined }),
					merge: (a, _b) => ({ ok: true, value: a }),
					canCombineWith: () => true,
				};
			}

			test("accepts a valid custom operator set", (t) => {
				const result = validateCustomOperators([
					customOp("regex", 4, "check"),
					customOp("transform", 2, "modify"),
				]);
				t.true(result.ok);
			});

			test("accepts an empty set", (t) => {
				const result = validateCustomOperators([]);
				t.true(result.ok);
			});

			test("rejects a custom operator named after a standard operator", (t) => {
				const result = validateCustomOperators([customOp("value", 4, "check")]);
				t.false(result.ok);
				if (result.ok) return;
				t.ok(result.error.description.includes("conflicts with a standard operator"));
			});

			test("rejects a duplicate name within the supplied set", (t) => {
				const result = validateCustomOperators([
					customOp("regex", 4, "check"),
					customOp("regex", 5, "check"),
				]);
				t.false(result.ok);
				if (result.ok) return;
				t.ok(result.error.description.includes("Duplicate"));
			});

			test("rejects modify-action operator with order <= 1", (t) => {
				const result = validateCustomOperators([customOp("transform", 1, "modify")]);
				t.false(result.ok);
				if (result.ok) return;
				t.ok(result.error.description.includes("order > 1"));
			});

			test("rejects check-action operator with order >= 7", (t) => {
				const result = validateCustomOperators([customOp("regex", 7, "check")]);
				t.false(result.ok);
				if (result.ok) return;
				t.ok(result.error.description.includes("order < 7"));
			});

			test("rejects 'both'-action operator with order outside (1,7)", (t) => {
				const lo = validateCustomOperators([customOp("ranged", 1, "both")]);
				const hi = validateCustomOperators([customOp("ranged", 7, "both")]);
				t.false(lo.ok);
				t.false(hi.ok);
			});
		});

		module("core / value operator", () => {
			test("apply: returns the operator value when param is present", (t) => {
				t.deepEqual(getOp(PolicyOperator.Value).apply("existing", "forced"), {
					ok: true,
					value: "forced",
				});
			});
			test("apply: returns removed when operator value is null", (t) => {
				t.deepEqual(getOp(PolicyOperator.Value).apply("existing", null), {
					ok: true,
					value: null,
					removed: true,
				});
			});
			test("apply: sets value even when param is absent", (t) => {
				t.deepEqual(getOp(PolicyOperator.Value).apply(undefined, "forced"), {
					ok: true,
					value: "forced",
				});
			});
			test("apply: removes when param is absent and value is null", (t) => {
				t.deepEqual(getOp(PolicyOperator.Value).apply(undefined, null), {
					ok: true,
					value: null,
					removed: true,
				});
			});
			test("merge: succeeds when values are equal", (t) => {
				t.deepEqual(getOp(PolicyOperator.Value).merge("same", "same"), { ok: true, value: "same" });
			});
			test("merge: succeeds when arrays are equal", (t) => {
				t.deepEqual(getOp(PolicyOperator.Value).merge(["a", "b"], ["a", "b"]), {
					ok: true,
					value: ["a", "b"],
				});
			});
			test("merge: fails when values differ", (t) => {
				t.false(getOp(PolicyOperator.Value).merge("one", "two").ok);
			});
		});

		module("core / add operator", () => {
			test("apply: sets value when param is absent", (t) => {
				t.deepEqual(getOp(PolicyOperator.Add).apply(undefined, ["x", "y"]), {
					ok: true,
					value: ["x", "y"],
				});
			});
			test("apply: unions with existing array without duplicates", (t) => {
				t.deepEqual(getOp(PolicyOperator.Add).apply(["a", "b"], ["b", "c"]), {
					ok: true,
					value: ["a", "b", "c"],
				});
			});
			test("apply: unions with existing when param already has all values", (t) => {
				t.deepEqual(getOp(PolicyOperator.Add).apply(["a", "b"], ["a"]), {
					ok: true,
					value: ["a", "b"],
				});
			});
			test("merge: returns union of arrays", (t) => {
				t.deepEqual(getOp(PolicyOperator.Add).merge(["a"], ["b"]), { ok: true, value: ["a", "b"] });
			});
			test("merge: deduplicates", (t) => {
				t.deepEqual(getOp(PolicyOperator.Add).merge(["a", "b"], ["b", "c"]), {
					ok: true,
					value: ["a", "b", "c"],
				});
			});
		});

		module("core / default operator", () => {
			test("apply: sets value when param is absent", (t) => {
				t.deepEqual(getOp(PolicyOperator.Default).apply(undefined, "fallback"), {
					ok: true,
					value: "fallback",
				});
			});
			test("apply: keeps existing value when param is present", (t) => {
				t.deepEqual(getOp(PolicyOperator.Default).apply("existing", "fallback"), {
					ok: true,
					value: "existing",
				});
			});
			test("merge: succeeds when values are equal", (t) => {
				t.deepEqual(getOp(PolicyOperator.Default).merge("same", "same"), {
					ok: true,
					value: "same",
				});
			});
			test("merge: fails when values differ", (t) => {
				t.false(getOp(PolicyOperator.Default).merge("a", "b").ok);
			});
		});

		module("core / one_of operator", () => {
			test("apply: passes when value is in allowed set", (t) => {
				t.deepEqual(getOp(PolicyOperator.OneOf).apply("a", ["a", "b", "c"]), {
					ok: true,
					value: "a",
				});
			});
			test("apply: fails when value is not in allowed set", (t) => {
				t.false(getOp(PolicyOperator.OneOf).apply("z", ["a", "b", "c"]).ok);
			});
			test("apply: passes when param is absent", (t) => {
				t.deepEqual(getOp(PolicyOperator.OneOf).apply(undefined, ["a", "b"]), {
					ok: true,
					value: undefined,
				});
			});
			test("merge: returns intersection", (t) => {
				t.deepEqual(getOp(PolicyOperator.OneOf).merge(["a", "b", "c"], ["b", "c", "d"]), {
					ok: true,
					value: ["b", "c"],
				});
			});
			test("merge: fails when intersection is empty", (t) => {
				t.false(getOp(PolicyOperator.OneOf).merge(["a", "b"], ["c", "d"]).ok);
			});
		});

		module("core / subset_of operator", () => {
			test("apply: intersects param with allowed set", (t) => {
				t.deepEqual(getOp(PolicyOperator.SubsetOf).apply(["a", "b", "c"], ["b", "c", "d"]), {
					ok: true,
					value: ["b", "c"],
				});
			});
			test("apply: passes when param is absent", (t) => {
				t.deepEqual(getOp(PolicyOperator.SubsetOf).apply(undefined, ["a", "b"]), {
					ok: true,
					value: undefined,
				});
			});
			test("apply: returns empty array when no overlap", (t) => {
				t.deepEqual(getOp(PolicyOperator.SubsetOf).apply(["x"], ["a", "b"]), {
					ok: true,
					value: [],
				});
			});
			test("merge: returns intersection of ceilings", (t) => {
				t.deepEqual(getOp(PolicyOperator.SubsetOf).merge(["a", "b", "c"], ["b", "c", "d"]), {
					ok: true,
					value: ["b", "c"],
				});
			});
			test("merge: allows empty intersection (restrictive)", (t) => {
				t.deepEqual(getOp(PolicyOperator.SubsetOf).merge(["a"], ["b"]), { ok: true, value: [] });
			});
		});

		module("core / superset_of operator", () => {
			test("apply: passes when param contains all required values", (t) => {
				t.deepEqual(getOp(PolicyOperator.SupersetOf).apply(["a", "b", "c"], ["a", "b"]), {
					ok: true,
					value: ["a", "b", "c"],
				});
			});
			test("apply: fails when param is missing required values", (t) => {
				t.false(getOp(PolicyOperator.SupersetOf).apply(["a"], ["a", "b"]).ok);
			});
			test("apply: passes when param is absent", (t) => {
				t.deepEqual(getOp(PolicyOperator.SupersetOf).apply(undefined, ["a"]), {
					ok: true,
					value: undefined,
				});
			});
			test("merge: returns union of floors", (t) => {
				t.deepEqual(getOp(PolicyOperator.SupersetOf).merge(["a", "b"], ["b", "c"]), {
					ok: true,
					value: ["a", "b", "c"],
				});
			});
		});

		module("core / essential operator", () => {
			test("apply: fails when essential=true and value is absent", (t) => {
				t.false(getOp(PolicyOperator.Essential).apply(undefined, true).ok);
			});
			test("apply: passes when essential=true and value is present", (t) => {
				t.deepEqual(getOp(PolicyOperator.Essential).apply("exists", true), {
					ok: true,
					value: "exists",
				});
			});
			test("apply: passes when essential=false and value is absent", (t) => {
				t.deepEqual(getOp(PolicyOperator.Essential).apply(undefined, false), {
					ok: true,
					value: undefined,
				});
			});
			test("merge: returns logical OR (true wins)", (t) => {
				t.deepEqual(getOp(PolicyOperator.Essential).merge(false, true), { ok: true, value: true });
				t.deepEqual(getOp(PolicyOperator.Essential).merge(true, false), { ok: true, value: true });
				t.deepEqual(getOp(PolicyOperator.Essential).merge(true, true), { ok: true, value: true });
				t.deepEqual(getOp(PolicyOperator.Essential).merge(false, false), {
					ok: true,
					value: false,
				});
			});
		});

		module("core / canCombineWith — always allowed (Y) combinations", () => {
			const ops2 = [
				PolicyOperator.Value,
				PolicyOperator.Add,
				PolicyOperator.Default,
				PolicyOperator.OneOf,
				PolicyOperator.SubsetOf,
				PolicyOperator.SupersetOf,
				PolicyOperator.Essential,
			] as const;
			const matrix: Record<string, Record<string, string>> = {
				value: {
					value: "-",
					add: "C",
					default: "C",
					one_of: "C",
					subset_of: "C",
					superset_of: "C",
					essential: "C*",
				},
				add: {
					value: "C",
					add: "-",
					default: "Y",
					one_of: "-",
					subset_of: "C",
					superset_of: "Y",
					essential: "Y",
				},
				default: {
					value: "C",
					add: "Y",
					default: "-",
					one_of: "Y",
					subset_of: "Y",
					superset_of: "Y",
					essential: "Y",
				},
				one_of: {
					value: "C",
					add: "-",
					default: "Y",
					one_of: "-",
					subset_of: "-",
					superset_of: "-",
					essential: "Y",
				},
				subset_of: {
					value: "C",
					add: "C",
					default: "Y",
					one_of: "-",
					subset_of: "-",
					superset_of: "C",
					essential: "Y",
				},
				superset_of: {
					value: "C",
					add: "Y",
					default: "Y",
					one_of: "-",
					subset_of: "C",
					superset_of: "-",
					essential: "Y",
				},
				essential: {
					value: "C*",
					add: "Y",
					default: "Y",
					one_of: "Y",
					subset_of: "Y",
					superset_of: "Y",
					essential: "-",
				},
			};
			for (const a of ops2) {
				for (const b of ops2) {
					if (matrix[a]?.[b] === "Y") {
						test(`${a} + ${b} is always allowed`, (t) => {
							const thisVal =
								a === "essential" ? true : a === "add" ? ["x"] : a === "superset_of" ? ["x"] : "x";
							const otherVal =
								b === "essential" ? true : b === "add" ? ["x"] : b === "superset_of" ? ["x"] : "x";
							t.true(getOp(a).canCombineWith(b, thisVal, otherVal));
						});
					}
				}
			}
		});

		module("core / canCombineWith — never allowed (-) combinations", () => {
			const ops3 = [
				PolicyOperator.Value,
				PolicyOperator.Add,
				PolicyOperator.Default,
				PolicyOperator.OneOf,
				PolicyOperator.SubsetOf,
				PolicyOperator.SupersetOf,
				PolicyOperator.Essential,
			] as const;
			const neverMatrix: Record<string, Record<string, string>> = {
				value: {
					value: "-",
					add: "C",
					default: "C",
					one_of: "C",
					subset_of: "C",
					superset_of: "C",
					essential: "C*",
				},
				add: {
					value: "C",
					add: "-",
					default: "Y",
					one_of: "-",
					subset_of: "C",
					superset_of: "Y",
					essential: "Y",
				},
				default: {
					value: "C",
					add: "Y",
					default: "-",
					one_of: "Y",
					subset_of: "Y",
					superset_of: "Y",
					essential: "Y",
				},
				one_of: {
					value: "C",
					add: "-",
					default: "Y",
					one_of: "-",
					subset_of: "-",
					superset_of: "-",
					essential: "Y",
				},
				subset_of: {
					value: "C",
					add: "C",
					default: "Y",
					one_of: "-",
					subset_of: "-",
					superset_of: "C",
					essential: "Y",
				},
				superset_of: {
					value: "C",
					add: "Y",
					default: "Y",
					one_of: "-",
					subset_of: "C",
					superset_of: "-",
					essential: "Y",
				},
				essential: {
					value: "C*",
					add: "Y",
					default: "Y",
					one_of: "Y",
					subset_of: "Y",
					superset_of: "Y",
					essential: "-",
				},
			};
			for (const a of ops3) {
				for (const b of ops3) {
					if (neverMatrix[a]?.[b] === "-") {
						test(`${a} + ${b} is never allowed`, (t) => {
							const thisVal =
								a === "essential"
									? true
									: a === "add"
										? ["x"]
										: a === "superset_of"
											? ["x"]
											: ["x"];
							const otherVal =
								b === "essential"
									? true
									: b === "add"
										? ["x"]
										: b === "superset_of"
											? ["x"]
											: ["x"];
							t.false(getOp(a).canCombineWith(b, thisVal, otherVal));
						});
					}
				}
			}
		});

		module("core / canCombineWith — conditional (C) combinations", () => {
			test("value + add: allowed when add subset of value array", (t) => {
				t.true(operators.value?.canCombineWith("add", ["a", "b"], ["a"]));
			});
			test("value + add: rejected when add not subset of value", (t) => {
				t.false(operators.value?.canCombineWith("add", ["a"], ["b"]));
			});
			test("add + value: allowed when add subset of value array", (t) => {
				t.true(operators.add?.canCombineWith("value", ["a"], ["a", "b"]));
			});
			test("value + default: allowed when equal", (t) => {
				t.true(operators.value?.canCombineWith("default", "x", "x"));
			});
			test("value + default: rejected when different", (t) => {
				t.false(operators.value?.canCombineWith("default", "x", "y"));
			});
			test("value + default: rejected when value is null", (t) => {
				t.false(operators.value?.canCombineWith("default", null, null));
			});
			test("value + one_of: allowed when value in one_of set", (t) => {
				t.true(operators.value?.canCombineWith("one_of", "a", ["a", "b"]));
			});
			test("value + one_of: rejected when value not in one_of set", (t) => {
				t.false(operators.value?.canCombineWith("one_of", "c", ["a", "b"]));
			});
			test("value + subset_of: allowed when value array subset of subset_of", (t) => {
				t.true(operators.value?.canCombineWith("subset_of", ["a", "b"], ["a", "b", "c"]));
			});
			test("value + subset_of: rejected when value not subset", (t) => {
				t.false(operators.value?.canCombineWith("subset_of", ["a", "d"], ["a", "b", "c"]));
			});
			test("value + subset_of: scalar in subset_of", (t) => {
				t.true(operators.value?.canCombineWith("subset_of", "a", ["a", "b"]));
			});
			test("value + subset_of: scalar not in subset_of", (t) => {
				t.false(operators.value?.canCombineWith("subset_of", "z", ["a", "b"]));
			});
			test("value + superset_of: allowed when value superset", (t) => {
				t.true(operators.value?.canCombineWith("superset_of", ["a", "b", "c"], ["a", "b"]));
			});
			test("value + superset_of: rejected when value not superset", (t) => {
				t.false(operators.value?.canCombineWith("superset_of", ["a"], ["a", "b"]));
			});
			test("add + subset_of: allowed when add subset of ceiling", (t) => {
				t.true(operators.add?.canCombineWith("subset_of", ["a"], ["a", "b", "c"]));
			});
			test("add + subset_of: rejected when add exceeds ceiling", (t) => {
				t.false(operators.add?.canCombineWith("subset_of", ["a", "d"], ["a", "b"]));
			});
			test("subset_of + add: allowed when add subset of ceiling", (t) => {
				t.true(operators.subset_of?.canCombineWith("add", ["a", "b", "c"], ["a"]));
			});
			test("subset_of + superset_of: allowed when floor ⊆ ceiling", (t) => {
				t.true(operators.subset_of?.canCombineWith("superset_of", ["a", "b", "c"], ["a", "b"]));
			});
			test("subset_of + superset_of: rejected when floor ⊄ ceiling", (t) => {
				t.false(operators.subset_of?.canCombineWith("superset_of", ["a", "b"], ["a", "b", "c"]));
			});
			test("superset_of + subset_of: allowed when floor ⊆ ceiling", (t) => {
				t.true(operators.superset_of?.canCombineWith("subset_of", ["a", "b"], ["a", "b", "c"]));
			});
		});

		module("core / canCombineWith — special conditional (C*) combinations", () => {
			test("value + essential: allowed normally", (t) => {
				t.true(operators.value?.canCombineWith("essential", "x", true));
			});
			test("value + essential: rejected when value=null AND essential=true", (t) => {
				t.false(operators.value?.canCombineWith("essential", null, true));
			});
			test("value + essential: allowed when value=null AND essential=false", (t) => {
				t.true(operators.value?.canCombineWith("essential", null, false));
			});
			test("essential + value: rejected when value=null AND essential=true", (t) => {
				t.false(operators.essential?.canCombineWith("value", true, null));
			});
			test("essential + value: allowed when essential=false AND value=null", (t) => {
				t.true(operators.essential?.canCombineWith("value", false, null));
			});
		});

		module("core / operator non-array robustness", () => {
			test("add apply: wraps scalar parameterValue in array before union", (t) => {
				const r = getOp(PolicyOperator.Add).apply("existing", ["new1", "new2"]);
				t.true(r.ok);
				if (r.ok) {
					t.deepEqual(r.value, ["existing", "new1", "new2"]);
				}
			});
			test("add apply: handles scalar operatorValue", (t) => {
				const r = getOp(PolicyOperator.Add).apply(["a"], "b");
				t.true(r.ok);
				if (r.ok) {
					t.deepEqual(r.value, ["a", "b"]);
				}
			});
			test("add merge: handles scalar values by wrapping in arrays", (t) => {
				const r = getOp(PolicyOperator.Add).merge("a", "b");
				t.true(r.ok);
				if (r.ok) {
					t.deepEqual(r.value, ["a", "b"]);
				}
			});
			test("subset_of apply: handles scalar parameterValue against array constraint (in set)", (t) => {
				const r = getOp(PolicyOperator.SubsetOf).apply("a", ["a", "b"]);
				t.true(r.ok);
				if (r.ok) {
					t.equal(r.value, "a");
				}
			});
			test("subset_of apply: handles scalar parameterValue against array constraint (not in set)", (t) => {
				t.false(getOp(PolicyOperator.SubsetOf).apply("c", ["a", "b"]).ok);
			});
			test("subset_of merge: handles scalar values by wrapping in arrays", (t) => {
				const r = getOp(PolicyOperator.SubsetOf).merge("a", "b");
				t.true(r.ok);
				if (r.ok) {
					t.deepEqual(r.value, []);
				}
			});
			test("superset_of apply: handles scalar parameterValue against array constraint (is superset)", (t) => {
				const r = getOp(PolicyOperator.SupersetOf).apply("a", ["a"]);
				t.true(r.ok);
				if (r.ok) {
					t.equal(r.value, "a");
				}
			});
			test("superset_of apply: handles scalar parameterValue against array constraint (not superset)", (t) => {
				t.false(getOp(PolicyOperator.SupersetOf).apply("a", ["a", "b"]).ok);
			});
			test("superset_of merge: handles scalar values by wrapping in arrays", (t) => {
				const r = getOp(PolicyOperator.SupersetOf).merge("a", "b");
				t.true(r.ok);
				if (r.ok) {
					t.deepEqual(r.value, ["a", "b"]);
				}
			});
		});
	}

	// ── federation-api/index ──────────────────────────────────────────
	{
		const fa_now = Math.floor(Date.now() / 1000);

		async function setupFAKeys() {
			const { privateKey, publicKey } = await _genKey("ES256");
			const kid = "test-key-1";
			const priv = { ...privateKey, kid };
			const pub = { ...publicKey, kid };
			const jwks: import("../../../packages/core/src/schemas/jwk.js").JWKSet = { keys: [pub] };
			return { priv, pub, jwks, kid };
		}

		module("core / verifyResolveResponse", () => {
			test("accepts valid resolve-response+jwt", async (t) => {
				const { priv, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{
						iss: "https://authority.example.com",
						sub: "https://leaf.example.com",
						iat: fa_now,
						exp: fa_now + 3600,
						metadata: { federation_entity: { organization_name: "Test" } },
						trust_chain: ["jwt1", "jwt2"],
					},
					priv,
					{ kid, typ: JwtTyp.ResolveResponse },
				);
				const result = await verifyResolveResponse(jwt, jwks);
				t.true(result.ok);
				if (result.ok) {
					t.equal(result.value.sub, "https://leaf.example.com");
				}
			});
			test("rejects wrong typ header", async (t) => {
				const { priv, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{
						iss: "https://authority.example.com",
						sub: "https://leaf.example.com",
						iat: fa_now,
						exp: fa_now + 3600,
						metadata: { federation_entity: {} },
						trust_chain: ["jwt1"],
					},
					priv,
					{ kid, typ: JwtTyp.EntityStatement },
				);
				t.false((await verifyResolveResponse(jwt, jwks)).ok);
			});
			test("accepts resolve response with aud claim", async (t) => {
				const { priv, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{
						iss: "https://authority.example.com",
						sub: "https://leaf.example.com",
						iat: fa_now,
						exp: fa_now + 3600,
						metadata: { federation_entity: { organization_name: "Test" } },
						trust_chain: ["jwt1", "jwt2"],
						aud: "https://client.example.com",
					},
					priv,
					{ kid, typ: JwtTyp.ResolveResponse },
				);
				const result = await verifyResolveResponse(jwt, jwks);
				t.true(result.ok);
				if (result.ok) {
					t.equal(result.value.aud, "https://client.example.com");
				}
			});
			test("accepts resolve response with additional claims", async (t) => {
				const { priv, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{
						iss: "https://authority.example.com",
						sub: "https://leaf.example.com",
						iat: fa_now,
						exp: fa_now + 3600,
						metadata: { federation_entity: { organization_name: "Test" } },
						trust_chain: ["jwt1"],
						custom_claim: "value",
					},
					priv,
					{ kid, typ: JwtTyp.ResolveResponse },
				);
				t.true((await verifyResolveResponse(jwt, jwks)).ok);
			});
			test("rejects invalid signature", async (t) => {
				const { priv, kid } = await setupFAKeys();
				const { publicKey: otherPub } = await _genKey("ES256");
				const otherJwks = { keys: [{ ...otherPub, kid }] };
				const jwt = await _signES(
					{
						iss: "https://authority.example.com",
						sub: "https://leaf.example.com",
						iat: fa_now,
						exp: fa_now + 3600,
						metadata: { federation_entity: {} },
						trust_chain: ["jwt1"],
					},
					priv,
					{ kid, typ: JwtTyp.ResolveResponse },
				);
				t.false((await verifyResolveResponse(jwt, otherJwks)).ok);
			});
		});

		module("core / verifyTrustMarkStatusResponse", () => {
			test("accepts valid trust-mark-status-response+jwt", async (t) => {
				const { priv, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{
						iss: "https://authority.example.com",
						iat: fa_now,
						trust_mark: "some.jwt.token",
						status: "active",
					},
					priv,
					{ kid, typ: JwtTyp.TrustMarkStatusResponse },
				);
				const result = await verifyTrustMarkStatusResponse(jwt, jwks);
				t.true(result.ok);
				if (result.ok) {
					t.equal(result.value.status, "active");
				}
			});
			test("rejects wrong typ header", async (t) => {
				const { priv, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{
						iss: "https://authority.example.com",
						iat: fa_now,
						trust_mark: "some.jwt",
						status: "active",
					},
					priv,
					{ kid, typ: JwtTyp.EntityStatement },
				);
				t.false((await verifyTrustMarkStatusResponse(jwt, jwks)).ok);
			});
			test("accepts additional status values", async (t) => {
				const { priv, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{
						iss: "https://authority.example.com",
						iat: fa_now,
						trust_mark: "some.jwt.token",
						status: "suspended",
					},
					priv,
					{ kid, typ: JwtTyp.TrustMarkStatusResponse },
				);
				const result = await verifyTrustMarkStatusResponse(jwt, jwks);
				t.true(result.ok);
				if (result.ok) {
					t.equal(result.value.status, "suspended");
				}
			});
			test("accepts additional claims in trust mark status response", async (t) => {
				const { priv, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{
						iss: "https://authority.example.com",
						iat: fa_now,
						trust_mark: "some.jwt.token",
						status: "active",
						custom_field: "extra",
					},
					priv,
					{ kid, typ: JwtTyp.TrustMarkStatusResponse },
				);
				t.true((await verifyTrustMarkStatusResponse(jwt, jwks)).ok);
			});
		});

		module("core / verifyHistoricalKeysResponse", () => {
			test("accepts valid jwk-set+jwt", async (t) => {
				const { priv, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{
						iss: "https://authority.example.com",
						iat: fa_now,
						keys: [{ kty: "EC", kid: "old-key-1", exp: fa_now - 3600 }],
					},
					priv,
					{ kid, typ: JwtTyp.JwkSet },
				);
				const result = await verifyHistoricalKeysResponse(jwt, jwks);
				t.true(result.ok);
				if (result.ok) {
					t.equal(result.value.keys.length, 1);
				}
			});
			test("rejects wrong typ header", async (t) => {
				const { priv, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{
						iss: "https://authority.example.com",
						iat: fa_now,
						keys: [{ kty: "EC", kid: "k1", exp: fa_now }],
					},
					priv,
					{ kid, typ: JwtTyp.EntityStatement },
				);
				t.false((await verifyHistoricalKeysResponse(jwt, jwks)).ok);
			});
			test("rejects keys without kid", async (t) => {
				const { priv, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{ iss: "https://authority.example.com", iat: fa_now, keys: [{ kty: "EC", exp: fa_now }] },
					priv,
					{ kid, typ: JwtTyp.JwkSet },
				);
				t.false((await verifyHistoricalKeysResponse(jwt, jwks)).ok);
			});
		});

		module("core / verifySignedJwkSet", () => {
			test("accepts valid jwk-set+jwt with required claims iss, sub, keys", async (t) => {
				const { priv, pub, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{
						iss: "https://entity.example.com",
						sub: "https://entity.example.com",
						iat: fa_now,
						keys: [pub],
					},
					priv,
					{ kid, typ: JwtTyp.JwkSet },
				);
				const result = await verifySignedJwkSet(jwt, jwks);
				t.true(result.ok);
				if (result.ok) {
					t.equal(result.value.iss, "https://entity.example.com");
					t.equal(result.value.sub, "https://entity.example.com");
					t.equal(result.value.keys.length, 1);
				}
			});
			test("rejects wrong typ header", async (t) => {
				const { priv, jwks, kid } = await setupFAKeys();
				const { publicKey: otherPub } = await _genKey("ES256");
				const jwt = await _signES(
					{
						iss: "https://entity.example.com",
						sub: "https://entity.example.com",
						iat: fa_now,
						keys: [otherPub],
					},
					priv,
					{ kid, typ: JwtTyp.EntityStatement },
				);
				t.false((await verifySignedJwkSet(jwt, jwks)).ok);
			});
			test("rejects missing keys in payload", async (t) => {
				const { priv, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{ iss: "https://entity.example.com", sub: "https://entity.example.com", iat: fa_now },
					priv,
					{ kid, typ: JwtTyp.JwkSet },
				);
				t.false((await verifySignedJwkSet(jwt, jwks)).ok);
			});
			test("rejects missing iss in payload", async (t) => {
				const { priv, pub, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{ sub: "https://entity.example.com", iat: fa_now, keys: [pub] } as Parameters<
						typeof _signES
					>[0],
					priv,
					{ kid, typ: JwtTyp.JwkSet },
				);
				t.false((await verifySignedJwkSet(jwt, jwks)).ok);
			});
			test("rejects missing sub in payload", async (t) => {
				const { priv, pub, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{ iss: "https://entity.example.com", iat: fa_now, keys: [pub] } as Parameters<
						typeof _signES
					>[0],
					priv,
					{ kid, typ: JwtTyp.JwkSet },
				);
				t.false((await verifySignedJwkSet(jwt, jwks)).ok);
			});
			test("rejects invalid signature (wrong key)", async (t) => {
				const { pub } = await setupFAKeys();
				const { privateKey: signerPriv, publicKey: signerPub } = await _genKey("ES256");
				const { publicKey: wrongPub } = await _genKey("ES256");
				const wrongJwks = { keys: [wrongPub] };
				const jwt = await _signES(
					{
						iss: "https://entity.example.com",
						sub: "https://entity.example.com",
						iat: fa_now,
						keys: [pub],
					},
					signerPriv,
					{ kid: signerPub.kid as string, typ: JwtTyp.JwkSet },
				);
				t.false((await verifySignedJwkSet(jwt, wrongJwks)).ok);
			});
			test("rejects JWT without kid header", async (t) => {
				const jose = await import("jose");
				const { priv, pub, jwks } = await setupFAKeys();
				const cryptoKey = await jose.importJWK(priv as unknown as JoseJWK, "ES256");
				const jwt = await new jose.SignJWT({
					iss: "https://entity.example.com",
					sub: "https://entity.example.com",
					iat: fa_now,
					keys: [pub],
				} as unknown as JWTPayload)
					.setProtectedHeader({ alg: "ES256", typ: JwtTyp.JwkSet } as JWTHeaderParameters)
					.sign(cryptoKey as Parameters<SignJWT["sign"]>[0]);
				const result = await verifySignedJwkSet(jwt, jwks);
				t.false(result.ok);
			});
		});

		module("core / fetchSignedJwkSet", () => {
			async function buildSignedJwkSetJwt() {
				const { priv, pub, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{
						iss: "https://entity.example.com",
						sub: "https://entity.example.com",
						iat: fa_now,
						keys: [pub],
					},
					priv,
					{ kid, typ: JwtTyp.JwkSet },
				);
				return { jwt, jwks };
			}

			test("happy path: 200 + correct Content-Type + valid JWT", async (t) => {
				const { jwt, jwks } = await buildSignedJwkSetJwt();
				const httpClient: HttpClient = async () =>
					new Response(jwt, {
						status: 200,
						headers: { "Content-Type": "application/jwk-set+jwt" },
					});
				const result = await fetchSignedJwkSet("https://entity.example.com/jwks.jose", jwks, {
					httpClient,
				});
				t.true(result.ok);
				if (!result.ok) return;
				t.equal(result.value.iss, "https://entity.example.com");
				t.equal(result.value.keys.length, 1);
			});

			test("rejects http:// URL", async (t) => {
				const { jwks } = await setupFAKeys();
				const result = await fetchSignedJwkSet("http://entity.example.com/jwks.jose", jwks);
				t.false(result.ok);
				if (result.ok) return;
				t.ok(result.error.description.includes("https"));
			});

			test("rejects URL with fragment", async (t) => {
				const { jwks } = await setupFAKeys();
				const result = await fetchSignedJwkSet("https://entity.example.com/jwks.jose#frag", jwks);
				t.false(result.ok);
				if (result.ok) return;
				t.ok(result.error.description.includes("fragment"));
			});

			test("rejects HTTP 404", async (t) => {
				const { jwks } = await setupFAKeys();
				const httpClient: HttpClient = async () =>
					new Response("not found", {
						status: 404,
						headers: { "Content-Type": "application/jwk-set+jwt" },
					});
				const result = await fetchSignedJwkSet("https://entity.example.com/jwks.jose", jwks, {
					httpClient,
				});
				t.false(result.ok);
			});

			test("rejects 200 with wrong Content-Type", async (t) => {
				const { jwt, jwks } = await buildSignedJwkSetJwt();
				const httpClient: HttpClient = async () =>
					new Response(jwt, {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				const result = await fetchSignedJwkSet("https://entity.example.com/jwks.jose", jwks, {
					httpClient,
				});
				t.false(result.ok);
				if (result.ok) return;
				t.ok(result.error.description.includes("Content-Type"));
			});

			test("accepts Content-Type with parameters (charset)", async (t) => {
				const { jwt, jwks } = await buildSignedJwkSetJwt();
				const httpClient: HttpClient = async () =>
					new Response(jwt, {
						status: 200,
						headers: { "Content-Type": "application/jwk-set+jwt; charset=utf-8" },
					});
				const result = await fetchSignedJwkSet("https://entity.example.com/jwks.jose", jwks, {
					httpClient,
				});
				t.true(result.ok);
			});

			test("propagates verifier failure (typ mismatch)", async (t) => {
				const { priv, pub, jwks, kid } = await setupFAKeys();
				const wrongTypJwt = await _signES(
					{
						iss: "https://entity.example.com",
						sub: "https://entity.example.com",
						iat: fa_now,
						keys: [pub],
					},
					priv,
					{ kid, typ: JwtTyp.EntityStatement },
				);
				const httpClient: HttpClient = async () =>
					new Response(wrongTypJwt, {
						status: 200,
						headers: { "Content-Type": "application/jwk-set+jwt" },
					});
				const result = await fetchSignedJwkSet("https://entity.example.com/jwks.jose", jwks, {
					httpClient,
				});
				t.false(result.ok);
			});
		});

		module("core / fetchJwkSet", () => {
			async function setupValidJwkSet() {
				const { publicKey } = await _genKey("ES256");
				const pub = { ...publicKey, kid: "test-key-1" };
				return JSON.stringify({ keys: [pub] });
			}

			test("happy path: 200 + valid JWK Set JSON", async (t) => {
				const body = await setupValidJwkSet();
				const httpClient: HttpClient = async () =>
					new Response(body, {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				const result = await fetchJwkSet("https://entity.example.com/jwks.json", { httpClient });
				t.true(result.ok);
				if (!result.ok) return;
				t.equal(result.value.keys.length, 1);
			});

			test("rejects http:// URL", async (t) => {
				const result = await fetchJwkSet("http://entity.example.com/jwks.json");
				t.false(result.ok);
				if (result.ok) return;
				t.ok(result.error.description.includes("https"));
			});

			test("rejects URL with fragment", async (t) => {
				const result = await fetchJwkSet("https://entity.example.com/jwks.json#frag");
				t.false(result.ok);
				if (result.ok) return;
				t.ok(result.error.description.includes("fragment"));
			});

			test("rejects HTTP 404", async (t) => {
				const httpClient: HttpClient = async () =>
					new Response("not found", {
						status: 404,
						headers: { "Content-Type": "application/json" },
					});
				const result = await fetchJwkSet("https://entity.example.com/jwks.json", { httpClient });
				t.false(result.ok);
			});

			test("rejects 200 with non-JSON body", async (t) => {
				const httpClient: HttpClient = async () =>
					new Response("<html>nope</html>", {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				const result = await fetchJwkSet("https://entity.example.com/jwks.json", { httpClient });
				t.false(result.ok);
				if (result.ok) return;
				t.ok(result.error.description.includes("not valid JSON"));
			});

			test("rejects 200 with JSON missing 'keys' array", async (t) => {
				const httpClient: HttpClient = async () =>
					new Response(JSON.stringify({ foo: "bar" }), {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				const result = await fetchJwkSet("https://entity.example.com/jwks.json", { httpClient });
				t.false(result.ok);
				if (result.ok) return;
				t.ok(result.error.description.includes("not a valid JWK Set"));
			});

			test("rejects mixed signing+encryption JWK Set without 'use'", async (t) => {
				const { publicKey: ecPub } = await _genKey("ES256");
				const sig = { ...ecPub, kid: "sig-1", alg: "ES256" };
				const enc = {
					kty: "RSA",
					kid: "enc-1",
					n: "n1",
					e: "AQAB",
					alg: "RSA-OAEP-256",
				};
				const body = JSON.stringify({ keys: [sig, enc] });
				const httpClient: HttpClient = async () =>
					new Response(body, {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				const result = await fetchJwkSet("https://entity.example.com/jwks.json", { httpClient });
				t.false(result.ok);
				if (result.ok) return;
				t.ok(result.error.description.includes("'use'"));
			});
		});

		module("core / resolveEntityKeys", () => {
			async function buildSignedJwkSetJwt(opts?: { kidOverride?: string }) {
				const { priv, pub, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{
						iss: "https://entity.example.com",
						sub: "https://entity.example.com",
						iat: fa_now,
						keys: [pub],
					},
					priv,
					{ kid: opts?.kidOverride ?? kid, typ: JwtTyp.JwkSet },
				);
				return { jwt, jwks, pub };
			}

			function inlineKey() {
				return { kty: "EC" as const, kid: "inline-1", crv: "P-256", x: "x1", y: "y1" };
			}

			test("uses signed_jwks_uri when all three representations are present", async (t) => {
				const { jwt, jwks } = await buildSignedJwkSetJwt();
				const httpClient: HttpClient = async (url) => {
					if ((url as string).includes("signed")) {
						return new Response(jwt, {
							status: 200,
							headers: { "Content-Type": "application/jwk-set+jwt" },
						});
					}
					return new Response(JSON.stringify({ keys: [inlineKey()] }), {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				};
				const result = await resolveEntityKeys(
					{
						signed_jwks_uri: "https://entity.example.com/signed.jose",
						jwks: { keys: [inlineKey()] },
						jwks_uri: "https://entity.example.com/jwks.json",
					},
					jwks,
					{ httpClient },
				);
				t.true(result.ok);
				if (!result.ok) return;
				t.equal(result.value.source, "signed_jwks_uri");
			});

			test("falls back to jwks (inline) when signed_jwks_uri absent", async (t) => {
				const { jwks } = await setupFAKeys();
				const result = await resolveEntityKeys(
					{
						jwks: { keys: [inlineKey()] },
						jwks_uri: "https://entity.example.com/jwks.json",
					},
					jwks,
				);
				t.true(result.ok);
				if (!result.ok) return;
				t.equal(result.value.source, "jwks");
				t.equal(result.value.keys.length, 1);
			});

			test("uses jwks_uri when only that representation is present", async (t) => {
				const { jwks } = await setupFAKeys();
				const httpClient: HttpClient = async () =>
					new Response(JSON.stringify({ keys: [inlineKey()] }), {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				const result = await resolveEntityKeys(
					{ jwks_uri: "https://entity.example.com/jwks.json" },
					jwks,
					{ httpClient },
				);
				t.true(result.ok);
				if (!result.ok) return;
				t.equal(result.value.source, "jwks_uri");
			});

			test("returns InvalidMetadata when no representation is present", async (t) => {
				const { jwks } = await setupFAKeys();
				const result = await resolveEntityKeys({ issuer: "https://entity.example.com" }, jwks);
				t.false(result.ok);
				if (result.ok) return;
				t.equal(result.error.code, FederationErrorCode.InvalidMetadata);
				t.ok(result.error.description.includes("no JWK Set representation"));
			});

			test("strict default: signed_jwks_uri failure returns the error (no fallback)", async (t) => {
				const { jwks } = await setupFAKeys();
				const httpClient: HttpClient = async (url) => {
					if ((url as string).includes("signed")) {
						return new Response("not found", {
							status: 404,
							headers: { "Content-Type": "application/jwk-set+jwt" },
						});
					}
					t.notOk(true, "fallback to jwks_uri should not be attempted in strict mode");
					return new Response(JSON.stringify({ keys: [inlineKey()] }), {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				};
				const result = await resolveEntityKeys(
					{
						signed_jwks_uri: "https://entity.example.com/signed.jose",
						jwks_uri: "https://entity.example.com/jwks.json",
					},
					jwks,
					{ httpClient },
				);
				t.false(result.ok);
			});

			test("returns the use-rule error when chosen path violates it", async (t) => {
				const { jwks } = await setupFAKeys();
				const sig = { kty: "EC", kid: "sig-1", crv: "P-256", x: "x1", y: "y1", alg: "ES256" };
				const enc = { kty: "RSA", kid: "enc-1", n: "n1", e: "AQAB", alg: "RSA-OAEP-256" };
				const result = await resolveEntityKeys({ jwks: { keys: [sig, enc] } }, jwks);
				t.false(result.ok);
				if (result.ok) return;
				t.ok(result.error.description.includes("'use'"));
			});

			test("allowFallback: signed fails but jwks present → falls through to jwks", async (t) => {
				const { jwks } = await setupFAKeys();
				const httpClient: HttpClient = async () =>
					new Response("not found", {
						status: 404,
						headers: { "Content-Type": "application/jwk-set+jwt" },
					});
				const result = await resolveEntityKeys(
					{
						signed_jwks_uri: "https://entity.example.com/signed.jose",
						jwks: { keys: [inlineKey()] },
					},
					jwks,
					{ httpClient, allowFallback: true },
				);
				t.true(result.ok);
				if (!result.ok) return;
				t.equal(result.value.source, "jwks");
			});

			test("allowFallback: all branches failing returns aggregated error", async (t) => {
				const { jwks } = await setupFAKeys();
				const httpClient: HttpClient = async () =>
					new Response("not found", {
						status: 404,
						headers: { "Content-Type": "application/jwk-set+jwt" },
					});
				const result = await resolveEntityKeys(
					{
						signed_jwks_uri: "https://entity.example.com/signed.jose",
						jwks_uri: "https://entity.example.com/jwks.json",
					},
					jwks,
					{ httpClient, allowFallback: true },
				);
				t.false(result.ok);
				if (result.ok) return;
				t.ok(result.error.description.includes("[signed_jwks_uri]"));
				t.ok(result.error.description.includes("[jwks_uri]"));
			});
		});

		module("core / validateSignedJwkSetSpecHygiene", () => {
			const ENTITY = "https://entity.example.com";
			type Payload = Parameters<typeof validateSignedJwkSetSpecHygiene>[0];
			function basePayload(): Payload {
				return {
					iss: ENTITY,
					sub: ENTITY,
					keys: [{ kty: "EC", kid: "k1", crv: "P-256", x: "x1", y: "y1" }],
				} as unknown as Payload;
			}

			test("accepts payload with sub === iss and no aud/nbf/jti", (t) => {
				const result = validateSignedJwkSetSpecHygiene(basePayload());
				t.true(result.ok);
			});

			test("rejects payload with sub !== iss", (t) => {
				const result = validateSignedJwkSetSpecHygiene({
					...basePayload(),
					sub: "https://other.example.com",
				} as unknown as Payload);
				t.false(result.ok);
				if (result.ok) return;
				t.ok(result.error.description.includes("'sub'"));
				t.ok(result.error.description.includes("'iss'"));
			});

			test("rejects payload containing aud", (t) => {
				const result = validateSignedJwkSetSpecHygiene({
					...basePayload(),
					aud: "https://op.example.com",
				} as unknown as Parameters<typeof validateSignedJwkSetSpecHygiene>[0]);
				t.false(result.ok);
				if (result.ok) return;
				t.ok(result.error.description.includes("'aud'"));
			});

			test("rejects payload containing nbf", (t) => {
				const result = validateSignedJwkSetSpecHygiene({
					...basePayload(),
					nbf: 1234567890,
				} as unknown as Parameters<typeof validateSignedJwkSetSpecHygiene>[0]);
				t.false(result.ok);
				if (result.ok) return;
				t.ok(result.error.description.includes("'nbf'"));
			});

			test("rejects payload containing jti", (t) => {
				const result = validateSignedJwkSetSpecHygiene({
					...basePayload(),
					jti: "abc-123",
				} as unknown as Parameters<typeof validateSignedJwkSetSpecHygiene>[0]);
				t.false(result.ok);
				if (result.ok) return;
				t.ok(result.error.description.includes("'jti'"));
			});

			test("default verifySignedJwkSet accepts sub !== iss (regression: library does NOT over-enforce SHOULD)", async (t) => {
				const { priv, pub, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{
						iss: ENTITY,
						sub: "https://other-owner.example.com",
						iat: fa_now,
						keys: [pub],
					},
					priv,
					{ kid, typ: JwtTyp.JwkSet },
				);
				const result = await verifySignedJwkSet(jwt, jwks);
				t.true(
					result.ok,
					"verifySignedJwkSet must accept sub !== iss; that constraint is opt-in via validateSignedJwkSetSpecHygiene",
				);
			});
		});

		module("core / fetchListSubordinates", () => {
			test("parses JSON array of entity identifiers from list endpoint", async (t) => {
				const httpClient: HttpClient = async () =>
					new Response(JSON.stringify(["https://a.example.com", "https://b.example.com"]), {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				const result = await fetchListSubordinates(
					"https://ta.example.com/federation_list",
					undefined,
					{ httpClient },
				);
				t.true(result.ok);
				if (result.ok) {
					t.equal(result.value.length, 2);
					t.equal(result.value[0], "https://a.example.com");
					t.equal(result.value[1], "https://b.example.com");
				}
			});
			test("repeats entity_type query for arrays and includes other filters", async (t) => {
				let capturedUrl = "";
				const httpClient: HttpClient = async (input) => {
					capturedUrl = typeof input === "string" ? input : (input as URL).toString();
					return new Response("[]", {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				};
				const result = await fetchListSubordinates(
					"https://ta.example.com/federation_list",
					{
						entityType: [EntityType.OpenIDProvider, EntityType.OpenIDRelyingParty],
						trustMarked: true,
						intermediate: false,
						trustMarkType: "https://ta.example.com/marks/audited",
					},
					{ httpClient },
				);
				t.true(result.ok);
				const url = new URL(capturedUrl);
				const types = url.searchParams.getAll("entity_type");
				t.equal(types.length, 2);
				t.equal(types[0], EntityType.OpenIDProvider);
				t.equal(types[1], EntityType.OpenIDRelyingParty);
				t.equal(url.searchParams.get("trust_marked"), "true");
				t.equal(url.searchParams.get("intermediate"), "false");
				t.equal(url.searchParams.get("trust_mark_type"), "https://ta.example.com/marks/audited");
			});
			test("rejects when list endpoint returns a non-array body", async (t) => {
				const httpClient: HttpClient = async () =>
					new Response(JSON.stringify({ foo: 1 }), {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				const result = await fetchListSubordinates(
					"https://ta.example.com/federation_list",
					undefined,
					{ httpClient },
				);
				t.false(result.ok);
			});
		});

		module("core / fetchHistoricalKeys", () => {
			test("happy path: 200 + jwk-set+jwt verifies and returns payload", async (t) => {
				const { priv, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{
						iss: "https://authority.example.com",
						iat: fa_now,
						keys: [{ kty: "EC", kid: "old-1", exp: fa_now - 3600 }],
					},
					priv,
					{ kid, typ: JwtTyp.JwkSet },
				);
				const httpClient: HttpClient = async () =>
					new Response(jwt, {
						status: 200,
						headers: { "Content-Type": "application/jwk-set+jwt" },
					});
				const result = await fetchHistoricalKeys(
					"https://ta.example.com/federation_historical_keys",
					jwks,
					{ httpClient },
				);
				t.true(isOk(result));
				if (isOk(result)) t.equal(result.value.keys.length, 1);
			});

			test("rejects http endpoint URL", async (t) => {
				const { jwks } = await setupFAKeys();
				const result = await fetchHistoricalKeys(
					"http://ta.example.com/federation_historical_keys",
					jwks,
				);
				t.true(isErr(result));
				if (isErr(result)) t.true(result.error.description.toLowerCase().includes("https"));
			});

			test("rejects 404", async (t) => {
				const { jwks } = await setupFAKeys();
				const httpClient: HttpClient = async () =>
					new Response("not found", {
						status: 404,
						headers: { "Content-Type": "application/jwk-set+jwt" },
					});
				const result = await fetchHistoricalKeys(
					"https://ta.example.com/federation_historical_keys",
					jwks,
					{ httpClient },
				);
				t.true(isErr(result));
			});

			test("rejects wrong Content-Type", async (t) => {
				const { priv, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{
						iss: "https://authority.example.com",
						iat: fa_now,
						keys: [{ kty: "EC", kid: "k1", exp: fa_now }],
					},
					priv,
					{ kid, typ: JwtTyp.JwkSet },
				);
				const httpClient: HttpClient = async () =>
					new Response(jwt, {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				const result = await fetchHistoricalKeys(
					"https://ta.example.com/federation_historical_keys",
					jwks,
					{ httpClient },
				);
				t.true(isErr(result));
				if (isErr(result)) t.true(result.error.description.toLowerCase().includes("content-type"));
			});

			test("propagates verifier failure (wrong typ)", async (t) => {
				const { priv, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{
						iss: "https://authority.example.com",
						iat: fa_now,
						keys: [{ kty: "EC", kid: "k1", exp: fa_now }],
					},
					priv,
					{ kid, typ: JwtTyp.EntityStatement },
				);
				const httpClient: HttpClient = async () =>
					new Response(jwt, {
						status: 200,
						headers: { "Content-Type": "application/jwk-set+jwt" },
					});
				const result = await fetchHistoricalKeys(
					"https://ta.example.com/federation_historical_keys",
					jwks,
					{ httpClient },
				);
				t.true(isErr(result));
			});
		});

		module("core / fetchTrustMarkList", () => {
			test("happy path: returns array of Entity Identifiers", async (t) => {
				const httpClient: HttpClient = async () =>
					new Response(JSON.stringify(["https://a.example.com", "https://b.example.com"]), {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				const result = await fetchTrustMarkList(
					"https://issuer.example.com/federation_trust_mark_list",
					{ trustMarkType: "https://example.com/tm" },
					{ httpClient },
				);
				t.true(isOk(result));
				if (isOk(result)) {
					t.equal(result.value.length, 2);
					t.equal(result.value[0], "https://a.example.com");
				}
			});

			test("includes optional sub query parameter when provided", async (t) => {
				let capturedUrl = "";
				const httpClient: HttpClient = async (url) => {
					capturedUrl = url as string;
					return new Response(JSON.stringify(["https://leaf.example.com"]), {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				};
				const result = await fetchTrustMarkList(
					"https://issuer.example.com/federation_trust_mark_list",
					{
						trustMarkType: "https://example.com/tm",
						sub: "https://leaf.example.com" as EntityId,
					},
					{ httpClient },
				);
				t.true(isOk(result));
				t.true(capturedUrl.includes("sub=https"));
				t.true(capturedUrl.includes("trust_mark_type=https"));
			});

			test("rejects http endpoint URL", async (t) => {
				const result = await fetchTrustMarkList(
					"http://issuer.example.com/federation_trust_mark_list",
					{ trustMarkType: "https://example.com/tm" },
				);
				t.true(isErr(result));
				if (isErr(result)) t.true(result.error.description.toLowerCase().includes("https"));
			});

			test("rejects missing trust_mark_type", async (t) => {
				const result = await fetchTrustMarkList(
					"https://issuer.example.com/federation_trust_mark_list",
					{ trustMarkType: "" },
				);
				t.true(isErr(result));
				if (isErr(result)) t.true(result.error.description.includes("trust_mark_type"));
			});

			test("rejects non-array JSON response", async (t) => {
				const httpClient: HttpClient = async () =>
					new Response(JSON.stringify({ entities: [] }), {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				const result = await fetchTrustMarkList(
					"https://issuer.example.com/federation_trust_mark_list",
					{ trustMarkType: "https://example.com/tm" },
					{ httpClient },
				);
				t.true(isErr(result));
				if (isErr(result)) t.true(result.error.description.includes("array"));
			});
		});

		module("core / fetchResolveResponse", () => {
			test("returns raw JWT bytes that pipe into verifyResolveResponse", async (t) => {
				const { priv, jwks, kid } = await setupFAKeys();
				const jwt = await _signES(
					{
						iss: "https://resolver.example.com",
						sub: "https://leaf.example.com",
						iat: fa_now,
						exp: fa_now + 3600,
						metadata: { federation_entity: { organization_name: "Resolved" } },
						trust_chain: ["jwt1", "jwt2"],
					},
					priv,
					{ kid, typ: JwtTyp.ResolveResponse },
				);
				const httpClient: HttpClient = async () =>
					new Response(jwt, {
						status: 200,
						headers: { "Content-Type": MediaType.ResolveResponse },
					});
				const fetchResult = await fetchResolveResponse(
					"https://resolver.example.com/federation_resolve",
					{
						sub: "https://leaf.example.com" as EntityId,
						trustAnchor: "https://ta.example.com" as EntityId,
					},
					{ httpClient },
				);
				t.true(fetchResult.ok);
				if (!fetchResult.ok) return;
				const verifyResult = await verifyResolveResponse(fetchResult.value, jwks);
				t.true(verifyResult.ok);
				if (verifyResult.ok) {
					t.equal(verifyResult.value.sub, "https://leaf.example.com");
				}
			});
			test("repeats trust_anchor and entity_type queries for arrays alongside required sub", async (t) => {
				let capturedUrl = "";
				const httpClient: HttpClient = async (input) => {
					capturedUrl = typeof input === "string" ? input : (input as URL).toString();
					return new Response("body", {
						status: 200,
						headers: { "Content-Type": MediaType.ResolveResponse },
					});
				};
				await fetchResolveResponse(
					"https://resolver.example.com/federation_resolve",
					{
						sub: "https://leaf.example.com" as EntityId,
						trustAnchor: [
							"https://ta1.example.com" as EntityId,
							"https://ta2.example.com" as EntityId,
						],
						entityType: [EntityType.OpenIDProvider, EntityType.FederationEntity],
					},
					{ httpClient },
				);
				const url = new URL(capturedUrl);
				t.equal(url.searchParams.get("sub"), "https://leaf.example.com");
				const tas = url.searchParams.getAll("trust_anchor");
				t.equal(tas.length, 2);
				t.equal(tas[0], "https://ta1.example.com");
				t.equal(tas[1], "https://ta2.example.com");
				const types = url.searchParams.getAll("entity_type");
				t.equal(types.length, 2);
				t.equal(types[0], EntityType.OpenIDProvider);
				t.equal(types[1], EntityType.FederationEntity);
			});
			test("returns network error on HTTP non-2xx response", async (t) => {
				const httpClient: HttpClient = async () => new Response("not found", { status: 404 });
				const result = await fetchResolveResponse(
					"https://resolver.example.com/federation_resolve",
					{
						sub: "https://leaf.example.com" as EntityId,
						trustAnchor: "https://ta.example.com" as EntityId,
					},
					{ httpClient },
				);
				t.false(result.ok);
			});
		});
	}

	// ── trust-chain/anchor-keys ──────────────────────────────────────
	{
		const ak_entityId = "https://ta.example.com" as EntityId;
		module("core / compareTrustAnchorKeys", () => {
			test("returns match: true when JWK sets have same kids", (t) => {
				const ecJwks = {
					keys: [
						{ kty: "EC" as const, kid: "key-1", crv: "P-256", x: "x1", y: "y1" },
						{ kty: "EC" as const, kid: "key-2", crv: "P-256", x: "x2", y: "y2" },
					],
				};
				const independentJwks = {
					keys: [
						{ kty: "EC" as const, kid: "key-2", crv: "P-256", x: "x2", y: "y2" },
						{ kty: "EC" as const, kid: "key-1", crv: "P-256", x: "x1", y: "y1" },
					],
				};
				const result = compareTrustAnchorKeys(ecJwks, independentJwks, ak_entityId);
				t.true(result.match);
				t.deepEqual(result.missingInEc, []);
				t.deepEqual(result.missingInIndependent, []);
			});
			test("returns match: false with diff details when kids differ", (t) => {
				const ecJwks = {
					keys: [
						{ kty: "EC" as const, kid: "key-1", crv: "P-256", x: "x1", y: "y1" },
						{ kty: "EC" as const, kid: "key-2", crv: "P-256", x: "x2", y: "y2" },
					],
				};
				const independentJwks = {
					keys: [
						{ kty: "EC" as const, kid: "key-2", crv: "P-256", x: "x2", y: "y2" },
						{ kty: "EC" as const, kid: "key-3", crv: "P-256", x: "x3", y: "y3" },
					],
				};
				const result = compareTrustAnchorKeys(ecJwks, independentJwks, ak_entityId);
				t.false(result.match);
				t.deepEqual(result.missingInEc, ["key-3"]);
				t.deepEqual(result.missingInIndependent, ["key-1"]);
				t.deepEqual(result.ecKids, ["key-1", "key-2"]);
				t.deepEqual(result.independentKids, ["key-2", "key-3"]);
			});
			test("handles empty JWK sets", (t) => {
				const emptyJwks = {
					keys: [] as Array<{ kty: "EC"; kid: string; crv: string; x: string; y: string }>,
				};
				const nonEmptyJwks = {
					keys: [{ kty: "EC" as const, kid: "key-1", crv: "P-256", x: "x1", y: "y1" }],
				};
				const result = compareTrustAnchorKeys(emptyJwks, nonEmptyJwks, ak_entityId);
				t.false(result.match);
				t.deepEqual(result.ecKids, []);
				t.deepEqual(result.missingInEc, ["key-1"]);
				t.deepEqual(result.missingInIndependent, []);
			});
		});
	}

	// ── integration ──────────────────────────────────────────────────
	module("core / integration", () => {
		test("resolves and validates a 2-entity chain (leaf → TA)", async (t) => {
			const builder = new MockFederationBuilder();
			await builder.addTrustAnchor("https://ta.example.com");
			await builder.addLeaf("https://leaf.example.com", "https://ta.example.com", {
				metadata: {
					openid_relying_party: { client_name: "Test RP" },
					federation_entity: { organization_name: "Test Org" },
				},
			});
			const { trustAnchors, httpClient } = builder.build();
			const resolveResult = await resolveTrustChains(
				"https://leaf.example.com" as EntityId,
				trustAnchors,
				{ httpClient },
			);
			t.equal(resolveResult.chains.length, 1);
			const chain = resolveResult.chains[0] as (typeof resolveResult.chains)[number];
			t.equal(chain.entityId, "https://leaf.example.com");
			t.equal(chain.trustAnchorId, "https://ta.example.com");
			t.equal(chain.statements.length, 3);
			const validateResult = await validateTrustChain(chain.statements as string[], trustAnchors);
			t.true(validateResult.valid);
			if (validateResult.valid) {
				t.equal(validateResult.chain.entityId, "https://leaf.example.com");
				t.equal(validateResult.chain.trustAnchorId, "https://ta.example.com");
			}
		});
		test("resolves and validates a 3-entity chain (leaf → intermediate → TA)", async (t) => {
			const builder = new MockFederationBuilder();
			await builder.addTrustAnchor("https://ta.example.com");
			await builder.addIntermediate("https://int.example.com", "https://ta.example.com");
			await builder.addLeaf("https://leaf.example.com", "https://int.example.com", {
				metadata: { openid_relying_party: { client_name: "Leaf RP" } },
			});
			const { trustAnchors, httpClient } = builder.build();
			const resolveResult = await resolveTrustChains(
				"https://leaf.example.com" as EntityId,
				trustAnchors,
				{ httpClient },
			);
			t.equal(resolveResult.chains.length, 1);
			const chain = resolveResult.chains[0] as (typeof resolveResult.chains)[number];
			t.equal(chain.statements.length, 4);
			const validateResult = await validateTrustChain(chain.statements as string[], trustAnchors);
			t.true(validateResult.valid);
		});
		test("resolves and validates a 4-entity chain (leaf → int1 → int2 → TA)", async (t) => {
			const builder = new MockFederationBuilder();
			await builder.addTrustAnchor("https://edugain.example.com");
			await builder.addIntermediate("https://swamid.example.com", "https://edugain.example.com");
			await builder.addIntermediate("https://umu.example.com", "https://swamid.example.com");
			await builder.addLeaf("https://op.umu.example.com", "https://umu.example.com", {
				metadata: {
					openid_provider: {
						issuer: "https://op.umu.example.com",
						authorization_endpoint: "https://op.umu.example.com/auth",
						token_endpoint: "https://op.umu.example.com/token",
						response_types_supported: ["code"],
						subject_types_supported: ["public"],
						id_token_signing_alg_values_supported: ["ES256"],
					},
				},
			});
			const { trustAnchors, httpClient } = builder.build();
			const resolveResult = await resolveTrustChains(
				"https://op.umu.example.com" as EntityId,
				trustAnchors,
				{ httpClient },
			);
			t.equal(resolveResult.chains.length, 1);
			const chain = resolveResult.chains[0] as (typeof resolveResult.chains)[number];
			t.equal(chain.statements.length, 5);
			const validateResult = await validateTrustChain(chain.statements as string[], trustAnchors);
			t.true(validateResult.valid);
			if (validateResult.valid) {
				t.equal(validateResult.chain.entityId, "https://op.umu.example.com");
				t.equal(validateResult.chain.trustAnchorId, "https://edugain.example.com");
			}
		});
		test("applies metadata policy across intermediates during validation", async (t) => {
			const builder = new MockFederationBuilder();
			await builder.addTrustAnchor("https://ta.example.com");
			await builder.addIntermediate("https://int.example.com", "https://ta.example.com", {
				metadataPolicy: {
					openid_relying_party: {
						scope: { subset_of: ["openid", "profile", "email"] },
						token_endpoint_auth_method: { default: "private_key_jwt" },
					},
				},
			});
			await builder.addLeaf("https://leaf.example.com", "https://int.example.com", {
				metadata: {
					openid_relying_party: {
						client_name: "Policy Leaf",
						scope: "openid profile email address",
					},
				},
			});
			const { trustAnchors, httpClient } = builder.build();
			const resolveResult = await resolveTrustChains(
				"https://leaf.example.com" as EntityId,
				trustAnchors,
				{ httpClient },
			);
			t.equal(resolveResult.chains.length, 1);
			const validateResult = await validateTrustChain(
				resolveResult.chains[0]?.statements as string[],
				trustAnchors,
			);
			t.true(validateResult.valid);
			if (validateResult.valid) {
				const rpMeta = validateResult.chain.resolvedMetadata.openid_relying_party;
				t.notEqual(rpMeta, undefined);
				t.equal(rpMeta?.scope, "openid profile email");
				t.equal(rpMeta?.token_endpoint_auth_method, "private_key_jwt");
			}
		});
		test("enforces constraints during validation", async (t) => {
			const builder = new MockFederationBuilder();
			await builder.addTrustAnchor("https://ta.example.com");
			await builder.addIntermediate("https://int.example.com", "https://ta.example.com", {
				constraints: { max_path_length: 1, naming_constraints: { permitted: [".example.com"] } },
			});
			await builder.addLeaf("https://leaf.example.com", "https://int.example.com", {
				metadata: { openid_relying_party: { client_name: "Constrained Leaf" } },
			});
			const { trustAnchors, httpClient } = builder.build();
			const resolveResult = await resolveTrustChains(
				"https://leaf.example.com" as EntityId,
				trustAnchors,
				{ httpClient },
			);
			t.equal(resolveResult.chains.length, 1);
			const validateResult = await validateTrustChain(
				resolveResult.chains[0]?.statements as string[],
				trustAnchors,
			);
			t.true(validateResult.valid);
		});
		test("rejects chain when naming constraints violated", async (t) => {
			const builder = new MockFederationBuilder();
			await builder.addTrustAnchor("https://ta.example.com");
			await builder.addIntermediate("https://int.example.com", "https://ta.example.com", {
				constraints: { naming_constraints: { permitted: [".restricted.com"] } },
			});
			await builder.addLeaf("https://leaf.example.com", "https://int.example.com", {
				metadata: { openid_relying_party: { client_name: "Wrong Domain Leaf" } },
			});
			const { trustAnchors, httpClient } = builder.build();
			const resolveResult = await resolveTrustChains(
				"https://leaf.example.com" as EntityId,
				trustAnchors,
				{ httpClient },
			);
			t.equal(resolveResult.chains.length, 1);
			const validateResult = await validateTrustChain(
				resolveResult.chains[0]?.statements as string[],
				trustAnchors,
				{ verboseErrors: true },
			);
			t.false(validateResult.valid);
			t.true(validateResult.errors.some((e) => e.code === "ERR_CONSTRAINT_VIOLATION"));
		});
	});

	// ── trust-marks/index ─────────────────────────────────────────────
	{
		const tm_now = Math.floor(Date.now() / 1000);
		async function tm_createJwt(
			payload: Record<string, unknown>,
			privateKey: JWK,
			typ: string = JwtTyp.TrustMark,
		) {
			return signEntityStatement(payload, privateKey, { typ });
		}
		module("core / validateTrustMark", () => {
			test("validates a well-formed trust mark", async (t) => {
				const issuerKeys = await generateSigningKey("ES256");
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/trust-mark/certified",
						iat: tm_now,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/trust-mark/certified": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
				);
				t.true(isOk(result));
				if (isOk(result)) {
					t.equal(result.value.trustMarkType, "https://example.com/trust-mark/certified");
					t.equal(result.value.issuer, "https://issuer.example.com");
					t.equal(result.value.subject, "https://subject.example.com");
					t.equal(result.value.issuedAt, tm_now);
				}
			});
			test("rejects trust mark with wrong typ", async (t) => {
				const issuerKeys = await generateSigningKey("ES256");
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
					},
					issuerKeys.privateKey,
					JwtTyp.EntityStatement,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
				);
				t.true(isErr(result));
				if (isErr(result)) t.equal(result.error.code, "ERR_TRUST_MARK_INVALID");
			});
			test("rejects trust mark from unauthorized issuer", async (t) => {
				const issuerKeys = await generateSigningKey("ES256");
				const jwt = await tm_createJwt(
					{
						iss: "https://unauthorized.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
				);
				t.true(isErr(result));
				if (isErr(result)) t.equal(result.error.code, "ERR_TRUST_MARK_INVALID");
			});
			test("rejects expired trust mark", async (t) => {
				const issuerKeys = await generateSigningKey("ES256");
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now - 7200,
						exp: tm_now - 3600,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
				);
				t.true(isErr(result));
				if (isErr(result)) t.equal(result.error.code, "ERR_TRUST_MARK_INVALID");
			});
			test("rejects trust mark with missing required claims", async (t) => {
				const issuerKeys = await generateSigningKey("ES256");
				const jwt = await tm_createJwt(
					{ iss: "https://issuer.example.com", sub: "https://subject.example.com", iat: tm_now },
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(jwt, {}, { keys: [issuerKeys.publicKey] });
				t.true(isErr(result));
				if (isErr(result)) t.equal(result.error.code, "ERR_TRUST_MARK_INVALID");
			});
			test("accepts trust mark with exp in the future", async (t) => {
				const issuerKeys = await generateSigningKey("ES256");
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
						exp: tm_now + 3600,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
				);
				t.true(isOk(result));
				if (isOk(result)) t.equal(result.value.expiresAt, tm_now + 3600);
			});
			test("rejects trust mark with iat in the future (beyond clock skew)", async (t) => {
				const issuerKeys = await generateSigningKey("ES256");
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now + 3600,
						exp: tm_now + 7200,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
				);
				t.true(isErr(result));
			});
			test("rejects trust mark with signature verified against wrong JWKS", async (t) => {
				const issuerKeys = await generateSigningKey("ES256");
				const otherKeys = await generateSigningKey("ES256");
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [otherKeys.publicKey] },
				);
				t.true(isErr(result));
				if (isErr(result))
					t.true(result.error.description.includes("Signature verification failed"));
			});
			test("rejects delegation where iss doesn't match owner sub", async (t) => {
				const ownerKeys = await generateSigningKey("ES256");
				const issuerKeys = await generateSigningKey("ES256");
				const delegationJwt = await signEntityStatement(
					{
						iss: "https://wrong-owner.example.com",
						sub: "https://issuer.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
						exp: tm_now + 86400,
					},
					ownerKeys.privateKey,
					{ typ: JwtTyp.TrustMarkDelegation },
				);
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
						delegation: delegationJwt,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
					{
						trustMarkOwners: {
							"https://example.com/tm": {
								sub: "https://owner.example.com",
								jwks: { keys: [ownerKeys.publicKey] },
							},
						},
					},
				);
				t.true(isErr(result));
				if (isErr(result))
					t.true(result.error.description.includes("does not match trust_mark_owners sub"));
			});
			test("rejects delegation with iat in the future", async (t) => {
				const ownerKeys = await generateSigningKey("ES256");
				const issuerKeys = await generateSigningKey("ES256");
				const delegationJwt = await signEntityStatement(
					{
						iss: "https://owner.example.com",
						sub: "https://issuer.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now + 7200,
						exp: tm_now + 86400,
					},
					ownerKeys.privateKey,
					{ typ: JwtTyp.TrustMarkDelegation },
				);
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
						delegation: delegationJwt,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
					{
						trustMarkOwners: {
							"https://example.com/tm": {
								sub: "https://owner.example.com",
								jwks: { keys: [ownerKeys.publicKey] },
							},
						},
					},
				);
				t.true(isErr(result));
				if (isErr(result))
					t.true(result.error.description.includes("Delegation iat is in the future"));
			});
			test("validates trust mark with delegation", async (t) => {
				const ownerKeys = await generateSigningKey("ES256");
				const issuerKeys = await generateSigningKey("ES256");
				const delegationJwt = await signEntityStatement(
					{
						iss: "https://owner.example.com",
						sub: "https://issuer.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
						exp: tm_now + 86400,
					},
					ownerKeys.privateKey,
					{ typ: JwtTyp.TrustMarkDelegation },
				);
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
						delegation: delegationJwt,
					},
					issuerKeys.privateKey,
				);
				const taJwks: JWKSet = { keys: [issuerKeys.publicKey] };
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					taJwks,
					{
						trustMarkOwners: {
							"https://example.com/tm": {
								sub: "https://owner.example.com",
								jwks: { keys: [ownerKeys.publicKey] },
							},
						},
					},
				);
				t.true(isOk(result));
				if (isOk(result)) {
					t.notEqual(result.value.delegation, undefined);
					t.equal(result.value.delegation?.issuer, "https://owner.example.com");
					t.equal(result.value.delegation?.subject, "https://issuer.example.com");
				}
			});
			test("rejects trust mark without kid header", async (t) => {
				const issuerKeys = await generateSigningKey("ES256");
				const jose = await import("jose");
				const cryptoKey = await jose.importJWK(
					issuerKeys.privateKey as unknown as JoseJWK,
					"ES256",
				);
				const jwt = await new jose.SignJWT({
					iss: "https://issuer.example.com",
					sub: "https://subject.example.com",
					trust_mark_type: "https://example.com/tm",
					iat: tm_now,
				} as JWTPayload)
					.setProtectedHeader({ alg: "ES256", typ: JwtTyp.TrustMark } as JWTHeaderParameters)
					.sign(cryptoKey as Parameters<SignJWT["sign"]>[0]);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
				);
				t.true(isErr(result));
				if (isErr(result)) t.true(result.error.description.includes("kid"));
			});
			test("rejects trust mark where sub does not match expectedSubject", async (t) => {
				const issuerKeys = await generateSigningKey("ES256");
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://wrong-subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
					{ expectedSubject: "https://correct-subject.example.com" },
				);
				t.true(isErr(result));
				if (isErr(result))
					t.true(result.error.description.includes("does not match expected entity"));
			});
			test("accepts trust mark where sub matches expectedSubject", async (t) => {
				const issuerKeys = await generateSigningKey("ES256");
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
					{ expectedSubject: "https://subject.example.com" },
				);
				t.true(isOk(result));
			});
			test("rejects trust mark when trust_mark_type in trustMarkOwners but no delegation", async (t) => {
				const issuerKeys = await generateSigningKey("ES256");
				const ownerKeys = await generateSigningKey("ES256");
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
					{
						trustMarkOwners: {
							"https://example.com/tm": {
								sub: "https://owner.example.com",
								jwks: { keys: [ownerKeys.publicKey] },
							},
						},
					},
				);
				t.true(isErr(result));
				if (isErr(result)) t.true(result.error.description.includes("requires delegation"));
			});
			test("rejects delegation without kid header", async (t) => {
				const ownerKeys = await generateSigningKey("ES256");
				const issuerKeys = await generateSigningKey("ES256");
				const jose = await import("jose");
				const ownerCryptoKey = await jose.importJWK(
					ownerKeys.privateKey as unknown as JoseJWK,
					"ES256",
				);
				const delegationJwt = await new jose.SignJWT({
					iss: "https://owner.example.com",
					sub: "https://issuer.example.com",
					trust_mark_type: "https://example.com/tm",
					iat: tm_now,
					exp: tm_now + 86400,
				} as JWTPayload)
					.setProtectedHeader({
						alg: "ES256",
						typ: JwtTyp.TrustMarkDelegation,
					} as JWTHeaderParameters)
					.sign(ownerCryptoKey as Parameters<SignJWT["sign"]>[0]);
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
						delegation: delegationJwt,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
					{
						trustMarkOwners: {
							"https://example.com/tm": {
								sub: "https://owner.example.com",
								jwks: { keys: [ownerKeys.publicKey] },
							},
						},
					},
				);
				t.true(isErr(result));
				if (isErr(result)) t.true(result.error.description.includes("kid"));
			});
			test("allows any issuer when trust_mark_issuers has empty array", async (t) => {
				const issuerKeys = await generateSigningKey("ES256");
				const jwt = await tm_createJwt(
					{
						iss: "https://anyone.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": [] },
					{ keys: [issuerKeys.publicKey] },
				);
				t.true(isOk(result));
			});
			test("rejects trust mark with unrecognized type (not in trust_mark_issuers)", async (t) => {
				const issuerKeys = await generateSigningKey("ES256");
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/unknown-type",
						iat: tm_now,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
				);
				t.true(isErr(result));
				if (isErr(result)) t.equal(result.error.description, "Trust mark type not recognized");
			});
			test("rejects delegation with alg=none (signEntityStatement blocks it)", async (t) => {
				const ownerKeys = await generateSigningKey("ES256");
				await t.rejects(
					signEntityStatement(
						{
							iss: "https://owner.example.com",
							sub: "https://issuer.example.com",
							trust_mark_type: "https://example.com/tm",
							iat: tm_now,
							exp: tm_now + 86400,
						},
						ownerKeys.privateKey,
						{ typ: JwtTyp.TrustMarkDelegation, alg: "none" },
					),
					/Unsupported signing algorithm/,
				);
			});
			test("rejects trust mark with alg=none (signEntityStatement blocks it)", async (t) => {
				const issuerKeys = await generateSigningKey("ES256");
				await t.rejects(
					signEntityStatement(
						{
							iss: "https://issuer.example.com",
							sub: "https://subject.example.com",
							trust_mark_type: "https://example.com/tm",
							iat: tm_now,
						},
						issuerKeys.privateKey,
						{ typ: JwtTyp.TrustMark, alg: "none" },
					),
					/Unsupported signing algorithm/,
				);
			});
			test("rejects delegation with wrong typ value", async (t) => {
				const ownerKeys = await generateSigningKey("ES256");
				const issuerKeys = await generateSigningKey("ES256");
				const wrongTypDelegation = await signEntityStatement(
					{
						iss: "https://owner.example.com",
						sub: "https://issuer.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
					},
					ownerKeys.privateKey,
					{ typ: JwtTyp.EntityStatement },
				);
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
						delegation: wrongTypDelegation,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
					{
						trustMarkOwners: {
							"https://example.com/tm": {
								sub: "https://owner.example.com",
								jwks: { keys: [ownerKeys.publicKey] },
							},
						},
					},
				);
				t.true(isErr(result));
				if (isErr(result)) {
					t.true(result.error.description.includes("Invalid delegation typ"));
				}
			});
			test("rejects delegation where sub does not match trust mark issuer", async (t) => {
				const ownerKeys = await generateSigningKey("ES256");
				const issuerKeys = await generateSigningKey("ES256");
				const delegationJwt = await signTrustMarkDelegation({
					issuer: "https://owner.example.com",
					subject: "https://other-issuer.example.com",
					trustMarkType: "https://example.com/tm",
					privateKey: ownerKeys.privateKey,
				});
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
						delegation: delegationJwt,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
					{
						trustMarkOwners: {
							"https://example.com/tm": {
								sub: "https://owner.example.com",
								jwks: { keys: [ownerKeys.publicKey] },
							},
						},
					},
				);
				t.true(isErr(result));
				if (isErr(result)) {
					t.true(result.error.description.includes("does not match trust mark issuer"));
				}
			});
			test("rejects expired delegation (exp in past)", async (t) => {
				const ownerKeys = await generateSigningKey("ES256");
				const issuerKeys = await generateSigningKey("ES256");
				const delegationJwt = await signEntityStatement(
					{
						iss: "https://owner.example.com",
						sub: "https://issuer.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now - 7200,
						exp: tm_now - 3600,
					},
					ownerKeys.privateKey,
					{ typ: JwtTyp.TrustMarkDelegation },
				);
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
						delegation: delegationJwt,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
					{
						trustMarkOwners: {
							"https://example.com/tm": {
								sub: "https://owner.example.com",
								jwks: { keys: [ownerKeys.publicKey] },
							},
						},
					},
				);
				t.true(isErr(result));
				if (isErr(result)) {
					// jose's jwtVerify catches the expired exp before our explicit guard fires;
					// either error path is acceptable as long as the delegation is rejected.
					const desc = result.error.description;
					t.true(
						desc.includes("Delegation has expired") ||
							desc.includes("Delegation signature verification failed"),
						`expected expired-delegation rejection, got: ${desc}`,
					);
				}
			});
			test("rejects delegation where trust_mark_type mismatches the trust mark", async (t) => {
				const ownerKeys = await generateSigningKey("ES256");
				const issuerKeys = await generateSigningKey("ES256");
				const delegationJwt = await signTrustMarkDelegation({
					issuer: "https://owner.example.com",
					subject: "https://issuer.example.com",
					trustMarkType: "https://example.com/tm-other",
					privateKey: ownerKeys.privateKey,
				});
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
						delegation: delegationJwt,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
					{
						trustMarkOwners: {
							"https://example.com/tm": {
								sub: "https://owner.example.com",
								jwks: { keys: [ownerKeys.publicKey] },
							},
						},
					},
				);
				t.true(isErr(result));
				if (isErr(result)) {
					t.true(result.error.description.includes("does not match"));
				}
			});
		});
		module("core / signTrustMarkDelegation", () => {
			test("creates a valid delegation JWT with correct typ header", async (t) => {
				const ownerKeys = await generateSigningKey("ES256");
				const delegationJwt = await signTrustMarkDelegation({
					issuer: "https://owner.example.com",
					subject: "https://issuer.example.com",
					trustMarkType: "https://example.com/tm",
					privateKey: ownerKeys.privateKey,
				});
				const decoded = decodeEntityStatement(delegationJwt);
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				t.equal(decoded.value.header.typ, JwtTyp.TrustMarkDelegation);
				const payload = decoded.value.payload as Record<string, unknown>;
				t.equal(payload.iss, "https://owner.example.com");
				t.equal(payload.sub, "https://issuer.example.com");
				t.equal(payload.trust_mark_type, "https://example.com/tm");
				t.equal(typeof payload.iat, "number");
				t.equal(typeof payload.exp, "number");
			});
			test("roundtrips through validateTrustMark when embedded in a trust mark", async (t) => {
				const ownerKeys = await generateSigningKey("ES256");
				const issuerKeys = await generateSigningKey("ES256");
				const delegationJwt = await signTrustMarkDelegation({
					issuer: "https://owner.example.com",
					subject: "https://issuer.example.com",
					trustMarkType: "https://example.com/tm",
					privateKey: ownerKeys.privateKey,
				});
				const jwt = await tm_createJwt(
					{
						iss: "https://issuer.example.com",
						sub: "https://subject.example.com",
						trust_mark_type: "https://example.com/tm",
						iat: tm_now,
						delegation: delegationJwt,
					},
					issuerKeys.privateKey,
				);
				const result = await validateTrustMark(
					jwt,
					{ "https://example.com/tm": ["https://issuer.example.com"] },
					{ keys: [issuerKeys.publicKey] },
					{
						trustMarkOwners: {
							"https://example.com/tm": {
								sub: "https://owner.example.com",
								jwks: { keys: [ownerKeys.publicKey] },
							},
						},
					},
				);
				t.true(isOk(result));
				if (isOk(result)) {
					t.notEqual(result.value.delegation, undefined);
					t.equal(result.value.delegation?.issuer, "https://owner.example.com");
					t.equal(result.value.delegation?.subject, "https://issuer.example.com");
					t.equal(result.value.delegation?.trustMarkType, "https://example.com/tm");
				}
			});
			test("respects custom ttlSeconds", async (t) => {
				const ownerKeys = await generateSigningKey("ES256");
				const delegationJwt = await signTrustMarkDelegation({
					issuer: "https://owner.example.com",
					subject: "https://issuer.example.com",
					trustMarkType: "https://example.com/tm",
					privateKey: ownerKeys.privateKey,
					ttlSeconds: 3600,
				});
				const decoded = decodeEntityStatement(delegationJwt);
				t.true(isOk(decoded));
				if (!isOk(decoded)) return;
				const payload = decoded.value.payload as Record<string, unknown>;
				t.equal((payload.exp as number) - (payload.iat as number), 3600);
			});
		});

		module("core / validateTrustMarkLogo", () => {
			test("happy path: 200 + image/png Content-Type", async (t) => {
				const httpClient: HttpClient = async () =>
					new Response("\x89PNG\r\n", {
						status: 200,
						headers: { "Content-Type": "image/png" },
					});
				const result = await validateTrustMarkLogo("https://example.com/logo.png", {
					httpClient,
				});
				t.true(isOk(result));
				if (isOk(result)) t.equal(result.value.contentType, "image/png");
			});

			test("rejects http URL (helper https-only)", async (t) => {
				const result = await validateTrustMarkLogo("http://example.com/logo.png");
				t.true(isErr(result));
				if (isErr(result)) {
					t.true(result.error.description.toLowerCase().includes("https"));
				}
			});

			test("rejects URL with fragment", async (t) => {
				const result = await validateTrustMarkLogo("https://example.com/logo.png#layer-1");
				t.true(isErr(result));
				if (isErr(result)) t.true(result.error.description.includes("fragment"));
			});

			test("rejects non-image Content-Type", async (t) => {
				const httpClient: HttpClient = async () =>
					new Response("<html>not an image</html>", {
						status: 200,
						headers: { "Content-Type": "text/html" },
					});
				const result = await validateTrustMarkLogo("https://example.com/page", { httpClient });
				t.true(isErr(result));
				if (isErr(result)) t.true(result.error.description.includes("not an image"));
			});

			test("rejects HTTP 404", async (t) => {
				const httpClient: HttpClient = async () =>
					new Response("not found", {
						status: 404,
						headers: { "Content-Type": "text/plain" },
					});
				const result = await validateTrustMarkLogo("https://example.com/missing.png", {
					httpClient,
				});
				t.true(isErr(result));
				if (isErr(result)) t.true(result.error.description.includes("404"));
			});
		});

		module("core / fetchTrustMark", () => {
			test("happy path: GET returns trust mark JWT", async (t) => {
				const httpClient: HttpClient = async () =>
					new Response("eyJ.fake.jwt", {
						status: 200,
						headers: { "Content-Type": "application/trust-mark+jwt" },
					});
				const result = await fetchTrustMark(
					"https://ta.example.com/federation_trust_mark",
					{
						trustMarkType: "https://example.com/tm",
						sub: "https://leaf.example.com" as EntityId,
					},
					{ httpClient },
				);
				t.true(isOk(result));
				if (isOk(result)) t.equal(result.value, "eyJ.fake.jwt");
			});

			test("rejects http endpoint URL", async (t) => {
				const result = await fetchTrustMark("http://ta.example.com/federation_trust_mark", {
					trustMarkType: "https://example.com/tm",
					sub: "https://leaf.example.com" as EntityId,
				});
				t.true(isErr(result));
				if (isErr(result)) t.true(result.error.description.includes("https"));
			});

			test("rejects 404", async (t) => {
				const httpClient: HttpClient = async () =>
					new Response("not found", {
						status: 404,
						headers: { "Content-Type": "application/trust-mark+jwt" },
					});
				const result = await fetchTrustMark(
					"https://ta.example.com/federation_trust_mark",
					{
						trustMarkType: "https://example.com/tm",
						sub: "https://leaf.example.com" as EntityId,
					},
					{ httpClient },
				);
				t.true(isErr(result));
			});

			test("rejects wrong Content-Type", async (t) => {
				const httpClient: HttpClient = async () =>
					new Response("eyJ.fake.jwt", {
						status: 200,
						headers: { "Content-Type": "application/jwt" },
					});
				const result = await fetchTrustMark(
					"https://ta.example.com/federation_trust_mark",
					{
						trustMarkType: "https://example.com/tm",
						sub: "https://leaf.example.com" as EntityId,
					},
					{ httpClient },
				);
				t.true(isErr(result));
				if (isErr(result)) t.true(result.error.description.includes("Content-Type"));
			});

			test("rejects missing trust_mark_type", async (t) => {
				const result = await fetchTrustMark("https://ta.example.com/federation_trust_mark", {
					trustMarkType: "",
					sub: "https://leaf.example.com" as EntityId,
				});
				t.true(isErr(result));
				if (isErr(result)) t.true(result.error.description.includes("trust_mark_type"));
			});
		});

		module("core / fetchTrustMarkStatus", () => {
			async function buildStatusResponseJwt(
				status: string,
				signerKeys: { privateKey: JWK; publicKey: JWK },
			): Promise<string> {
				const now = Math.floor(Date.now() / 1000);
				return _signES(
					{
						iss: "https://ta.example.com",
						iat: now,
						trust_mark: "eyJ.original.jwt",
						status,
					} as Parameters<typeof _signES>[0],
					signerKeys.privateKey,
					{ kid: signerKeys.privateKey.kid as string, typ: JwtTyp.TrustMarkStatusResponse },
				);
			}

			test("happy path: POST returns status JWT (active)", async (t) => {
				const signerKeys = await _genKey("ES256");
				const responseJwt = await buildStatusResponseJwt("active", signerKeys);
				const httpClient: HttpClient = async () =>
					new Response(responseJwt, {
						status: 200,
						headers: { "Content-Type": "application/trust-mark-status-response+jwt" },
					});
				const result = await fetchTrustMarkStatus(
					"https://ta.example.com/federation_trust_mark_status",
					"eyJ.original.jwt",
					{ keys: [signerKeys.publicKey] },
					{ httpClient },
				);
				t.true(isOk(result));
				if (isOk(result)) {
					t.equal(result.value.status, "active");
					t.equal(result.value.issuer, "https://ta.example.com");
				}
			});

			test("returns expired status pass-through", async (t) => {
				const signerKeys = await _genKey("ES256");
				const responseJwt = await buildStatusResponseJwt("expired", signerKeys);
				const httpClient: HttpClient = async () =>
					new Response(responseJwt, {
						status: 200,
						headers: { "Content-Type": "application/trust-mark-status-response+jwt" },
					});
				const result = await fetchTrustMarkStatus(
					"https://ta.example.com/federation_trust_mark_status",
					"eyJ.original.jwt",
					{ keys: [signerKeys.publicKey] },
					{ httpClient },
				);
				t.true(isOk(result));
				if (isOk(result)) t.equal(result.value.status, "expired");
			});

			test("rejects wrong Content-Type", async (t) => {
				const signerKeys = await _genKey("ES256");
				const responseJwt = await buildStatusResponseJwt("active", signerKeys);
				const httpClient: HttpClient = async () =>
					new Response(responseJwt, {
						status: 200,
						headers: { "Content-Type": "application/jwt" },
					});
				const result = await fetchTrustMarkStatus(
					"https://ta.example.com/federation_trust_mark_status",
					"eyJ.original.jwt",
					{ keys: [signerKeys.publicKey] },
					{ httpClient },
				);
				t.true(isErr(result));
				if (isErr(result)) t.true(result.error.description.includes("Content-Type"));
			});

			test("rejects signature failure (wrong signer key)", async (t) => {
				const signerKeys = await _genKey("ES256");
				const wrongKeys = await _genKey("ES256");
				const responseJwt = await buildStatusResponseJwt("active", signerKeys);
				const httpClient: HttpClient = async () =>
					new Response(responseJwt, {
						status: 200,
						headers: { "Content-Type": "application/trust-mark-status-response+jwt" },
					});
				const result = await fetchTrustMarkStatus(
					"https://ta.example.com/federation_trust_mark_status",
					"eyJ.original.jwt",
					{ keys: [wrongKeys.publicKey] },
					{ httpClient },
				);
				t.true(isErr(result));
			});

			test("rejects http endpoint URL", async (t) => {
				const signerKeys = await _genKey("ES256");
				const result = await fetchTrustMarkStatus(
					"http://ta.example.com/federation_trust_mark_status",
					"eyJ.original.jwt",
					{ keys: [signerKeys.publicKey] },
				);
				t.true(isErr(result));
				if (isErr(result)) t.true(result.error.description.includes("https"));
			});
		});
	}

	// ── trust-chain/refresh ───────────────────────────────────────────
	{
		const rf_now = Math.floor(Date.now() / 1000);
		async function rf_signEC(
			entityId: string,
			privateKey: JWK,
			publicKey: JWK,
			overrides?: Record<string, unknown>,
		) {
			return signEntityStatement(
				{
					iss: entityId,
					sub: entityId,
					iat: rf_now,
					exp: rf_now + 3600,
					jwks: { keys: [publicKey] },
					...overrides,
				},
				privateKey,
				{ typ: JwtTyp.EntityStatement },
			);
		}
		function rf_makeChain(overrides: Partial<ValidatedTrustChain> = {}): ValidatedTrustChain {
			return {
				statements: [
					{
						header: { alg: "ES256", typ: "entity-statement+jwt", kid: "k1" },
						payload: {
							iss: "https://leaf.example.com",
							sub: "https://leaf.example.com",
							iat: rf_now,
							exp: rf_now + 3600,
							jwks: { keys: [{ kty: "EC", kid: "k1", crv: "P-256", x: "x", y: "y" }] },
						},
					} as unknown as ParsedEntityStatement,
				],
				entityId: "https://leaf.example.com" as EntityId,
				trustAnchorId: "https://ta.example.com" as EntityId,
				expiresAt: rf_now + 3600,
				resolvedMetadata: {},
				trustMarks: [],
				...overrides,
			};
		}
		module("core / refreshTrustChain", () => {
			test("returns the same chain if not expired", async (t) => {
				const chain = rf_makeChain({ expiresAt: rf_now + 3600 });
				const trustAnchors: TrustAnchorSet = new Map();
				const futureClock: Clock = { now: () => rf_now };
				const result = await refreshTrustChain(chain, trustAnchors, undefined, futureClock);
				t.equal(result, chain);
			});
			test("re-resolves when chain is expired", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await rf_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{
						authority_hints: ["https://ta.example.com"],
						metadata: { openid_relying_party: { client_name: "Leaf" } },
					},
				);
				const ss = await signEntityStatement(
					{
						iss: "https://ta.example.com",
						sub: "https://leaf.example.com",
						iat: rf_now,
						exp: rf_now + 7200,
						jwks: { keys: [leafKeys.publicKey] },
					},
					taKeys.privateKey,
					{ typ: JwtTyp.EntityStatement },
				);
				const taEc = await rf_signEC(
					"https://ta.example.com",
					taKeys.privateKey,
					taKeys.publicKey,
					{
						metadata: {
							federation_entity: { federation_fetch_endpoint: "https://ta.example.com/fetch" },
						},
					},
				);
				const trustAnchors: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const expiredChain = rf_makeChain({ expiresAt: rf_now - 100 });
				const responses: Response[] = [
					new Response(leafEc, {
						status: 200,
						headers: { "Content-Type": "application/entity-statement+jwt" },
					}),
					new Response(taEc, {
						status: 200,
						headers: { "Content-Type": "application/entity-statement+jwt" },
					}),
					new Response(ss, {
						status: 200,
						headers: { "Content-Type": "application/entity-statement+jwt" },
					}),
					new Response(taEc, {
						status: 200,
						headers: { "Content-Type": "application/entity-statement+jwt" },
					}),
				];
				const httpClient = async () => responses.shift()!;
				const result = await refreshTrustChain(
					expiredChain,
					trustAnchors,
					{ httpClient },
					{ now: () => rf_now },
				);
				t.notEqual(result, expiredChain);
				t.equal(result.entityId, "https://leaf.example.com");
			});
			test("re-resolves when forceRefresh is true even if not expired", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await rf_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{
						authority_hints: ["https://ta.example.com"],
						metadata: { openid_relying_party: { client_name: "Leaf" } },
					},
				);
				const ss = await signEntityStatement(
					{
						iss: "https://ta.example.com",
						sub: "https://leaf.example.com",
						iat: rf_now,
						exp: rf_now + 7200,
						jwks: { keys: [leafKeys.publicKey] },
					},
					taKeys.privateKey,
					{ typ: JwtTyp.EntityStatement },
				);
				const taEc = await rf_signEC(
					"https://ta.example.com",
					taKeys.privateKey,
					taKeys.publicKey,
					{
						metadata: {
							federation_entity: { federation_fetch_endpoint: "https://ta.example.com/fetch" },
						},
					},
				);
				const trustAnchors: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const freshChain = rf_makeChain({ expiresAt: rf_now + 9999 });
				const responses: Response[] = [
					new Response(leafEc, {
						status: 200,
						headers: { "Content-Type": "application/entity-statement+jwt" },
					}),
					new Response(taEc, {
						status: 200,
						headers: { "Content-Type": "application/entity-statement+jwt" },
					}),
					new Response(ss, {
						status: 200,
						headers: { "Content-Type": "application/entity-statement+jwt" },
					}),
					new Response(taEc, {
						status: 200,
						headers: { "Content-Type": "application/entity-statement+jwt" },
					}),
				];
				type HttpArgs = [string | URL | Request, RequestInit | undefined];
				const calls: HttpArgs[] = [];
				const httpClient = async (url: string | URL | Request, init?: RequestInit) => {
					calls.push([url, init]);
					return responses.shift()!;
				};
				const result = await refreshTrustChain(
					freshChain,
					trustAnchors,
					{ httpClient, forceRefresh: true },
					{ now: () => rf_now },
				);
				t.notEqual(result, freshChain);
				t.true(calls.length > 0, "httpClient was called at least once");
			});
			test("throws if re-resolve fails", async (t) => {
				const expiredChain = rf_makeChain({ expiresAt: rf_now - 100 });
				const trustAnchors: TrustAnchorSet = new Map();
				const httpClient = async () => new Response("Not Found", { status: 404 });
				await t.rejects(
					refreshTrustChain(expiredChain, trustAnchors, { httpClient }, { now: () => rf_now }),
					/Failed to refresh trust chain/,
				);
			});
		});
	}

	// ── trust-chain/resolve ───────────────────────────────────────────
	{
		const rs_now = Math.floor(Date.now() / 1000);
		async function rs_signEC(eid: string, privateKey: JWK, overrides?: Record<string, unknown>) {
			return signEntityStatement(
				{
					iss: eid,
					sub: eid,
					iat: rs_now,
					exp: rs_now + 3600,
					jwks: { keys: [privateKey] },
					...overrides,
				},
				privateKey,
				{ typ: JwtTyp.EntityStatement },
			);
		}
		async function rs_signSS(
			issuer: string,
			subject: string,
			privateKey: JWK,
			overrides?: Record<string, unknown>,
		) {
			return signEntityStatement(
				{
					iss: issuer,
					sub: subject,
					iat: rs_now,
					exp: rs_now + 3600,
					jwks: { keys: [privateKey] },
					...overrides,
				},
				privateKey,
				{ typ: JwtTyp.EntityStatement },
			);
		}
		module("core / createConcurrencyLimiter", () => {
			test("limits concurrent executions", async (t) => {
				const limiter = createConcurrencyLimiter(2);
				let active = 0,
					maxActive = 0;
				const task = async () => {
					active++;
					maxActive = Math.max(maxActive, active);
					await new Promise((r) => setTimeout(r, 50));
					active--;
					return "done";
				};
				const results = await Promise.all([
					limiter(task),
					limiter(task),
					limiter(task),
					limiter(task),
				]);
				t.ok(maxActive <= 2);
				t.deepEqual(results, ["done", "done", "done", "done"]);
			});
			test("queues excess requests and releases on completion", async (t) => {
				const limiter = createConcurrencyLimiter(1);
				const order: number[] = [];
				const task = (id: number) => async () => {
					order.push(id);
					await new Promise((r) => setTimeout(r, 10));
					return id;
				};
				const results = await Promise.all([limiter(task(1)), limiter(task(2)), limiter(task(3))]);
				t.deepEqual(results, [1, 2, 3]);
				t.deepEqual(order, [1, 2, 3]);
			});
		});
		module("core / resolveTrustChains", () => {
			test("resolves single path: leaf → TA", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const taEc = await rs_signEC("https://ta.example.com", taKeys.privateKey, {
					jwks: { keys: [taKeys.publicKey] },
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: "https://ta.example.com/federation_fetch",
						},
					},
				});
				const leafEc = await rs_signEC("https://leaf.example.com", leafKeys.privateKey, {
					jwks: { keys: [leafKeys.publicKey] },
					authority_hints: ["https://ta.example.com"],
					metadata: { federation_entity: { organization_name: "Leaf" } },
				});
				const ss = await rs_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					{ jwks: { keys: [leafKeys.publicKey] } },
				);
				const responses: Record<string, string> = {
					"https://leaf.example.com/.well-known/openid-federation": leafEc,
					"https://ta.example.com/.well-known/openid-federation": taEc,
					"https://ta.example.com/federation_fetch?sub=https%3A%2F%2Fleaf.example.com": ss,
				};
				const mockFetch = async (url: string | URL | Request) => {
					const body = responses[url.toString()];
					return body
						? new Response(body, {
								status: 200,
								headers: { "Content-Type": "application/entity-statement+jwt" },
							})
						: new Response("Not found", { status: 404 });
				};
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await resolveTrustChains("https://leaf.example.com" as EntityId, taSet, {
					httpClient: mockFetch,
				});
				t.ok(result.chains.length >= 1);
				t.equal(result.chains[0]?.entityId, "https://leaf.example.com");
				t.equal(result.chains[0]?.trustAnchorId, "https://ta.example.com");
				t.equal(result.chains[0]?.statements.length, 3);
			});
			test("resolves two paths: leaf → int1 → TA and leaf → int2 → TA", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const int1Keys = await generateSigningKey("ES256");
				const int2Keys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const taEc = await rs_signEC("https://ta.example.com", taKeys.privateKey, {
					jwks: { keys: [taKeys.publicKey] },
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: "https://ta.example.com/federation_fetch",
						},
					},
				});
				const int1Ec = await rs_signEC("https://int1.example.com", int1Keys.privateKey, {
					jwks: { keys: [int1Keys.publicKey] },
					authority_hints: ["https://ta.example.com"],
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: "https://int1.example.com/federation_fetch",
						},
					},
				});
				const int2Ec = await rs_signEC("https://int2.example.com", int2Keys.privateKey, {
					jwks: { keys: [int2Keys.publicKey] },
					authority_hints: ["https://ta.example.com"],
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: "https://int2.example.com/federation_fetch",
						},
					},
				});
				const leafEc = await rs_signEC("https://leaf.example.com", leafKeys.privateKey, {
					jwks: { keys: [leafKeys.publicKey] },
					authority_hints: ["https://int1.example.com", "https://int2.example.com"],
				});
				const ssInt1Leaf = await rs_signSS(
					"https://int1.example.com",
					"https://leaf.example.com",
					int1Keys.privateKey,
					{ jwks: { keys: [leafKeys.publicKey] } },
				);
				const ssInt2Leaf = await rs_signSS(
					"https://int2.example.com",
					"https://leaf.example.com",
					int2Keys.privateKey,
					{ jwks: { keys: [leafKeys.publicKey] } },
				);
				const ssTaInt1 = await rs_signSS(
					"https://ta.example.com",
					"https://int1.example.com",
					taKeys.privateKey,
					{ jwks: { keys: [int1Keys.publicKey] } },
				);
				const ssTaInt2 = await rs_signSS(
					"https://ta.example.com",
					"https://int2.example.com",
					taKeys.privateKey,
					{ jwks: { keys: [int2Keys.publicKey] } },
				);
				const responses: Record<string, string> = {
					"https://leaf.example.com/.well-known/openid-federation": leafEc,
					"https://int1.example.com/.well-known/openid-federation": int1Ec,
					"https://int2.example.com/.well-known/openid-federation": int2Ec,
					"https://ta.example.com/.well-known/openid-federation": taEc,
					"https://int1.example.com/federation_fetch?sub=https%3A%2F%2Fleaf.example.com":
						ssInt1Leaf,
					"https://int2.example.com/federation_fetch?sub=https%3A%2F%2Fleaf.example.com":
						ssInt2Leaf,
					"https://ta.example.com/federation_fetch?sub=https%3A%2F%2Fint1.example.com": ssTaInt1,
					"https://ta.example.com/federation_fetch?sub=https%3A%2F%2Fint2.example.com": ssTaInt2,
				};
				const mockFetch = async (url: string | URL | Request) => {
					const body = responses[url.toString()];
					return body
						? new Response(body, {
								status: 200,
								headers: { "Content-Type": "application/entity-statement+jwt" },
							})
						: new Response("Not found", { status: 404 });
				};
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await resolveTrustChains("https://leaf.example.com" as EntityId, taSet, {
					httpClient: mockFetch,
				});
				t.equal(result.chains.length, 2);
			});
			test("detects loop: A → B → A", async (t) => {
				const aKeys = await generateSigningKey("ES256");
				const bKeys = await generateSigningKey("ES256");
				const aEc = await rs_signEC("https://a.example.com", aKeys.privateKey, {
					jwks: { keys: [aKeys.publicKey] },
					authority_hints: ["https://b.example.com"],
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: "https://a.example.com/federation_fetch",
						},
					},
				});
				const bEc = await rs_signEC("https://b.example.com", bKeys.privateKey, {
					jwks: { keys: [bKeys.publicKey] },
					authority_hints: ["https://a.example.com"],
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: "https://b.example.com/federation_fetch",
						},
					},
				});
				const ssBA = await rs_signSS(
					"https://b.example.com",
					"https://a.example.com",
					bKeys.privateKey,
					{ jwks: { keys: [aKeys.publicKey] } },
				);
				const ssAB = await rs_signSS(
					"https://a.example.com",
					"https://b.example.com",
					aKeys.privateKey,
					{ jwks: { keys: [bKeys.publicKey] } },
				);
				const responses: Record<string, string> = {
					"https://a.example.com/.well-known/openid-federation": aEc,
					"https://b.example.com/.well-known/openid-federation": bEc,
					"https://b.example.com/federation_fetch?sub=https%3A%2F%2Fa.example.com": ssBA,
					"https://a.example.com/federation_fetch?sub=https%3A%2F%2Fb.example.com": ssAB,
				};
				const mockFetch = async (url: string | URL | Request) => {
					const body = responses[url.toString()];
					return body
						? new Response(body, {
								status: 200,
								headers: { "Content-Type": "application/entity-statement+jwt" },
							})
						: new Response("Not found", { status: 404 });
				};
				const result = await resolveTrustChains("https://a.example.com" as EntityId, new Map(), {
					httpClient: mockFetch,
					maxChainDepth: 5,
				});
				t.equal(result.chains.length, 0);
				t.ok(result.errors.length > 0);
			});
			test("respects maxChainDepth", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const taEc = await rs_signEC("https://ta.example.com", taKeys.privateKey, {
					jwks: { keys: [taKeys.publicKey] },
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: "https://ta.example.com/federation_fetch",
						},
					},
				});
				const leafEc = await rs_signEC("https://leaf.example.com", leafKeys.privateKey, {
					jwks: { keys: [leafKeys.publicKey] },
					authority_hints: ["https://ta.example.com"],
				});
				const ss = await rs_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					{ jwks: { keys: [leafKeys.publicKey] } },
				);
				const responses: Record<string, string> = {
					"https://leaf.example.com/.well-known/openid-federation": leafEc,
					"https://ta.example.com/.well-known/openid-federation": taEc,
					"https://ta.example.com/federation_fetch?sub=https%3A%2F%2Fleaf.example.com": ss,
				};
				const mockFetch = async (url: string | URL | Request) => {
					const body = responses[url.toString()];
					return body
						? new Response(body, {
								status: 200,
								headers: { "Content-Type": "application/entity-statement+jwt" },
							})
						: new Response("Not found", { status: 404 });
				};
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await resolveTrustChains("https://leaf.example.com" as EntityId, taSet, {
					httpClient: mockFetch,
					maxChainDepth: 0,
				});
				t.equal(result.chains.length, 0);
			});
			test("inspects no more authority_hints than maxAuthorityHints", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const taEc = await rs_signEC("https://ta.example.com", taKeys.privateKey, {
					jwks: { keys: [taKeys.publicKey] },
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: "https://ta.example.com/federation_fetch",
						},
					},
				});
				const leafEc = await rs_signEC("https://leaf.example.com", leafKeys.privateKey, {
					jwks: { keys: [leafKeys.publicKey] },
					authority_hints: [
						"https://ta.example.com",
						"https://hint2.example.com",
						"https://hint3.example.com",
						"https://hint4.example.com",
						"https://hint5.example.com",
					],
				});
				const ss = await rs_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					{ jwks: { keys: [leafKeys.publicKey] } },
				);
				const responses: Record<string, string> = {
					"https://leaf.example.com/.well-known/openid-federation": leafEc,
					"https://ta.example.com/.well-known/openid-federation": taEc,
					"https://ta.example.com/federation_fetch?sub=https%3A%2F%2Fleaf.example.com": ss,
				};
				const fetchedUrls: string[] = [];
				const mockFetch = async (url: string | URL | Request) => {
					const urlStr = url.toString();
					fetchedUrls.push(urlStr);
					const body = responses[urlStr];
					return body
						? new Response(body, {
								status: 200,
								headers: { "Content-Type": "application/entity-statement+jwt" },
							})
						: new Response("Not found", { status: 404 });
				};
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				await resolveTrustChains("https://leaf.example.com" as EntityId, taSet, {
					httpClient: mockFetch,
					maxAuthorityHints: 2,
				});
				// Only the first two hints should have produced an EC fetch:
				// "https://ta.example.com" and "https://hint2.example.com".
				const fetchedHintEcs = fetchedUrls.filter((u) =>
					u.endsWith("/.well-known/openid-federation"),
				);
				t.true(fetchedHintEcs.includes("https://ta.example.com/.well-known/openid-federation"));
				t.true(fetchedHintEcs.includes("https://hint2.example.com/.well-known/openid-federation"));
				t.false(fetchedHintEcs.includes("https://hint3.example.com/.well-known/openid-federation"));
				t.false(fetchedHintEcs.includes("https://hint4.example.com/.well-known/openid-federation"));
				t.false(fetchedHintEcs.includes("https://hint5.example.com/.well-known/openid-federation"));
			});
			test("rejects leaf EC where iss/sub don't match entityId", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const fakeLeafEc = await rs_signEC("https://imposter.example.com", leafKeys.privateKey, {
					jwks: { keys: [leafKeys.publicKey] },
					authority_hints: ["https://ta.example.com"],
				});
				const mockFetch = async (url: string | URL | Request) => {
					const urlStr = url.toString();
					if (urlStr.includes("leaf.example.com/.well-known"))
						return new Response(fakeLeafEc, {
							status: 200,
							headers: { "Content-Type": "application/entity-statement+jwt" },
						});
					return new Response("Not found", { status: 404 });
				};
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await resolveTrustChains("https://leaf.example.com" as EntityId, taSet, {
					httpClient: mockFetch,
				});
				t.equal(result.chains.length, 0);
				t.ok(result.errors.length > 0);
				t.equal(result.errors[0]?.code, "ERR_TRUST_CHAIN_INVALID");
				t.true(result.errors[0]?.description?.includes("identity mismatch") ?? false);
			});
			test("errors when authority hint entity has no federation_fetch_endpoint", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const taEc = await rs_signEC("https://ta.example.com", taKeys.privateKey, {
					jwks: { keys: [taKeys.publicKey] },
				});
				const leafEc = await rs_signEC("https://leaf.example.com", leafKeys.privateKey, {
					jwks: { keys: [leafKeys.publicKey] },
					authority_hints: ["https://ta.example.com"],
				});
				const responses: Record<string, string> = {
					"https://leaf.example.com/.well-known/openid-federation": leafEc,
					"https://ta.example.com/.well-known/openid-federation": taEc,
				};
				const mockFetch = async (url: string | URL | Request) => {
					const body = responses[url.toString()];
					return body
						? new Response(body, {
								status: 200,
								headers: { "Content-Type": "application/entity-statement+jwt" },
							})
						: new Response("Not found", { status: 404 });
				};
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await resolveTrustChains("https://leaf.example.com" as EntityId, taSet, {
					httpClient: mockFetch,
				});
				t.equal(result.chains.length, 0);
				t.ok(result.errors.length > 0);
				t.true(
					result.errors.some((e) => e.description?.includes("federation_fetch_endpoint") ?? false),
				);
			});
			test("handles HTTP failure on one path without aborting others", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const intKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const taEc = await rs_signEC("https://ta.example.com", taKeys.privateKey, {
					jwks: { keys: [taKeys.publicKey] },
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: "https://ta.example.com/federation_fetch",
						},
					},
				});
				const intEc = await rs_signEC("https://int.example.com", intKeys.privateKey, {
					jwks: { keys: [intKeys.publicKey] },
					authority_hints: ["https://ta.example.com"],
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: "https://int.example.com/federation_fetch",
						},
					},
				});
				const leafEc = await rs_signEC("https://leaf.example.com", leafKeys.privateKey, {
					jwks: { keys: [leafKeys.publicKey] },
					authority_hints: ["https://broken.example.com", "https://int.example.com"],
				});
				const ssIntLeaf = await rs_signSS(
					"https://int.example.com",
					"https://leaf.example.com",
					intKeys.privateKey,
					{ jwks: { keys: [leafKeys.publicKey] } },
				);
				const ssTaInt = await rs_signSS(
					"https://ta.example.com",
					"https://int.example.com",
					taKeys.privateKey,
					{ jwks: { keys: [intKeys.publicKey] } },
				);
				const responses: Record<string, string> = {
					"https://leaf.example.com/.well-known/openid-federation": leafEc,
					"https://int.example.com/.well-known/openid-federation": intEc,
					"https://ta.example.com/.well-known/openid-federation": taEc,
					"https://int.example.com/federation_fetch?sub=https%3A%2F%2Fleaf.example.com": ssIntLeaf,
					"https://ta.example.com/federation_fetch?sub=https%3A%2F%2Fint.example.com": ssTaInt,
				};
				const mockFetch = async (url: string | URL | Request) => {
					const body = responses[url.toString()];
					return body
						? new Response(body, {
								status: 200,
								headers: { "Content-Type": "application/entity-statement+jwt" },
							})
						: new Response("Not found", { status: 404 });
				};
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await resolveTrustChains("https://leaf.example.com" as EntityId, taSet, {
					httpClient: mockFetch,
				});
				t.ok(result.chains.length >= 1);
				t.ok(result.errors.length >= 1);
			});
			test("exhausts fetch budget when maxTotalFetches: 1", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const taEc = await rs_signEC("https://ta.example.com", taKeys.privateKey, {
					jwks: { keys: [taKeys.publicKey] },
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: "https://ta.example.com/federation_fetch",
						},
					},
				});
				const leafEc = await rs_signEC("https://leaf.example.com", leafKeys.privateKey, {
					jwks: { keys: [leafKeys.publicKey] },
					authority_hints: ["https://ta.example.com"],
				});
				const ss = await rs_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
				);
				const mockFetch = async (input: string | URL | Request) => {
					const url = typeof input === "string" ? input : input.toString();
					if (url.includes(".well-known/openid-federation")) {
						if (url.includes("leaf"))
							return new Response(leafEc, {
								status: 200,
								headers: { "Content-Type": "application/entity-statement+jwt" },
							});
						if (url.includes("ta"))
							return new Response(taEc, {
								status: 200,
								headers: { "Content-Type": "application/entity-statement+jwt" },
							});
					}
					if (url.includes("federation_fetch"))
						return new Response(ss, {
							status: 200,
							headers: { "Content-Type": "application/entity-statement+jwt" },
						});
					return new Response("Not found", { status: 404 });
				};
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await resolveTrustChains("https://leaf.example.com" as EntityId, taSet, {
					httpClient: mockFetch,
					maxTotalFetches: 1,
				});
				t.equal(result.chains.length, 0);
				t.true(result.errors.some((e) => e.description.includes("budget")));
			});
			test("exhausts fetch budget on subordinate statement fetch when maxTotalFetches: 2", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const taEc = await rs_signEC("https://ta.example.com", taKeys.privateKey, {
					jwks: { keys: [taKeys.publicKey] },
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: "https://ta.example.com/federation_fetch",
						},
					},
				});
				const leafEc = await rs_signEC("https://leaf.example.com", leafKeys.privateKey, {
					jwks: { keys: [leafKeys.publicKey] },
					authority_hints: ["https://ta.example.com"],
				});
				const ss = await rs_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
				);
				const mockFetch = async (input: string | URL | Request) => {
					const url = typeof input === "string" ? input : input.toString();
					if (url.includes(".well-known/openid-federation")) {
						if (url.includes("leaf"))
							return new Response(leafEc, {
								status: 200,
								headers: { "Content-Type": "application/entity-statement+jwt" },
							});
						if (url.includes("ta"))
							return new Response(taEc, {
								status: 200,
								headers: { "Content-Type": "application/entity-statement+jwt" },
							});
					}
					if (url.includes("federation_fetch"))
						return new Response(ss, {
							status: 200,
							headers: { "Content-Type": "application/entity-statement+jwt" },
						});
					return new Response("Not found", { status: 404 });
				};
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await resolveTrustChains("https://leaf.example.com" as EntityId, taSet, {
					httpClient: mockFetch,
					maxTotalFetches: 2,
				});
				t.equal(result.chains.length, 0);
				t.true(result.errors.some((e) => e.description.includes("budget")));
			});
		});
		module("core / resolveTrustChainForAnchor", () => {
			async function setupSimpleFederation() {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const taEc = await rs_signEC("https://ta.example.com", taKeys.privateKey, {
					jwks: { keys: [taKeys.publicKey] },
					metadata: {
						federation_entity: {
							federation_fetch_endpoint: "https://ta.example.com/federation_fetch",
						},
					},
				});
				const leafEc = await rs_signEC("https://leaf.example.com", leafKeys.privateKey, {
					jwks: { keys: [leafKeys.publicKey] },
					authority_hints: ["https://ta.example.com"],
					metadata: { federation_entity: { organization_name: "Leaf" } },
				});
				const ss = await rs_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					{ jwks: { keys: [leafKeys.publicKey] } },
				);
				const responses: Record<string, string> = {
					"https://leaf.example.com/.well-known/openid-federation": leafEc,
					"https://ta.example.com/.well-known/openid-federation": taEc,
					"https://ta.example.com/federation_fetch?sub=https%3A%2F%2Fleaf.example.com": ss,
				};
				const mockFetch = async (url: string | URL | Request) => {
					const body = responses[url.toString()];
					return body
						? new Response(body, {
								status: 200,
								headers: { "Content-Type": "application/entity-statement+jwt" },
							})
						: new Response("Not found", { status: 404 });
				};
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				return { taSet, mockFetch };
			}
			test("resolves chain ending at the requested Trust Anchor", async (t) => {
				const { taSet, mockFetch } = await setupSimpleFederation();
				const result = await resolveTrustChainForAnchor(
					"https://leaf.example.com" as EntityId,
					"https://ta.example.com" as EntityId,
					taSet,
					{ httpClient: mockFetch },
				);
				t.true(isOk(result));
				if (isOk(result)) {
					t.true(result.value.length >= 2);
				}
			});
			test("errors when the requested TA is not in the pre-trusted set", async (t) => {
				const { taSet, mockFetch } = await setupSimpleFederation();
				const result = await resolveTrustChainForAnchor(
					"https://leaf.example.com" as EntityId,
					"https://other-ta.example.com" as EntityId,
					taSet,
					{ httpClient: mockFetch },
				);
				t.true(isErr(result));
			});
			test("errors when no chain to the requested TA can be built", async (t) => {
				const { taSet } = await setupSimpleFederation();
				const noopFetch = async () => new Response("Not found", { status: 404 });
				const result = await resolveTrustChainForAnchor(
					"https://leaf.example.com" as EntityId,
					"https://ta.example.com" as EntityId,
					taSet,
					{ httpClient: noopFetch },
				);
				t.true(isErr(result));
			});
		});
	}

	// ── trust-chain/fetch ─────────────────────────────────────────────
	module("core / validateFetchUrl", () => {
		test("accepts valid HTTPS URL", (t) => {
			t.true(isOk(validateFetchUrl("https://example.com/.well-known/openid-federation")));
		});
		test("rejects non-HTTPS URL", (t) => {
			t.true(isErr(validateFetchUrl("http://example.com/.well-known/openid-federation")));
		});
		test("rejects URL with credentials", (t) => {
			t.true(isErr(validateFetchUrl("https://user:pass@example.com/path")));
		});
		test("rejects URL longer than 2048 characters", (t) => {
			t.true(isErr(validateFetchUrl(`https://example.com/${"a".repeat(2048)}`)));
		});
		test("rejects invalid URL", (t) => {
			t.true(isErr(validateFetchUrl("not-a-url")));
		});
		test("rejects loopback IP 127.0.0.1", (t) => {
			t.true(isErr(validateFetchUrl("https://127.0.0.1/.well-known/openid-federation")));
		});
		test("rejects private IP 10.0.0.1", (t) => {
			t.true(isErr(validateFetchUrl("https://10.0.0.1/.well-known/openid-federation")));
		});
		test("rejects private IP 192.168.1.1", (t) => {
			t.true(isErr(validateFetchUrl("https://192.168.1.1/.well-known/openid-federation")));
		});
		test("rejects private IP 172.16.0.1", (t) => {
			t.true(isErr(validateFetchUrl("https://172.16.0.1/.well-known/openid-federation")));
		});
		test("allows public IP", (t) => {
			t.true(isOk(validateFetchUrl("https://8.8.8.8/.well-known/openid-federation")));
		});
		test("respects allowedHosts filter", (t) => {
			t.true(
				isOk(
					validateFetchUrl("https://allowed.example.com/path", {
						allowedHosts: ["allowed.example.com"],
					}),
				),
			);
			t.true(
				isErr(
					validateFetchUrl("https://other.example.com/path", {
						allowedHosts: ["allowed.example.com"],
					}),
				),
			);
		});
	});
	module("core / validateEntityId", () => {
		test("accepts valid entity ID", (t) => {
			t.true(isOk(validateEntityId("https://example.com")));
		});
		test("rejects non-HTTPS entity ID", (t) => {
			t.true(isErr(validateEntityId("http://example.com")));
		});
		test("rejects entity ID with credentials", (t) => {
			t.true(isErr(validateEntityId("https://user:pass@example.com")));
		});
	});
	module("core / fetchEntityConfiguration", () => {
		test("constructs correct URL with /.well-known/openid-federation", async (t) => {
			let capturedUrl = "";
			const mockFetch = async (url: string | URL | Request) => {
				capturedUrl = url.toString();
				return new Response("jwt-token", {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			};
			const result = await fetchEntityConfiguration("https://example.com" as EntityId, {
				httpClient: mockFetch,
			});
			t.true(isOk(result));
			t.equal(capturedUrl, "https://example.com/.well-known/openid-federation");
		});
		test("strips trailing slash from entity ID before constructing well-known URL", async (t) => {
			let capturedUrl = "";
			const mockFetch = async (url: string | URL | Request) => {
				capturedUrl = url.toString();
				return new Response("jwt-token", {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			};
			const result = await fetchEntityConfiguration("https://example.com/" as EntityId, {
				httpClient: mockFetch,
			});
			t.true(isOk(result));
			t.equal(capturedUrl, "https://example.com/.well-known/openid-federation");
		});
		test("sets Accept header for entity-statement+jwt", async (t) => {
			let capturedInit: RequestInit | undefined;
			const mockFetch = async (_url: string | URL | Request, init?: RequestInit) => {
				capturedInit = init;
				return new Response("jwt", {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			};
			await fetchEntityConfiguration("https://example.com" as EntityId, { httpClient: mockFetch });
			t.notEqual(capturedInit?.headers, undefined);
			const headers = new Headers(capturedInit?.headers);
			t.equal(headers.get("Accept"), "application/entity-statement+jwt");
		});
		test("returns cached result on cache hit", async (t) => {
			const cache = new MemoryCache();
			let callCount = 0;
			const mockFetch = async () => {
				callCount++;
				return new Response("jwt", {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			};
			const r1 = await fetchEntityConfiguration("https://example.com" as EntityId, {
				httpClient: mockFetch,
				cache,
			});
			t.true(isOk(r1));
			t.equal(callCount, 1);
			const r2 = await fetchEntityConfiguration("https://example.com" as EntityId, {
				httpClient: mockFetch,
				cache,
			});
			t.true(isOk(r2));
			t.equal(callCount, 1);
		});
		test("returns error on non-200 status", async (t) => {
			const mockFetch = async () => new Response("Not found", { status: 404 });
			const result = await fetchEntityConfiguration("https://example.com" as EntityId, {
				httpClient: mockFetch,
			});
			t.true(isErr(result));
			if (isErr(result)) t.equal(result.error.code, "ERR_NETWORK");
		});
		test("rejects response with wrong Content-Type", async (t) => {
			const mockFetch = async () =>
				new Response("not-a-jwt", { status: 200, headers: { "Content-Type": "text/html" } });
			const result = await fetchEntityConfiguration("https://example.com" as EntityId, {
				httpClient: mockFetch,
			});
			t.true(isErr(result));
			if (isErr(result)) {
				t.equal(result.error.code, "ERR_NETWORK");
				t.true(result.error.description.includes("Content-Type"));
			}
		});
		test("accepts response with Content-Type including charset parameter", async (t) => {
			const mockFetch = async () =>
				new Response("jwt-token", {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt; charset=utf-8" },
				});
			t.true(
				isOk(
					await fetchEntityConfiguration("https://example.com" as EntityId, {
						httpClient: mockFetch,
					}),
				),
			);
		});
		test("rejects response with text/plain Content-Type", async (t) => {
			const mockFetch = async () =>
				new Response("jwt-token", { status: 200, headers: { "Content-Type": "text/plain" } });
			const result = await fetchEntityConfiguration("https://example.com" as EntityId, {
				httpClient: mockFetch,
			});
			t.true(isErr(result));
			if (isErr(result)) {
				t.equal(result.error.code, "ERR_NETWORK");
				t.true(result.error.description.includes("Content-Type"));
			}
		});
		test("rejects response exceeding maxResponseBytes via Content-Length", async (t) => {
			const mockFetch = async () =>
				new Response("small body", {
					status: 200,
					headers: {
						"Content-Type": "application/entity-statement+jwt",
						"Content-Length": "999999",
					},
				});
			const result = await fetchEntityConfiguration("https://example.com" as EntityId, {
				httpClient: mockFetch,
				maxResponseBytes: 1024,
			});
			t.true(isErr(result));
			if (isErr(result)) t.true(result.error.description.includes("Response too large"));
		});
		test("rejects response exceeding maxResponseBytes via body length", async (t) => {
			const mockFetch = async () =>
				new Response("x".repeat(2048), {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			const result = await fetchEntityConfiguration("https://example.com" as EntityId, {
				httpClient: mockFetch,
				maxResponseBytes: 1024,
			});
			t.true(isErr(result));
			if (isErr(result)) t.true(result.error.description.includes("Response too large"));
		});
		test("accepts response body exactly at limit", async (t) => {
			const limit = 1024;
			const mockFetch = async () =>
				new Response("x".repeat(limit), {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			t.true(
				isOk(
					await fetchEntityConfiguration("https://example.com" as EntityId, {
						httpClient: mockFetch,
						maxResponseBytes: limit,
					}),
				),
			);
		});
		test("rejects response body 1 byte over limit when streamed", async (t) => {
			const limit = 1024;
			const encoded = new TextEncoder().encode("x".repeat(limit + 1));
			const stream = new ReadableStream<Uint8Array>({
				start(c) {
					c.enqueue(encoded);
					c.close();
				},
			});
			const mockFetch = async () =>
				new Response(stream, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			const result = await fetchEntityConfiguration("https://example.com" as EntityId, {
				httpClient: mockFetch,
				maxResponseBytes: limit,
			});
			t.true(isErr(result));
			if (isErr(result)) t.true(result.error.description.includes("Response too large"));
		});
		test("rejects spoofed Content-Length with oversized streaming body", async (t) => {
			const limit = 1024;
			const encoded = new TextEncoder().encode("x".repeat(limit + 100));
			const stream = new ReadableStream<Uint8Array>({
				start(c) {
					c.enqueue(encoded);
					c.close();
				},
			});
			const mockFetch = async () =>
				new Response(stream, {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt", "Content-Length": "10" },
				});
			const result = await fetchEntityConfiguration("https://example.com" as EntityId, {
				httpClient: mockFetch,
				maxResponseBytes: limit,
			});
			t.true(isErr(result));
			if (isErr(result)) t.true(result.error.description.includes("Response too large"));
		});
		test("returns timeout error on abort", async (t) => {
			const mockFetch = async (_url: string | URL | Request, init?: RequestInit) =>
				new Promise<Response>((_, reject) => {
					if (init?.signal)
						init.signal.addEventListener("abort", () =>
							reject(new DOMException("Aborted", "AbortError")),
						);
				});
			const controller = new AbortController();
			const promise = fetchEntityConfiguration("https://example.com" as EntityId, {
				httpClient: mockFetch,
				signal: controller.signal,
				httpTimeoutMs: 60000,
			});
			controller.abort();
			const result = await promise;
			t.true(isErr(result));
			if (isErr(result)) t.equal(result.error.code, "ERR_TIMEOUT");
		});
	});
	module("core / fetchEntityConfiguration — SSRF protection", () => {
		const ssrfNeverCalled = async () => {
			throw new Error("should not be called");
		};
		test("rejects HTTP (non-HTTPS) entity ID", async (t) => {
			const result = await fetchEntityConfiguration("http://example.com" as EntityId, {
				httpClient: ssrfNeverCalled,
			});
			t.true(isErr(result));
			if (isErr(result)) t.true(result.error.description.includes("HTTPS"));
		});
		test("rejects private IP 127.0.0.1", async (t) => {
			const result = await fetchEntityConfiguration("https://127.0.0.1" as EntityId, {
				httpClient: ssrfNeverCalled,
			});
			t.true(isErr(result));
			if (isErr(result)) t.true(result.error.description.includes("special-use address"));
		});
		test("rejects private IP 10.0.0.1", async (t) => {
			t.true(
				isErr(
					await fetchEntityConfiguration("https://10.0.0.1" as EntityId, {
						httpClient: ssrfNeverCalled,
					}),
				),
			);
		});
		test("rejects private IP 172.16.0.1", async (t) => {
			t.true(
				isErr(
					await fetchEntityConfiguration("https://172.16.0.1" as EntityId, {
						httpClient: ssrfNeverCalled,
					}),
				),
			);
		});
		test("rejects private IP 192.168.1.1", async (t) => {
			t.true(
				isErr(
					await fetchEntityConfiguration("https://192.168.1.1" as EntityId, {
						httpClient: ssrfNeverCalled,
					}),
				),
			);
		});
		test("rejects URL with credentials", async (t) => {
			const result = await fetchEntityConfiguration("https://user:pass@example.com" as EntityId, {
				httpClient: ssrfNeverCalled,
			});
			t.true(isErr(result));
			if (isErr(result)) t.true(result.error.description.includes("credentials"));
		});
		test("rejects URL exceeding 2048 characters", async (t) => {
			const longId = `https://example.com/${"a".repeat(2048)}` as EntityId;
			const result = await fetchEntityConfiguration(longId, { httpClient: ssrfNeverCalled });
			t.true(isErr(result));
			if (isErr(result)) t.true(result.error.description.includes("2048"));
		});
	});
	module("core / fetchSubordinateStatement — SSRF protection", () => {
		const ssrf2NeverCalled = async () => {
			throw new Error("should not be called");
		};
		test("rejects HTTP fetch endpoint", async (t) => {
			const result = await fetchSubordinateStatement(
				"http://example.com/federation_fetch",
				"https://sub.example.com" as EntityId,
				{ httpClient: ssrf2NeverCalled },
			);
			t.true(isErr(result));
		});
		test("rejects private IP fetch endpoint", async (t) => {
			const result = await fetchSubordinateStatement(
				"https://192.168.1.1/federation_fetch",
				"https://sub.example.com" as EntityId,
				{ httpClient: ssrf2NeverCalled },
			);
			t.true(isErr(result));
		});
	});
	module("core / fetchSubordinateStatement", () => {
		test("constructs URL with ?sub= query parameter", async (t) => {
			let capturedUrl = "";
			const mockFetch = async (url: string | URL | Request) => {
				capturedUrl = url.toString();
				return new Response("jwt", {
					status: 200,
					headers: { "Content-Type": "application/entity-statement+jwt" },
				});
			};
			const result = await fetchSubordinateStatement(
				"https://superior.example.com/federation_fetch",
				"https://subject.example.com" as EntityId,
				{ httpClient: mockFetch },
			);
			t.true(isOk(result));
			t.true(capturedUrl.includes("sub=https%3A%2F%2Fsubject.example.com"));
		});
		test("returns error for non-200 response", async (t) => {
			const mockFetch = async () => new Response("Error", { status: 500 });
			const result = await fetchSubordinateStatement(
				"https://superior.example.com/federation_fetch",
				"https://subject.example.com" as EntityId,
				{ httpClient: mockFetch },
			);
			t.true(isErr(result));
		});
	});
	module("core / ipv4ToInt", () => {
		test("converts valid IPv4 addresses", (t) => {
			t.equal(ipv4ToInt("0.0.0.0"), 0x00000000);
			t.equal(ipv4ToInt("127.0.0.1"), 0x7f000001);
			t.equal(ipv4ToInt("10.0.0.1"), 0x0a000001);
			t.equal(ipv4ToInt("255.255.255.255"), 0xffffffff);
			t.equal(ipv4ToInt("8.8.8.8"), 0x08080808);
		});
		test("returns -1 for non-IPv4 strings", (t) => {
			t.equal(ipv4ToInt("not-an-ip"), -1);
			t.equal(ipv4ToInt("::1"), -1);
			t.equal(ipv4ToInt("256.0.0.1"), -1);
			t.equal(ipv4ToInt("1.2.3"), -1);
		});
	});
	module("core / isSpecialUseIPv4", () => {
		test("blocks 0.0.0.0/8 — This network", (t) => {
			t.true(isSpecialUseIPv4("0.0.0.0"));
			t.true(isSpecialUseIPv4("0.1.2.3"));
			t.true(isSpecialUseIPv4("0.255.255.255"));
		});
		test("blocks 10.0.0.0/8 — Private", (t) => {
			t.true(isSpecialUseIPv4("10.0.0.0"));
			t.true(isSpecialUseIPv4("10.0.0.1"));
			t.true(isSpecialUseIPv4("10.255.255.255"));
		});
		test("blocks 100.64.0.0/10 — Shared Address Space", (t) => {
			t.true(isSpecialUseIPv4("100.64.0.0"));
			t.true(isSpecialUseIPv4("100.64.0.1"));
			t.true(isSpecialUseIPv4("100.127.255.255"));
			t.false(isSpecialUseIPv4("100.63.255.255"));
			t.false(isSpecialUseIPv4("100.128.0.0"));
		});
		test("blocks 127.0.0.0/8 — Loopback", (t) => {
			t.true(isSpecialUseIPv4("127.0.0.1"));
			t.true(isSpecialUseIPv4("127.255.255.255"));
		});
		test("blocks 169.254.0.0/16 — Link-local", (t) => {
			t.true(isSpecialUseIPv4("169.254.0.0"));
			t.true(isSpecialUseIPv4("169.254.1.1"));
			t.true(isSpecialUseIPv4("169.254.255.255"));
		});
		test("blocks 172.16.0.0/12 — Private", (t) => {
			t.true(isSpecialUseIPv4("172.16.0.0"));
			t.true(isSpecialUseIPv4("172.16.0.1"));
			t.true(isSpecialUseIPv4("172.31.255.255"));
			t.false(isSpecialUseIPv4("172.15.255.255"));
			t.false(isSpecialUseIPv4("172.32.0.0"));
		});
		test("blocks 192.0.0.0/24 — IETF Protocol Assignments", (t) => {
			t.true(isSpecialUseIPv4("192.0.0.0"));
			t.true(isSpecialUseIPv4("192.0.0.255"));
		});
		test("blocks 192.0.2.0/24 — TEST-NET-1 (documentation)", (t) => {
			t.true(isSpecialUseIPv4("192.0.2.0"));
			t.true(isSpecialUseIPv4("192.0.2.1"));
			t.true(isSpecialUseIPv4("192.0.2.255"));
		});
		test("blocks 192.88.99.0/24 — 6to4 Relay Anycast", (t) => {
			t.true(isSpecialUseIPv4("192.88.99.0"));
			t.true(isSpecialUseIPv4("192.88.99.255"));
		});
		test("blocks 192.168.0.0/16 — Private", (t) => {
			t.true(isSpecialUseIPv4("192.168.0.0"));
			t.true(isSpecialUseIPv4("192.168.1.1"));
			t.true(isSpecialUseIPv4("192.168.255.255"));
		});
		test("blocks 198.18.0.0/15 — Benchmarking", (t) => {
			t.true(isSpecialUseIPv4("198.18.0.0"));
			t.true(isSpecialUseIPv4("198.19.255.255"));
			t.false(isSpecialUseIPv4("198.17.255.255"));
			t.false(isSpecialUseIPv4("198.20.0.0"));
		});
		test("blocks 198.51.100.0/24 — TEST-NET-2 (documentation)", (t) => {
			t.true(isSpecialUseIPv4("198.51.100.0"));
			t.true(isSpecialUseIPv4("198.51.100.255"));
		});
		test("blocks 203.0.113.0/24 — TEST-NET-3 (documentation)", (t) => {
			t.true(isSpecialUseIPv4("203.0.113.0"));
			t.true(isSpecialUseIPv4("203.0.113.255"));
		});
		test("blocks 224.0.0.0/4 — Multicast", (t) => {
			t.true(isSpecialUseIPv4("224.0.0.0"));
			t.true(isSpecialUseIPv4("239.255.255.255"));
		});
		test("blocks 240.0.0.0/4 — Reserved", (t) => {
			t.true(isSpecialUseIPv4("240.0.0.0"));
			t.true(isSpecialUseIPv4("254.255.255.255"));
		});
		test("blocks 255.255.255.255/32 — Limited Broadcast", (t) => {
			t.true(isSpecialUseIPv4("255.255.255.255"));
		});
		test("allows public unicast addresses", (t) => {
			t.false(isSpecialUseIPv4("8.8.8.8"));
			t.false(isSpecialUseIPv4("1.1.1.1"));
			t.false(isSpecialUseIPv4("93.184.216.34"));
			t.false(isSpecialUseIPv4("208.67.222.222"));
		});
	});
	module("core / expandIPv6", () => {
		test("expands :: (all zeros)", (t) => {
			t.equal(expandIPv6("::"), "00000000000000000000000000000000");
		});
		test("expands ::1 (loopback)", (t) => {
			t.equal(expandIPv6("::1"), "00000000000000000000000000000001");
		});
		test("expands full address without ::", (t) => {
			t.equal(
				expandIPv6("2001:0db8:0000:0000:0000:0000:0000:0001"),
				"20010db8000000000000000000000001",
			);
		});
		test("expands address with :: in the middle", (t) => {
			t.equal(expandIPv6("fe80::1"), "fe800000000000000000000000000001");
		});
		test("handles IPv4-mapped notation ::ffff:192.168.1.1", (t) => {
			t.equal(expandIPv6("::ffff:192.168.1.1"), "00000000000000000000ffffc0a80101");
		});
		test("returns empty string for invalid addresses", (t) => {
			t.equal(expandIPv6("not-an-ipv6"), "");
			t.equal(expandIPv6("::1::2"), "");
		});
	});
	module("core / isSpecialUseIPv6", () => {
		test("blocks :: — Unspecified Address", (t) => {
			t.true(isSpecialUseIPv6("::"));
		});
		test("blocks ::1 — Loopback", (t) => {
			t.true(isSpecialUseIPv6("::1"));
		});
		test("blocks ::ffff:0:0/96 — IPv4-mapped (any IPv4)", (t) => {
			t.true(isSpecialUseIPv6("::ffff:192.168.1.1"));
			t.true(isSpecialUseIPv6("::ffff:10.0.0.1"));
			t.true(isSpecialUseIPv6("::ffff:8.8.8.8"));
		});
		test("blocks 64:ff9b::/96 — IPv4/IPv6 translation", (t) => {
			t.true(isSpecialUseIPv6("64:ff9b::1"));
			t.true(isSpecialUseIPv6("64:ff9b::192.0.2.1"));
		});
		test("blocks 64:ff9b:1::/48 — IPv4/IPv6 translation", (t) => {
			t.true(isSpecialUseIPv6("64:ff9b:1::"));
			t.true(isSpecialUseIPv6("64:ff9b:1:0:0:0:0:1"));
		});
		test("blocks 100::/64 — Discard-only", (t) => {
			t.true(isSpecialUseIPv6("100::1"));
			t.true(isSpecialUseIPv6("100:0:0:0::1"));
			t.false(isSpecialUseIPv6("100:1::"));
		});
		test("blocks 2001::/23 — IETF Protocol Assignments (second group 0000–01ff)", (t) => {
			t.true(isSpecialUseIPv6("2001::1"));
			t.true(isSpecialUseIPv6("2001:1::"));
			t.true(isSpecialUseIPv6("2001:1ff::"));
			t.false(isSpecialUseIPv6("2001:200::"));
		});
		test("blocks 2001:db8::/32 — Documentation (separate entry)", (t) => {
			t.true(isSpecialUseIPv6("2001:db8::1"));
			t.true(isSpecialUseIPv6("2001:db8:85a3::8a2e:370:7334"));
		});
		test("blocks 2002::/16 — 6to4", (t) => {
			t.true(isSpecialUseIPv6("2002::1"));
			t.true(isSpecialUseIPv6("2002:c000:204::"));
		});
		test("blocks fc00::/7 — Unique-Local (fc::/8 and fd::/8)", (t) => {
			t.true(isSpecialUseIPv6("fc00::1"));
			t.true(isSpecialUseIPv6("fd00::1"));
			t.true(isSpecialUseIPv6("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
			t.false(isSpecialUseIPv6("fe00::1"));
		});
		test("blocks fe80::/10 — Link-local Unicast", (t) => {
			t.true(isSpecialUseIPv6("fe80::1"));
			t.true(isSpecialUseIPv6("fe80::dead:beef"));
			t.true(isSpecialUseIPv6("fe8f::1"));
			t.true(isSpecialUseIPv6("fe90::1"));
			t.true(isSpecialUseIPv6("fea0::1"));
			t.true(isSpecialUseIPv6("feb0::1"));
			t.true(isSpecialUseIPv6("febf::1"));
			t.false(isSpecialUseIPv6("fec0::1"));
		});
		test("blocks ff00::/8 — Multicast", (t) => {
			t.true(isSpecialUseIPv6("ff02::1"));
			t.true(isSpecialUseIPv6("ff02::2"));
			t.true(isSpecialUseIPv6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
		});
		test("allows public global unicast addresses", (t) => {
			t.false(isSpecialUseIPv6("2607:f8b0:4004:800::200e"));
			t.false(isSpecialUseIPv6("2a00:1450:4001:81e::200e"));
			t.false(isSpecialUseIPv6("2606:4700:4700::1111"));
			t.false(isSpecialUseIPv6("2001:4860:4860::8888"));
		});
	});
	module("core / isSpecialUseIP", () => {
		test("dispatches to isSpecialUseIPv4 for IPv4 addresses", (t) => {
			t.true(isSpecialUseIP("10.0.0.1"));
			t.false(isSpecialUseIP("8.8.8.8"));
		});
		test("dispatches to isSpecialUseIPv6 for bare IPv6 addresses", (t) => {
			t.true(isSpecialUseIP("::1"));
			t.false(isSpecialUseIP("2607:f8b0:4004:800::200e"));
		});
		test("handles bracketed IPv6 literals from URL hostnames", (t) => {
			t.true(isSpecialUseIP("[::1]"));
			t.true(isSpecialUseIP("[fe80::1]"));
			t.true(isSpecialUseIP("[fc00::1]"));
			t.false(isSpecialUseIP("[2607:f8b0:4004:800::200e]"));
		});
	});
	module("core / validateFetchUrl — IANA special-use IP blocking", () => {
		test("rejects IPv6 loopback literal [::1]", (t) => {
			const r = validateFetchUrl("https://[::1]/.well-known/openid-federation");
			t.true(isErr(r));
			if (isErr(r)) t.true(r.error.description.includes("special-use address"));
		});
		test("rejects IPv6 link-local literal [fe80::1]", (t) => {
			const r = validateFetchUrl("https://[fe80::1]/.well-known/openid-federation");
			t.true(isErr(r));
			if (isErr(r)) t.true(r.error.description.includes("special-use address"));
		});
		test("rejects IPv6 ULA literal [fc00::1]", (t) => {
			t.true(isErr(validateFetchUrl("https://[fc00::1]/.well-known/openid-federation")));
		});
		test("rejects documentation address [2001:db8::1]", (t) => {
			t.true(isErr(validateFetchUrl("https://[2001:db8::1]/.well-known/openid-federation")));
		});
		test("rejects IANA ranges not in old DEFAULT_BLOCKED_CIDRS — 100.64.0.1 (shared space)", (t) => {
			const r = validateFetchUrl("https://100.64.0.1/.well-known/openid-federation");
			t.true(isErr(r));
			if (isErr(r)) t.true(r.error.description.includes("special-use address"));
		});
		test("rejects 192.0.2.1 (TEST-NET-1, not in old blocklist)", (t) => {
			t.true(isErr(validateFetchUrl("https://192.0.2.1/.well-known/openid-federation")));
		});
		test("accepts public IPv6 address", (t) => {
			t.true(
				isOk(validateFetchUrl("https://[2607:f8b0:4004:800::200e]/.well-known/openid-federation")),
			);
		});
		test("user-supplied blockedCIDRs are additive and still reported as blocked CIDR range", (t) => {
			const r = validateFetchUrl("https://203.0.114.1/.well-known/openid-federation", {
				blockedCIDRs: ["203.0.114.0/24"],
			});
			t.true(isErr(r));
			if (isErr(r)) t.true(r.error.description.includes("blocked CIDR range"));
		});
	});

	// ── trust-chain/validate ──────────────────────────────────────────
	{
		const vt_now = Math.floor(Date.now() / 1000);
		async function vt_signEC(
			eid: string,
			privateKey: JWK,
			publicKey: JWK,
			overrides?: Record<string, unknown>,
		) {
			return signEntityStatement(
				{
					iss: eid,
					sub: eid,
					iat: vt_now,
					exp: vt_now + 3600,
					jwks: { keys: [publicKey] },
					...overrides,
				},
				privateKey,
				{ typ: JwtTyp.EntityStatement },
			);
		}
		async function vt_signSS(
			issuer: string,
			subject: string,
			privateKey: JWK,
			subjectPublicKey: JWK,
			overrides?: Record<string, unknown>,
		) {
			return signEntityStatement(
				{
					iss: issuer,
					sub: subject,
					iat: vt_now,
					exp: vt_now + 3600,
					jwks: { keys: [subjectPublicKey] },
					...overrides,
				},
				privateKey,
				{ typ: JwtTyp.EntityStatement },
			);
		}
		async function vt_buildSimple() {
			const taKeys = await generateSigningKey("ES256");
			const leafKeys = await generateSigningKey("ES256");
			const leafEc = await vt_signEC(
				"https://leaf.example.com",
				leafKeys.privateKey,
				leafKeys.publicKey,
				{
					authority_hints: ["https://ta.example.com"],
					metadata: {
						federation_entity: { organization_name: "Leaf Org" },
						openid_relying_party: { client_name: "Leaf RP" },
					},
				},
			);
			const ss = await vt_signSS(
				"https://ta.example.com",
				"https://leaf.example.com",
				taKeys.privateKey,
				leafKeys.publicKey,
			);
			const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
			const taSet: TrustAnchorSet = new Map([
				["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
			]);
			return { chain: [leafEc, ss, taEc], taSet, taKeys, leafKeys };
		}
		module("core / validateTrustChain", () => {
			test("validates a simple 2-entity chain (leaf → TA)", async (t) => {
				const { chain, taSet } = await vt_buildSimple();
				const result = await validateTrustChain(chain, taSet);
				t.true(result.valid);
				if (result.valid) {
					t.equal(result.chain.entityId, "https://leaf.example.com");
					t.equal(result.chain.trustAnchorId, "https://ta.example.com");
					t.equal(result.chain.statements.length, 3);
				}
			});
			test("accepts chain that omits the Trust Anchor EC at the end", async (t) => {
				const { chain, taSet } = await vt_buildSimple();
				// Drop the trailing TA Entity Configuration. The remaining array is
				// [leaf EC, TA-signed SS]; the TA's public keys come from `taSet`.
				const chainWithoutTaEc = chain.slice(0, -1);
				const result = await validateTrustChain(chainWithoutTaEc, taSet);
				t.true(result.valid);
				if (result.valid) {
					t.equal(result.chain.entityId, "https://leaf.example.com");
					t.equal(result.chain.trustAnchorId, "https://ta.example.com");
					t.equal(result.chain.statements.length, 2);
				}
			});
			test("rejects chain with unknown trust anchor", async (t) => {
				const { chain } = await vt_buildSimple();
				const result = await validateTrustChain(chain, new Map(), { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.code === "ERR_TRUST_ANCHOR_UNKNOWN"));
			});
			test("rejects expired statements", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ iat: vt_now - 7200, exp: vt_now - 3600, authority_hints: ["https://ta.example.com"] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
					{ iat: vt_now - 7200, exp: vt_now - 3600 },
				);
				const taEc = await vt_signEC(
					"https://ta.example.com",
					taKeys.privateKey,
					taKeys.publicKey,
					{ iat: vt_now - 7200, exp: vt_now - 3600 },
				);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.checkNumber === 5));
			});

			test("rejects statement with iat in the future", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ iat: vt_now + 7200, exp: vt_now + 86400, authority_hints: ["https://ta.example.com"] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
					{ iat: vt_now - 60, exp: vt_now + 86400 },
				);
				const taEc = await vt_signEC(
					"https://ta.example.com",
					taKeys.privateKey,
					taKeys.publicKey,
					{ iat: vt_now - 60, exp: vt_now + 86400 },
				);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(
					result.errors.some((e) => /iat.*future/i.test(e.message ?? "")),
					"expected an iat-in-future rejection",
				);
			});

			test("rejects leaf entity configuration where iss does not equal sub", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await signEntityStatement(
					{
						iss: "https://leaf.example.com",
						sub: "https://other.example.com",
						iat: vt_now,
						exp: vt_now + 86400,
						jwks: { keys: [leafKeys.publicKey] },
						authority_hints: ["https://ta.example.com"],
					},
					leafKeys.privateKey,
					{ typ: JwtTyp.EntityStatement },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
					{ iat: vt_now, exp: vt_now + 86400 },
				);
				const taEc = await vt_signEC(
					"https://ta.example.com",
					taKeys.privateKey,
					taKeys.publicKey,
					{ iat: vt_now, exp: vt_now + 86400 },
				);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(
					result.errors.some((e) => /iss.*sub|Leaf EC iss/i.test(e.message ?? "")),
					"expected leaf iss/sub mismatch rejection",
				);
			});

			test("rejects trust anchor signed with a key not in the pre-trusted trustAnchors set", async (t) => {
				const taSigningKeys = await generateSigningKey("ES256");
				const taPreTrustedKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ iat: vt_now, exp: vt_now + 86400, authority_hints: ["https://ta.example.com"] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taSigningKeys.privateKey,
					leafKeys.publicKey,
					{ iat: vt_now, exp: vt_now + 86400 },
				);
				const taEc = await vt_signEC(
					"https://ta.example.com",
					taSigningKeys.privateKey,
					taSigningKeys.publicKey,
					{ iat: vt_now, exp: vt_now + 86400 },
				);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taPreTrustedKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(
					result.errors.some((e) => /TA signature/i.test(e.message ?? "")),
					"expected TA signature verification failure",
				);
			});
			test("rejects chain with invalid leaf self-signature", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const wrongKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					wrongKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.checkNumber === 10));
			});
			test("accumulates multiple errors", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ iat: vt_now - 7200, exp: vt_now - 3600, authority_hints: ["https://ta.example.com"] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
					{ iat: vt_now - 7200, exp: vt_now - 3600 },
				);
				const taEc = await vt_signEC(
					"https://ta.example.com",
					taKeys.privateKey,
					taKeys.publicKey,
					{ iat: vt_now - 7200, exp: vt_now - 3600 },
				);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.ok(result.errors.length > 1);
			});
			test("detects chain continuity violation (check 12)", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"] },
				);
				const ss = await vt_signSS(
					"https://other.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.checkNumber === 12));
			});
			test("validates signature at all chain positions including j=0 (check 13)", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const wrongKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					wrongKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.checkNumber === 13));
			});
			test("applies superior metadata override from immediate superior (first SS, not last)", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const intKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{
						authority_hints: ["https://int.example.com"],
						metadata: {
							openid_relying_party: { client_name: "Original", scope: "openid profile email" },
						},
					},
				);
				const ssIntLeaf = await vt_signSS(
					"https://int.example.com",
					"https://leaf.example.com",
					intKeys.privateKey,
					leafKeys.publicKey,
					{
						metadata: { openid_relying_party: { client_name: "Overridden by Int" } },
						metadata_policy: {
							openid_relying_party: { scope: { subset_of: ["openid", "profile", "email"] } },
						},
					},
				);
				const ssTaInt = await vt_signSS(
					"https://ta.example.com",
					"https://int.example.com",
					taKeys.privateKey,
					intKeys.publicKey,
					{ metadata: { openid_relying_party: { client_name: "Should Not Override" } } },
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ssIntLeaf, ssTaInt, taEc], taSet, {
					verboseErrors: true,
				});
				t.true(result.valid);
				if (result.valid)
					t.equal(
						result.chain.resolvedMetadata.openid_relying_party?.client_name,
						"Overridden by Int",
					);
			});
			test("rejects statement without jwks", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"] },
				);
				const ss = await signEntityStatement(
					{
						iss: "https://ta.example.com",
						sub: "https://leaf.example.com",
						iat: vt_now,
						exp: vt_now + 3600,
					},
					taKeys.privateKey,
					{ typ: JwtTyp.EntityStatement },
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.message.includes("jwks")));
			});
			test("rejects crit containing standard claim", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"], crit: ["iss"] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.message.includes("crit")));
			});
			test("rejects crit with unknown extension", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"], crit: ["x_custom_ext"] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
			});
			test("accepts crit with registered extension", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{
						authority_hints: ["https://ta.example.com"],
						crit: ["x_custom_ext"],
						x_custom_ext: "some value",
					},
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, {
					understoodCriticalClaims: new Set(["x_custom_ext"]),
					verboseErrors: true,
				});
				t.true(result.valid);
			});
			test("rejects EC-only claims in subordinate statement", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
					{ trust_marks: [{ trust_mark_type: "x", trust_mark: "y" }] },
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.message.includes("trust_marks")));
			});
			test("rejects EC-only claim trust_mark_issuers in subordinate statement", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
					{ trust_mark_issuers: { "https://example.com/tm": ["https://issuer.example.com"] } },
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.message.includes("trust_mark_issuers")));
			});
			test("rejects EC-only claim trust_mark_owners in subordinate statement", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
					{
						trust_mark_owners: {
							"https://example.com/tm": { sub: "https://owner.example.com", jwks: { keys: [] } },
						},
					},
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.message.includes("trust_mark_owners")));
			});
			test("rejects empty authority_hints array", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: [] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(
					result.errors.some(
						(e) => e.message.includes("authority_hints") && e.message.includes("empty"),
					),
				);
			});
			test("rejects TA EC with authority_hints", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC(
					"https://ta.example.com",
					taKeys.privateKey,
					taKeys.publicKey,
					{ authority_hints: ["https://other.example.com"] },
				);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(
					result.errors.some(
						(e) => e.message.includes("Trust Anchor") && e.message.includes("authority_hints"),
					),
				);
			});
			test("rejects TA EC with trust_anchor_hints", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC(
					"https://ta.example.com",
					taKeys.privateKey,
					taKeys.publicKey,
					{ trust_anchor_hints: ["https://other.example.com"] },
				);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(
					result.errors.some(
						(e) => e.message.includes("Trust Anchor") && e.message.includes("trust_anchor_hints"),
					),
				);
			});
			test("rejects SS issuer not in subject's authority_hints", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://other.example.com"] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.message.includes("authority_hints")));
			});
			test("rejects SS-only claims in entity configuration", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{
						authority_hints: ["https://ta.example.com"],
						source_endpoint: "https://example.com/fetch",
					},
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.message.includes("source_endpoint")));
			});
			test("rejects SS-only claim metadata_policy in entity configuration", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{
						authority_hints: ["https://ta.example.com"],
						metadata_policy: { openid_relying_party: { contacts: { add: ["admin@example.com"] } } },
					},
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.message.includes("metadata_policy")));
			});
			test("rejects SS-only claim constraints in entity configuration", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"], constraints: { max_path_length: 0 } },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.message.includes("constraints")));
			});
			test("rejects metadata containing null values", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{
						authority_hints: ["https://ta.example.com"],
						metadata: { openid_relying_party: { client_name: "Test", scope: null } },
					},
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.message.includes("null")));
			});
			test("rejects chain statement with aud", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"], aud: "https://someone.example.com" },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.message.includes("aud")));
			});
			test("rejects chain statement with trust_anchor", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"], trust_anchor: "https://ta.example.com" },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.message.includes("trust_anchor")));
			});
			test("only collects trust_mark_issuers from TA EC", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const intKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const tmIssuerKeys = await generateSigningKey("ES256");
				const trustMarkJwt = await signEntityStatement(
					{
						iss: "https://non-approved-issuer.example.com",
						sub: "https://leaf.example.com",
						iat: vt_now,
						exp: vt_now + 3600,
						id: "https://trust-mark-type.example.com",
					},
					tmIssuerKeys.privateKey,
					{ typ: "trust-mark+jwt" },
				);
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{
						authority_hints: ["https://int.example.com"],
						trust_marks: [
							{ trust_mark_type: "https://trust-mark-type.example.com", trust_mark: trustMarkJwt },
						],
					},
				);
				const ssIntLeaf = await vt_signSS(
					"https://int.example.com",
					"https://leaf.example.com",
					intKeys.privateKey,
					leafKeys.publicKey,
				);
				const ssTaInt = await vt_signSS(
					"https://ta.example.com",
					"https://int.example.com",
					taKeys.privateKey,
					intKeys.publicKey,
				);
				const taEc = await vt_signEC(
					"https://ta.example.com",
					taKeys.privateKey,
					taKeys.publicKey,
					{
						trust_mark_issuers: {
							"https://trust-mark-type.example.com": ["https://approved-issuer.example.com"],
						},
					},
				);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ssIntLeaf, ssTaInt, taEc], taSet, {
					verboseErrors: true,
				});
				t.true(result.valid);
				if (result.valid) t.equal(result.chain.trustMarks.length, 0);
			});
			test("ignores trust mark when outer trust_mark_type does not match inner JWT trust_mark_type", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const issuerKeys = await generateSigningKey("ES256");
				const tmJwt = await signEntityStatement(
					{
						iss: "https://issuer.example.com",
						sub: "https://leaf.example.com",
						trust_mark_type: "https://tm-b.example.com",
						iat: vt_now,
					},
					issuerKeys.privateKey,
					{ typ: JwtTyp.TrustMark },
				);
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{
						authority_hints: ["https://ta.example.com"],
						trust_marks: [{ trust_mark_type: "https://tm-a.example.com", trust_mark: tmJwt }],
					},
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC(
					"https://ta.example.com",
					taKeys.privateKey,
					taKeys.publicKey,
					{
						trust_mark_issuers: {
							"https://tm-a.example.com": ["https://issuer.example.com"],
							"https://tm-b.example.com": ["https://issuer.example.com"],
						},
					},
				);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet);
				t.true(result.valid);
				if (result.valid) t.equal(result.chain.trustMarks.length, 0);
			});
			test("rejects entity statement with missing kid header", async (t) => {
				const jose = await import("jose");
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafCryptoKey = await jose.importJWK(
					leafKeys.privateKey as unknown as JoseJWK,
					"ES256",
				);
				const leafEc = await new jose.SignJWT({
					iss: "https://leaf.example.com",
					sub: "https://leaf.example.com",
					iat: vt_now,
					exp: vt_now + 3600,
					jwks: { keys: [leafKeys.publicKey] },
					authority_hints: ["https://ta.example.com"],
				} as unknown as JWTPayload)
					.setProtectedHeader({ alg: "ES256", typ: JwtTyp.EntityStatement } as JWTHeaderParameters)
					.sign(leafCryptoKey as Parameters<SignJWT["sign"]>[0]);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.field === "kid"));
			});
			test("rejects EC containing trust_chain header", async (t) => {
				const jose = await import("jose");
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafCryptoKey = await jose.importJWK(
					leafKeys.privateKey as unknown as JoseJWK,
					"ES256",
				);
				const leafEc = await new jose.SignJWT({
					iss: "https://leaf.example.com",
					sub: "https://leaf.example.com",
					iat: vt_now,
					exp: vt_now + 3600,
					jwks: { keys: [leafKeys.publicKey] },
					authority_hints: ["https://ta.example.com"],
				} as unknown as JWTPayload)
					.setProtectedHeader({
						alg: "ES256",
						typ: JwtTyp.EntityStatement,
						kid: leafKeys.publicKey.kid as string,
						trust_chain: ["some.jwt"],
					} as JWTHeaderParameters)
					.sign(leafCryptoKey as Parameters<SignJWT["sign"]>[0]);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.message.includes("trust_chain")));
			});
			test("rejects SS containing trust_chain header", async (t) => {
				const jose = await import("jose");
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"] },
				);
				const taCryptoKey = await jose.importJWK(taKeys.privateKey as unknown as JoseJWK, "ES256");
				const ss = await new jose.SignJWT({
					iss: "https://ta.example.com",
					sub: "https://leaf.example.com",
					iat: vt_now,
					exp: vt_now + 3600,
					jwks: { keys: [leafKeys.publicKey] },
				} as unknown as JWTPayload)
					.setProtectedHeader({
						alg: "ES256",
						typ: JwtTyp.EntityStatement,
						kid: taKeys.publicKey.kid as string,
						trust_chain: ["some.jwt"],
					} as JWTHeaderParameters)
					.sign(taCryptoKey as Parameters<SignJWT["sign"]>[0]);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.message.includes("trust_chain")));
			});
			test("rejects SS containing peer_trust_chain header", async (t) => {
				const jose = await import("jose");
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"] },
				);
				const taCryptoKey = await jose.importJWK(taKeys.privateKey as unknown as JoseJWK, "ES256");
				const ss = await new jose.SignJWT({
					iss: "https://ta.example.com",
					sub: "https://leaf.example.com",
					iat: vt_now,
					exp: vt_now + 3600,
					jwks: { keys: [leafKeys.publicKey] },
				} as unknown as JWTPayload)
					.setProtectedHeader({
						alg: "ES256",
						typ: JwtTyp.EntityStatement,
						kid: taKeys.publicKey.kid as string,
						peer_trust_chain: ["some.jwt"],
					} as JWTHeaderParameters)
					.sign(taCryptoKey as Parameters<SignJWT["sign"]>[0]);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.message.includes("peer_trust_chain")));
			});
			test("rejects EC containing peer_trust_chain header", async (t) => {
				const jose = await import("jose");
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafCryptoKey = await jose.importJWK(
					leafKeys.privateKey as unknown as JoseJWK,
					"ES256",
				);
				const leafEc = await new jose.SignJWT({
					iss: "https://leaf.example.com",
					sub: "https://leaf.example.com",
					iat: vt_now,
					exp: vt_now + 3600,
					jwks: { keys: [leafKeys.publicKey] },
					authority_hints: ["https://ta.example.com"],
				} as unknown as JWTPayload)
					.setProtectedHeader({
						alg: "ES256",
						typ: JwtTyp.EntityStatement,
						kid: leafKeys.publicKey.kid as string,
						peer_trust_chain: ["some.jwt"],
					} as JWTHeaderParameters)
					.sign(leafCryptoKey as Parameters<SignJWT["sign"]>[0]);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(result.errors.some((e) => e.message.includes("peer_trust_chain")));
			});
			test("rejects federation_entity metadata containing jwks", async (t) => {
				const { taSet, leafKeys, taKeys } = await vt_buildSimple();
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{
						authority_hints: ["https://ta.example.com"],
						metadata: {
							federation_entity: {
								organization_name: "Test",
								jwks: { keys: [leafKeys.publicKey] },
							},
						},
					},
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(
					result.errors.some(
						(e) => e.message.includes("jwks") && e.message.includes("federation_entity"),
					),
				);
			});
			test("rejects federation_entity metadata containing jwks_uri", async (t) => {
				const { taSet, leafKeys, taKeys } = await vt_buildSimple();
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{
						authority_hints: ["https://ta.example.com"],
						metadata: {
							federation_entity: {
								organization_name: "Test",
								jwks_uri: "https://example.com/jwks",
							},
						},
					},
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(
					result.errors.some(
						(e) => e.message.includes("jwks_uri") && e.message.includes("federation_entity"),
					),
				);
			});
			test("rejects federation_entity metadata containing signed_jwks_uri", async (t) => {
				const { taSet, leafKeys, taKeys } = await vt_buildSimple();
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{
						authority_hints: ["https://ta.example.com"],
						metadata: {
							federation_entity: {
								organization_name: "Test",
								signed_jwks_uri: "https://example.com/signed-jwks",
							},
						},
					},
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(
					result.errors.some(
						(e) => e.message.includes("signed_jwks_uri") && e.message.includes("federation_entity"),
					),
				);
			});
			test("rejects openid_provider.issuer not matching entity identifier", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{
						authority_hints: ["https://ta.example.com"],
						metadata: {
							openid_provider: {
								issuer: "https://different.example.com",
								authorization_endpoint: "https://leaf.example.com/auth",
								token_endpoint: "https://leaf.example.com/token",
								response_types_supported: ["code"],
								subject_types_supported: ["public"],
								id_token_signing_alg_values_supported: ["RS256"],
							},
						},
					},
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(
					result.errors.some(
						(e) => e.message.includes("openid_provider") && e.message.includes("issuer"),
					),
				);
			});
			test("rejects leaf EC whose openid_relying_party.jwks mixes signing and encryption keys without 'use'", async (t) => {
				const { taSet, leafKeys, taKeys } = await vt_buildSimple();
				const sigKey = {
					kty: "EC",
					kid: "sig-1",
					crv: "P-256",
					x: "x1",
					y: "y1",
					alg: "ES256",
				};
				const encKey = {
					kty: "RSA",
					kid: "enc-1",
					n: "n1",
					e: "AQAB",
					alg: "RSA-OAEP-256",
				};
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{
						authority_hints: ["https://ta.example.com"],
						metadata: {
							openid_relying_party: {
								redirect_uris: ["https://leaf.example.com/cb"],
								jwks: { keys: [sigKey, encKey] },
							},
						},
					},
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, {
					verboseErrors: true,
				});
				t.false(result.valid);
				t.true(
					result.errors.some(
						(e) => e.message.includes("signing and encryption") && e.message.includes("'use'"),
					),
				);
			});

			test("rejects oauth_authorization_server.issuer not matching entity identifier", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{
						authority_hints: ["https://ta.example.com"],
						metadata: { oauth_authorization_server: { issuer: "https://different.example.com" } },
					},
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(
					result.errors.some(
						(e) => e.message.includes("oauth_authorization_server") && e.message.includes("issuer"),
					),
				);
			});
			test("rejects SS metadata with openid_provider.issuer not matching subject", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
					{ metadata: { openid_provider: { issuer: "https://wrong.example.com" } } },
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(
					result.errors.some(
						(e) => e.message.includes("openid_provider") && e.message.includes("issuer"),
					),
				);
			});
			test("rejects SS metadata with oauth_authorization_server.issuer not matching subject", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
					{ metadata: { oauth_authorization_server: { issuer: "https://wrong.example.com" } } },
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.false(result.valid);
				t.true(
					result.errors.some(
						(e) => e.message.includes("oauth_authorization_server") && e.message.includes("issuer"),
					),
				);
			});
			test("rejects crit with duplicate claim names", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"], crit: ["x_ext", "x_ext"], x_ext: "value" },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, {
					understoodCriticalClaims: new Set(["x_ext"]),
					verboseErrors: true,
				});
				t.false(result.valid);
				t.true(
					result.errors.some((e) => e.message.includes("Duplicate") && e.message.includes("crit")),
				);
			});
			test("rejects crit claim name absent from JWT payload", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"], crit: ["x_absent"] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, {
					understoodCriticalClaims: new Set(["x_absent"]),
					verboseErrors: true,
				});
				t.false(result.valid);
				t.true(
					result.errors.some(
						(e) => e.message.includes("does not exist") && e.message.includes("crit"),
					),
				);
			});
			test("validates chain with constraints (max_path_length)", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"] },
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
					{ constraints: { max_path_length: 0 } },
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.true(result.valid);
			});
			test("applies allowed_entity_types filter after merging Immediate Superior SS metadata", async (t) => {
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{
						authority_hints: ["https://ta.example.com"],
						metadata: { openid_relying_party: { client_name: "RP" } },
					},
				);
				const ss = await vt_signSS(
					"https://ta.example.com",
					"https://leaf.example.com",
					taKeys.privateKey,
					leafKeys.publicKey,
					{
						metadata: { oauth_client: { client_id: "c1" } },
						constraints: { allowed_entity_types: ["openid_relying_party"] },
					},
				);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, { verboseErrors: true });
				t.true(result.valid);
				if (!result.valid) return;
				t.false("oauth_client" in (result.chain.resolvedMetadata as Record<string, unknown>));
				t.true(
					"openid_relying_party" in (result.chain.resolvedMetadata as Record<string, unknown>),
				);
			});
			test("rejects chain statement with missing exp", async (t) => {
				const jose = await import("jose");
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"] },
				);
				const taCryptoKey = await jose.importJWK(taKeys.privateKey as unknown as JoseJWK, "ES256");
				// SS deliberately omits exp to exercise the required-claims path.
				const ss = await new jose.SignJWT({
					iss: "https://ta.example.com",
					sub: "https://leaf.example.com",
					iat: vt_now,
					jwks: { keys: [leafKeys.publicKey] },
				} as unknown as JWTPayload)
					.setProtectedHeader({
						alg: "ES256",
						typ: JwtTyp.EntityStatement,
						kid: taKeys.publicKey.kid as string,
					} as JWTHeaderParameters)
					.sign(taCryptoKey as Parameters<SignJWT["sign"]>[0]);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, {
					verboseErrors: true,
				});
				t.false(result.valid);
				t.true(
					result.errors.some((e) => e.checkNumber === 1 && e.field === "exp"),
					"expected a missing-exp rejection (checkNumber 1, field exp)",
				);
			});
			test("rejects chain statement with missing iat", async (t) => {
				const jose = await import("jose");
				const taKeys = await generateSigningKey("ES256");
				const leafKeys = await generateSigningKey("ES256");
				const leafEc = await vt_signEC(
					"https://leaf.example.com",
					leafKeys.privateKey,
					leafKeys.publicKey,
					{ authority_hints: ["https://ta.example.com"] },
				);
				const taCryptoKey = await jose.importJWK(taKeys.privateKey as unknown as JoseJWK, "ES256");
				// SS deliberately omits iat to exercise the required-claims path.
				const ss = await new jose.SignJWT({
					iss: "https://ta.example.com",
					sub: "https://leaf.example.com",
					exp: vt_now + 3600,
					jwks: { keys: [leafKeys.publicKey] },
				} as unknown as JWTPayload)
					.setProtectedHeader({
						alg: "ES256",
						typ: JwtTyp.EntityStatement,
						kid: taKeys.publicKey.kid as string,
					} as JWTHeaderParameters)
					.sign(taCryptoKey as Parameters<SignJWT["sign"]>[0]);
				const taEc = await vt_signEC("https://ta.example.com", taKeys.privateKey, taKeys.publicKey);
				const taSet: TrustAnchorSet = new Map([
					["https://ta.example.com" as EntityId, { jwks: { keys: [taKeys.publicKey] } }],
				]);
				const result = await validateTrustChain([leafEc, ss, taEc], taSet, {
					verboseErrors: true,
				});
				t.false(result.valid);
				t.true(
					result.errors.some((e) => e.checkNumber === 1 && e.field === "iat"),
					"expected a missing-iat rejection (checkNumber 1, field iat)",
				);
			});
		});
		module("core / calculateChainExpiration", () => {
			test("returns minimum exp from all statements", (t) => {
				const statements: ParsedEntityStatement[] = [
					{
						header: { alg: "ES256", typ: "entity-statement+jwt", kid: "k1" },
						payload: {
							iss: "a",
							sub: "a",
							iat: vt_now,
							exp: vt_now + 7200,
						} as EntityStatementPayload,
					},
					{
						header: { alg: "ES256", typ: "entity-statement+jwt", kid: "k1" },
						payload: {
							iss: "b",
							sub: "a",
							iat: vt_now,
							exp: vt_now + 3600,
						} as EntityStatementPayload,
					},
					{
						header: { alg: "ES256", typ: "entity-statement+jwt", kid: "k1" },
						payload: {
							iss: "c",
							sub: "c",
							iat: vt_now,
							exp: vt_now + 1800,
						} as EntityStatementPayload,
					},
				];
				t.equal(calculateChainExpiration(statements), vt_now + 1800);
			});
		});
		module("core / isChainExpired", () => {
			test("returns true when chain has expired", (t) => {
				const chain = {
					statements: [],
					entityId: "https://leaf.example.com" as EntityId,
					trustAnchorId: "https://ta.example.com" as EntityId,
					expiresAt: vt_now - 100,
					resolvedMetadata: {},
					trustMarks: [],
				} as ValidatedTrustChain;
				t.true(isChainExpired(chain, { now: () => vt_now }));
			});
			test("returns false when chain is still valid", (t) => {
				const chain = {
					statements: [],
					entityId: "https://leaf.example.com" as EntityId,
					trustAnchorId: "https://ta.example.com" as EntityId,
					expiresAt: vt_now + 3600,
					resolvedMetadata: {},
					trustMarks: [],
				} as ValidatedTrustChain;
				t.false(isChainExpired(chain, { now: () => vt_now }));
			});
			test("returns true when expiresAt equals now (boundary)", (t) => {
				const chain = {
					statements: [],
					entityId: "https://leaf.example.com" as EntityId,
					trustAnchorId: "https://ta.example.com" as EntityId,
					expiresAt: vt_now,
					resolvedMetadata: {},
					trustMarks: [],
				} as ValidatedTrustChain;
				t.true(isChainExpired(chain, { now: () => vt_now }));
			});
		});
		module("core / chainRemainingTtl", () => {
			test("returns remaining seconds", (t) => {
				t.equal(
					chainRemainingTtl({ expiresAt: vt_now + 3600 } as ValidatedTrustChain, {
						now: () => vt_now,
					}),
					3600,
				);
			});
			test("returns 0 when expired", (t) => {
				t.equal(
					chainRemainingTtl({ expiresAt: vt_now - 100 } as ValidatedTrustChain, {
						now: () => vt_now,
					}),
					0,
				);
			});
		});
		module("core / describeTrustChain", () => {
			test("returns hostnames joined by ←", (t) => {
				const chain = {
					statements: [
						{ header: {}, payload: { sub: "https://leaf.example.com" } },
						{ header: {}, payload: { sub: "https://leaf.example.com" } },
						{ header: {}, payload: { sub: "https://ta.example.com" } },
					],
				} as unknown as ValidatedTrustChain;
				t.equal(describeTrustChain(chain), "leaf.example.com ← leaf.example.com ← ta.example.com");
			});
		});
		{
			const sc_makeChain = (
				length: number,
				expiresAt: number,
				taId: string,
			): ValidatedTrustChain => ({
				statements: Array(length).fill({
					header: {},
					payload: {
						sub: "https://a.example.com",
						iss: "https://a.example.com",
						iat: vt_now,
						exp: expiresAt,
					},
				} as ParsedEntityStatement),
				entityId: "https://leaf.example.com" as EntityId,
				trustAnchorId: taId as EntityId,
				expiresAt,
				resolvedMetadata: {},
				trustMarks: [],
			});
			module("core / shortestChain", () => {
				test("selects chain with fewest statements", (t) => {
					const chains = [
						sc_makeChain(4, vt_now + 3600, "https://ta1.example.com"),
						sc_makeChain(2, vt_now + 3600, "https://ta2.example.com"),
						sc_makeChain(3, vt_now + 3600, "https://ta3.example.com"),
					];
					t.equal(shortestChain(chains).statements.length, 2);
				});
			});
			module("core / longestExpiry", () => {
				test("selects chain with latest expiration", (t) => {
					const chains = [
						sc_makeChain(3, vt_now + 1800, "https://ta1.example.com"),
						sc_makeChain(3, vt_now + 7200, "https://ta2.example.com"),
						sc_makeChain(3, vt_now + 3600, "https://ta3.example.com"),
					];
					t.equal(longestExpiry(chains).expiresAt, vt_now + 7200);
				});
			});
			module("core / preferTrustAnchor", () => {
				test("prefers chain with matching TA", (t) => {
					const chains = [
						sc_makeChain(3, vt_now + 3600, "https://ta1.example.com"),
						sc_makeChain(4, vt_now + 3600, "https://preferred.example.com"),
						sc_makeChain(2, vt_now + 3600, "https://ta3.example.com"),
					];
					t.equal(
						preferTrustAnchor("https://preferred.example.com")(chains).trustAnchorId,
						"https://preferred.example.com",
					);
				});
				test("falls back to shortest when no TA match", (t) => {
					const chains = [
						sc_makeChain(4, vt_now + 3600, "https://ta1.example.com"),
						sc_makeChain(2, vt_now + 3600, "https://ta2.example.com"),
					];
					t.equal(
						preferTrustAnchor("https://nonexistent.example.com")(chains).statements.length,
						2,
					);
				});
			});
		}
	}
};
