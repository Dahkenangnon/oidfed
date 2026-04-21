import { describe, expect, it } from "vitest";
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
} from "../src/constants.js";

describe("constants", () => {
	it("has correct well-known path", () => {
		expect(WELL_KNOWN_OPENID_FEDERATION).toBe("/.well-known/openid-federation");
	});

	it("FederationEndpoint has all 8 paths", () => {
		expect(Object.keys(FederationEndpoint)).toHaveLength(8);
		expect(FederationEndpoint.Fetch).toBe("/federation_fetch");
		expect(FederationEndpoint.List).toBe("/federation_list");
		expect(FederationEndpoint.Resolve).toBe("/federation_resolve");
		expect(FederationEndpoint.Registration).toBe("/federation_registration");
		expect(FederationEndpoint.TrustMarkStatus).toBe("/federation_trust_mark_status");
		expect(FederationEndpoint.TrustMarkList).toBe("/federation_trust_mark_list");
		expect(FederationEndpoint.TrustMark).toBe("/federation_trust_mark");
		expect(FederationEndpoint.HistoricalKeys).toBe("/federation_historical_keys");
	});

	it("MediaType has all 11 types", () => {
		expect(Object.keys(MediaType)).toHaveLength(11);
		expect(MediaType.EntityStatement).toBe("application/entity-statement+jwt");
		expect(MediaType.TrustMark).toBe("application/trust-mark+jwt");
		expect(MediaType.Json).toBe("application/json");
	});

	it("JwtTyp has all 7 values", () => {
		expect(Object.keys(JwtTyp)).toHaveLength(7);
		expect(JwtTyp.EntityStatement).toBe("entity-statement+jwt");
		expect(JwtTyp.TrustMark).toBe("trust-mark+jwt");
	});

	it("EntityType has all 6 types", () => {
		expect(Object.keys(EntityType)).toHaveLength(6);
		expect(EntityType.FederationEntity).toBe("federation_entity");
		expect(EntityType.OpenIDRelyingParty).toBe("openid_relying_party");
		expect(EntityType.OpenIDProvider).toBe("openid_provider");
		expect(EntityType.OAuthAuthorizationServer).toBe("oauth_authorization_server");
		expect(EntityType.OAuthClient).toBe("oauth_client");
		expect(EntityType.OAuthResource).toBe("oauth_resource");
	});

	it("ClientRegistrationType has 2 types", () => {
		expect(Object.keys(ClientRegistrationType)).toHaveLength(2);
		expect(ClientRegistrationType.Automatic).toBe("automatic");
		expect(ClientRegistrationType.Explicit).toBe("explicit");
	});

	it("PolicyOperator has all 7 operators", () => {
		expect(Object.keys(PolicyOperator)).toHaveLength(7);
		expect(PolicyOperator.Value).toBe("value");
		expect(PolicyOperator.Essential).toBe("essential");
	});

	it("FederationErrorCode has 11 codes", () => {
		expect(Object.keys(FederationErrorCode)).toHaveLength(11);
		expect(FederationErrorCode.InvalidRequest).toBe("invalid_request");
		expect(FederationErrorCode.NotFound).toBe("not_found");
	});

	it("InternalErrorCode has 12 codes", () => {
		expect(Object.keys(InternalErrorCode)).toHaveLength(12);
		expect(InternalErrorCode.TrustChainInvalid).toBe("ERR_TRUST_CHAIN_INVALID");
		expect(InternalErrorCode.LoopDetected).toBe("ERR_LOOP_DETECTED");
	});

	it("CachePrefix has 3 prefixes", () => {
		expect(Object.keys(CachePrefix)).toHaveLength(3);
		expect(CachePrefix.EntityConfiguration).toBe("ec:");
		expect(CachePrefix.EntityStatement).toBe("es:");
		expect(CachePrefix.TrustChain).toBe("chain:");
	});

	it("TrustMarkStatus has 4 values", () => {
		expect(Object.keys(TrustMarkStatus)).toHaveLength(4);
		expect(TrustMarkStatus.Active).toBe("active");
		expect(TrustMarkStatus.Revoked).toBe("revoked");
	});

	it("has correct numeric defaults", () => {
		expect(DEFAULT_HTTP_TIMEOUT_MS).toBe(10_000);
		expect(DEFAULT_CLOCK_SKEW_SECONDS).toBe(60);
		expect(DEFAULT_MAX_CHAIN_DEPTH).toBe(8);
		expect(DEFAULT_MAX_AUTHORITY_HINTS).toBe(10);
		expect(DEFAULT_CACHE_TTL_SECONDS).toBe(3600);
		expect(DEFAULT_CACHE_MAX_TTL_SECONDS).toBe(86400);
	});

	it("REQUIRED_ALGORITHMS contains ES256 and PS256", () => {
		expect(REQUIRED_ALGORITHMS).toContain("ES256");
		expect(REQUIRED_ALGORITHMS).toContain("PS256");
		expect(REQUIRED_ALGORITHMS).toHaveLength(2);
	});

	it("SUPPORTED_ALGORITHMS contains all expected algorithms", () => {
		expect(SUPPORTED_ALGORITHMS).toContain("ES256");
		expect(SUPPORTED_ALGORITHMS).toContain("ES384");
		expect(SUPPORTED_ALGORITHMS).toContain("ES512");
		expect(SUPPORTED_ALGORITHMS).toContain("PS256");
		expect(SUPPORTED_ALGORITHMS).toContain("PS384");
		expect(SUPPORTED_ALGORITHMS).toContain("PS512");
		expect(SUPPORTED_ALGORITHMS).toContain("RS256");
		expect(SUPPORTED_ALGORITHMS).toHaveLength(7);
	});
});
