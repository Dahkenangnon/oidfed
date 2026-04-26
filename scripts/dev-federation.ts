#!/usr/bin/env npx tsx
/**
 * Launches all 6 federation topologies on a fixed port for browser access.
 *
 * Prerequisites:
 *   1. pnpm setup:e2e              — generate TLS certs
 *   2. pnpm build                  — build all packages
 *   3. Add /etc/hosts entries (printed on startup)
 *
 * Usage:
 *   pnpm dev:federation             — starts on port 8443
 *   pnpm dev:federation -- --port 9443
 */

import { readFileSync } from "node:fs";
import https from "node:https";
import { join } from "node:path";
import { parseArgs } from "node:util";
import express from "express";

import {
	createAuthorityServer,
	MemoryKeyStore,
	MemorySubordinateStore,
	MemoryTrustMarkStore,
	type AuthorityConfig,
	type AuthorityServer,
	type SubordinateRecord,
} from "@oidfed/authority";
import {
	entityId,
	generateSigningKey,
	InMemoryJtiStore,
	type EntityId,
	type EntityType,
	type JWK,
	type TrustAnchorSet,
} from "@oidfed/core";
import { createLeafEntity, type LeafEntity } from "@oidfed/leaf";
import { processAutomaticRegistration } from "@oidfed/oidc";
import Provider from "oidc-provider";

// ---------------------------------------------------------------------------

const { values } = parseArgs({
	options: {
		port: { type: "string", default: "8443" },
	},
});

const PORT = Number.parseInt(values.port!, 10);
const CERT_DIR = join(import.meta.dirname, "../.certs");

// ---------------------------------------------------------------------------
// Topology definitions (adapted from e2e, with prefixed hostnames)
// ---------------------------------------------------------------------------

interface EntityDefinition {
	id: string;
	role: "trust-anchor" | "intermediate" | "leaf";
	protocolRole?: "op" | "rp";
	authorityHints?: string[];
	metadata: Record<string, Record<string, unknown>>;
	metadataPolicy?: Record<string, Record<string, unknown>>;
	constraints?: { max_path_length?: number };
	trustMarkIssuers?: Record<string, string[]>;
}

interface TopologyDefinition {
	name: string;
	description: string;
	entities: EntityDefinition[];
}

function h(hostname: string): string {
	return `https://${hostname}.ofed.test`;
}

function fedEntity(hostname: string, endpoints: string[]): Record<string, string> {
	const base = h(hostname);
	const result: Record<string, string> = {};
	for (const ep of endpoints) {
		result[`${ep}_endpoint`] = `${base}/${ep}`;
	}
	return result;
}

function taFedEntity(hostname: string): Record<string, string> {
	return fedEntity(hostname, [
		"federation_fetch",
		"federation_list",
		"federation_resolve",
		"federation_trust_mark",
		"federation_trust_mark_status",
		"federation_trust_mark_list",
	]);
}

function iaFedEntity(hostname: string): Record<string, string> {
	return fedEntity(hostname, ["federation_fetch", "federation_list", "federation_resolve"]);
}

/**
 * Federation-entity metadata for an OP leaf.
 * Advertises the endpoints actually served by createOpApp():
 *   federation_fetch, federation_list, federation_registration.
 * (resolve, trust-mark endpoints are NOT advertised; leaf OPs don't issue
 * trust marks or run a resolve service on behalf of others.)
 */
function opFedEntity(hostname: string): Record<string, string> {
	return fedEntity(hostname, ["federation_fetch", "federation_list", "federation_registration"]);
}

/**
 * openid_provider metadata for an OP.
 * - jwks_uri: required by OIDC Discovery so clients can verify ID tokens.
 * - federation_registration_endpoint: also placed here (§OpenIDProviderMetadataSchema)
 *   so OIDC-aware clients find it even without reading federation_entity.
 */
function opMetadata(hostname: string): Record<string, unknown> {
	const base = h(hostname);
	return {
		issuer: base,
		authorization_endpoint: `${base}/auth`,
		token_endpoint: `${base}/token`,
		jwks_uri: `${base}/jwks`,
		response_types_supported: ["code"],
		subject_types_supported: ["public"],
		id_token_signing_alg_values_supported: ["ES256"],
		client_registration_types_supported: ["automatic", "explicit"],
		federation_registration_endpoint: `${base}/federation_registration`,
	};
}

/**
 * openid_relying_party metadata for an RP.
 * jwks is intentionally omitted here — it is injected at bootstrap time
 * once keys are generated (see bootstrapTopology steps 6 & 7).
 */
function rpMetadata(hostname: string): Record<string, unknown> {
	return {
		redirect_uris: [`${h(hostname)}/callback`],
		response_types: ["code"],
		grant_types: ["authorization_code"],
		client_registration_types: ["automatic"],
		token_endpoint_auth_method: "private_key_jwt",
		scope: "openid",
	};
}

/**
 * Builds rich federation_entity metadata with optional spec fields (§5.2).
 * Merges endpoint URIs from the base with org info, contacts, URIs, keywords.
 */
function richFedEntity(
	base: Record<string, string>,
	info: {
		organization_name: string;
		display_name?: string;
		description?: string;
		contacts?: string[];
		logo_uri?: string;
		policy_uri?: string;
		information_uri?: string;
		organization_uri?: string;
		keywords?: string[];
	},
): Record<string, unknown> {
	const result: Record<string, unknown> = { ...base };
	result.organization_name = info.organization_name;
	if (info.display_name) result.display_name = info.display_name;
	if (info.description) result.description = info.description;
	if (info.contacts) result.contacts = info.contacts;
	if (info.logo_uri) result.logo_uri = info.logo_uri;
	if (info.policy_uri) result.policy_uri = info.policy_uri;
	if (info.information_uri) result.information_uri = info.information_uri;
	if (info.organization_uri) result.organization_uri = info.organization_uri;
	if (info.keywords) result.keywords = info.keywords;
	return result;
}

const TOPOLOGIES: TopologyDefinition[] = [
	// 1. single-anchor
	// max_path_length=0: TA issues directly to leaf OPs and RPs, no intermediates allowed.
	{
		name: "single-anchor",
		description: "TA + OP + 2 RPs with trust marks, policy, and constraints",
		entities: [
			{
				id: h("ta-sa"),
				role: "trust-anchor",
				constraints: { max_path_length: 0 },
				metadata: {
					federation_entity: richFedEntity(taFedEntity("ta-sa"), {
						organization_name: "Single-Anchor Trust Authority",
						display_name: "SA Trust Anchor",
						description: "Root trust anchor for the single-anchor federation topology",
						contacts: ["admin@ta-sa.ofed.test", "security@ta-sa.ofed.test"],
						logo_uri: "https://placehold.co/128x128/e74c3c/white?text=TA",
						policy_uri: `${h("ta-sa")}/policy`,
						information_uri: `${h("ta-sa")}/about`,
						organization_uri: `${h("ta-sa")}`,
						keywords: ["trust-anchor", "single-anchor", "openid-federation"],
					}),
				},
				trustMarkIssuers: { [`${h("ta-sa")}/trust-marks/certified`]: [h("ta-sa")] },
			},
			{
				id: h("op-sa"),
				role: "leaf",
				protocolRole: "op",
				authorityHints: [h("ta-sa")],
				metadata: {
					federation_entity: richFedEntity(opFedEntity("op-sa"), {
						organization_name: "SA OpenID Provider Inc.",
						display_name: "SA Identity Service",
						description: "OpenID Provider serving the single-anchor federation",
						contacts: ["ops@op-sa.ofed.test"],
						logo_uri: "https://placehold.co/128x128/3498db/white?text=OP",
						organization_uri: `${h("op-sa")}`,
						keywords: ["openid-provider", "identity"],
					}),
					openid_provider: opMetadata("op-sa"),
				},
				// metadataPolicy on an OP entity → goes into the PARENT's (ta-sa's) subordinate
				// statement about this OP → constrains this OP's OWN openid_provider metadata. ✓
				// Per §9: subordinate statement's metadata_policy applies to the subject entity's metadata.
				metadataPolicy: {
					openid_provider: {
						token_endpoint_auth_methods_supported: { default: ["private_key_jwt"] },
					},
				},
			},
			{
				id: h("rp-sa"),
				role: "leaf",
				protocolRole: "rp",
				authorityHints: [h("ta-sa")],
				metadata: {
					federation_entity: richFedEntity({}, {
						organization_name: "SA Relying Party 1",
						description: "Consumer-facing relying party (automatic registration)",
						contacts: ["dev@rp-sa.ofed.test"],
						keywords: ["relying-party", "consumer"],
					}),
					openid_relying_party: rpMetadata("rp-sa"),
				},
			},
			{
				id: h("rp2-sa"),
				role: "leaf",
				protocolRole: "rp",
				authorityHints: [h("ta-sa")],
				metadata: {
					federation_entity: richFedEntity({}, {
						organization_name: "SA Relying Party 2",
						display_name: "SA RP2 (Explicit)",
						description: "Enterprise relying party using explicit registration",
						contacts: ["enterprise@rp2-sa.ofed.test"],
						keywords: ["relying-party", "explicit-registration"],
					}),
					openid_relying_party: {
						...rpMetadata("rp2-sa"),
						client_registration_types: ["explicit"],
					},
				},
			},
		],
	},
	// 2. hierarchical
	// BUG FIX: metadataPolicy was previously on ia-edu-hi and ia-health-hi, which caused it to
	// appear in TA's subordinate statement ABOUT the IAs. The policy references openid_provider,
	// which those IAs don't have — but more critically, when resolving an RP's trust chain through
	// the IA, applyMetadataPolicy() would CREATE an openid_provider entry on the RP (a spec
	// violation). The fix: metadataPolicy belongs on the OP entity definitions, so it ends up in
	// the IA's subordinate statement ABOUT the OP — correctly constraining the OP's own metadata.
	{
		name: "hierarchical",
		description: "TA → 2 IAs (edu, health) → OPs + RPs",
		entities: [
			{
				id: h("ta-hi"),
				role: "trust-anchor",
				constraints: { max_path_length: 1 },
				metadata: {
					federation_entity: richFedEntity(taFedEntity("ta-hi"), {
						organization_name: "National Federation Authority",
						display_name: "NFA Trust Anchor",
						description: "Top-level trust anchor overseeing education and healthcare sectors",
						contacts: ["admin@ta-hi.ofed.test", "compliance@ta-hi.ofed.test"],
						logo_uri: "https://placehold.co/128x128/9b59b6/white?text=NFA",
						policy_uri: `${h("ta-hi")}/policy`,
						organization_uri: `${h("ta-hi")}`,
						keywords: ["trust-anchor", "hierarchical", "national"],
					}),
				},
				trustMarkIssuers: { [`${h("ta-hi")}/trust-marks/certified`]: [h("ta-hi")] },
			},
			{
				id: h("ia-edu-hi"),
				role: "intermediate",
				authorityHints: [h("ta-hi")],
				metadata: {
					federation_entity: richFedEntity(iaFedEntity("ia-edu-hi"), {
						organization_name: "Education Sector Authority",
						display_name: "EduFed",
						description: "Intermediate authority for universities and educational institutions",
						contacts: ["registrar@ia-edu-hi.ofed.test"],
						logo_uri: "https://placehold.co/128x128/2ecc71/white?text=EDU",
						organization_uri: `${h("ia-edu-hi")}`,
						keywords: ["intermediate", "education", "university"],
					}),
				},
				// No metadataPolicy here — IA has only federation_entity metadata, not openid_provider.
				// The OP-specific policy is placed on the OP entity below (→ ia-edu-hi's sub stmt). ✓
			},
			{
				id: h("ia-health-hi"),
				role: "intermediate",
				authorityHints: [h("ta-hi")],
				metadata: {
					federation_entity: richFedEntity(iaFedEntity("ia-health-hi"), {
						organization_name: "Healthcare Sector Authority",
						display_name: "HealthFed",
						description: "Intermediate authority for hospitals and healthcare providers",
						contacts: ["admin@ia-health-hi.ofed.test"],
						logo_uri: "https://placehold.co/128x128/e74c3c/white?text=MED",
						keywords: ["intermediate", "healthcare", "hospital"],
					}),
				},
			},
			{
				id: h("op-uni-hi"),
				role: "leaf",
				protocolRole: "op",
				authorityHints: [h("ia-edu-hi")],
				metadata: {
					federation_entity: richFedEntity(opFedEntity("op-uni-hi"), {
						organization_name: "State University",
						display_name: "UniLogin",
						description: "University identity provider for students and faculty",
						contacts: ["iam@op-uni-hi.ofed.test"],
						logo_uri: "https://placehold.co/128x128/3498db/white?text=UNI",
						information_uri: `${h("op-uni-hi")}/about`,
						keywords: ["openid-provider", "university", "education"],
					}),
					openid_provider: opMetadata("op-uni-hi"),
				},
				// metadataPolicy here → ia-edu-hi's subordinate statement about op-uni-hi → ✓
				metadataPolicy: {
					openid_provider: {
						token_endpoint_auth_methods_supported: { default: ["private_key_jwt"] },
					},
				},
			},
			{
				id: h("rp1-hi"),
				role: "leaf",
				protocolRole: "rp",
				authorityHints: [h("ia-edu-hi")],
				metadata: {
					federation_entity: richFedEntity({}, {
						organization_name: "Student Portal",
						description: "Learning management system for enrolled students",
						contacts: ["support@rp1-hi.ofed.test"],
						keywords: ["relying-party", "education", "lms"],
					}),
					openid_relying_party: rpMetadata("rp1-hi"),
				},
			},
			{
				id: h("op-hosp-hi"),
				role: "leaf",
				protocolRole: "op",
				authorityHints: [h("ia-health-hi")],
				metadata: {
					federation_entity: richFedEntity(opFedEntity("op-hosp-hi"), {
						organization_name: "Central Hospital",
						display_name: "HospitalID",
						description: "Healthcare identity provider for clinical staff",
						contacts: ["it@op-hosp-hi.ofed.test"],
						logo_uri: "https://placehold.co/128x128/e74c3c/white?text=H+",
						policy_uri: `${h("op-hosp-hi")}/privacy`,
						keywords: ["openid-provider", "healthcare", "hospital"],
					}),
					openid_provider: opMetadata("op-hosp-hi"),
				},
				// metadataPolicy here → ia-health-hi's subordinate statement about op-hosp-hi → ✓
				metadataPolicy: {
					openid_provider: {
						token_endpoint_auth_methods_supported: { default: ["private_key_jwt"] },
					},
				},
			},
			{
				id: h("rp2-hi"),
				role: "leaf",
				protocolRole: "rp",
				authorityHints: [h("ia-health-hi")],
				metadata: {
					federation_entity: richFedEntity({}, {
						organization_name: "Patient Records Portal",
						display_name: "PatientAccess",
						description: "Electronic health records portal with explicit registration",
						contacts: ["compliance@rp2-hi.ofed.test"],
						policy_uri: `${h("rp2-hi")}/privacy`,
						keywords: ["relying-party", "healthcare", "ehr"],
					}),
					openid_relying_party: {
						...rpMetadata("rp2-hi"),
						client_registration_types: ["explicit"],
					},
				},
			},
		],
	},
	// 3. multi-anchor
	{
		name: "multi-anchor",
		description: "2 TAs (gov, industry) → shared IA → OP + 2 RPs",
		entities: [
			{
				id: h("ta-gov-ma"),
				role: "trust-anchor",
				constraints: { max_path_length: 1 },
				metadata: {
					federation_entity: richFedEntity(taFedEntity("ta-gov-ma"), {
						organization_name: "Government Digital Authority",
						display_name: "GovTrust",
						description: "Government trust anchor for public sector identity federation",
						contacts: ["registry@ta-gov-ma.ofed.test"],
						logo_uri: "https://placehold.co/128x128/1a5276/white?text=GOV",
						policy_uri: `${h("ta-gov-ma")}/policy`,
						organization_uri: `${h("ta-gov-ma")}`,
						keywords: ["trust-anchor", "government", "public-sector"],
					}),
				},
				trustMarkIssuers: { [`${h("ta-gov-ma")}/trust-marks/gov-certified`]: [h("ta-gov-ma")] },
			},
			{
				id: h("ta-ind-ma"),
				role: "trust-anchor",
				constraints: { max_path_length: 1 },
				metadata: {
					federation_entity: richFedEntity(taFedEntity("ta-ind-ma"), {
						organization_name: "Industry Standards Consortium",
						display_name: "IndTrust",
						description: "Industry consortium trust anchor for private sector federation",
						contacts: ["membership@ta-ind-ma.ofed.test"],
						logo_uri: "https://placehold.co/128x128/f39c12/white?text=IND",
						organization_uri: `${h("ta-ind-ma")}`,
						keywords: ["trust-anchor", "industry", "private-sector"],
					}),
				},
				trustMarkIssuers: { [`${h("ta-ind-ma")}/trust-marks/ind-certified`]: [h("ta-ind-ma")] },
			},
			{
				id: h("ia-shared-ma"),
				role: "intermediate",
				authorityHints: [h("ta-gov-ma"), h("ta-ind-ma")],
				metadata: {
					federation_entity: richFedEntity(iaFedEntity("ia-shared-ma"), {
						organization_name: "Cross-Sector Bridge Authority",
						description: "Shared intermediate bridging government and industry trust anchors",
						contacts: ["bridge-ops@ia-shared-ma.ofed.test"],
						keywords: ["intermediate", "multi-anchor", "bridge"],
					}),
				},
				// No metadataPolicy — OP-specific policy belongs on op-ma (see below). ✓
			},
			{
				id: h("op-ma"),
				role: "leaf",
				protocolRole: "op",
				authorityHints: [h("ia-shared-ma")],
				metadata: {
					federation_entity: richFedEntity(opFedEntity("op-ma"), {
						organization_name: "Unified Identity Services",
						display_name: "UnifiedID",
						description: "OpenID Provider trusted by both government and industry anchors",
						contacts: ["support@op-ma.ofed.test"],
						keywords: ["openid-provider", "multi-anchor"],
					}),
					openid_provider: opMetadata("op-ma"),
				},
				// metadataPolicy here → ia-shared-ma's subordinate statement about op-ma → ✓
				metadataPolicy: {
					openid_provider: {
						token_endpoint_auth_methods_supported: { default: ["private_key_jwt"] },
					},
				},
			},
			{
				id: h("rp1-ma"),
				role: "leaf",
				protocolRole: "rp",
				authorityHints: [h("ia-shared-ma")],
				metadata: {
					federation_entity: richFedEntity({}, {
						organization_name: "Gov Services Portal",
						contacts: ["admin@rp1-ma.ofed.test"],
						keywords: ["relying-party", "government"],
					}),
					openid_relying_party: rpMetadata("rp1-ma"),
				},
			},
			{
				id: h("rp2-ma"),
				role: "leaf",
				protocolRole: "rp",
				authorityHints: [h("ia-shared-ma")],
				metadata: {
					federation_entity: richFedEntity({}, {
						organization_name: "Industry Compliance Platform",
						display_name: "ComplianceHub",
						contacts: ["compliance@rp2-ma.ofed.test"],
						keywords: ["relying-party", "industry", "compliance"],
					}),
					openid_relying_party: {
						...rpMetadata("rp2-ma"),
						client_registration_types: ["explicit"],
					},
				},
			},
		],
	},
	// 4. constrained
	// Demonstrates max_path_length enforcement:
	//   op-direct-co: TA→OP (0 intermediates, compliant with max_path_length=0) ✓
	//   op-deep-co:   TA→IA→OP (1 intermediate, violates max_path_length=0)    ✗ (intentional)
	{
		name: "constrained",
		description: "TA with max_path_length=0 → direct OP + IA with nested OP",
		entities: [
			{
				id: h("ta-co"),
				role: "trust-anchor",
				constraints: { max_path_length: 0 },
				metadata: {
					federation_entity: richFedEntity(taFedEntity("ta-co"), {
						organization_name: "Strict Compliance Authority",
						description: "Trust anchor with max_path_length=0 (no intermediates allowed)",
						contacts: ["strict@ta-co.ofed.test"],
						keywords: ["trust-anchor", "constrained", "strict"],
					}),
				},
				trustMarkIssuers: { [`${h("ta-co")}/trust-marks/certified`]: [h("ta-co")] },
			},
			{
				id: h("op-direct-co"),
				role: "leaf",
				protocolRole: "op",
				authorityHints: [h("ta-co")],
				metadata: {
					federation_entity: richFedEntity(opFedEntity("op-direct-co"), {
						organization_name: "Compliant Direct Provider",
						description: "OP directly under TA (0 intermediates — compliant)",
						contacts: ["ops@op-direct-co.ofed.test"],
						keywords: ["openid-provider", "compliant"],
					}),
					openid_provider: opMetadata("op-direct-co"),
				},
				// Direct TA→OP: metadataPolicy here → ta-co's sub stmt about op-direct-co → ✓
				metadataPolicy: {
					openid_provider: {
						token_endpoint_auth_methods_supported: { default: ["private_key_jwt"] },
					},
				},
			},
			{
				id: h("ia-deep-co"),
				role: "intermediate",
				authorityHints: [h("ta-co")],
				metadata: {
					federation_entity: richFedEntity(iaFedEntity("ia-deep-co"), {
						organization_name: "Unauthorized Intermediate",
						description: "Intermediate that violates max_path_length=0 constraint",
						keywords: ["intermediate", "violation"],
					}),
				},
			},
			{
				id: h("op-deep-co"),
				role: "leaf",
				protocolRole: "op",
				authorityHints: [h("ia-deep-co")],
				metadata: {
					federation_entity: richFedEntity(opFedEntity("op-deep-co"), {
						organization_name: "Deep Nested Provider",
						description: "OP behind unauthorized intermediate (chain will fail validation)",
						keywords: ["openid-provider", "violation"],
					}),
					openid_provider: opMetadata("op-deep-co"),
				},
				// Intentionally violates ta-co's max_path_length=0 (1 intermediate via ia-deep-co).
				// No metadataPolicy needed — chain is invalid anyway.
			},
		],
	},
	// 5. cross-federation
	{
		name: "cross-federation",
		description: "2 federations (X, Y) linked by a bridge entity",
		entities: [
			{
				id: h("ta-x-xf"),
				role: "trust-anchor",
				constraints: { max_path_length: 2 },
				metadata: {
					federation_entity: richFedEntity(taFedEntity("ta-x-xf"), {
						organization_name: "Federation X Consortium",
						display_name: "FedX",
						description: "Trust anchor for federation X",
						contacts: ["admin@ta-x-xf.ofed.test"],
						logo_uri: "https://placehold.co/128x128/2980b9/white?text=FX",
						organization_uri: `${h("ta-x-xf")}`,
						keywords: ["trust-anchor", "federation-x", "cross-federation"],
					}),
				},
				trustMarkIssuers: { [`${h("ta-x-xf")}/trust-marks/certified`]: [h("ta-x-xf")] },
			},
			{
				id: h("ia-x-xf"),
				role: "intermediate",
				authorityHints: [h("ta-x-xf")],
				metadata: {
					federation_entity: richFedEntity(iaFedEntity("ia-x-xf"), {
						organization_name: "FedX Intermediate",
						contacts: ["ops@ia-x-xf.ofed.test"],
						keywords: ["intermediate", "federation-x"],
					}),
				},
				// No metadataPolicy — OP-specific policy placed on op-x-xf below. ✓
			},
			{
				id: h("op-x-xf"),
				role: "leaf",
				protocolRole: "op",
				authorityHints: [h("ia-x-xf")],
				metadata: {
					federation_entity: richFedEntity(opFedEntity("op-x-xf"), {
						organization_name: "FedX Identity Provider",
						contacts: ["iam@op-x-xf.ofed.test"],
						keywords: ["openid-provider", "federation-x"],
					}),
					openid_provider: opMetadata("op-x-xf"),
				},
				// metadataPolicy here → ia-x-xf's subordinate statement about op-x-xf → ✓
				metadataPolicy: {
					openid_provider: {
						token_endpoint_auth_methods_supported: { default: ["private_key_jwt"] },
					},
				},
			},
			{
				id: h("rp-x-xf"),
				role: "leaf",
				protocolRole: "rp",
				authorityHints: [h("ia-x-xf")],
				metadata: {
					federation_entity: richFedEntity({}, {
						organization_name: "FedX Client App",
						keywords: ["relying-party", "federation-x"],
					}),
					openid_relying_party: rpMetadata("rp-x-xf"),
				},
			},
			{
				id: h("ta-y-xf"),
				role: "trust-anchor",
				constraints: { max_path_length: 2 },
				metadata: {
					federation_entity: richFedEntity(taFedEntity("ta-y-xf"), {
						organization_name: "Federation Y Alliance",
						display_name: "FedY",
						description: "Trust anchor for federation Y",
						contacts: ["admin@ta-y-xf.ofed.test"],
						logo_uri: "https://placehold.co/128x128/27ae60/white?text=FY",
						organization_uri: `${h("ta-y-xf")}`,
						keywords: ["trust-anchor", "federation-y", "cross-federation"],
					}),
				},
				trustMarkIssuers: { [`${h("ta-y-xf")}/trust-marks/certified`]: [h("ta-y-xf")] },
			},
			{
				id: h("ia-y-xf"),
				role: "intermediate",
				authorityHints: [h("ta-y-xf")],
				metadata: {
					federation_entity: richFedEntity(iaFedEntity("ia-y-xf"), {
						organization_name: "FedY Intermediate",
						contacts: ["ops@ia-y-xf.ofed.test"],
						keywords: ["intermediate", "federation-y"],
					}),
				},
				// No metadataPolicy — OP-specific policy placed on op-y-xf below. ✓
			},
			{
				id: h("op-y-xf"),
				role: "leaf",
				protocolRole: "op",
				authorityHints: [h("ia-y-xf")],
				metadata: {
					federation_entity: richFedEntity(opFedEntity("op-y-xf"), {
						organization_name: "FedY Identity Provider",
						contacts: ["iam@op-y-xf.ofed.test"],
						keywords: ["openid-provider", "federation-y"],
					}),
					openid_provider: opMetadata("op-y-xf"),
				},
				// metadataPolicy here → ia-y-xf's subordinate statement about op-y-xf → ✓
				metadataPolicy: {
					openid_provider: {
						token_endpoint_auth_methods_supported: { default: ["private_key_jwt"] },
					},
				},
			},
			{
				id: h("rp-y-xf"),
				role: "leaf",
				protocolRole: "rp",
				authorityHints: [h("ia-y-xf")],
				metadata: {
					federation_entity: richFedEntity({}, {
						organization_name: "FedY Client App",
						keywords: ["relying-party", "federation-y"],
					}),
					openid_relying_party: rpMetadata("rp-y-xf"),
				},
			},
			{
				id: h("bridge-xf"),
				role: "intermediate",
				authorityHints: [h("ta-x-xf"), h("ta-y-xf")],
				metadata: {
					federation_entity: richFedEntity(iaFedEntity("bridge-xf"), {
						organization_name: "Cross-Federation Bridge Entity",
						description: "Bridges Federation X and Federation Y trust domains",
						contacts: ["bridge-ops@bridge-xf.ofed.test"],
						keywords: ["intermediate", "bridge", "cross-federation"],
					}),
				},
			},
		],
	},
	// 6. policy-operators
	// Demonstrates all policy operators from §9.2. The metadataPolicy is on op-po (not ia-po)
	// so it appears correctly in ia-po's subordinate statement about op-po. After resolution:
	//   grant_types_supported:               ["authorization_code"] (subset_of passes) ✓
	//   token_endpoint_auth_methods_supported: ["private_key_jwt"]  (value overrides)  ✓
	//   id_token_signing_alg_values_supported: ["RS256","ES256"]    (add appends)       ✓
	{
		name: "policy-operators",
		description: "TA → IA with diverse policy operators → OP + RP",
		entities: [
			{
				id: h("ta-po"),
				role: "trust-anchor",
				constraints: { max_path_length: 1 },
				metadata: {
					federation_entity: richFedEntity(taFedEntity("ta-po"), {
						organization_name: "Policy Testing Authority",
						description: "Trust anchor demonstrating all metadata policy operators from §9.2",
						contacts: ["policy@ta-po.ofed.test"],
						keywords: ["trust-anchor", "policy-operators"],
					}),
				},
				trustMarkIssuers: { [`${h("ta-po")}/trust-marks/certified`]: [h("ta-po")] },
			},
			{
				id: h("ia-po"),
				role: "intermediate",
				authorityHints: [h("ta-po")],
				metadata: {
					federation_entity: richFedEntity(iaFedEntity("ia-po"), {
						organization_name: "Policy Enforcement IA",
						contacts: ["policy@ia-po.ofed.test"],
						keywords: ["intermediate", "policy"],
					}),
				},
				// No metadataPolicy on the IA — policy belongs on op-po below. ✓
			},
			{
				id: h("op-po"),
				role: "leaf",
				protocolRole: "op",
				authorityHints: [h("ia-po")],
				metadata: {
					federation_entity: richFedEntity(opFedEntity("op-po"), {
						organization_name: "Policy Test Provider",
						description: "OP with diverse policy operators applied to its metadata",
						contacts: ["test@op-po.ofed.test"],
						keywords: ["openid-provider", "policy-test"],
					}),
					openid_provider: {
						...opMetadata("op-po"),
						grant_types_supported: ["authorization_code"],
						token_endpoint_auth_methods_supported: ["client_secret_basic"],
						id_token_signing_alg_values_supported: ["RS256"],
					},
				},
				// metadataPolicy here → ia-po's subordinate statement about op-po → constrains
				// op-po's own openid_provider metadata. Per §9, operators are applied left to right. ✓
				metadataPolicy: {
					openid_provider: {
						grant_types_supported: { subset_of: ["authorization_code"] },
						token_endpoint_auth_methods_supported: { value: ["private_key_jwt"] },
						id_token_signing_alg_values_supported: { add: ["ES256"] },
					},
				},
			},
			{
				id: h("rp-po"),
				role: "leaf",
				protocolRole: "rp",
				authorityHints: [h("ia-po")],
				metadata: {
					federation_entity: richFedEntity({}, {
						organization_name: "Policy Test RP",
						contacts: ["test@rp-po.ofed.test"],
						keywords: ["relying-party", "policy-test"],
					}),
					openid_relying_party: rpMetadata("rp-po"),
				},
			},
		],
	},
];

// ---------------------------------------------------------------------------
// Generic bootstrap
// ---------------------------------------------------------------------------

interface EntityInstance {
	server: AuthorityServer | LeafEntity;
	keys: { signing: JWK; public: JWK };
	def: EntityDefinition;
	trustMarkStore?: MemoryTrustMarkStore;
}

function rewriteUrl(url: string, port: number): string {
	return url.replace(/https:\/\/([^/:]+)/g, `https://$1:${port}`);
}

function rewriteMetadata(
	metadata: Record<string, Record<string, unknown>>,
	port: number,
): Record<string, Record<string, unknown>> {
	const result: Record<string, Record<string, unknown>> = {};
	for (const [type, values] of Object.entries(metadata)) {
		const rewritten: Record<string, unknown> = {};
		for (const [k, v] of Object.entries(values)) {
			if (typeof v === "string" && v.startsWith("https://")) {
				rewritten[k] = rewriteUrl(v, port);
			} else if (Array.isArray(v)) {
				rewritten[k] = v.map((item) =>
					typeof item === "string" && item.startsWith("https://") ? rewriteUrl(item, port) : item,
				);
			} else {
				rewritten[k] = v;
			}
		}
		result[type] = rewritten;
	}
	return result;
}

function bridgeHandler(handler: (req: Request) => Promise<Response>): express.RequestHandler {
	return async (req, res) => {
		const url = new URL(req.originalUrl, `https://${req.headers.host}`);
		const hasBody = req.method !== "GET" && req.method !== "HEAD";
		let body: BodyInit | undefined;
		if (hasBody) {
			if (Buffer.isBuffer(req.body)) {
				body = req.body.toString("utf-8");
			} else if (typeof req.body === "object" && req.body !== null) {
				body = new URLSearchParams(req.body as Record<string, string>).toString();
			}
		}
		const request = new Request(url.toString(), {
			method: req.method,
			headers: req.headers as Record<string, string>,
			...(body !== undefined ? { body } : {}),
		});
		const response = await handler(request);
		res.status(response.status);
		for (const [key, value] of response.headers) {
			res.setHeader(key, value);
		}
		res.send(await response.text());
	};
}

function createOpApp(
	authority: AuthorityServer,
	eid: string,
	trustAnchors: TrustAnchorSet,
): express.Express {
	const app = express();
	app.use(express.raw({ type: "application/entity-statement+jwt", limit: "64kb" }));
	app.use(express.urlencoded({ extended: false, limit: "64kb" }));

	const jtiStore = new InMemoryJtiStore();
	const fedHandler = authority.handler();

	const oidc = new Provider(eid, {
		clients: [],
		findAccount: async (_ctx: unknown, id: string) => ({
			accountId: id,
			async claims() {
				return { sub: id };
			},
		}),
		features: { registration: { enabled: false } },
	});
	oidc.proxy = true;

	app.all("/.well-known/openid-federation", bridgeHandler(fedHandler));
	for (const path of [
		"/federation_fetch",
		"/federation_list",
		"/federation_resolve",
		"/federation_trust_mark",
		"/federation_trust_mark_status",
		"/federation_trust_mark_list",
	]) {
		app.all(path, bridgeHandler(fedHandler));
	}

	app.get("/auth", async (req, res, next) => {
		const requestJwt = req.query.request as string | undefined;
		if (requestJwt) {
			const result = await processAutomaticRegistration(requestJwt, trustAnchors, {
				opEntityId: eid as EntityId,
				jtiStore,
				httpClient: fetch,
			});
			if (!result.ok) {
				res.status(400).json({ error: result.error.code, error_description: result.error.description });
				return;
			}
		}
		const handler = oidc.callback() as express.RequestHandler;
		return handler(req, res, next);
	});

	app.use("/", oidc.callback() as express.RequestHandler);
	return app;
}

function createAuthorityApp(authority: AuthorityServer, eid: string): express.Express {
	const app = express();
	app.use(express.raw({ type: "application/entity-statement+jwt", limit: "64kb" }));
	app.use(express.urlencoded({ extended: false, limit: "64kb" }));
	app.all("/*splat", bridgeHandler(authority.handler()));
	return app;
}

function createLeafApp(leaf: LeafEntity, eid: string): express.Express {
	const app = express();
	app.get("/.well-known/openid-federation", bridgeHandler(leaf.handler()));
	return app;
}

async function bootstrapTopology(
	topology: TopologyDefinition,
	port: number,
): Promise<{ vhosts: Map<string, express.Express>; entities: Map<string, EntityInstance>; trustAnchors: TrustAnchorSet }> {
	const rw = (url: string) => rewriteUrl(url, port);


	// 1. Generate keys
	const entityKeys = new Map<string, { signing: JWK; public: JWK }>();
	for (const entity of topology.entities) {
		const key = await generateSigningKey("ES256");
		entityKeys.set(entity.id, { signing: key.privateKey as JWK, public: key.publicKey as JWK });
	}
	const getKeys = (id: string) => {
		const k = entityKeys.get(id);
		if (!k) throw new Error(`No keys for entity ${id}`);
		return k;
	};

	// 2. Trust anchor set
	const taEntities = topology.entities.filter((e) => e.role === "trust-anchor");
	const trustAnchors: TrustAnchorSet = new Map(
		taEntities.map((ta) => [entityId(rw(ta.id)), { jwks: { keys: [getKeys(ta.id).public] } }]),
	);

	const entities = new Map<string, EntityInstance>();
	const vhosts = new Map<string, express.Express>();

	function buildAuthorityConfig(
		entity: EntityDefinition,
		subordinateStore: MemorySubordinateStore,
		trustMarkStore: MemoryTrustMarkStore,
		keyStore: MemoryKeyStore,
		extraTrustMarks?: Array<{ trust_mark_type: string; trust_mark: string }>,
	): Record<string, unknown> {
		const eid = rw(entity.id);
		const metadata = rewriteMetadata(entity.metadata, port);
		const authorityHints = entity.authorityHints?.map((ah) => entityId(rw(ah)));

		const cfg: Record<string, unknown> = {
			entityId: entityId(eid),
			signingKeys: [getKeys(entity.id).signing],
			metadata: {
				federation_entity: (metadata.federation_entity as Record<string, string>) ?? {},
				...Object.fromEntries(Object.entries(metadata).filter(([k]) => k !== "federation_entity")),
			},
			subordinateStore,
			keyStore,
			trustMarkStore,
			trustAnchors,
		};
		if (authorityHints) cfg.authorityHints = authorityHints;
		if (entity.trustMarkIssuers) {
			cfg.trustMarkIssuers = Object.fromEntries(
				Object.entries(entity.trustMarkIssuers).map(([tmType, issuers]) => [
					rw(tmType),
					issuers.map(rw),
				]),
			);
		}
		if (extraTrustMarks && extraTrustMarks.length > 0) {
			cfg.trustMarks = extraTrustMarks;
		}
		return cfg;
	}

	// Stores reused across passes
	const subordinateStoreMap = new Map<string, MemorySubordinateStore>();
	const trustMarkStoreMap = new Map<string, MemoryTrustMarkStore>();
	const keyStoreMap = new Map<string, MemoryKeyStore>();

	for (const entity of topology.entities) {
		const isAuthority = entity.role === "trust-anchor" || entity.role === "intermediate" || entity.protocolRole === "op";
		if (!isAuthority) continue;
		const keys = getKeys(entity.id);
		subordinateStoreMap.set(entity.id, new MemorySubordinateStore());
		trustMarkStoreMap.set(entity.id, new MemoryTrustMarkStore());
		keyStoreMap.set(entity.id, new MemoryKeyStore(keys.signing));
	}

	// 3a. Create TAs and intermediates first (needed to issue trust marks)
	for (const entity of topology.entities) {
		if (entity.protocolRole === "op") continue;
		const isAuthority = entity.role === "trust-anchor" || entity.role === "intermediate";
		if (!isAuthority) continue;

		const eid = rw(entity.id);
		const keys = getKeys(entity.id);
		const subordinateStore = subordinateStoreMap.get(entity.id)!;
		const trustMarkStore = trustMarkStoreMap.get(entity.id)!;
		const keyStore = keyStoreMap.get(entity.id)!;

		const cfg = buildAuthorityConfig(entity, subordinateStore, trustMarkStore, keyStore);
		const authority = createAuthorityServer(cfg as unknown as AuthorityConfig);
		entities.set(entity.id, { server: authority, keys, def: entity, trustMarkStore });

		const hostname = new URL(eid).hostname;
		vhosts.set(hostname, createAuthorityApp(authority, eid));
	}

	// 3b. Issue trust marks from TAs before creating OPs (so OPs can embed them)
	// Map: opEntityId → list of { trust_mark_type, trust_mark } JWTs
	const opTrustMarks = new Map<string, Array<{ trust_mark_type: string; trust_mark: string }>>();

	for (const ta of taEntities) {
		if (!ta.trustMarkIssuers) continue;
		const taInstance = entities.get(ta.id);
		if (!taInstance) continue;
		const taServer = taInstance.server as AuthorityServer;

		for (const [tmType] of Object.entries(ta.trustMarkIssuers)) {
			const rewrittenTmType = rw(tmType);

			// Issue trust marks to all OPs in this topology
			for (const entity of topology.entities) {
				if (entity.protocolRole !== "op") continue;
				const eid = rw(entity.id);
				const jwt = await taServer.issueTrustMark(eid, rewrittenTmType);
				const existing = opTrustMarks.get(entity.id) ?? [];
				existing.push({ trust_mark_type: rewrittenTmType, trust_mark: jwt });
				opTrustMarks.set(entity.id, existing);
			}
		}
	}

	// 3c. Create OP authorities with trust marks embedded in their EC
	for (const entity of topology.entities) {
		if (entity.protocolRole !== "op") continue;

		const eid = rw(entity.id);
		const keys = getKeys(entity.id);
		const subordinateStore = subordinateStoreMap.get(entity.id)!;
		const trustMarkStore = trustMarkStoreMap.get(entity.id)!;
		const keyStore = keyStoreMap.get(entity.id)!;
		const extraTrustMarks = opTrustMarks.get(entity.id);

		const cfg = buildAuthorityConfig(entity, subordinateStore, trustMarkStore, keyStore, extraTrustMarks);
		const authority = createAuthorityServer(cfg as unknown as AuthorityConfig);
		entities.set(entity.id, { server: authority, keys, def: entity, trustMarkStore });

		const hostname = new URL(eid).hostname;
		vhosts.set(hostname, createOpApp(authority, eid, trustAnchors));
	}

	// 4. Create leaf entities (non-OP)
	for (const entity of topology.entities) {
		if (entity.protocolRole === "op") continue;
		if (entity.role !== "leaf") continue;

		const eid = rw(entity.id);
		const keys = getKeys(entity.id);
		let metadata = rewriteMetadata(entity.metadata, port);
		const authorityHints = entity.authorityHints?.map((ah) => entityId(rw(ah))) ?? [];

		// Inject the RP's public JWKS into openid_relying_party so the OP can use it for
		// private_key_jwt token-endpoint auth after resolving the trust chain. The leaf EC's
		// top-level jwks carries the federation signing key; the RP's OIDC client key is the same
		// key and must also be declared in openid_relying_party per §12.1. ✓
		if (entity.protocolRole === "rp" && metadata.openid_relying_party) {
			metadata = {
				...metadata,
				openid_relying_party: {
					...metadata.openid_relying_party,
					jwks: { keys: [keys.public] },
				},
			};
		}

		const leaf = createLeafEntity({
			entityId: entityId(eid),
			signingKeys: [keys.signing],
			authorityHints,
			metadata: metadata as Record<string, Record<string, unknown>>,
		});

		entities.set(entity.id, { server: leaf, keys, def: entity });

		const hostname = new URL(eid).hostname;
		vhosts.set(hostname, createLeafApp(leaf, eid));
	}

	// 5. Register subordinates in parent authority stores
	for (const entity of topology.entities) {
		if (!entity.authorityHints) continue;

		for (const parentId of entity.authorityHints) {
			const store = subordinateStoreMap.get(parentId);
			if (!store) continue;

			const keys = getKeys(entity.id);
			const eid = rw(entity.id);
			let metadata = rewriteMetadata(entity.metadata, port);

			// Mirror the JWKS injection from step 4 so the subordinate statement's metadata
			// also carries the RP's client JWKS (used by the OP for token-endpoint auth). ✓
			if (entity.protocolRole === "rp" && metadata.openid_relying_party) {
				metadata = {
					...metadata,
					openid_relying_party: {
						...metadata.openid_relying_party,
						jwks: { keys: [keys.public] },
					},
				};
			}

			// Parent's constraints apply to all subordinate statements it issues
			const parentEntity = topology.entities.find((e) => e.id === parentId);
			const parentConstraints = parentEntity?.constraints;

			const record: SubordinateRecord = {
				entityId: entityId(eid),
				jwks: { keys: [keys.public] },
				metadata,
				...(entity.metadataPolicy !== undefined ? { metadataPolicy: entity.metadataPolicy } : {}),
				...(parentConstraints !== undefined ? { constraints: parentConstraints } : {}),
				entityTypes: Object.keys(entity.metadata) as EntityType[],
				isIntermediate: entity.role === "intermediate" || entity.protocolRole === "op",
				createdAt: Date.now() / 1000,
				updatedAt: Date.now() / 1000,
			};

			await store.add(record);
		}
	}

	return { vhosts, entities, trustAnchors };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
	const allVhosts = new Map<string, express.Express>();
	const allHostnames: string[] = [];
	const topologyInfo: Array<{ name: string; entities: Array<{ role: string; url: string }> }> = [];

	for (const topology of TOPOLOGIES) {
		const { vhosts } = await bootstrapTopology(topology, PORT);

		const entityInfo: Array<{ role: string; url: string }> = [];
		for (const entity of topology.entities) {
			const eid = rewriteUrl(entity.id, PORT);
			const hostname = new URL(eid).hostname;
			allHostnames.push(hostname);

			const role = entity.protocolRole
				? `${entity.role}/${entity.protocolRole}`
				: entity.role;
			entityInfo.push({ role, url: `${eid}/.well-known/openid-federation` });
		}
		topologyInfo.push({ name: topology.name, entities: entityInfo });

		for (const [hostname, app] of vhosts) {
			allVhosts.set(hostname, app);
		}
	}

	// Start HTTPS vhost server
	const cert = readFileSync(join(CERT_DIR, "ofed.pem"));
	const key = readFileSync(join(CERT_DIR, "ofed-key.pem"));

	const server = https.createServer({ cert, key }, (req, res) => {
		const origin = req.headers.origin;
		if (origin) {
			res.setHeader("Access-Control-Allow-Origin", origin);
			res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
			res.setHeader("Access-Control-Allow-Headers", "Content-Type, Accept");
			res.setHeader("Access-Control-Max-Age", "86400");
		}
		if (req.method === "OPTIONS") {
			res.writeHead(204);
			res.end();
			return;
		}

		const host = (req.headers.host ?? "").replace(/:\d+$/, "");
		const app = allVhosts.get(host);
		if (typeof app !== "function") {
			res.writeHead(404, { "Content-Type": "text/plain" });
			res.end(`No vhost for ${host}`);
			return;
		}
		app(req, res);
	});

	await new Promise<void>((resolve) => {
		server.listen(PORT, "127.0.0.1", () => resolve());
	});

	console.log(`Federation is running on port ${PORT}`);
	console.log();

	for (const topo of topologyInfo) {
		console.log(`[${topo.name}]`);
		for (const e of topo.entities) {
			console.log(`  ${e.role.padEnd(22)} ${e.url}`);
		}
		console.log();
	}

	console.log("Required /etc/hosts entry:");
	// Split into lines of ~8 hostnames each for readability
	const hostnameChunks: string[][] = [];
	for (let i = 0; i < allHostnames.length; i += 8) {
		hostnameChunks.push(allHostnames.slice(i, i + 8));
	}
	for (const chunk of hostnameChunks) {
		console.log(`  127.0.0.1  ${chunk.join(" ")}`);
	}
	console.log();
	console.log("Press Ctrl+C to stop.");

	process.on("SIGINT", () => {
		console.log("\nShutting down...");
		server.close(() => process.exit(0));
	});
	process.on("SIGTERM", () => {
		server.close(() => process.exit(0));
	});
}

main().catch((err) => {
	console.error("Failed to start federation:", err);
	process.exit(1);
});
