/**
 * Pure helpers that enforce the shape rules for Entity Configurations and
 * Subordinate Statements emitted by this Authority. Used by the EC builder,
 * the fetch endpoint, and the subordinate store.
 */
import { PolicyOperator, STANDARD_ENTITY_STATEMENT_CLAIMS } from "@oidfed/core";
import { InvalidMetadata, InvalidSubordinateStatementShape } from "../errors.js";

export { InvalidMetadata, InvalidSubordinateStatementShape };

const STANDARD_POLICY_OPERATORS: readonly string[] = Object.values(PolicyOperator);

/**
 * Operational fields that an Authority publishes in its own
 * `metadata.federation_entity` block and that MUST NOT appear in a
 * Subordinate Statement (the subordinate owns its own operational discovery).
 *
 * Set is the canonical source — keep alphabetically grouped (URL claims first,
 * then `_auth_methods` companions, then the signing-alg list).
 */
export const FEDERATION_ENTITY_OPERATIONAL_FIELDS: readonly string[] = Object.freeze([
	"federation_extended_list_endpoint",
	"federation_extended_list_endpoint_auth_methods",
	"federation_fetch_endpoint",
	"federation_fetch_endpoint_auth_methods",
	"federation_historical_keys_endpoint",
	"federation_historical_keys_endpoint_auth_methods",
	"federation_list_endpoint",
	"federation_list_endpoint_auth_methods",
	"federation_resolve_endpoint",
	"federation_resolve_endpoint_auth_methods",
	"federation_trust_mark_endpoint",
	"federation_trust_mark_endpoint_auth_methods",
	"federation_trust_mark_list_endpoint",
	"federation_trust_mark_list_endpoint_auth_methods",
	"federation_trust_mark_status_endpoint",
	"federation_trust_mark_status_endpoint_auth_methods",
	"endpoint_auth_signing_alg_values_supported",
]);

const FEDERATION_ENTITY_OPERATIONAL_SET: ReadonlySet<string> = new Set(
	FEDERATION_ENTITY_OPERATIONAL_FIELDS,
);

/**
 * True iff `key` is an operational field of `federation_entity` (endpoint URL,
 * its auth-methods descriptor, or the signing-alg list). Exact lookup.
 */
export function isFederationEntityOperationalField(key: string): boolean {
	return FEDERATION_ENTITY_OPERATIONAL_SET.has(key);
}

/**
 * Top-level Entity Statement claims that must not appear in a Subordinate
 * Statement payload. The first five belong only in an Entity Configuration;
 * `aud` belongs only in Explicit Registration requests/responses; `trust_anchor`
 * belongs only in Explicit Registration responses.
 */
export const SUBORDINATE_STATEMENT_FORBIDDEN_TOP_LEVEL_CLAIMS: readonly string[] = Object.freeze([
	"authority_hints",
	"trust_anchor_hints",
	"trust_marks",
	"trust_mark_issuers",
	"trust_mark_owners",
	"aud",
	"trust_anchor",
]);

/**
 * Returned by sanitizers when a non-object value is passed where an object
 * was expected. Lets callers treat both undefined and malformed input as
 * "nothing to sanitize".
 */
function isPlainObject(v: unknown): v is Record<string, unknown> {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Returns a cleaned-up copy of an Authority's metadata claim suitable for
 * embedding in a Subordinate Statement: strips every operational field from
 * `metadata.federation_entity`. Other entity-type blocks
 * (`openid_relying_party`, `openid_provider`, `oauth_*`, ...) pass through
 * unchanged so the parent can attest legitimate non-endpoint metadata.
 *
 * Returns `undefined` when the resulting metadata claim has no remaining
 * entity types — callers should omit the `metadata` claim from the JWT
 * payload in that case.
 */
export function sanitizeSubordinateMetadata(
	metadata: Readonly<Record<string, unknown>> | undefined,
): Record<string, unknown> | undefined {
	if (!isPlainObject(metadata)) return undefined;
	const result: Record<string, unknown> = {};
	for (const [entityType, claims] of Object.entries(metadata)) {
		if (entityType !== "federation_entity") {
			result[entityType] = claims;
			continue;
		}
		if (!isPlainObject(claims)) {
			// Pass through malformed federation_entity blocks untouched so the
			// schema validator at signing time fails with a clearer error.
			result[entityType] = claims;
			continue;
		}
		const filtered: Record<string, unknown> = {};
		for (const [k, v] of Object.entries(claims)) {
			if (isFederationEntityOperationalField(k)) continue;
			filtered[k] = v;
		}
		if (Object.keys(filtered).length > 0) {
			result[entityType] = filtered;
		}
	}
	return Object.keys(result).length > 0 ? result : undefined;
}

/**
 * Throws `InvalidSubordinateStatementShape` if the payload contains any claim
 * that is only valid in an Entity Configuration or in an Explicit Registration
 * request/response. Defense-in-depth gate immediately before signing.
 */
export function assertSubordinateStatementShape(payload: Record<string, unknown>): void {
	const offenders: string[] = [];
	for (const claim of SUBORDINATE_STATEMENT_FORBIDDEN_TOP_LEVEL_CLAIMS) {
		if (claim in payload) offenders.push(claim);
	}
	if (offenders.length > 0) throw new InvalidSubordinateStatementShape(offenders);
}

/**
 * Validates the `crit` array on an Entity Statement payload. A `crit` claim,
 * when present, must:
 *   - not be the empty array
 *   - contain only string entries
 *   - not list any standard claim name (those in `STANDARD_ENTITY_STATEMENT_CLAIMS`
 *     from `@oidfed/core`) — `crit` is for extension claims only
 *   - not contain duplicates
 *   - reference only claims that actually appear in the payload
 *
 * Throws `InvalidSubordinateStatementShape` on any violation.
 */
export function assertCritShape(payload: Record<string, unknown>): void {
	if (!("crit" in payload)) return;
	const crit = payload.crit;
	if (!Array.isArray(crit)) {
		throw new InvalidSubordinateStatementShape(["crit (must be an array of strings)"]);
	}
	if (crit.length === 0) {
		throw new InvalidSubordinateStatementShape(["crit (must not be the empty array)"]);
	}
	const seen = new Set<string>();
	const violations: string[] = [];
	for (const name of crit) {
		if (typeof name !== "string") {
			violations.push("crit (entries must be strings)");
			continue;
		}
		if (seen.has(name)) {
			violations.push(`crit duplicate: ${name}`);
			continue;
		}
		seen.add(name);
		if (STANDARD_ENTITY_STATEMENT_CLAIMS.has(name)) {
			violations.push(`crit cannot list spec-defined claim: ${name}`);
			continue;
		}
		if (!(name in payload)) {
			violations.push(`crit references missing claim: ${name}`);
		}
	}
	if (violations.length > 0) throw new InvalidSubordinateStatementShape(violations);
}

/**
 * Validates the `metadata_policy_crit` array. When present it must:
 *   - not be the empty array
 *   - contain only string entries
 *   - not include the name of any standard metadata-policy operator
 *     (use `PolicyOperator` from `@oidfed/core`)
 *   - not contain duplicates
 *
 * Throws `InvalidSubordinateStatementShape` on any violation.
 */
export function assertMetadataPolicyCritShape(payload: Record<string, unknown>): void {
	if (!("metadata_policy_crit" in payload)) return;
	const list = payload.metadata_policy_crit;
	if (!Array.isArray(list)) {
		throw new InvalidSubordinateStatementShape([
			"metadata_policy_crit (must be an array of strings)",
		]);
	}
	if (list.length === 0) {
		throw new InvalidSubordinateStatementShape([
			"metadata_policy_crit (must not be the empty array)",
		]);
	}
	const seen = new Set<string>();
	const violations: string[] = [];
	for (const name of list) {
		if (typeof name !== "string") {
			violations.push("metadata_policy_crit (entries must be strings)");
			continue;
		}
		if (seen.has(name)) {
			violations.push(`metadata_policy_crit duplicate: ${name}`);
			continue;
		}
		seen.add(name);
		if (STANDARD_POLICY_OPERATORS.includes(name)) {
			violations.push(`metadata_policy_crit cannot list standard operator: ${name}`);
		}
	}
	if (violations.length > 0) throw new InvalidSubordinateStatementShape(violations);
}

/**
 * Validates that a `metadata_policy` claim, if present, is a JSON object
 * (not an array, scalar, or `null`). Deep operator-level validation lives
 * in `@oidfed/core` and is applied by readers.
 */
export function assertMetadataPolicyShape(payload: Record<string, unknown>): void {
	if (!("metadata_policy" in payload)) return;
	if (!isPlainObject(payload.metadata_policy)) {
		throw new InvalidSubordinateStatementShape(["metadata_policy (must be a JSON object)"]);
	}
}

/**
 * Walks the metadata object recursively and throws `InvalidMetadata` if any
 * leaf is `null`. Treats arrays as ordered leaves and recurses into objects.
 */
export function assertMetadataValuesNotNull(
	metadata: Readonly<Record<string, unknown>> | undefined,
): void {
	if (metadata === undefined) return;
	if (!isPlainObject(metadata)) return;
	walk(metadata, "");
}

function walk(value: unknown, path: string): void {
	if (value === null) {
		throw new InvalidMetadata(path || "<root>");
	}
	if (Array.isArray(value)) {
		for (let i = 0; i < value.length; i++) {
			walk(value[i], `${path}[${i}]`);
		}
		return;
	}
	if (isPlainObject(value)) {
		for (const [k, v] of Object.entries(value)) {
			walk(v, path ? `${path}.${k}` : k);
		}
	}
}
