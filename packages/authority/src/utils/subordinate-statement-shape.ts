/**
 * Pure helpers that enforce the shape rules for Entity Configurations and
 * Subordinate Statements emitted by this Authority. Used by the EC builder,
 * the fetch endpoint, and the subordinate store.
 */
import { findInvalidMetadataNullPaths } from "@oidfed/core";
import { InvalidMetadata } from "../errors.js";

export { InvalidMetadata };

/**
 * Operational fields that an Authority publishes in its own
 * `metadata.federation_entity` block. Federation §§8.1, 8.2 and 8.4 reserve
 * fetch, list and mark-status publication to the Entity Configuration; Extended
 * Listing §4 imports the list restriction. The remaining exclusions are oidfed's
 * host-owned discovery policy, applied consistently to signed and unsigned views.
 *
 * Set is the canonical source — keep alphabetically grouped (URL claims first,
 * then `_auth_methods` companions, then the signing-alg list).
 */
export const FEDERATION_ENTITY_OPERATIONAL_FIELDS: readonly string[] = Object.freeze([
	"federation_collection_endpoint",
	"federation_collection_endpoint_auth_methods",
	"federation_subordinate_events_endpoint",
	"federation_subordinate_events_endpoint_auth_methods",
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
 * Reject null entity-type blocks and direct metadata parameter values (Federation §5).
 */
export function assertMetadataValuesNotNull(
	metadata: Readonly<Record<string, unknown>> | undefined,
): void {
	if (metadata === undefined) return;
	if (!isPlainObject(metadata)) return;
	const invalid = findInvalidMetadataNullPaths(metadata)[0];
	if (invalid) {
		const path = invalid.reduce<string>(
			(prefix, component) =>
				typeof component === "number"
					? `${prefix}[${component}]`
					: prefix
						? `${prefix}.${component}`
						: component,
			"",
		);
		throw new InvalidMetadata(path || "<root>");
	}
}
