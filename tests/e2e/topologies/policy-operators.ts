import type { TopologyDefinition } from "./types.js";

/**
 * Topology for testing metadata policy operators beyond `default`.
 * TA → IA (with various policy operators) → OP + RP
 *
 * IA policy operators tested:
 * - subset_of: grant_types must be subset of ["authorization_code"]
 * - value: token_endpoint_auth_methods_supported fixed to ["private_key_jwt"]
 * - add: adds "ES256" to id_token_signing_alg_values_supported
 * - essential: subject_types_supported is required
 */
export const policyOperatorsTopology: TopologyDefinition = {
	name: "policy-operators",
	description: "TA → IA with diverse policy operators → OP + RP",
	entities: [
		{
			id: "https://ta.ofed.test",
			role: "trust-anchor",
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ta.ofed.test/federation_fetch",
					federation_list_endpoint: "https://ta.ofed.test/federation_list",
					federation_resolve_endpoint: "https://ta.ofed.test/federation_resolve",
					federation_historical_keys_endpoint: "https://ta.ofed.test/federation_historical_keys",
				},
			},
		},
		{
			id: "https://ia.ofed.test",
			role: "intermediate",
			authorityHints: ["https://ta.ofed.test"],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ia.ofed.test/federation_fetch",
					federation_list_endpoint: "https://ia.ofed.test/federation_list",
					federation_historical_keys_endpoint: "https://ia.ofed.test/federation_historical_keys",
				},
			},
			metadataPolicy: {
				openid_provider: {
					grant_types_supported: {
						subset_of: ["authorization_code"],
					},
					token_endpoint_auth_methods_supported: {
						value: ["private_key_jwt"],
					},
					id_token_signing_alg_values_supported: {
						add: ["ES256"],
					},
					subject_types_supported: {
						essential: true,
					},
				},
			},
		},
		{
			id: "https://op.ofed.test",
			role: "leaf",
			protocolRole: "op",
			authorityHints: ["https://ia.ofed.test"],
			metadata: {
				federation_entity: {
					federation_registration_endpoint: "https://op.ofed.test/federation_registration",
				},
				openid_provider: {
					issuer: "https://op.ofed.test",
					authorization_endpoint: "https://op.ofed.test/auth",
					token_endpoint: "https://op.ofed.test/token",
					response_types_supported: ["code"],
					grant_types_supported: ["authorization_code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["RS256"],
					token_endpoint_auth_methods_supported: ["client_secret_basic"],
					client_registration_types_supported: ["automatic"],
				},
			},
		},
		{
			id: "https://rp.ofed.test",
			role: "leaf",
			protocolRole: "rp",
			authorityHints: ["https://ia.ofed.test"],
			metadata: {
				openid_relying_party: {
					redirect_uris: ["https://rp.ofed.test/callback"],
					response_types: ["code"],
					grant_types: ["authorization_code"],
					client_registration_types: ["automatic"],
					token_endpoint_auth_method: "private_key_jwt",
				},
			},
		},
	],
};
