import type { TopologyDefinition } from "./types.js";

/**
 * Topology for testing maxPathLength constraints.
 * TA has max_path_length: 0 on its subordinate statements, meaning only direct subordinates
 * of the TA are allowed (no intermediates). IA-Deep and its subordinate OP-Deep should
 * fail chain validation because the path OP-Deep → IA-Deep → TA has 1 intermediate,
 * exceeding maxPathLength=0. Direct subordinate OP-Direct should resolve fine.
 */
export const constrainedTopology: TopologyDefinition = {
	name: "constrained",
	description: "TA with max_path_length=0 → direct OP + IA with nested OP",
	entities: [
		{
			id: "https://ta.ofed.test",
			role: "trust-anchor",
			constraints: { max_path_length: 0 },
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
			id: "https://op-direct.ofed.test",
			role: "leaf",
			protocolRole: "op",
			authorityHints: ["https://ta.ofed.test"],
			metadata: {
				federation_entity: {
					federation_registration_endpoint: "https://op-direct.ofed.test/federation_registration",
				},
				openid_provider: {
					issuer: "https://op-direct.ofed.test",
					authorization_endpoint: "https://op-direct.ofed.test/auth",
					token_endpoint: "https://op-direct.ofed.test/token",
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256"],
					client_registration_types_supported: ["automatic"],
				},
			},
		},
		{
			id: "https://ia-deep.ofed.test",
			role: "intermediate",
			authorityHints: ["https://ta.ofed.test"],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: "https://ia-deep.ofed.test/federation_fetch",
					federation_list_endpoint: "https://ia-deep.ofed.test/federation_list",
					federation_historical_keys_endpoint:
						"https://ia-deep.ofed.test/federation_historical_keys",
				},
			},
		},
		{
			id: "https://op-deep.ofed.test",
			role: "leaf",
			protocolRole: "op",
			authorityHints: ["https://ia-deep.ofed.test"],
			metadata: {
				federation_entity: {
					federation_registration_endpoint: "https://op-deep.ofed.test/federation_registration",
				},
				openid_provider: {
					issuer: "https://op-deep.ofed.test",
					authorization_endpoint: "https://op-deep.ofed.test/auth",
					token_endpoint: "https://op-deep.ofed.test/token",
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256"],
					client_registration_types_supported: ["automatic"],
				},
			},
		},
	],
};
